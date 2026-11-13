//! Sync sessions (sync.md): on one stream of a connection with ALPN `openvault/sync/1`, two
//! members exchange hellos, bring their logs level, then reconcile every set they share.
//!
//! A session runs until 60 seconds pass without a message. While it runs, the device tells it of
//! local writes and log changes through [`Notice`]s, so they reach the peer straight away, and
//! the session tells the device through [`Report`]s when it goes quiet and when it took log
//! entries the device didn't have. It counts as quiet once 2 seconds pass without a message:
//! caught up, and only waiting.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::{Connection, ConnectionError, RecvStream, SendStream};
use openvault_core::membership::LogEntry;
use openvault_core::sets::{Fingerprint, ItemId, SetId, Summary};
use openvault_core::{DeviceId, DeviceKeys, Received, Vault, VaultId};
use openvault_crypto::hash::Hash;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};
use tracing::{debug, warn};

use crate::EndpointKey;
use crate::frame::{self, FrameError, Reason};
use crate::wire::{
    self, HELLO, ITEMS, LOG_BATCH, LOG_ENTRIES, LOG_REQUEST, RECONCILE, ROOTS, Reader, WANT,
};

pub const ALPN: &[u8] = b"openvault/sync/1";

/// How long a session waits for a message before it closes (sync.md, lifetime).
pub const IDLE: Duration = Duration::from_secs(60);
/// How long a session goes without a message before it counts as quiet: caught up, though still
/// open in case more work comes (sync.md, quiet). The protocol has no message that says a
/// session is done, so this is how a device tells.
pub const QUIET: Duration = Duration::from_secs(2);
/// A range with at most this many items is sent as ids rather than a fingerprint.
const IDS_LIMIT: usize = 32;
/// How many ranges a fingerprint that differs splits into.
const SPLIT: usize = 16;
/// The most log entries one session takes (sync.md, who may request).
const MAX_LOG: usize = 4096;
/// The most ranges or ids one message may carry.
const MAX_LIST: u16 = 1024;
/// Close codes: a session ended, and a connection closed because the two devices already have a
/// session (sync.md, who connects).
const DONE: u32 = 0;
const DUPLICATE: u32 = 1;

/// What a session needs from the device's store. Every call may wait on the database, so a
/// session makes them from blocking sections.
pub trait SyncStore: Send + Sync + 'static {
    /// The vault id and this device's log head.
    fn hello(&self) -> openvault_core::Result<(VaultId, u64, Hash)>;
    fn log_from(&self, from: u64, max: u16) -> openvault_core::Result<Vec<LogEntry>>;
    fn append_log(&self, entries: &[LogEntry]) -> openvault_core::Result<usize>;
    /// The member, not revoked, whose transport key is `endpoint`.
    fn member(&self, endpoint: &EndpointKey) -> Option<DeviceId>;
    fn shared_sets(&self, peer: DeviceId) -> Vec<SetId>;
    fn summary(&self, set: SetId) -> openvault_core::Result<Summary>;
    fn ids(
        &self,
        set: SetId,
        lower: &ItemId,
        upper: Option<&ItemId>,
    ) -> openvault_core::Result<Vec<ItemId>>;
    fn items(&self, set: SetId, ids: &[ItemId]) -> openvault_core::Result<Vec<Vec<u8>>>;
    fn receive(&self, set: SetId, item: &[u8]) -> openvault_core::Result<Received>;
}

/// What the device tells a running session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// A local write changed this set.
    Changed(SetId),
    /// The log has new entries.
    Log,
}

/// What a running session tells the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    /// `true` when the session has gone [`QUIET`] without a message: caught up, and only
    /// waiting. `false` when a message comes after that.
    Quiet(bool),
    /// The session took log entries this device didn't have. The device's other sessions and
    /// visible members should hear of them (sync.md, when devices sync). Entries it already had
    /// aren't reported, so passing them on stops at devices that have them.
    Log,
}

/// Which side opened the connection. The opener starts each set's reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Opener,
    Accepter,
}

/// What a session did, for the device's log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Log entries this device took in.
    pub log_received: usize,
    /// New records and grants this device took in.
    pub received: usize,
    /// Items the peer sent that failed their checks and were dropped.
    pub dropped: usize,
    /// Log entries this device sent.
    pub log_sent: usize,
    /// Records and grants this device sent.
    pub sent: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("can't connect: {0}")]
    Connect(String),
    #[error("{0}")]
    Refused(Reason),
    /// The peer closed the connection because the two devices already have a session. This isn't
    /// a failure.
    #[error("the peer already has a session with this device")]
    Duplicate,
    #[error(transparent)]
    Store(#[from] openvault_core::Error),
}

impl SyncError {
    /// The reason to send the peer before closing, if the failure is one it should hear of.
    pub fn reason(&self) -> Option<Reason> {
        match self {
            Self::Refused(reason) => Some(*reason),
            Self::Frame(FrameError::Bad(_)) => Some(Reason::BadMessage),
            Self::Store(openvault_core::Error::Fork) => Some(Reason::Fork),
            _ => None,
        }
    }
}

/// A range's upper bound, exclusive; `None` is the end of the id space.
type Upper = Option<ItemId>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Mode {
    Skip,
    Fingerprint {
        count: u64,
        fingerprint: Fingerprint,
    },
    Ids(Vec<ItemId>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Range {
    upper: Upper,
    mode: Mode,
}

struct Session<S: SyncStore> {
    store: Arc<S>,
    send: SendStream,
    role: Role,
    peer_endpoint: EndpointKey,
    vault: VaultId,
    peer_head: Option<(u64, Hash)>,
    /// The head in the last hello this device sent. The roots started over when it was sent.
    announced: Option<(u64, Hash)>,
    /// Set once the logs are level and the peer is known to be a member.
    peer: Option<DeviceId>,
    shared: Vec<SetId>,
    roots_sent: bool,
    /// Set the first time the logs are level and the peer is known to be a member. Unlike the
    /// roots, a log change doesn't clear it: the peer has passed the checks once, and messages
    /// about sets are taken from then on (sync.md, after a log change).
    leveled: bool,
    peer_roots: HashMap<SetId, (u64, Fingerprint)>,
    reconciled: HashSet<SetId>,
    log_requested: bool,
    /// Set when the last message brought log entries this device didn't have, until the device
    /// hears of them ([`Report::Log`]).
    log_grew: bool,
    outcome: Outcome,
}

/// Runs a session on `connection` until `idle` passes without a message ([`IDLE`] outside
/// tests), the peer closes it, or it fails. `report` hears [`Report::Quiet`] each time the
/// session goes quiet or has work again, and [`Report::Log`] each time it took log entries this
/// device didn't have. A session starts with work to do.
pub async fn run<S: SyncStore>(
    connection: Connection,
    role: Role,
    store: Arc<S>,
    mut notices: mpsc::Receiver<Notice>,
    idle: Duration,
    mut report: impl FnMut(Report) + Send,
) -> Result<Outcome, SyncError> {
    let result = session(&connection, role, store, &mut notices, idle, &mut report).await;
    let duplicate = matches!(
        connection.close_reason(),
        Some(ConnectionError::ApplicationClosed(close)) if u64::from(close.error_code) == u64::from(DUPLICATE)
    );
    connection.close(DONE.into(), b"done");
    match result {
        Err(_) if duplicate => Err(SyncError::Duplicate),
        result => result,
    }
}

/// Closes a connection that duplicates a running session with the same peer. The peer's session
/// ends with [`SyncError::Duplicate`].
pub fn close_duplicate(connection: &Connection) {
    connection.close(DUPLICATE.into(), b"already syncing");
}

async fn session<S: SyncStore>(
    connection: &Connection,
    role: Role,
    store: Arc<S>,
    notices: &mut mpsc::Receiver<Notice>,
    idle: Duration,
    report: &mut (impl FnMut(Report) + Send),
) -> Result<Outcome, SyncError> {
    let peer_endpoint = *connection.remote_id().as_bytes();
    let (send, recv) = match role {
        Role::Opener => connection.open_bi().await,
        Role::Accepter => connection.accept_bi().await,
    }
    .map_err(|e| SyncError::Connect(e.to_string()))?;
    let (vault, ..) = blocking(|| store.hello())?;
    let mut session = Session {
        store,
        send,
        role,
        peer_endpoint,
        vault,
        peer_head: None,
        announced: None,
        peer: None,
        shared: Vec::new(),
        roots_sent: false,
        leveled: false,
        peer_roots: HashMap::new(),
        reconciled: HashSet::new(),
        log_requested: false,
        log_grew: false,
        outcome: Outcome::default(),
    };
    let result = session.drive(recv, notices, idle, report).await;
    if let Err(error) = &result {
        if let Some(reason) = error.reason() {
            frame::send_error(&mut session.send, reason, &error.to_string()).await;
        }
    } else {
        let _ = session.send.finish();
    }
    result.map(|()| session.outcome)
}

impl<S: SyncStore> Session<S> {
    async fn drive(
        &mut self,
        recv: RecvStream,
        notices: &mut mpsc::Receiver<Notice>,
        idle: Duration,
        report: &mut (impl FnMut(Report) + Send),
    ) -> Result<(), SyncError> {
        let head = self.head()?;
        self.send_hello(head).await?;
        // One read stays in flight across the loop. `select!` drops the branches it doesn't take,
        // and a read dropped part way through a message would lose the bytes it had read.
        let mut reading = Box::pin(next_message(recv));
        let mut deadline = Instant::now() + idle;
        // When the session goes quiet if no message comes first; `None` once it has. A message
        // either way puts it off, and tells `quiet` if the session had gone quiet.
        let mut quiet_at = Some(Instant::now() + QUIET);
        loop {
            tokio::select! {
                (recv, message) = &mut reading => {
                    let (kind, body) = match message {
                        Ok(message) => message,
                        // The peer went idle first and closed.
                        Err(FrameError::Connection(_)) if self.peer.is_some() => return Ok(()),
                        Err(FrameError::Peer { reason, .. }) => return Err(SyncError::Refused(reason)),
                        Err(e) => return Err(e.into()),
                    };
                    reading.set(next_message(recv));
                    deadline = Instant::now() + idle;
                    if quiet_at.replace(Instant::now() + QUIET).is_none() {
                        report(Report::Quiet(false));
                    }
                    let handled = self.handle(kind, &body).await;
                    // Entries the device took are passed on even if the session then ends, as
                    // it does when they revoked the peer.
                    if std::mem::take(&mut self.log_grew) {
                        report(Report::Log);
                    }
                    if let Err(error) = handled {
                        return Err(peer_reason(&mut reading, error).await);
                    }
                }
                Some(notice) = notices.recv() => {
                    match self.notice(notice).await {
                        Ok(sent) => {
                            if sent && quiet_at.replace(Instant::now() + QUIET).is_none() {
                                report(Report::Quiet(false));
                            }
                        }
                        Err(error) => return Err(peer_reason(&mut reading, error).await),
                    }
                }
                () = sleep_until(quiet_at.unwrap_or(deadline)), if quiet_at.is_some() => {
                    quiet_at = None;
                    report(Report::Quiet(true));
                }
                () = sleep_until(deadline) => return Ok(()),
            }
        }
    }

    async fn handle(&mut self, kind: u8, body: &[u8]) -> Result<(), SyncError> {
        match kind {
            HELLO => {
                let (vault, seq, hash) = wire::parse_hello(body)?;
                if vault != self.vault {
                    return Err(SyncError::Refused(Reason::WrongVault));
                }
                self.peer_head = Some((seq, hash));
                self.progress().await
            }
            LOG_REQUEST => {
                let (from, max) = wire::parse_log_request(body)?;
                // Only members are answered; a revoked peer gets nothing (sync.md).
                let endpoint = self.peer_endpoint;
                if blocking(|| self.store.member(&endpoint)).is_none() {
                    return Err(SyncError::Refused(Reason::NotAMember));
                }
                let entries = blocking(|| self.store.log_from(from, max.min(LOG_BATCH)))?;
                frame::write(&mut self.send, LOG_ENTRIES, &wire::log_entries(&entries)).await?;
                self.outcome.log_sent += entries.len();
                Ok(())
            }
            LOG_ENTRIES => {
                self.log_requested = false;
                let entries = wire::parse_log_entries(body)?;
                if entries.is_empty() {
                    return Err(FrameError::Bad("no log entries").into());
                }
                self.outcome.log_received += entries.len();
                if self.outcome.log_received > MAX_LOG {
                    return Err(FrameError::Bad("too many log entries").into());
                }
                let new = blocking(|| self.store.append_log(&entries))?;
                if new > 0 {
                    self.log_grew = true;
                    // The log changed, so what the devices share may have: start the roots over.
                    self.reset_roots();
                    let head = self.head()?;
                    self.send_hello(head).await?;
                }
                self.progress().await
            }
            ROOTS => {
                let mut reader = Reader(body);
                for _ in 0..reader.u16()? {
                    let set = reader.set()?;
                    let root = (reader.u64()?, reader.array()?);
                    self.peer_roots.insert(set, root);
                    // A changed root starts that set over.
                    self.reconciled.remove(&set);
                }
                reader.finish()?;
                self.progress().await
            }
            RECONCILE => {
                let (set, ranges) = parse_reconcile(body)?;
                if !self.shares(set)? {
                    return Ok(());
                }
                self.answer(set, ranges).await
            }
            WANT => {
                let mut reader = Reader(body);
                let set = reader.set()?;
                let count = reader.u16()?;
                if count > MAX_LIST {
                    return Err(FrameError::Bad("too many ids").into());
                }
                let ids: Vec<ItemId> = (0..count)
                    .map(|_| reader.array())
                    .collect::<Result<_, _>>()?;
                reader.finish()?;
                if !self.shares(set)? {
                    return Ok(());
                }
                self.send_items(set, &ids).await
            }
            ITEMS => {
                let (set, items) = wire::parse_items(body)?;
                if !self.shares(set)? {
                    return Ok(());
                }
                for item in items {
                    match blocking(|| self.store.receive(set, item)) {
                        Ok(Received::New) => self.outcome.received += 1,
                        Ok(Received::Known) => {}
                        Ok(Received::Unreadable) => {
                            self.outcome.received += 1;
                            warn!("a record from the peer didn't open; it's kept but not used");
                        }
                        // Dropped; reconciliation offers it again, and it may pass once the
                        // log has grown (sync.md, dropped records).
                        Err(error) => {
                            self.outcome.dropped += 1;
                            debug!("dropped an item from the peer: {error}");
                        }
                    }
                }
                Ok(())
            }
            _ => Err(FrameError::Bad("unexpected message").into()),
        }
    }

    /// Requests log entries while the peer is ahead, then checks membership and sends roots once
    /// the logs are level, then, on the opening side, starts reconciling the sets that differ.
    async fn progress(&mut self) -> Result<(), SyncError> {
        let Some(peer_head) = self.peer_head else {
            return Ok(());
        };
        let (_, seq, hash) = blocking(|| self.store.hello())?;
        if peer_head.0 > seq {
            if !self.log_requested {
                let max = LOG_BATCH.min(u16::try_from(peer_head.0 - seq).unwrap_or(LOG_BATCH));
                frame::write(
                    &mut self.send,
                    LOG_REQUEST,
                    &wire::log_request(seq + 1, max),
                )
                .await?;
                self.log_requested = true;
            }
            return Ok(());
        }
        if peer_head.0 < seq {
            // The peer is behind and will ask.
            return Ok(());
        }
        if peer_head.1 != hash {
            return Err(SyncError::Store(openvault_core::Error::Fork));
        }
        if self.peer.is_none() {
            let endpoint = self.peer_endpoint;
            let peer = blocking(|| self.store.member(&endpoint))
                .ok_or(SyncError::Refused(Reason::NotAMember))?;
            self.peer = Some(peer);
            self.leveled = true;
        }
        if !self.roots_sent {
            let peer = self.peer.expect("set above");
            self.shared = blocking(|| self.store.shared_sets(peer));
            let sets = self.shared.clone();
            self.send_roots(&sets).await?;
            self.roots_sent = true;
        }
        if self.role == Role::Opener {
            for set in self.shared.clone() {
                if self.reconciled.contains(&set) {
                    continue;
                }
                let Some(&(count, fingerprint)) = self.peer_roots.get(&set) else {
                    continue;
                };
                self.reconciled.insert(set);
                let summary = blocking(|| self.store.summary(set))?;
                if (summary.count, summary.fingerprint()) == (count, fingerprint) {
                    continue;
                }
                // One range over everything, as ids if there are few.
                let mode = if summary.count as usize <= IDS_LIMIT {
                    Mode::Ids(blocking(|| self.store.ids(set, &[0; 32], None))?)
                } else {
                    Mode::Fingerprint {
                        count: summary.count,
                        fingerprint: summary.fingerprint(),
                    }
                };
                let range = Range { upper: None, mode };
                frame::write(&mut self.send, RECONCILE, &encode_reconcile(set, &[range])).await?;
            }
        }
        Ok(())
    }

    /// Passes a notice on to the peer. True if it sent the peer anything.
    async fn notice(&mut self, notice: Notice) -> Result<bool, SyncError> {
        match notice {
            Notice::Log => {
                let head = self.head()?;
                // This session sent the peer this head already, and its roots started over
                // then. Starting them over again would drop roots the peer has sent since, and
                // the opener wouldn't reconcile again (sync.md, during a session). The session
                // that took the entries hears of them this way too.
                if self.announced == Some(head) {
                    return Ok(false);
                }
                self.reset_roots();
                self.send_hello(head).await?;
                self.progress().await?;
                Ok(true)
            }
            Notice::Changed(set) if self.roots_sent && self.shared.contains(&set) => {
                // The peer learns the new root; the opener also starts the set over itself.
                self.send_roots(&[set]).await?;
                self.reconciled.remove(&set);
                self.progress().await?;
                Ok(true)
            }
            Notice::Changed(_) => Ok(false),
        }
    }

    /// Answers a reconcile range by range (sync.md, answering).
    async fn answer(&mut self, set: SetId, ranges: Vec<Range>) -> Result<(), SyncError> {
        let mut lower: ItemId = [0; 32];
        let mut reply: Vec<Range> = Vec::new();
        let mut to_send: Vec<ItemId> = Vec::new();
        let mut to_want: Vec<ItemId> = Vec::new();
        for range in ranges {
            match range.mode {
                Mode::Skip => reply.push(range.clone()),
                Mode::Fingerprint { count, fingerprint } => {
                    let mine = blocking(|| self.store.ids(set, &lower, range.upper.as_ref()))?;
                    let summary = Summary::of(&mine);
                    if (summary.count, summary.fingerprint()) == (count, fingerprint) {
                        reply.push(Range {
                            upper: range.upper,
                            mode: Mode::Skip,
                        });
                    } else if mine.len() <= IDS_LIMIT {
                        reply.push(Range {
                            upper: range.upper,
                            mode: Mode::Ids(mine),
                        });
                    } else {
                        reply.extend(split(&mine, range.upper));
                    }
                }
                Mode::Ids(theirs) => {
                    let mine = blocking(|| self.store.ids(set, &lower, range.upper.as_ref()))?;
                    let theirs_set: HashSet<&ItemId> = theirs.iter().collect();
                    let mine_set: HashSet<&ItemId> = mine.iter().collect();
                    to_send.extend(mine.iter().filter(|id| !theirs_set.contains(id)));
                    to_want.extend(theirs.iter().filter(|id| !mine_set.contains(id)));
                    reply.push(Range {
                        upper: range.upper,
                        mode: Mode::Skip,
                    });
                }
            }
            if let Some(upper) = range.upper {
                lower = upper;
            }
        }
        if !to_send.is_empty() {
            self.send_items(set, &to_send).await?;
        }
        for ids in to_want.chunks(usize::from(MAX_LIST)) {
            let mut body = set.as_bytes().to_vec();
            body.extend_from_slice(&(ids.len() as u16).to_be_bytes());
            for id in ids {
                body.extend_from_slice(id);
            }
            frame::write(&mut self.send, WANT, &body).await?;
        }
        let reply = merge_skips(reply);
        // A reply of only skips means the set is settled, and needs no answer.
        if reply.iter().any(|range| range.mode != Mode::Skip) {
            frame::write(&mut self.send, RECONCILE, &encode_reconcile(set, &reply)).await?;
        }
        Ok(())
    }

    async fn send_items(&mut self, set: SetId, ids: &[ItemId]) -> Result<(), SyncError> {
        let items = blocking(|| self.store.items(set, ids))?;
        self.outcome.sent += items.len();
        for message in wire::items(set, &items) {
            frame::write(&mut self.send, ITEMS, &message).await?;
        }
        Ok(())
    }

    /// This device's log head now.
    fn head(&self) -> Result<(u64, Hash), SyncError> {
        let (_, seq, hash) = blocking(|| self.store.hello())?;
        Ok((seq, hash))
    }

    async fn send_hello(&mut self, (seq, hash): (u64, Hash)) -> Result<(), SyncError> {
        frame::write(&mut self.send, HELLO, &wire::hello(self.vault, seq, &hash)).await?;
        self.announced = Some((seq, hash));
        Ok(())
    }

    async fn send_roots(&mut self, sets: &[SetId]) -> Result<(), SyncError> {
        let mut body = (sets.len() as u16).to_be_bytes().to_vec();
        for &set in sets {
            let summary = blocking(|| self.store.summary(set))?;
            body.extend_from_slice(set.as_bytes());
            body.extend_from_slice(&summary.count.to_be_bytes());
            body.extend_from_slice(&summary.fingerprint());
        }
        frame::write(&mut self.send, ROOTS, &body).await?;
        Ok(())
    }

    /// Starts the roots over after the log changed. The peer's membership is checked again once
    /// the logs are level, since the change may have revoked it, and at each message about a set
    /// before then ([`Self::shares`]).
    fn reset_roots(&mut self) {
        self.peer = None;
        self.roots_sent = false;
        self.peer_roots.clear();
        self.reconciled.clear();
    }

    /// Whether to act on the peer's message about `set`: true if the device shares it with the
    /// peer under its current log (design §9, serving). The roots aren't asked, since a log
    /// change starts them over while the peer may still be answering under the older log
    /// (sync.md, after a log change). A set it doesn't share is ignored for the same reason,
    /// and a revoked peer ends the session.
    fn shares(&self, set: SetId) -> Result<bool, SyncError> {
        if !self.leveled {
            // Sets come after the roots, and the roots after the logs are level.
            return Err(FrameError::Bad("a set before the logs were level").into());
        }
        let endpoint = self.peer_endpoint;
        let peer = blocking(|| self.store.member(&endpoint))
            .ok_or(SyncError::Refused(Reason::NotAMember))?;
        if blocking(|| self.store.shared_sets(peer)).contains(&set) {
            Ok(true)
        } else {
            debug!("ignored a message about a set this device doesn't share with the peer");
            Ok(false)
        }
    }
}

/// A vault behind a mutex is a sync store. `hello` also picks up writes by other processes
/// (service.md, the store).
impl<K: DeviceKeys + Send + 'static> SyncStore for Mutex<Vault<K>> {
    fn hello(&self) -> openvault_core::Result<(VaultId, u64, Hash)> {
        let mut vault = self.lock().expect("poisoned");
        vault.refresh()?;
        let (seq, hash) = vault
            .membership()
            .ok_or(openvault_core::Error::NoLog)?
            .head();
        Ok((vault.vault_id(), seq, hash))
    }

    fn log_from(&self, from: u64, max: u16) -> openvault_core::Result<Vec<LogEntry>> {
        self.lock().expect("poisoned").log_from(from, max)
    }

    fn append_log(&self, entries: &[LogEntry]) -> openvault_core::Result<usize> {
        self.lock().expect("poisoned").append_log(entries)
    }

    fn member(&self, endpoint: &EndpointKey) -> Option<DeviceId> {
        self.lock().expect("poisoned").member_by_endpoint(endpoint)
    }

    fn shared_sets(&self, peer: DeviceId) -> Vec<SetId> {
        self.lock().expect("poisoned").shared_sets(peer)
    }

    fn summary(&self, set: SetId) -> openvault_core::Result<Summary> {
        self.lock().expect("poisoned").set_summary(set)
    }

    fn ids(
        &self,
        set: SetId,
        lower: &ItemId,
        upper: Option<&ItemId>,
    ) -> openvault_core::Result<Vec<ItemId>> {
        self.lock().expect("poisoned").set_ids(set, lower, upper)
    }

    fn items(&self, set: SetId, ids: &[ItemId]) -> openvault_core::Result<Vec<Vec<u8>>> {
        self.lock().expect("poisoned").set_items(set, ids)
    }

    fn receive(&self, set: SetId, item: &[u8]) -> openvault_core::Result<Received> {
        self.lock().expect("poisoned").receive(set, item)
    }
}

/// Splits `ids` (in order, more than [`IDS_LIMIT`]) into [`SPLIT`] ranges of nearly equal count,
/// each with its fingerprint. The last one runs to `upper`.
fn split(ids: &[ItemId], upper: Upper) -> Vec<Range> {
    let n = ids.len();
    (0..SPLIT)
        .map(|k| {
            let (start, end) = (k * n / SPLIT, (k + 1) * n / SPLIT);
            let summary = Summary::of(&ids[start..end]);
            Range {
                upper: if k + 1 == SPLIT {
                    upper
                } else {
                    Some(ids[end])
                },
                mode: Mode::Fingerprint {
                    count: summary.count,
                    fingerprint: summary.fingerprint(),
                },
            }
        })
        .collect()
}

/// Adjacent skips become one range.
fn merge_skips(ranges: Vec<Range>) -> Vec<Range> {
    let mut merged: Vec<Range> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if range.mode == Mode::Skip
            && let Some(last) = merged.last_mut()
            && last.mode == Mode::Skip
        {
            last.upper = range.upper;
            continue;
        }
        merged.push(range);
    }
    merged
}

/// `set id (17) ‖ range count (u16) ‖ ranges`, each `upper ‖ mode ‖ payload` (sync.md, ranges).
fn encode_reconcile(set: SetId, ranges: &[Range]) -> Vec<u8> {
    let mut out = set.as_bytes().to_vec();
    out.extend_from_slice(&(ranges.len() as u16).to_be_bytes());
    for range in ranges {
        match &range.upper {
            Some(id) => {
                out.push(0x00);
                out.extend_from_slice(id);
            }
            None => out.push(0x01),
        }
        match &range.mode {
            Mode::Skip => out.push(0x00),
            Mode::Fingerprint { count, fingerprint } => {
                out.push(0x01);
                out.extend_from_slice(&count.to_be_bytes());
                out.extend_from_slice(fingerprint);
            }
            Mode::Ids(ids) => {
                out.push(0x02);
                out.extend_from_slice(&(ids.len() as u16).to_be_bytes());
                for id in ids {
                    out.extend_from_slice(id);
                }
            }
        }
    }
    out
}

/// Decodes a reconcile and checks its ranges cover the id space, in order.
fn parse_reconcile(body: &[u8]) -> Result<(SetId, Vec<Range>), FrameError> {
    let mut reader = Reader(body);
    let set = reader.set()?;
    let count = reader.u16()?;
    if count == 0 || count > MAX_LIST {
        return Err(FrameError::Bad("range count"));
    }
    let mut ranges = Vec::with_capacity(usize::from(count));
    let mut last: Option<ItemId> = None;
    for i in 0..count {
        let upper = match reader.u8()? {
            0x00 => Some(reader.array()?),
            0x01 if i + 1 == count => None,
            _ => return Err(FrameError::Bad("range bound")),
        };
        if let (Some(previous), Some(upper)) = (last, upper)
            && upper <= previous
        {
            return Err(FrameError::Bad("ranges out of order"));
        }
        if upper.is_some() && i + 1 == count {
            return Err(FrameError::Bad("the ranges don't reach the end"));
        }
        last = upper;
        let mode = match reader.u8()? {
            0x00 => Mode::Skip,
            0x01 => Mode::Fingerprint {
                count: reader.u64()?,
                fingerprint: reader.array()?,
            },
            0x02 => {
                let n = reader.u16()?;
                if n > MAX_LIST {
                    return Err(FrameError::Bad("too many ids"));
                }
                Mode::Ids((0..n).map(|_| reader.array()).collect::<Result<_, _>>()?)
            }
            _ => return Err(FrameError::Bad("range mode")),
        };
        ranges.push(Range { upper, mode });
    }
    reader.finish()?;
    Ok((set, ranges))
}

/// Reads the next message and hands the stream back for the one after.
/// How long a session whose write failed waits for the peer's reason, if it sent one.
const REASON_WAIT: Duration = Duration::from_secs(2);

/// A write that fails because the peer stopped reading may race the error message the peer sent
/// just before: both devices can end a session at once, as when both learn of a revocation. The
/// read already in flight gets that message if it's coming, and its reason is the session's.
async fn peer_reason<F>(reading: &mut F, error: SyncError) -> SyncError
where
    F: Future<Output = (RecvStream, Result<(u8, Vec<u8>), FrameError>)> + Unpin,
{
    if matches!(error, SyncError::Frame(FrameError::Connection(_)))
        && let Ok((_, Err(FrameError::Peer { reason, .. }))) =
            tokio::time::timeout(REASON_WAIT, reading).await
    {
        return SyncError::Refused(reason);
    }
    error
}

pub(crate) async fn next_message(
    mut recv: RecvStream,
) -> (RecvStream, Result<(u8, Vec<u8>), FrameError>) {
    let message = frame::read(&mut recv).await;
    (recv, message)
}

/// Runs a store call that may wait on the database without holding up the runtime's other
/// tasks. Sessions run on a multi-threaded runtime.
pub(crate) fn blocking<T>(f: impl FnOnce() -> T) -> T {
    tokio::task::block_in_place(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A new protocol is a new minor version of the build, since older builds can't speak it
    /// (README, versions). Change both together.
    #[test]
    fn the_build_version_follows_the_protocols() {
        assert_eq!(
            (
                env!("CARGO_PKG_VERSION_MINOR"),
                ALPN,
                crate::join::ALPN,
                crate::coord::ALPN,
                crate::chunks::ALPN
            ),
            (
                "5",
                &b"openvault/sync/1"[..],
                &b"openvault/join/1"[..],
                &b"openvault/coord/1"[..],
                &b"openvault/chunks/1"[..]
            )
        );
    }

    #[test]
    fn reconciles_round_trip_and_are_checked() {
        let ranges = vec![
            Range {
                upper: Some([1; 32]),
                mode: Mode::Skip,
            },
            Range {
                upper: Some([2; 32]),
                mode: Mode::Fingerprint {
                    count: 40,
                    fingerprint: [9; 16],
                },
            },
            Range {
                upper: None,
                mode: Mode::Ids(vec![[3; 32], [4; 32]]),
            },
        ];
        let body = encode_reconcile(SetId::GRANTS, &ranges);
        assert_eq!(
            parse_reconcile(&body).unwrap(),
            (SetId::GRANTS, ranges.clone())
        );

        let out_of_order = [ranges[1].clone(), ranges[0].clone(), ranges[2].clone()];
        assert!(parse_reconcile(&encode_reconcile(SetId::GRANTS, &out_of_order)).is_err());
        assert!(parse_reconcile(&encode_reconcile(SetId::GRANTS, &ranges[..2])).is_err());
    }

    #[test]
    fn splits_cover_the_range_in_nearly_equal_parts() {
        let ids: Vec<ItemId> = (0..100u8).map(|i| [i; 32]).collect();
        let ranges = split(&ids, None);
        assert_eq!(ranges.len(), SPLIT);
        assert_eq!(ranges.last().unwrap().upper, None);
        let total: u64 = ranges
            .iter()
            .map(|range| match range.mode {
                Mode::Fingerprint { count, .. } => count,
                _ => panic!("not a fingerprint"),
            })
            .sum();
        assert_eq!(total, 100);
        assert_eq!(ranges[0].upper, Some(ids[6]));
        assert_eq!(
            merge_skips(vec![
                Range {
                    upper: Some([1; 32]),
                    mode: Mode::Skip
                },
                Range {
                    upper: None,
                    mode: Mode::Skip
                },
            ]),
            [Range {
                upper: None,
                mode: Mode::Skip
            }]
        );
    }
}

#[cfg(test)]
pub(crate) mod session_tests {
    use openvault_core::join::JoinRequest;
    use openvault_core::membership::{DeviceName, Scope};
    use openvault_core::{CollectionId, Kind, SoftwareKeys, transport_seed};
    use openvault_crypto::RecoveryKey;

    use super::*;
    use crate::{Node, Options};

    pub(crate) type Store = Mutex<Vault<SoftwareKeys>>;

    pub(crate) struct Pair {
        _dir: tempfile::TempDir,
        pub(crate) recovery: RecoveryKey,
        pub(crate) admin: Arc<Store>,
        pub(crate) joined: Arc<Store>,
        pub(crate) admin_node: Node,
        pub(crate) joined_node: Node,
        pub(crate) latem: CollectionId,
    }

    /// An admin vault with `latem` and `ssh`, and a device that joined it with read on `latem`,
    /// each with an endpoint that accepts sync and chunk requests.
    pub(crate) async fn pair(entries: usize) -> Pair {
        let dir = tempfile::tempdir().unwrap();
        let recovery = RecoveryKey::generate();
        let admin_keys = SoftwareKeys::generate();
        let admin_seed = transport_seed(&admin_keys);
        let mut admin = Vault::create(
            &dir.path().join("admin.db"),
            admin_keys,
            &recovery,
            "MacBook",
            None,
        )
        .unwrap();
        let latem = admin
            .create_collection("latem", &recovery.admin_signing_key())
            .unwrap();
        admin
            .create_collection("ssh", &recovery.admin_signing_key())
            .unwrap();
        for i in 0..entries {
            admin
                .set(
                    latem,
                    &format!("prod/KEY_{i}"),
                    Kind::Secret,
                    format!("value {i}").as_bytes(),
                )
                .unwrap();
        }
        let joiner_keys = SoftwareKeys::generate();
        let joiner_seed = transport_seed(&joiner_keys);
        let device = DeviceId::random();
        let name = DeviceName {
            platform: "linux".into(),
            name: "Desktop".into(),
        };
        let request = JoinRequest::sign(&[1; 32], device, &joiner_keys, name.clone()).unwrap();
        let approval = admin
            .approve_join(
                &request,
                &[(latem, Scope::Read)],
                &recovery.admin_signing_key(),
            )
            .unwrap();
        let head = admin.membership().unwrap().head();
        let joined = Vault::join(
            &dir.path().join("joined.db"),
            joiner_keys,
            device,
            &name,
            head,
            &approval.log,
            &approval.grants,
        )
        .unwrap();
        let options = || Options {
            alpns: vec![ALPN.to_vec(), crate::chunks::ALPN.to_vec()],
            ..crate::test_options()
        };
        Pair {
            _dir: dir,
            recovery,
            admin: Arc::new(Mutex::new(admin)),
            joined: Arc::new(Mutex::new(joined)),
            admin_node: Node::start(&admin_seed, options()).await.unwrap().0,
            joined_node: Node::start(&joiner_seed, options()).await.unwrap().0,
            latem,
        }
    }

    /// Runs one session, `opener` dialing `accepter`, with `idle` as the idle time. Returns both
    /// outcomes. `during` runs once the session has started.
    async fn session(
        opener: (&Node, &Arc<Store>),
        accepter: (&Node, &Arc<Store>),
        idle: Duration,
        during: impl AsyncFnOnce(&mpsc::Sender<Notice>),
    ) -> (Outcome, Outcome) {
        let (accept_tx, accept_rx) = mpsc::channel(8);
        let accept_store = accepter.1.clone();
        let endpoint = accepter.0.endpoint().clone();
        let accepting = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            run(
                connection,
                Role::Accepter,
                accept_store,
                accept_rx,
                idle,
                |_| {},
            )
            .await
        });
        let id = iroh::EndpointId::from_bytes(&accepter.0.id()).unwrap();
        let connection = opener.0.endpoint().connect(id, ALPN).await.unwrap();
        let (tx, rx) = mpsc::channel(8);
        let opening = tokio::spawn(run(
            connection,
            Role::Opener,
            opener.1.clone(),
            rx,
            idle,
            |_| {},
        ));
        during(&tx).await;
        drop(accept_tx);
        (
            opening.await.unwrap().unwrap(),
            accepting.await.unwrap().unwrap(),
        )
    }

    fn summaries(store: &Store, latem: CollectionId) -> (Summary, Summary) {
        let vault = store.lock().unwrap();
        (
            vault.set_summary(SetId::records(latem)).unwrap(),
            vault.set_summary(SetId::GRANTS).unwrap(),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_joined_device_catches_up_and_later_writes_follow() {
        let p = pair(2).await;
        let admin = (&p.admin_node, &p.admin);
        let joined = (&p.joined_node, &p.joined);
        let (opened, accepted) = session(admin, joined, Duration::from_secs(2), async |_| {}).await;
        // The collection record and two entries, and four grants: the admin's and the recovery
        // key's for both collections. Every member keeps every grant (sync.md, who stores
        // grants), even ones it can't open.
        assert_eq!(accepted.received, 3 + 4);
        assert_eq!(opened.dropped + accepted.dropped, 0);
        assert_eq!(summaries(&p.joined, p.latem), summaries(&p.admin, p.latem));
        {
            let mut vault = p.joined.lock().unwrap();
            assert_eq!(vault.collection("latem").unwrap(), p.latem);
            let entry = vault.get(p.latem, "prod/KEY_1").unwrap().unwrap();
            assert_eq!(&entry.value[..], b"value 1");
            assert!(vault.collection("ssh").is_err(), "no scope on ssh");
        }

        // A later write reaches it in the next session, which it opens this time.
        p.admin
            .lock()
            .unwrap()
            .set(p.latem, "prod/NEW", Kind::Var, b"fresh")
            .unwrap();
        let (opened, _) = session(joined, admin, Duration::from_secs(2), async |_| {}).await;
        assert_eq!(opened.received, 1);
        let entry = p
            .joined
            .lock()
            .unwrap()
            .get(p.latem, "prod/NEW")
            .unwrap()
            .unwrap();
        assert_eq!(&entry.value[..], b"fresh");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn notices_reach_a_running_session() {
        let p = pair(1).await;
        let admin = (&p.admin_node, &p.admin);
        let joined = (&p.joined_node, &p.joined);
        let admin_store = p.admin.clone();
        let latem = p.latem;
        let (opened, _) = session(
            admin,
            joined,
            Duration::from_secs(3),
            async move |notices| {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                admin_store
                    .lock()
                    .unwrap()
                    .set(latem, "prod/LIVE", Kind::Var, b"now")
                    .unwrap();
                notices
                    .send(Notice::Changed(SetId::records(latem)))
                    .await
                    .unwrap();
            },
        )
        .await;
        assert!(opened.sent >= 4, "{opened:?}");
        let entry = p
            .joined
            .lock()
            .unwrap()
            .get(p.latem, "prod/LIVE")
            .unwrap()
            .unwrap();
        assert_eq!(&entry.value[..], b"now");
    }

    /// A session goes quiet once it has caught up, has work again when a notice brings some, and
    /// goes quiet again once that's sent, all while it stays open (sync.md, quiet).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_says_when_it_has_caught_up() {
        let p = pair(1).await;
        let idle = Duration::from_secs(5);
        let (accept_tx, accept_rx) = mpsc::channel(8);
        let accept_store = p.joined.clone();
        let endpoint = p.joined_node.endpoint().clone();
        let accepting = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            run(
                connection,
                Role::Accepter,
                accept_store,
                accept_rx,
                idle,
                |_| {},
            )
            .await
        });
        let id = iroh::EndpointId::from_bytes(&p.joined_node.id()).unwrap();
        let connection = p.admin_node.endpoint().connect(id, ALPN).await.unwrap();
        let (open_tx, open_rx) = mpsc::channel(8);
        let (heard_tx, mut heard) = mpsc::unbounded_channel();
        let opening = tokio::spawn(run(
            connection,
            Role::Opener,
            p.admin.clone(),
            open_rx,
            idle,
            move |report| {
                if let Report::Quiet(quiet) = report {
                    let _ = heard_tx.send(quiet);
                }
            },
        ));

        // It starts with work, so the first thing it says is that it caught up.
        assert_eq!(heard.recv().await, Some(true));
        assert_eq!(p.joined.lock().unwrap().list(p.latem).unwrap().len(), 1);

        p.admin
            .lock()
            .unwrap()
            .set(p.latem, "prod/LATER", Kind::Var, b"later")
            .unwrap();
        open_tx
            .send(Notice::Changed(SetId::records(p.latem)))
            .await
            .unwrap();
        assert_eq!(heard.recv().await, Some(false));
        assert_eq!(heard.recv().await, Some(true));
        assert_eq!(p.joined.lock().unwrap().list(p.latem).unwrap().len(), 2);

        // A notice for a set the two don't share sends nothing, so it stays quiet until it
        // closes.
        open_tx
            .send(Notice::Changed(SetId::records(CollectionId::random())))
            .await
            .unwrap();
        drop(accept_tx);
        opening.await.unwrap().unwrap();
        accepting.await.unwrap().unwrap();
        assert_eq!(heard.recv().await, None, "nothing after the last quiet");
    }

    /// A log notice for a head the session has sent already changes nothing, as when the session
    /// that took the entries hears of them from the device. Before 0.5.7 it started the roots
    /// over: the joined device's roots, which had come, were dropped, so the admin, which opened
    /// the session, didn't reconcile its next write.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_log_notice_for_a_head_already_sent_changes_nothing() {
        let p = pair(1).await;
        // Long enough to go quiet after the notices even if the joined device answers nothing.
        let idle = Duration::from_secs(6);
        let (accept_tx, accept_rx) = mpsc::channel(8);
        let accept_store = p.joined.clone();
        let endpoint = p.joined_node.endpoint().clone();
        let accepting = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            run(
                connection,
                Role::Accepter,
                accept_store,
                accept_rx,
                idle,
                |_| {},
            )
            .await
        });
        let id = iroh::EndpointId::from_bytes(&p.joined_node.id()).unwrap();
        let connection = p.admin_node.endpoint().connect(id, ALPN).await.unwrap();
        let (open_tx, open_rx) = mpsc::channel(8);
        let (heard_tx, mut heard) = mpsc::unbounded_channel();
        let opening = tokio::spawn(run(
            connection,
            Role::Opener,
            p.admin.clone(),
            open_rx,
            idle,
            move |report| {
                let _ = heard_tx.send(report);
            },
        ));
        // Caught up, so each side has the other's roots.
        assert_eq!(heard.recv().await, Some(Report::Quiet(true)));

        open_tx.send(Notice::Log).await.unwrap();
        p.admin
            .lock()
            .unwrap()
            .set(p.latem, "prod/LATER", Kind::Var, b"later")
            .unwrap();
        open_tx
            .send(Notice::Changed(SetId::records(p.latem)))
            .await
            .unwrap();
        // Only the write wakes the session.
        assert_eq!(heard.recv().await, Some(Report::Quiet(false)));
        assert_eq!(heard.recv().await, Some(Report::Quiet(true)));
        assert_eq!(
            p.joined.lock().unwrap().list(p.latem).unwrap().len(),
            2,
            "the write reached the joined device"
        );

        drop((open_tx, accept_tx));
        opening.await.unwrap().unwrap();
        accepting.await.unwrap().unwrap();
        assert_eq!(heard.recv().await, None, "no log entries came");
    }

    /// The side that takes log entries it didn't have reports them, once per message that
    /// brought some. The side that sent them, and a later session with nothing new, report none.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_reports_log_entries_new_to_the_device() {
        let p = pair(0).await;
        let ssh = p.admin.lock().unwrap().collection("ssh").unwrap();
        let joined_device = p.joined.lock().unwrap().device_id();
        p.admin
            .lock()
            .unwrap()
            .set_scope(
                joined_device,
                ssh,
                Scope::Read,
                &p.recovery.admin_signing_key(),
            )
            .unwrap();
        for round in 0..2 {
            let (accept_tx, accept_rx) = mpsc::channel(8);
            let accept_store = p.joined.clone();
            let endpoint = p.joined_node.endpoint().clone();
            let (joined_tx, mut joined_heard) = mpsc::unbounded_channel();
            let accepting = tokio::spawn(async move {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                run(
                    connection,
                    Role::Accepter,
                    accept_store,
                    accept_rx,
                    Duration::from_secs(2),
                    move |report| {
                        let _ = joined_tx.send(report);
                    },
                )
                .await
            });
            let id = iroh::EndpointId::from_bytes(&p.joined_node.id()).unwrap();
            let connection = p.admin_node.endpoint().connect(id, ALPN).await.unwrap();
            let (open_tx, open_rx) = mpsc::channel(8);
            let (admin_tx, mut admin_heard) = mpsc::unbounded_channel();
            let opened = run(
                connection,
                Role::Opener,
                p.admin.clone(),
                open_rx,
                Duration::from_secs(2),
                move |report| {
                    let _ = admin_tx.send(report);
                },
            )
            .await
            .unwrap();
            drop((open_tx, accept_tx));
            let accepted = accepting.await.unwrap().unwrap();
            let logs = |heard: &mut mpsc::UnboundedReceiver<Report>| {
                std::iter::from_fn(|| heard.try_recv().ok())
                    .filter(|report| *report == Report::Log)
                    .count()
            };
            assert_eq!(logs(&mut admin_heard), 0, "round {round}");
            if round == 0 {
                assert!(accepted.log_received > 0, "{accepted:?}");
                assert_eq!(opened.log_sent, accepted.log_received);
                assert_eq!(logs(&mut joined_heard), 1, "one message of entries");
            } else {
                assert_eq!(accepted.log_received, 0, "{accepted:?}");
                assert_eq!(logs(&mut joined_heard), 0, "nothing new");
            }
        }
        assert_eq!(
            p.joined.lock().unwrap().membership().unwrap().head(),
            p.admin.lock().unwrap().membership().unwrap().head()
        );
    }

    /// A session ends once both sides know the peer was revoked, even when the revoked device has
    /// the newest log, as it would from a device that hadn't yet applied the revocation.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_ends_when_its_peer_is_revoked() {
        let p = pair(1).await;
        let idle = Duration::from_secs(10);
        let (accept_tx, accept_rx) = mpsc::channel(8);
        let accept_store = p.joined.clone();
        let endpoint = p.joined_node.endpoint().clone();
        let accepting = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            run(
                connection,
                Role::Accepter,
                accept_store,
                accept_rx,
                idle,
                |_| {},
            )
            .await
        });
        let id = iroh::EndpointId::from_bytes(&p.joined_node.id()).unwrap();
        let connection = p.admin_node.endpoint().connect(id, ALPN).await.unwrap();
        let (open_tx, open_rx) = mpsc::channel(8);
        let opening = tokio::spawn(run(
            connection,
            Role::Opener,
            p.admin.clone(),
            open_rx,
            idle,
            |_| {},
        ));
        tokio::time::sleep(Duration::from_secs(1)).await;

        let joined = p.joined.lock().unwrap().device_id();
        let entries = {
            let mut admin = p.admin.lock().unwrap();
            let head = admin.membership().unwrap().head().0;
            admin
                .revoke_device(joined, &p.recovery.admin_signing_key())
                .unwrap();
            admin.log_from(head + 1, 64).unwrap()
        };
        p.joined.lock().unwrap().append_log(&entries).unwrap();
        open_tx.send(Notice::Log).await.unwrap();
        accept_tx.send(Notice::Log).await.unwrap();

        for side in [opening, accepting] {
            let result = tokio::time::timeout(Duration::from_secs(5), side)
                .await
                .expect("the session ended")
                .unwrap();
            assert!(
                matches!(result, Err(SyncError::Refused(Reason::NotAMember))),
                "{result:?}"
            );
        }
    }

    /// A connection the peer closes because the two already have a session ends with
    /// `Duplicate`, which the device doesn't count as a failure.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_duplicate_connection_ends_without_a_failure() {
        let p = pair(0).await;
        let endpoint = p.joined_node.endpoint().clone();
        let accepting = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            close_duplicate(&connection);
        });
        let id = iroh::EndpointId::from_bytes(&p.joined_node.id()).unwrap();
        let connection = p.admin_node.endpoint().connect(id, ALPN).await.unwrap();
        let (_notices, rx) = mpsc::channel(1);
        let result = run(
            connection,
            Role::Opener,
            p.admin.clone(),
            rx,
            Duration::from_secs(5),
            |_| {},
        )
        .await;
        assert!(matches!(result, Err(SyncError::Duplicate)), "{result:?}");
        accepting.await.unwrap();
    }

    /// Notices that arrive while a long items message is still coming in leave it whole.
    #[tokio::test(flavor = "multi_thread")]
    async fn notices_during_a_long_message_leave_it_whole() {
        let p = pair(0).await;
        {
            let mut admin = p.admin.lock().unwrap();
            for i in 0..12u8 {
                admin
                    .set(
                        p.latem,
                        &format!("big/{i}"),
                        Kind::Secret,
                        &vec![i; 512 * 1024],
                    )
                    .unwrap();
            }
        }
        let admin = (&p.admin_node, &p.admin);
        let joined = (&p.joined_node, &p.joined);
        // A set the two don't share: each notice wakes the session and does nothing else.
        let elsewhere = Notice::Changed(SetId::records(CollectionId::random()));
        let (opened, _) = session(
            joined,
            admin,
            Duration::from_secs(2),
            async move |notices| {
                for _ in 0..2000 {
                    if notices.send(elsewhere).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_micros(200)).await;
                }
            },
        )
        .await;
        // The twelve records, the collection record and four grants.
        assert_eq!(opened.received, 12 + 1 + 4);
        assert_eq!(summaries(&p.joined, p.latem), summaries(&p.admin, p.latem));
    }

    /// More than 32 items on each side, overlapping, settles through fingerprints and splits.
    #[tokio::test(flavor = "multi_thread")]
    async fn large_sets_settle_through_fingerprints() {
        let p = pair(100).await;
        let set = SetId::records(p.latem);
        // Give the joined device 40 of the records and the grants first.
        {
            let admin = p.admin.lock().unwrap();
            let mut joined = p.joined.lock().unwrap();
            for grant in admin
                .set_items(
                    SetId::GRANTS,
                    &admin.set_ids(SetId::GRANTS, &[0; 32], None).unwrap(),
                )
                .unwrap()
            {
                joined.receive(SetId::GRANTS, &grant).unwrap();
            }
            let ids = admin.set_ids(set, &[0; 32], None).unwrap();
            let some: Vec<ItemId> = ids.iter().step_by(2).take(40).copied().collect();
            for item in admin.set_items(set, &some).unwrap() {
                joined.receive(set, &item).unwrap();
            }
        }
        let admin = (&p.admin_node, &p.admin);
        let joined = (&p.joined_node, &p.joined);
        session(joined, admin, Duration::from_secs(2), async |_| {}).await;
        let (admin_records, _) = summaries(&p.admin, p.latem);
        let (joined_records, _) = summaries(&p.joined, p.latem);
        assert_eq!(admin_records.count, 101);
        assert_eq!(joined_records, admin_records);
        let listed = p.joined.lock().unwrap().list(p.latem).unwrap().len();
        assert_eq!(listed, 100);
    }

    /// A store that can hold up its next read of a set's ids until the test lets it go. A device
    /// answering a reconcile reads its ids first, so its answer waits too.
    struct Holding {
        store: Arc<Store>,
        hold: Mutex<Option<Hold>>,
    }

    /// What a held read tells when it starts waiting, and what lets it go.
    type Hold = (
        tokio::sync::oneshot::Sender<()>,
        std::sync::mpsc::Receiver<()>,
    );

    impl SyncStore for Holding {
        fn hello(&self) -> openvault_core::Result<(VaultId, u64, Hash)> {
            self.store.hello()
        }

        fn log_from(&self, from: u64, max: u16) -> openvault_core::Result<Vec<LogEntry>> {
            self.store.log_from(from, max)
        }

        fn append_log(&self, entries: &[LogEntry]) -> openvault_core::Result<usize> {
            self.store.append_log(entries)
        }

        fn member(&self, endpoint: &EndpointKey) -> Option<DeviceId> {
            self.store.member(endpoint)
        }

        fn shared_sets(&self, peer: DeviceId) -> Vec<SetId> {
            self.store.shared_sets(peer)
        }

        fn summary(&self, set: SetId) -> openvault_core::Result<Summary> {
            self.store.summary(set)
        }

        fn ids(
            &self,
            set: SetId,
            lower: &ItemId,
            upper: Option<&ItemId>,
        ) -> openvault_core::Result<Vec<ItemId>> {
            let hold = self.hold.lock().unwrap().take();
            if let Some((waiting, release)) = hold {
                let _ = waiting.send(());
                let _ = release.recv();
            }
            self.store.ids(set, lower, upper)
        }

        fn items(&self, set: SetId, ids: &[ItemId]) -> openvault_core::Result<Vec<Vec<u8>>> {
            self.store.items(set, ids)
        }

        fn receive(&self, set: SetId, item: &[u8]) -> openvault_core::Result<Received> {
            self.store.receive(set, item)
        }
    }

    /// A session the admin opened with the joined device, still running.
    struct Live {
        opening: tokio::task::JoinHandle<Result<Outcome, SyncError>>,
        accepting: tokio::task::JoinHandle<Result<Outcome, SyncError>>,
        notices: (mpsc::Sender<Notice>, mpsc::Sender<Notice>),
    }

    impl Live {
        /// Whether either side has ended.
        fn ended(&self) -> bool {
            self.opening.is_finished() || self.accepting.is_finished()
        }

        /// Lets both sides go idle, and returns what each did.
        async fn end(self) -> (Result<Outcome, SyncError>, Result<Outcome, SyncError>) {
            drop(self.notices);
            (self.opening.await.unwrap(), self.accepting.await.unwrap())
        }
    }

    /// Opens a session from the admin to the joined device and, once it has caught up, makes
    /// `change` to the admin's log while the joined device is part way through answering a
    /// reconcile of latem, as when a scope change lands during a live session. The admin's
    /// session acts on the change, starting its roots over, before the answer arrives: the
    /// joined device sent it under the older log.
    async fn change_mid_answer(p: &Pair, change: impl FnOnce(&mut Vault<SoftwareKeys>)) -> Live {
        let idle = Duration::from_secs(5);
        let holding = Arc::new(Holding {
            store: p.joined.clone(),
            hold: Mutex::new(None),
        });
        let (accept_tx, accept_rx) = mpsc::channel(8);
        let accept_store = holding.clone();
        let endpoint = p.joined_node.endpoint().clone();
        let accepting = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            run(
                connection,
                Role::Accepter,
                accept_store,
                accept_rx,
                idle,
                |_| {},
            )
            .await
        });
        let id = iroh::EndpointId::from_bytes(&p.joined_node.id()).unwrap();
        let connection = p.admin_node.endpoint().connect(id, ALPN).await.unwrap();
        // Room for one notice, so a send returns only once the session has taken the one before.
        let (open_tx, open_rx) = mpsc::channel(1);
        let (heard_tx, mut heard) = mpsc::unbounded_channel();
        let opening = tokio::spawn(run(
            connection,
            Role::Opener,
            p.admin.clone(),
            open_rx,
            idle,
            move |report| {
                if let Report::Quiet(quiet) = report {
                    let _ = heard_tx.send(quiet);
                }
            },
        ));
        assert_eq!(heard.recv().await, Some(true), "caught up");

        // A write to latem: the admin sends its root and reconciles it, and the joined device's
        // answer waits.
        let (waiting_tx, waiting) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        *holding.hold.lock().unwrap() = Some((waiting_tx, release_rx));
        p.admin
            .lock()
            .unwrap()
            .set(p.latem, "prod/LATER", Kind::Var, b"later")
            .unwrap();
        open_tx
            .send(Notice::Changed(SetId::records(p.latem)))
            .await
            .unwrap();
        waiting.await.unwrap();

        change(&mut p.admin.lock().unwrap());
        open_tx.send(Notice::Log).await.unwrap();
        // A notice that does nothing, twice: the second send returns once the session has taken
        // the first, so it has finished acting on the log's.
        let nothing = Notice::Changed(SetId::records(CollectionId::random()));
        open_tx.send(nothing).await.unwrap();
        open_tx.send(nothing).await.unwrap();
        release.send(()).unwrap();
        Live {
            opening,
            accepting,
            notices: (open_tx, accept_tx),
        }
    }

    /// A scope change that newly shares a set, landing during a live session, leaves the session
    /// up, and the set syncs in it. The answer the joined device sent under the older log is
    /// still taken (sync.md, after a log change).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_scope_change_during_a_session_shares_its_set_in_it() {
        let p = pair(1).await;
        let ssh = p.admin.lock().unwrap().collection("ssh").unwrap();
        p.admin
            .lock()
            .unwrap()
            .set(ssh, "deploy/KEY", Kind::Secret, b"ssh key")
            .unwrap();
        let joined = p.joined.lock().unwrap().device_id();
        let admin_key = p.recovery.admin_signing_key();
        let live = change_mid_answer(&p, |admin| {
            admin
                .set_scope(joined, ssh, Scope::Read, &admin_key)
                .unwrap();
        })
        .await;

        let read = || {
            let mut vault = p.joined.lock().unwrap();
            let ssh = vault.collection("ssh").ok()?;
            vault.get(ssh, "deploy/KEY").ok().flatten()
        };
        let synced = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(entry) = read() {
                    return Some(entry);
                }
                if live.ended() {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("ssh reached the joined device within 10 seconds");
        let Some(entry) = synced else {
            panic!("the session ended: {:?}", live.end().await);
        };
        assert_eq!(&entry.value[..], b"ssh key");
        let later = p
            .joined
            .lock()
            .unwrap()
            .get(p.latem, "prod/LATER")
            .unwrap()
            .expect("the held answer was answered");
        assert_eq!(&later.value[..], b"later");

        let (opened, accepted) = live.end().await;
        let (opened, accepted) = (opened.unwrap(), accepted.unwrap());
        assert_eq!((opened.log_sent, accepted.log_received), (1, 1));
        assert_eq!(opened.dropped + accepted.dropped, 0);
    }

    /// A scope change that takes a set away, landing while the joined device is asking for that
    /// set's items, serves nothing more from it (design §9, serving): the admin goes by its
    /// current log, not the one the request was made under. The session stays up.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_set_taken_away_during_a_session_is_no_longer_served() {
        let p = pair(1).await;
        let joined = p.joined.lock().unwrap().device_id();
        let admin_key = p.recovery.admin_signing_key();
        let latem = p.latem;
        let live = change_mid_answer(&p, |admin| {
            admin
                .set_scope(joined, latem, Scope::None, &admin_key)
                .unwrap();
        })
        .await;
        let (opened, accepted) = live.end().await;
        let (opened, accepted) = (opened.unwrap(), accepted.unwrap());
        // The set_scope and the rotation of latem's key.
        assert_eq!((opened.log_sent, accepted.log_received), (2, 2));
        let (admin_records, _) = summaries(&p.admin, latem);
        let (joined_records, _) = summaries(&p.joined, latem);
        assert_eq!(
            joined_records.count + 1,
            admin_records.count,
            "the record it asked for wasn't sent"
        );
        let admin = p.admin.lock().unwrap().device_id();
        assert!(
            !p.joined
                .lock()
                .unwrap()
                .shared_sets(admin)
                .contains(&SetId::records(latem))
        );
    }

    /// A device revoked while it's answering a reconcile has its session ended with "not a
    /// member" when the answer arrives, and is sent nothing more.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_revoked_during_an_answer_has_its_session_ended() {
        let p = pair(1).await;
        let joined = p.joined.lock().unwrap().device_id();
        let admin_key = p.recovery.admin_signing_key();
        let live = change_mid_answer(&p, |admin| {
            admin.revoke_device(joined, &admin_key).unwrap();
        })
        .await;
        for side in [live.opening, live.accepting] {
            let result = tokio::time::timeout(Duration::from_secs(5), side)
                .await
                .expect("the session ended")
                .unwrap();
            assert!(
                matches!(result, Err(SyncError::Refused(Reason::NotAMember))),
                "{result:?}"
            );
        }
        let (admin_records, _) = summaries(&p.admin, p.latem);
        let (joined_records, _) = summaries(&p.joined, p.latem);
        assert_eq!(joined_records.count + 1, admin_records.count);
    }
}
