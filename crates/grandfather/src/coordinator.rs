//! The coordinator's side of `frozen::ALPN_COORD` (coordinator.md, coordinator): a session per
//! device connection, which brings the logs level and says hello again once they are, which tells
//! the device it can close.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use pinkvault_net::EndpointKey;
use pinkvault_net::coord::NO_LOG;
use pinkvault_net::frame::{self, FrameError, Reason};
use pinkvault_net::sync::SyncError;
use pinkvault_net::wire::{self, HELLO, LOG_BATCH, LOG_ENTRIES, LOG_REQUEST};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, info, warn};

use crate::store::Store;

/// How long a connection has to say hello.
const HELLO_WAIT: Duration = Duration::from_secs(10);
/// The most connections served at once: well above any vault's devices.
const MAX_SESSIONS: usize = 256;
/// The most log entries one session takes before the logs are level (sync.md's limit).
const MAX_LOG: usize = 4096;

pub(crate) struct Coordinator {
    store: Mutex<Store>,
    /// The relay's list, kept to the log copy's members.
    members: Arc<RwLock<HashSet<EndpointKey>>>,
    /// The session whose entries grew the log: every other session says hello again.
    grown: broadcast::Sender<u64>,
    next_id: AtomicU64,
    sessions: AtomicUsize,
}

impl Coordinator {
    pub(crate) fn new(store: Store) -> Arc<Self> {
        let members = Arc::new(RwLock::new(store.members()));
        Arc::new(Self {
            store: Mutex::new(store),
            members,
            grown: broadcast::channel(16).0,
            next_id: AtomicU64::new(0),
            sessions: AtomicUsize::new(0),
        })
    }

    pub(crate) fn members(&self) -> Arc<RwLock<HashSet<EndpointKey>>> {
        self.members.clone()
    }

    pub(crate) fn head(&self) -> Option<(u64, [u8; 32])> {
        self.store.lock().expect("poisoned").head()
    }

    /// Serves a device's connection until it closes or fails.
    pub(crate) async fn serve(self: Arc<Self>, connection: Connection) {
        let peer = *connection.remote_id().as_bytes();
        if self.sessions.fetch_add(1, Ordering::Relaxed) >= MAX_SESSIONS {
            self.sessions.fetch_sub(1, Ordering::Relaxed);
            warn!("refused a connection: {MAX_SESSIONS} are open already");
            connection.close(0u32.into(), b"busy");
            return;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let result = self.session(&connection, id).await;
        self.sessions.fetch_sub(1, Ordering::Relaxed);
        connection.close(0u32.into(), b"done");
        let short = short(&peer);
        match result {
            Ok(()) => debug!("{short} left"),
            Err(SyncError::Frame(FrameError::Connection(e))) => debug!("{short} left: {e}"),
            Err(e @ SyncError::Refused(Reason::NotAMember | Reason::WrongVault)) => {
                info!("refused {short}: {e}");
            }
            Err(e) => warn!("the session with {short} failed: {e}"),
        }
    }

    async fn session(&self, connection: &Connection, id: u64) -> Result<(), SyncError> {
        let (mut send, recv) = tokio::time::timeout(HELLO_WAIT, connection.accept_bi())
            .await
            .map_err(|_| SyncError::Connect("it opened no stream".into()))?
            .map_err(|e| SyncError::Connect(e.to_string()))?;
        let mut session = Session {
            coordinator: self,
            peer: *connection.remote_id().as_bytes(),
            id,
            send: &mut send,
            peer_head: None,
            requested: false,
            received: 0,
        };
        let result = session.drive(recv).await;
        if let Err(error) = &result
            && let Some(reason) = error.reason()
        {
            frame::send_error(&mut send, reason, &error.to_string()).await;
        }
        result
    }
}

struct Session<'a> {
    coordinator: &'a Coordinator,
    peer: EndpointKey,
    id: u64,
    send: &'a mut SendStream,
    peer_head: Option<(u64, [u8; 32])>,
    requested: bool,
    received: usize,
}

impl Session<'_> {
    async fn drive(&mut self, mut recv: RecvStream) -> Result<(), SyncError> {
        let mut grown = self.coordinator.grown.subscribe();
        self.send_hello().await?;
        let (kind, body) = tokio::time::timeout(HELLO_WAIT, frame::read(&mut recv))
            .await
            .map_err(|_| FrameError::Bad("no hello"))??;
        if kind != HELLO {
            return Err(FrameError::Bad("the first message isn't hello").into());
        }
        self.handle(kind, &body).await?;
        // One read stays in flight across the loop, as in a sync session.
        let mut reading = Box::pin(next_message(recv));
        loop {
            tokio::select! {
                (recv, message) = &mut reading => {
                    let (kind, body) = match message {
                        Ok(message) => message,
                        Err(FrameError::Peer { reason, .. }) => return Err(SyncError::Refused(reason)),
                        Err(e) => return Err(e.into()),
                    };
                    reading.set(next_message(recv));
                    self.handle(kind, &body).await?;
                }
                grew = grown.recv() => match grew {
                    Ok(origin) if origin == self.id => {}
                    Ok(_) | Err(RecvError::Lagged(_)) => self.send_hello().await?,
                    Err(RecvError::Closed) => return Ok(()),
                },
            }
        }
    }

    async fn handle(&mut self, kind: u8, body: &[u8]) -> Result<(), SyncError> {
        match kind {
            HELLO => {
                let (vault, seq, hash) = wire::parse_hello(body)?;
                if vault != self.store().vault() {
                    return Err(SyncError::Refused(Reason::WrongVault));
                }
                self.peer_head = Some((seq, hash));
            }
            LOG_REQUEST => {
                let (from, max) = wire::parse_log_request(body)?;
                self.require_member()?;
                let entries = self.store().log_from(from, max.min(LOG_BATCH))?;
                frame::write(self.send, LOG_ENTRIES, &wire::log_entries(&entries)).await?;
                return Ok(());
            }
            LOG_ENTRIES => {
                self.requested = false;
                let entries = wire::parse_log_entries(body)?;
                if entries.is_empty() {
                    return Err(FrameError::Bad("no log entries").into());
                }
                self.received += entries.len();
                if self.received > MAX_LOG {
                    return Err(FrameError::Bad("too many log entries").into());
                }
                let (new, head, members) = {
                    let mut store = self.store();
                    let new = store.append(&entries)?;
                    (new, store.head(), store.members())
                };
                if new > 0 {
                    if let Some((seq, _)) = head {
                        info!("the log is at entry {seq}, from {}", short(&self.peer));
                    }
                    *self.coordinator.members.write().expect("poisoned") = members;
                    let _ = self.coordinator.grown.send(self.id);
                }
            }
            _ => return Err(FrameError::Bad("unexpected message").into()),
        }
        self.progress().await
    }

    /// Requests entries while the device is ahead, or everything while this copy is empty. Once
    /// the logs are level, checks the device is a member and says hello.
    async fn progress(&mut self) -> Result<(), SyncError> {
        let Some((peer_seq, peer_hash)) = self.peer_head else {
            return Ok(());
        };
        let head = self.store().head();
        let from = match head {
            None => 0,
            Some((seq, _)) if peer_seq > seq => seq + 1,
            Some((seq, hash)) if peer_seq == seq => {
                if peer_hash != hash {
                    return Err(SyncError::Store(pinkvault_core::Error::Fork));
                }
                self.received = 0;
                self.require_member()?;
                return self.send_hello().await;
            }
            // The device is behind, and will ask; the request checks it's a member.
            Some(_) => return Ok(()),
        };
        if !self.requested {
            let max = u16::try_from(peer_seq - from)
                .map_or(LOG_BATCH, |n| n.saturating_add(1))
                .min(LOG_BATCH);
            frame::write(self.send, LOG_REQUEST, &wire::log_request(from, max)).await?;
            self.requested = true;
        }
        Ok(())
    }

    fn require_member(&self) -> Result<(), SyncError> {
        if self
            .coordinator
            .members
            .read()
            .expect("poisoned")
            .contains(&self.peer)
        {
            Ok(())
        } else {
            Err(SyncError::Refused(Reason::NotAMember))
        }
    }

    async fn send_hello(&mut self) -> Result<(), SyncError> {
        let (vault, (seq, hash)) = {
            let store = self.store();
            (store.vault(), store.head().unwrap_or((0, NO_LOG)))
        };
        frame::write(self.send, HELLO, &wire::hello(vault, seq, &hash)).await?;
        Ok(())
    }

    /// The store, for a call too quick to need a blocking section: the log copy is small, and
    /// writes come only with membership changes.
    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.coordinator.store.lock().expect("poisoned")
    }
}

async fn next_message(mut recv: RecvStream) -> (RecvStream, Result<(u8, Vec<u8>), FrameError>) {
    let message = frame::read(&mut recv).await;
    (recv, message)
}

/// The first bytes of an endpoint id, for the log.
pub(crate) fn short(key: &EndpointKey) -> String {
    key[..5].iter().map(|b| format!("{b:02x}")).collect()
}
