//! Running sync sessions (sync.md, when devices sync): one at a time with each visible member,
//! started when it becomes visible, after a local write to a set it shares, and after the log
//! changes. There are no timers besides the retries of sessions that failed. With a coordinator
//! configured, members are dialed through the grandfather's relay as well as directly
//! (coordinator.md, devices).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openvault_core::sets::SetId;
use openvault_core::{DeviceId, Vault};
use openvault_keystore::Keys;
use openvault_net::sync::{self, Notice, Outcome, Role, SyncError};
use openvault_net::{EndpointAddr, EndpointId, EndpointKey, Node, RelayUrl};
use tokio::sync::{broadcast, mpsc};
use tokio::task::AbortHandle;
use tracing::{debug, info, warn};

use crate::api::{Event, Peer, PeerState};

/// The first retry after a failed session, doubling to [`LAST_RETRY`] (sync.md, retries).
const FIRST_RETRY: Duration = Duration::from_secs(30);
const LAST_RETRY: Duration = Duration::from_secs(60 * 60);

pub(crate) struct Engine {
    node: Arc<Node>,
    vault: Arc<Mutex<Vault<Keys>>>,
    /// The grandfather's relay, if a coordinator is configured.
    relay: Option<RelayUrl>,
    /// What watching apps hear of (service.md, for apps).
    events: broadcast::Sender<Event>,
    state: Mutex<State>,
    next_id: AtomicU64,
}

#[derive(Default)]
struct State {
    sessions: HashMap<EndpointKey, Running>,
    /// The delay before the next retry, for peers whose last session failed.
    retries: HashMap<EndpointKey, Duration>,
    /// Why each peer's last session failed, and when the next try is due.
    failures: HashMap<EndpointKey, (String, Instant)>,
    /// When mDNS stopped showing each peer that has gone, since the service started.
    gone_at: HashMap<EndpointKey, Instant>,
    /// The connection to the coordinator, which says hello again when the log grows.
    coordinator: Option<mpsc::Sender<Notice>>,
}

struct Running {
    id: u64,
    notices: mpsc::Sender<Notice>,
    opened_here: bool,
    task: AbortHandle,
}

impl Engine {
    pub(crate) fn new(
        node: Arc<Node>,
        vault: Arc<Mutex<Vault<Keys>>>,
        relay: Option<RelayUrl>,
        events: broadcast::Sender<Event>,
    ) -> Arc<Self> {
        Arc::new(Self {
            node,
            vault,
            events,
            relay,
            state: Mutex::new(State::default()),
            next_id: AtomicU64::new(0),
        })
    }

    /// Starts a session with `peer` unless one is running or it isn't a member.
    pub(crate) fn dial(self: &Arc<Self>, peer: EndpointKey) {
        if self.member(&peer).is_none() {
            return;
        }
        let mut state = self.state.lock().expect("poisoned");
        if state.sessions.contains_key(&peer) {
            return;
        }
        let (notices, receive) = mpsc::channel(32);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let engine = self.clone();
        let task = tokio::spawn(async move {
            let result = match EndpointId::from_bytes(&peer) {
                Ok(remote) => match engine
                    .node
                    .endpoint()
                    .connect(engine.addr(remote), sync::ALPN)
                    .await
                {
                    Ok(connection) => {
                        sync::run(
                            connection,
                            Role::Opener,
                            engine.vault.clone(),
                            receive,
                            sync::IDLE,
                        )
                        .await
                    }
                    Err(e) => Err(SyncError::Connect(e.to_string())),
                },
                Err(e) => Err(SyncError::Connect(e.to_string())),
            };
            engine.finished(peer, id, result);
        });
        state.sessions.insert(
            peer,
            Running {
                id,
                notices,
                opened_here: true,
                task: task.abort_handle(),
            },
        );
        self.emit(Event::DEVICES);
    }

    /// Takes a connection a peer opened. If both opened one at the same time, the one opened by
    /// the device with the smaller endpoint id is kept (sync.md, who connects).
    pub(crate) fn accept(self: &Arc<Self>, connection: openvault_net::Connection) {
        let peer = *connection.remote_id().as_bytes();
        let mut state = self.state.lock().expect("poisoned");
        if let Some(existing) = state.sessions.get(&peer) {
            if !existing.opened_here || self.node.id() < peer {
                sync::close_duplicate(&connection);
                return;
            }
            existing.task.abort();
            state.sessions.remove(&peer);
        }
        let (notices, receive) = mpsc::channel(32);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let engine = self.clone();
        let task = tokio::spawn(async move {
            let result = sync::run(
                connection,
                Role::Accepter,
                engine.vault.clone(),
                receive,
                sync::IDLE,
            )
            .await;
            engine.finished(peer, id, result);
        });
        state.sessions.insert(
            peer,
            Running {
                id,
                notices,
                opened_here: false,
                task: task.abort_handle(),
            },
        );
        self.emit(Event::DEVICES);
    }

    /// A local write changed `set`: running sessions send it on, and visible members that share
    /// it without a session get one.
    pub(crate) fn changed(self: &Arc<Self>, set: SetId) {
        self.notify(Notice::Changed(set));
        for peer in self.visible_members() {
            let shares = {
                let vault = self.vault.lock().expect("poisoned");
                vault
                    .member_by_endpoint(&peer)
                    .is_some_and(|device| vault.shared_sets(device).contains(&set))
            };
            if shares {
                self.dial(peer);
            }
        }
    }

    /// The log has new entries: every visible member hears of them, and so does the coordinator.
    pub(crate) fn log_changed(self: &Arc<Self>) {
        self.log_grew();
        if let Some(coordinator) = &self.state.lock().expect("poisoned").coordinator {
            let _ = coordinator.try_send(Notice::Log);
        }
    }

    /// Entries from the coordinator grew the log: every visible member hears of them.
    pub(crate) fn log_grew(self: &Arc<Self>) {
        self.notify(Notice::Log);
        for peer in self.visible_members() {
            self.dial(peer);
        }
    }

    /// A peer stopped being visible: retries stop until it reappears (sync.md, retries).
    pub(crate) fn gone(&self, peer: &EndpointKey) {
        let mut state = self.state.lock().expect("poisoned");
        state.retries.remove(peer);
        state.failures.remove(peer);
        state.gone_at.insert(*peer, Instant::now());
    }

    /// Each of `members`' sync state (service.md, for apps).
    pub(crate) fn peers(&self, members: &[(DeviceId, EndpointKey)]) -> Vec<Peer> {
        let visible = self.node.visible();
        let state = self.state.lock().expect("poisoned");
        let now = Instant::now();
        members
            .iter()
            .map(|(device, key)| {
                let on_network = visible.contains(key);
                let failure = state.failures.get(key);
                Peer {
                    device: *device,
                    state: if state.sessions.contains_key(key) {
                        PeerState::Syncing
                    } else if failure.is_some() {
                        PeerState::Failing
                    } else if on_network {
                        PeerState::OnNetwork
                    } else {
                        PeerState::NotSeen
                    },
                    seen: if on_network {
                        Some(0)
                    } else {
                        state.gone_at.get(key).map(|at| {
                            u32::try_from(now.duration_since(*at).as_secs()).unwrap_or(u32::MAX - 1)
                        })
                    },
                    retry_in: failure.map_or(0, |(_, at)| {
                        u32::try_from(at.saturating_duration_since(now).as_secs())
                            .unwrap_or(u32::MAX)
                    }),
                    error: failure.map(|(error, _)| error.clone()).unwrap_or_default(),
                }
            })
            .collect()
    }

    /// Tells watching apps that `what` may have changed. Nobody watching isn't an error.
    fn emit(&self, what: u8) {
        let _ = self.events.send(Event {
            what,
            collections: Vec::new(),
        });
    }

    /// Where the coordinator's task hears of log changes.
    #[cfg(feature = "coordinator")]
    pub(crate) fn set_coordinator(&self, notices: mpsc::Sender<Notice>) {
        self.state.lock().expect("poisoned").coordinator = Some(notices);
    }

    fn notify(&self, notice: Notice) {
        let state = self.state.lock().expect("poisoned");
        for running in state.sessions.values() {
            let _ = running.notices.try_send(notice);
        }
    }

    /// How to reach `peer`: through the relay as well, if there is one, and wherever mDNS saw it.
    fn addr(&self, peer: EndpointId) -> EndpointAddr {
        match &self.relay {
            Some(url) => EndpointAddr::new(peer).with_relay_url(url.clone()),
            None => peer.into(),
        }
    }

    fn finished(self: &Arc<Self>, peer: EndpointKey, id: u64, result: Result<Outcome, SyncError>) {
        let name = self.name(&peer);
        let mut state = self.state.lock().expect("poisoned");
        if state
            .sessions
            .get(&peer)
            .is_some_and(|running| running.id == id)
        {
            state.sessions.remove(&peer);
        }
        match result {
            Ok(outcome) => {
                state.retries.remove(&peer);
                state.failures.remove(&peer);
                let mut what = Event::DEVICES;
                if outcome.received > 0 {
                    what |= Event::ENTRIES;
                }
                if outcome.log_received > 0 {
                    what |= Event::LOG;
                }
                self.emit(what);
                match describe(&outcome) {
                    Some(moved) => info!("synced with {name}: {moved}"),
                    None => debug!("synced with {name}: nothing new"),
                }
                if outcome.dropped > 0 {
                    warn!(
                        "dropped {} items from {name} that failed their checks",
                        outcome.dropped
                    );
                }
            }
            // Both devices connected at once and the other kept its own connection, which carries
            // the session (sync.md, who connects).
            Err(SyncError::Duplicate) => debug!("{name} already has a session with this device"),
            Err(error) => {
                let delay = *state.retries.get(&peer).unwrap_or(&FIRST_RETRY);
                state.retries.insert(peer, (delay * 2).min(LAST_RETRY));
                state
                    .failures
                    .insert(peer, (error.to_string(), Instant::now() + delay));
                self.emit(Event::DEVICES);
                warn!(
                    "sync with {name} failed: {error}; retrying in {}s if it stays visible",
                    delay.as_secs()
                );
                let engine = self.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let still_waiting = engine
                        .state
                        .lock()
                        .expect("poisoned")
                        .retries
                        .contains_key(&peer);
                    if still_waiting && engine.node.visible().contains(&peer) {
                        engine.dial(peer);
                    }
                });
            }
        }
    }

    fn visible_members(&self) -> Vec<EndpointKey> {
        self.node
            .visible()
            .into_iter()
            .filter(|peer| self.member(peer).is_some())
            .collect()
    }

    fn member(&self, peer: &EndpointKey) -> Option<DeviceId> {
        self.vault
            .lock()
            .expect("poisoned")
            .member_by_endpoint(peer)
    }

    fn name(&self, peer: &EndpointKey) -> String {
        let vault = self.vault.lock().expect("poisoned");
        vault
            .member_by_endpoint(peer)
            .and_then(|device| vault.device_name(device).ok().flatten())
            .map_or_else(|| "a device".to_owned(), |name| name.name)
    }
}

/// What a session moved, such as "received 28 records and grants; sent 2 log entries", or `None`
/// if nothing.
fn describe(outcome: &Outcome) -> Option<String> {
    let received = counts(outcome.log_received, outcome.received);
    let sent = counts(outcome.log_sent, outcome.sent);
    let parts: Vec<String> = [("received", received), ("sent", sent)]
        .into_iter()
        .filter_map(|(verb, counts)| counts.map(|counts| format!("{verb} {counts}")))
        .collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

fn counts(log_entries: usize, items: usize) -> Option<String> {
    let parts: Vec<String> = [
        (log_entries, "log entry", "log entries"),
        (items, "record or grant", "records and grants"),
    ]
    .into_iter()
    .filter(|&(n, ..)| n > 0)
    .map(|(n, one, many)| format!("{n} {}", if n == 1 { one } else { many }))
    .collect();
    (!parts.is_empty()).then(|| parts.join(" and "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_read_as_sentences() {
        let outcome = |log_received, received, log_sent, sent| Outcome {
            log_received,
            received,
            dropped: 0,
            log_sent,
            sent,
        };
        assert_eq!(describe(&outcome(0, 0, 0, 0)), None);
        assert_eq!(
            describe(&outcome(0, 28, 0, 0)).unwrap(),
            "received 28 records and grants"
        );
        assert_eq!(
            describe(&outcome(0, 0, 0, 28)).unwrap(),
            "sent 28 records and grants"
        );
        assert_eq!(
            describe(&outcome(2, 1, 1, 3)).unwrap(),
            "received 2 log entries and 1 record or grant; sent 1 log entry and 3 records and grants"
        );
    }
}
