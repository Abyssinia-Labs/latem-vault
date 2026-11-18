//! `latem-vault service`: holds the vault open, runs the endpoint, and answers on the socket
//! (service.md).

use std::collections::HashMap;
use std::fs::{self, File, TryLockError};
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use latem_vault_core::membership::{AdminKey as AdminKeyTrait, Scope};
use latem_vault_core::sets::SetId;
use latem_vault_core::{DeviceId, Vault, transport_seed};
use latem_vault_keystore::Keys;
use latem_vault_net::join::{self, AdminSession, JoinError};
use latem_vault_net::{EndpointKey, Event, Node, Options, Relay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::api::{self, ErrorCode, JoinRequestSummary, Joiner, Request, Response};
#[cfg(feature = "coordinator")]
use crate::coordinator;
use crate::engine::Engine;
use crate::fetch::Fetcher;
use crate::handler::{self, Context, transport_endpoint};
use crate::{ADMIN_KEY, LOCK, SOCKET, VAULT};

/// The most connections that watch at once (service.md, for apps).
const WATCHERS: usize = 16;
/// The most join sessions open at once, and how long one lasts: the code's lifetime (join.md).
const JOIN_SESSIONS: usize = 4;
const JOIN_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Wrong codes a joiner allows before it stops (join.md).
const CODE_TRIES: u8 = 3;

struct Shared {
    vault: Arc<Mutex<Vault<Keys>>>,
    admin_key: PathBuf,
    node: Arc<Node>,
    engine: Arc<Engine>,
    fetcher: Arc<Fetcher>,
    version: String,
    /// What watching apps hear of.
    events: broadcast::Sender<api::Event>,
    watchers: AtomicUsize,
    joins: Mutex<Joins>,
}

/// Joins an app or the CLI is in the middle of (service.md, for apps).
#[derive(Default)]
struct Joins {
    sessions: HashMap<u32, (AdminSession, Instant)>,
    next: u32,
    /// Wrong codes so far for each joiner, until it announces again.
    tries: HashMap<EndpointKey, u8>,
}

/// What a request changed, which sync or fetching passes on.
enum Change {
    /// The records of the collection with this name.
    Records(String),
    Log,
    /// The collection with this name is kept: it gets the chunks it's missing.
    Kept(String),
}

/// Runs the service for the vault in `dir` until Ctrl-C or SIGTERM. `keys` are the device's
/// keys, already unlocked, and `version` is this build's, for the log. Must be called inside a
/// tokio runtime.
pub async fn run(dir: &Path, keys: Keys, version: &str) -> Result<()> {
    // Held until the service exits, so a second service for the same vault refuses to start.
    let lock = File::create(dir.join(LOCK))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            bail!(
                "a service is already running for the vault in {}",
                dir.display()
            )
        }
        Err(TryLockError::Error(e)) => return Err(e.into()),
    }

    let seed = transport_seed(&keys);
    let vault = Vault::open(&dir.join(VAULT), keys)?;
    let (vault_id, device_id) = (vault.vault_id(), vault.device_id());

    // Any socket here is left over from a service that crashed: the lock says none is running.
    let socket = dir.join(SOCKET);
    match fs::remove_file(&socket) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("can't remove the old socket"),
    }
    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("can't listen on {}", socket.display()))?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;

    #[cfg(feature = "coordinator")]
    let coordinator = crate::configured_coordinator(dir)?;
    #[cfg(not(feature = "coordinator"))]
    let coordinator: Option<latem_vault_net::coord::Address> = {
        let file = dir.join(crate::COORDINATOR);
        if file.exists() {
            warn!(
                "this build leaves out the coordinator (cargo feature `coordinator`), so {} is \
                 ignored: other devices are found on the local network only",
                file.display()
            );
        }
        None
    };
    let relay = coordinator.as_ref().map(|address| address.relay_url());
    let options = Options {
        alpns: vec![
            latem_vault_net::sync::ALPN.to_vec(),
            latem_vault_net::chunks::ALPN.to_vec(),
        ],
        relay: relay.clone().map(Relay::new),
        ..Options::default()
    };
    let (node, mut events) = Node::start(&seed, options).await?;
    let node = Arc::new(node);
    drop(seed);
    info!(
        vault = %vault_id,
        device = %device_id,
        endpoint = %hex(&node.id()),
        "latem-vault {version} running; socket {}",
        socket.display()
    );

    let vault = Arc::new(Mutex::new(vault));
    let app_events = broadcast::channel(64).0;
    let fetcher = Fetcher::new(
        node.clone(),
        vault.clone(),
        relay.clone(),
        app_events.clone(),
    );
    let shared = Arc::new(Shared {
        engine: Engine::new(
            node.clone(),
            vault.clone(),
            relay,
            app_events.clone(),
            fetcher.clone(),
        ),
        fetcher,
        vault,
        admin_key: dir.join(ADMIN_KEY),
        node,
        version: version.to_owned(),
        events: app_events,
        watchers: AtomicUsize::new(0),
        joins: Mutex::new(Joins::default()),
    });
    // Chunks that went unreferenced 30 days ago go now, a batch at a time (files.md, dropping
    // chunks), so requests get the vault between batches.
    {
        let vault = shared.vault.clone();
        tokio::task::spawn_blocking(move || sweep(&vault));
    }
    #[cfg(feature = "coordinator")]
    let keeping = coordinator.map(|address| {
        info!("using the coordinator and relay at {}", address.hostname);
        tokio::spawn(coordinator::keep(
            address,
            shared.node.clone(),
            shared.vault.clone(),
            shared.engine.clone(),
        ))
    });
    let mut terminate = signal(SignalKind::terminate())?;
    let result = loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve(&shared, stream).await {
                            warn!("local API connection failed: {e:#}");
                        }
                    });
                }
                Err(e) => break Err(e).context("can't accept on the socket"),
            },
            Some(incoming) = shared.node.endpoint().accept() => {
                let shared = shared.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(connection) if connection.alpn() == latem_vault_net::sync::ALPN => {
                            shared.engine.accept(connection);
                        }
                        Ok(connection) if connection.alpn() == latem_vault_net::chunks::ALPN => {
                            let served = latem_vault_net::chunks::serve(
                                connection,
                                shared.vault.clone(),
                                latem_vault_net::chunks::IDLE,
                            )
                            .await;
                            match served {
                                Ok(0) => {}
                                Ok(sent) => info!(sent, "sent chunks to another device"),
                                Err(e) => warn!("a chunk request failed: {e}"),
                            }
                        }
                        Ok(connection) => connection.close(0u32.into(), b"unknown protocol"),
                        Err(e) => debug!("an incoming connection failed: {e}"),
                    }
                });
            }
            Some(event) = events.recv() => {
                let shared = shared.clone();
                tokio::task::spawn_blocking(move || {
                    log_event(&shared, event);
                    match event {
                        Event::Visible(peer) => shared.engine.dial(peer),
                        Event::Gone(peer) => {
                            shared.engine.gone(&peer);
                            // A joiner that announces again gets new tries.
                            shared.joins.lock().expect("poisoned").tries.remove(&peer);
                        }
                    }
                    emit(&shared, api::Event::DEVICES | api::Event::JOINERS, Vec::new());
                });
            }
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = terminate.recv() => break Ok(()),
        }
    };

    let _ = fs::remove_file(&socket);
    info!("service stopped");
    // Closing the endpoint ends the coordinator's connection, which isn't a failure to retry.
    #[cfg(feature = "coordinator")]
    if let Some(keeping) = keeping {
        keeping.abort();
    }
    shared.node.close().await;
    drop(lock);
    result
}

/// Answers one request on `stream`.
async fn serve(shared: &Arc<Shared>, mut stream: UnixStream) -> Result<()> {
    // The socket is 0600 in a 0700 directory; this also refuses a process running as anyone
    // else that got hold of a connection.
    let uid = match stream.peer_cred() {
        Ok(cred) => cred.uid(),
        // A probe that has already hung up: the CLI checking whether the service runs.
        Err(e) if e.kind() == ErrorKind::NotConnected => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    // SAFETY: geteuid has no preconditions and can't fail.
    if uid != unsafe { libc::geteuid() } {
        bail!("refused a connection from uid {uid}");
    }

    let mut prefix = [0; 4];
    match stream.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    let response = match api::message_len(prefix) {
        Ok(len) => {
            let mut message = Zeroizing::new(vec![0; len]);
            stream.read_exact(&mut message).await?;
            let (kind, body) = api::split(message)?;
            match Request::decode(kind, &body) {
                // It keeps the connection (service.md, for apps).
                Ok(Request::Watch) => return watch(shared, stream).await,
                Ok(Request::Joiners) => joiners(shared),
                Ok(Request::CheckCode { joiner, code }) => check_code(shared, joiner, code).await,
                Ok(Request::Approve {
                    session,
                    scopes,
                    recovery_phrase,
                }) => approve(shared, session, scopes, recovery_phrase).await,
                Ok(Request::Refuse { session }) => refuse(shared, session).await,
                Ok(Request::Fetch { collection, name }) => {
                    match shared.fetcher.file(&collection, &name).await {
                        Ok(missing) => Response::Fetched { missing },
                        Err(e) => Response::error(format!("{e:#}")),
                    }
                }
                Ok(request) => {
                    let shared = shared.clone();
                    tokio::task::spawn_blocking(move || answer(&shared, request)).await?
                }
                Err(e) => Response::error(e.to_string()),
            }
        }
        Err(e) => Response::error(e.to_string()),
    };
    stream.write_all(&response.encode()).await?;
    stream.shutdown().await?;
    Ok(())
}

fn answer(shared: &Shared, request: Request) -> Response {
    match request {
        Request::Status => {
            return Response::Status {
                version: shared.version.clone(),
                pid: std::process::id(),
                // One node per service process, so the process's count is the service's.
                mdns_stops: u32::try_from(latem_vault_net::discovery_stops()).unwrap_or(u32::MAX),
            };
        }
        Request::Peers => return peers(shared),
        _ => {}
    }
    let change = match &request {
        Request::Set { collection, .. } | Request::Delete { collection, .. } => {
            Some(Change::Records(collection.clone()))
        }
        Request::CreateCollection { .. }
        | Request::Changed
        | Request::Revoke { .. }
        | Request::SetScope { .. }
        | Request::SetScopes { .. } => Some(Change::Log),
        Request::Placement {
            collection,
            set: Some(latem_vault_core::Placement::Keep),
        } => Some(Change::Kept(collection.clone())),
        _ => None,
    };
    // Touch ID is asked for before the vault is locked, so sessions and other requests go on
    // while its dialog is open (service.md, asking for Touch ID).
    let approved = if handler::signed_by_admin(&request) {
        match handler::approve_first(
            &shared.vault,
            |vault| handler::admin_reason(vault, &request),
            handler::admin_key_for(&shared.admin_key),
        ) {
            Ok(approved) => approved,
            Err(error) => return handler::error_response(error),
        }
    } else {
        None
    };
    let visible = shared.node.visible();
    let (response, set, kept) = {
        let mut vault = shared.vault.lock().expect("poisoned");
        // Another process may have written while the service wasn't looking (service.md, the
        // store).
        if let Err(e) = vault.refresh() {
            return Response::error(format!("{e:#}"));
        }
        let response = handler::handle(
            &mut Context {
                vault: &mut vault,
                admin_key: &shared.admin_key,
                admin: approved.as_ref().map(|key| key as &dyn AdminKeyTrait),
                visible: Some(&visible),
            },
            request,
        );
        let set = match &change {
            Some(Change::Records(name)) => vault.collection(name).ok().map(SetId::records),
            _ => None,
        };
        let kept = match &change {
            Some(Change::Kept(name)) => vault.collection(name).ok(),
            _ => None,
        };
        (response, set, kept)
    };
    if !matches!(response, Response::Error { .. }) {
        match (change, set) {
            (Some(Change::Records(name)), Some(set)) => {
                shared.engine.changed(set);
                emit(shared, api::Event::ENTRIES, vec![name]);
            }
            (Some(Change::Kept(_)), _) => {
                if let Some(collection) = kept {
                    shared.fetcher.kept(collection);
                }
            }
            (Some(Change::Log), _) => {
                shared.engine.log_changed();
                // A new key can carry entries over (sync.md, revoking and reducing scopes).
                emit(
                    shared,
                    api::Event::LOG | api::Event::DEVICES | api::Event::ENTRIES,
                    Vec::new(),
                );
            }
            _ => {}
        }
    }
    response
}

/// Sweeps chunks that are due until none are left, releasing the vault between batches.
fn sweep(vault: &Mutex<Vault<Keys>>) {
    let mut deleted = 0;
    loop {
        match vault.lock().expect("poisoned").sweep_chunks() {
            Ok(swept) => {
                deleted += swept.deleted;
                if !swept.more {
                    break;
                }
            }
            Err(e) => {
                warn!("sweeping chunks failed: {e:#}");
                break;
            }
        }
    }
    if deleted > 0 {
        info!(deleted, "swept chunks no file has named for 30 days");
    }
}

/// Tells watching apps that `what` may have changed. Nobody watching isn't an error.
fn emit(shared: &Shared, what: u8, collections: Vec<String>) {
    let _ = shared.events.send(api::Event { what, collections });
}

/// Sends events on `stream` until the client closes it or the service stops.
async fn watch(shared: &Arc<Shared>, mut stream: UnixStream) -> Result<()> {
    if shared.watchers.fetch_add(1, Ordering::Relaxed) >= WATCHERS {
        shared.watchers.fetch_sub(1, Ordering::Relaxed);
        let refused = Response::error(format!("{WATCHERS} connections are watching already"));
        stream.write_all(&refused.encode()).await?;
        return Ok(());
    }
    let result = send_events(shared, &mut stream).await;
    shared.watchers.fetch_sub(1, Ordering::Relaxed);
    match result {
        // The app went away.
        Err(e) if matches!(e.kind(), ErrorKind::BrokenPipe | ErrorKind::ConnectionReset) => Ok(()),
        result => Ok(result?),
    }
}

async fn send_events(shared: &Shared, stream: &mut UnixStream) -> std::io::Result<()> {
    let mut events = shared.events.subscribe();
    stream.write_all(&Response::Done.encode()).await?;
    let mut byte = [0; 1];
    loop {
        tokio::select! {
            event = events.recv() => {
                let event = match event {
                    Ok(event) => event,
                    // Some were missed, so anything may have changed.
                    Err(RecvError::Lagged(_)) => api::Event {
                        what: api::Event::ENTRIES
                            | api::Event::LOG
                            | api::Event::DEVICES
                            | api::Event::JOINERS,
                        collections: Vec::new(),
                    },
                    Err(RecvError::Closed) => return Ok(()),
                };
                stream.write_all(&Response::Event(event).encode()).await?;
            }
            // The client sends nothing more, so a byte or the end both stop the watch.
            _ = stream.read(&mut byte) => return Ok(()),
        }
    }
}

/// Each member's sync state, this device and revoked ones aside.
fn peers(shared: &Shared) -> Response {
    let members: Vec<(DeviceId, EndpointKey)> = {
        let mut vault = shared.vault.lock().expect("poisoned");
        if let Err(e) = vault.refresh() {
            return Response::error(format!("{e:#}"));
        }
        let this = vault.device_id();
        vault
            .membership()
            .map(|m| {
                m.devices()
                    .filter(|d| !d.revoked && d.info.id != this)
                    .filter_map(|d| Some((d.info.id, transport_endpoint(&d.info.transport_key)?)))
                    .collect()
            })
            .unwrap_or_default()
    };
    Response::Peers(shared.engine.peers(&members))
}

/// The endpoints whose mDNS announcement says they're waiting to join (join.md).
fn joiners(shared: &Shared) -> Response {
    Response::Joiners(
        shared
            .node
            .announcements()
            .into_iter()
            .filter_map(|(endpoint, announcement)| {
                let (platform, name) = join::parse_announcement(&announcement)?;
                Some(Joiner {
                    endpoint,
                    platform,
                    name,
                })
            })
            .collect(),
    )
}

/// Runs the PAKE with `joiner`, and keeps the session for approve or refuse.
async fn check_code(shared: &Shared, joiner: EndpointKey, code: Zeroizing<String>) -> Response {
    {
        let mut joins = shared.joins.lock().expect("poisoned");
        // Dropping a session closes its connection, which the joiner takes as a refusal.
        joins
            .sessions
            .retain(|_, (_, started)| started.elapsed() < JOIN_LIFETIME);
        if joins.sessions.len() >= JOIN_SESSIONS {
            return Response::error(format!("{JOIN_SESSIONS} joins are waiting already"));
        }
        if joins.tries.get(&joiner).copied().unwrap_or(0) >= CODE_TRIES {
            return Response::error(
                "three wrong codes; run `latem-vault join` on the device again".to_owned(),
            );
        }
    }
    match AdminSession::start(shared.node.endpoint(), joiner, &code).await {
        Ok(session) => {
            let request = session.request().clone();
            let mut joins = shared.joins.lock().expect("poisoned");
            joins.tries.remove(&joiner);
            let id = joins.next;
            joins.next = joins.next.wrapping_add(1);
            joins.sessions.insert(id, (session, Instant::now()));
            Response::JoinRequest(JoinRequestSummary {
                session: id,
                device: request.device,
                hardware: request.is_hardware(),
                platform: request.name.platform,
                name: request.name.name,
            })
        }
        Err(JoinError::WrongCode) => {
            let mut joins = shared.joins.lock().expect("poisoned");
            let tries = joins.tries.entry(joiner).or_insert(0);
            *tries += 1;
            match CODE_TRIES - *tries {
                0 => Response::error(
                    "three wrong codes; run `latem-vault join` on the device again".to_owned(),
                ),
                left => Response::Error {
                    code: ErrorCode::WrongCode,
                    message: format!(
                        "wrong code; {left} {} left",
                        if left == 1 { "try" } else { "tries" }
                    ),
                },
            }
        }
        Err(e) => Response::error(e.to_string()),
    }
}

/// Approves a session's join, then sends the joiner the log and grants (join.md, approval).
async fn approve(
    shared: &Arc<Shared>,
    session: u32,
    scopes: Vec<(String, Scope)>,
    recovery_phrase: Option<Zeroizing<String>>,
) -> Response {
    let Some((admin_session, started)) = shared
        .joins
        .lock()
        .expect("poisoned")
        .sessions
        .remove(&session)
    else {
        return Response::error(format!(
            "there's no join session {session}; check the code again"
        ));
    };
    let request = admin_session.request().clone();
    let signed = {
        let shared = shared.clone();
        tokio::task::spawn_blocking(move || {
            // Touch ID first, with the vault unlocked, as for other requests (service.md, asking
            // for Touch ID).
            let approved = handler::approve_first(
                &shared.vault,
                |vault| Ok(Some(handler::joining(vault, &request, &scopes)?.1)),
                handler::admin_key_for(&shared.admin_key),
            )?;
            let mut vault = shared.vault.lock().expect("poisoned");
            vault.refresh()?;
            let approval = handler::approve_join(
                &mut vault,
                &shared.admin_key,
                approved.as_ref().map(|key| key as &dyn AdminKeyTrait),
                &request,
                &scopes,
                recovery_phrase.as_deref().map(String::as_str),
            )?;
            Ok::<_, anyhow::Error>((vault.vault_id(), approval))
        })
        .await
    };
    let (vault_id, approval) = match signed {
        Ok(Ok(signed)) => signed,
        Ok(Err(error)) => {
            let response = handler::error_response(error);
            if let Response::Error {
                code: ErrorCode::RecoveryPhraseNeeded,
                ..
            } = response
            {
                // The CLI or the app asks for the phrase and sends approve again.
                shared
                    .joins
                    .lock()
                    .expect("poisoned")
                    .sessions
                    .insert(session, (admin_session, started));
            } else if let Response::Error { message, .. } = &response {
                admin_session.refuse(message).await;
            }
            return response;
        }
        Err(e) => return Response::error(e.to_string()),
    };
    // The approval is in the log either way, and syncs; the joiner can start over if this fails.
    let finished = admin_session
        .finish(vault_id, &approval.log, &approval.grants)
        .await;
    shared.engine.log_changed();
    emit(
        shared,
        api::Event::LOG | api::Event::DEVICES | api::Event::JOINERS,
        Vec::new(),
    );
    match finished {
        Ok(()) => Response::Done,
        Err(e) => Response::error(format!(
            "approved, but the device didn't get the log: {e}; run `latem-vault join` on it again"
        )),
    }
}

/// Tells a session's joiner it wasn't approved.
async fn refuse(shared: &Shared, session: u32) -> Response {
    let removed = shared
        .joins
        .lock()
        .expect("poisoned")
        .sessions
        .remove(&session);
    match removed {
        Some((admin_session, _)) => {
            admin_session.refuse("not approved").await;
            Response::Done
        }
        None => Response::error(format!("there's no join session {session}")),
    }
}

/// Logs a member that has become visible or gone, and other latem vault endpoints at debug level.
fn log_event(shared: &Shared, event: Event) {
    let (key, change) = match event {
        Event::Visible(key) => (key, "is visible"),
        Event::Gone(key) => (key, "is gone"),
    };
    let mut vault = shared.vault.lock().expect("poisoned");
    let _ = vault.refresh();
    match member(&vault, &key) {
        Some(device) => {
            let name = vault
                .device_name(device)
                .ok()
                .flatten()
                .map_or_else(|| device.to_string(), |name| name.name);
            info!("{name} {change}");
        }
        None => debug!(
            "latem vault endpoint {} outside this vault {change}",
            hex(&key)
        ),
    }
}

/// The device whose transport key is `key`, if it's in the log and not revoked.
fn member(vault: &Vault<Keys>, key: &EndpointKey) -> Option<DeviceId> {
    vault
        .membership()?
        .devices()
        .find(|d| {
            !d.revoked
                && d.info.id != vault.device_id()
                && transport_endpoint(&d.info.transport_key).as_ref() == Some(key)
        })
        .map(|d| d.info.id)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
