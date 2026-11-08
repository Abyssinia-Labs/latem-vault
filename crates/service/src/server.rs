//! `openvault service`: holds the vault open, runs the endpoint, and answers on the socket
//! (service.md).

use std::fs::{self, File, TryLockError};
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result, bail};
use openvault_core::sets::SetId;
use openvault_core::{DeviceId, Vault, transport_seed};
use openvault_keystore::Keys;
use openvault_net::{EndpointKey, Event, Node, Options};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::api::{self, Request, Response};
use crate::engine::Engine;
use crate::handler::{self, Context, transport_endpoint};
use crate::{ADMIN_KEY, LOCK, SOCKET, VAULT};

struct Shared {
    vault: Arc<Mutex<Vault<Keys>>>,
    admin_key: PathBuf,
    node: Arc<Node>,
    engine: Arc<Engine>,
}

/// What a request changed, which sync passes on.
enum Change {
    /// The records of the collection with this name.
    Records(String),
    Log,
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

    let options = Options {
        alpns: vec![openvault_net::sync::ALPN.to_vec()],
        ..Options::default()
    };
    let (node, mut events) = Node::start(&seed, options).await?;
    let node = Arc::new(node);
    drop(seed);
    info!(
        vault = %vault_id,
        device = %device_id,
        endpoint = %hex(&node.id()),
        "openvault {version} running; socket {}",
        socket.display()
    );

    let vault = Arc::new(Mutex::new(vault));
    let shared = Arc::new(Shared {
        engine: Engine::new(node.clone(), vault.clone()),
        vault,
        admin_key: dir.join(ADMIN_KEY),
        node,
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
                        Ok(connection) if connection.alpn() == openvault_net::sync::ALPN => {
                            shared.engine.accept(connection);
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
                        Event::Gone(peer) => shared.engine.gone(&peer),
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = terminate.recv() => break Ok(()),
        }
    };

    let _ = fs::remove_file(&socket);
    info!("service stopped");
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
    let change = match &request {
        Request::Set { collection, .. } | Request::Delete { collection, .. } => {
            Some(Change::Records(collection.clone()))
        }
        Request::CreateCollection { .. } | Request::Changed | Request::Revoke { .. } => {
            Some(Change::Log)
        }
        _ => None,
    };
    let visible = shared.node.visible();
    let (response, set) = {
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
                visible: Some(&visible),
            },
            request,
        );
        let set = match &change {
            Some(Change::Records(name)) => vault.collection(name).ok().map(SetId::records),
            _ => None,
        };
        (response, set)
    };
    if !matches!(response, Response::Error { .. }) {
        match (change, set) {
            (Some(Change::Records(_)), Some(set)) => shared.engine.changed(set),
            (Some(Change::Log), _) => shared.engine.log_changed(),
            _ => {}
        }
    }
    response
}

/// Logs a member that has become visible or gone, and other OpenVault endpoints at debug level.
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
            "OpenVault endpoint {} outside this vault {change}",
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
