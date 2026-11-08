//! `openvault service`: holds the vault open, runs the endpoint, and answers on the socket
//! (service.md).

use std::fs::{self, File, TryLockError};
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result, bail};
use openvault_core::{DeviceId, Vault, transport_seed};
use openvault_keystore::Keys;
use openvault_net::{EndpointKey, Event, Node, Options};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::api::{self, Request, Response};
use crate::handler::{self, Context, transport_endpoint};
use crate::{ADMIN_KEY, LOCK, SOCKET, VAULT};

struct Shared {
    vault: Mutex<Vault<Keys>>,
    admin_key: PathBuf,
    node: Node,
}

/// Runs the service for the vault in `dir` until Ctrl-C or SIGTERM. `keys` are the device's
/// keys, already unlocked. Must be called inside a tokio runtime.
pub async fn run(dir: &Path, keys: Keys) -> Result<()> {
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

    let (node, mut events) = Node::start(&seed, Options::default()).await?;
    drop(seed);
    info!(
        vault = %vault_id,
        device = %device_id,
        endpoint = %hex(&node.id()),
        "service running; socket {}",
        socket.display()
    );

    let shared = Arc::new(Shared {
        vault: Mutex::new(vault),
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
            Some(event) = events.recv() => {
                let shared = shared.clone();
                tokio::task::spawn_blocking(move || log_event(&shared, event));
            }
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = terminate.recv() => break Ok(()),
        }
    };

    let _ = fs::remove_file(&socket);
    info!("service stopped");
    if let Ok(shared) = Arc::try_unwrap(shared) {
        shared.node.close().await;
    }
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
    let visible = shared.node.visible();
    let mut vault = shared.vault.lock().expect("poisoned");
    // Another process may have written while the service wasn't looking (service.md, the
    // store).
    if let Err(e) = vault.refresh() {
        return Response::error(format!("{e:#}"));
    }
    handler::handle(
        &mut Context {
            vault: &mut vault,
            admin_key: &shared.admin_key,
            visible: Some(&visible),
        },
        request,
    )
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
