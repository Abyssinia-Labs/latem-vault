//! Making a vault on this device, or joining one (join.md, commands): what `openvault init` and
//! `openvault join` do, without the terminal, so the apps do the same. The CLI prints and asks;
//! the apps show it.
//!
//! The joiner runs its own endpoint, because it has no vault for a service to hold yet.

use std::fs;
use std::future::Future;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use openvault_core::membership::{AdminKey as _, DeviceName};
use openvault_core::{DeviceId, Vault, transport_seed};
use openvault_crypto::RecoveryKey;
use openvault_keystore::{AdminKey, Backend, Keys};
use openvault_net::join::{self, JoinError, JoinerSession};
use openvault_net::{Node, Options};
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::{ADMIN_KEY, KEYS, VAULT};

/// The file that holds a joining device's id until the join completes, so joining again resumes
/// with the same identity (join.md, commands).
pub const JOINING: &str = "joining";
/// How long a code is shown for (join.md, the code).
pub const JOIN_TIME: Duration = Duration::from_secs(10 * 60);
/// Failed PAKE sessions before the joiner gives up.
pub const ATTEMPTS: usize = 3;

/// A vault made by [`create`], and the recovery key to show once.
pub struct Created {
    pub vault: Vault<Keys>,
    pub recovery: RecoveryKey,
    /// Whether this device got an admin key: only with the Secure Enclave.
    pub admin: bool,
}

/// Makes a vault in `dir` with this device as its first member. The device that creates the
/// vault administers it (design §14): a Mac with a Secure Enclave gets an admin key that asks for
/// Touch ID; anywhere else, the recovery phrase is the only admin key. `passphrase` is for
/// [`Backend::Passphrase`], and checked already.
pub fn create(
    dir: &Path,
    backend: Backend,
    passphrase: Option<&str>,
    name: &str,
) -> Result<Created> {
    if dir.join(VAULT).exists() {
        bail!("there is already a vault in {}", dir.display());
    }
    create_private_dir(dir)?;
    let keys_path = dir.join(KEYS);
    let keys = match (backend, passphrase) {
        (Backend::Passphrase, Some(passphrase)) => {
            Keys::create_with_passphrase(&keys_path, passphrase)?
        }
        (Backend::Passphrase, None) => bail!("keys behind a passphrase need one"),
        (backend, _) => Keys::create(&keys_path, backend)?,
    };
    let remove_files = || {
        let _ = fs::remove_file(&keys_path);
        let _ = fs::remove_file(dir.join(ADMIN_KEY));
    };
    let admin = match backend {
        Backend::SecureEnclave => {
            Some(AdminKey::create(&dir.join(ADMIN_KEY)).inspect_err(|_| remove_files())?)
        }
        Backend::Software | Backend::Passphrase => None,
    };
    let recovery = RecoveryKey::generate();
    let admin_key = admin.as_ref().map(|admin| admin.verifying_key());
    let vault = Vault::create(&dir.join(VAULT), keys, &recovery, name, admin_key)
        .inspect_err(|_| remove_files())?;
    Ok(Created {
        vault,
        recovery,
        admin: admin.is_some(),
    })
}

/// Whether `dir` holds a join begun earlier and not finished: a key file and the joining file,
/// but no vault.
pub fn join_in_progress(dir: &Path) -> bool {
    !dir.join(VAULT).exists() && dir.join(KEYS).exists() && dir.join(JOINING).exists()
}

/// Forgets a join in progress, so this device can make a vault, or join with other keys. An
/// admin who approved it already has a device in the log that never arrives, to revoke.
pub fn forget_join(dir: &Path) -> Result<()> {
    if !join_in_progress(dir) {
        bail!("{} has no join in progress", dir.display());
    }
    fs::remove_file(dir.join(KEYS))?;
    fs::remove_file(dir.join(JOINING))?;
    Ok(())
}

/// The keys and id of the join in progress, loaded with `load`, or new ones made with `backend`.
/// `new_passphrase` is asked only for new keys behind a passphrase.
pub fn joining_keys(
    dir: &Path,
    backend: Backend,
    new_passphrase: impl FnOnce() -> Result<Zeroizing<String>>,
    load: impl FnOnce(&Path) -> Result<Keys>,
) -> Result<(Keys, DeviceId)> {
    if dir.join(VAULT).exists() {
        bail!("this device is already in a vault ({})", dir.display());
    }
    let joining = dir.join(JOINING);
    let keys_path = dir.join(KEYS);
    if keys_path.exists() {
        let id = fs::read_to_string(&joining).with_context(|| {
            format!(
                "{} has a key file but no vault and no join in progress",
                dir.display()
            )
        })?;
        let device = id.trim().parse().context("the joining file is damaged")?;
        return Ok((load(&keys_path)?, device));
    }
    let passphrase = match backend {
        Backend::Passphrase => Some(new_passphrase()?),
        _ => None,
    };
    create_private_dir(dir)?;
    let keys = match &passphrase {
        Some(passphrase) => Keys::create_with_passphrase(&keys_path, passphrase)?,
        None => Keys::create(&keys_path, backend)?,
    };
    let device = DeviceId::random();
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options
        .open(&joining)
        .and_then(|mut file| writeln!(file, "{device}"));
    if let Err(e) = written {
        let _ = fs::remove_file(&keys_path);
        return Err(e).context("can't save the joining device's id");
    }
    Ok((keys, device))
}

/// What happens while a joiner waits, for whoever shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinProgress {
    /// An admin typed a wrong code; `left` more tries before the joiner gives up.
    WrongCode { left: usize },
    /// An admin's session failed for another reason.
    Failed(String),
    /// The code matched, and the admin is choosing what this device may open.
    CodeAccepted,
}

/// Announces this device as waiting to join, on an endpoint of its own, and answers admins until
/// one completes the join, three sessions fail, 10 minutes pass, or `stop` finishes. On success
/// the vault is in `dir` and the joining file is gone; otherwise the keys and the joining file
/// stay, so joining again resumes with the same identity.
pub async fn join(
    dir: &Path,
    keys: Keys,
    device: DeviceId,
    name: &DeviceName,
    code: &str,
    progress: impl FnMut(JoinProgress),
    stop: impl Future<Output = ()>,
) -> Result<Vault<Keys>> {
    name.check()?;
    let options = Options {
        alpns: vec![join::ALPN.to_vec()],
        announcement: Some(join::announcement(name)),
        ..Options::default()
    };
    let (node, _events) = Node::start(&transport_seed(&keys), options).await?;
    let result = tokio::select! {
        result = accept_join(dir, &node, keys, device, name, code, progress) => result,
        () = stop => Err(anyhow!("stopped waiting")),
    };
    node.close().await;
    let vault = result?;
    let _ = fs::remove_file(dir.join(JOINING));
    Ok(vault)
}

/// Answers admins until one completes the join, three sessions fail, or the time is up.
async fn accept_join(
    dir: &Path,
    node: &Node,
    keys: Keys,
    device: DeviceId,
    name: &DeviceName,
    code: &str,
    mut progress: impl FnMut(JoinProgress),
) -> Result<Vault<Keys>> {
    let deadline = Instant::now() + JOIN_TIME;
    let mut failures = 0;
    loop {
        let incoming = tokio::select! {
            incoming = node.endpoint().accept() => incoming.context("the endpoint closed")?,
            _ = tokio::time::sleep_until(deadline) => {
                bail!("no admin approved this device within 10 minutes");
            }
        };
        let Ok(connection) = incoming.await else {
            continue;
        };
        let mut session = match JoinerSession::accept(connection, node.id(), code).await {
            Ok(session) => session,
            Err(error) => {
                failures += 1;
                progress(match error {
                    JoinError::WrongCode => JoinProgress::WrongCode {
                        left: ATTEMPTS - failures,
                    },
                    other => JoinProgress::Failed(other.to_string()),
                });
                if failures == ATTEMPTS {
                    bail!("three join attempts failed");
                }
                continue;
            }
        };
        progress(JoinProgress::CodeAccepted);
        let request = openvault_core::join::JoinRequest::sign(
            session.session_id(),
            device,
            &keys,
            name.clone(),
        )?;
        let accepted = session.request(&request, deadline).await?;
        let (log, grants) = session.receive(accepted.head).await?;
        let path = dir.join(VAULT);
        return match Vault::join(&path, keys, device, name, accepted.head, &log, &grants) {
            Ok(vault) if vault.vault_id() == accepted.vault => {
                session.joined().await?;
                Ok(vault)
            }
            Ok(_) => {
                let _ = fs::remove_file(&path);
                session.fail("the log is another vault's").await;
                bail!("the admin sent another vault's log")
            }
            Err(error) => {
                session.fail(&error.to_string()).await;
                Err(anyhow!(error).context("the admin's vault didn't check out"))
            }
        };
    }
}

/// Makes `path` and its parents, readable only by this user.
pub fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(path)
        .with_context(|| format!("can't create {}", path.display()))
}
