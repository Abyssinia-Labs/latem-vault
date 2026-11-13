//! Swift bindings to the service's local API, for the Mac app (service.md, for apps; design §16).
//!
//! The app is a client of the service, as the CLI is: [`Client`] sends each request on the
//! socket and turns the response into records Swift can use, and [`Client::watch`] keeps a
//! connection open and calls a Swift listener on each event. Every call blocks, so Swift makes
//! them off the main thread. Values cross into Swift as `Data`, where they can't be wiped.

use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use openvault_core::file::Manifest;
use openvault_core::membership::{DeviceName, Scope as CoreScope};
use openvault_core::{DeviceId, Kind as CoreKind, Placement as CorePlacement, env_file};
use openvault_crypto::pake;
use openvault_keystore::{Backend, Keys};
use openvault_service::api::{self, ErrorCode, Request, Response};
use openvault_service::{client, files, setup};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

/// This library's version, as `openvault --version` prints its number.
#[uniffi::export]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum OpenVaultError {
    /// No service answers on the socket.
    #[error("the OpenVault service isn't running")]
    NotRunning,
    /// Signing needs the recovery phrase: ask for it and call again with it.
    #[error("{message}")]
    RecoveryPhraseNeeded { message: String },
    /// A join code didn't match; the message says how many tries are left.
    #[error("{message}")]
    WrongCode { message: String },
    #[error("{message}")]
    Failed { message: String },
}

impl From<io::Error> for OpenVaultError {
    fn from(error: io::Error) -> Self {
        Self::Failed {
            message: error.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Scope {
    None,
    Hold,
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Kind {
    Secret,
    Variable,
    /// A file (files.md). Its bytes are read with `export_file`, and written with `write_file`.
    File,
}

/// Which of a collection's file chunks this device keeps (files.md, placement).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Placement {
    /// Every current file's chunks.
    Keep,
    /// The chunks of files read lately, up to 2 GiB.
    OnDemand,
}

#[derive(Debug, uniffi::Record)]
pub struct Status {
    pub version: String,
    pub pid: u32,
    pub mdns_stops: u32,
}

#[derive(Debug, uniffi::Record)]
pub struct VaultInfo {
    pub vault: String,
    pub device: String,
    /// The recovery key's fingerprint, such as `d06a 5f28`.
    pub recovery: String,
    pub log_head: u64,
    /// Whether this device has an admin key the log lists.
    pub admin: bool,
}

#[derive(Debug, uniffi::Record)]
pub struct DeviceScope {
    pub device: String,
    pub scope: Scope,
}

#[derive(Debug, uniffi::Record)]
pub struct CollectionSummary {
    pub name: String,
    pub secrets: u32,
    pub variables: u32,
    /// The collection's current key (epoch).
    pub key: u32,
    pub devices: Vec<DeviceScope>,
    #[uniffi(default = 0)]
    pub files: u32,
}

/// An entry as a list shows it: a variable's value, and never a secret's or a file's.
#[derive(uniffi::Record)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub set_by: String,
    pub key: u32,
    pub value: Option<Vec<u8>>,
    /// A file's length in bytes; 0 for the others.
    #[uniffi(default = 0)]
    pub size: u64,
    /// How many of a file's chunks aren't on this device: it can't be read until they're fetched.
    #[uniffi(default = 0)]
    pub missing: u32,
}

#[derive(uniffi::Record)]
pub struct Value {
    pub kind: Kind,
    pub value: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct NewEntry {
    pub name: String,
    pub kind: Kind,
    pub value: Vec<u8>,
}

#[derive(Debug, uniffi::Record)]
pub struct Device {
    pub id: String,
    pub this: bool,
    pub revoked: bool,
    pub visible: bool,
    pub hardware: bool,
    /// `None` when the name doesn't open: show the id instead.
    pub platform: Option<String>,
    pub name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PeerState {
    /// Not seen since the service started.
    NotSeen,
    /// On the network, or in a session that has caught up and only waits for more work.
    OnNetwork,
    /// In a session that is still moving something: one that hasn't gone 2 seconds without a
    /// message (sync.md, quiet).
    Syncing,
    /// Its last session failed.
    Failing,
}

#[derive(Debug, uniffi::Record)]
pub struct Peer {
    pub device: String,
    pub state: PeerState,
    /// Seconds since mDNS last showed it: 0 while it's on the network or in a session, `None`
    /// if never.
    pub seen: Option<u32>,
    pub retry_in: u32,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum LogChange {
    Genesis,
    AddDevice,
    SetScope,
    RevokeDevice,
    RotateKey,
    AddAdmin,
    RemoveAdmin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Signer {
    RecoveryKey,
    ThisDevice,
    OtherAdmin,
}

#[derive(Debug, uniffi::Record)]
pub struct LogLine {
    pub seq: u64,
    pub hash: String,
    pub change: LogChange,
    pub device: Option<String>,
    pub collection: Option<String>,
    pub scope: Scope,
    pub key: u32,
    pub signer: Signer,
}

#[derive(Debug, uniffi::Record)]
pub struct WatchEvent {
    pub entries: bool,
    pub log: bool,
    pub devices: bool,
    pub joiners: bool,
    /// For `entries`: the collections, or empty for any.
    pub collections: Vec<String>,
}

#[derive(Debug, uniffi::Record)]
pub struct Joiner {
    pub endpoint: Vec<u8>,
    pub platform: String,
    pub name: String,
}

#[derive(Debug, uniffi::Record)]
pub struct JoinRequest {
    pub session: u32,
    pub device: String,
    pub platform: String,
    pub name: String,
    pub hardware: bool,
}

#[derive(Debug, uniffi::Record)]
pub struct ScopeChange {
    pub collection: String,
    pub scope: Scope,
}

#[derive(Debug, uniffi::Record)]
pub struct ScopesSet {
    pub rotated: Vec<String>,
    pub granted: u32,
    pub carried: u32,
}

#[derive(Debug, uniffi::Record)]
pub struct Revoked {
    pub rotated: Vec<String>,
    pub carried: u32,
}

#[derive(Debug, uniffi::Record)]
pub struct CollectionNames {
    pub collection: String,
    pub names: Vec<String>,
}

#[derive(Debug, uniffi::Record)]
pub struct Review {
    /// Each collection the device can read, with its current secrets' names.
    pub secrets: Vec<CollectionNames>,
    /// Each collection the device can read, with its current files' names.
    pub files: Vec<CollectionNames>,
    /// Each collection's current entries the device wrote last.
    pub wrote_last: Vec<CollectionNames>,
}

/// Hears a watch's events (service.md, for apps).
#[uniffi::export(with_foreign)]
pub trait WatchListener: Send + Sync {
    fn on_event(&self, event: WatchEvent);
    /// The watch ended: `stop` was called, or the service stopped. `error` says what failed.
    fn on_end(&self, error: Option<String>);
}

/// One `NAME=value` line of a `.env` file.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct EnvLine {
    pub name: String,
    pub value: Vec<u8>,
    /// Where it is in the file, from 1.
    pub line: u32,
}

/// Reads a `.env` file as `openvault import-env` does, and so as latem does. If any line can't
/// be read, nothing is returned, and the error names the line but never shows it.
#[uniffi::export]
pub fn parse_env(file: Vec<u8>) -> Result<Vec<EnvLine>, OpenVaultError> {
    let file = Zeroizing::new(file);
    if file.len() > env_file::MAX_LEN {
        return Err(failed(format!(
            "the file is larger than {} bytes",
            env_file::MAX_LEN
        )));
    }
    let lines = env_file::parse(&file).map_err(|error| failed(error.to_string()))?;
    Ok(lines
        .into_iter()
        .map(|line| EnvLine {
            name: line.name,
            value: line.value.to_vec(),
            line: u32::try_from(line.number).unwrap_or(u32::MAX),
        })
        .collect())
}

/// How a device's keys are kept (keystore.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum KeyStorage {
    SecureEnclave,
    Software,
    /// Software keys behind a passphrase, which a service started at login has nobody to type.
    Passphrase,
}

/// What an openvault directory holds, read from its files without the service.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeviceHome {
    pub path: String,
    pub vault: bool,
    /// `None` without a key file.
    pub keys: Option<KeyStorage>,
    /// Whether a join was begun here and not finished: [`join_vault`] resumes it, and
    /// [`forget_join`] drops it.
    pub joining: bool,
}

/// The openvault directory `home`, or `OPENVAULT_HOME` or `~/.openvault` without one: whether it
/// holds a vault, and how its keys are kept. An app checks this before starting the service,
/// which can't run without a vault or ask for a passphrase.
#[uniffi::export]
pub fn device_home(home: Option<String>) -> Result<DeviceHome, OpenVaultError> {
    let home = locate(home)?;
    let keys = home.join(openvault_service::KEYS);
    let keys = match keys.exists() {
        false => None,
        true => Some(
            match openvault_keystore::backend_of(&keys).map_err(|e| failed(e.to_string()))? {
                Backend::SecureEnclave => KeyStorage::SecureEnclave,
                Backend::Software => KeyStorage::Software,
                Backend::Passphrase => KeyStorage::Passphrase,
            },
        ),
    };
    Ok(DeviceHome {
        path: home
            .to_str()
            .ok_or_else(|| failed(format!("{} isn't UTF-8", home.display())))?
            .to_owned(),
        vault: home.join(openvault_service::VAULT).exists(),
        keys,
        joining: setup::join_in_progress(&home),
    })
}

/// This computer's host name without `.local`, as a new device's name in the log.
#[uniffi::export]
pub fn default_device_name() -> String {
    openvault_service::default_device_name()
}

/// Whether this Mac has a Secure Enclave for a new device's keys, which `init` and `join` then
/// use unless told otherwise.
#[uniffi::export]
pub fn secure_enclave_available() -> bool {
    Backend::SecureEnclave.is_available()
}

/// A vault [`create_vault`] made.
#[derive(Debug, uniffi::Record)]
pub struct NewVault {
    pub vault: String,
    pub device: String,
    /// The recovery key's fingerprint, as [`VaultInfo`] gives it: `d06a 5f28`.
    pub recovery: String,
    /// The 24 words, to show once.
    pub phrase: String,
    /// Whether this device got an admin key: only with the Secure Enclave.
    pub admin: bool,
}

/// Makes a vault in `home` with this device as its first member, as `openvault init` does
/// (service.md, without the service). With the Secure Enclave the device gets an admin key too.
/// `passphrase` is for [`KeyStorage::Passphrase`]. No service runs yet; start one after.
#[uniffi::export]
pub fn create_vault(
    home: Option<String>,
    keys: KeyStorage,
    name: String,
    passphrase: Option<String>,
) -> Result<NewVault, OpenVaultError> {
    let home = locate(home)?;
    let passphrase = passphrase.map(Zeroizing::new);
    if let Some(passphrase) = &passphrase {
        openvault_keystore::check_passphrase(passphrase).map_err(|e| failed(e.to_string()))?;
    }
    DeviceName {
        platform: std::env::consts::OS.into(),
        name: name.clone(),
    }
    .check()
    .map_err(|e| failed(e.to_string()))?;
    let created = setup::create(
        &home,
        backend(keys),
        passphrase.as_ref().map(|p| p.as_str()),
        &name,
    )
    .map_err(|e| failed(format!("{e:#}")))?;
    let recovery = openvault_crypto::hash::hash(created.vault.recovery_key().as_bytes());
    Ok(NewVault {
        vault: created.vault.vault_id().to_string(),
        device: created.vault.device_id().to_string(),
        recovery: fingerprint(&recovery[..4]),
        phrase: created.recovery.to_phrase().to_string(),
        admin: created.admin,
    })
}

/// What happens while a joiner waits.
#[derive(Debug, uniffi::Enum)]
pub enum JoinProgress {
    /// An admin typed a wrong code; `left` more tries before the join ends.
    WrongCode { left: u8 },
    /// An admin's session failed for another reason.
    Failed { message: String },
    /// The code matched, and the admin is choosing what this device may open.
    CodeAccepted,
}

/// Hears a join's progress, on the library's thread.
#[uniffi::export(with_foreign)]
pub trait JoinListener: Send + Sync {
    fn on_progress(&self, progress: JoinProgress);
    /// Called once: `None` once this device is in the vault, otherwise why it isn't.
    fn on_end(&self, error: Option<String>);
}

/// A join [`join_vault`] started: the code to show, until the listener hears the end.
#[derive(uniffi::Object)]
pub struct Joining {
    code: Zeroizing<String>,
    device: String,
    stop: Mutex<Option<oneshot::Sender<()>>>,
}

#[uniffi::export]
impl Joining {
    /// The 6 digits to type on an admin device.
    pub fn code(&self) -> String {
        self.code.to_string()
    }

    /// This device's id, as the admin will see it.
    pub fn device(&self) -> String {
        self.device.clone()
    }

    /// Stops waiting; the listener hears that it stopped. Dropping the join stops it too.
    pub fn stop(&self) {
        if let Some(stop) = self.stop.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = stop.send(());
        }
    }
}

/// Starts joining a vault from `home`, as `openvault join` does: makes this device's keys with
/// `keys`, or loads those of a join in progress, and announces it on the local network with a
/// 6-digit code for an admin to type. It returns at once; the join runs on its own thread, on an
/// endpoint of its own, for up to 10 minutes. Once `listener` hears it ended without an error,
/// the vault is in `home`, and a service can start.
#[uniffi::export]
pub fn join_vault(
    home: Option<String>,
    keys: KeyStorage,
    name: String,
    passphrase: Option<String>,
    listener: Arc<dyn JoinListener>,
) -> Result<Arc<Joining>, OpenVaultError> {
    let home = locate(home)?;
    let name = DeviceName {
        platform: std::env::consts::OS.into(),
        name,
    };
    name.check().map_err(|e| failed(e.to_string()))?;
    let passphrase = passphrase.map(Zeroizing::new);
    let (keys, device) = setup::joining_keys(
        &home,
        backend(keys),
        || match &passphrase {
            Some(passphrase) => {
                openvault_keystore::check_passphrase(passphrase)?;
                Ok(passphrase.clone())
            }
            None => anyhow::bail!("keys behind a passphrase need one"),
        },
        |path| {
            Ok(match &passphrase {
                Some(passphrase) => Keys::load_with_passphrase(path, passphrase)?,
                None => Keys::load(path)?,
            })
        },
    )
    .map_err(|e| failed(format!("{e:#}")))?;
    let code = Zeroizing::new(pake::new_code());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (stop, stopped) = oneshot::channel();
    let joining = Arc::new(Joining {
        code: code.clone(),
        device: device.to_string(),
        stop: Mutex::new(Some(stop)),
    });
    std::thread::Builder::new()
        .name("openvault join".into())
        .spawn(move || {
            let progress = |progress| {
                listener.on_progress(match progress {
                    setup::JoinProgress::WrongCode { left } => {
                        JoinProgress::WrongCode { left: left as u8 }
                    }
                    setup::JoinProgress::Failed(message) => JoinProgress::Failed { message },
                    setup::JoinProgress::CodeAccepted => JoinProgress::CodeAccepted,
                })
            };
            let stopped = async {
                // A dropped sender stops the join as a sent stop does.
                let _ = stopped.await;
            };
            let joined = runtime.block_on(setup::join(
                &home, keys, device, &name, &code, progress, stopped,
            ));
            listener.on_end(joined.err().map(|e| format!("{e:#}")));
        })?;
    Ok(joining)
}

/// Forgets a join begun in `home` and not finished, so this device can make a vault, or join
/// with other keys.
#[uniffi::export]
pub fn forget_join(home: Option<String>) -> Result<(), OpenVaultError> {
    setup::forget_join(&locate(home)?).map_err(|e| failed(format!("{e:#}")))
}

fn backend(keys: KeyStorage) -> Backend {
    match keys {
        KeyStorage::SecureEnclave => Backend::SecureEnclave,
        KeyStorage::Software => Backend::Software,
        KeyStorage::Passphrase => Backend::Passphrase,
    }
}

/// A recovery fingerprint's 4 bytes as the screens show them: `d06a 5f28`.
fn fingerprint(bytes: &[u8]) -> String {
    format!(
        "{:02x}{:02x} {:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    )
}

/// `home`, or `OPENVAULT_HOME`, or `~/.openvault`, as the CLI finds it.
fn locate(home: Option<String>) -> Result<PathBuf, OpenVaultError> {
    Ok(match home.map(PathBuf::from) {
        Some(home) => home,
        None => match std::env::var_os("OPENVAULT_HOME") {
            Some(home) => PathBuf::from(home),
            None => std::env::home_dir()
                .ok_or_else(|| failed("can't find the home directory"))?
                .join(".openvault"),
        },
    })
}

/// The service of the vault in one openvault directory.
#[derive(uniffi::Object)]
pub struct Client {
    socket: PathBuf,
}

#[uniffi::export]
impl Client {
    /// The client for the vault in `home`, or in `OPENVAULT_HOME` or `~/.openvault` without one.
    #[uniffi::constructor]
    pub fn new(home: Option<String>) -> Result<Arc<Self>, OpenVaultError> {
        Ok(Arc::new(Self {
            socket: locate(home)?.join(openvault_service::SOCKET),
        }))
    }

    pub fn is_running(&self) -> bool {
        client::is_running(&self.socket)
    }

    pub fn status(&self) -> Result<Status, OpenVaultError> {
        match self.call(&Request::Status)? {
            Response::Status {
                version,
                pid,
                mdns_stops,
            } => Ok(Status {
                version,
                pid,
                mdns_stops,
            }),
            other => Err(unexpected(other)),
        }
    }

    pub fn vault(&self) -> Result<VaultInfo, OpenVaultError> {
        match self.call(&Request::Vault)? {
            Response::Vault(info) => Ok(VaultInfo {
                vault: info.vault.to_string(),
                device: info.device.to_string(),
                recovery: fingerprint(&info.recovery),
                log_head: info.log_head,
                admin: info.admin,
            }),
            other => Err(unexpected(other)),
        }
    }

    pub fn collections(&self) -> Result<Vec<CollectionSummary>, OpenVaultError> {
        match self.call(&Request::CollectionSummaries)? {
            Response::CollectionSummaries(summaries) => Ok(summaries
                .into_iter()
                .map(|summary| CollectionSummary {
                    name: summary.name,
                    secrets: summary.secrets,
                    variables: summary.variables,
                    files: summary.files,
                    key: summary.key,
                    devices: summary
                        .devices
                        .into_iter()
                        .map(|(device, scope)| DeviceScope {
                            device: device.to_string(),
                            scope: scope.into(),
                        })
                        .collect(),
                })
                .collect()),
            other => Err(unexpected(other)),
        }
    }

    pub fn create_collection(
        &self,
        name: String,
        recovery_phrase: Option<String>,
    ) -> Result<(), OpenVaultError> {
        done(self.call(&Request::CreateCollection {
            name,
            recovery_phrase: recovery_phrase.map(Into::into),
        })?)
    }

    /// A collection's current entries, with variables' values but never secrets'. Files come with
    /// their sizes and how many of their chunks aren't here, from the listing, which only a
    /// collection with files asks for.
    pub fn entries(&self, collection: String) -> Result<Vec<Entry>, OpenVaultError> {
        let details = match self.call(&Request::EntryDetails {
            collection: collection.clone(),
        })? {
            Response::EntryDetails(details) => details,
            other => return Err(unexpected(other)),
        };
        let files: HashMap<String, (u64, u32)> =
            if details.iter().any(|detail| detail.kind == CoreKind::File) {
                match self.call(&Request::List { collection })? {
                    Response::Listing(listed) => listed
                        .into_iter()
                        .filter(|listed| listed.kind == CoreKind::File)
                        .map(|listed| (listed.name, (listed.size, listed.missing)))
                        .collect(),
                    other => return Err(unexpected(other)),
                }
            } else {
                HashMap::new()
            };
        Ok(details
            .into_iter()
            .map(|detail| {
                let (size, missing) = files.get(&detail.name).copied().unwrap_or_default();
                Entry {
                    kind: detail.kind.into(),
                    value: (detail.kind == CoreKind::Var).then(|| detail.value.to_vec()),
                    name: detail.name,
                    set_by: detail.set_by.to_string(),
                    key: detail.key,
                    size,
                    missing,
                }
            })
            .collect())
    }

    /// A secret's or variable's value, or `None` if it doesn't exist or is a file, whose bytes
    /// `export_file` writes out instead.
    pub fn get(&self, collection: String, name: String) -> Result<Option<Value>, OpenVaultError> {
        match self.call(&Request::Get { collection, name })? {
            Response::Entry(value) => {
                Ok(value
                    .filter(|value| value.kind != CoreKind::File)
                    .map(|value| Value {
                        kind: value.kind.into(),
                        value: value.value.to_vec(),
                    }))
            }
            other => Err(unexpected(other)),
        }
    }

    /// Writes every entry in one transaction. Files are written with `write_file`.
    pub fn set(&self, collection: String, entries: Vec<NewEntry>) -> Result<(), OpenVaultError> {
        if entries.iter().any(|entry| entry.kind == Kind::File) {
            return Err(failed("files are written with write_file"));
        }
        let entries = entries
            .into_iter()
            .map(|entry| api::Item {
                name: entry.name,
                kind: entry.kind.into(),
                value: entry.value.into(),
            })
            .collect();
        done(self.call(&Request::Set {
            collection,
            entries,
        })?)
    }

    /// Returns whether there was one to delete.
    pub fn delete(&self, collection: String, name: String) -> Result<bool, OpenVaultError> {
        match self.call(&Request::Delete { collection, name })? {
            Response::Deleted(existed) => Ok(existed),
            other => Err(unexpected(other)),
        }
    }

    /// Gets the chunks of a file that aren't on this device from the devices that read its
    /// collection, and returns how many none of them had: 0 once it can be read (files.md,
    /// asking). It answers when it's done, which for a large file takes the transfer's time.
    pub fn fetch(&self, collection: String, name: String) -> Result<u64, OpenVaultError> {
        match self.call(&Request::Fetch { collection, name })? {
            Response::Fetched { missing } => Ok(missing),
            other => Err(unexpected(other)),
        }
    }

    /// Writes a file's bytes to `path`, readable only by this user (0700 if it's executable), with
    /// the time it was written, through a private file renamed into place once it's whole. Its
    /// chunks must be here: `fetch` first.
    pub fn export_file(
        &self,
        collection: String,
        name: String,
        path: String,
    ) -> Result<(), OpenVaultError> {
        let manifest = self.manifest(&collection, &name)?;
        let mut calls = Calls(self);
        files::write_out(
            Path::new(&path),
            manifest.executable,
            manifest.mtime,
            |file| files::write_contents(&mut calls, &collection, &manifest, file),
        )
        .map_err(from_anyhow)
    }

    /// Writes the file at `path` as `collection`/`name`: an import, or a save of a copy that was
    /// opened. Returns whether it wrote a version: a file whose contents and executable bit are
    /// the current version's is left as it is. It fails if the name is a secret's or a
    /// variable's.
    pub fn write_file(
        &self,
        collection: String,
        name: String,
        path: String,
    ) -> Result<bool, OpenVaultError> {
        files::write_file(&mut Calls(self), &collection, &name, Path::new(&path))
            .map(|written| written.is_some())
            .map_err(from_anyhow)
    }

    /// This device's placement for a collection, after setting it if `set` is given. Set to keep,
    /// the collection gets its missing chunks at once.
    pub fn placement(
        &self,
        collection: String,
        set: Option<Placement>,
    ) -> Result<Placement, OpenVaultError> {
        match self.call(&Request::Placement {
            collection,
            set: set.map(Into::into),
        })? {
            Response::Placement(placement) => Ok(placement.into()),
            other => Err(unexpected(other)),
        }
    }

    pub fn devices(&self) -> Result<Vec<Device>, OpenVaultError> {
        match self.call(&Request::Devices)? {
            Response::Devices(devices) => Ok(devices
                .into_iter()
                .map(|device| {
                    let (platform, name) = device.name.unzip();
                    Device {
                        id: device.id.to_string(),
                        this: device.this,
                        revoked: device.revoked,
                        visible: device.visible,
                        hardware: device.hardware,
                        platform,
                        name,
                    }
                })
                .collect()),
            other => Err(unexpected(other)),
        }
    }

    pub fn peers(&self) -> Result<Vec<Peer>, OpenVaultError> {
        match self.call(&Request::Peers)? {
            Response::Peers(peers) => Ok(peers
                .into_iter()
                .map(|peer| Peer {
                    device: peer.device.to_string(),
                    state: match peer.state {
                        api::PeerState::NotSeen => PeerState::NotSeen,
                        api::PeerState::OnNetwork => PeerState::OnNetwork,
                        api::PeerState::Syncing => PeerState::Syncing,
                        api::PeerState::Failing => PeerState::Failing,
                    },
                    seen: peer.seen,
                    retry_in: peer.retry_in,
                    error: (!peer.error.is_empty()).then_some(peer.error),
                })
                .collect()),
            other => Err(unexpected(other)),
        }
    }

    /// Up to `max` log entries from seq `from`, at most 256.
    pub fn log(&self, from: u64, max: u16) -> Result<Vec<LogLine>, OpenVaultError> {
        match self.call(&Request::Log { from, max })? {
            Response::Log(lines) => lines.into_iter().map(log_line).collect(),
            other => Err(unexpected(other)),
        }
    }

    /// What a device can read and wrote last, to show before revoking it.
    pub fn review(&self, device: String) -> Result<Review, OpenVaultError> {
        let device = device_id(&device)?;
        match self.call(&Request::Review { device })? {
            Response::Review(review) => Ok(Review {
                secrets: review
                    .secrets
                    .into_iter()
                    .map(|(collection, names)| CollectionNames { collection, names })
                    .collect(),
                files: review
                    .files
                    .into_iter()
                    .map(|(collection, names)| CollectionNames { collection, names })
                    .collect(),
                wrote_last: review
                    .wrote_last
                    .into_iter()
                    .map(|(collection, written)| CollectionNames {
                        collection,
                        names: written.into_iter().map(|entry| entry.name).collect(),
                    })
                    .collect(),
            }),
            other => Err(unexpected(other)),
        }
    }

    pub fn revoke(
        &self,
        device: String,
        recovery_phrase: Option<String>,
    ) -> Result<Revoked, OpenVaultError> {
        let device = device_id(&device)?;
        match self.call(&Request::Revoke {
            device,
            recovery_phrase: recovery_phrase.map(Into::into),
        })? {
            Response::Revoked { rotated, carried } => Ok(Revoked { rotated, carried }),
            other => Err(unexpected(other)),
        }
    }

    /// Several scope changes for one device, with one Touch ID prompt.
    pub fn set_scopes(
        &self,
        device: String,
        changes: Vec<ScopeChange>,
        recovery_phrase: Option<String>,
    ) -> Result<ScopesSet, OpenVaultError> {
        let device = device_id(&device)?;
        match self.call(&Request::SetScopes {
            device,
            changes: scope_list(changes),
            recovery_phrase: recovery_phrase.map(Into::into),
        })? {
            Response::ScopesSet {
                rotated,
                granted,
                carried,
            } => Ok(ScopesSet {
                rotated,
                granted,
                carried,
            }),
            other => Err(unexpected(other)),
        }
    }

    /// The devices waiting to join on this network, as their announcements say.
    pub fn joiners(&self) -> Result<Vec<Joiner>, OpenVaultError> {
        match self.call(&Request::Joiners)? {
            Response::Joiners(joiners) => Ok(joiners
                .into_iter()
                .map(|joiner| Joiner {
                    endpoint: joiner.endpoint.to_vec(),
                    platform: joiner.platform,
                    name: joiner.name,
                })
                .collect()),
            other => Err(unexpected(other)),
        }
    }

    /// Checks the code a joiner shows; on a match, what it asks to join as.
    pub fn check_code(
        &self,
        endpoint: Vec<u8>,
        code: String,
    ) -> Result<JoinRequest, OpenVaultError> {
        let joiner = endpoint
            .try_into()
            .map_err(|_| failed("an endpoint id is 32 bytes"))?;
        match self.call(&Request::CheckCode {
            joiner,
            code: code.into(),
        })? {
            Response::JoinRequest(request) => Ok(JoinRequest {
                session: request.session,
                device: request.device.to_string(),
                platform: request.platform,
                name: request.name,
                hardware: request.hardware,
            }),
            other => Err(unexpected(other)),
        }
    }

    pub fn approve(
        &self,
        session: u32,
        scopes: Vec<ScopeChange>,
        recovery_phrase: Option<String>,
    ) -> Result<(), OpenVaultError> {
        done(self.call(&Request::Approve {
            session,
            scopes: scope_list(scopes),
            recovery_phrase: recovery_phrase.map(Into::into),
        })?)
    }

    pub fn refuse(&self, session: u32) -> Result<(), OpenVaultError> {
        done(self.call(&Request::Refuse { session })?)
    }

    /// Calls `listener` on each event until [`Watch::stop`], or until the service stops.
    pub fn watch(&self, listener: Arc<dyn WatchListener>) -> Result<Arc<Watch>, OpenVaultError> {
        let mut stream = match UnixStream::connect(&self.socket) {
            Ok(stream) => stream,
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
                return Err(OpenVaultError::NotRunning);
            }
            Err(e) => return Err(e.into()),
        };
        api::write_message(&mut stream, &Request::Watch.encode())?;
        match read(&mut stream)? {
            Response::Done => {}
            other => return Err(unexpected(other)),
        }
        let reading = stream.try_clone()?;
        std::thread::Builder::new()
            .name("openvault watch".into())
            .spawn(move || listen(reading, listener))?;
        Ok(Arc::new(Watch { stream }))
    }
}

/// A watch's connection; stopping it, or dropping it, ends the watch.
#[derive(uniffi::Object)]
pub struct Watch {
    stream: UnixStream,
}

#[uniffi::export]
impl Watch {
    pub fn stop(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Client {
    /// A file's manifest: what it holds, or the chunks it's in.
    fn manifest(&self, collection: &str, name: &str) -> Result<Manifest, OpenVaultError> {
        match self.call(&Request::Get {
            collection: collection.into(),
            name: name.into(),
        })? {
            Response::Entry(Some(value)) if value.kind == CoreKind::File => {
                Manifest::decode(&value.value).map_err(|e| failed(e.to_string()))
            }
            Response::Entry(_) => Err(failed(format!("no file {collection}/{name}"))),
            other => Err(unexpected(other)),
        }
    }

    fn call(&self, request: &Request) -> Result<Response, OpenVaultError> {
        match client::call(&self.socket, request)? {
            Some(Response::Error { code, message }) => Err(match code {
                ErrorCode::RecoveryPhraseNeeded => OpenVaultError::RecoveryPhraseNeeded { message },
                ErrorCode::WrongCode => OpenVaultError::WrongCode { message },
                ErrorCode::Other => OpenVaultError::Failed { message },
            }),
            Some(response) => Ok(response),
            None => Err(OpenVaultError::NotRunning),
        }
    }
}

/// Reads events until the connection ends, then says why.
fn listen(mut stream: UnixStream, listener: Arc<dyn WatchListener>) {
    loop {
        match read(&mut stream) {
            Ok(Response::Event(event)) => listener.on_event(WatchEvent {
                entries: event.what & api::Event::ENTRIES != 0,
                log: event.what & api::Event::LOG != 0,
                devices: event.what & api::Event::DEVICES != 0,
                joiners: event.what & api::Event::JOINERS != 0,
                collections: event.collections,
            }),
            Ok(other) => {
                listener.on_end(Some(unexpected(other).to_string()));
                return;
            }
            // Stopped here, or the service went away: both end the watch quietly.
            Err(OpenVaultError::Failed { .. }) => {
                listener.on_end(None);
                return;
            }
            Err(error) => {
                listener.on_end(Some(error.to_string()));
                return;
            }
        }
    }
}

fn read(stream: &mut UnixStream) -> Result<Response, OpenVaultError> {
    let (kind, body) = api::read_message(stream).map_err(|e| failed(e.to_string()))?;
    Response::decode(kind, &body).map_err(|e| failed(e.to_string()))
}

fn log_line(line: api::LogLine) -> Result<LogLine, OpenVaultError> {
    let none = DeviceId::from_bytes([0; 16]);
    Ok(LogLine {
        seq: line.seq,
        hash: line.hash.iter().map(|b| format!("{b:02x}")).collect(),
        change: match line.change {
            0x01 => LogChange::Genesis,
            0x02 => LogChange::AddDevice,
            0x03 => LogChange::SetScope,
            0x04 => LogChange::RevokeDevice,
            0x05 => LogChange::RotateKey,
            0x06 => LogChange::AddAdmin,
            0x07 => LogChange::RemoveAdmin,
            other => return Err(failed(format!("unknown log entry type {other:#04x}"))),
        },
        device: (line.device != none).then(|| line.device.to_string()),
        collection: (!line.collection.is_empty()).then_some(line.collection),
        scope: line.scope.into(),
        key: line.key,
        signer: match line.signer {
            api::Signer::Recovery => Signer::RecoveryKey,
            api::Signer::ThisDevice => Signer::ThisDevice,
            api::Signer::OtherAdmin => Signer::OtherAdmin,
        },
    })
}

fn scope_list(changes: Vec<ScopeChange>) -> Vec<(String, CoreScope)> {
    changes
        .into_iter()
        .map(|change| (change.collection, change.scope.into()))
        .collect()
}

fn device_id(id: &str) -> Result<DeviceId, OpenVaultError> {
    id.parse()
        .map_err(|_| failed(format!("{id} isn't a device id")))
}

/// The client as the shared file code calls it (`openvault_service::files`).
struct Calls<'a>(&'a Client);

impl files::Caller for Calls<'_> {
    fn call(&mut self, request: Request) -> anyhow::Result<Response> {
        Ok(self.0.call(&request)?)
    }
}

/// Back from the shared file code: the service's own error if that's what it was.
fn from_anyhow(error: anyhow::Error) -> OpenVaultError {
    match error.downcast::<OpenVaultError>() {
        Ok(error) => error,
        Err(error) => failed(format!("{error:#}")),
    }
}

/// Why this Mac's disk isn't encrypted, or `None` if it is (FileVault). A file imported from an
/// unencrypted disk may stay on it in the clear after its original is deleted, so the app asks
/// first (files.md, import).
#[uniffi::export]
pub fn disk_not_encrypted() -> Option<String> {
    files::disk_encryption().err()
}

fn done(response: Response) -> Result<(), OpenVaultError> {
    match response {
        Response::Done => Ok(()),
        other => Err(unexpected(other)),
    }
}

fn unexpected(response: Response) -> OpenVaultError {
    failed(format!(
        "unexpected response from the service: {response:?}"
    ))
}

fn failed(message: impl Into<String>) -> OpenVaultError {
    OpenVaultError::Failed {
        message: message.into(),
    }
}

impl From<CoreScope> for Scope {
    fn from(scope: CoreScope) -> Self {
        match scope {
            CoreScope::None => Self::None,
            CoreScope::Hold => Self::Hold,
            CoreScope::Read => Self::Read,
            CoreScope::Write => Self::Write,
        }
    }
}

impl From<Scope> for CoreScope {
    fn from(scope: Scope) -> Self {
        match scope {
            Scope::None => Self::None,
            Scope::Hold => Self::Hold,
            Scope::Read => Self::Read,
            Scope::Write => Self::Write,
        }
    }
}

impl From<CoreKind> for Kind {
    fn from(kind: CoreKind) -> Self {
        match kind {
            CoreKind::Var => Self::Variable,
            CoreKind::File => Self::File,
            // Collection entries never cross the local API.
            CoreKind::Secret | CoreKind::Collection => Self::Secret,
        }
    }
}

impl From<Kind> for CoreKind {
    fn from(kind: Kind) -> Self {
        match kind {
            Kind::Secret => Self::Secret,
            Kind::Variable => Self::Var,
            Kind::File => Self::File,
        }
    }
}

impl From<CorePlacement> for Placement {
    fn from(placement: CorePlacement) -> Self {
        match placement {
            CorePlacement::Keep => Self::Keep,
            CorePlacement::OnDemand => Self::OnDemand,
        }
    }
}

impl From<Placement> for CorePlacement {
    fn from(placement: Placement) -> Self {
        match placement {
            Placement::Keep => Self::Keep,
            Placement::OnDemand => Self::OnDemand,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn log_lines_name_their_parts() {
        let device = DeviceId::random();
        let line = log_line(api::LogLine {
            seq: 10,
            hash: [0xab; 32],
            change: 0x03,
            device,
            collection: "latem".into(),
            scope: CoreScope::Read,
            key: 0,
            signer: api::Signer::ThisDevice,
        })
        .unwrap();
        assert_eq!(line.change, LogChange::SetScope);
        assert_eq!(line.device, Some(device.to_string()));
        assert_eq!(line.collection.as_deref(), Some("latem"));
        assert_eq!((line.scope, line.signer), (Scope::Read, Signer::ThisDevice));
        assert_eq!(line.hash, "ab".repeat(32));

        let genesis = log_line(api::LogLine {
            seq: 0,
            hash: [0; 32],
            change: 0x01,
            device: DeviceId::from_bytes([0; 16]),
            collection: String::new(),
            scope: CoreScope::None,
            key: 0,
            signer: api::Signer::Recovery,
        })
        .unwrap();
        assert_eq!((genesis.device, genesis.collection), (None, None));
    }

    #[test]
    fn env_files_read_as_import_env_reads_them() {
        let lines = parse_env(b"# latem\nREGION=eu-west\nTOKEN='a b'\n".to_vec()).unwrap();
        let read: Vec<_> = lines
            .iter()
            .map(|l| (l.name.as_str(), l.value.as_slice(), l.line))
            .collect();
        assert_eq!(
            read,
            [("REGION", &b"eu-west"[..], 2), ("TOKEN", &b"a b"[..], 3)]
        );
        let error = parse_env(b"A=1\nhunter2\n".to_vec())
            .unwrap_err()
            .to_string();
        assert_eq!(error, "line 2: expected NAME=value");
    }

    #[test]
    fn an_empty_home_has_no_vault_or_keys() {
        let home = std::env::temp_dir().join(format!("openvault-ffi-home-{}", std::process::id()));
        let found = device_home(Some(home.to_string_lossy().into_owned())).unwrap();
        assert_eq!((found.vault, found.keys), (false, None));
        assert_eq!(found.path, home.to_string_lossy());
    }

    #[test]
    fn a_vault_is_made_without_the_service() {
        let home = temp_home("create");
        let path = Some(home.to_string_lossy().into_owned());
        let made = create_vault(path.clone(), KeyStorage::Software, "Studio".into(), None).unwrap();
        assert_eq!(made.phrase.split(' ').count(), 24);
        assert_eq!(made.recovery.len(), 9);
        assert!(!made.admin, "only the Secure Enclave gets an admin key");
        let found = device_home(path.clone()).unwrap();
        assert_eq!(
            (found.vault, found.keys, found.joining),
            (true, Some(KeyStorage::Software), false)
        );
        let again = create_vault(path, KeyStorage::Software, "Studio".into(), None).unwrap_err();
        assert!(again.to_string().starts_with("there is already a vault"));
        assert!(matches!(
            create_vault(
                None,
                KeyStorage::Passphrase,
                "x".into(),
                Some("short".into())
            ),
            Err(OpenVaultError::Failed { .. })
        ));
        std::fs::remove_dir_all(home).unwrap();
    }

    /// Records what a join's listener hears.
    #[derive(Default)]
    struct Heard {
        ended: std::sync::Mutex<Option<Option<String>>>,
        done: std::sync::Condvar,
    }

    impl JoinListener for Heard {
        fn on_progress(&self, _progress: JoinProgress) {}

        fn on_end(&self, error: Option<String>) {
            *self.ended.lock().unwrap() = Some(error);
            self.done.notify_all();
        }
    }

    #[test]
    fn a_join_waits_until_stopped_and_can_be_forgotten() {
        let home = temp_home("join");
        let path = Some(home.to_string_lossy().into_owned());
        let heard = Arc::new(Heard::default());
        let joining = join_vault(
            path.clone(),
            KeyStorage::Software,
            "Studio".into(),
            None,
            heard.clone(),
        )
        .unwrap();
        assert!(joining.code().len() == 6 && joining.code().bytes().all(|b| b.is_ascii_digit()));
        let found = device_home(path.clone()).unwrap();
        assert_eq!((found.vault, found.joining), (false, true));

        joining.stop();
        let ended = heard
            .done
            .wait_timeout_while(heard.ended.lock().unwrap(), Duration::from_secs(10), |e| {
                e.is_none()
            })
            .unwrap()
            .0
            .clone();
        assert_eq!(ended, Some(Some("stopped waiting".into())));

        // Joining again resumes as the same device, with the same keys.
        let again = join_vault(
            path.clone(),
            KeyStorage::Software,
            "Studio".into(),
            None,
            Arc::new(Heard::default()),
        )
        .unwrap();
        assert_eq!(again.device(), joining.device());
        drop(again);
        forget_join(path.clone()).unwrap();
        let found = device_home(path.clone()).unwrap();
        assert_eq!((found.keys, found.joining), (None, false));
        assert!(forget_join(path).is_err());
        std::fs::remove_dir_all(home).unwrap();
    }

    fn temp_home(name: &str) -> PathBuf {
        let home =
            std::env::temp_dir().join(format!("openvault-ffi-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        home
    }

    #[test]
    fn a_missing_service_is_not_running() {
        let home = std::env::temp_dir().join(format!("openvault-ffi-{}", std::process::id()));
        let client = Client::new(Some(home.to_string_lossy().into_owned())).unwrap();
        assert!(!client.is_running());
        assert!(matches!(client.vault(), Err(OpenVaultError::NotRunning)));
        assert!(matches!(
            client.check_code(vec![0; 31], "123456".into()),
            Err(OpenVaultError::Failed { .. })
        ));
    }
}
