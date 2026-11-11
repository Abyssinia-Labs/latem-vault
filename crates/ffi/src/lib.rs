//! Swift bindings to the service's local API, for the Mac app (service.md, for apps; design §16).
//!
//! The app is a client of the service, as the CLI is: [`Client`] sends each request on the
//! socket and turns the response into records Swift can use, and [`Client::watch`] keeps a
//! connection open and calls a Swift listener on each event. Every call blocks, so Swift makes
//! them off the main thread. Values cross into Swift as `Data`, where they can't be wiped.

use std::io::{self, ErrorKind};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;

use openvault_core::membership::Scope as CoreScope;
use openvault_core::{DeviceId, Kind as CoreKind};
use openvault_keystore::Backend;
use openvault_service::api::{self, ErrorCode, Request, Response};
use openvault_service::client;

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
}

/// An entry as a list shows it: a variable's value, and never a secret's.
#[derive(uniffi::Record)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub set_by: String,
    pub key: u32,
    pub value: Option<Vec<u8>>,
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
    NotSeen,
    OnNetwork,
    Syncing,
    Failing,
}

#[derive(Debug, uniffi::Record)]
pub struct Peer {
    pub device: String,
    pub state: PeerState,
    /// Seconds since mDNS last showed it: 0 while it's on the network, `None` if never.
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
    })
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
                recovery: format!(
                    "{:02x}{:02x} {:02x}{:02x}",
                    info.recovery[0], info.recovery[1], info.recovery[2], info.recovery[3]
                ),
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

    /// A collection's current entries, with variables' values but never secrets'.
    pub fn entries(&self, collection: String) -> Result<Vec<Entry>, OpenVaultError> {
        match self.call(&Request::EntryDetails { collection })? {
            Response::EntryDetails(details) => Ok(details
                .into_iter()
                .map(|detail| Entry {
                    kind: detail.kind.into(),
                    value: (detail.kind == CoreKind::Var).then(|| detail.value.to_vec()),
                    name: detail.name,
                    set_by: detail.set_by.to_string(),
                    key: detail.key,
                })
                .collect()),
            other => Err(unexpected(other)),
        }
    }

    /// One entry's value, or `None` if it doesn't exist.
    pub fn get(&self, collection: String, name: String) -> Result<Option<Value>, OpenVaultError> {
        match self.call(&Request::Get { collection, name })? {
            Response::Entry(value) => Ok(value.map(|value| Value {
                kind: value.kind.into(),
                value: value.value.to_vec(),
            })),
            other => Err(unexpected(other)),
        }
    }

    /// Writes every entry in one transaction.
    pub fn set(&self, collection: String, entries: Vec<NewEntry>) -> Result<(), OpenVaultError> {
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
        }
    }
}

#[cfg(test)]
mod tests {
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
    fn an_empty_home_has_no_vault_or_keys() {
        let home = std::env::temp_dir().join(format!("openvault-ffi-home-{}", std::process::id()));
        let found = device_home(Some(home.to_string_lossy().into_owned())).unwrap();
        assert_eq!((found.vault, found.keys), (false, None));
        assert_eq!(found.path, home.to_string_lossy());
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
