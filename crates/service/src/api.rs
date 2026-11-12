//! The local API's messages and their encoding (service.md, local API).
//!
//! Each message is `u32 length ‖ type ‖ body`. Buffers that can hold values are sized before
//! they are filled, so they never reallocate and leave copies behind, and are wiped when dropped.

use std::io::{self, Read, Write};

use openvault_core::file::ChunkId;
use openvault_core::membership::Scope;
use openvault_core::{DeviceId, Kind, Placement, Review, VaultId, Written};
use zeroize::Zeroizing;

/// The longest message, type and body: a folder of large values still fits.
pub const MAX_MESSAGE: usize = 16 << 20;

/// What the CLI asks the service to do.
#[derive(Debug)]
pub enum Request {
    Collections,
    CreateCollection {
        name: String,
        /// Needed only when this device has no admin key.
        recovery_phrase: Option<Zeroizing<String>>,
    },
    Get {
        collection: String,
        name: String,
    },
    /// Writes every entry in one transaction.
    Set {
        collection: String,
        entries: Vec<Item>,
    },
    Delete {
        collection: String,
        name: String,
    },
    List {
        collection: String,
    },
    /// The current values under `folder/`, for `openvault run`.
    Folder {
        collection: String,
        folder: String,
    },
    Devices,
    /// Something wrote to the vault without the service, such as `openvault approve`: the
    /// service reloads what it keeps and tells the other devices.
    Changed,
    /// What a device can read and wrote last, before revoking it.
    Review {
        device: DeviceId,
    },
    Revoke {
        device: DeviceId,
        /// Needed only when this device has no admin key.
        recovery_phrase: Option<Zeroizing<String>>,
    },
    SetScope {
        device: DeviceId,
        collection: String,
        scope: Scope,
        /// Needed only when this device has no admin key.
        recovery_phrase: Option<Zeroizing<String>>,
    },
    /// Which build the service is and how it's doing. Only the service answers it.
    Status,
    /// This vault and device, for apps (service.md, for apps).
    Vault,
    CollectionSummaries,
    /// Every current entry of a collection, with variables' values but never secrets'.
    EntryDetails {
        collection: String,
    },
    /// Up to `max` log entries from seq `from`.
    Log {
        from: u64,
        max: u16,
    },
    /// Several scope changes for one device, under one admin signature.
    SetScopes {
        device: DeviceId,
        changes: Vec<(String, Scope)>,
        /// Needed only when this device has no admin key.
        recovery_phrase: Option<Zeroizing<String>>,
    },
    /// Keeps the connection open for events. Only the service answers it.
    Watch,
    /// Each member's sync state. Only the service answers it.
    Peers,
    /// The devices waiting to join on this network. Only the service answers it.
    Joiners,
    /// Runs the PAKE with a joiner (join.md). Only the service answers it.
    CheckCode {
        joiner: [u8; 32],
        code: Zeroizing<String>,
    },
    Approve {
        session: u32,
        scopes: Vec<(String, Scope)>,
        /// Needed only when this device has no admin key.
        recovery_phrase: Option<Zeroizing<String>>,
    },
    Refuse {
        session: u32,
    },
    /// Seals a piece of a file and keeps it (files.md, the service).
    WriteChunk {
        collection: String,
        data: ChunkData,
    },
    /// A chunk a file's manifest names, opened.
    ReadChunk {
        collection: String,
        epoch: u32,
        id: ChunkId,
    },
    /// This device's placement for a collection, after setting it if `set` is given.
    Placement {
        collection: String,
        set: Option<Placement>,
    },
    /// Gets the chunks of a file that aren't here from the devices that share its collection,
    /// and answers once they're all here, or with how many none of them had (files.md, the
    /// service). Without a service, it only counts them.
    Fetch {
        collection: String,
        name: String,
    },
}

#[derive(Debug)]
pub enum Response {
    Done,
    Names(Vec<String>),
    Entry(Option<Value>),
    Entries(Vec<Item>),
    Listing(Vec<Listed>),
    Deleted(bool),
    Devices(Vec<DeviceSummary>),
    Review(Review),
    Revoked {
        /// The collections that got a new key.
        rotated: Vec<String>,
        /// Entries the device wrote last, written again under the new keys.
        carried: u32,
    },
    ScopeSet {
        /// Whether the collection got a new key.
        rotated: bool,
        /// Keys of the collection given to the device.
        granted: u32,
        /// Entries the device wrote last, written again under the new key.
        carried: u32,
    },
    Status {
        /// The service's version, as `openvault --version` prints it.
        version: String,
        pid: u32,
        /// How many times mDNS has stopped since the service started.
        mdns_stops: u32,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
    Vault(VaultInfo),
    CollectionSummaries(Vec<CollectionSummary>),
    EntryDetails(Vec<EntryDetail>),
    Log(Vec<LogLine>),
    Event(Event),
    Peers(Vec<Peer>),
    Joiners(Vec<Joiner>),
    JoinRequest(JoinRequestSummary),
    ScopesSet {
        /// The collections that got a new key.
        rotated: Vec<String>,
        /// Keys of the collections given to the device.
        granted: u32,
        /// Entries the device wrote last, written again under the new keys.
        carried: u32,
    },
    ChunkWritten {
        id: ChunkId,
        /// The collection key it's sealed under, which its manifest names.
        epoch: u32,
    },
    Chunk(ChunkData),
    Placement(Placement),
    /// How many of a file's chunks still aren't here.
    Fetched {
        missing: u64,
    },
}

/// A piece of a file, in the clear: at most a chunk, which never shows in debug output.
pub struct ChunkData(pub Zeroizing<Vec<u8>>);

impl std::fmt::Debug for ChunkData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChunkData({} bytes)", self.0.len())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultInfo {
    pub vault: VaultId,
    pub device: DeviceId,
    /// The first 4 bytes of the recovery key's hash.
    pub recovery: [u8; 4],
    /// The last log entry's seq, 0 before the log starts.
    pub log_head: u64,
    /// Whether this device has an admin key the log lists.
    pub admin: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionSummary {
    pub name: String,
    pub secrets: u32,
    pub variables: u32,
    pub files: u32,
    /// The collection's current key (epoch).
    pub key: u32,
    /// Devices that aren't revoked, with a scope other than none.
    pub devices: Vec<(DeviceId, Scope)>,
}

/// An entry with who set it and which key sealed it. `value` is a variable's, and always empty
/// for a secret.
pub struct EntryDetail {
    pub name: String,
    pub kind: Kind,
    pub set_by: DeviceId,
    pub key: u32,
    pub value: Zeroizing<Vec<u8>>,
}

/// A membership log entry, as an app shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogLine {
    pub seq: u64,
    pub hash: [u8; 32],
    /// The entry's type (membership.md).
    pub change: u8,
    /// Zeros if the type has no device.
    pub device: DeviceId,
    /// Empty if the type has no collection; the id in hex if this device doesn't have it.
    pub collection: String,
    pub scope: Scope,
    pub key: u32,
    pub signer: Signer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signer {
    Recovery,
    ThisDevice,
    OtherAdmin,
}

/// What may have changed, for a watching app.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Event {
    /// A set of the `Event::*` bits.
    pub what: u8,
    /// For [`Event::ENTRIES`]: the collections, or empty for any.
    pub collections: Vec<String>,
}

impl Event {
    pub const ENTRIES: u8 = 0x01;
    pub const LOG: u8 = 0x02;
    pub const DEVICES: u8 = 0x04;
    pub const JOINERS: u8 = 0x08;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    /// Not seen since the service started.
    NotSeen,
    /// On the network, or in a session that has caught up and only waits for more work.
    OnNetwork,
    /// In a session that hasn't gone quiet yet (sync.md, quiet).
    Syncing,
    /// Its last session failed.
    Failing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub device: DeviceId,
    pub state: PeerState,
    /// Seconds since mDNS last showed it: 0 while it's on the network or in a session, `None`
    /// if never.
    pub seen: Option<u32>,
    /// Seconds until the next attempt after a failure, 0 if none is waiting.
    pub retry_in: u32,
    /// Why the last session failed, or empty.
    pub error: String,
}

/// A device waiting to join, as its mDNS announcement says; unchecked (join.md).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Joiner {
    pub endpoint: [u8; 32],
    pub platform: String,
    pub name: String,
}

/// What a joiner signed, once its code matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequestSummary {
    pub session: u32,
    pub device: DeviceId,
    pub platform: String,
    pub name: String,
    pub hardware: bool,
}

/// A secret, variable or file with its name. A file's value is its manifest.
pub struct Item {
    pub name: String,
    pub kind: Kind,
    pub value: Zeroizing<Vec<u8>>,
}

pub struct Value {
    pub kind: Kind,
    pub value: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub name: String,
    pub kind: Kind,
    /// A file's size in bytes; 0 for anything else.
    pub size: u64,
    /// How many of a file's chunks this device doesn't hold.
    pub missing: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceSummary {
    pub id: DeviceId,
    pub this: bool,
    pub revoked: bool,
    pub visible: bool,
    /// P-256 keys, in a Secure Enclave or TPM.
    pub hardware: bool,
    /// `None` for a name that doesn't open, which is shown as the device id.
    pub name: Option<(String, String)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    Other,
    RecoveryPhraseNeeded,
    WrongCode,
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for EntryDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryDetail")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("set_by", &self.set_by)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Value")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("bad message: {0}")]
    Bad(&'static str),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl Request {
    /// The whole message, length included.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Self::Collections => frame(0x01, |_| {}),
            Self::CreateCollection {
                name,
                recovery_phrase,
            } => frame(0x02, |w| {
                w.str(name);
                match recovery_phrase {
                    Some(phrase) => {
                        w.u8(1);
                        w.str(phrase);
                    }
                    None => w.u8(0),
                }
            }),
            Self::Get { collection, name } => frame(0x03, |w| {
                w.str(collection);
                w.str(name);
            }),
            Self::Set {
                collection,
                entries,
            } => frame(0x04, |w| {
                w.str(collection);
                w.items(entries);
            }),
            Self::Delete { collection, name } => frame(0x05, |w| {
                w.str(collection);
                w.str(name);
            }),
            Self::List { collection } => frame(0x06, |w| w.str(collection)),
            Self::Folder { collection, folder } => frame(0x07, |w| {
                w.str(collection);
                w.str(folder);
            }),
            Self::Devices => frame(0x08, |_| {}),
            Self::Changed => frame(0x09, |_| {}),
            Self::Review { device } => frame(0x0a, |w| w.put(device.as_bytes())),
            Self::Revoke {
                device,
                recovery_phrase,
            } => frame(0x0b, |w| {
                w.put(device.as_bytes());
                w.phrase(recovery_phrase.as_deref().map(String::as_str));
            }),
            Self::SetScope {
                device,
                collection,
                scope,
                recovery_phrase,
            } => frame(0x0c, |w| {
                w.put(device.as_bytes());
                w.str(collection);
                w.u8(scope.code());
                w.phrase(recovery_phrase.as_deref().map(String::as_str));
            }),
            Self::Status => frame(0x0d, |_| {}),
            Self::Vault => frame(0x0e, |_| {}),
            Self::CollectionSummaries => frame(0x0f, |_| {}),
            Self::EntryDetails { collection } => frame(0x10, |w| w.str(collection)),
            Self::Log { from, max } => frame(0x11, |w| {
                w.put(&from.to_be_bytes());
                w.put(&max.to_be_bytes());
            }),
            Self::SetScopes {
                device,
                changes,
                recovery_phrase,
            } => frame(0x12, |w| {
                w.put(device.as_bytes());
                w.scopes(changes);
                w.phrase(recovery_phrase.as_deref().map(String::as_str));
            }),
            Self::Watch => frame(0x13, |_| {}),
            Self::Peers => frame(0x14, |_| {}),
            Self::Joiners => frame(0x15, |_| {}),
            Self::CheckCode { joiner, code } => frame(0x16, |w| {
                w.put(joiner);
                w.str(code);
            }),
            Self::Approve {
                session,
                scopes,
                recovery_phrase,
            } => frame(0x17, |w| {
                w.put(&session.to_be_bytes());
                w.scopes(scopes);
                w.phrase(recovery_phrase.as_deref().map(String::as_str));
            }),
            Self::Refuse { session } => frame(0x18, |w| w.put(&session.to_be_bytes())),
            Self::WriteChunk { collection, data } => frame(0x19, |w| {
                w.str(collection);
                w.bytes(&data.0);
            }),
            Self::ReadChunk {
                collection,
                epoch,
                id,
            } => frame(0x1a, |w| {
                w.str(collection);
                w.put(&epoch.to_be_bytes());
                w.put(id);
            }),
            Self::Placement { collection, set } => frame(0x1b, |w| {
                w.str(collection);
                w.u8(set.map_or(0, Placement::code));
            }),
            Self::Fetch { collection, name } => frame(0x1c, |w| {
                w.str(collection);
                w.str(name);
            }),
        }
    }

    pub fn decode(kind: u8, body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader(body);
        let request = match kind {
            0x01 => Self::Collections,
            0x02 => Self::CreateCollection {
                name: r.string()?,
                recovery_phrase: match r.u8()? {
                    0 => None,
                    1 => Some(Zeroizing::new(r.string()?)),
                    _ => return Err(DecodeError::Bad("has phrase")),
                },
            },
            0x03 => Self::Get {
                collection: r.string()?,
                name: r.string()?,
            },
            0x04 => Self::Set {
                collection: r.string()?,
                entries: r.items()?,
            },
            0x05 => Self::Delete {
                collection: r.string()?,
                name: r.string()?,
            },
            0x06 => Self::List {
                collection: r.string()?,
            },
            0x07 => Self::Folder {
                collection: r.string()?,
                folder: r.string()?,
            },
            0x08 => Self::Devices,
            0x09 => Self::Changed,
            0x0a => Self::Review {
                device: r.device()?,
            },
            0x0b => Self::Revoke {
                device: r.device()?,
                recovery_phrase: r.phrase()?,
            },
            0x0c => Self::SetScope {
                device: r.device()?,
                collection: r.string()?,
                scope: Scope::from_code(r.u8()?).ok_or(DecodeError::Bad("scope"))?,
                recovery_phrase: r.phrase()?,
            },
            0x0d => Self::Status,
            0x0e => Self::Vault,
            0x0f => Self::CollectionSummaries,
            0x10 => Self::EntryDetails {
                collection: r.string()?,
            },
            0x11 => Self::Log {
                from: r.u64()?,
                max: r.u16()?,
            },
            0x12 => Self::SetScopes {
                device: r.device()?,
                changes: r.scopes()?,
                recovery_phrase: r.phrase()?,
            },
            0x13 => Self::Watch,
            0x14 => Self::Peers,
            0x15 => Self::Joiners,
            0x16 => Self::CheckCode {
                joiner: r.endpoint()?,
                code: Zeroizing::new(r.string()?),
            },
            0x17 => Self::Approve {
                session: r.u32()?,
                scopes: r.scopes()?,
                recovery_phrase: r.phrase()?,
            },
            0x18 => Self::Refuse { session: r.u32()? },
            0x19 => Self::WriteChunk {
                collection: r.string()?,
                data: ChunkData(r.value()?),
            },
            0x1a => Self::ReadChunk {
                collection: r.string()?,
                epoch: r.u32()?,
                id: r.array()?,
            },
            0x1b => Self::Placement {
                collection: r.string()?,
                set: match r.u8()? {
                    0 => None,
                    code => Some(Placement::from_code(code).ok_or(DecodeError::Bad("placement"))?),
                },
            },
            0x1c => Self::Fetch {
                collection: r.string()?,
                name: r.string()?,
            },
            _ => return Err(DecodeError::Bad("unknown request")),
        };
        r.finish()?;
        Ok(request)
    }
}

impl Response {
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            code: ErrorCode::Other,
            message: message.into(),
        }
    }

    /// The whole message, length included.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Self::Done => frame(0x80, |_| {}),
            Self::Names(names) => frame(0x81, |w| {
                w.count(names.len());
                for name in names {
                    w.str(name);
                }
            }),
            Self::Entry(value) => frame(0x82, |w| match value {
                Some(value) => {
                    w.u8(1);
                    w.kind(value.kind);
                    w.bytes(&value.value);
                }
                None => w.u8(0),
            }),
            Self::Entries(items) => frame(0x83, |w| w.items(items)),
            Self::Listing(listed) => frame(0x84, |w| {
                w.count(listed.len());
                for entry in listed {
                    w.str(&entry.name);
                    w.kind(entry.kind);
                    if entry.kind == Kind::File {
                        w.put(&entry.size.to_be_bytes());
                        w.put(&entry.missing.to_be_bytes());
                    }
                }
            }),
            Self::Deleted(existed) => frame(0x85, |w| w.u8((*existed).into())),
            Self::Devices(devices) => frame(0x86, |w| {
                w.count(devices.len());
                for device in devices {
                    w.put(device.id.as_bytes());
                    let flags = u8::from(device.this)
                        | u8::from(device.revoked) << 1
                        | u8::from(device.visible) << 2
                        | u8::from(device.hardware) << 3;
                    w.u8(flags);
                    let (platform, name) = device
                        .name
                        .as_ref()
                        .map_or(("", ""), |(platform, name)| (platform, name));
                    w.str(platform);
                    w.str(name);
                }
            }),
            Self::Review(review) => frame(0x87, |w| {
                w.count(review.secrets.len());
                for (collection, names) in &review.secrets {
                    w.str(collection);
                    w.count(names.len());
                    for name in names {
                        w.str(name);
                    }
                }
                w.count(review.wrote_last.len());
                for (collection, written) in &review.wrote_last {
                    w.str(collection);
                    w.count(written.len());
                    for entry in written {
                        w.str(&entry.name);
                        w.u8(entry.deleted.into());
                    }
                }
            }),
            Self::Revoked { rotated, carried } => frame(0x88, |w| {
                w.count(rotated.len());
                for name in rotated {
                    w.str(name);
                }
                w.put(&carried.to_be_bytes());
            }),
            Self::ScopeSet {
                rotated,
                granted,
                carried,
            } => frame(0x89, |w| {
                w.u8((*rotated).into());
                w.put(&granted.to_be_bytes());
                w.put(&carried.to_be_bytes());
            }),
            Self::Status {
                version,
                pid,
                mdns_stops,
            } => frame(0x8a, |w| {
                w.str(version);
                w.put(&pid.to_be_bytes());
                w.put(&mdns_stops.to_be_bytes());
            }),
            Self::Error { code, message } => frame(0x7f, |w| {
                w.u8(match code {
                    ErrorCode::Other => 0x01,
                    ErrorCode::RecoveryPhraseNeeded => 0x02,
                    ErrorCode::WrongCode => 0x03,
                });
                w.str(truncate(message, 4096));
            }),
            Self::Vault(info) => frame(0x8b, |w| {
                w.put(info.vault.as_bytes());
                w.put(info.device.as_bytes());
                w.put(&info.recovery);
                w.put(&info.log_head.to_be_bytes());
                w.u8(info.admin.into());
            }),
            Self::CollectionSummaries(collections) => frame(0x8c, |w| {
                w.count(collections.len());
                for collection in collections {
                    w.str(&collection.name);
                    w.put(&collection.secrets.to_be_bytes());
                    w.put(&collection.variables.to_be_bytes());
                    w.put(&collection.files.to_be_bytes());
                    w.put(&collection.key.to_be_bytes());
                    w.count(collection.devices.len());
                    for (device, scope) in &collection.devices {
                        w.put(device.as_bytes());
                        w.u8(scope.code());
                    }
                }
            }),
            Self::EntryDetails(entries) => frame(0x8d, |w| {
                w.count(entries.len());
                for entry in entries {
                    w.str(&entry.name);
                    w.kind(entry.kind);
                    w.put(entry.set_by.as_bytes());
                    w.put(&entry.key.to_be_bytes());
                    w.bytes(&entry.value);
                }
            }),
            Self::Log(lines) => frame(0x8e, |w| {
                w.count(lines.len());
                for line in lines {
                    w.put(&line.seq.to_be_bytes());
                    w.put(&line.hash);
                    w.u8(line.change);
                    w.put(line.device.as_bytes());
                    w.str(&line.collection);
                    w.u8(line.scope.code());
                    w.put(&line.key.to_be_bytes());
                    w.u8(match line.signer {
                        Signer::Recovery => 0x00,
                        Signer::ThisDevice => 0x01,
                        Signer::OtherAdmin => 0x02,
                    });
                }
            }),
            Self::Event(event) => frame(0x8f, |w| {
                w.u8(event.what);
                w.count(event.collections.len());
                for name in &event.collections {
                    w.str(name);
                }
            }),
            Self::Peers(peers) => frame(0x90, |w| {
                w.count(peers.len());
                for peer in peers {
                    w.put(peer.device.as_bytes());
                    w.u8(match peer.state {
                        PeerState::NotSeen => 0x00,
                        PeerState::OnNetwork => 0x01,
                        PeerState::Syncing => 0x02,
                        PeerState::Failing => 0x03,
                    });
                    w.put(&peer.seen.unwrap_or(u32::MAX).to_be_bytes());
                    w.put(&peer.retry_in.to_be_bytes());
                    w.str(truncate(&peer.error, 1024));
                }
            }),
            Self::Joiners(joiners) => frame(0x91, |w| {
                w.count(joiners.len());
                for joiner in joiners {
                    w.put(&joiner.endpoint);
                    w.str(&joiner.platform);
                    w.str(&joiner.name);
                }
            }),
            Self::JoinRequest(request) => frame(0x92, |w| {
                w.put(&request.session.to_be_bytes());
                w.put(request.device.as_bytes());
                w.str(&request.platform);
                w.str(&request.name);
                w.u8(request.hardware.into());
            }),
            Self::ScopesSet {
                rotated,
                granted,
                carried,
            } => frame(0x93, |w| {
                w.count(rotated.len());
                for name in rotated {
                    w.str(name);
                }
                w.put(&granted.to_be_bytes());
                w.put(&carried.to_be_bytes());
            }),
            Self::ChunkWritten { id, epoch } => frame(0x94, |w| {
                w.put(id);
                w.put(&epoch.to_be_bytes());
            }),
            Self::Chunk(data) => frame(0x95, |w| w.bytes(&data.0)),
            Self::Placement(placement) => frame(0x96, |w| w.u8(placement.code())),
            Self::Fetched { missing } => frame(0x97, |w| w.put(&missing.to_be_bytes())),
        }
    }

    pub fn decode(kind: u8, body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader(body);
        let response = match kind {
            0x80 => Self::Done,
            0x81 => {
                let count = r.count()?;
                let mut names = Vec::with_capacity(count);
                for _ in 0..count {
                    names.push(r.string()?);
                }
                Self::Names(names)
            }
            0x82 => Self::Entry(match r.u8()? {
                0 => None,
                1 => Some(Value {
                    kind: r.kind()?,
                    value: r.value()?,
                }),
                _ => return Err(DecodeError::Bad("found")),
            }),
            0x83 => Self::Entries(r.items()?),
            0x84 => {
                let count = r.count()?;
                let mut listed = Vec::with_capacity(count);
                for _ in 0..count {
                    let (name, kind) = (r.string()?, r.kind()?);
                    let (size, missing) = if kind == Kind::File {
                        (r.u64()?, r.u32()?)
                    } else {
                        (0, 0)
                    };
                    listed.push(Listed {
                        name,
                        kind,
                        size,
                        missing,
                    });
                }
                Self::Listing(listed)
            }
            0x85 => Self::Deleted(match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(DecodeError::Bad("existed")),
            }),
            0x86 => {
                let count = r.count()?;
                let mut devices = Vec::with_capacity(count);
                for _ in 0..count {
                    let id = DeviceId::try_from(r.take(16)?)
                        .map_err(|_| DecodeError::Bad("device id"))?;
                    let flags = r.u8()?;
                    if flags >> 4 != 0 {
                        return Err(DecodeError::Bad("device flags"));
                    }
                    let platform = r.string()?;
                    let name = r.string()?;
                    devices.push(DeviceSummary {
                        id,
                        this: flags & 1 != 0,
                        revoked: flags & 2 != 0,
                        visible: flags & 4 != 0,
                        hardware: flags & 8 != 0,
                        name: (!name.is_empty()).then_some((platform, name)),
                    });
                }
                Self::Devices(devices)
            }
            0x87 => {
                let mut review = Review::default();
                for _ in 0..r.count()? {
                    let collection = r.string()?;
                    let count = r.count()?;
                    let mut names = Vec::with_capacity(count);
                    for _ in 0..count {
                        names.push(r.string()?);
                    }
                    review.secrets.push((collection, names));
                }
                for _ in 0..r.count()? {
                    let collection = r.string()?;
                    let count = r.count()?;
                    let mut written = Vec::with_capacity(count);
                    for _ in 0..count {
                        written.push(Written {
                            name: r.string()?,
                            deleted: match r.u8()? {
                                0 => false,
                                1 => true,
                                _ => return Err(DecodeError::Bad("deleted")),
                            },
                        });
                    }
                    review.wrote_last.push((collection, written));
                }
                Self::Review(review)
            }
            0x88 => {
                let count = r.count()?;
                let mut rotated = Vec::with_capacity(count);
                for _ in 0..count {
                    rotated.push(r.string()?);
                }
                Self::Revoked {
                    rotated,
                    carried: u32::from_be_bytes(r.take(4)?.try_into().expect("took 4 bytes")),
                }
            }
            0x89 => Self::ScopeSet {
                rotated: match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(DecodeError::Bad("rotated")),
                },
                granted: u32::from_be_bytes(r.take(4)?.try_into().expect("took 4 bytes")),
                carried: u32::from_be_bytes(r.take(4)?.try_into().expect("took 4 bytes")),
            },
            0x8a => Self::Status {
                version: r.string()?,
                pid: u32::from_be_bytes(r.take(4)?.try_into().expect("took 4 bytes")),
                mdns_stops: u32::from_be_bytes(r.take(4)?.try_into().expect("took 4 bytes")),
            },
            0x7f => Self::Error {
                code: match r.u8()? {
                    0x02 => ErrorCode::RecoveryPhraseNeeded,
                    0x03 => ErrorCode::WrongCode,
                    _ => ErrorCode::Other,
                },
                message: r.string()?,
            },
            0x8b => Self::Vault(VaultInfo {
                vault: VaultId::from_bytes(r.array()?),
                device: r.device()?,
                recovery: r.array()?,
                log_head: r.u64()?,
                admin: r.flag("admin")?,
            }),
            0x8c => {
                let count = r.count()?;
                let mut collections = Vec::with_capacity(count);
                for _ in 0..count {
                    let name = r.string()?;
                    let (secrets, variables, files, key) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
                    let devices = (0..r.count()?)
                        .map(|_| Ok((r.device()?, r.scope()?)))
                        .collect::<Result<_, DecodeError>>()?;
                    collections.push(CollectionSummary {
                        name,
                        secrets,
                        variables,
                        files,
                        key,
                        devices,
                    });
                }
                Self::CollectionSummaries(collections)
            }
            0x8d => {
                let count = r.count()?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    entries.push(EntryDetail {
                        name: r.string()?,
                        kind: r.kind()?,
                        set_by: r.device()?,
                        key: r.u32()?,
                        value: r.value()?,
                    });
                }
                Self::EntryDetails(entries)
            }
            0x8e => {
                let count = r.count()?;
                let mut lines = Vec::with_capacity(count);
                for _ in 0..count {
                    lines.push(LogLine {
                        seq: r.u64()?,
                        hash: r.array()?,
                        change: r.u8()?,
                        device: r.device()?,
                        collection: r.string()?,
                        scope: r.scope()?,
                        key: r.u32()?,
                        signer: match r.u8()? {
                            0x00 => Signer::Recovery,
                            0x01 => Signer::ThisDevice,
                            0x02 => Signer::OtherAdmin,
                            _ => return Err(DecodeError::Bad("signer")),
                        },
                    });
                }
                Self::Log(lines)
            }
            0x8f => Self::Event(Event {
                what: r.u8()?,
                collections: (0..r.count()?)
                    .map(|_| r.string())
                    .collect::<Result<_, _>>()?,
            }),
            0x90 => {
                let count = r.count()?;
                let mut peers = Vec::with_capacity(count);
                for _ in 0..count {
                    peers.push(Peer {
                        device: r.device()?,
                        state: match r.u8()? {
                            0x00 => PeerState::NotSeen,
                            0x01 => PeerState::OnNetwork,
                            0x02 => PeerState::Syncing,
                            0x03 => PeerState::Failing,
                            _ => return Err(DecodeError::Bad("peer state")),
                        },
                        seen: Some(r.u32()?).filter(|&seen| seen != u32::MAX),
                        retry_in: r.u32()?,
                        error: r.string()?,
                    });
                }
                Self::Peers(peers)
            }
            0x91 => {
                let count = r.count()?;
                let mut joiners = Vec::with_capacity(count);
                for _ in 0..count {
                    joiners.push(Joiner {
                        endpoint: r.endpoint()?,
                        platform: r.string()?,
                        name: r.string()?,
                    });
                }
                Self::Joiners(joiners)
            }
            0x92 => Self::JoinRequest(JoinRequestSummary {
                session: r.u32()?,
                device: r.device()?,
                platform: r.string()?,
                name: r.string()?,
                hardware: r.flag("hardware")?,
            }),
            0x93 => Self::ScopesSet {
                rotated: (0..r.count()?)
                    .map(|_| r.string())
                    .collect::<Result<_, _>>()?,
                granted: r.u32()?,
                carried: r.u32()?,
            },
            0x94 => Self::ChunkWritten {
                id: r.array()?,
                epoch: r.u32()?,
            },
            0x95 => Self::Chunk(ChunkData(r.value()?)),
            0x96 => {
                Self::Placement(Placement::from_code(r.u8()?).ok_or(DecodeError::Bad("placement"))?)
            }
            0x97 => Self::Fetched { missing: r.u64()? },
            _ => return Err(DecodeError::Bad("unknown response")),
        };
        r.finish()?;
        Ok(response)
    }
}

/// Reads one message: its type and body.
pub fn read_message(reader: &mut impl Read) -> Result<(u8, Zeroizing<Vec<u8>>), DecodeError> {
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;
    let mut message = Zeroizing::new(vec![0; message_len(len)?]);
    reader.read_exact(&mut message)?;
    split(message)
}

/// Writes one message from [`Request::encode`] or [`Response::encode`].
pub fn write_message(writer: &mut impl Write, message: &[u8]) -> io::Result<()> {
    writer.write_all(message)?;
    writer.flush()
}

/// The length prefix's value, checked against [`MAX_MESSAGE`].
pub fn message_len(prefix: [u8; 4]) -> Result<usize, DecodeError> {
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > MAX_MESSAGE {
        return Err(DecodeError::Bad("length"));
    }
    Ok(len)
}

/// Splits a message without its length prefix into its type and body.
pub fn split(mut message: Zeroizing<Vec<u8>>) -> Result<(u8, Zeroizing<Vec<u8>>), DecodeError> {
    let kind = message[0];
    // Shifts the body down in place, so no copy is left behind.
    message.copy_within(1.., 0);
    let len = message.len() - 1;
    message.truncate(len);
    Ok((kind, message))
}

/// Builds a message: the body is written twice, once to count it and once into a buffer of
/// exactly that size.
fn frame(kind: u8, body: impl Fn(&mut Writer)) -> Zeroizing<Vec<u8>> {
    let mut counter = Writer { buf: None, len: 0 };
    body(&mut counter);
    let len = 1 + counter.len;
    assert!(len <= MAX_MESSAGE, "callers keep messages within the limit");
    let mut writer = Writer {
        buf: Some(Zeroizing::new(Vec::with_capacity(4 + len))),
        len: 0,
    };
    writer.put(&(len as u32).to_be_bytes());
    writer.u8(kind);
    body(&mut writer);
    writer.buf.expect("filled")
}

struct Writer {
    /// `None` while counting.
    buf: Option<Zeroizing<Vec<u8>>>,
    len: usize,
}

impl Writer {
    fn put(&mut self, bytes: &[u8]) {
        self.len += bytes.len();
        if let Some(buf) = &mut self.buf {
            buf.extend_from_slice(bytes);
        }
    }

    fn u8(&mut self, value: u8) {
        self.put(&[value]);
    }

    fn count(&mut self, count: usize) {
        self.put(
            &u32::try_from(count)
                .expect("bounded by the message limit")
                .to_be_bytes(),
        );
    }

    /// `has phrase (u8) ‖ phrase (str, only if has phrase is 1)`.
    fn phrase(&mut self, phrase: Option<&str>) {
        match phrase {
            Some(phrase) => {
                self.u8(1);
                self.str(phrase);
            }
            None => self.u8(0),
        }
    }

    fn str(&mut self, s: &str) {
        let len = u16::try_from(s.len()).expect("names, phrases and messages are short");
        self.put(&len.to_be_bytes());
        self.put(s.as_bytes());
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.count(bytes.len());
        self.put(bytes);
    }

    fn kind(&mut self, kind: Kind) {
        self.u8(kind_code(kind));
    }

    fn items(&mut self, items: &[Item]) {
        self.count(items.len());
        for item in items {
            self.str(&item.name);
            self.kind(item.kind);
            self.bytes(&item.value);
        }
    }

    /// `count (u32) ‖ collection (str) ‖ scope (u8)` for each.
    fn scopes(&mut self, scopes: &[(String, Scope)]) {
        self.count(scopes.len());
        for (collection, scope) in scopes {
            self.str(collection);
            self.u8(scope.code());
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        if self.0.len() < len {
            return Err(DecodeError::Bad("truncated"));
        }
        let (field, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(field)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn phrase(&mut self) -> Result<Option<Zeroizing<String>>, DecodeError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(Zeroizing::new(self.string()?))),
            _ => Err(DecodeError::Bad("has phrase")),
        }
    }

    fn device(&mut self) -> Result<DeviceId, DecodeError> {
        DeviceId::try_from(self.take(16)?).map_err(|_| DecodeError::Bad("device id"))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.take(N)?.try_into().expect("took N bytes"))
    }

    fn endpoint(&mut self) -> Result<[u8; 32], DecodeError> {
        self.array()
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn flag(&mut self, what: &'static str) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::Bad(what)),
        }
    }

    fn scope(&mut self) -> Result<Scope, DecodeError> {
        Scope::from_code(self.u8()?).ok_or(DecodeError::Bad("scope"))
    }

    fn scopes(&mut self) -> Result<Vec<(String, Scope)>, DecodeError> {
        let count = self.count()?;
        let mut scopes = Vec::with_capacity(count);
        for _ in 0..count {
            scopes.push((self.string()?, self.scope()?));
        }
        Ok(scopes)
    }

    fn count(&mut self) -> Result<usize, DecodeError> {
        let count = u32::from_be_bytes(self.take(4)?.try_into().expect("took 4")) as usize;
        // Each item takes at least one byte, so a count beyond the rest is a lie, and
        // allocating for it would let a message ask for any amount of memory.
        if count > self.0.len() {
            return Err(DecodeError::Bad("count"));
        }
        Ok(count)
    }

    fn string(&mut self) -> Result<String, DecodeError> {
        let len = u16::from_be_bytes(self.take(2)?.try_into().expect("took 2"));
        let bytes = self.take(len.into())?;
        String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::Bad("UTF-8"))
    }

    fn value(&mut self) -> Result<Zeroizing<Vec<u8>>, DecodeError> {
        let len = self.count()?;
        Ok(Zeroizing::new(self.take(len)?.to_vec()))
    }

    fn kind(&mut self) -> Result<Kind, DecodeError> {
        match self.u8()? {
            0x01 => Ok(Kind::Secret),
            0x02 => Ok(Kind::Var),
            0x03 => Ok(Kind::File),
            _ => Err(DecodeError::Bad("kind")),
        }
    }

    fn items(&mut self) -> Result<Vec<Item>, DecodeError> {
        let count = self.count()?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(Item {
                name: self.string()?,
                kind: self.kind()?,
                value: self.value()?,
            });
        }
        Ok(items)
    }

    fn finish(self) -> Result<(), DecodeError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Bad("trailing bytes"))
        }
    }
}

fn kind_code(kind: Kind) -> u8 {
    match kind {
        Kind::Secret => 0x01,
        Kind::Var => 0x02,
        Kind::File => 0x03,
        Kind::Collection => unreachable!("collection entries never cross the local API"),
    }
}

/// `message` cut to at most `max` bytes, at a character boundary.
fn truncate(message: &str, max: usize) -> &str {
    if message.len() <= max {
        return message;
    }
    let mut end = max;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    &message[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_request(request: &Request) -> Request {
        let message = request.encode();
        let (kind, body) = read_message(&mut &message[..]).unwrap();
        Request::decode(kind, &body).unwrap()
    }

    fn round_trip_response(response: &Response) -> Response {
        let message = response.encode();
        let (kind, body) = read_message(&mut &message[..]).unwrap();
        Response::decode(kind, &body).unwrap()
    }

    fn item(name: &str, kind: Kind, value: &[u8]) -> Item {
        Item {
            name: name.into(),
            kind,
            value: Zeroizing::new(value.to_vec()),
        }
    }

    #[test]
    fn requests_round_trip() {
        let set = Request::Set {
            collection: "latem".into(),
            entries: vec![
                item("prod/SENTRY_DSN", Kind::Secret, b"https://sentry"),
                item("prod/REGION", Kind::Var, b""),
            ],
        };
        let Request::Set {
            collection,
            entries,
        } = round_trip_request(&set)
        else {
            panic!("not a set");
        };
        assert_eq!(collection, "latem");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "prod/SENTRY_DSN");
        assert_eq!(entries[0].kind, Kind::Secret);
        assert_eq!(&entries[0].value[..], b"https://sentry");
        assert_eq!(entries[1].kind, Kind::Var);
        assert!(entries[1].value.is_empty());

        let create = Request::CreateCollection {
            name: "ssh".into(),
            recovery_phrase: Some(Zeroizing::new("abandon ability".into())),
        };
        let Request::CreateCollection {
            name,
            recovery_phrase,
        } = round_trip_request(&create)
        else {
            panic!("not a create");
        };
        assert_eq!(name, "ssh");
        assert_eq!(
            recovery_phrase.as_deref().map(String::as_str),
            Some("abandon ability")
        );

        let device = DeviceId::random();
        let Request::Revoke {
            device: decoded,
            recovery_phrase: None,
        } = round_trip_request(&Request::Revoke {
            device,
            recovery_phrase: None,
        })
        else {
            panic!("not a revoke");
        };
        assert_eq!(decoded, device);
        let Request::SetScope {
            collection,
            scope: Scope::Hold,
            recovery_phrase: Some(_),
            ..
        } = round_trip_request(&Request::SetScope {
            device,
            collection: "latem".into(),
            scope: Scope::Hold,
            recovery_phrase: Some(Zeroizing::new("abandon ability".into())),
        })
        else {
            panic!("not a scope change");
        };
        assert_eq!(collection, "latem");
        let Request::Review { device: decoded } = round_trip_request(&Request::Review { device })
        else {
            panic!("not a review");
        };
        assert_eq!(decoded, device);

        for request in [Request::Collections, Request::Devices] {
            let message = request.encode();
            assert_eq!(&message[..], &[0, 0, 0, 1, message[4]]);
            round_trip_request(&request);
        }
    }

    #[test]
    fn responses_round_trip() {
        let devices = vec![
            DeviceSummary {
                id: DeviceId::random(),
                this: true,
                revoked: false,
                visible: false,
                hardware: true,
                name: Some(("macos".into(), "MacBook".into())),
            },
            DeviceSummary {
                id: DeviceId::random(),
                this: false,
                revoked: true,
                visible: true,
                hardware: false,
                name: None,
            },
        ];
        let Response::Devices(decoded) = round_trip_response(&Response::Devices(devices.clone()))
        else {
            panic!("not devices");
        };
        assert_eq!(decoded, devices);

        let Response::Entry(Some(value)) = round_trip_response(&Response::Entry(Some(Value {
            kind: Kind::Var,
            value: Zeroizing::new(b"eu-west".to_vec()),
        }))) else {
            panic!("not an entry");
        };
        assert_eq!((value.kind, &value.value[..]), (Kind::Var, &b"eu-west"[..]));

        let review = Review {
            secrets: vec![("latem".into(), vec!["prod/SENTRY_DSN".into()])],
            wrote_last: vec![(
                "latem".into(),
                vec![
                    Written {
                        name: "prod/REGION".into(),
                        deleted: false,
                    },
                    Written {
                        name: "prod/OLD".into(),
                        deleted: true,
                    },
                ],
            )],
        };
        let Response::Review(decoded) = round_trip_response(&Response::Review(review)) else {
            panic!("not a review");
        };
        assert_eq!(decoded.secrets[0].1, ["prod/SENTRY_DSN"]);
        assert_eq!(decoded.wrote_last[0].1.len(), 2);
        assert!(decoded.wrote_last[0].1[1].deleted);
        let Response::ScopeSet {
            rotated: true,
            granted: 2,
            carried: 1,
        } = round_trip_response(&Response::ScopeSet {
            rotated: true,
            granted: 2,
            carried: 1,
        })
        else {
            panic!("not a scope change");
        };
        let Response::Revoked { rotated, carried } = round_trip_response(&Response::Revoked {
            rotated: vec!["latem".into()],
            carried: 3,
        }) else {
            panic!("not revoked");
        };
        assert_eq!((rotated, carried), (vec!["latem".to_owned()], 3));
        let Response::Status {
            version,
            pid: 4242,
            mdns_stops: 2,
        } = round_trip_response(&Response::Status {
            version: "0.2.2 (5664970)".into(),
            pid: 4242,
            mdns_stops: 2,
        })
        else {
            panic!("not a status");
        };
        assert_eq!(version, "0.2.2 (5664970)");
        assert!(matches!(
            round_trip_request(&Request::Status),
            Request::Status
        ));

        let Response::Error { code, message } = round_trip_response(&Response::Error {
            code: ErrorCode::RecoveryPhraseNeeded,
            message: "needs the phrase".into(),
        }) else {
            panic!("not an error");
        };
        assert_eq!(code, ErrorCode::RecoveryPhraseNeeded);
        assert_eq!(message, "needs the phrase");
    }

    #[test]
    fn app_messages_round_trip() {
        let device = DeviceId::random();
        let Request::SetScopes {
            device: decoded,
            changes,
            recovery_phrase: None,
        } = round_trip_request(&Request::SetScopes {
            device,
            changes: vec![("latem".into(), Scope::Read), ("ssh".into(), Scope::None)],
            recovery_phrase: None,
        })
        else {
            panic!("not set scopes");
        };
        assert_eq!(decoded, device);
        assert_eq!(
            changes,
            [
                ("latem".to_owned(), Scope::Read),
                ("ssh".to_owned(), Scope::None)
            ]
        );
        let Request::Log { from: 7, max: 64 } =
            round_trip_request(&Request::Log { from: 7, max: 64 })
        else {
            panic!("not a log request");
        };
        let Request::CheckCode { joiner, code } = round_trip_request(&Request::CheckCode {
            joiner: [7; 32],
            code: Zeroizing::new("482917".into()),
        }) else {
            panic!("not a code");
        };
        assert_eq!((joiner, code.as_str()), ([7; 32], "482917"));
        let Request::Approve {
            session: 3,
            scopes,
            recovery_phrase: Some(_),
        } = round_trip_request(&Request::Approve {
            session: 3,
            scopes: vec![("latem".into(), Scope::Write)],
            recovery_phrase: Some(Zeroizing::new("abandon ability".into())),
        })
        else {
            panic!("not an approval");
        };
        assert_eq!(scopes, [("latem".to_owned(), Scope::Write)]);
        for request in [
            Request::Vault,
            Request::CollectionSummaries,
            Request::Watch,
            Request::Peers,
            Request::Joiners,
            Request::Refuse { session: 9 },
            Request::EntryDetails {
                collection: "latem".into(),
            },
        ] {
            let again = round_trip_request(&request);
            assert_eq!(format!("{again:?}"), format!("{request:?}"));
        }

        let info = VaultInfo {
            vault: VaultId::random(),
            device,
            recovery: [0xd0, 0x6a, 0x5f, 0x28],
            log_head: 24,
            admin: true,
        };
        let Response::Vault(decoded) = round_trip_response(&Response::Vault(info.clone())) else {
            panic!("not a vault");
        };
        assert_eq!(decoded, info);
        let summaries = vec![CollectionSummary {
            name: "latem".into(),
            secrets: 22,
            variables: 6,
            files: 3,
            key: 2,
            devices: vec![(device, Scope::Write), (DeviceId::random(), Scope::Read)],
        }];
        let Response::CollectionSummaries(decoded) =
            round_trip_response(&Response::CollectionSummaries(summaries.clone()))
        else {
            panic!("not summaries");
        };
        assert_eq!(decoded, summaries);
        let Response::EntryDetails(details) =
            round_trip_response(&Response::EntryDetails(vec![EntryDetail {
                name: "prod/REGION".into(),
                kind: Kind::Var,
                set_by: device,
                key: 2,
                value: Zeroizing::new(b"eu-west".to_vec()),
            }]))
        else {
            panic!("not details");
        };
        assert_eq!(
            (details[0].set_by, details[0].key, &details[0].value[..]),
            (device, 2, &b"eu-west"[..])
        );
        let lines = vec![LogLine {
            seq: 10,
            hash: [3; 32],
            change: 0x03,
            device,
            collection: "latem".into(),
            scope: Scope::Read,
            key: 0,
            signer: Signer::ThisDevice,
        }];
        let Response::Log(decoded) = round_trip_response(&Response::Log(lines.clone())) else {
            panic!("not a log");
        };
        assert_eq!(decoded, lines);
        let event = Event {
            what: Event::ENTRIES | Event::DEVICES,
            collections: vec!["latem".into()],
        };
        let Response::Event(decoded) = round_trip_response(&Response::Event(event.clone())) else {
            panic!("not an event");
        };
        assert_eq!(decoded, event);
        let peers = vec![
            Peer {
                device,
                state: PeerState::Failing,
                seen: Some(3600),
                retry_in: 232,
                error: "can't connect".into(),
            },
            Peer {
                device: DeviceId::random(),
                state: PeerState::NotSeen,
                seen: None,
                retry_in: 0,
                error: String::new(),
            },
        ];
        let Response::Peers(decoded) = round_trip_response(&Response::Peers(peers.clone())) else {
            panic!("not peers");
        };
        assert_eq!(decoded, peers);
        let joiners = vec![Joiner {
            endpoint: [5; 32],
            platform: "macos".into(),
            name: "Mac mini".into(),
        }];
        let Response::Joiners(decoded) = round_trip_response(&Response::Joiners(joiners.clone()))
        else {
            panic!("not joiners");
        };
        assert_eq!(decoded, joiners);
        let request = JoinRequestSummary {
            session: 1,
            device,
            platform: "macos".into(),
            name: "Mac mini".into(),
            hardware: true,
        };
        let Response::JoinRequest(decoded) =
            round_trip_response(&Response::JoinRequest(request.clone()))
        else {
            panic!("not a join request");
        };
        assert_eq!(decoded, request);
        let Response::ScopesSet {
            rotated,
            granted: 2,
            carried: 1,
        } = round_trip_response(&Response::ScopesSet {
            rotated: vec!["latem".into()],
            granted: 2,
            carried: 1,
        })
        else {
            panic!("not scopes set");
        };
        assert_eq!(rotated, ["latem"]);
        let Response::Error {
            code: ErrorCode::WrongCode,
            ..
        } = round_trip_response(&Response::Error {
            code: ErrorCode::WrongCode,
            message: "wrong code; 2 tries left".into(),
        })
        else {
            panic!("not a wrong code");
        };
    }

    #[test]
    fn file_messages_round_trip() {
        let Request::WriteChunk { collection, data } = round_trip_request(&Request::WriteChunk {
            collection: "docs".into(),
            data: ChunkData(Zeroizing::new(vec![9; 1 << 20])),
        }) else {
            panic!("write chunk");
        };
        assert_eq!((collection.as_str(), data.0.len()), ("docs", 1 << 20));
        assert_eq!(format!("{data:?}"), "ChunkData(1048576 bytes)");
        let Request::ReadChunk {
            collection,
            epoch,
            id,
        } = round_trip_request(&Request::ReadChunk {
            collection: "docs".into(),
            epoch: 3,
            id: [4; 32],
        })
        else {
            panic!("read chunk");
        };
        assert_eq!((collection.as_str(), epoch, id), ("docs", 3, [4; 32]));
        for set in [None, Some(Placement::Keep), Some(Placement::OnDemand)] {
            let Request::Placement { set: back, .. } = round_trip_request(&Request::Placement {
                collection: "docs".into(),
                set,
            }) else {
                panic!("placement");
            };
            assert_eq!(back, set);
        }

        let Response::ChunkWritten { id, epoch } = round_trip_response(&Response::ChunkWritten {
            id: [1; 32],
            epoch: 2,
        }) else {
            panic!("chunk written");
        };
        assert_eq!((id, epoch), ([1; 32], 2));
        let Response::Chunk(data) = round_trip_response(&Response::Chunk(ChunkData(
            Zeroizing::new(b"piece".to_vec()),
        ))) else {
            panic!("chunk");
        };
        assert_eq!(&data.0[..], b"piece");
        let Response::Placement(placement) =
            round_trip_response(&Response::Placement(Placement::OnDemand))
        else {
            panic!("placement");
        };
        assert_eq!(placement, Placement::OnDemand);
        let Request::Fetch { collection, name } = round_trip_request(&Request::Fetch {
            collection: "docs".into(),
            name: "2026/passport.pdf".into(),
        }) else {
            panic!("fetch");
        };
        assert_eq!(
            (collection.as_str(), name.as_str()),
            ("docs", "2026/passport.pdf")
        );
        let Response::Fetched { missing } = round_trip_response(&Response::Fetched { missing: 3 })
        else {
            panic!("fetched");
        };
        assert_eq!(missing, 3);

        // A listing gives a file's size and how many of its chunks aren't here.
        let listed = vec![
            Listed {
                name: "prod/REGION".into(),
                kind: Kind::Var,
                size: 0,
                missing: 0,
            },
            Listed {
                name: "release/upload.jks".into(),
                kind: Kind::File,
                size: 3 << 20,
                missing: 2,
            },
        ];
        let Response::Listing(back) = round_trip_response(&Response::Listing(listed.clone()))
        else {
            panic!("listing");
        };
        assert_eq!(back, listed);
        let Response::Entry(Some(value)) = round_trip_response(&Response::Entry(Some(Value {
            kind: Kind::File,
            value: Zeroizing::new(b"manifest".to_vec()),
        }))) else {
            panic!("entry");
        };
        assert_eq!(value.kind, Kind::File);
    }

    #[test]
    fn rejects_bad_messages() {
        let good = Request::Get {
            collection: "latem".into(),
            name: "prod/X".into(),
        }
        .encode();
        let (kind, body) = read_message(&mut &good[..]).unwrap();

        assert!(Request::decode(0x70, &body).is_err(), "unknown type");
        assert!(
            Request::decode(kind, &body[..body.len() - 1]).is_err(),
            "truncated"
        );
        assert!(
            Request::decode(kind, &[&body[..], &[0]].concat()).is_err(),
            "trailing"
        );

        // A count larger than the message can't make the reader allocate for it.
        let lying = [&[0, 5][..], b"latem", &[0xff, 0xff, 0xff, 0xff]].concat();
        assert!(Request::decode(0x04, &lying).is_err());

        for prefix in [[0, 0, 0, 0], ((MAX_MESSAGE + 1) as u32).to_be_bytes()] {
            assert!(read_message(&mut &prefix[..]).is_err());
        }
    }
}
