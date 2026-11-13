//! OpenVault's collections, records, membership log and local store.
//!
//! Formats are specified in `docs/spec/records.md` and `docs/spec/membership.md`. Cryptography comes from
//! `openvault-crypto`; device keys come from whatever implements [`DeviceKeys`].

pub mod env_file;
pub mod file;
pub mod grant;
mod ids;
pub mod join;
mod keys;
pub mod membership;
pub mod names;
pub mod record;
pub mod sets;
mod store;

use std::path::PathBuf;

pub use ids::{CollectionId, DeviceId, VaultId};
pub use keys::{DeviceKeys, SoftwareKeys, transport_seed};
pub use record::{Kind, Version};
pub use store::{
    Approval, CACHE_LIMIT, CHUNK_RETENTION_SECS, CollectionInfo, Entry, EntryInfo, FileLine,
    NAMED_FILES, Placement, Received, Review, Revocation, SWEEP_BATCH, ScopeChange, Swept, Vault,
    Written, WrittenChunk,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Crypto(#[from] openvault_crypto::Error),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("keystore error: {0}")]
    Keystore(String),
    #[error("{0}")]
    InvalidName(&'static str),
    #[error("invalid id")]
    InvalidId,
    #[error("values are at most {} bytes", record::MAX_VALUE_LEN)]
    ValueTooLarge,
    #[error("invalid file manifest: {0}")]
    InvalidManifest(&'static str),
    #[error("chunk {} isn't on this device", hex::encode(&.0[..8]))]
    ChunkMissing(file::ChunkId),
    #[error("a chunk is at most {} bytes", file::CHUNK_SIZE)]
    ChunkTooLarge,
    #[error("no current file in that collection names that chunk")]
    ChunkUnwanted,
    #[error("only secrets, variables and files can be set")]
    NotSettable,
    #[error("a vault already exists at {}", .0.display())]
    VaultExists(PathBuf),
    #[error("no vault at {}", .0.display())]
    NoVault(PathBuf),
    #[error("this vault was created with other device keys")]
    WrongKeys,
    #[error("unsupported store version {0}")]
    UnsupportedStore(i64),
    #[error("collection {0} already exists")]
    CollectionExists(String),
    #[error("no collection {0}")]
    NoSuchCollection(String),
    #[error("this device has no key for collection {0}")]
    NoKey(CollectionId),
    #[error("this device can't write to that collection")]
    ReadOnly,
    #[error("invalid record: {0}")]
    InvalidRecord(&'static str),
    #[error("invalid log entry: {0}")]
    InvalidLogEntry(&'static str),
    #[error("invalid grant: {0}")]
    InvalidGrant(&'static str),
    #[error("invalid join: {0}")]
    InvalidJoin(&'static str),
    #[error("the membership log has forked; an admin must choose a side")]
    Fork,
    #[error("this vault has no membership log yet")]
    NoLog,
    #[error("can't revoke that device: {0}")]
    CantRevoke(&'static str),
    #[error("can't change that device's scope: {0}")]
    CantChangeScope(&'static str),
    #[error("this vault already has a membership log")]
    LogExists,
    #[error("that recovery phrase belongs to another vault")]
    WrongRecoveryKey,
    #[error(
        "this vault's membership log is from before device names were sealed; create the vault again"
    )]
    LogBeforeSealedNames,
    #[error("store is corrupt: {0}")]
    Corrupt(&'static str),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
