//! OpenVault's collections, records and local store.
//!
//! Formats are specified in `docs/spec/records.md`. Cryptography comes from
//! `openvault-crypto`; device keys come from whatever implements [`DeviceKeys`].

mod ids;
mod keys;
pub mod names;
pub mod record;
mod store;

use std::path::PathBuf;

pub use ids::{CollectionId, DeviceId, VaultId};
pub use keys::{DeviceKeys, SoftwareKeys};
pub use record::{Kind, Version};
pub use store::{CollectionInfo, Entry, EntryInfo, Vault};

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
    #[error("only secrets and variables can be set")]
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
    #[error("invalid record: {0}")]
    InvalidRecord(&'static str),
    #[error("store is corrupt: {0}")]
    Corrupt(&'static str),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
