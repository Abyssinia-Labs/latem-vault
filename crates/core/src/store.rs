//! The local store: one SQLite database per vault (records.md, local store).

mod files;
mod revoke;
mod sync;

pub use files::{CACHE_LIMIT, CHUNK_RETENTION_SECS, Placement, SWEEP_BATCH, Swept, WrittenChunk};
pub use revoke::{FileLine, NAMED_FILES, Review, Revocation, ScopeChange, Written};
pub use sync::Received;

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use latem_vault_crypto::hash::{Hash, contexts, derive_key, keyed_hash};
use latem_vault_crypto::{
    RecoveryKey, SigningKey, SymmetricKey, VerifyingKey, WrapKey, WrappedKey,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use zeroize::Zeroizing;

use crate::file::Manifest;
use crate::grant::Grant;
use crate::join::JoinRequest;
use crate::membership::{
    AdminKey, Change, DeviceInfo, DeviceName, LogEntry, Membership, Scope, names_key_context,
};
use crate::record::{Body, Kind, Record, Version};
use crate::sets::{ItemId, SetId, Summary};
use crate::{CollectionId, DeviceId, DeviceKeys, Error, Result, VaultId, names, transport_seed};

/// Version 2 added the membership log, version 3 sealed the device names in it (membership.md,
/// names key), and version 4 added grants (sync.md, grants) and the epoch history to the kept
/// membership, version 5 added set summaries and collections known before their name arrives
/// (sync.md), and version 6 added the records waiting for their key. Opening a version 1 store
/// adds the (empty) log and grants tables. A version 2 store opens only if its log is empty,
/// since its entries are in the old format. Opening a version 3 store rebuilds the kept
/// membership from the log and signs a grant for each collection key the device holds. Opening a
/// version 4 store rebuilds the collections table and adds up its sets. Opening a version 5
/// store lists the records it kept without their key, and keeps the key of each grant to this
/// device it holds, which a device that joined with version 4 didn't. Version 7 added files'
/// chunks (files.md, local store); opening an older store opens again every record that isn't
/// current, since a build before files kept file records without decoding them.
const SCHEMA_VERSION: i64 = 7;

/// Every grant this device knows of, its own and other devices' (sync.md, who stores grants).
const GRANTS_SCHEMA: &str = "
CREATE TABLE grants (
    grant_id BLOB PRIMARY KEY,
    collection_id BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    -- A device id, or 16 zero bytes for the recovery key.
    recipient BLOB NOT NULL,
    grant BLOB NOT NULL
) STRICT;

CREATE INDEX grants_by_recipient ON grants (recipient, collection_id, epoch);
";

/// Records kept before this device had the key for their epoch, as when a record arrives before
/// the grant of its key. When the key arrives they are opened and become entries (records.md,
/// waiting records).
const WAITING_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS waiting (
    record_id BLOB PRIMARY KEY REFERENCES records,
    collection_id BLOB NOT NULL,
    epoch INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS waiting_by_key ON waiting (collection_id, epoch);
";

/// What approving a join gives the joiner (join.md, approval): the whole log, and its grants.
pub struct Approval {
    pub log: Vec<LogEntry>,
    pub grants: Vec<Grant>,
}

/// The membership log (membership.md), in order. Its current state is kept in `meta` as
/// `membership`, so opening a vault doesn't replay it.
const LOG_SCHEMA: &str = "
CREATE TABLE log (
    seq INTEGER PRIMARY KEY,
    hash BLOB NOT NULL,
    entry BLOB NOT NULL
) STRICT;
";

const SCHEMA: &str = "
CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;

CREATE TABLE devices (
    device_id BLOB PRIMARY KEY,
    verifying_key BLOB NOT NULL,
    wrap_key BLOB NOT NULL
) STRICT;

-- A collection's name tag and label are NULL until its collection record has arrived and
-- opened, as on a device that has just joined.
CREATE TABLE collections (
    collection_id BLOB PRIMARY KEY,
    epoch INTEGER NOT NULL,
    name_tag BLOB UNIQUE,
    label BLOB
) STRICT;

CREATE TABLE collection_keys (
    collection_id BLOB NOT NULL REFERENCES collections,
    epoch INTEGER NOT NULL,
    recipient BLOB NOT NULL,
    wrapped BLOB NOT NULL,
    PRIMARY KEY (collection_id, epoch, recipient)
) STRICT;

CREATE TABLE records (
    record_id BLOB PRIMARY KEY,
    collection_id BLOB NOT NULL REFERENCES collections,
    record BLOB NOT NULL
) STRICT;

CREATE INDEX records_by_collection ON records (collection_id, record_id);

-- Each set's item count and id sum (sync.md, sets), updated with every insert.
CREATE TABLE sets (
    set_id BLOB PRIMARY KEY,
    count INTEGER NOT NULL,
    sum BLOB NOT NULL
) STRICT;

-- The current version of each name, including deletions.
CREATE TABLE entries (
    collection_id BLOB NOT NULL REFERENCES collections,
    name_tag BLOB NOT NULL,
    record_id BLOB NOT NULL REFERENCES records,
    lamport INTEGER NOT NULL,
    device_id BLOB NOT NULL,
    deleted INTEGER NOT NULL,
    label BLOB NOT NULL,
    PRIMARY KEY (collection_id, name_tag)
) STRICT;
";

/// Replaces the current version only with a newer one, so the order records arrive in
/// doesn't matter.
const UPSERT_ENTRY: &str = "
INSERT INTO entries (collection_id, name_tag, record_id, lamport, device_id, deleted, label)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
ON CONFLICT (collection_id, name_tag) DO UPDATE SET
    record_id = excluded.record_id,
    lamport = excluded.lamport,
    device_id = excluded.device_id,
    deleted = excluded.deleted,
    label = excluded.label
WHERE (excluded.lamport, excluded.device_id) > (entries.lamport, entries.device_id)
";

/// A secret, variable or file, decrypted. A file's value is its manifest (files.md).
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub value: Zeroizing<Vec<u8>>,
    pub version: Version,
    /// The collection key it was sealed with.
    pub epoch: u32,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("version", &self.version)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryInfo {
    pub name: String,
    pub kind: Kind,
    /// A file's size in bytes; 0 for anything else.
    pub size: u64,
}

/// What an entry's label holds: its kind and name, and a file's size, so listing needs no
/// collection key.
pub(crate) struct Label {
    pub kind: Kind,
    pub name: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionInfo {
    pub id: CollectionId,
    pub name: String,
}

/// An open vault on this device.
pub struct Vault<K: DeviceKeys> {
    conn: Connection,
    keys: K,
    vault_id: VaultId,
    device_id: DeviceId,
    recovery: WrapKey,
    index_key: Zeroizing<[u8; 32]>,
    cache_key: SymmetricKey,
    /// Unwrapped collection keys, so each is unwrapped at most once per open.
    collection_keys: HashMap<(CollectionId, u32), SymmetricKey>,
    /// `None` for a vault created before the membership log, until
    /// [`start_log`](Self::start_log).
    membership: Option<Membership>,
    /// SQLite's `data_version` when `membership` was last loaded, which changes when another
    /// connection writes.
    data_version: i64,
    /// The directory chunks are kept in, beside the database.
    chunks: PathBuf,
    /// Whether chunks became unreferenced since the last finished sweep.
    dropped: AtomicBool,
    /// Whether a received record made a file that names chunks current, since
    /// [`take_files_arrived`](Self::take_files_arrived).
    arrived: AtomicBool,
}

impl<K: DeviceKeys> Vault<K> {
    /// Creates a new vault at `path`, with this device, called `name`, as its only member.
    ///
    /// The recovery key signs the log's first entries as admin (membership.md, creating a
    /// vault), and every collection key is also wrapped to it. `admin` is this device's admin
    /// key, if it has one; genesis lists it as an admin too.
    pub fn create(
        path: &Path,
        keys: K,
        recovery: &RecoveryKey,
        name: &str,
        admin: Option<VerifyingKey>,
    ) -> Result<Self> {
        let vault_id = VaultId::random();
        let device_id = DeviceId::random();
        let (membership, log) =
            start_membership(vault_id, recovery, admin, &keys, device_id, name)?;
        let recovery = recovery.unwrap_key().wrap_key();
        create_file(path)?;
        let init = || -> Result<Connection> {
            let conn = connect(path)?;
            let tx = conn.unchecked_transaction()?;
            init_store(&tx, vault_id, device_id, &recovery, &keys)?;
            save_log(&tx, &log, &membership)?;
            tx.commit()?;
            Ok(conn)
        };
        match init() {
            Ok(conn) => Self::new(
                conn,
                path,
                keys,
                vault_id,
                device_id,
                recovery,
                Some(membership),
            ),
            Err(e) => {
                let _ = std::fs::remove_file(path);
                Err(e)
            }
        }
    }

    /// Opens the vault at `path`. `keys` must be the keys it was created with.
    pub fn open(path: &Path, keys: K) -> Result<Self> {
        if !path.exists() {
            return Err(Error::NoVault(path.into()));
        }
        let mut conn = connect(path)?;
        upgrade(&mut conn, &keys)?;
        let vault_id = VaultId::try_from(meta(&conn, "vault_id")?.as_slice())?;
        let device_id = DeviceId::try_from(meta(&conn, "device_id")?.as_slice())?;
        let recovery = WrapKey::from_bytes(&meta(&conn, "recovery_wrap_key")?)?;
        let (verifying_key, wrap_key): (Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT verifying_key, wrap_key FROM devices WHERE device_id = ?1",
                [&device_id.as_bytes()[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(Error::Corrupt("this device isn't in the device table"))?;
        if verifying_key != keys.verifying_key().as_bytes()
            || wrap_key != keys.wrap_key().as_bytes()
        {
            return Err(Error::WrongKeys);
        }
        let membership = load_membership(&conn, vault_id, device_id, &keys)?;
        let mut vault = Self::new(conn, path, keys, vault_id, device_id, recovery, membership)?;
        vault.open_waiting()?;
        Ok(vault)
    }

    fn new(
        conn: Connection,
        path: &Path,
        keys: K,
        vault_id: VaultId,
        device_id: DeviceId,
        recovery: WrapKey,
        membership: Option<Membership>,
    ) -> Result<Self> {
        let local = keys.local_key().as_bytes();
        let index_key = derive_key(contexts::LOCAL_INDEX, local);
        let cache_key = SymmetricKey::from_bytes(*derive_key(contexts::LOCAL_CACHE, local));
        let data_version = data_version(&conn)?;
        Ok(Self {
            conn,
            keys,
            vault_id,
            device_id,
            recovery,
            index_key,
            cache_key,
            collection_keys: HashMap::new(),
            membership,
            data_version,
            chunks: path.with_file_name("chunks"),
            dropped: AtomicBool::new(false),
            arrived: AtomicBool::new(false),
        })
    }

    /// Reloads the membership this vault keeps in memory if another process has written to
    /// the store since it was loaded (service.md, the store). Returns whether it had.
    pub fn refresh(&mut self) -> Result<bool> {
        let version = data_version(&self.conn)?;
        if version == self.data_version {
            return Ok(false);
        }
        self.membership = load_membership(&self.conn, self.vault_id, self.device_id, &self.keys)?;
        self.data_version = version;
        Ok(true)
    }

    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The id of the vault at `path`, read without its keys: for a grandfather started on one of
    /// the vault's devices (coordinator.md).
    pub fn id_at(path: &Path) -> Result<VaultId> {
        if !path.exists() {
            return Err(Error::NoVault(path.into()));
        }
        VaultId::try_from(meta(&connect(path)?, "vault_id")?.as_slice())
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Who is in the vault, or `None` for a vault that hasn't started its log.
    pub fn membership(&self) -> Option<&Membership> {
        self.membership.as_ref()
    }

    /// The recovery key's public half, which wraps keys to it.
    pub fn recovery_key(&self) -> &WrapKey {
        &self.recovery
    }

    /// Whether `recovery` is this vault's recovery key.
    pub fn is_recovery_key(&self, recovery: &RecoveryKey) -> bool {
        recovery.unwrap_key().wrap_key() == self.recovery
    }

    /// The platform and name of `device`, opened with the names key from this device's own
    /// add_device entry (membership.md, names key). `None` if the log doesn't list the device.
    pub fn device_name(&self, device: DeviceId) -> Result<Option<DeviceName>> {
        let Some(membership) = &self.membership else {
            return Ok(None);
        };
        let Some(target) = membership.device(device) else {
            return Ok(None);
        };
        let name = target
            .info
            .name
            .open(&self.names_key(membership)?, self.vault_id, device)?;
        Ok(Some(name))
    }

    /// The names key, from this device's own add_device entry.
    fn names_key(&self, membership: &Membership) -> Result<SymmetricKey> {
        let this = membership
            .device(self.device_id)
            .ok_or(Error::Corrupt("this device isn't in the membership log"))?;
        self.keys
            .unwrap(&names_key_context(self.vault_id), &this.info.names_key)
    }

    /// Every log entry, in order.
    pub fn log(&self) -> Result<Vec<LogEntry>> {
        read_log(&self.conn)
    }

    /// At most `max` log entries from seq `from`, in order.
    pub fn log_range(&self, from: u64, max: usize) -> Result<Vec<LogEntry>> {
        let from = i64::try_from(from).unwrap_or(i64::MAX);
        let max = i64::try_from(max).unwrap_or(i64::MAX);
        let mut statement = self
            .conn
            .prepare("SELECT entry FROM log WHERE seq >= ?1 ORDER BY seq LIMIT ?2")?;
        let rows = statement.query_map(params![from, max], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|entry| LogEntry::from_bytes(&entry?))
            .collect::<Result<_>>()
    }

    /// Approves a join (join.md, approval). `admin` signs add_device for `request` and a
    /// set_scope for each of `scopes`, and this device grants the joiner every key it holds for
    /// the collections the joiner may read. All of it is written in one transaction.
    ///
    /// If the joiner is already in the log with the same keys, an approved join was
    /// interrupted: nothing is signed, and the grants written then are returned again.
    pub fn approve_join(
        &mut self,
        request: &JoinRequest,
        scopes: &[(CollectionId, Scope)],
        admin: &impl AdminKey,
    ) -> Result<Approval> {
        let membership = self.membership.as_ref().ok_or(Error::NoLog)?;
        if let Some(existing) = membership.device(request.device) {
            let same_keys = existing.info.verifying_key == request.verifying_key
                && existing.info.wrap_key == request.wrap_key
                && existing.info.transport_key == request.transport_key;
            if existing.revoked || !same_keys {
                return Err(Error::InvalidJoin(
                    "the device id is in the log with other keys, or revoked",
                ));
            }
            return Ok(Approval {
                log: self.log()?,
                grants: self.grants_to(request.device)?,
            });
        }

        // Signed before anything is written, so a refused signature leaves nothing behind.
        let info = DeviceInfo::new(
            self.vault_id,
            request.device,
            request.verifying_key.clone(),
            request.wrap_key.clone(),
            request.transport_key.clone(),
            &request.name,
            &self.names_key(membership)?,
        )?;
        let mut membership = membership.clone();
        let mut entries = vec![membership.append(Change::AddDevice(info), admin)?];
        for &(collection, scope) in scopes {
            if scope != Scope::None {
                let change = Change::SetScope {
                    device: request.device,
                    collection,
                    scope,
                };
                entries.push(membership.append(change, admin)?);
            }
        }

        let mut grants = Vec::new();
        for &(collection, scope) in scopes {
            if scope < Scope::Read {
                continue;
            }
            let current = membership.epoch(collection).expect("set_scope named it");
            for epoch in 0..=current {
                // Keys this device doesn't hold come from a device that does (join.md).
                let key = match self.take_key(collection, epoch) {
                    Ok(key) => key,
                    Err(Error::NoKey(_)) => continue,
                    Err(e) => return Err(e),
                };
                let wrapped = request
                    .wrap_key
                    .wrap(&wrap_context(self.vault_id, collection, epoch), &key);
                self.collection_keys.insert((collection, epoch), key);
                grants.push(self.sign_grant(collection, epoch, Some(request.device), wrapped)?);
            }
        }

        let tx = self.conn.unchecked_transaction()?;
        save_log(&tx, &entries, &membership)?;
        for grant in &grants {
            insert_grant(&tx, grant)?;
        }
        tx.commit()?;
        self.membership = Some(membership);
        Ok(Approval {
            log: self.log()?,
            grants,
        })
    }

    /// Creates the store of a device that has just joined (join.md, joining), from what the
    /// admin sent. It checks that `log` verifies from genesis and ends at `head`, that it adds
    /// `device` with `keys` and the `name` the joiner sent, and that every grant is to this
    /// device, valid, and unwraps.
    pub fn join(
        path: &Path,
        keys: K,
        device: DeviceId,
        name: &DeviceName,
        head: (u64, Hash),
        log: &[LogEntry],
        grants: &[Grant],
    ) -> Result<Self> {
        let membership = Membership::replay(log)?;
        if membership.head() != head {
            return Err(Error::InvalidJoin(
                "the log doesn't end at the admin's head",
            ));
        }
        let vault_id = membership.vault();
        let this = membership
            .device(device)
            .filter(|this| !this.revoked)
            .ok_or(Error::InvalidJoin("the log doesn't add this device"))?;
        let transport = SigningKey::from_ed25519_seed(&transport_seed(&keys)).verifying_key();
        if this.info.verifying_key != keys.verifying_key()
            || this.info.wrap_key != keys.wrap_key()
            || this.info.transport_key != transport
        {
            return Err(Error::InvalidJoin(
                "the log adds this device with other keys",
            ));
        }
        let names_key = keys
            .unwrap(&names_key_context(vault_id), &this.info.names_key)
            .map_err(|_| Error::InvalidJoin("the names key doesn't unwrap"))?;
        if this
            .info
            .name
            .open(&names_key, vault_id, device)
            .ok()
            .as_ref()
            != Some(name)
        {
            return Err(Error::InvalidJoin(
                "the log has another name for this device",
            ));
        }
        for grant in grants {
            if grant.recipient() != Some(device) {
                return Err(Error::InvalidJoin("a grant is for another device"));
            }
            grant.check(&membership)?;
            let context = wrap_context(vault_id, grant.collection(), grant.epoch());
            keys.unwrap(&context, grant.wrapped())
                .map_err(|_| Error::InvalidJoin("a grant doesn't unwrap"))?;
        }

        let recovery = membership.recovery_key().clone();
        create_file(path)?;
        let init = || -> Result<Connection> {
            let conn = connect(path)?;
            let tx = conn.unchecked_transaction()?;
            init_store(&tx, vault_id, device, &recovery, &keys)?;
            save_log(&tx, log, &membership)?;
            for grant in grants {
                insert_grant(&tx, grant)?;
                let epoch = membership
                    .epoch(grant.collection())
                    .expect("checked by the grant");
                ensure_collection(&tx, grant.collection(), epoch)?;
                keep_own_key(&tx, grant, &keys.wrap_key())?;
            }
            tx.commit()?;
            Ok(conn)
        };
        match init() {
            Ok(conn) => Self::new(
                conn,
                path,
                keys,
                vault_id,
                device,
                recovery,
                Some(membership),
            ),
            Err(e) => {
                let _ = std::fs::remove_file(path);
                Err(e)
            }
        }
    }

    /// The grants to `device` that this store holds.
    fn grants_to(&self, device: DeviceId) -> Result<Vec<Grant>> {
        let mut statement = self.conn.prepare(
            "SELECT grant FROM grants WHERE recipient = ?1 ORDER BY collection_id, epoch",
        )?;
        let rows = statement.query_map([&device.as_bytes()[..]], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|bytes| Grant::from_bytes(&bytes?))
            .collect::<Result<_>>()
    }

    /// A grant of `wrapped` signed with this device's signing key.
    fn sign_grant(
        &self,
        collection: CollectionId,
        epoch: u32,
        recipient: Option<DeviceId>,
        wrapped: WrappedKey,
    ) -> Result<Grant> {
        Grant::sign(
            self.vault_id,
            collection,
            epoch,
            recipient,
            wrapped,
            self.keys.verifying_key(),
            |context, message| self.keys.sign(context, message),
        )
    }

    /// Starts the log of a vault created before there was one (membership.md, creating a
    /// vault): genesis, this device as `name`, and `write` on every existing collection, all
    /// signed by `recovery`, which must be this vault's recovery key.
    pub fn start_log(&mut self, recovery: &RecoveryKey, name: &str) -> Result<()> {
        if self.membership.is_some() {
            return Err(Error::LogExists);
        }
        if !self.is_recovery_key(recovery) {
            return Err(Error::WrongRecoveryKey);
        }
        let (mut membership, mut log) = start_membership(
            self.vault_id,
            recovery,
            None,
            &self.keys,
            self.device_id,
            name,
        )?;
        let admin = recovery.admin_signing_key();
        for collection in self.collections()? {
            let scope = Change::SetScope {
                device: self.device_id,
                collection: collection.id,
                scope: Scope::Write,
            };
            log.push(membership.append(scope, &admin)?);
            for epoch in 1..=self.epoch(collection.id)? {
                let rotate = Change::RotateEpoch {
                    collection: collection.id,
                    epoch,
                };
                log.push(membership.append(rotate, &admin)?);
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        save_log(&tx, &log, &membership)?;
        write_own_grants(
            &tx,
            self.vault_id,
            self.device_id,
            &self.recovery,
            &self.keys,
        )?;
        tx.commit()?;
        self.membership = Some(membership);
        Ok(())
    }

    /// Creates a collection this device can write. `admin` signs the set_scope entry that
    /// gives it `write` (membership.md, types), so the vault must have started its log.
    pub fn create_collection(&mut self, name: &str, admin: &impl AdminKey) -> Result<CollectionId> {
        names::check_collection(name)?;
        let membership = self.membership.as_ref().ok_or(Error::NoLog)?;
        let tag = self.collection_tag(name);
        if collection_exists(&self.conn, &tag)? {
            return Err(Error::CollectionExists(name.into()));
        }
        let id = CollectionId::random();
        // Signed before anything is written, so a refused signature leaves nothing behind.
        let mut membership = membership.clone();
        let scope = Change::SetScope {
            device: self.device_id,
            collection: id,
            scope: Scope::Write,
        };
        let entry = membership.append(scope, admin)?;
        let key = SymmetricKey::generate();

        let tx = self.conn.unchecked_transaction()?;
        // Again inside the transaction, in case another process created it meanwhile.
        if collection_exists(&tx, &tag)? {
            return Err(Error::CollectionExists(name.into()));
        }
        let label = self
            .cache_key
            .seal(&collection_label_aad(id), name.as_bytes());
        tx.execute(
            "INSERT INTO collections VALUES (?1, 0, ?2, ?3)",
            params![&id.as_bytes()[..], &tag[..], label],
        )?;
        let context = wrap_context(self.vault_id, id, 0);
        // This device and the recovery key get the key, as collection_keys rows to unwrap and
        // as grants to sync (sync.md, who writes grants).
        for (recipient, wrap_key) in [
            (Some(self.device_id), self.keys.wrap_key()),
            (None, self.recovery.clone()),
        ] {
            let wrapped = wrap_key.wrap(&context, &key);
            tx.execute(
                "INSERT INTO collection_keys VALUES (?1, 0, ?2, ?3)",
                params![&id.as_bytes()[..], wrap_key.as_bytes(), wrapped.to_bytes()],
            )?;
            insert_grant(&tx, &self.sign_grant(id, 0, recipient, wrapped)?)?;
        }
        let body = Body::new(Kind::Collection, "", name.as_bytes());
        self.write_record(&tx, id, 0, &key, &body, false)?;
        save_log(&tx, &[entry], &membership)?;
        tx.commit()?;

        self.collection_keys.insert((id, 0), key);
        self.membership = Some(membership);
        Ok(id)
    }

    /// Finds a collection by name.
    pub fn collection(&self, name: &str) -> Result<CollectionId> {
        names::check_collection(name)?;
        self.conn
            .query_row(
                "SELECT collection_id FROM collections WHERE name_tag = ?1",
                [&self.collection_tag(name)[..]],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .ok_or_else(|| Error::NoSuchCollection(name.into()))
            .and_then(|id| CollectionId::try_from(id.as_slice()))
    }

    /// Every collection on this device, by name.
    pub fn collections(&self) -> Result<Vec<CollectionInfo>> {
        let mut statement = self
            .conn
            .prepare("SELECT collection_id, label FROM collections WHERE label IS NOT NULL")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut collections = rows
            .map(|row| {
                let (id, label) = row?;
                let id = CollectionId::try_from(id.as_slice())?;
                let name = self.cache_key.open(&collection_label_aad(id), &label)?;
                let name = String::from_utf8(name.to_vec())
                    .map_err(|_| Error::Corrupt("collection label"))?;
                Ok(CollectionInfo { id, name })
            })
            .collect::<Result<Vec<_>>>()?;
        collections.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(collections)
    }

    /// Sets a secret, variable or file, replacing any current value. A file's value is its
    /// manifest, and this device must hold every chunk it names.
    pub fn set(
        &mut self,
        collection: CollectionId,
        name: &str,
        kind: Kind,
        value: &[u8],
    ) -> Result<()> {
        self.set_all(collection, [(name, kind, value)])
    }

    /// Sets several secrets, variables and files in one transaction, so either all of them are
    /// written or none are.
    pub fn set_all<'a>(
        &mut self,
        collection: CollectionId,
        entries: impl IntoIterator<Item = (&'a str, Kind, &'a [u8])>,
    ) -> Result<()> {
        let bodies = entries
            .into_iter()
            .map(|(name, kind, value)| {
                if kind == Kind::Collection {
                    return Err(Error::NotSettable);
                }
                names::check_entry(name)?;
                Ok(Body::new(kind, name, value))
            })
            .collect::<Result<Vec<_>>>()?;
        if bodies.is_empty() {
            return Ok(());
        }
        self.write(collection, &bodies, false)
    }

    /// The current value of a secret, variable or file, or `None` if it doesn't exist or was
    /// deleted.
    pub fn get(&mut self, collection: CollectionId, name: &str) -> Result<Option<Entry>> {
        names::check_entry(name)?;
        self.epoch(collection)?;
        let tag = self.entry_tag(collection, name);
        let current = self
            .conn
            .query_row(
                "SELECT record_id, deleted FROM entries WHERE collection_id = ?1 AND name_tag = ?2",
                params![&collection.as_bytes()[..], &tag[..]],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?;
        let Some((record_id, false)) = current else {
            return Ok(None);
        };
        let record = self.load_record(&record_id)?;
        let body = self.open_record(collection, &record)?;
        if body.name != name || body.kind == Kind::Collection {
            return Err(Error::Corrupt("index points at another entry"));
        }
        Ok(Some(Entry {
            name: body.name,
            kind: body.kind,
            value: body.value,
            version: record.header().version,
            epoch: record.header().epoch,
        }))
    }

    /// Deletes a secret, variable or file. Returns whether there was one to delete.
    pub fn delete(&mut self, collection: CollectionId, name: &str) -> Result<bool> {
        names::check_entry(name)?;
        self.epoch(collection)?;
        let tag = self.entry_tag(collection, name);
        let current = self
            .conn
            .query_row(
                "SELECT deleted, label FROM entries WHERE collection_id = ?1 AND name_tag = ?2",
                params![&collection.as_bytes()[..], &tag[..]],
                |row| Ok((row.get::<_, bool>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let Some((false, label)) = current else {
            return Ok(false);
        };
        let kind = self.open_entry_label(collection, &tag, &label)?.kind;
        self.write(collection, &[Body::new(kind, name, b"")], true)?;
        Ok(true)
    }

    /// The names and kinds of a collection's current secrets, variables and files, by name, with
    /// files' sizes.
    ///
    /// Reads only the index, so it needs no collection key.
    pub fn list(&self, collection: CollectionId) -> Result<Vec<EntryInfo>> {
        self.epoch(collection)?;
        let mut statement = self.conn.prepare(
            "SELECT name_tag, label FROM entries WHERE collection_id = ?1 AND deleted = 0",
        )?;
        let rows = statement.query_map([&collection.as_bytes()[..]], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let (tag, label) = row?;
            let tag: Hash = tag.try_into().map_err(|_| Error::Corrupt("name tag"))?;
            let Label { kind, name, size } = self.open_entry_label(collection, &tag, &label)?;
            if kind != Kind::Collection {
                entries.push(EntryInfo { name, kind, size });
            }
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// The current secrets, variables and files under `folder/`, such as every entry in `prod/`.
    pub fn entries_in(&mut self, collection: CollectionId, folder: &str) -> Result<Vec<Entry>> {
        let prefix = format!("{folder}/");
        let names: Vec<String> = self
            .list(collection)?
            .into_iter()
            .filter_map(|info| info.name.starts_with(&prefix).then_some(info.name))
            .collect();
        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            entries.extend(self.get(collection, &name)?);
        }
        Ok(entries)
    }

    fn write(&mut self, collection: CollectionId, bodies: &[Body], deleted: bool) -> Result<()> {
        let epoch = self.epoch(collection)?;
        // Other devices would refuse its records (sync.md, accepting records).
        if let Some(membership) = &self.membership
            && membership.scope(self.device_id, collection) != Scope::Write
        {
            return Err(Error::ReadOnly);
        }
        if !deleted {
            for body in bodies.iter().filter(|body| body.kind == Kind::File) {
                self.check_chunks(collection, epoch, &Manifest::decode(&body.value)?)?;
            }
        }
        let key = self.take_key(collection, epoch)?;
        let result = self.commit_records(collection, epoch, &key, bodies, deleted);
        self.collection_keys.insert((collection, epoch), key);
        result
    }

    fn commit_records(
        &self,
        collection: CollectionId,
        epoch: u32,
        key: &SymmetricKey,
        bodies: &[Body],
        deleted: bool,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for body in bodies {
            self.write_record(&tx, collection, epoch, key, body, deleted)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Writes a new record with the next Lamport clock value and makes it current.
    fn write_record(
        &self,
        tx: &Transaction<'_>,
        collection: CollectionId,
        epoch: u32,
        key: &SymmetricKey,
        body: &Body,
        deleted: bool,
    ) -> Result<()> {
        let clock = u64::from_be_bytes(
            meta(tx, "clock")?
                .try_into()
                .map_err(|_| Error::Corrupt("clock"))?,
        );
        let lamport = clock
            .checked_add(1)
            .ok_or(Error::Corrupt("clock overflow"))?;
        let version = Version {
            lamport,
            device: self.device_id,
        };
        let record = Record::seal(collection, epoch, version, deleted, body, key, &self.keys)?;
        let record_id = record.id();
        tx.execute(
            "INSERT INTO records VALUES (?1, ?2, ?3)",
            params![
                &record_id[..],
                &collection.as_bytes()[..],
                record.to_bytes()
            ],
        )?;
        add_to_set(tx, SetId::records(collection), &record_id)?;

        let tag = self.entry_tag(collection, &body.name);
        let label = self.entry_label(collection, &tag, body, deleted);
        tx.execute(
            UPSERT_ENTRY,
            params![
                &collection.as_bytes()[..],
                &tag[..],
                &record_id[..],
                i64::try_from(lamport).map_err(|_| Error::Corrupt("clock overflow"))?,
                &self.device_id.as_bytes()[..],
                deleted,
                label
            ],
        )?;
        // A local write is always the newest version.
        self.set_file_chunks(
            tx,
            collection,
            &tag,
            &files::named_chunks(body.kind, deleted, &body.value),
        )?;
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'clock'",
            [&lamport.to_be_bytes()[..]],
        )?;
        Ok(())
    }

    fn load_record(&self, record_id: &[u8]) -> Result<Record> {
        let bytes: Vec<u8> = self
            .conn
            .query_row(
                "SELECT record FROM records WHERE record_id = ?1",
                [record_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(Error::Corrupt("index points at a missing record"))?;
        let record = Record::from_bytes(&bytes)?;
        if record.id() != record_id {
            return Err(Error::Corrupt("record doesn't match its id"));
        }
        Ok(record)
    }

    fn open_record(&mut self, collection: CollectionId, record: &Record) -> Result<Body> {
        let header = record.header();
        if header.collection != collection {
            return Err(Error::Corrupt("record is from another collection"));
        }
        let author = self.device_key(header.version.device)?;
        let key = self.take_key(collection, header.epoch)?;
        let body = record.open(&author, &key);
        self.collection_keys.insert((collection, header.epoch), key);
        body
    }

    /// Removes a collection key from the cache, or unwraps it. Callers put it back.
    fn take_key(&mut self, collection: CollectionId, epoch: u32) -> Result<SymmetricKey> {
        if let Some(key) = self.collection_keys.remove(&(collection, epoch)) {
            return Ok(key);
        }
        let wrapped: Vec<u8> = self
            .conn
            .query_row(
                "SELECT wrapped FROM collection_keys
                 WHERE collection_id = ?1 AND epoch = ?2 AND recipient = ?3",
                params![
                    &collection.as_bytes()[..],
                    epoch,
                    self.keys.wrap_key().as_bytes()
                ],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(Error::NoKey(collection))?;
        self.keys.unwrap(
            &wrap_context(self.vault_id, collection, epoch),
            &WrappedKey::from_bytes(&wrapped)?,
        )
    }

    fn epoch(&self, collection: CollectionId) -> Result<u32> {
        self.conn
            .query_row(
                "SELECT epoch FROM collections WHERE collection_id = ?1",
                [&collection.as_bytes()[..]],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| Error::NoSuchCollection(collection.to_string()))
    }

    fn device_key(&self, device: DeviceId) -> Result<VerifyingKey> {
        if let Some(device) = self.membership.as_ref().and_then(|m| m.device(device)) {
            return Ok(device.info.verifying_key.clone());
        }
        // A vault from before the membership log knows only this device.
        let bytes: Vec<u8> = self
            .conn
            .query_row(
                "SELECT verifying_key FROM devices WHERE device_id = ?1",
                [&device.as_bytes()[..]],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(Error::InvalidRecord("unknown author"))?;
        Ok(VerifyingKey::from_bytes(&bytes)?)
    }

    /// `kind ‖ name`, or `kind ‖ size ‖ name` for a file, sealed with the cache key.
    fn entry_label(
        &self,
        collection: CollectionId,
        tag: &Hash,
        body: &Body,
        deleted: bool,
    ) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(9 + body.name.len());
        plaintext.push(body.kind.code());
        if body.kind == Kind::File {
            let size = if deleted {
                0
            } else {
                crate::file::size_of(&body.value).unwrap_or(0)
            };
            plaintext.extend_from_slice(&size.to_be_bytes());
        }
        plaintext.extend_from_slice(body.name.as_bytes());
        self.cache_key
            .seal(&entry_label_aad(collection, tag), &plaintext)
    }

    fn open_entry_label(
        &self,
        collection: CollectionId,
        tag: &Hash,
        label: &[u8],
    ) -> Result<Label> {
        const CORRUPT: Error = Error::Corrupt("entry label");
        let plaintext = self
            .cache_key
            .open(&entry_label_aad(collection, tag), label)?;
        let (&kind, rest) = plaintext.split_first().ok_or(CORRUPT)?;
        let kind = Kind::from_code(kind).ok_or(CORRUPT)?;
        let (size, name) = if kind == Kind::File {
            let (size, name) = rest.split_first_chunk::<8>().ok_or(CORRUPT)?;
            (u64::from_be_bytes(*size), name)
        } else {
            (0, rest)
        };
        let name = String::from_utf8(name.to_vec()).map_err(|_| CORRUPT)?;
        Ok(Label { kind, name, size })
    }

    fn entry_tag(&self, collection: CollectionId, name: &str) -> Hash {
        let input = [b"entry\0", &collection.as_bytes()[..], name.as_bytes()].concat();
        keyed_hash(&self.index_key, &input)
    }

    fn collection_tag(&self, name: &str) -> Hash {
        keyed_hash(
            &self.index_key,
            &[b"collection\0", name.as_bytes()].concat(),
        )
    }
}

fn connect(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.pragma_update(None, "foreign_keys", true)?;
    // Overwrite deleted content instead of leaving it in free pages.
    conn.pragma_update(None, "secure_delete", true)?;
    // Several `latem-vault run` processes may read while another writes.
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(conn)
}

/// Brings an older store up to [`SCHEMA_VERSION`]. Version 1 had no membership log, version
/// 2's log had device names in the clear, and version 3 had no grants or epoch history.
fn upgrade(conn: &mut Connection, keys: &impl DeviceKeys) -> Result<()> {
    match user_version(conn)? {
        SCHEMA_VERSION => return Ok(()),
        1..=6 => {}
        other => return Err(Error::UnsupportedStore(other)),
    }
    // Rebuilding the collections table needs foreign keys off, which can only change outside a
    // transaction.
    conn.pragma_update(None, "foreign_keys", false)?;
    let result = upgrade_in_transaction(conn, keys);
    conn.pragma_update(None, "foreign_keys", true)?;
    result
}

fn upgrade_in_transaction(conn: &mut Connection, keys: &impl DeviceKeys) -> Result<()> {
    // Immediate, so two processes opening the same old store don't both upgrade it.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version = user_version(&tx)?;
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version == 1 {
        tx.execute_batch(LOG_SCHEMA)?;
    }
    if version == 2 {
        let entries: i64 = tx.query_row("SELECT count(*) FROM log", [], |row| row.get(0))?;
        if entries > 0 {
            return Err(Error::LogBeforeSealedNames);
        }
    }
    if version < 4 {
        tx.execute_batch(GRANTS_SCHEMA)?;
    }
    if version < 5 {
        tx.execute_batch(V5_SCHEMA)?;
    }
    let log = read_log(&tx)?;
    if version < 4 && !log.is_empty() {
        // The kept membership gained the epoch history, so it's rebuilt from the log.
        let membership = Membership::replay(&log)?;
        save_log(&tx, &[], &membership)?;
        let vault = VaultId::try_from(meta(&tx, "vault_id")?.as_slice())?;
        let device = DeviceId::try_from(meta(&tx, "device_id")?.as_slice())?;
        let recovery = WrapKey::from_bytes(&meta(&tx, "recovery_wrap_key")?)?;
        write_own_grants(&tx, vault, device, &recovery, keys)?;
    }
    if version < 5 {
        // After any grants the step above signs.
        sum_sets(&tx)?;
    }
    tx.execute_batch(WAITING_SCHEMA)?;
    tx.execute_batch(files::FILES_SCHEMA)?;
    // Before the keys below arrive, so the records they open are on the list.
    list_waiting(&tx)?;
    if version < 6 && !log.is_empty() {
        keep_granted_keys(&tx, &log, keys)?;
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(())
}

/// Version 5: collections whose name hasn't arrived yet, the sets, and the index that reads a
/// collection's record ids in order. The collections table is rebuilt to make its name columns
/// nullable, which needs foreign keys off: `upgrade` turns them off around the transaction.
const V5_SCHEMA: &str = "
CREATE TABLE collections_v5 (
    collection_id BLOB PRIMARY KEY,
    epoch INTEGER NOT NULL,
    name_tag BLOB UNIQUE,
    label BLOB
) STRICT;
INSERT INTO collections_v5 SELECT collection_id, epoch, name_tag, label FROM collections;
DROP TABLE collections;
ALTER TABLE collections_v5 RENAME TO collections;
CREATE INDEX IF NOT EXISTS records_by_collection ON records (collection_id, record_id);
CREATE TABLE IF NOT EXISTS sets (
    set_id BLOB PRIMARY KEY,
    count INTEGER NOT NULL,
    sum BLOB NOT NULL
) STRICT;
";

/// Lists each record that isn't an entry's current version as waiting to be opened: the upgrade
/// to version 6, which added the list for records kept without their key, and to version 7, since
/// an older build kept file records it couldn't decode. Opening the vault opens the ones whose
/// key it has by then; the rest wait for their key.
fn list_waiting(tx: &Transaction<'_>) -> Result<()> {
    // Only records that aren't an entry's current version, and of those, each is parsed.
    let mut waiting = Vec::new();
    {
        let mut statement = tx.prepare(
            "SELECT record FROM records WHERE record_id NOT IN (SELECT record_id FROM entries)",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let record = Record::from_bytes(&row.get::<_, Vec<u8>>(0)?)?;
            waiting.push((
                record.id(),
                record.header().collection,
                record.header().epoch,
            ));
        }
    }
    for (id, collection, epoch) in waiting {
        tx.execute(
            "INSERT OR IGNORE INTO waiting VALUES (?1, ?2, ?3)",
            params![&id[..], &collection.as_bytes()[..], epoch],
        )?;
    }
    Ok(())
}

/// Keeps the key of each grant to this device that it holds without the key: a device that
/// joined with version 4 kept its grants but not their keys (the upgrade to version 6).
fn keep_granted_keys(tx: &Transaction<'_>, log: &[LogEntry], keys: &impl DeviceKeys) -> Result<()> {
    let wrap_key = keys.wrap_key();
    let device = DeviceId::try_from(meta(tx, "device_id")?.as_slice())?;
    let grants: Vec<Vec<u8>> = {
        let mut statement = tx.prepare(
            "SELECT grant FROM grants g WHERE recipient = ?1 AND NOT EXISTS (
                 SELECT 1 FROM collection_keys k
                 WHERE k.collection_id = g.collection_id AND k.epoch = g.epoch
                 AND k.recipient = ?2
             )",
        )?;
        statement
            .query_map(
                params![&device.as_bytes()[..], wrap_key.as_bytes()],
                |row| row.get(0),
            )?
            .collect::<rusqlite::Result<_>>()?
    };
    if grants.is_empty() {
        return Ok(());
    }
    let membership = Membership::replay(log)?;
    for bytes in grants {
        let grant = Grant::from_bytes(&bytes)?;
        let context = wrap_context(membership.vault(), grant.collection(), grant.epoch());
        if keys.unwrap(&context, grant.wrapped()).is_err() {
            continue;
        }
        let Some(epoch) = membership.epoch(grant.collection()) else {
            continue;
        };
        ensure_collection(tx, grant.collection(), epoch)?;
        keep_own_key(tx, &grant, &wrap_key)?;
    }
    Ok(())
}

/// Adds up every set from the records and grants already stored.
fn sum_sets(tx: &Transaction<'_>) -> Result<()> {
    tx.execute("DELETE FROM sets", [])?;
    let mut sets: HashMap<SetId, Summary> = HashMap::new();
    {
        let mut statement = tx.prepare("SELECT collection_id, record_id FROM records")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (collection, id) = row?;
            let collection = CollectionId::try_from(collection.as_slice())?;
            let id: ItemId = id.try_into().map_err(|_| Error::Corrupt("record id"))?;
            sets.entry(SetId::records(collection)).or_default().add(&id);
        }
        let mut statement = tx.prepare("SELECT grant_id FROM grants")?;
        for id in statement.query_map([], |row| row.get::<_, Vec<u8>>(0))? {
            let id: ItemId = id?.try_into().map_err(|_| Error::Corrupt("grant id"))?;
            sets.entry(SetId::GRANTS).or_default().add(&id);
        }
    }
    for (set, summary) in sets {
        tx.execute(
            "INSERT INTO sets VALUES (?1, ?2, ?3)",
            params![
                &set.as_bytes()[..],
                i64::try_from(summary.count).map_err(|_| Error::Corrupt("set count"))?,
                &summary.sum[..]
            ],
        )?;
    }
    Ok(())
}

/// Creates the store's file, so it is never readable by others, even briefly.
fn create_file(path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    match options.open(path) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(Error::VaultExists(path.into()))
        }
        result => {
            drop(result?);
            Ok(())
        }
    }
}

/// The tables and this device's rows in a new store.
fn init_store(
    tx: &Transaction<'_>,
    vault: VaultId,
    device: DeviceId,
    recovery: &WrapKey,
    keys: &impl DeviceKeys,
) -> Result<()> {
    tx.execute_batch(SCHEMA)?;
    tx.execute_batch(LOG_SCHEMA)?;
    tx.execute_batch(GRANTS_SCHEMA)?;
    tx.execute_batch(WAITING_SCHEMA)?;
    tx.execute_batch(files::FILES_SCHEMA)?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    for (key, value) in [
        ("vault_id", &vault.as_bytes()[..]),
        ("device_id", &device.as_bytes()[..]),
        ("recovery_wrap_key", recovery.as_bytes()),
        ("clock", &0u64.to_be_bytes()[..]),
    ] {
        tx.execute("INSERT INTO meta VALUES (?1, ?2)", params![key, value])?;
    }
    tx.execute(
        "INSERT INTO devices VALUES (?1, ?2, ?3)",
        params![
            &device.as_bytes()[..],
            keys.verifying_key().as_bytes(),
            keys.wrap_key().as_bytes()
        ],
    )?;
    Ok(())
}

fn read_log(conn: &Connection) -> Result<Vec<LogEntry>> {
    let mut statement = conn.prepare("SELECT entry FROM log ORDER BY seq")?;
    let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    rows.map(|entry| LogEntry::from_bytes(&entry?))
        .collect::<Result<_>>()
}

/// Keeps a grant, and adds it to the grants set if it's new. Returns whether it was.
fn insert_grant(tx: &Transaction<'_>, grant: &Grant) -> Result<bool> {
    let recipient = grant
        .recipient()
        .map_or([0; 16], |device| *device.as_bytes());
    let id = grant.id();
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO grants VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            &id[..],
            &grant.collection().as_bytes()[..],
            grant.epoch(),
            &recipient[..],
            grant.to_bytes()
        ],
    )? == 1;
    if inserted {
        add_to_set(tx, SetId::GRANTS, &id)?;
    }
    Ok(inserted)
}

/// Adds an item to a set's count and id sum.
fn add_to_set(tx: &Transaction<'_>, set: SetId, id: &ItemId) -> Result<()> {
    let mut summary = set_summary(tx, set)?;
    summary.add(id);
    tx.execute(
        "INSERT INTO sets VALUES (?1, ?2, ?3)
         ON CONFLICT (set_id) DO UPDATE SET count = excluded.count, sum = excluded.sum",
        params![
            &set.as_bytes()[..],
            i64::try_from(summary.count).map_err(|_| Error::Corrupt("set count"))?,
            &summary.sum[..]
        ],
    )?;
    Ok(())
}

fn set_summary(conn: &Connection, set: SetId) -> Result<Summary> {
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT count, sum FROM sets WHERE set_id = ?1",
            [&set.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((count, sum)) = row else {
        return Ok(Summary::default());
    };
    Ok(Summary {
        count: u64::try_from(count).map_err(|_| Error::Corrupt("set count"))?,
        sum: sum.try_into().map_err(|_| Error::Corrupt("set sum"))?,
    })
}

/// A row for a collection this device knows from the log but whose name hasn't arrived, so its
/// grants and records have something to belong to.
fn ensure_collection(tx: &Transaction<'_>, collection: CollectionId, epoch: u32) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO collections VALUES (?1, ?2, NULL, NULL)",
        params![&collection.as_bytes()[..], epoch],
    )?;
    Ok(())
}

/// Keeps a grant to this device as the wrapped key it unwraps.
fn keep_own_key(tx: &Transaction<'_>, grant: &Grant, wrap_key: &WrapKey) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO collection_keys VALUES (?1, ?2, ?3, ?4)",
        params![
            &grant.collection().as_bytes()[..],
            grant.epoch(),
            wrap_key.as_bytes(),
            grant.wrapped().to_bytes()
        ],
    )?;
    Ok(())
}

/// Signs a grant for each collection key this device holds for itself or the recovery key and
/// has no grant for yet: the upgrade to grants, and a log started for an M1 vault.
fn write_own_grants(
    tx: &Transaction<'_>,
    vault: VaultId,
    device: DeviceId,
    recovery: &WrapKey,
    keys: &impl DeviceKeys,
) -> Result<()> {
    struct Row {
        collection: Vec<u8>,
        epoch: u32,
        recipient: Vec<u8>,
        wrapped: Vec<u8>,
    }
    let own = keys.wrap_key();
    let rows: Vec<Row> = {
        let mut statement =
            tx.prepare("SELECT collection_id, epoch, recipient, wrapped FROM collection_keys")?;
        statement
            .query_map([], |row| {
                Ok(Row {
                    collection: row.get(0)?,
                    epoch: row.get(1)?,
                    recipient: row.get(2)?,
                    wrapped: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?
    };
    for Row {
        collection,
        epoch,
        recipient,
        wrapped,
    } in rows
    {
        let recipient = if recipient == own.as_bytes() {
            Some(device)
        } else if recipient == recovery.as_bytes() {
            None
        } else {
            continue;
        };
        let grant = Grant::sign(
            vault,
            CollectionId::try_from(collection.as_slice())?,
            epoch,
            recipient,
            WrappedKey::from_bytes(&wrapped)?,
            keys.verifying_key(),
            |context, message| keys.sign(context, message),
        )?;
        insert_grant(tx, &grant)?;
    }
    Ok(())
}

fn data_version(conn: &Connection) -> Result<i64> {
    Ok(conn.pragma_query_value(None, "data_version", |row| row.get(0))?)
}

fn user_version(conn: &Connection) -> Result<i64> {
    Ok(conn.pragma_query_value(None, "user_version", |row| row.get(0))?)
}

/// The kept membership, checked against the log's last entry and this device's keys. `None`
/// for a vault that hasn't started its log.
fn load_membership(
    conn: &Connection,
    vault: VaultId,
    device: DeviceId,
    keys: &impl DeviceKeys,
) -> Result<Option<Membership>> {
    let Some(state) = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'membership'",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
    else {
        return Ok(None);
    };
    let membership =
        Membership::from_state_bytes(&state).map_err(|_| Error::Corrupt("membership state"))?;
    let last: Option<Vec<u8>> = conn
        .query_row(
            "SELECT hash FROM log ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if membership.vault() != vault || last.as_deref() != Some(&membership.head().1[..]) {
        return Err(Error::Corrupt("the membership state doesn't match the log"));
    }
    match membership.device(device) {
        Some(this)
            if this.info.verifying_key == keys.verifying_key()
                && this.info.wrap_key == keys.wrap_key() =>
        {
            Ok(Some(membership))
        }
        _ => Err(Error::Corrupt("this device isn't in the membership log")),
    }
}

/// The log's first entries, signed by the recovery key's admin key: genesis, listing that key
/// and `device_admin` as the admins, then add_device for this device as `name` (membership.md,
/// creating a vault). A new names key seals the name and is wrapped to the recovery key and to
/// this device.
fn start_membership(
    vault: VaultId,
    recovery: &RecoveryKey,
    device_admin: Option<VerifyingKey>,
    keys: &impl DeviceKeys,
    device: DeviceId,
    name: &str,
) -> Result<(Membership, Vec<LogEntry>)> {
    let admin = recovery.admin_signing_key();
    let admins = std::iter::once(admin.verifying_key())
        .chain(device_admin)
        .collect();
    let names_key = SymmetricKey::generate();
    let (mut membership, genesis) = Membership::create(
        vault,
        recovery.unwrap_key().wrap_key(),
        admins,
        &names_key,
        &admin,
    )?;
    let info = device_info(vault, device, keys, name, &names_key)?;
    let add = membership.append(Change::AddDevice(info), &admin)?;
    Ok((membership, vec![genesis, add]))
}

/// This device as add_device describes it. Its transport key is derived from the local key
/// (records.md, local store), so the key file doesn't need to hold one.
fn device_info(
    vault: VaultId,
    id: DeviceId,
    keys: &impl DeviceKeys,
    name: &str,
    names_key: &SymmetricKey,
) -> Result<DeviceInfo> {
    let transport = crate::transport_seed(keys);
    let name = DeviceName {
        platform: std::env::consts::OS.into(),
        name: name.into(),
    };
    DeviceInfo::new(
        vault,
        id,
        keys.verifying_key(),
        keys.wrap_key(),
        SigningKey::from_ed25519_seed(&transport).verifying_key(),
        &name,
        names_key,
    )
}

/// Adds accepted entries to the log and keeps the membership they lead to.
fn save_log(tx: &Transaction<'_>, entries: &[LogEntry], membership: &Membership) -> Result<()> {
    for entry in entries {
        let seq = i64::try_from(entry.seq()).map_err(|_| Error::Corrupt("log sequence"))?;
        tx.execute(
            "INSERT INTO log VALUES (?1, ?2, ?3)",
            params![seq, &entry.hash()[..], entry.to_bytes()],
        )?;
    }
    tx.execute(
        "INSERT INTO meta VALUES ('membership', ?1)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        [membership.to_state_bytes()],
    )?;
    Ok(())
}

fn collection_exists(conn: &Connection, tag: &Hash) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM collections WHERE name_tag = ?1",
            [&tag[..]],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn meta(conn: &Connection, key: &str) -> Result<Vec<u8>> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
        row.get(0)
    })
    .optional()?
    .ok_or(Error::Corrupt("missing vault metadata"))
}

/// `vault_id ‖ collection_id ‖ epoch` (records.md, collection keys).
fn wrap_context(vault: VaultId, collection: CollectionId, epoch: u32) -> Vec<u8> {
    [
        &vault.as_bytes()[..],
        collection.as_bytes(),
        &epoch.to_be_bytes(),
    ]
    .concat()
}

fn collection_label_aad(collection: CollectionId) -> Vec<u8> {
    [b"collection\0", &collection.as_bytes()[..]].concat()
}

fn entry_label_aad(collection: CollectionId, tag: &Hash) -> Vec<u8> {
    [&collection.as_bytes()[..], tag].concat()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use latem_vault_crypto::RecoveryKey;

    use super::*;
    use crate::SoftwareKeys;

    struct Setup {
        _dir: tempfile::TempDir,
        path: PathBuf,
        keys: SoftwareKeys,
        recovery: RecoveryKey,
    }

    fn setup() -> Setup {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        Setup {
            _dir: dir,
            path,
            keys: SoftwareKeys::generate(),
            recovery: RecoveryKey::generate(),
        }
    }

    impl Setup {
        fn create(&self) -> Vault<&SoftwareKeys> {
            Vault::create(&self.path, &self.keys, &self.recovery, "test", None).unwrap()
        }

        fn open(&self) -> Vault<&SoftwareKeys> {
            Vault::open(&self.path, &self.keys).unwrap()
        }

        /// The recovery key's admin key, the vault's only admin.
        fn admin(&self) -> SigningKey {
            self.recovery.admin_signing_key()
        }
    }

    fn stored_log(vault: &Vault<&SoftwareKeys>) -> Vec<LogEntry> {
        let mut statement = vault
            .conn
            .prepare("SELECT entry FROM log ORDER BY seq")
            .unwrap();
        statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .unwrap()
            .map(|entry| LogEntry::from_bytes(&entry.unwrap()).unwrap())
            .collect()
    }

    fn value(entry: Option<Entry>) -> Option<Vec<u8>> {
        entry.map(|e| e.value.to_vec())
    }

    fn grants(vault: &Vault<&SoftwareKeys>) -> Vec<Grant> {
        let mut statement = vault.conn.prepare("SELECT grant FROM grants").unwrap();
        statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .unwrap()
            .map(|bytes| Grant::from_bytes(&bytes.unwrap()).unwrap())
            .collect()
    }

    fn desktop() -> DeviceName {
        DeviceName {
            platform: "linux".into(),
            name: "Desktop".into(),
        }
    }

    #[test]
    fn creating_a_collection_grants_its_key_to_this_device_and_recovery() {
        let s = setup();
        let mut vault = s.create();
        let id = vault.create_collection("latem", &s.admin()).unwrap();
        let grants = grants(&vault);
        let m = vault.membership().unwrap();
        let mut recipients: Vec<_> = grants.iter().map(Grant::recipient).collect();
        recipients.sort();
        assert_eq!(recipients, [None, Some(vault.device_id())]);
        for grant in &grants {
            assert_eq!((grant.collection(), grant.epoch()), (id, 0));
            grant.check(m).unwrap();
            assert_eq!(Grant::from_bytes(&grant.to_bytes()).unwrap(), *grant);
        }
        let recovery = grants.iter().find(|g| g.recipient().is_none()).unwrap();
        s.recovery
            .unwrap_key()
            .unwrap(&wrap_context(vault.vault_id(), id, 0), recovery.wrapped())
            .unwrap();
    }

    #[test]
    fn grants_follow_the_rules() {
        let s = setup();
        let mut vault = s.create();
        let id = vault.create_collection("latem", &s.admin()).unwrap();
        let m = vault.membership().unwrap().clone();
        let this = vault.device_id();
        let wrapped = s.keys.wrap_key().wrap(
            &wrap_context(vault.vault_id(), id, 0),
            &SymmetricKey::generate(),
        );
        let grant = |vault_id, epoch, recipient, signer: &SoftwareKeys| {
            Grant::sign(
                vault_id,
                id,
                epoch,
                recipient,
                wrapped.clone(),
                signer.verifying_key(),
                |context, message| signer.sign(context, message),
            )
            .unwrap()
        };
        grant(vault.vault_id(), 0, Some(this), &s.keys)
            .check(&m)
            .unwrap();

        let stranger = SoftwareKeys::generate();
        for (bad, why) in [
            (
                grant(VaultId::random(), 0, Some(this), &s.keys),
                "another vault",
            ),
            (
                grant(vault.vault_id(), 1, Some(this), &s.keys),
                "an epoch the log hasn't reached",
            ),
            (
                grant(vault.vault_id(), 0, Some(DeviceId::random()), &s.keys),
                "an unknown recipient",
            ),
            (
                grant(vault.vault_id(), 0, Some(this), &stranger),
                "a signer who couldn't read",
            ),
        ] {
            assert!(
                matches!(bad.check(&m), Err(Error::InvalidGrant(_))),
                "{why}"
            );
        }

        // The recovery key's grant must be wrapped to its kind of key; this one is X25519 too.
        grant(vault.vault_id(), 0, None, &s.keys).check(&m).unwrap();
        // The admin at the start of the epoch may sign, even without a scope.
        let admin = s.admin();
        Grant::sign(
            vault.vault_id(),
            id,
            0,
            Some(this),
            wrapped.clone(),
            admin.verifying_key(),
            |c, msg| Ok(admin.sign(c, msg)),
        )
        .unwrap()
        .check(&m)
        .unwrap();

        let mut tampered = grant(vault.vault_id(), 0, Some(this), &s.keys).to_bytes();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(Grant::from_bytes(&tampered).unwrap().check(&m).is_err());
    }

    #[test]
    fn epoch_history_records_who_could_read_and_write() {
        let s = setup();
        let mut vault = s.create();
        let id = vault.create_collection("latem", &s.admin()).unwrap();
        let this = vault.device_id();
        let mut m = vault.membership().unwrap().clone();
        assert!(m.had_scope(this, id, 0, Scope::Write));
        assert!(m.had_scope(this, id, 0, Scope::Read));
        assert!(!m.had_scope(this, id, 1, Scope::Read));
        assert_eq!(m.epoch_admins(id, 0), [s.admin().verifying_key()]);

        let other = DeviceInfo::new(
            vault.vault_id(),
            DeviceId::random(),
            SoftwareKeys::generate().verifying_key(),
            SoftwareKeys::generate().wrap_key(),
            SigningKey::generate_ed25519().verifying_key(),
            &desktop(),
            &SymmetricKey::generate(),
        )
        .unwrap();
        let other_id = other.id;
        m.append(Change::AddDevice(other), &s.admin()).unwrap();
        let read = Change::SetScope {
            device: other_id,
            collection: id,
            scope: Scope::Read,
        };
        m.append(read, &s.admin()).unwrap();
        m.append(Change::RevokeDevice(other_id), &s.admin())
            .unwrap();
        m.append(
            Change::RotateEpoch {
                collection: id,
                epoch: 1,
            },
            &s.admin(),
        )
        .unwrap();
        // It could read during epoch 0, never write, and has nothing in epoch 1.
        assert!(m.had_scope(other_id, id, 0, Scope::Read));
        assert!(!m.had_scope(other_id, id, 0, Scope::Write));
        assert!(!m.had_scope(other_id, id, 1, Scope::Read));
        assert!(m.had_scope(this, id, 1, Scope::Write));

        let state = Membership::from_state_bytes(&m.to_state_bytes()).unwrap();
        assert!(state.had_scope(other_id, id, 0, Scope::Read));
        assert_eq!(state.to_state_bytes(), m.to_state_bytes());
    }

    #[test]
    fn approving_a_join_builds_the_joiners_store() {
        let s = setup();
        let mut admin_vault = s.create();
        let latem = admin_vault.create_collection("latem", &s.admin()).unwrap();
        let ssh = admin_vault.create_collection("ssh", &s.admin()).unwrap();
        admin_vault
            .set(latem, "prod/SENTRY_DSN", Kind::Secret, b"https://sentry")
            .unwrap();

        let joiner_keys = SoftwareKeys::generate();
        let joiner = DeviceId::random();
        let request = JoinRequest::sign(&[9; 32], joiner, &joiner_keys, desktop()).unwrap();
        let scopes = [(latem, Scope::Read), (ssh, Scope::Hold)];
        let approval = admin_vault
            .approve_join(&request, &scopes, &s.admin())
            .unwrap();
        // add_device and two set_scopes after genesis, add_device and the two collections.
        assert_eq!(approval.log.len(), 7);
        assert_eq!(
            approval.grants.len(),
            1,
            "a key for latem only: hold can't read"
        );
        let m = admin_vault.membership().unwrap().clone();
        assert_eq!(m.scope(joiner, latem), Scope::Read);
        assert_eq!(admin_vault.device_name(joiner).unwrap(), Some(desktop()));

        // Approving again, as after an interrupted join, signs nothing new.
        let again = admin_vault
            .approve_join(&request, &scopes, &s.admin())
            .unwrap();
        assert_eq!(again.log.len(), 7);
        assert_eq!(again.grants, approval.grants);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("joined.db");
        let join = |head, name: &DeviceName, grants: &[Grant]| {
            Vault::join(
                &path,
                &joiner_keys,
                joiner,
                name,
                head,
                &approval.log,
                grants,
            )
        };
        assert!(
            join((0, [0; 32]), &desktop(), &approval.grants).is_err(),
            "another head"
        );
        let other_name = DeviceName {
            name: "Laptop".into(),
            ..desktop()
        };
        assert!(
            join(m.head(), &other_name, &approval.grants).is_err(),
            "another name"
        );
        assert!(!path.exists(), "a refused join writes nothing");

        let joined = join(m.head(), &desktop(), &approval.grants).unwrap();
        assert_eq!(joined.vault_id(), admin_vault.vault_id());
        assert_eq!(joined.device_id(), joiner);
        assert_eq!(joined.membership().unwrap().head(), m.head());
        assert_eq!(
            joined
                .device_name(admin_vault.device_id())
                .unwrap()
                .unwrap()
                .name,
            "test"
        );
        drop(joined);
        let reopened = Vault::open(&path, &joiner_keys).unwrap();
        assert_eq!(grants_to_count(&reopened, joiner), 1);

        // A device id that is in the log with other keys is refused.
        let impostor =
            JoinRequest::sign(&[9; 32], joiner, &SoftwareKeys::generate(), desktop()).unwrap();
        assert!(matches!(
            admin_vault.approve_join(&impostor, &scopes, &s.admin()),
            Err(Error::InvalidJoin(_))
        ));
    }

    fn grants_to_count(vault: &Vault<&SoftwareKeys>, device: DeviceId) -> usize {
        vault.grants_to(device).unwrap().len()
    }

    /// A new store version is a new minor version of the build, since older builds refuse the
    /// store (README, versions). Change both together.
    #[test]
    fn the_build_version_follows_the_store_version() {
        assert_eq!((env!("CARGO_PKG_VERSION_MINOR"), SCHEMA_VERSION), ("6", 7));
    }

    #[test]
    fn version_3_stores_get_grants_and_epoch_history() {
        let s = setup();
        let id = {
            let mut vault = s.create();
            let id = vault.create_collection("latem", &s.admin()).unwrap();
            vault.set(id, "A", Kind::Var, b"1").unwrap();
            // A version 3 store had no grants, and its kept state no epoch history, which the
            // upgrade rebuilds from the log rather than reads.
            vault
                .conn
                .execute_batch(
                    "DROP TABLE grants;
                     UPDATE meta SET value = x'00' WHERE key = 'membership';
                     PRAGMA user_version = 3;",
                )
                .unwrap();
            id
        };
        let mut vault = s.open();
        assert_eq!(user_version(&vault.conn).unwrap(), SCHEMA_VERSION);
        assert_eq!(value(vault.get(id, "A").unwrap()), Some(b"1".to_vec()));
        let m = vault.membership().unwrap();
        assert!(m.had_scope(vault.device_id(), id, 0, Scope::Write));
        let grants = grants(&vault);
        assert_eq!(grants.len(), 2);
        for grant in &grants {
            grant.check(m).unwrap();
        }
    }

    /// The admin's vault with `latem` (two entries) and `ssh`, and a device that joined it with
    /// read on `latem`.
    fn joined_pair<'a>(
        s: &'a Setup,
        joiner_keys: &SoftwareKeys,
    ) -> (
        Vault<&'a SoftwareKeys>,
        Vault<SoftwareKeys>,
        CollectionId,
        PathBuf,
    ) {
        let mut admin = s.create();
        let latem = admin.create_collection("latem", &s.admin()).unwrap();
        admin.create_collection("ssh", &s.admin()).unwrap();
        admin
            .set(latem, "prod/SENTRY_DSN", Kind::Secret, b"https://sentry")
            .unwrap();
        admin
            .set(latem, "prod/REGION", Kind::Var, b"eu-west")
            .unwrap();
        let (joined, path) = join_device(
            s,
            &mut admin,
            joiner_keys,
            "joined.db",
            &[(latem, Scope::Read)],
        );
        (admin, joined, latem, path)
    }

    /// A device that joined `admin`'s vault with `scopes`, its store in `file`.
    fn join_device(
        s: &Setup,
        admin: &mut Vault<&SoftwareKeys>,
        joiner_keys: &SoftwareKeys,
        file: &str,
        scopes: &[(CollectionId, Scope)],
    ) -> (Vault<SoftwareKeys>, PathBuf) {
        let device = DeviceId::random();
        let request = JoinRequest::sign(&[1; 32], device, joiner_keys, desktop()).unwrap();
        let approval = admin.approve_join(&request, scopes, &s.admin()).unwrap();
        let path = s.path.with_file_name(file);
        let head = admin.membership().unwrap().head();
        let keys = SoftwareKeys::from_parts(
            latem_vault_crypto::UnwrapKey::from_secret_bytes(
                &joiner_keys.parts().0.to_secret_bytes(),
            )
            .unwrap(),
            SigningKey::from_secret_bytes(&joiner_keys.parts().1.to_secret_bytes()).unwrap(),
            SymmetricKey::from_bytes(*joiner_keys.local_key().as_bytes()),
        );
        let joined = Vault::join(
            &path,
            keys,
            device,
            &desktop(),
            head,
            &approval.log,
            &approval.grants,
        )
        .unwrap();
        (joined, path)
    }

    /// Sends `from`'s log entries that `to` lacks.
    fn send_log<A: DeviceKeys, B: DeviceKeys>(from: &Vault<A>, to: &mut Vault<B>) {
        let head = to.membership().unwrap().head().0;
        to.append_log(&from.log_from(head + 1, 64).unwrap())
            .unwrap();
    }

    /// The epoch of the current version of `name`.
    fn current_epoch<K: DeviceKeys>(vault: &Vault<K>, collection: CollectionId, name: &str) -> u32 {
        let record: Vec<u8> = vault
            .conn
            .query_row(
                "SELECT r.record FROM entries e JOIN records r USING (record_id)
                 WHERE e.collection_id = ?1 AND e.name_tag = ?2",
                params![
                    &collection.as_bytes()[..],
                    &vault.entry_tag(collection, name)[..]
                ],
                |row| row.get(0),
            )
            .unwrap();
        Record::from_bytes(&record).unwrap().header().epoch
    }

    /// Sends `from` everything in each set they share that `to` lacks, as reconciliation would.
    fn send_missing<A: DeviceKeys, B: DeviceKeys>(from: &Vault<A>, to: &mut Vault<B>) -> usize {
        let sets = to.shared_sets(from.device_id());
        sets.into_iter().map(|set| send_set(from, to, set)).sum()
    }

    /// Sends `from` everything in `set` that `to` lacks.
    fn send_set<A: DeviceKeys, B: DeviceKeys>(
        from: &Vault<A>,
        to: &mut Vault<B>,
        set: SetId,
    ) -> usize {
        let theirs: std::collections::HashSet<ItemId> = to
            .set_ids(set, &[0; 32], None)
            .unwrap()
            .into_iter()
            .collect();
        let missing: Vec<ItemId> = from
            .set_ids(set, &[0; 32], None)
            .unwrap()
            .into_iter()
            .filter(|id| !theirs.contains(id))
            .collect();
        let items = from.set_items(set, &missing).unwrap();
        for item in &items {
            assert_eq!(to.receive(set, item).unwrap(), Received::New);
        }
        items.len()
    }

    #[test]
    fn a_joined_device_takes_in_records_and_grants() {
        let s = setup();
        let joiner_keys = SoftwareKeys::generate();
        let (admin, mut joined, latem, _) = joined_pair(&s, &joiner_keys);
        assert!(joined.collections().unwrap().is_empty(), "no records yet");
        let shared = joined.shared_sets(admin.device_id());
        assert_eq!(shared, admin.shared_sets(joined.device_id()));
        assert_eq!(
            shared,
            [SetId::records(latem), SetId::GRANTS],
            "not ssh: no scope on it"
        );

        // The collection record and two entries, and the admin's and recovery key's grants.
        assert_eq!(send_missing(&admin, &mut joined), 3 + 4);
        assert_eq!(send_missing(&admin, &mut joined), 0);
        for set in &shared {
            assert_eq!(
                joined.set_summary(*set).unwrap(),
                admin.set_summary(*set).unwrap()
            );
        }
        let names: Vec<String> = joined
            .collections()
            .unwrap()
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert_eq!(names, ["latem"]);
        assert_eq!(joined.collection("latem").unwrap(), latem);
        assert_eq!(
            value(joined.get(latem, "prod/SENTRY_DSN").unwrap()),
            Some(b"https://sentry".to_vec())
        );
        assert_eq!(joined.list(latem).unwrap().len(), 2);

        // Sending something again is harmless.
        let id = admin
            .set_ids(SetId::records(latem), &[0; 32], None)
            .unwrap()[0];
        let item = admin
            .set_items(SetId::records(latem), &[id])
            .unwrap()
            .remove(0);
        assert_eq!(
            joined.receive(SetId::records(latem), &item).unwrap(),
            Received::Known
        );
        // Its clock moved past everything it took in, so its writes would be newer.
        assert_eq!(
            meta(&joined.conn, "clock").unwrap(),
            meta(&admin.conn, "clock").unwrap()
        );
        // A reader can't write.
        assert!(matches!(
            joined.set(latem, "prod/X", Kind::Var, b"1"),
            Err(Error::ReadOnly)
        ));
    }

    #[test]
    fn records_that_arrive_before_their_key_are_opened_when_it_does() {
        let s = setup();
        let joiner_keys = SoftwareKeys::generate();
        let (admin, mut joined, latem, _) = joined_pair(&s, &joiner_keys);
        // As if its grant came after the join, as it does after a key change: no grant or key.
        joined
            .conn
            .execute_batch("DELETE FROM collection_keys; DELETE FROM grants;")
            .unwrap();
        joined
            .conn
            .execute(
                "DELETE FROM sets WHERE set_id = ?1",
                [&SetId::GRANTS.as_bytes()[..]],
            )
            .unwrap();

        // The collection record and two entries arrive first, and are kept unopened.
        assert_eq!(send_set(&admin, &mut joined, SetId::records(latem)), 3);
        assert_eq!(waiting(&joined), 3);
        assert!(joined.collections().unwrap().is_empty());
        assert!(matches!(
            joined.collection("latem"),
            Err(Error::NoSuchCollection(_))
        ));

        // Then the grants: the admin's and recovery key's for both collections, and its own.
        assert_eq!(send_set(&admin, &mut joined, SetId::GRANTS), 4 + 1);
        assert_eq!(waiting(&joined), 0);
        assert_eq!(joined.collection("latem").unwrap(), latem);
        assert_eq!(
            value(joined.get(latem, "prod/SENTRY_DSN").unwrap()),
            Some(b"https://sentry".to_vec())
        );
        assert_eq!(joined.list(latem).unwrap().len(), 2);
    }

    fn waiting<K: DeviceKeys>(vault: &Vault<K>) -> i64 {
        vault
            .conn
            .query_row("SELECT count(*) FROM waiting", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn version_5_stores_keep_their_granted_keys_and_open_what_waited() {
        let s = setup();
        let joiner_keys = SoftwareKeys::generate();
        let (admin, mut joined, latem, path) = joined_pair(&s, &joiner_keys);
        // A device that joined with version 4 kept its grant but not the key in it, so with
        // version 5 the records it took in stayed unopened, and nothing listed them.
        joined
            .conn
            .execute("DELETE FROM collection_keys", [])
            .unwrap();
        assert_eq!(send_missing(&admin, &mut joined), 3 + 4);
        assert!(joined.collections().unwrap().is_empty());
        joined
            .conn
            .execute_batch("DROP TABLE waiting; PRAGMA user_version = 5;")
            .unwrap();
        drop(joined);

        let mut joined = Vault::open(&path, &joiner_keys).unwrap();
        assert_eq!(user_version(&joined.conn).unwrap(), SCHEMA_VERSION);
        assert_eq!(waiting(&joined), 0);
        assert_eq!(joined.collection("latem").unwrap(), latem);
        assert_eq!(
            value(joined.get(latem, "prod/REGION").unwrap()),
            Some(b"eu-west".to_vec())
        );
        drop(joined);
        let joined = Vault::open(&path, &joiner_keys).unwrap();
        assert_eq!(joined.list(latem).unwrap().len(), 2);
    }

    #[test]
    fn revoking_a_reader_gives_the_others_a_new_key() {
        let s = setup();
        let joiner_keys = SoftwareKeys::generate();
        let (mut admin, joined, latem, _) = joined_pair(&s, &joiner_keys);
        let ssh = admin.collection("ssh").unwrap();
        // A file it could read is listed too, apart from the secrets: a keystore is a key.
        let keystore = Manifest {
            size: 5,
            executable: false,
            mtime: 0,
            content: crate::file::Content::Inline(Zeroizing::new(b"store".to_vec())),
        };
        admin
            .set(latem, "prod/upload.jks", Kind::File, &keystore.encode())
            .unwrap();
        let review = admin.review_revocation(joined.device_id()).unwrap();
        assert_eq!(
            review.secrets,
            [("latem".to_owned(), vec!["prod/SENTRY_DSN".to_owned()])]
        );
        assert_eq!(
            review.files,
            [(
                "latem".to_owned(),
                vec![FileLine {
                    name: "prod/upload.jks".to_owned(),
                    files: 1
                }]
            )]
        );
        assert!(
            review.wrote_last.is_empty(),
            "the admin wrote the file, not the device"
        );

        let revocation = admin.revoke_device(joined.device_id(), &s.admin()).unwrap();
        assert_eq!(revocation.rotated, [latem], "not ssh: it couldn't read it");
        assert_eq!(revocation.carried, 0);
        let m = admin.membership().unwrap();
        assert!(m.device(joined.device_id()).unwrap().revoked);
        assert_eq!(m.scope(joined.device_id(), latem), Scope::None);
        assert_eq!((m.epoch(latem), m.epoch(ssh)), (Some(1), Some(0)));
        // The new key goes to this device and the recovery key, and the grants check out.
        let new: Vec<Grant> = grants(&admin)
            .into_iter()
            .filter(|grant| grant.collection() == latem && grant.epoch() == 1)
            .collect();
        assert_eq!(new.len(), 2);
        assert!(new.iter().any(|grant| grant.recipient().is_none()));
        assert!(
            new.iter()
                .any(|grant| grant.recipient() == Some(admin.device_id()))
        );
        for grant in &new {
            grant.check(m).unwrap();
        }
        // What was there still reads, and new writes use the new key.
        assert_eq!(
            value(admin.get(latem, "prod/REGION").unwrap()),
            Some(b"eu-west".to_vec())
        );
        admin.set(latem, "prod/NEW", Kind::Var, b"1").unwrap();
        assert_eq!(current_epoch(&admin, latem, "prod/NEW"), 1);
        assert_eq!(current_epoch(&admin, latem, "prod/REGION"), 0);

        for device in [joined.device_id(), admin.device_id()] {
            assert!(matches!(
                admin.revoke_device(device, &s.admin()),
                Err(Error::CantRevoke(_))
            ));
        }
    }

    #[test]
    fn scopes_go_up_with_their_keys_and_down_with_new_ones() {
        let s = setup();
        let joiner_keys = SoftwareKeys::generate();
        let (mut admin, mut joined, latem, _) = joined_pair(&s, &joiner_keys);
        let ssh = admin.collection("ssh").unwrap();
        admin
            .set(ssh, "github/KEY", Kind::Secret, b"ssh-ed25519")
            .unwrap();
        let device = joined.device_id();

        // Read on ssh brings its key.
        let change = admin
            .set_scope(device, ssh, Scope::Read, &s.admin())
            .unwrap();
        assert_eq!(
            (change.rotated, change.granted, change.carried),
            (false, 1, 0)
        );
        send_log(&admin, &mut joined);
        send_missing(&admin, &mut joined);
        assert_eq!(
            value(joined.get(ssh, "github/KEY").unwrap()),
            Some(b"ssh-ed25519".to_vec())
        );

        // Write on latem needs no new key.
        let change = admin
            .set_scope(device, latem, Scope::Write, &s.admin())
            .unwrap();
        assert_eq!((change.rotated, change.granted), (false, 0));
        send_log(&admin, &mut joined);
        joined
            .set(latem, "prod/REGION", Kind::Var, b"from the desktop")
            .unwrap();
        send_missing(&joined, &mut admin);

        // Back to read: latem gets a new key, and the admin keeps its last write.
        let change = admin
            .set_scope(device, latem, Scope::Read, &s.admin())
            .unwrap();
        assert_eq!((change.rotated, change.carried), (true, 1));
        let region = admin.get(latem, "prod/REGION").unwrap().unwrap();
        assert_eq!(
            (&region.value[..], region.version.device),
            (&b"from the desktop"[..], admin.device_id())
        );
        send_log(&admin, &mut joined);
        send_missing(&admin, &mut joined);
        assert_eq!(
            value(joined.get(latem, "prod/REGION").unwrap()),
            Some(b"from the desktop".to_vec())
        );
        assert!(matches!(
            joined.set(latem, "prod/X", Kind::Var, b"1"),
            Err(Error::ReadOnly)
        ));

        // None on ssh: a new key it doesn't get.
        let change = admin
            .set_scope(device, ssh, Scope::None, &s.admin())
            .unwrap();
        assert!(change.rotated);
        assert_eq!(admin.membership().unwrap().epoch(ssh), Some(1));
        assert!(!grants(&admin).iter().any(|grant| {
            grant.collection() == ssh && grant.epoch() == 1 && grant.recipient() == Some(device)
        }));

        for (device, scope) in [(device, Scope::None), (admin.device_id(), Scope::Read)] {
            assert!(matches!(
                admin.set_scope(device, ssh, scope, &s.admin()),
                Err(Error::CantChangeScope(_))
            ));
        }
    }

    /// After a key change, a new reader still needs the older keys, since most entries are
    /// still sealed with them.
    #[test]
    fn a_device_that_joins_after_a_key_change_gets_the_older_keys() {
        let s = setup();
        let first_keys = SoftwareKeys::generate();
        let (mut admin, first, latem, _) = joined_pair(&s, &first_keys);
        admin.revoke_device(first.device_id(), &s.admin()).unwrap();
        admin.set(latem, "prod/NEW", Kind::Var, b"after").unwrap();
        assert_eq!(admin.membership().unwrap().epoch(latem), Some(1));

        let second_keys = SoftwareKeys::generate();
        let (mut second, _) = join_device(
            &s,
            &mut admin,
            &second_keys,
            "second.db",
            &[(latem, Scope::Read)],
        );
        send_missing(&admin, &mut second);
        assert_eq!(
            value(second.get(latem, "prod/SENTRY_DSN").unwrap()),
            Some(b"https://sentry".to_vec()),
            "written under the first key"
        );
        assert_eq!(
            value(second.get(latem, "prod/NEW").unwrap()),
            Some(b"after".to_vec())
        );
    }

    #[test]
    fn a_revoked_writers_versions_stop_counting_and_its_writes_are_carried_forward() {
        let s = setup();
        let (reader_keys, writer_keys) = (SoftwareKeys::generate(), SoftwareKeys::generate());
        let (mut admin, mut reader, latem, _) = joined_pair(&s, &reader_keys);
        let (mut writer, _) = join_device(
            &s,
            &mut admin,
            &writer_keys,
            "writer.db",
            &[(latem, Scope::Write)],
        );
        send_log(&admin, &mut reader);
        send_missing(&admin, &mut writer);
        // The writer changes one entry and adds another, and every device has them.
        writer
            .set(latem, "prod/REGION", Kind::Var, b"us-east")
            .unwrap();
        writer
            .set(latem, "prod/ADDED", Kind::Secret, b"from the writer")
            .unwrap();
        send_missing(&writer, &mut admin);
        send_missing(&admin, &mut reader);
        assert_eq!(
            value(reader.get(latem, "prod/REGION").unwrap()),
            Some(b"us-east".to_vec())
        );
        let review = admin.review_revocation(writer.device_id()).unwrap();
        assert_eq!(review.wrote_last.len(), 1);
        assert_eq!(
            review.wrote_last[0]
                .1
                .iter()
                .map(|w| &w.name[..])
                .collect::<Vec<_>>(),
            ["prod/ADDED", "prod/REGION"]
        );

        // The admin writes the writer's last changes again under the new key, so its values stay.
        let revocation = admin.revoke_device(writer.device_id(), &s.admin()).unwrap();
        assert_eq!(revocation.carried, 2);
        let region = admin.get(latem, "prod/REGION").unwrap().unwrap();
        assert_eq!(&region.value[..], b"us-east");
        assert_eq!(region.version.device, admin.device_id());
        assert_eq!(current_epoch(&admin, latem, "prod/REGION"), 1);

        // A reader that learns of the revocation stops counting the writer's versions...
        send_log(&admin, &mut reader);
        assert_eq!(
            value(reader.get(latem, "prod/REGION").unwrap()),
            Some(b"eu-west".to_vec())
        );
        assert_eq!(value(reader.get(latem, "prod/ADDED").unwrap()), None);
        // ...until the new key and the carried versions arrive.
        send_missing(&admin, &mut reader);
        assert_eq!(
            value(reader.get(latem, "prod/REGION").unwrap()),
            Some(b"us-east".to_vec())
        );
        assert_eq!(
            value(reader.get(latem, "prod/ADDED").unwrap()),
            Some(b"from the writer".to_vec())
        );

        // What it signs with its old key no longer becomes current, whatever its clock.
        writer
            .set(latem, "prod/REGION", Kind::Var, b"forged")
            .unwrap();
        send_set(&writer, &mut admin, SetId::records(latem));
        assert_eq!(
            value(admin.get(latem, "prod/REGION").unwrap()),
            Some(b"us-east".to_vec())
        );
    }

    #[test]
    fn records_and_grants_are_checked_before_they_are_kept() {
        let s = setup();
        let joiner_keys = SoftwareKeys::generate();
        let (mut admin, joined, latem, _) = joined_pair(&s, &joiner_keys);
        let records = SetId::records(latem);
        let id = admin.set_ids(records, &[0; 32], None).unwrap()[0];
        let mut item = admin.set_items(records, &[id]).unwrap().remove(0);

        // A record under another collection's set, or changed in transit.
        let ssh = admin.collection("ssh").unwrap();
        assert!(admin.receive(SetId::records(ssh), &item).is_err());
        item[50] ^= 1;
        assert!(admin.receive(records, &item).is_err());

        // A record signed by a device that can only read the collection.
        let key = SymmetricKey::generate();
        let version = Version {
            lamport: 99,
            device: joined.device_id(),
        };
        let forged = Record::seal(
            latem,
            0,
            version,
            false,
            &Body::new(Kind::Var, "prod/X", b"1"),
            &key,
            &joiner_keys,
        )
        .unwrap();
        assert!(matches!(
            admin.receive(records, &forged.to_bytes()),
            Err(Error::InvalidRecord(
                "the author couldn't write at that epoch"
            ))
        ));
        assert!(admin.receive(SetId::GRANTS, b"not a grant").is_err());
    }

    #[test]
    fn log_entries_arrive_in_order_and_forks_are_found() {
        let s = setup();
        let joiner_keys = SoftwareKeys::generate();
        let (mut admin, mut joined, _, _) = joined_pair(&s, &joiner_keys);
        let head = joined.membership().unwrap().head().0;
        admin.create_collection("new", &s.admin()).unwrap();
        let more = admin.log_from(head + 1, 64).unwrap();
        assert_eq!(more.len(), 1);
        // Entries it already has are skipped.
        let all = admin.log_from(0, 64).unwrap();
        assert_eq!(joined.append_log(&all).unwrap(), 1);
        assert_eq!(joined.append_log(&more).unwrap(), 0);
        assert_eq!(
            joined.membership().unwrap().head(),
            admin.membership().unwrap().head()
        );

        // Two admins signing different entries at the same seq.
        let at = admin.membership().unwrap().head().0 + 1;
        admin.create_collection("one", &s.admin()).unwrap();
        joined.create_collection("two", &s.admin()).unwrap();
        let theirs = joined.log_from(at, 1).unwrap();
        assert!(matches!(admin.append_log(&theirs), Err(Error::Fork)));
    }

    #[test]
    fn version_4_stores_get_their_sets_added_up() {
        let s = setup();
        let latem = {
            let mut vault = s.create();
            let latem = vault.create_collection("latem", &s.admin()).unwrap();
            vault.set(latem, "A", Kind::Var, b"1").unwrap();
            vault
                .conn
                .execute_batch("DELETE FROM sets; PRAGMA user_version = 4;")
                .unwrap();
            latem
        };
        let vault = s.open();
        assert_eq!(user_version(&vault.conn).unwrap(), SCHEMA_VERSION);
        for set in [SetId::records(latem), SetId::GRANTS] {
            let ids = vault.set_ids(set, &[0; 32], None).unwrap();
            assert_eq!(vault.set_summary(set).unwrap(), Summary::of(&ids));
        }
        assert_eq!(vault.set_summary(SetId::records(latem)).unwrap().count, 2);
        assert_eq!(vault.collections().unwrap().len(), 1);
    }

    #[test]
    fn refresh_picks_up_log_entries_from_another_connection() {
        let s = setup();
        let mut first = s.create();
        let mut second = s.open();
        assert!(!second.refresh().unwrap(), "nothing has been written yet");

        first.create_collection("latem", &s.admin()).unwrap();
        assert!(second.refresh().unwrap());
        assert!(!second.refresh().unwrap());
        assert_eq!(
            second.membership().unwrap().head(),
            first.membership().unwrap().head()
        );

        // Without the refresh, this would sign an entry at a seq the log already has.
        second.create_collection("ssh", &s.admin()).unwrap();
        assert!(first.refresh().unwrap());
        assert_eq!(first.collections().unwrap().len(), 2);
        assert_eq!(
            first.membership().unwrap().head(),
            second.membership().unwrap().head()
        );
    }

    #[test]
    fn values_survive_reopening() {
        let s = setup();
        let (vault_id, id) = {
            let mut vault = s.create();
            let id = vault.create_collection("latem-cloud", &s.admin()).unwrap();
            vault
                .set(id, "prod/SENTRY_DSN", Kind::Var, b"https://sentry.example")
                .unwrap();
            vault
                .set(id, "prod/STRIPE_KEY", Kind::Secret, b"sk_live_x")
                .unwrap();
            (vault.vault_id(), id)
        };

        let mut vault = s.open();
        assert_eq!(vault.vault_id(), vault_id);
        assert_eq!(vault.collection("latem-cloud").unwrap(), id);
        assert_eq!(
            vault.collections().unwrap(),
            [CollectionInfo {
                id,
                name: "latem-cloud".into()
            }]
        );
        assert_eq!(
            vault.list(id).unwrap(),
            [
                EntryInfo {
                    name: "prod/SENTRY_DSN".into(),
                    kind: Kind::Var,
                    size: 0,
                },
                EntryInfo {
                    name: "prod/STRIPE_KEY".into(),
                    kind: Kind::Secret,
                    size: 0,
                },
            ]
        );
        let entry = vault.get(id, "prod/STRIPE_KEY").unwrap().unwrap();
        assert_eq!(
            (entry.kind, entry.value.as_slice()),
            (Kind::Secret, &b"sk_live_x"[..])
        );
        assert_eq!(entry.version.device, vault.device_id());
    }

    #[test]
    fn create_and_open_errors() {
        let s = setup();
        drop(s.create());
        assert!(matches!(
            Vault::create(&s.path, &s.keys, &s.recovery, "test", None),
            Err(Error::VaultExists(_))
        ));
        // A name the log refuses leaves no file behind.
        let unnamed = s.path.with_file_name("unnamed.db");
        assert!(matches!(
            Vault::create(&unnamed, &s.keys, &s.recovery, "", None),
            Err(Error::InvalidLogEntry(_))
        ));
        assert!(!unnamed.exists());
        assert!(matches!(
            Vault::open(&s.path, SoftwareKeys::generate()),
            Err(Error::WrongKeys)
        ));
        let missing = s.path.with_file_name("missing.db");
        assert!(matches!(
            Vault::open(&missing, &s.keys),
            Err(Error::NoVault(_))
        ));
    }

    #[test]
    fn create_starts_the_membership_log() {
        let s = setup();
        let device = {
            let vault = s.create();
            let m = vault.membership().unwrap();
            assert_eq!(m.head().0, 1);
            assert_eq!(m.admins(), [s.admin().verifying_key()]);
            assert_eq!(m.recovery_key(), &s.recovery.unwrap_key().wrap_key());
            let device = m.device(vault.device_id()).unwrap().info.clone();
            assert_eq!(device.verifying_key, s.keys.verifying_key());
            assert_eq!(device.wrap_key, s.keys.wrap_key());
            assert!(device.transport_key.is_ed25519());
            assert_eq!(
                vault.device_name(vault.device_id()).unwrap(),
                Some(DeviceName {
                    platform: std::env::consts::OS.into(),
                    name: "test".into(),
                })
            );
            assert_eq!(vault.device_name(DeviceId::random()).unwrap(), None);
            // The recovery key opens the same names key.
            let names_key = s
                .recovery
                .unwrap_key()
                .unwrap(&names_key_context(vault.vault_id()), m.recovery_names_key())
                .unwrap();
            assert_eq!(
                device
                    .name
                    .open(&names_key, vault.vault_id(), vault.device_id())
                    .unwrap()
                    .name,
                "test"
            );
            assert!(vault.is_recovery_key(&s.recovery));
            assert!(!vault.is_recovery_key(&RecoveryKey::generate()));
            device
        };

        // Reopening restores the kept state, which matches a replay of the stored log.
        let vault = s.open();
        let m = vault.membership().unwrap();
        assert_eq!(m.device(vault.device_id()).unwrap().info, device);
        let log = stored_log(&vault);
        assert_eq!(log.len(), 2);
        assert_eq!(
            Membership::replay(&log).unwrap().to_state_bytes(),
            m.to_state_bytes()
        );
    }

    #[test]
    fn a_device_admin_key_is_an_admin_from_the_start() {
        let s = setup();
        // A P-256 key, as a Secure Enclave admin key would be.
        let device_admin = SigningKey::generate_p256();
        let mut vault = Vault::create(
            &s.path,
            &s.keys,
            &s.recovery,
            "test",
            Some(device_admin.verifying_key()),
        )
        .unwrap();
        assert_eq!(
            vault.membership().unwrap().admins(),
            [s.admin().verifying_key(), device_admin.verifying_key()]
        );
        let id = vault.create_collection("c", &device_admin).unwrap();
        assert_eq!(
            vault.membership().unwrap().scope(vault.device_id(), id),
            Scope::Write
        );
    }

    #[test]
    fn creating_a_collection_needs_an_admin() {
        let s = setup();
        let mut vault = s.create();
        let head = vault.membership().unwrap().head();
        let outsider = SigningKey::generate_ed25519();
        assert!(matches!(
            vault.create_collection("c", &outsider),
            Err(Error::InvalidLogEntry("signer isn't an admin"))
        ));
        assert!(vault.collections().unwrap().is_empty());
        assert_eq!(vault.membership().unwrap().head(), head);

        let id = vault.create_collection("c", &s.admin()).unwrap();
        let m = vault.membership().unwrap();
        assert_eq!(m.scope(vault.device_id(), id), Scope::Write);
        assert_eq!(m.epoch(id), Some(0));
        drop(vault);
        let vault = s.open();
        assert_eq!(
            vault.membership().unwrap().scope(vault.device_id(), id),
            Scope::Write
        );
        assert_eq!(stored_log(&vault).len(), 3);
    }

    #[test]
    fn logs_from_before_sealed_names_are_refused() {
        let s = setup();
        drop(s.create());
        {
            let conn = connect(&s.path).unwrap();
            conn.execute_batch("DROP TABLE grants").unwrap();
            conn.pragma_update(None, "user_version", 2).unwrap();
        }
        assert!(matches!(
            Vault::open(&s.path, &s.keys),
            Err(Error::LogBeforeSealedNames)
        ));

        // A version 2 store whose log is still empty (an M1 vault that was opened by a build
        // with the log, but never started one) upgrades.
        {
            let conn = connect(&s.path).unwrap();
            conn.execute_batch("DELETE FROM log; DELETE FROM meta WHERE key = 'membership';")
                .unwrap();
        }
        let vault = s.open();
        assert!(vault.membership().is_none());
        assert_eq!(user_version(&vault.conn).unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn vaults_from_before_the_log_start_one_with_the_recovery_key() {
        let s = setup();
        let id = {
            let mut vault = s.create();
            let id = vault.create_collection("c", &s.admin()).unwrap();
            vault.set(id, "A", Kind::Var, b"1").unwrap();
            // Make it a version 1 store, as M1 created them.
            vault
                .conn
                .execute_batch(
                    "DROP TABLE log;
                     DROP TABLE grants;
                     DELETE FROM meta WHERE key = 'membership';
                     PRAGMA user_version = 1;",
                )
                .unwrap();
            id
        };

        let mut vault = s.open();
        assert!(vault.membership().is_none());
        assert_eq!(value(vault.get(id, "A").unwrap()), Some(b"1".to_vec()));
        assert!(matches!(
            vault.create_collection("d", &s.admin()),
            Err(Error::NoLog)
        ));
        assert!(matches!(
            vault.start_log(&RecoveryKey::generate(), "test"),
            Err(Error::WrongRecoveryKey)
        ));
        vault.start_log(&s.recovery, "test").unwrap();
        assert!(matches!(
            vault.start_log(&s.recovery, "test"),
            Err(Error::LogExists)
        ));
        let d = vault.create_collection("d", &s.admin()).unwrap();

        // genesis, add_device, the existing collection's scope, then the new one's.
        let vault = s.open();
        let m = vault.membership().unwrap();
        assert_eq!(m.head().0, 3);
        assert_eq!(m.scope(vault.device_id(), id), Scope::Write);
        assert_eq!(m.scope(vault.device_id(), d), Scope::Write);
        // Starting the log granted the existing collection's keys too.
        assert_eq!(grants(&vault).len(), 4);
    }

    #[test]
    fn rejects_state_that_doesnt_match_the_log() {
        let s = setup();
        drop(s.create());
        Connection::open(&s.path)
            .unwrap()
            .execute("UPDATE log SET hash = zeroblob(32) WHERE seq = 1", [])
            .unwrap();
        assert!(matches!(
            Vault::open(&s.path, &s.keys),
            Err(Error::Corrupt(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn store_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let s = setup();
        drop(s.create());
        let mode = std::fs::metadata(&s.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn overwrite_delete_and_restore() {
        let s = setup();
        let mut vault = s.create();
        let id = vault.create_collection("c", &s.admin()).unwrap();

        vault.set(id, "A", Kind::Var, b"1").unwrap();
        let first = vault.get(id, "A").unwrap().unwrap().version;
        vault.set(id, "A", Kind::Var, b"2").unwrap();
        let second = vault.get(id, "A").unwrap().unwrap();
        assert_eq!(second.value.as_slice(), b"2");
        assert!(second.version > first);

        assert!(vault.delete(id, "A").unwrap());
        assert!(!vault.delete(id, "A").unwrap());
        assert!(vault.get(id, "A").unwrap().is_none());
        assert!(vault.list(id).unwrap().is_empty());
        assert!(!vault.delete(id, "never-set").unwrap());

        vault.set(id, "A", Kind::Secret, b"3").unwrap();
        assert_eq!(value(vault.get(id, "A").unwrap()), Some(b"3".to_vec()));
        assert_eq!(vault.list(id).unwrap()[0].kind, Kind::Secret);
    }

    #[test]
    fn set_all_writes_everything_or_nothing() {
        let s = setup();
        let mut vault = s.create();
        let id = vault.create_collection("c", &s.admin()).unwrap();

        let big = vec![0; crate::record::MAX_VALUE_LEN + 1];
        assert!(matches!(
            vault.set_all(
                id,
                [("A", Kind::Var, &b"1"[..]), ("B", Kind::Secret, &big[..])]
            ),
            Err(Error::ValueTooLarge)
        ));
        assert!(vault.list(id).unwrap().is_empty());

        vault
            .set_all(
                id,
                [("A", Kind::Var, &b"1"[..]), ("B", Kind::Secret, &b"2"[..])],
            )
            .unwrap();
        assert_eq!(value(vault.get(id, "A").unwrap()), Some(b"1".to_vec()));
        assert_eq!(value(vault.get(id, "B").unwrap()), Some(b"2".to_vec()));
        vault.set_all(id, []).unwrap();
    }

    #[test]
    fn older_versions_never_replace_newer() {
        let s = setup();
        let mut vault = s.create();
        let id = vault.create_collection("c", &s.admin()).unwrap();
        vault.set(id, "A", Kind::Var, b"new").unwrap();

        // Rewind the clock, as if this write had been made before the one above.
        vault
            .conn
            .execute(
                "UPDATE meta SET value = ?1 WHERE key = 'clock'",
                [&0u64.to_be_bytes()[..]],
            )
            .unwrap();
        vault.set(id, "A", Kind::Var, b"old").unwrap();
        assert_eq!(value(vault.get(id, "A").unwrap()), Some(b"new".to_vec()));
    }

    #[test]
    fn collection_errors() {
        let s = setup();
        let mut vault = s.create();
        let id = vault.create_collection("c", &s.admin()).unwrap();
        assert!(matches!(
            vault.create_collection("c", &s.admin()),
            Err(Error::CollectionExists(_))
        ));
        assert!(matches!(
            vault.create_collection("a/b", &s.admin()),
            Err(Error::InvalidName(_))
        ));
        assert!(matches!(
            vault.collection("nope"),
            Err(Error::NoSuchCollection(_))
        ));

        let unknown = CollectionId::random();
        assert!(matches!(
            vault.set(unknown, "A", Kind::Var, b""),
            Err(Error::NoSuchCollection(_))
        ));
        assert!(matches!(
            vault.get(unknown, "A"),
            Err(Error::NoSuchCollection(_))
        ));
        assert!(matches!(
            vault.set(id, "A", Kind::Collection, b""),
            Err(Error::NotSettable)
        ));
        assert!(matches!(
            vault.set(id, "a//b", Kind::Var, b""),
            Err(Error::InvalidName(_))
        ));
    }

    #[test]
    fn entries_in_a_folder() {
        let s = setup();
        let mut vault = s.create();
        let id = vault.create_collection("c", &s.admin()).unwrap();
        for name in ["prod/A", "prod/B", "staging/A", "prodx/C", "prod"] {
            vault.set(id, name, Kind::Var, name.as_bytes()).unwrap();
        }
        let names: Vec<_> = vault
            .entries_in(id, "prod")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["prod/A", "prod/B"]);
    }

    #[test]
    fn recovery_key_unwraps_every_collection_key() {
        let s = setup();
        let mut vault = s.create();
        let id = vault.create_collection("c", &s.admin()).unwrap();
        vault.set(id, "A", Kind::Secret, b"recover me").unwrap();

        let recovery_wrap_key = s.recovery.unwrap_key().wrap_key();
        let wrapped: Vec<u8> = vault
            .conn
            .query_row(
                "SELECT wrapped FROM collection_keys WHERE collection_id = ?1 AND recipient = ?2",
                params![&id.as_bytes()[..], recovery_wrap_key.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        let key = s
            .recovery
            .unwrap_key()
            .unwrap(
                &wrap_context(vault.vault_id(), id, 0),
                &WrappedKey::from_bytes(&wrapped).unwrap(),
            )
            .unwrap();

        let tag = vault.entry_tag(id, "A");
        let record_id: Vec<u8> = vault
            .conn
            .query_row(
                "SELECT record_id FROM entries WHERE name_tag = ?1",
                [&tag[..]],
                |row| row.get(0),
            )
            .unwrap();
        let record = vault.load_record(&record_id).unwrap();
        let body = record.open(&s.keys.verifying_key(), &key).unwrap();
        assert_eq!(body.value.as_slice(), b"recover me");
    }

    #[test]
    fn tampered_records_are_rejected() {
        let s = setup();
        let mut vault = s.create();
        let id = vault.create_collection("c", &s.admin()).unwrap();
        vault.set(id, "A", Kind::Secret, b"value").unwrap();

        let original: Vec<u8> = vault
            .conn
            .query_row(
                "SELECT record FROM records ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        for i in [0, 30, 100, original.len() - 1] {
            let mut tampered = original.clone();
            tampered[i] ^= 1;
            vault
                .conn
                .execute(
                    "UPDATE records SET record = ?1 WHERE record = ?2",
                    params![tampered, original],
                )
                .unwrap();
            assert!(vault.get(id, "A").is_err(), "byte {i}");
            vault
                .conn
                .execute(
                    "UPDATE records SET record = ?1 WHERE record = ?2",
                    params![original, tampered],
                )
                .unwrap();
        }
        assert!(vault.get(id, "A").unwrap().is_some());
    }

    #[test]
    fn nothing_is_stored_in_the_clear() {
        let s = setup();
        {
            let mut vault = s.create();
            let id = vault.create_collection("latem-cloud", &s.admin()).unwrap();
            vault
                .set(
                    id,
                    "prod/STRIPE_KEY",
                    Kind::Secret,
                    b"sk_live_plaintext_canary",
                )
                .unwrap();
            assert!(vault.delete(id, "prod/STRIPE_KEY").unwrap());
            vault
                .set(id, "prod/SENTRY_DSN", Kind::Var, b"https://canary.example")
                .unwrap();
        }
        let file = std::fs::read(&s.path).unwrap();
        for needle in [
            "latem-cloud",
            "STRIPE_KEY",
            "sk_live_plaintext_canary",
            "SENTRY_DSN",
            "canary.example",
        ] {
            let found = file.windows(needle.len()).any(|w| w == needle.as_bytes());
            assert!(!found, "{needle} is in the database file");
        }
    }

    /// Seals `pieces` as chunks and a file of them, as `import` does.
    fn write_file<K: DeviceKeys>(
        vault: &mut Vault<K>,
        collection: CollectionId,
        name: &str,
        pieces: &[&[u8]],
    ) -> crate::file::Manifest {
        let written: Vec<WrittenChunk> = pieces
            .iter()
            .map(|piece| vault.write_chunk(collection, piece).unwrap())
            .collect();
        let manifest = crate::file::Manifest {
            size: pieces.iter().map(|piece| piece.len() as u64).sum(),
            executable: false,
            mtime: 1_762_819_200,
            content: crate::file::Content::Chunks {
                epoch: written[0].epoch,
                ids: written.iter().map(|chunk| chunk.id).collect(),
            },
        };
        vault
            .set(collection, name, Kind::File, &manifest.encode())
            .unwrap();
        manifest
    }

    /// A chunk of `CHUNK_SIZE` bytes, the last piece `last` long.
    fn pieces(fill: &[u8], last: usize) -> Vec<Vec<u8>> {
        let mut pieces: Vec<Vec<u8>> = fill
            .iter()
            .map(|&byte| vec![byte; crate::file::CHUNK_SIZE])
            .collect();
        pieces.last_mut().unwrap().truncate(last);
        pieces
    }

    fn unreferenced<K: DeviceKeys>(vault: &Vault<K>) -> Vec<ItemId> {
        let mut statement = vault
            .conn
            .prepare("SELECT chunk_id FROM chunks WHERE unreferenced IS NOT NULL ORDER BY chunk_id")
            .unwrap();
        statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .unwrap()
            .map(|id| id.unwrap().try_into().unwrap())
            .collect()
    }

    fn held<K: DeviceKeys>(vault: &Vault<K>) -> i64 {
        vault
            .conn
            .query_row("SELECT count(*) FROM chunks", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn files_are_kept_in_chunks_and_read_back() {
        let s = setup();
        let mut vault = s.create();
        let docs = vault.create_collection("docs", &s.admin()).unwrap();
        // Two equal pieces seal to one chunk.
        let pieces = pieces(b"aab", 1000);
        let refs: Vec<&[u8]> = pieces.iter().map(Vec::as_slice).collect();
        let manifest = write_file(&mut vault, docs, "2026/scan.pdf", &refs);
        let ids = manifest.chunks();
        assert_eq!(
            (ids.len(), ids[0] == ids[1], ids[1] == ids[2]),
            (3, true, false)
        );
        assert_eq!(held(&vault), 2);
        assert!(unreferenced(&vault).is_empty());

        // Each chunk is a private file under its id, in the directory beside the store.
        for id in ids {
            let path = vault.chunk_path(id);
            assert!(path.starts_with(s.path.with_file_name("chunks")));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
        }

        assert_eq!(
            vault.list(docs).unwrap(),
            [EntryInfo {
                name: "2026/scan.pdf".into(),
                kind: Kind::File,
                size: 2 * crate::file::CHUNK_SIZE as u64 + 1000,
            }]
        );
        assert!(vault.missing_chunks(docs).unwrap().is_empty());
        let entry = vault.get(docs, "2026/scan.pdf").unwrap().unwrap();
        let read = crate::file::Manifest::decode(&entry.value).unwrap();
        assert!(read == manifest);
        let crate::file::Content::Chunks { epoch, ids } = &read.content else {
            panic!("chunked");
        };
        for (id, piece) in ids.iter().zip(&pieces) {
            assert_eq!(&vault.read_chunk(docs, *epoch, id).unwrap()[..], &piece[..]);
        }
        assert!(matches!(
            vault.read_chunk(docs, epoch + 1, &ids[0]),
            Err(Error::ChunkMissing(_))
        ));

        // A small file is in its manifest.
        let inline = crate::file::Manifest {
            size: 5,
            executable: true,
            mtime: 0,
            content: crate::file::Content::Inline(Zeroizing::new(b"hello".to_vec())),
        };
        vault
            .set(docs, "run.sh", Kind::File, &inline.encode())
            .unwrap();
        let entry = vault.get(docs, "run.sh").unwrap().unwrap();
        assert!(crate::file::Manifest::decode(&entry.value).unwrap() == inline);
        assert_eq!(vault.list(docs).unwrap()[1].size, 5);

        // The store holds none of it in the clear.
        drop(vault);
        let file = std::fs::read(&s.path).unwrap();
        for needle in ["scan.pdf", "hello", "run.sh"] {
            assert!(
                !file.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "{needle}"
            );
        }
    }

    #[test]
    fn a_manifest_names_only_chunks_this_device_holds() {
        let s = setup();
        let mut vault = s.create();
        let docs = vault.create_collection("docs", &s.admin()).unwrap();
        let other = vault.create_collection("other", &s.admin()).unwrap();
        let chunk = vault.write_chunk(docs, b"piece").unwrap();
        let manifest = |epoch, id| crate::file::Manifest {
            size: 5,
            executable: false,
            mtime: 0,
            content: crate::file::Content::Chunks {
                epoch,
                ids: vec![id],
            },
        };
        let set = |vault: &mut Vault<&SoftwareKeys>, collection, m: crate::file::Manifest| {
            vault.set(collection, "f", Kind::File, &m.encode())
        };
        assert!(matches!(
            set(&mut vault, docs, manifest(0, [7; 32])),
            Err(Error::ChunkMissing(_))
        ));
        assert!(matches!(
            set(&mut vault, other, manifest(0, chunk.id)),
            Err(Error::ChunkMissing(_))
        ));
        assert!(set(&mut vault, docs, manifest(1, chunk.id)).is_err());
        std::fs::remove_file(vault.chunk_path(&chunk.id)).unwrap();
        assert!(matches!(
            set(&mut vault, docs, manifest(0, chunk.id)),
            Err(Error::ChunkMissing(_))
        ));
        // Writing it again puts the file back.
        assert_eq!(vault.write_chunk(docs, b"piece").unwrap(), chunk);
        set(&mut vault, docs, manifest(0, chunk.id)).unwrap();

        assert!(matches!(
            vault.write_chunk(docs, b""),
            Err(Error::ChunkTooLarge)
        ));
        assert!(matches!(
            vault.write_chunk(docs, &vec![0; crate::file::CHUNK_SIZE + 1]),
            Err(Error::ChunkTooLarge)
        ));
        assert!(matches!(
            vault.set(docs, "g", Kind::File, b"not a manifest"),
            Err(Error::InvalidManifest(_))
        ));
    }

    #[test]
    fn chunks_no_version_names_are_swept_after_30_days() {
        let s = setup();
        let mut vault = s.create();
        let docs = vault.create_collection("docs", &s.admin()).unwrap();
        let now = files_now();
        let later = now + CHUNK_RETENTION_SECS + 60;
        let one = vec![1; crate::file::CHUNK_SIZE];
        let first = write_file(&mut vault, docs, "a", &[&one, b"two"]);
        assert!(!vault.chunks_dropped());
        // A new version keeps "one" and drops "two".
        let second = write_file(&mut vault, docs, "a", &[&one, b"three"]);
        assert!(vault.chunks_dropped());
        assert_eq!(unreferenced(&vault), [first.chunks()[1]]);
        // It isn't due for 30 days.
        assert_eq!(vault.sweep_chunks_at(now).unwrap(), Swept::default());
        assert!(!vault.chunks_dropped());

        let two = vault.chunk_path(&first.chunks()[1]);
        assert!(two.exists());
        let swept = vault.sweep_chunks_at(later).unwrap();
        assert_eq!(
            swept,
            Swept {
                deleted: 1,
                more: false
            }
        );
        assert!(!two.exists());
        assert_eq!(held(&vault), 2);

        // Another file naming a chunk keeps it; deleting the last one drops it.
        let third = write_file(&mut vault, docs, "b", &[&one]);
        assert_eq!(third.chunks()[0], second.chunks()[0]);
        assert!(vault.delete(docs, "a").unwrap());
        assert_eq!(unreferenced(&vault), [second.chunks()[1]]);
        assert!(vault.delete(docs, "b").unwrap());
        assert_eq!(unreferenced(&vault).len(), 2);
        // Naming one again before it's swept takes it off.
        write_file(&mut vault, docs, "c", &[&one]);
        assert_eq!(unreferenced(&vault), [second.chunks()[1]]);

        // A chunk no manifest ever named, as when an import stops halfway, goes too.
        vault.write_chunk(docs, b"abandoned").unwrap();
        assert_eq!(unreferenced(&vault).len(), 2);
        assert_eq!(vault.sweep_chunks_at(later).unwrap().deleted, 2);
        assert_eq!(held(&vault), 1);

        // A sweep deletes at most a batch, and says when there's more.
        for i in 0..=SWEEP_BATCH as u32 {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            vault
                .conn
                .execute(
                    "INSERT INTO chunks VALUES (?1, ?2, 0, 1, 0, 0)",
                    params![&id[..], &docs.as_bytes()[..]],
                )
                .unwrap();
        }
        let swept = vault.sweep_chunks_at(later).unwrap();
        assert_eq!(
            swept,
            Swept {
                deleted: SWEEP_BATCH,
                more: true
            }
        );
        assert_eq!(
            vault.sweep_chunks_at(later).unwrap(),
            Swept {
                deleted: 1,
                more: false
            }
        );
        assert_eq!(held(&vault), 1);
    }

    fn files_now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn placement_is_kept_per_collection() {
        let s = setup();
        let mut vault = s.create();
        let docs = vault.create_collection("docs", &s.admin()).unwrap();
        assert_eq!(vault.placement(docs).unwrap(), Placement::Keep);
        vault.set_placement(docs, Placement::OnDemand).unwrap();
        drop(vault);
        let mut vault = s.open();
        assert_eq!(vault.placement(docs).unwrap(), Placement::OnDemand);
        vault.set_placement(docs, Placement::Keep).unwrap();
        assert_eq!(vault.placement(docs).unwrap(), Placement::Keep);
        let rows: i64 = vault
            .conn
            .query_row("SELECT count(*) FROM placements", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 0);
        assert!(vault.placement(CollectionId::random()).is_err());
    }

    #[test]
    fn a_file_from_another_device_waits_for_its_chunks() {
        let s = setup();
        let joiner_keys = SoftwareKeys::generate();
        let (mut admin, mut joined, latem, _) = joined_pair(&s, &joiner_keys);
        let manifest = write_file(&mut admin, latem, "release/upload.jks", &[b"jks"]);
        send_missing(&admin, &mut joined);
        let listed = joined.list(latem).unwrap();
        let file = listed.iter().find(|e| e.kind == Kind::File).unwrap();
        assert_eq!((file.name.as_str(), file.size), ("release/upload.jks", 3));
        assert_eq!(
            joined.missing_chunks(latem).unwrap(),
            HashMap::from([("release/upload.jks".to_owned(), 1)])
        );
        assert!(matches!(
            joined.read_chunk(latem, 0, &manifest.chunks()[0]),
            Err(Error::ChunkMissing(_))
        ));
        // A device that reads can't write its own chunks.
        assert!(matches!(
            joined.write_chunk(latem, b"x"),
            Err(Error::ReadOnly)
        ));
    }

    /// A device takes in the chunks a peer sends for its current files, and only those
    /// (files.md, sync).
    #[test]
    fn chunks_from_a_peer_are_checked_and_kept() {
        let s = setup();
        let joiner_keys = SoftwareKeys::generate();
        let (mut admin, mut joined, latem, _) = joined_pair(&s, &joiner_keys);
        let pieces = pieces(&[1, 2], 10);
        let pieces: Vec<&[u8]> = pieces.iter().map(Vec::as_slice).collect();
        let manifest = write_file(&mut admin, latem, "release/app.aab", &pieces);
        let crate::file::Content::Chunks { epoch, ids } = &manifest.content else {
            panic!("a file of two pieces is in chunks");
        };
        let (epoch, first, second) = (*epoch, ids[0], ids[1]);
        assert!(!joined.take_files_arrived());
        send_missing(&admin, &mut joined);
        assert!(
            joined.take_files_arrived(),
            "a file that names chunks arrived"
        );
        assert!(!joined.take_files_arrived(), "and that's said once");
        assert_eq!(
            joined.chunks_not_held(&[first, second, first]).unwrap(),
            [first, second]
        );

        let sealed = admin.sealed_chunk(latem, &first).unwrap().unwrap();
        assert!(
            admin
                .sealed_chunk(CollectionId::random(), &first)
                .unwrap()
                .is_none(),
            "only for its own collection"
        );
        let mut bad = sealed.clone();
        bad[30] ^= 1;
        assert!(joined.receive_chunk(latem, epoch, &first, &bad).is_err());
        let loose = admin.write_chunk(latem, b"loose").unwrap();
        let loose_sealed = admin.sealed_chunk(latem, &loose.id).unwrap().unwrap();
        assert!(matches!(
            joined.receive_chunk(latem, epoch, &loose.id, &loose_sealed),
            Err(Error::ChunkUnwanted)
        ));
        assert!(joined.receive_chunk(latem, epoch, &first, &sealed).unwrap());
        assert!(
            !joined.receive_chunk(latem, epoch, &first, &sealed).unwrap(),
            "kept once"
        );
        assert_eq!(joined.chunks_not_held(ids).unwrap(), [second]);
        assert_eq!(
            joined.missing_chunks(latem).unwrap(),
            HashMap::from([("release/app.aab".to_owned(), 1)])
        );
        let sealed = admin.sealed_chunk(latem, &second).unwrap().unwrap();
        assert!(
            joined
                .receive_chunk(latem, epoch, &second, &sealed)
                .unwrap()
        );
        assert!(joined.missing_chunks(latem).unwrap().is_empty());
        assert_eq!(
            &joined.read_chunk(latem, epoch, &second).unwrap()[..],
            pieces[1]
        );
        assert!(
            unreferenced(&joined).is_empty(),
            "a current file names them"
        );
    }

    /// Chunks of on-demand collections over the limit go least recently used first, sparing
    /// the file being read; kept collections' chunks don't count (files.md, placement).
    #[test]
    fn the_on_demand_cache_drops_what_was_used_least_lately() {
        let s = setup();
        let mut vault = s.create();
        let docs = vault.create_collection("docs", &s.admin()).unwrap();
        let latem = vault.create_collection("latem", &s.admin()).unwrap();
        let a = write_file(&mut vault, docs, "a.pdf", &[b"aaaa"]);
        let b = write_file(&mut vault, docs, "b.pdf", &[b"bbbb"]);
        let c = write_file(&mut vault, docs, "c.pdf", &[b"cccc"]);
        let kept = write_file(&mut vault, latem, "kept.jks", &[b"kkkk"]);
        assert_eq!(
            vault.trim_cache_to(0, &[]).unwrap(),
            0,
            "nothing is on demand"
        );

        vault.set_placement(docs, Placement::OnDemand).unwrap();
        for (manifest, used) in [(&a, 100), (&b, 200), (&c, 300)] {
            vault
                .conn
                .execute(
                    "UPDATE chunks SET used = ?2 WHERE chunk_id = ?1",
                    params![&manifest.chunks()[0][..], used],
                )
                .unwrap();
        }
        // Each sealed chunk is 4 bytes, a nonce and a tag: room for two. `a` was used least
        // lately, but it's being read.
        let size = 4 + 24 + 16;
        assert_eq!(vault.trim_cache_to(2 * size, a.chunks()).unwrap(), 1);
        assert_eq!(vault.chunks_not_held(b.chunks()).unwrap(), b.chunks());
        assert!(!vault.chunk_path(&b.chunks()[0]).exists());
        for held in [&a, &c, &kept] {
            assert!(vault.chunks_not_held(held.chunks()).unwrap().is_empty());
        }
        assert_eq!(
            vault.missing_chunks(docs).unwrap(),
            HashMap::from([("b.pdf".to_owned(), 1)])
        );
        assert_eq!(vault.trim_cache_to(2 * size, &[]).unwrap(), 0, "within it");
        assert_eq!(vault.trim_cache_to(size, &[]).unwrap(), 1);
        assert_eq!(vault.chunks_not_held(a.chunks()).unwrap(), a.chunks());
    }

    #[test]
    fn version_6_stores_open_the_file_records_they_kept() {
        let s = setup();
        let id = {
            let mut vault = s.create();
            let id = vault.create_collection("docs", &s.admin()).unwrap();
            let inline = crate::file::Manifest {
                size: 2,
                executable: false,
                mtime: 0,
                content: crate::file::Content::Inline(Zeroizing::new(b"hi".to_vec())),
            };
            vault
                .set(id, "a.txt", Kind::File, &inline.encode())
                .unwrap();
            vault.set(id, "B", Kind::Var, b"1").unwrap();
            // A build before files kept the record without making it current.
            vault
                .conn
                .execute(
                    "DELETE FROM entries WHERE name_tag = ?1",
                    [&vault.entry_tag(id, "a.txt")[..]],
                )
                .unwrap();
            vault
                .conn
                .execute_batch(
                    "DROP TABLE chunks; DROP TABLE file_chunks; DROP TABLE placements;
                     PRAGMA user_version = 6;",
                )
                .unwrap();
            id
        };
        let mut vault = s.open();
        assert_eq!(user_version(&vault.conn).unwrap(), SCHEMA_VERSION);
        assert_eq!(waiting(&vault), 0);
        let names: Vec<String> = vault
            .list(id)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["B", "a.txt"]);
        assert!(vault.get(id, "a.txt").unwrap().is_some());
    }
}
