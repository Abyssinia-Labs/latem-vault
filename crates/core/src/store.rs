//! The local store: one SQLite database per vault (records.md, local store).

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::path::Path;
use std::time::Duration;

use openvault_crypto::hash::{Hash, contexts, derive_key, keyed_hash};
use openvault_crypto::{SymmetricKey, VerifyingKey, WrapKey, WrappedKey};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use zeroize::Zeroizing;

use crate::record::{Body, Kind, Record, Version};
use crate::{CollectionId, DeviceId, DeviceKeys, Error, Result, VaultId, names};

const SCHEMA_VERSION: i64 = 1;

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

CREATE TABLE collections (
    collection_id BLOB PRIMARY KEY,
    epoch INTEGER NOT NULL,
    name_tag BLOB NOT NULL UNIQUE,
    label BLOB NOT NULL
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

/// A secret or variable, decrypted.
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub value: Zeroizing<Vec<u8>>,
    pub version: Version,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryInfo {
    pub name: String,
    pub kind: Kind,
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
}

impl<K: DeviceKeys> Vault<K> {
    /// Creates a new vault at `path`, with this device as its only member.
    ///
    /// Every collection key is also wrapped to `recovery`.
    pub fn create(path: &Path, keys: K, recovery: &WrapKey) -> Result<Self> {
        // Create the file ourselves so it is never readable by others, even briefly.
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        match options.open(path) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(Error::VaultExists(path.into()));
            }
            result => drop(result?),
        }

        let vault_id = VaultId::random();
        let device_id = DeviceId::random();
        let init = || -> Result<Connection> {
            let conn = connect(path)?;
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(SCHEMA)?;
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            for (key, value) in [
                ("vault_id", &vault_id.as_bytes()[..]),
                ("device_id", &device_id.as_bytes()[..]),
                ("recovery_wrap_key", recovery.as_bytes()),
                ("clock", &0u64.to_be_bytes()[..]),
            ] {
                tx.execute("INSERT INTO meta VALUES (?1, ?2)", params![key, value])?;
            }
            tx.execute(
                "INSERT INTO devices VALUES (?1, ?2, ?3)",
                params![
                    &device_id.as_bytes()[..],
                    keys.verifying_key().as_bytes(),
                    keys.wrap_key().as_bytes()
                ],
            )?;
            tx.commit()?;
            Ok(conn)
        };
        match init() {
            Ok(conn) => Ok(Self::new(conn, keys, vault_id, device_id, recovery.clone())),
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
        let conn = connect(path)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != SCHEMA_VERSION {
            return Err(Error::UnsupportedStore(version));
        }
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
        Ok(Self::new(conn, keys, vault_id, device_id, recovery))
    }

    fn new(
        conn: Connection,
        keys: K,
        vault_id: VaultId,
        device_id: DeviceId,
        recovery: WrapKey,
    ) -> Self {
        let local = keys.local_key().as_bytes();
        let index_key = derive_key(contexts::LOCAL_INDEX, local);
        let cache_key = SymmetricKey::from_bytes(*derive_key(contexts::LOCAL_CACHE, local));
        Self {
            conn,
            keys,
            vault_id,
            device_id,
            recovery,
            index_key,
            cache_key,
            collection_keys: HashMap::new(),
        }
    }

    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub fn create_collection(&mut self, name: &str) -> Result<CollectionId> {
        names::check_collection(name)?;
        let tag = self.collection_tag(name);
        let id = CollectionId::random();
        let key = SymmetricKey::generate();

        let tx = self.conn.unchecked_transaction()?;
        let taken = tx
            .query_row(
                "SELECT 1 FROM collections WHERE name_tag = ?1",
                [&tag[..]],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if taken {
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
        for recipient in [self.keys.wrap_key(), self.recovery.clone()] {
            tx.execute(
                "INSERT INTO collection_keys VALUES (?1, 0, ?2, ?3)",
                params![
                    &id.as_bytes()[..],
                    recipient.as_bytes(),
                    recipient.wrap(&context, &key).to_bytes()
                ],
            )?;
        }
        let body = Body::new(Kind::Collection, "", name.as_bytes());
        self.write_record(&tx, id, 0, &key, &body, false)?;
        tx.commit()?;

        self.collection_keys.insert((id, 0), key);
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
            .prepare("SELECT collection_id, label FROM collections")?;
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

    /// Sets a secret or variable, replacing any current value.
    pub fn set(
        &mut self,
        collection: CollectionId,
        name: &str,
        kind: Kind,
        value: &[u8],
    ) -> Result<()> {
        if kind == Kind::Collection {
            return Err(Error::NotSettable);
        }
        names::check_entry(name)?;
        self.write(collection, &Body::new(kind, name, value), false)
    }

    /// The current value of a secret or variable, or `None` if it doesn't exist or was deleted.
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
        }))
    }

    /// Deletes a secret or variable. Returns whether there was one to delete.
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
        let (kind, _) = self.open_entry_label(collection, &tag, &label)?;
        self.write(collection, &Body::new(kind, name, b""), true)?;
        Ok(true)
    }

    /// The names and kinds of a collection's current secrets and variables, by name.
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
            let (kind, name) = self.open_entry_label(collection, &tag, &label)?;
            if kind != Kind::Collection {
                entries.push(EntryInfo { name, kind });
            }
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// The current secrets and variables under `folder/`, such as every entry in `prod/`.
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

    fn write(&mut self, collection: CollectionId, body: &Body, deleted: bool) -> Result<()> {
        let epoch = self.epoch(collection)?;
        let key = self.take_key(collection, epoch)?;
        let result = self.commit_record(collection, epoch, &key, body, deleted);
        self.collection_keys.insert((collection, epoch), key);
        result
    }

    fn commit_record(
        &self,
        collection: CollectionId,
        epoch: u32,
        key: &SymmetricKey,
        body: &Body,
        deleted: bool,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        self.write_record(&tx, collection, epoch, key, body, deleted)?;
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

        let tag = self.entry_tag(collection, &body.name);
        let label = self.cache_key.seal(
            &entry_label_aad(collection, &tag),
            &[&[body.kind.code()][..], body.name.as_bytes()].concat(),
        );
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

    fn open_entry_label(
        &self,
        collection: CollectionId,
        tag: &Hash,
        label: &[u8],
    ) -> Result<(Kind, String)> {
        let plaintext = self
            .cache_key
            .open(&entry_label_aad(collection, tag), label)?;
        let (&kind, name) = plaintext
            .split_first()
            .ok_or(Error::Corrupt("entry label"))?;
        let kind = Kind::from_code(kind).ok_or(Error::Corrupt("entry label"))?;
        let name = String::from_utf8(name.to_vec()).map_err(|_| Error::Corrupt("entry label"))?;
        Ok((kind, name))
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
    // Several `openvault run` processes may read while another writes.
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(conn)
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

    use openvault_crypto::RecoveryKey;

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
            Vault::create(
                &self.path,
                &self.keys,
                &self.recovery.unwrap_key().wrap_key(),
            )
            .unwrap()
        }

        fn open(&self) -> Vault<&SoftwareKeys> {
            Vault::open(&self.path, &self.keys).unwrap()
        }
    }

    fn value(entry: Option<Entry>) -> Option<Vec<u8>> {
        entry.map(|e| e.value.to_vec())
    }

    #[test]
    fn values_survive_reopening() {
        let s = setup();
        let (vault_id, id) = {
            let mut vault = s.create();
            let id = vault.create_collection("latem-cloud").unwrap();
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
                    kind: Kind::Var
                },
                EntryInfo {
                    name: "prod/STRIPE_KEY".into(),
                    kind: Kind::Secret
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
        let recovery = s.recovery.unwrap_key().wrap_key();
        assert!(matches!(
            Vault::create(&s.path, &s.keys, &recovery),
            Err(Error::VaultExists(_))
        ));
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
        let id = vault.create_collection("c").unwrap();

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
    fn older_versions_never_replace_newer() {
        let s = setup();
        let mut vault = s.create();
        let id = vault.create_collection("c").unwrap();
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
        let id = vault.create_collection("c").unwrap();
        assert!(matches!(
            vault.create_collection("c"),
            Err(Error::CollectionExists(_))
        ));
        assert!(matches!(
            vault.create_collection("a/b"),
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
        let id = vault.create_collection("c").unwrap();
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
        let id = vault.create_collection("c").unwrap();
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
        let id = vault.create_collection("c").unwrap();
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
            let id = vault.create_collection("latem-cloud").unwrap();
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
}
