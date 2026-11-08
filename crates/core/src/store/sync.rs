//! What sync needs from the store (sync.md): the log after a given entry, the sets this device
//! shares with a peer and what is in them, and taking in other devices' log entries, records and
//! grants.

use openvault_crypto::SymmetricKey;
use rusqlite::{OptionalExtension, Transaction, params};

use super::{
    UPSERT_ENTRY, Vault, add_to_set, collection_label_aad, ensure_collection, entry_label_aad,
    insert_grant, keep_own_key, meta, read_log, save_log, set_summary, wrap_context,
};
use crate::grant::Grant;
use crate::membership::{Change, LogEntry, Membership, Scope};
use crate::record::{Body, Kind, Record};
use crate::sets::{ItemId, SetId, Summary};
use crate::{CollectionId, DeviceId, DeviceKeys, Error, Result, names};

/// What became of an item a peer sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    New,
    /// This device already had it.
    Known,
    /// Kept in its set, but it didn't decrypt or decode, so it never becomes an entry's current
    /// version (sync.md, opening the body).
    Unreadable,
}

/// Lamport clocks stay below 2^63, so they fit SQLite's signed integers.
const MAX_LAMPORT: u64 = 1 << 63;

impl<K: DeviceKeys> Vault<K> {
    /// Up to `max` log entries, from `from` on.
    pub fn log_from(&self, from: u64, max: u16) -> Result<Vec<LogEntry>> {
        let from = i64::try_from(from).unwrap_or(i64::MAX);
        let mut statement = self
            .conn
            .prepare("SELECT entry FROM log WHERE seq >= ?1 ORDER BY seq LIMIT ?2")?;
        let rows = statement.query_map(params![from, max], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|entry| LogEntry::from_bytes(&entry?))
            .collect::<Result<_>>()
    }

    /// Checks and appends entries a peer sent (sync.md, checking entries). Entries this device
    /// already has are skipped. One with a `seq` this device has but another hash is a fork if it
    /// would have been accepted there, and an invalid entry otherwise. Returns how many entries
    /// were new.
    pub fn append_log(&mut self, entries: &[LogEntry]) -> Result<usize> {
        let mut membership = self.membership.clone().ok_or(Error::NoLog)?;
        let head = membership.head().0;
        if entries.iter().any(|entry| entry.seq() <= head) {
            let own = read_log(&self.conn)?;
            for entry in entries.iter().filter(|entry| entry.seq() <= head) {
                let seq = usize::try_from(entry.seq()).map_err(|_| Error::Corrupt("log seq"))?;
                if own[seq].hash() != entry.hash() {
                    return Err(if Membership::is_fork(&own, entry)? {
                        Error::Fork
                    } else {
                        Error::InvalidLogEntry("it differs from this device's entry")
                    });
                }
            }
        }
        let new: Vec<LogEntry> = entries
            .iter()
            .filter(|entry| entry.seq() > head)
            .cloned()
            .collect();
        if new.is_empty() {
            return Ok(0);
        }
        for entry in &new {
            membership.apply(entry)?;
        }
        // A collection whose key changed is recounted, since versions from a device that lost
        // `write` stop counting (records.md, versions).
        let mut rotated: Vec<CollectionId> = new
            .iter()
            .filter_map(|entry| match entry.change() {
                Change::RotateEpoch { collection, .. } => Some(*collection),
                _ => None,
            })
            .collect();
        rotated.sort();
        rotated.dedup();
        let keys = self.epoch_keys(&membership, &rotated)?;
        let tx = self.conn.unchecked_transaction()?;
        save_log(&tx, &new, &membership)?;
        for collection in membership.collections() {
            let epoch = membership.epoch(collection).expect("listed");
            tx.execute(
                "UPDATE collections SET epoch = ?2 WHERE collection_id = ?1 AND epoch != ?2",
                params![&collection.as_bytes()[..], epoch],
            )?;
        }
        for &collection in &rotated {
            self.recount(&tx, &membership, collection, &keys)?;
        }
        tx.commit()?;
        self.membership = Some(membership);
        self.collection_keys.extend(keys);
        Ok(new.len())
    }

    /// The device whose transport key is `endpoint`, if it is in the log and not revoked.
    pub fn member_by_endpoint(&self, endpoint: &[u8; 32]) -> Option<DeviceId> {
        self.membership
            .as_ref()?
            .device_by_endpoint(endpoint)
            .filter(|device| !device.revoked)
            .map(|device| device.info.id)
    }

    /// The sets this device shares with `peer` (sync.md, sets): the grants, and the records of
    /// every collection on which neither device's scope is none. Both work it out from the same
    /// log, so they agree.
    pub fn shared_sets(&self, peer: DeviceId) -> Vec<SetId> {
        let Some(membership) = &self.membership else {
            return Vec::new();
        };
        let mut sets = vec![SetId::GRANTS];
        for collection in membership.collections() {
            if membership.scope(self.device_id, collection) != Scope::None
                && membership.scope(peer, collection) != Scope::None
            {
                sets.push(SetId::records(collection));
            }
        }
        sets.sort();
        sets
    }

    /// The set's item count and id sum, from one row.
    pub fn set_summary(&self, set: SetId) -> Result<Summary> {
        set_summary(&self.conn, set)
    }

    /// The ids in `set` from `lower` up to, but not including, `upper` (`None` for the end of
    /// the id space), in order.
    pub fn set_ids(
        &self,
        set: SetId,
        lower: &ItemId,
        upper: Option<&ItemId>,
    ) -> Result<Vec<ItemId>> {
        let upper = upper.map(|upper| &upper[..]);
        let (query, collection) = match set.collection() {
            Some(collection) => (
                "SELECT record_id FROM records WHERE collection_id = ?1
                 AND record_id >= ?2 AND (?3 IS NULL OR record_id < ?3)
                 ORDER BY record_id",
                Some(collection.as_bytes().to_vec()),
            ),
            None => (
                "SELECT grant_id FROM grants WHERE ?1 IS NULL
                 AND grant_id >= ?2 AND (?3 IS NULL OR grant_id < ?3)
                 ORDER BY grant_id",
                None,
            ),
        };
        let mut statement = self.conn.prepare(query)?;
        let rows = statement.query_map(params![collection, &lower[..], upper], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|id| -> Result<ItemId> {
            id?.try_into().map_err(|_| Error::Corrupt("set item id"))
        })
        .collect()
    }

    /// The items with these ids that this device has, as they are sent.
    pub fn set_items(&self, set: SetId, ids: &[ItemId]) -> Result<Vec<Vec<u8>>> {
        let query = match set.collection() {
            Some(_) => "SELECT record FROM records WHERE record_id = ?1 AND collection_id = ?2",
            None => "SELECT grant FROM grants WHERE grant_id = ?1 AND ?2 IS NULL",
        };
        let collection = set.collection().map(|c| c.as_bytes().to_vec());
        let mut statement = self.conn.prepare(query)?;
        let mut items = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(item) = statement
                .query_row(params![&id[..], collection], |row| row.get::<_, Vec<u8>>(0))
                .optional()?
            {
                items.push(item);
            }
        }
        Ok(items)
    }

    /// Takes in an item a peer sent for `set`, after the checks for its kind (sync.md, accepting
    /// grants and accepting records). An item that fails them is an error and isn't kept.
    pub fn receive(&mut self, set: SetId, item: &[u8]) -> Result<Received> {
        match set.collection() {
            Some(collection) => self.receive_record(collection, item),
            None => self.receive_grant(item),
        }
    }

    fn receive_grant(&mut self, bytes: &[u8]) -> Result<Received> {
        let membership = self.membership.as_ref().ok_or(Error::NoLog)?;
        let grant = Grant::from_bytes(bytes)?;
        grant.check(membership)?;
        let epoch = membership
            .epoch(grant.collection())
            .expect("checked by the grant");
        // A grant to this device that unwraps is also kept as the key it opens records with.
        let key = if grant.recipient() == Some(self.device_id) {
            self.keys
                .unwrap(
                    &wrap_context(self.vault_id, grant.collection(), grant.epoch()),
                    grant.wrapped(),
                )
                .ok()
        } else {
            None
        };
        let tx = self.conn.unchecked_transaction()?;
        if !insert_grant(&tx, &grant)? {
            return Ok(Received::Known);
        }
        if let Some(key) = &key {
            ensure_collection(&tx, grant.collection(), epoch)?;
            keep_own_key(&tx, &grant, &self.keys.wrap_key())?;
            self.read_waiting(&tx, grant.collection(), grant.epoch(), key)?;
        }
        tx.commit()?;
        Ok(Received::New)
    }

    fn receive_record(&mut self, collection: CollectionId, bytes: &[u8]) -> Result<Received> {
        let membership = self.membership.as_ref().ok_or(Error::NoLog)?;
        // Format, flags, lengths and the body hash.
        let record = Record::from_bytes(bytes)?;
        let header = record.header().clone();
        if header.collection != collection {
            return Err(Error::InvalidRecord(
                "the record is from another collection",
            ));
        }
        if header.version.lamport >= MAX_LAMPORT {
            return Err(Error::InvalidRecord("the Lamport clock is too large"));
        }
        let current = membership
            .epoch(collection)
            .ok_or(Error::InvalidRecord("the collection isn't in the log"))?;
        if header.epoch > current {
            return Err(Error::InvalidRecord(
                "the log hasn't reached the record's epoch",
            ));
        }
        let author = header.version.device;
        let author_key = membership
            .device(author)
            .ok_or(Error::InvalidRecord("unknown author"))?
            .info
            .verifying_key
            .clone();
        if !membership.had_scope(author, collection, header.epoch, Scope::Write) {
            return Err(Error::InvalidRecord(
                "the author couldn't write at that epoch",
            ));
        }
        record.verify(&author_key)?;
        let id = record.id();
        let known: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM records WHERE record_id = ?1",
                [&id[..]],
                |row| row.get(0),
            )
            .optional()?;
        if known.is_some() {
            return Ok(Received::Known);
        }

        let counts = counts(membership, &record);
        let readable = membership.scope(self.device_id, collection) >= Scope::Read;
        let body = if readable {
            match self.take_key(collection, header.epoch) {
                Ok(key) => {
                    let body = record.open(&author_key, &key);
                    self.collection_keys.insert((collection, header.epoch), key);
                    Some(body)
                }
                // The grant for this epoch hasn't arrived yet: the record waits for it.
                Err(Error::NoKey(_)) => None,
                Err(e) => return Err(e),
            }
        } else {
            None
        };

        let tx = self.conn.unchecked_transaction()?;
        ensure_collection(&tx, collection, current)?;
        tx.execute(
            "INSERT INTO records VALUES (?1, ?2, ?3)",
            params![&id[..], &collection.as_bytes()[..], bytes],
        )?;
        add_to_set(&tx, SetId::records(collection), &id)?;
        advance_clock(&tx, header.version.lamport)?;
        let received = match body {
            Some(Ok(body)) => {
                if counts {
                    self.index(&tx, collection, &id, &record, &body)?;
                }
                Received::New
            }
            Some(Err(_)) => Received::Unreadable,
            None => {
                tx.execute(
                    "INSERT INTO waiting VALUES (?1, ?2, ?3)",
                    params![&id[..], &collection.as_bytes()[..], header.epoch],
                )?;
                Received::New
            }
        };
        tx.commit()?;
        Ok(received)
    }

    /// Opens the records waiting for a key this device now has, as after the upgrade to version 6
    /// (records.md, waiting records). Starts from this device's keys, so records it only holds
    /// cost nothing.
    pub(super) fn open_waiting(&mut self) -> Result<()> {
        if self.membership.is_none() {
            return Ok(());
        }
        let ready: Vec<(Vec<u8>, u32)> = {
            let mut statement = self.conn.prepare(
                "SELECT collection_id, epoch FROM collection_keys k WHERE recipient = ?1
                 AND EXISTS (
                     SELECT 1 FROM waiting w
                     WHERE w.collection_id = k.collection_id AND w.epoch = k.epoch
                 )",
            )?;
            statement
                .query_map([self.keys.wrap_key().as_bytes()], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?
                .collect::<rusqlite::Result<_>>()?
        };
        let mut keys = Vec::with_capacity(ready.len());
        for (collection, epoch) in ready {
            let collection = CollectionId::try_from(collection.as_slice())?;
            keys.push((collection, epoch, self.take_key(collection, epoch)?));
        }
        if keys.is_empty() {
            return Ok(());
        }
        let tx = self.conn.unchecked_transaction()?;
        for (collection, epoch, key) in &keys {
            self.read_waiting(&tx, *collection, *epoch, key)?;
        }
        tx.commit()?;
        for (collection, epoch, key) in keys {
            self.collection_keys.insert((collection, epoch), key);
        }
        Ok(())
    }

    /// Opens the records that waited for `key`, this device's key to `collection` at `epoch`,
    /// indexes the ones that count, and takes them all off the list. One that doesn't open stays
    /// kept but never becomes current, as when it arrives.
    fn read_waiting(
        &self,
        tx: &Transaction<'_>,
        collection: CollectionId,
        epoch: u32,
        key: &SymmetricKey,
    ) -> Result<()> {
        let membership = self.membership.as_ref().ok_or(Error::NoLog)?;
        let ids: Vec<Vec<u8>> = {
            let mut statement = tx
                .prepare("SELECT record_id FROM waiting WHERE collection_id = ?1 AND epoch = ?2")?;
            statement
                .query_map(params![&collection.as_bytes()[..], epoch], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        for id in ids {
            let bytes: Vec<u8> = tx.query_row(
                "SELECT record FROM records WHERE record_id = ?1",
                [&id[..]],
                |row| row.get(0),
            )?;
            let record = Record::from_bytes(&bytes)?;
            let author = membership
                .device(record.header().version.device)
                .ok_or(Error::InvalidRecord("unknown author"))?;
            if let Ok(body) = record.open(&author.info.verifying_key, key)
                && counts(membership, &record)
            {
                self.index(tx, collection, &record.id(), &record, &body)?;
            }
            tx.execute("DELETE FROM waiting WHERE record_id = ?1", [&id[..]])?;
        }
        Ok(())
    }

    /// Makes `record` the current version of its name if it is newer, and names the collection if
    /// it is the collection's own entry and now current.
    pub(super) fn index(
        &self,
        tx: &Transaction<'_>,
        collection: CollectionId,
        id: &ItemId,
        record: &Record,
        body: &Body,
    ) -> Result<()> {
        let header = record.header();
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
                &id[..],
                i64::try_from(header.version.lamport).expect("checked against MAX_LAMPORT"),
                &header.version.device.as_bytes()[..],
                header.deleted,
                label
            ],
        )?;
        if body.kind != Kind::Collection {
            return Ok(());
        }
        let current: Vec<u8> = tx.query_row(
            "SELECT record_id FROM entries WHERE collection_id = ?1 AND name_tag = ?2",
            params![&collection.as_bytes()[..], &tag[..]],
            |row| row.get(0),
        )?;
        if current != id[..] {
            return Ok(());
        }
        let name = std::str::from_utf8(&body.value)
            .map_err(|_| Error::InvalidRecord("the collection name isn't UTF-8"))?;
        names::check_collection(name)?;
        tx.execute(
            "UPDATE collections SET name_tag = ?2, label = ?3 WHERE collection_id = ?1",
            params![
                &collection.as_bytes()[..],
                &self.collection_tag(name)[..],
                self.cache_key
                    .seal(&collection_label_aad(collection), name.as_bytes())
            ],
        )?;
        Ok(())
    }
}

/// Whether a version may become its name's current one. One from an old epoch whose author has
/// since lost write never does (records.md, versions).
pub(super) fn counts(membership: &Membership, record: &Record) -> bool {
    let header = record.header();
    membership.epoch(header.collection) == Some(header.epoch)
        || membership.scope(header.version.device, header.collection) == Scope::Write
}

/// Moves the clock up to `lamport` if it's behind, so a local write is always newer than
/// anything this device has seen (records.md, versions).
fn advance_clock(tx: &Transaction<'_>, lamport: u64) -> Result<()> {
    let clock = u64::from_be_bytes(
        meta(tx, "clock")?
            .try_into()
            .map_err(|_| Error::Corrupt("clock"))?,
    );
    if lamport > clock {
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'clock'",
            [&lamport.to_be_bytes()[..]],
        )?;
    }
    Ok(())
}
