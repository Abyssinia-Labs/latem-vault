//! Revoking a device and changing its scopes (sync.md, revoking and reducing scopes): the log
//! entries, new keys where it loses `read` or `write`, the keys it gains with `read`, and
//! recounting a collection's entries once its key changes.

use std::collections::{HashMap, HashSet};

use openvault_crypto::SymmetricKey;
use openvault_crypto::hash::Hash;
use rusqlite::{Transaction, params};

use super::sync::counts;
use super::{Vault, insert_grant, save_log, wrap_context};
use crate::grant::Grant;
use crate::membership::{AdminKey, Change, Membership, Scope};
use crate::record::{Body, Kind, Record};
use crate::{CollectionId, DeviceId, DeviceKeys, Error, Result};

/// What revoking a device did.
#[derive(Debug)]
pub struct Revocation {
    /// The collections that got a new key, because the device could read them.
    pub rotated: Vec<CollectionId>,
    /// Entries the device wrote last that this device wrote again under the new key.
    pub carried: usize,
}

/// What changing a device's scope did.
#[derive(Debug)]
pub struct ScopeChange {
    /// Whether the collection got a new key, because the device lost `read` or `write`.
    pub rotated: bool,
    /// Keys of the collection given to the device, because it may now read it.
    pub granted: usize,
    /// Entries it wrote last that this device wrote again under the new key.
    pub carried: usize,
}

/// What a device can read and what it wrote last, to review before revoking it (sync.md,
/// reviewing). Only collections this device knows by name are listed.
#[derive(Debug, Default)]
pub struct Review {
    /// Each collection it can read, with the names of its current secrets, to change at their
    /// providers once it's revoked.
    pub secrets: Vec<(String, Vec<String>)>,
    /// Each collection's current entries that it wrote last.
    pub wrote_last: Vec<(String, Vec<Written>)>,
}

/// A current entry, as written by one device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Written {
    pub name: String,
    pub deleted: bool,
}

/// An entry whose current version a device wrote.
struct Current {
    name: String,
    kind: Kind,
    deleted: bool,
    record_id: Vec<u8>,
}

impl<K: DeviceKeys> Vault<K> {
    /// What `device` can read and what it wrote last.
    pub fn review_revocation(&self, device: DeviceId) -> Result<Review> {
        let membership = self.membership.as_ref().ok_or(Error::NoLog)?;
        if membership.device(device).is_none() {
            return Err(Error::CantRevoke("no such device"));
        }
        let mut review = Review::default();
        for collection in self.collections()? {
            if membership.scope(device, collection.id) >= Scope::Read {
                let secrets = self
                    .list(collection.id)?
                    .into_iter()
                    .filter(|entry| entry.kind == Kind::Secret)
                    .map(|entry| entry.name)
                    .collect();
                review.secrets.push((collection.name.clone(), secrets));
            }
            let written: Vec<Written> = self
                .written_by(collection.id, device)?
                .into_iter()
                .filter(|current| current.kind != Kind::Collection)
                .map(|current| Written {
                    name: current.name,
                    deleted: current.deleted,
                })
                .collect();
            if !written.is_empty() {
                review.wrote_last.push((collection.name, written));
            }
        }
        Ok(review)
    }

    /// Revokes `device`. `admin` signs revoke_device and a rotate_epoch for each collection the
    /// device could read, and this device gives each new key to every remaining reader and the
    /// recovery key. Where both could write, this device writes the entries the device wrote
    /// last again under the new key, so its real changes are kept. All of it is one transaction.
    pub fn revoke_device(&mut self, device: DeviceId, admin: &impl AdminKey) -> Result<Revocation> {
        let membership = self.membership.clone().ok_or(Error::NoLog)?;
        if device == self.device_id {
            return Err(Error::CantRevoke("it's the device doing the revoking"));
        }
        match membership.device(device) {
            None => return Err(Error::CantRevoke("no such device")),
            Some(found) if found.revoked => return Err(Error::CantRevoke("it's already revoked")),
            Some(_) => {}
        }
        let rotated: Vec<CollectionId> = membership
            .collections()
            .filter(|&collection| membership.scope(device, collection) >= Scope::Read)
            .collect();
        if rotated
            .iter()
            .any(|&collection| membership.scope(self.device_id, collection) < Scope::Read)
        {
            return Err(Error::CantRevoke(
                "it can read a collection this device can't, so this device can't give out its new key",
            ));
        }
        let losing_write: Vec<CollectionId> = rotated
            .iter()
            .copied()
            .filter(|&collection| membership.scope(device, collection) == Scope::Write)
            .collect();
        let carried = self.commit_change(
            Change::RevokeDevice(device),
            device,
            &rotated,
            &losing_write,
            Vec::new(),
            admin,
        )?;
        Ok(Revocation { rotated, carried })
    }

    /// Gives `device` `scope` on `collection` (membership.md, set_scope). Raising it to `read`
    /// or `write` grants it every key of the collection this device holds, the earlier epochs
    /// included. Taking away its `read` or `write` changes the collection's key, as revoking
    /// does, and where it loses `write` this device writes its last changes again under the new
    /// key. All of it is one transaction.
    pub fn set_scope(
        &mut self,
        device: DeviceId,
        collection: CollectionId,
        scope: Scope,
        admin: &impl AdminKey,
    ) -> Result<ScopeChange> {
        let membership = self.membership.clone().ok_or(Error::NoLog)?;
        if device == self.device_id {
            return Err(Error::CantChangeScope(
                "it's this device; change it from another one",
            ));
        }
        match membership.device(device) {
            None => return Err(Error::CantChangeScope("no such device")),
            Some(found) if found.revoked => return Err(Error::CantChangeScope("it's revoked")),
            Some(_) => {}
        }
        let current = membership
            .epoch(collection)
            .ok_or_else(|| Error::NoSuchCollection(collection.to_string()))?;
        let before = membership.scope(device, collection);
        if before == scope {
            return Err(Error::CantChangeScope("it already has that scope"));
        }
        let gains_read = before < Scope::Read && scope >= Scope::Read;
        let loses_write = before == Scope::Write && scope < Scope::Write;
        let rotates = loses_write || (before >= Scope::Read && scope < Scope::Read);
        if (gains_read || rotates) && membership.scope(self.device_id, collection) < Scope::Read {
            return Err(Error::CantChangeScope(
                "this device can't read the collection, so it can't give out its keys",
            ));
        }

        // Every key this device holds, for a device that may now read.
        let mut grants = Vec::new();
        if gains_read {
            let wrap_key = membership
                .device(device)
                .expect("checked above")
                .info
                .wrap_key
                .clone();
            for epoch in 0..=current {
                let key = match self.take_key(collection, epoch) {
                    Ok(key) => key,
                    Err(Error::NoKey(_)) => continue,
                    Err(e) => return Err(e),
                };
                let wrapped = wrap_key.wrap(&wrap_context(self.vault_id, collection, epoch), &key);
                self.collection_keys.insert((collection, epoch), key);
                grants.push(self.sign_grant(collection, epoch, Some(device), wrapped)?);
            }
        }
        let granted = grants.len();
        let rotated: &[CollectionId] = if rotates { &[collection] } else { &[] };
        let losing_write: &[CollectionId] = if loses_write { &[collection] } else { &[] };
        let carried = self.commit_change(
            Change::SetScope {
                device,
                collection,
                scope,
            },
            device,
            rotated,
            losing_write,
            grants,
            admin,
        )?;
        Ok(ScopeChange {
            rotated: rotates,
            granted,
            carried,
        })
    }

    /// Signs `change` and a rotate_epoch for each of `rotate`, makes each rotated collection's
    /// new key and grants it to every reader the change leaves and the recovery key, and writes
    /// it all with `grants` in one transaction, recounting each rotated collection. In
    /// `losing_write`, where this device can write, the entries `device` wrote last are written
    /// again under the new key. Returns how many were.
    fn commit_change(
        &mut self,
        change: Change,
        device: DeviceId,
        rotate: &[CollectionId],
        losing_write: &[CollectionId],
        mut grants: Vec<Grant>,
        admin: &impl AdminKey,
    ) -> Result<usize> {
        let mut membership = self.membership.clone().ok_or(Error::NoLog)?;
        // Read before anything changes: what it wrote last, and the keys so far, to recount
        // with.
        let mut carry = Vec::new();
        for &collection in losing_write {
            if membership.scope(self.device_id, collection) != Scope::Write {
                continue;
            }
            for current in self.written_by(collection, device)? {
                let body = if current.deleted {
                    Body::new(current.kind, &current.name, b"")
                } else {
                    let record = self.load_record(&current.record_id)?;
                    self.open_record(collection, &record)?
                };
                carry.push((collection, body, current.deleted));
            }
        }
        let old_keys = self.epoch_keys(&membership, rotate)?;

        // Signed before anything is written, so a refused signature leaves nothing behind.
        let mut entries = vec![membership.append(change, admin)?];
        for &collection in rotate {
            let epoch = membership.epoch(collection).expect("it could read it") + 1;
            entries.push(membership.append(Change::RotateEpoch { collection, epoch }, admin)?);
        }
        let first_new = grants.len();
        let mut new_keys = Vec::with_capacity(rotate.len());
        for &collection in rotate {
            let epoch = membership.epoch(collection).expect("rotated");
            let key = SymmetricKey::generate();
            let context = wrap_context(self.vault_id, collection, epoch);
            let readers: Vec<_> = membership
                .devices()
                .filter(|other| {
                    !other.revoked && membership.scope(other.info.id, collection) >= Scope::Read
                })
                .map(|other| (other.info.id, other.info.wrap_key.clone()))
                .collect();
            for (reader, wrap_key) in readers {
                let wrapped = wrap_key.wrap(&context, &key);
                grants.push(self.sign_grant(collection, epoch, Some(reader), wrapped)?);
            }
            let wrapped = self.recovery.wrap(&context, &key);
            grants.push(self.sign_grant(collection, epoch, None, wrapped)?);
            new_keys.push((collection, epoch, key));
        }

        let tx = self.conn.unchecked_transaction()?;
        save_log(&tx, &entries, &membership)?;
        for &(collection, epoch, _) in &new_keys {
            tx.execute(
                "UPDATE collections SET epoch = ?2 WHERE collection_id = ?1",
                params![&collection.as_bytes()[..], epoch],
            )?;
        }
        // The new keys' grants to this device and the recovery key are also kept as keys to
        // unwrap, as when a collection is created.
        let own = self.keys.wrap_key();
        for (i, grant) in grants.iter().enumerate() {
            insert_grant(&tx, grant)?;
            let recipient = match grant.recipient() {
                _ if i < first_new => continue,
                Some(reader) if reader == self.device_id => own.as_bytes(),
                Some(_) => continue,
                None => self.recovery.as_bytes(),
            };
            tx.execute(
                "INSERT INTO collection_keys VALUES (?1, ?2, ?3, ?4)",
                params![
                    &grant.collection().as_bytes()[..],
                    grant.epoch(),
                    recipient,
                    grant.wrapped().to_bytes()
                ],
            )?;
        }
        for &collection in rotate {
            self.recount(&tx, &membership, collection, &old_keys)?;
        }
        for (collection, body, deleted) in &carry {
            let (_, epoch, key) = new_keys
                .iter()
                .find(|(rotated, ..)| rotated == collection)
                .expect("carried only from rotated collections");
            self.write_record(&tx, *collection, *epoch, key, body, *deleted)?;
        }
        tx.commit()?;

        self.membership = Some(membership);
        self.collection_keys.extend(old_keys);
        for (collection, epoch, key) in new_keys {
            self.collection_keys.insert((collection, epoch), key);
        }
        Ok(carry.len())
    }

    /// This device's keys to every epoch of `collections` that `membership` has reached, for
    /// [`recount`](Self::recount). Callers put them back in the cache.
    pub(super) fn epoch_keys(
        &mut self,
        membership: &Membership,
        collections: &[CollectionId],
    ) -> Result<HashMap<(CollectionId, u32), SymmetricKey>> {
        let mut keys = HashMap::new();
        for &collection in collections {
            for epoch in 0..=membership.epoch(collection).unwrap_or(0) {
                match self.take_key(collection, epoch) {
                    Ok(key) => {
                        keys.insert((collection, epoch), key);
                    }
                    Err(Error::NoKey(_)) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(keys)
    }

    /// Recounts `collection` after its key changed (records.md, versions). A current version
    /// from an older epoch whose author no longer has `write` stops counting, and the newest
    /// version of its name that still counts takes its place, if there is one. Reads the
    /// collection's records only when a version stopped counting.
    pub(super) fn recount(
        &self,
        tx: &Transaction<'_>,
        membership: &Membership,
        collection: CollectionId,
        keys: &HashMap<(CollectionId, u32), SymmetricKey>,
    ) -> Result<()> {
        let authors: Vec<Vec<u8>> = {
            let mut statement =
                tx.prepare("SELECT DISTINCT device_id FROM entries WHERE collection_id = ?1")?;
            statement
                .query_map([&collection.as_bytes()[..]], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        let mut stale: HashSet<Hash> = HashSet::new();
        for author in authors {
            let author = DeviceId::try_from(author.as_slice())?;
            if membership.scope(author, collection) == Scope::Write {
                continue;
            }
            let rows: Vec<(Vec<u8>, Vec<u8>)> = {
                let mut statement = tx.prepare(
                    "SELECT e.name_tag, r.record FROM entries e JOIN records r USING (record_id)
                     WHERE e.collection_id = ?1 AND e.device_id = ?2",
                )?;
                statement
                    .query_map(
                        params![&collection.as_bytes()[..], &author.as_bytes()[..]],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?
                    .collect::<rusqlite::Result<_>>()?
            };
            for (tag, record) in rows {
                if !counts(membership, &Record::from_bytes(&record)?) {
                    stale.insert(tag.try_into().map_err(|_| Error::Corrupt("name tag"))?);
                }
            }
        }
        if stale.is_empty() {
            return Ok(());
        }
        for tag in &stale {
            tx.execute(
                "DELETE FROM entries WHERE collection_id = ?1 AND name_tag = ?2",
                params![&collection.as_bytes()[..], &tag[..]],
            )?;
            // Whatever becomes current below names its own chunks again.
            self.set_file_chunks(tx, collection, tag, &[])?;
        }
        let mut statement = tx.prepare("SELECT record FROM records WHERE collection_id = ?1")?;
        let mut rows = statement.query([&collection.as_bytes()[..]])?;
        while let Some(row) = rows.next()? {
            let record = Record::from_bytes(&row.get::<_, Vec<u8>>(0)?)?;
            let header = record.header();
            // Records without their key wait for it, and are counted when it arrives.
            let Some(key) = keys.get(&(collection, header.epoch)) else {
                continue;
            };
            if !counts(membership, &record) {
                continue;
            }
            let Some(author) = membership.device(header.version.device) else {
                continue;
            };
            let Ok(body) = record.open(&author.info.verifying_key, key) else {
                continue;
            };
            if stale.contains(&self.entry_tag(collection, &body.name)) {
                self.index(tx, collection, &record.id(), &record, &body)?;
            }
        }
        Ok(())
    }

    /// The entries in `collection` whose current version `device` wrote.
    fn written_by(&self, collection: CollectionId, device: DeviceId) -> Result<Vec<Current>> {
        let mut statement = self.conn.prepare(
            "SELECT name_tag, label, deleted, record_id FROM entries
             WHERE collection_id = ?1 AND device_id = ?2",
        )?;
        let rows = statement.query_map(
            params![&collection.as_bytes()[..], &device.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )?;
        let mut written = Vec::new();
        for row in rows {
            let (tag, label, deleted, record_id) = row?;
            let tag: Hash = tag.try_into().map_err(|_| Error::Corrupt("name tag"))?;
            let super::Label { kind, name, .. } =
                self.open_entry_label(collection, &tag, &label)?;
            written.push(Current {
                name,
                kind,
                deleted,
                record_id,
            });
        }
        written.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(written)
    }
}
