//! What files need from the store (files.md, local store): chunks kept as files beside the
//! database, the chunks each current file version names, sweeping the ones no version names any
//! more, and where this device keeps each collection's chunks.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use openvault_crypto::{ChunkKeys, chunk_id};
use rusqlite::{OptionalExtension, Transaction, params};
use zeroize::Zeroizing;

use super::Vault;
use crate::file::{CHUNK_SIZE, ChunkId, Content, Manifest, chunk_aad};
use crate::membership::Scope;
use crate::record::Kind;
use crate::{CollectionId, DeviceKeys, Error, Result};

/// The chunks this device holds, which chunks each current file version names, and this
/// device's placements. Added by version 7.
pub(super) const FILES_SCHEMA: &str = "
-- Each is a file in the chunks directory.
CREATE TABLE IF NOT EXISTS chunks (
    chunk_id BLOB PRIMARY KEY,
    collection_id BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    size INTEGER NOT NULL,
    -- When it was last written or read, in seconds since 1970, to the day.
    used INTEGER NOT NULL,
    -- When no current version named it any more; NULL while one does.
    unreferenced INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS chunks_by_unreferenced ON chunks (unreferenced)
    WHERE unreferenced IS NOT NULL;

-- Whether this device holds them or not.
CREATE TABLE IF NOT EXISTS file_chunks (
    collection_id BLOB NOT NULL,
    name_tag BLOB NOT NULL,
    chunk_id BLOB NOT NULL,
    PRIMARY KEY (collection_id, name_tag, chunk_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS file_chunks_by_chunk ON file_chunks (chunk_id);

-- Only where it isn't the default.
CREATE TABLE IF NOT EXISTS placements (
    collection_id BLOB PRIMARY KEY,
    placement INTEGER NOT NULL
) STRICT;
";

/// How long a chunk no current version names is kept, so an older version can still be read.
pub const CHUNK_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;
/// The most chunks one sweep deletes.
pub const SWEEP_BATCH: usize = 1000;
/// `used` changes at most this often, so reading a file doesn't write to the store each time.
const USED_RESOLUTION_SECS: i64 = 24 * 60 * 60;

/// Which chunks this device keeps for a collection (files.md, placement).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// Every chunk of every current version.
    Keep,
    /// The chunks of files read lately.
    OnDemand,
}

impl Placement {
    /// An iPhone fetches files when they're read; computers keep them all.
    pub const DEFAULT: Self = if cfg!(target_os = "ios") {
        Self::OnDemand
    } else {
        Self::Keep
    };

    pub fn code(self) -> u8 {
        match self {
            Self::Keep => 0x01,
            Self::OnDemand => 0x02,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::Keep),
            0x02 => Some(Self::OnDemand),
            _ => None,
        }
    }
}

/// A chunk this device sealed and holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrittenChunk {
    pub id: ChunkId,
    /// The collection key it's sealed under, which its manifest names.
    pub epoch: u32,
}

/// What one sweep did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Swept {
    pub deleted: usize,
    /// Whether more were due than one sweep deletes.
    pub more: bool,
}

impl<K: DeviceKeys> Vault<K> {
    /// Seals a piece of a file under the collection's current key and keeps it, unless this
    /// device already holds it. It counts as unreferenced until a manifest names it, so a write
    /// that stops halfway leaves chunks the sweep deletes.
    pub fn write_chunk(
        &mut self,
        collection: CollectionId,
        plaintext: &[u8],
    ) -> Result<WrittenChunk> {
        if plaintext.is_empty() || plaintext.len() > CHUNK_SIZE {
            return Err(Error::ChunkTooLarge);
        }
        let epoch = self.epoch(collection)?;
        if let Some(membership) = &self.membership
            && membership.scope(self.device_id, collection) != Scope::Write
        {
            return Err(Error::ReadOnly);
        }
        let key = self.take_key(collection, epoch)?;
        let sealed =
            ChunkKeys::derive(&key).seal(&chunk_aad(self.vault_id, collection, epoch), plaintext);
        self.collection_keys.insert((collection, epoch), key);
        let id = chunk_id(&sealed);
        let path = self.chunk_path(&id);
        let known = self
            .conn
            .query_row(
                "SELECT 1 FROM chunks WHERE chunk_id = ?1",
                [&id[..]],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if known && path.exists() {
            return Ok(WrittenChunk { id, epoch });
        }
        // The row first, so a chunk file is never left without one for the sweep to find.
        if !known {
            let now = now();
            self.conn.execute(
                "INSERT INTO chunks VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    &id[..],
                    &collection.as_bytes()[..],
                    epoch,
                    i64::try_from(sealed.len()).expect("a chunk is small"),
                    now,
                    now
                ],
            )?;
        }
        if let Err(e) = self.write_chunk_file(&path, &sealed) {
            if !known {
                self.conn
                    .execute("DELETE FROM chunks WHERE chunk_id = ?1", [&id[..]])?;
            }
            return Err(e);
        }
        Ok(WrittenChunk { id, epoch })
    }

    /// A chunk of a file in `collection`, sealed under `epoch` as its manifest says, checked
    /// against its id and opened.
    pub fn read_chunk(
        &mut self,
        collection: CollectionId,
        epoch: u32,
        id: &ChunkId,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let row: Option<(Vec<u8>, u32, i64)> = self
            .conn
            .query_row(
                "SELECT collection_id, epoch, used FROM chunks WHERE chunk_id = ?1",
                [&id[..]],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((held_in, held_epoch, used)) = row else {
            return Err(Error::ChunkMissing(*id));
        };
        if held_in != collection.as_bytes() || held_epoch != epoch {
            return Err(Error::ChunkMissing(*id));
        }
        let sealed = match fs::read(self.chunk_path(id)) {
            Ok(sealed) => sealed,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(Error::ChunkMissing(*id)),
            Err(e) => return Err(e.into()),
        };
        if chunk_id(&sealed) != *id {
            return Err(Error::Corrupt("a chunk doesn't match its id"));
        }
        let key = self.take_key(collection, epoch)?;
        let opened =
            ChunkKeys::derive(&key).open(&chunk_aad(self.vault_id, collection, epoch), &sealed);
        self.collection_keys.insert((collection, epoch), key);
        let plaintext = opened?;
        let now = now();
        if used <= now - USED_RESOLUTION_SECS {
            self.conn.execute(
                "UPDATE chunks SET used = ?2 WHERE chunk_id = ?1",
                params![&id[..], now],
            )?;
        }
        Ok(plaintext)
    }

    /// For each current file in `collection` with chunks this device doesn't hold, how many.
    pub fn missing_chunks(&self, collection: CollectionId) -> Result<HashMap<String, u64>> {
        let mut statement = self.conn.prepare(
            "SELECT f.name_tag, count(*), e.label FROM file_chunks f
             JOIN entries e USING (collection_id, name_tag)
             WHERE f.collection_id = ?1
             AND NOT EXISTS (SELECT 1 FROM chunks c WHERE c.chunk_id = f.chunk_id)
             GROUP BY f.name_tag",
        )?;
        let rows = statement.query_map([&collection.as_bytes()[..]], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut missing = HashMap::new();
        for row in rows {
            let (tag, count, label) = row?;
            let tag = tag.try_into().map_err(|_| Error::Corrupt("name tag"))?;
            let label = self.open_entry_label(collection, &tag, &label)?;
            missing.insert(label.name, u64::try_from(count).unwrap_or(0));
        }
        Ok(missing)
    }

    /// This device's placement for `collection`.
    pub fn placement(&self, collection: CollectionId) -> Result<Placement> {
        self.epoch(collection)?;
        let code: Option<u8> = self
            .conn
            .query_row(
                "SELECT placement FROM placements WHERE collection_id = ?1",
                [&collection.as_bytes()[..]],
                |row| row.get(0),
            )
            .optional()?;
        Ok(code
            .and_then(Placement::from_code)
            .unwrap_or(Placement::DEFAULT))
    }

    pub fn set_placement(&mut self, collection: CollectionId, placement: Placement) -> Result<()> {
        self.epoch(collection)?;
        if placement == Placement::DEFAULT {
            self.conn.execute(
                "DELETE FROM placements WHERE collection_id = ?1",
                [&collection.as_bytes()[..]],
            )?;
        } else {
            self.conn.execute(
                "INSERT INTO placements VALUES (?1, ?2)
                 ON CONFLICT (collection_id) DO UPDATE SET placement = excluded.placement",
                params![&collection.as_bytes()[..], placement.code()],
            )?;
        }
        Ok(())
    }

    /// Whether a write or a received record has left chunks unreferenced since the last sweep
    /// that finished, so it's worth sweeping.
    pub fn chunks_dropped(&self) -> bool {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Deletes up to [`SWEEP_BATCH`] chunks that no current version has named for
    /// [`CHUNK_RETENTION_SECS`]. Reads only those, by their index.
    pub fn sweep_chunks(&mut self) -> Result<Swept> {
        self.sweep_chunks_at(now())
    }

    pub(super) fn sweep_chunks_at(&mut self, now: i64) -> Result<Swept> {
        let due: Vec<Vec<u8>> = {
            let mut statement = self.conn.prepare(
                "SELECT chunk_id FROM chunks
                 WHERE unreferenced IS NOT NULL AND unreferenced <= ?1
                 ORDER BY unreferenced LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![now - CHUNK_RETENTION_SECS, SWEEP_BATCH as i64 + 1],
                    |row| row.get(0),
                )?
                .collect::<rusqlite::Result<_>>()?
        };
        let more = due.len() > SWEEP_BATCH;
        let due = &due[..due.len().min(SWEEP_BATCH)];
        // The files first: a row left after a crash is swept again, a file left without its row
        // never would be.
        for id in due {
            let id: ChunkId = id
                .as_slice()
                .try_into()
                .map_err(|_| Error::Corrupt("chunk id"))?;
            match fs::remove_file(self.chunk_path(&id)) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        for id in due {
            tx.execute("DELETE FROM chunks WHERE chunk_id = ?1", [id])?;
        }
        tx.commit()?;
        if !more {
            self.dropped.store(false, Ordering::Relaxed);
        }
        Ok(Swept {
            deleted: due.len(),
            more,
        })
    }

    /// Checks that this device holds every chunk `manifest` names, sealed in `collection` under
    /// the epoch it says, before a record names them.
    pub(super) fn check_chunks(
        &self,
        collection: CollectionId,
        epoch: u32,
        manifest: &Manifest,
    ) -> Result<()> {
        let Content::Chunks {
            epoch: sealed_under,
            ids,
        } = &manifest.content
        else {
            return Ok(());
        };
        if *sealed_under > epoch {
            return Err(Error::InvalidManifest(
                "its chunks are sealed under a later key",
            ));
        }
        let mut statement = self
            .conn
            .prepare_cached("SELECT collection_id, epoch FROM chunks WHERE chunk_id = ?1")?;
        let mut checked = HashSet::with_capacity(ids.len());
        for id in ids {
            if !checked.insert(id) {
                continue;
            }
            let row: Option<(Vec<u8>, u32)> = statement
                .query_row([&id[..]], |row| Ok((row.get(0)?, row.get(1)?)))
                .optional()?;
            let held = row.is_some_and(|(held_in, held_epoch)| {
                held_in == collection.as_bytes() && held_epoch == *sealed_under
            });
            if !held || !self.chunk_path(id).exists() {
                return Err(Error::ChunkMissing(*id));
            }
        }
        Ok(())
    }

    /// Records which chunks the current version of `tag` names: none for anything but a file.
    /// A chunk named again stops being unreferenced, and one no current version names any more
    /// starts its 30 days.
    pub(super) fn set_file_chunks(
        &self,
        tx: &Transaction<'_>,
        collection: CollectionId,
        tag: &[u8],
        chunks: &[ChunkId],
    ) -> Result<()> {
        let old: Vec<Vec<u8>> = {
            let mut statement = tx.prepare_cached(
                "SELECT chunk_id FROM file_chunks WHERE collection_id = ?1 AND name_tag = ?2",
            )?;
            statement
                .query_map(params![&collection.as_bytes()[..], tag], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        if old.is_empty() && chunks.is_empty() {
            return Ok(());
        }
        tx.execute(
            "DELETE FROM file_chunks WHERE collection_id = ?1 AND name_tag = ?2",
            params![&collection.as_bytes()[..], tag],
        )?;
        for id in chunks {
            tx.execute(
                "INSERT OR IGNORE INTO file_chunks VALUES (?1, ?2, ?3)",
                params![&collection.as_bytes()[..], tag, &id[..]],
            )?;
            tx.execute(
                "UPDATE chunks SET unreferenced = NULL
                 WHERE chunk_id = ?1 AND unreferenced IS NOT NULL",
                [&id[..]],
            )?;
        }
        let now = now();
        for id in old {
            if chunks.iter().any(|kept| kept[..] == id[..]) {
                continue;
            }
            let dropped = tx.execute(
                "UPDATE chunks SET unreferenced = ?2 WHERE chunk_id = ?1 AND unreferenced IS NULL
                 AND NOT EXISTS (SELECT 1 FROM file_chunks WHERE chunk_id = ?1)",
                params![&id[..], now],
            )?;
            if dropped > 0 {
                self.dropped.store(true, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    pub(super) fn chunk_path(&self, id: &ChunkId) -> PathBuf {
        let name = hex::encode(id);
        self.chunks.join(&name[..2]).join(name)
    }

    /// Writes under a temporary name and renames, so a chunk's own name only ever holds all of
    /// it. Synced first, since a manifest that names it may be committed right after.
    fn write_chunk_file(&self, path: &std::path::Path, sealed: &[u8]) -> Result<()> {
        let dir = path.parent().expect("chunks are in a directory");
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir)?;
        let temporary = dir.join(format!(
            ".{}.{}",
            hex::encode(&openvault_crypto::random_bytes::<8>()[..]),
            "partial"
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let result = (|| {
            let mut file = options.open(&temporary)?;
            file.write_all(sealed)?;
            file.sync_all()?;
            fs::rename(&temporary, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        Ok(result?)
    }
}

/// The chunks a body names, for [`Vault::set_file_chunks`]: none unless it's a file that isn't
/// deleted. The body was checked when it was sealed or opened, so it decodes.
pub(super) fn named_chunks(kind: Kind, deleted: bool, value: &[u8]) -> Vec<ChunkId> {
    if kind != Kind::File || deleted {
        return Vec::new();
    }
    Manifest::decode(value)
        .map(|manifest| manifest.chunks().to_vec())
        .unwrap_or_default()
}

/// Seconds since 1970.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}
