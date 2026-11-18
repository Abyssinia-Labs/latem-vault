//! The coordinator's copy of the membership log, in `coordinator.db` (coordinator.md, storage).

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::path::Path;

use latem_vault_core::membership::{LogEntry, Membership};
use latem_vault_core::{Error, Result, VaultId};
use latem_vault_crypto::hash::Hash;
use latem_vault_net::EndpointKey;
use rusqlite::{Connection, OptionalExtension, params};

const SCHEMA: &str = "
CREATE TABLE vault (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    vault_id BLOB NOT NULL,
    membership BLOB
);
CREATE TABLE log (seq INTEGER PRIMARY KEY, entry BLOB NOT NULL);
PRAGMA user_version = 1;
";

pub(crate) struct Store {
    conn: Connection,
    vault: VaultId,
    /// What the log describes after its last entry; `None` until a device gives it genesis.
    membership: Option<Membership>,
}

impl Store {
    /// Opens the store at `path`, creating it for `vault` if there's none. A store keeps the
    /// vault it was created for: naming another is an error.
    pub(crate) fn open(path: &Path, vault: Option<VaultId>) -> anyhow::Result<Self> {
        let new = !path.exists();
        if new {
            let Some(vault) = vault else {
                anyhow::bail!("there's no coordinator here yet; name its vault with --vault");
            };
            create_file(path)?;
            let conn = Connection::open(path)?;
            conn.execute_batch(SCHEMA)?;
            conn.execute(
                "INSERT INTO vault (one, vault_id) VALUES (1, ?1)",
                [&vault.as_bytes()[..]],
            )?;
            return Ok(Self {
                conn,
                vault,
                membership: None,
            });
        }
        let conn = Connection::open(path)?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version != 1 {
            return Err(Error::UnsupportedStore(version).into());
        }
        let (id, state): (Vec<u8>, Option<Vec<u8>>) =
            conn.query_row("SELECT vault_id, membership FROM vault", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
        let stored =
            VaultId::from_bytes(id.try_into().map_err(|_| Error::Corrupt("the vault id"))?);
        if let Some(vault) = vault
            && vault != stored
        {
            anyhow::bail!(
                "this coordinator is for vault {stored}, not {vault}; give it another data \
                 directory"
            );
        }
        let membership = state
            .map(|state| Membership::from_state_bytes(&state))
            .transpose()?;
        Ok(Self {
            conn,
            vault: stored,
            membership,
        })
    }

    pub(crate) fn vault(&self) -> VaultId {
        self.vault
    }

    /// The last entry's `seq` and hash, if it has a log.
    pub(crate) fn head(&self) -> Option<(u64, Hash)> {
        self.membership.as_ref().map(Membership::head)
    }

    /// The transport keys of the devices in the log that aren't revoked.
    pub(crate) fn members(&self) -> HashSet<EndpointKey> {
        let Some(membership) = &self.membership else {
            return HashSet::new();
        };
        membership
            .devices()
            .filter(|device| !device.revoked && device.info.transport_key.is_ed25519())
            .filter_map(|device| device.info.transport_key.as_bytes()[1..].try_into().ok())
            .collect()
    }

    /// Entries from `from`, at most `max` of them.
    pub(crate) fn log_from(&self, from: u64, max: u16) -> Result<Vec<LogEntry>> {
        let from = i64::try_from(from).unwrap_or(i64::MAX);
        let mut statement = self
            .conn
            .prepare_cached("SELECT entry FROM log WHERE seq >= ?1 ORDER BY seq LIMIT ?2")?;
        let rows = statement.query_map(params![from, max], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|entry| LogEntry::from_bytes(&entry?)).collect()
    }

    /// Checks `entries`, in order, as a device does (membership.md, accepting an entry), and
    /// keeps the ones past the head. Returns how many were new. Entries it already has must be
    /// the same; a different one that would also have been accepted is a fork.
    pub(crate) fn append(&mut self, entries: &[LogEntry]) -> Result<usize> {
        let head = self.head().map(|(seq, _)| seq);
        let mut new = Vec::new();
        for entry in entries {
            match head {
                Some(head) if entry.seq() <= head => self.check_known(entry)?,
                _ => new.push(entry),
            }
        }
        let Some((first, rest)) = new.split_first() else {
            return Ok(0);
        };
        let (mut membership, rest) = match &self.membership {
            Some(membership) => (membership.clone(), &new[..]),
            None => {
                let membership = Membership::from_genesis(first)?;
                if membership.vault() != self.vault {
                    return Err(Error::InvalidLogEntry("the genesis is another vault's"));
                }
                (membership, rest)
            }
        };
        for entry in rest {
            membership.apply(entry)?;
        }
        let tx = self.conn.unchecked_transaction()?;
        for entry in &new {
            let seq = i64::try_from(entry.seq()).map_err(|_| Error::Corrupt("log sequence"))?;
            tx.execute(
                "INSERT INTO log VALUES (?1, ?2)",
                params![seq, entry.to_bytes()],
            )?;
        }
        tx.execute(
            "UPDATE vault SET membership = ?1",
            [membership.to_state_bytes()],
        )?;
        tx.commit()?;
        self.membership = Some(membership);
        Ok(new.len())
    }

    /// Checks an entry at or before the head is the one kept.
    fn check_known(&self, entry: &LogEntry) -> Result<()> {
        let seq = i64::try_from(entry.seq()).map_err(|_| Error::Corrupt("log sequence"))?;
        let own: Vec<u8> = self
            .conn
            .query_row("SELECT entry FROM log WHERE seq = ?1", [seq], |row| {
                row.get(0)
            })
            .optional()?
            .ok_or(Error::Corrupt("a missing log entry"))?;
        let own = LogEntry::from_bytes(&own)?;
        if own.hash() == entry.hash() {
            return Ok(());
        }
        // Rare, so the log up to this entry is read whole, as a device does.
        let mut statement = self
            .conn
            .prepare("SELECT entry FROM log WHERE seq <= ?1 ORDER BY seq")?;
        let log = statement
            .query_map([seq], |row| row.get::<_, Vec<u8>>(0))?
            .map(|entry| LogEntry::from_bytes(&entry?))
            .collect::<Result<Vec<_>>>()?;
        Err(if Membership::is_fork(&log, entry)? {
            Error::Fork
        } else {
            Error::InvalidLogEntry("it differs from the coordinator's entry")
        })
    }
}

/// Creates the database file, so it is never readable by others, even briefly.
fn create_file(path: &Path) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path).map(drop)
}
