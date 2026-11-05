//! The membership log (membership.md): admins, devices, scopes and key epochs, as a chain of
//! admin-signed entries.
//!
//! [`Membership`] is the state after a run of entries. It checks each new entry against that
//! state before applying it, so it never holds a state the log doesn't justify.

use std::collections::HashMap;

use openvault_crypto::hash::{self, Hash, contexts};
use openvault_crypto::{Signature, SignatureContext, SigningKey, VerifyingKey, WrapKey};

use crate::{CollectionId, DeviceId, Error, Result, VaultId};

const FORMAT: u8 = 0x01;
const SIGNATURE_LEN: usize = 65;
pub const MAX_PAYLOAD_LEN: usize = 1024;
pub const MAX_ADMINS: usize = 8;
const MAX_PLATFORM_LEN: usize = 16;
pub const MAX_NAME_LEN: usize = 64;

const GENESIS: u8 = 0x01;
const ADD_DEVICE: u8 = 0x02;
const SET_SCOPE: u8 = 0x03;
const REVOKE_DEVICE: u8 = 0x04;
const ROTATE_EPOCH: u8 = 0x05;
const ADD_ADMIN: u8 = 0x06;
const REMOVE_ADMIN: u8 = 0x07;

/// What a device may do with a collection (design §3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    #[default]
    None,
    /// Store and serve the ciphertext, without the key.
    Hold,
    Read,
    Write,
}

impl Scope {
    fn code(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::Hold => 0x01,
            Self::Read => 0x02,
            Self::Write => 0x03,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(Self::None),
            0x01 => Some(Self::Hold),
            0x02 => Some(Self::Read),
            0x03 => Some(Self::Write),
            _ => None,
        }
    }
}

/// A device's description and public keys, as add_device records them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub id: DeviceId,
    /// Verifies the device's records.
    pub verifying_key: VerifyingKey,
    /// What collection keys are wrapped to for this device.
    pub wrap_key: WrapKey,
    /// The device's Ed25519 iroh identity.
    pub transport_key: VerifyingKey,
    /// Such as `macos`. Shown to people only.
    pub platform: String,
    /// Such as `MacBook`.
    pub name: String,
}

impl DeviceInfo {
    /// The add_device payload. Call [`Change::check_fields`] first.
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(self.verifying_key.as_bytes());
        out.extend_from_slice(self.wrap_key.as_bytes());
        out.extend_from_slice(self.transport_key.as_bytes());
        for text in [&self.platform, &self.name] {
            out.push(u8::try_from(text.len()).expect("checked against the limits"));
            out.extend_from_slice(text.as_bytes());
        }
    }
}

/// One change to the membership: a log entry's type and payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Genesis {
        recovery: WrapKey,
        admins: Vec<VerifyingKey>,
    },
    AddDevice(DeviceInfo),
    SetScope {
        device: DeviceId,
        collection: CollectionId,
        scope: Scope,
    },
    RevokeDevice(DeviceId),
    RotateEpoch {
        collection: CollectionId,
        epoch: u32,
    },
    AddAdmin(VerifyingKey),
    RemoveAdmin(VerifyingKey),
}

impl Change {
    /// The type code and payload. Call [`check_fields`](Self::check_fields) first.
    fn encode(&self) -> (u8, Vec<u8>) {
        let mut out = Vec::new();
        let code = match self {
            Self::Genesis { recovery, admins } => {
                out.extend_from_slice(recovery.as_bytes());
                out.push(u8::try_from(admins.len()).expect("checked against MAX_ADMINS"));
                for admin in admins {
                    out.extend_from_slice(admin.as_bytes());
                }
                GENESIS
            }
            Self::AddDevice(info) => {
                info.encode(&mut out);
                ADD_DEVICE
            }
            Self::SetScope {
                device,
                collection,
                scope,
            } => {
                out.extend_from_slice(device.as_bytes());
                out.extend_from_slice(collection.as_bytes());
                out.push(scope.code());
                SET_SCOPE
            }
            Self::RevokeDevice(device) => {
                out.extend_from_slice(device.as_bytes());
                REVOKE_DEVICE
            }
            Self::RotateEpoch { collection, epoch } => {
                out.extend_from_slice(collection.as_bytes());
                out.extend_from_slice(&epoch.to_be_bytes());
                ROTATE_EPOCH
            }
            Self::AddAdmin(key) => {
                out.extend_from_slice(key.as_bytes());
                ADD_ADMIN
            }
            Self::RemoveAdmin(key) => {
                out.extend_from_slice(key.as_bytes());
                REMOVE_ADMIN
            }
        };
        (code, out)
    }

    fn decode(code: u8, payload: &[u8]) -> Result<Self> {
        let mut r = Reader(payload);
        let change = match code {
            GENESIS => {
                let recovery = r.wrap_key()?;
                let count = r.u8()?;
                let admins = (0..count)
                    .map(|_| r.verifying_key())
                    .collect::<Result<_>>()?;
                Self::Genesis { recovery, admins }
            }
            ADD_DEVICE => Self::AddDevice(r.device_info()?),
            SET_SCOPE => {
                let device = DeviceId::from_bytes(r.array()?);
                let collection = CollectionId::from_bytes(r.array()?);
                let scope = Scope::from_code(r.u8()?).ok_or(invalid("unknown scope"))?;
                Self::SetScope {
                    device,
                    collection,
                    scope,
                }
            }
            REVOKE_DEVICE => Self::RevokeDevice(DeviceId::from_bytes(r.array()?)),
            ROTATE_EPOCH => {
                let collection = CollectionId::from_bytes(r.array()?);
                let epoch = u32::from_be_bytes(r.array()?);
                Self::RotateEpoch { collection, epoch }
            }
            ADD_ADMIN => Self::AddAdmin(r.verifying_key()?),
            REMOVE_ADMIN => Self::RemoveAdmin(r.verifying_key()?),
            _ => return Err(invalid("unknown entry type")),
        };
        r.finish()?;
        change.check_fields()?;
        Ok(change)
    }

    /// Checks what doesn't depend on the log: counts, lengths and key types.
    fn check_fields(&self) -> Result<()> {
        let result = match self {
            Self::Genesis { admins, .. } if admins.is_empty() || admins.len() > MAX_ADMINS => {
                Err("a vault has 1 to 8 admins")
            }
            Self::Genesis { admins, .. }
                if admins
                    .iter()
                    .enumerate()
                    .any(|(i, admin)| admins[..i].contains(admin)) =>
            {
                Err("an admin is listed twice")
            }
            Self::AddDevice(info) if !info.transport_key.is_ed25519() => {
                Err("the transport key must be Ed25519")
            }
            Self::AddDevice(info)
                if info.platform.is_empty()
                    || info.platform.len() > MAX_PLATFORM_LEN
                    || !info
                        .platform
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) =>
            {
                Err("the platform must be 1 to 16 of a-z and 0-9")
            }
            Self::AddDevice(info)
                if info.name.is_empty()
                    || info.name.len() > MAX_NAME_LEN
                    || info.name.chars().any(char::is_control) =>
            {
                Err("the device name must be 1 to 64 bytes with no control characters")
            }
            _ => Ok(()),
        };
        result.map_err(Error::InvalidLogEntry)
    }
}

/// A key that signs log entries as an admin: the recovery key's admin key, or a device's admin
/// key in its keystore.
pub trait AdminKey {
    fn verifying_key(&self) -> VerifyingKey;
    fn sign(&self, context: SignatureContext, message: &[u8]) -> Result<Signature>;
}

impl AdminKey for SigningKey {
    fn verifying_key(&self) -> VerifyingKey {
        SigningKey::verifying_key(self)
    }

    fn sign(&self, context: SignatureContext, message: &[u8]) -> Result<Signature> {
        Ok(SigningKey::sign(self, context, message))
    }
}

/// A signed log entry, as stored and synced: the unsigned part, then the signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    vault: VaultId,
    seq: u64,
    prev: Hash,
    signer: VerifyingKey,
    change: Change,
    unsigned: Vec<u8>,
    signature: Signature,
}

impl LogEntry {
    fn sign(
        vault: VaultId,
        seq: u64,
        prev: Hash,
        change: Change,
        admin: &impl AdminKey,
    ) -> Result<Self> {
        change.check_fields()?;
        let signer = admin.verifying_key();
        let (code, payload) = change.encode();
        let payload_len = u32::try_from(payload.len()).expect("fields are bounded");
        let unsigned = [
            &[FORMAT][..],
            vault.as_bytes(),
            &seq.to_be_bytes(),
            &prev,
            signer.as_bytes(),
            &[code],
            &payload_len.to_be_bytes(),
            &payload,
        ]
        .concat();
        let signature = admin.sign(SignatureContext::LogEntry, &unsigned)?;
        Ok(Self {
            vault,
            seq,
            prev,
            signer,
            change,
            unsigned,
            signature,
        })
    }

    /// Parses an entry. Its signature and place in the chain are checked by [`Membership`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let unsigned_len = bytes
            .len()
            .checked_sub(SIGNATURE_LEN)
            .ok_or(invalid("too short"))?;
        let (unsigned, signature) = bytes.split_at(unsigned_len);
        let mut r = Reader(unsigned);
        if r.u8()? != FORMAT {
            return Err(invalid("unknown format"));
        }
        let vault = VaultId::from_bytes(r.array()?);
        let seq = u64::from_be_bytes(r.array()?);
        let prev = r.array()?;
        let signer = r.verifying_key()?;
        let code = r.u8()?;
        let payload_len = u32::from_be_bytes(r.array()?) as usize;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(invalid("payload too large"));
        }
        let payload = r.take(payload_len)?;
        r.finish()?;
        Ok(Self {
            vault,
            seq,
            prev,
            signer,
            change: Change::decode(code, payload)?,
            unsigned: unsigned.to_vec(),
            signature: Signature::from_bytes(signature)?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.unsigned[..], self.signature.as_bytes()].concat()
    }

    /// Covers the unsigned part only, never the signature (crypto.md, signatures).
    pub fn hash(&self) -> Hash {
        *hash::derive_key(contexts::LOG_ENTRY_HASH, &self.unsigned)
    }

    pub fn vault(&self) -> VaultId {
        self.vault
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn signer(&self) -> &VerifyingKey {
        &self.signer
    }

    pub fn change(&self) -> &Change {
        &self.change
    }

    fn verify_signature(&self) -> Result<()> {
        self.signer
            .verify(SignatureContext::LogEntry, &self.unsigned, &self.signature)?;
        Ok(())
    }
}

/// A device in the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub info: DeviceInfo,
    pub revoked: bool,
}

/// The membership a log describes, after its entries so far.
#[derive(Clone, Debug)]
pub struct Membership {
    vault: VaultId,
    genesis: Hash,
    seq: u64,
    head: Hash,
    recovery: WrapKey,
    admins: Vec<VerifyingKey>,
    devices: HashMap<DeviceId, Device>,
    scopes: HashMap<(DeviceId, CollectionId), Scope>,
    epochs: HashMap<CollectionId, u32>,
}

impl Membership {
    /// Starts a new vault's log with a genesis entry signed by `admin`, which must be one of
    /// `admins`.
    pub fn create(
        vault: VaultId,
        recovery: WrapKey,
        admins: Vec<VerifyingKey>,
        admin: &impl AdminKey,
    ) -> Result<(Self, LogEntry)> {
        if !admins.contains(&admin.verifying_key()) {
            return Err(invalid("signer isn't an admin"));
        }
        let entry = LogEntry::sign(
            vault,
            0,
            [0; 32],
            Change::Genesis { recovery, admins },
            admin,
        )?;
        Ok((Self::from_genesis(&entry)?, entry))
    }

    /// Starts from a genesis entry, after checking it.
    pub fn from_genesis(entry: &LogEntry) -> Result<Self> {
        let Change::Genesis { recovery, admins } = &entry.change else {
            return Err(invalid("the first entry isn't genesis"));
        };
        if entry.seq != 0 || entry.prev != [0; 32] {
            return Err(invalid("genesis isn't first"));
        }
        if !admins.contains(&entry.signer) {
            return Err(invalid("signer isn't an admin"));
        }
        entry.verify_signature()?;
        let hash = entry.hash();
        Ok(Self {
            vault: entry.vault,
            genesis: hash,
            seq: 0,
            head: hash,
            recovery: recovery.clone(),
            admins: admins.clone(),
            devices: HashMap::new(),
            scopes: HashMap::new(),
            epochs: HashMap::new(),
        })
    }

    /// Checks a whole log, from genesis, and returns the membership it describes.
    pub fn replay<'a>(entries: impl IntoIterator<Item = &'a LogEntry>) -> Result<Self> {
        let mut entries = entries.into_iter();
        let genesis = entries.next().ok_or(invalid("the log is empty"))?;
        let mut membership = Self::from_genesis(genesis)?;
        for entry in entries {
            membership.apply(entry)?;
        }
        Ok(membership)
    }

    /// Checks `entry` as the next one in the log, then applies it.
    pub fn apply(&mut self, entry: &LogEntry) -> Result<()> {
        if entry.vault != self.vault {
            return Err(invalid("the entry is from another vault"));
        }
        if self.seq.checked_add(1) != Some(entry.seq) || entry.prev != self.head {
            return Err(invalid("the entry doesn't follow the last one"));
        }
        if !self.admins.contains(&entry.signer) {
            return Err(invalid("signer isn't an admin"));
        }
        entry.verify_signature()?;
        self.check(&entry.change)?;
        self.change(&entry.change);
        self.seq = entry.seq;
        self.head = entry.hash();
        Ok(())
    }

    /// Signs `change` with `admin` as the next entry, and applies it. The change is checked
    /// first, so an admin is never asked to sign an entry that would be rejected.
    pub fn append(&mut self, change: Change, admin: &impl AdminKey) -> Result<LogEntry> {
        if !self.admins.contains(&admin.verifying_key()) {
            return Err(invalid("signer isn't an admin"));
        }
        change.check_fields()?;
        self.check(&change)?;
        let seq = self.seq.checked_add(1).ok_or(invalid("the log is full"))?;
        let entry = LogEntry::sign(self.vault, seq, self.head, change, admin)?;
        self.apply(&entry)?;
        Ok(entry)
    }

    /// Whether `candidate` forks `log`, a device's own entries from genesis: it has a `seq`
    /// the log already has, a different hash, and would have been accepted in that place.
    ///
    /// A different genesis isn't a fork but another vault, since anyone can sign one.
    pub fn is_fork(log: &[LogEntry], candidate: &LogEntry) -> Result<bool> {
        let Some(seq) = usize::try_from(candidate.seq).ok().filter(|&seq| seq > 0) else {
            return Ok(false);
        };
        match log.get(seq) {
            Some(own) if own.hash() != candidate.hash() => {
                let mut before = Self::replay(&log[..seq])?;
                Ok(before.apply(candidate).is_ok())
            }
            _ => Ok(false),
        }
    }

    pub fn vault(&self) -> VaultId {
        self.vault
    }

    /// The genesis entry's hash, which identifies the vault in joins.
    pub fn genesis_hash(&self) -> Hash {
        self.genesis
    }

    /// The last entry's `seq` and hash.
    pub fn head(&self) -> (u64, Hash) {
        (self.seq, self.head)
    }

    /// The key every collection key is also wrapped to.
    pub fn recovery_key(&self) -> &WrapKey {
        &self.recovery
    }

    pub fn admins(&self) -> &[VerifyingKey] {
        &self.admins
    }

    pub fn device(&self, id: DeviceId) -> Option<&Device> {
        self.devices.get(&id)
    }

    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }

    /// What `device` may do with `collection`. Unknown and revoked devices have no scope.
    pub fn scope(&self, device: DeviceId, collection: CollectionId) -> Scope {
        self.scopes
            .get(&(device, collection))
            .copied()
            .unwrap_or_default()
    }

    /// The collection's current key epoch, or `None` if no set_scope has named it.
    pub fn epoch(&self, collection: CollectionId) -> Option<u32> {
        self.epochs.get(&collection).copied()
    }

    /// The state as bytes, which a device keeps next to its log so that opening a vault
    /// doesn't replay it (membership.md, keeping the log). Only the device that wrote it reads
    /// it back, so it isn't signed, and [`from_state_bytes`](Self::from_state_bytes) trusts it.
    pub fn to_state_bytes(&self) -> Vec<u8> {
        let mut out = [
            &self.vault.as_bytes()[..],
            &self.genesis,
            &self.seq.to_be_bytes(),
            &self.head,
            self.recovery.as_bytes(),
        ]
        .concat();
        out.push(u8::try_from(self.admins.len()).expect("checked against MAX_ADMINS"));
        for admin in &self.admins {
            out.extend_from_slice(admin.as_bytes());
        }

        // Sorted, so the same state is always the same bytes.
        let mut devices: Vec<&Device> = self.devices.values().collect();
        devices.sort_by_key(|device| device.info.id);
        push_count(&mut out, devices.len());
        for device in devices {
            device.info.encode(&mut out);
            out.push(u8::from(device.revoked));
        }
        let mut scopes: Vec<_> = self.scopes.iter().collect();
        scopes.sort();
        push_count(&mut out, scopes.len());
        for ((device, collection), scope) in scopes {
            out.extend_from_slice(device.as_bytes());
            out.extend_from_slice(collection.as_bytes());
            out.push(scope.code());
        }
        let mut epochs: Vec<_> = self.epochs.iter().collect();
        epochs.sort();
        push_count(&mut out, epochs.len());
        for (collection, epoch) in epochs {
            out.extend_from_slice(collection.as_bytes());
            out.extend_from_slice(&epoch.to_be_bytes());
        }
        out
    }

    pub fn from_state_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        let vault = VaultId::from_bytes(r.array()?);
        let genesis = r.array()?;
        let seq = u64::from_be_bytes(r.array()?);
        let head = r.array()?;
        let recovery = r.wrap_key()?;
        let admins = (0..r.u8()?)
            .map(|_| r.verifying_key())
            .collect::<Result<_>>()?;
        let devices = (0..r.u32()?)
            .map(|_| {
                let info = r.device_info()?;
                let revoked = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(invalid("unknown revoked flag")),
                };
                Ok((info.id, Device { info, revoked }))
            })
            .collect::<Result<_>>()?;
        let scopes = (0..r.u32()?)
            .map(|_| {
                let device = DeviceId::from_bytes(r.array()?);
                let collection = CollectionId::from_bytes(r.array()?);
                let scope = Scope::from_code(r.u8()?).ok_or(invalid("unknown scope"))?;
                Ok(((device, collection), scope))
            })
            .collect::<Result<_>>()?;
        let epochs = (0..r.u32()?)
            .map(|_| Ok((CollectionId::from_bytes(r.array()?), r.u32()?)))
            .collect::<Result<_>>()?;
        r.finish()?;
        Ok(Self {
            vault,
            genesis,
            seq,
            head,
            recovery,
            admins,
            devices,
            scopes,
            epochs,
        })
    }

    /// The rules for each type that depend on the log so far (membership.md).
    fn check(&self, change: &Change) -> Result<()> {
        let device = |id: &DeviceId| match self.devices.get(id) {
            None => Err("no such device"),
            Some(device) if device.revoked => Err("the device is revoked"),
            Some(device) => Ok(device),
        };
        let result = match change {
            Change::Genesis { .. } => Err("genesis isn't first"),
            Change::AddDevice(info) if self.devices.contains_key(&info.id) => {
                Err("the device id is taken")
            }
            Change::AddDevice(info)
                if self.devices.values().any(|d| {
                    d.info.verifying_key == info.verifying_key
                        || d.info.wrap_key == info.wrap_key
                        || d.info.transport_key == info.transport_key
                }) =>
            {
                Err("another device has the same keys")
            }
            Change::AddDevice(_) => Ok(()),
            Change::SetScope {
                device: id,
                collection,
                scope,
            } => device(id).and_then(|_| {
                if self.scope(*id, *collection) == *scope {
                    Err("the scope is unchanged")
                } else {
                    Ok(())
                }
            }),
            Change::RevokeDevice(id) => device(id).map(|_| ()),
            Change::RotateEpoch { collection, epoch } => match self.epoch(*collection) {
                None => Err("no such collection"),
                Some(current) if current.checked_add(1) != Some(*epoch) => {
                    Err("the epoch isn't the next one")
                }
                Some(_) => Ok(()),
            },
            Change::AddAdmin(key) if self.admins.contains(key) => Err("already an admin"),
            Change::AddAdmin(_) if self.admins.len() >= MAX_ADMINS => Err("too many admins"),
            Change::AddAdmin(_) => Ok(()),
            Change::RemoveAdmin(key) if !self.admins.contains(key) => Err("not an admin"),
            Change::RemoveAdmin(_) if self.admins.len() == 1 => {
                Err("the last admin can't be removed")
            }
            Change::RemoveAdmin(_) => Ok(()),
        };
        result.map_err(Error::InvalidLogEntry)
    }

    /// Applies a change that [`check`](Self::check) has accepted.
    fn change(&mut self, change: &Change) {
        match change {
            Change::Genesis { .. } => unreachable!("check rejects genesis after the first entry"),
            Change::AddDevice(info) => {
                self.devices.insert(
                    info.id,
                    Device {
                        info: info.clone(),
                        revoked: false,
                    },
                );
            }
            Change::SetScope {
                device,
                collection,
                scope,
            } => {
                self.epochs.entry(*collection).or_insert(0);
                if *scope == Scope::None {
                    self.scopes.remove(&(*device, *collection));
                } else {
                    self.scopes.insert((*device, *collection), *scope);
                }
            }
            Change::RevokeDevice(id) => {
                self.devices.get_mut(id).expect("checked").revoked = true;
                self.scopes.retain(|(device, _), _| device != id);
            }
            Change::RotateEpoch { collection, epoch } => {
                self.epochs.insert(*collection, *epoch);
            }
            Change::AddAdmin(key) => self.admins.push(key.clone()),
            Change::RemoveAdmin(key) => self.admins.retain(|admin| admin != key),
        }
    }
}

const fn invalid(reason: &'static str) -> Error {
    Error::InvalidLogEntry(reason)
}

fn push_count(out: &mut Vec<u8>, count: usize) {
    out.extend_from_slice(&u32::try_from(count).expect("fewer than 2^32").to_be_bytes());
}

/// Reads an entry's fields in order.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(len).ok_or(invalid("too short"))?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(invalid("too short"))?;
        self.0 = rest;
        Ok(*head)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn verifying_key(&mut self) -> Result<VerifyingKey> {
        let (key, rest) = VerifyingKey::split_prefix(self.0)?;
        self.0 = rest;
        Ok(key)
    }

    fn wrap_key(&mut self) -> Result<WrapKey> {
        let (key, rest) = WrapKey::split_prefix(self.0)?;
        self.0 = rest;
        Ok(key)
    }

    fn device_info(&mut self) -> Result<DeviceInfo> {
        let id = DeviceId::from_bytes(self.array()?);
        let verifying_key = self.verifying_key()?;
        let wrap_key = self.wrap_key()?;
        let transport_key = self.verifying_key()?;
        let platform = self.short_text()?;
        let name = self.short_text()?;
        Ok(DeviceInfo {
            id,
            verifying_key,
            wrap_key,
            transport_key,
            platform,
            name,
        })
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// A `u8` length, then that many bytes of UTF-8.
    fn short_text(&mut self) -> Result<String> {
        let len = self.u8()?;
        let bytes = self.take(len.into())?;
        String::from_utf8(bytes.to_vec()).map_err(|_| invalid("text isn't UTF-8"))
    }

    fn finish(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(invalid("trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use openvault_crypto::{RecoveryKey, UnwrapKey};

    use super::*;

    fn device(name: &str) -> DeviceInfo {
        DeviceInfo {
            id: DeviceId::random(),
            verifying_key: SigningKey::generate_p256().verifying_key(),
            wrap_key: UnwrapKey::generate_p256().wrap_key(),
            transport_key: SigningKey::generate_ed25519().verifying_key(),
            platform: "macos".into(),
            name: name.into(),
        }
    }

    /// A new vault with one admin, and its log so far.
    fn vault() -> (SigningKey, Membership, Vec<LogEntry>) {
        let admin = SigningKey::generate_ed25519();
        let (membership, genesis) = Membership::create(
            VaultId::random(),
            UnwrapKey::generate_x25519().wrap_key(),
            vec![admin.verifying_key()],
            &admin,
        )
        .unwrap();
        (admin, membership, vec![genesis])
    }

    fn rejected(result: Result<impl std::fmt::Debug>) -> &'static str {
        match result {
            Err(Error::InvalidLogEntry(reason)) => reason,
            other => panic!("expected an invalid entry, got {other:?}"),
        }
    }

    #[test]
    fn devices_scopes_and_epochs() {
        let (admin, mut m, mut log) = vault();
        let (mac, phone) = (device("MacBook"), device("iPhone"));
        let c = CollectionId::random();
        for change in [
            Change::AddDevice(mac.clone()),
            Change::AddDevice(phone.clone()),
            Change::SetScope {
                device: mac.id,
                collection: c,
                scope: Scope::Write,
            },
            Change::SetScope {
                device: phone.id,
                collection: c,
                scope: Scope::Read,
            },
            Change::RotateEpoch {
                collection: c,
                epoch: 1,
            },
            Change::RevokeDevice(phone.id),
        ] {
            log.push(m.append(change, &admin).unwrap());
        }

        assert_eq!(m.head().0, 6);
        assert_eq!(m.scope(mac.id, c), Scope::Write);
        assert_eq!(m.scope(phone.id, c), Scope::None);
        assert!(m.device(phone.id).unwrap().revoked);
        assert_eq!(m.device(mac.id).unwrap().info, mac);
        assert_eq!(m.epoch(c), Some(1));
        assert_eq!(m.epoch(CollectionId::random()), None);

        // Another device rebuilds the same membership from the bytes alone.
        let received: Vec<LogEntry> = log
            .iter()
            .map(|entry| LogEntry::from_bytes(&entry.to_bytes()).unwrap())
            .collect();
        assert_eq!(received, log);
        let rebuilt = Membership::replay(&received).unwrap();
        assert_eq!(rebuilt.head(), m.head());
        assert_eq!(rebuilt.genesis_hash(), log[0].hash());
        assert_eq!(rebuilt.scope(mac.id, c), Scope::Write);
        assert!(rebuilt.device(phone.id).unwrap().revoked);
        assert_eq!(rebuilt.to_state_bytes(), m.to_state_bytes());

        // The kept state restores the same membership without the log.
        let state = m.to_state_bytes();
        let restored = Membership::from_state_bytes(&state).unwrap();
        assert_eq!(restored.to_state_bytes(), state);
        assert_eq!(restored.scope(mac.id, c), Scope::Write);
        assert_eq!(restored.epoch(c), Some(1));
        assert!(Membership::from_state_bytes(&state[..state.len() - 1]).is_err());
        assert!(Membership::from_state_bytes(&[&state[..], &[0]].concat()).is_err());
    }

    #[test]
    fn rejects_changes_that_break_the_rules() {
        let (admin, mut m, _) = vault();
        let (mac, revoked) = (device("MacBook"), device("old"));
        let c = CollectionId::random();
        for change in [
            Change::AddDevice(mac.clone()),
            Change::AddDevice(revoked.clone()),
            Change::SetScope {
                device: mac.id,
                collection: c,
                scope: Scope::Write,
            },
            Change::RevokeDevice(revoked.id),
        ] {
            m.append(change, &admin).unwrap();
        }
        let head = m.head();

        let mut reused = device("copy");
        reused.wrap_key = revoked.wrap_key.clone();
        let mut p256_transport = device("x");
        p256_transport.transport_key = SigningKey::generate_p256().verifying_key();
        let mut platform = device("x");
        platform.platform = "macOS".into();
        let mut name = device("x");
        name.name = "line\nbreak".into();
        let scope = |device, scope| Change::SetScope {
            device,
            collection: c,
            scope,
        };
        let cases = [
            (
                Change::Genesis {
                    recovery: UnwrapKey::generate_x25519().wrap_key(),
                    admins: vec![admin.verifying_key()],
                },
                "genesis isn't first",
            ),
            (Change::AddDevice(mac.clone()), "the device id is taken"),
            (
                Change::AddDevice(reused),
                "another device has the same keys",
            ),
            (
                Change::AddDevice(p256_transport),
                "the transport key must be Ed25519",
            ),
            (
                Change::AddDevice(platform),
                "the platform must be 1 to 16 of a-z and 0-9",
            ),
            (
                Change::AddDevice(name),
                "the device name must be 1 to 64 bytes with no control characters",
            ),
            (scope(DeviceId::random(), Scope::Read), "no such device"),
            (scope(mac.id, Scope::Write), "the scope is unchanged"),
            (scope(revoked.id, Scope::Read), "the device is revoked"),
            (Change::RevokeDevice(revoked.id), "the device is revoked"),
            (
                Change::RotateEpoch {
                    collection: CollectionId::random(),
                    epoch: 1,
                },
                "no such collection",
            ),
            (
                Change::RotateEpoch {
                    collection: c,
                    epoch: 2,
                },
                "the epoch isn't the next one",
            ),
            (Change::AddAdmin(admin.verifying_key()), "already an admin"),
            (
                Change::RemoveAdmin(SigningKey::generate_ed25519().verifying_key()),
                "not an admin",
            ),
            (
                Change::RemoveAdmin(admin.verifying_key()),
                "the last admin can't be removed",
            ),
        ];
        for (change, reason) in cases {
            assert_eq!(
                rejected(m.append(change.clone(), &admin)),
                reason,
                "{change:?}"
            );
        }
        assert_eq!(m.head(), head);

        for _ in 1..MAX_ADMINS {
            let key = SigningKey::generate_ed25519().verifying_key();
            m.append(Change::AddAdmin(key), &admin).unwrap();
        }
        let ninth = SigningKey::generate_ed25519().verifying_key();
        assert_eq!(
            rejected(m.append(Change::AddAdmin(ninth), &admin)),
            "too many admins"
        );
    }

    #[test]
    fn only_current_admins_extend_the_chain() {
        let (admin, mut m, _) = vault();
        let other = SigningKey::generate_ed25519();
        assert_eq!(
            rejected(m.append(Change::AddDevice(device("a")), &other)),
            "signer isn't an admin"
        );

        // Entries signed elsewhere must follow this log's head, in order, from this vault.
        let mut ahead = m.clone();
        let first = ahead
            .append(Change::AddDevice(device("a")), &admin)
            .unwrap();
        let second = ahead
            .append(Change::AddDevice(device("b")), &admin)
            .unwrap();
        assert_eq!(
            rejected(m.apply(&second)),
            "the entry doesn't follow the last one"
        );
        m.apply(&first).unwrap();
        assert_eq!(
            rejected(m.apply(&first)),
            "the entry doesn't follow the last one"
        );
        let (other_admin, mut elsewhere, _) = vault();
        let foreign = elsewhere
            .append(Change::AddDevice(device("c")), &other_admin)
            .unwrap();
        assert_eq!(
            rejected(m.clone().apply(&foreign)),
            "the entry is from another vault"
        );

        // A changed payload or signature doesn't verify. The last payload byte is the last
        // letter of the device name.
        let mut bytes = second.to_bytes();
        let last = bytes.len() - SIGNATURE_LEN - 1;
        bytes[last] ^= 0x20;
        let tampered = LogEntry::from_bytes(&bytes).unwrap();
        assert!(matches!(
            m.clone().apply(&tampered),
            Err(Error::Crypto(openvault_crypto::Error::BadSignature))
        ));
        let mut bytes = second.to_bytes();
        *bytes.last_mut().unwrap() ^= 1;
        assert!(
            LogEntry::from_bytes(&bytes)
                .and_then(|entry| m.clone().apply(&entry))
                .is_err()
        );
        m.apply(&second).unwrap();

        // A removed admin can't sign; the admin that replaced it can.
        let next = SigningKey::generate_p256();
        m.append(Change::AddAdmin(next.verifying_key()), &admin)
            .unwrap();
        m.append(Change::RemoveAdmin(admin.verifying_key()), &next)
            .unwrap();
        assert_eq!(
            rejected(m.append(Change::AddDevice(device("d")), &admin)),
            "signer isn't an admin"
        );
        m.append(Change::AddDevice(device("d")), &next).unwrap();
    }

    #[test]
    fn rejects_bad_encodings() {
        let (admin, mut m, _) = vault();
        let entry = m.append(Change::AddDevice(device("a")), &admin).unwrap();
        let bytes = entry.to_bytes();
        let invalid = |bytes: &[u8]| LogEntry::from_bytes(bytes).is_err();

        assert!(invalid(&bytes[..bytes.len() - 1]));
        assert!(invalid(&[&bytes[..], &[0]].concat()));
        assert!(invalid(&bytes[..SIGNATURE_LEN]));

        // format ‖ vault ‖ seq ‖ prev ‖ signer, then the type and payload length.
        let type_at = 1 + 16 + 8 + 32 + admin.verifying_key().as_bytes().len();
        let mut changed = bytes.clone();
        changed[0] = 0x02;
        assert!(invalid(&changed));
        let mut changed = bytes.clone();
        changed[type_at] = 0x7f;
        assert!(invalid(&changed));
        let mut changed = bytes.clone();
        changed[type_at + 1..type_at + 5]
            .copy_from_slice(&u32::try_from(MAX_PAYLOAD_LEN + 1).unwrap().to_be_bytes());
        assert!(invalid(&changed));

        // A set_scope with an unknown scope byte.
        let c = CollectionId::random();
        let device = m.devices().next().unwrap().info.id;
        let entry = m
            .append(
                Change::SetScope {
                    device,
                    collection: c,
                    scope: Scope::Hold,
                },
                &admin,
            )
            .unwrap();
        let mut changed = entry.to_bytes();
        let last = changed.len() - SIGNATURE_LEN - 1;
        changed[last] = 0x04;
        assert!(invalid(&changed));
    }

    #[test]
    fn hash_covers_everything_but_the_signature() {
        let (admin, mut m, log) = vault();
        let entry = m.append(Change::AddDevice(device("a")), &admin).unwrap();
        let resigned = [&entry.unsigned[..], log[0].signature.as_bytes()].concat();
        assert_eq!(
            LogEntry::from_bytes(&resigned).unwrap().hash(),
            entry.hash()
        );
        assert_ne!(log[0].hash(), entry.hash());
    }

    #[test]
    fn finds_forks() {
        let (admin, mut m, mut log) = vault();
        let mac = device("MacBook");
        log.push(m.append(Change::AddDevice(mac.clone()), &admin).unwrap());
        let scope = |scope| Change::SetScope {
            device: mac.id,
            collection: CollectionId::from_bytes([7; 16]),
            scope,
        };
        let mut other = m.clone();
        log.push(m.append(scope(Scope::Write), &admin).unwrap());

        let fork = other.append(scope(Scope::Read), &admin).unwrap();
        assert!(Membership::is_fork(&log, &fork).unwrap());
        assert!(!Membership::is_fork(&log, &log[2]).unwrap());

        // Not forks: an entry that wouldn't be accepted, one beyond the log, another genesis.
        let outsider = SigningKey::generate_ed25519();
        let forged =
            LogEntry::sign(m.vault(), 2, log[1].hash(), scope(Scope::Read), &outsider).unwrap();
        assert!(!Membership::is_fork(&log, &forged).unwrap());
        let next = other
            .append(Change::AddDevice(device("b")), &admin)
            .unwrap();
        assert!(!Membership::is_fork(&log, &next).unwrap());
        let (_, _, elsewhere) = vault();
        assert!(!Membership::is_fork(&log, &elsewhere[0]).unwrap());
    }

    #[test]
    fn genesis_format_is_pinned() {
        // Recovery secret = 32 zero bytes (crypto.md test vector), vault id = 16 bytes of 1.
        let recovery = RecoveryKey::from_phrase(
            &["abandon"; 23]
                .into_iter()
                .chain(["art"])
                .collect::<Vec<_>>()
                .join(" "),
        )
        .unwrap();
        let admin = recovery.admin_signing_key();
        let (m, genesis) = Membership::create(
            VaultId::from_bytes([1; 16]),
            recovery.unwrap_key().wrap_key(),
            vec![admin.verifying_key()],
            &admin,
        )
        .unwrap();
        assert_eq!(
            genesis.to_bytes().len(),
            1 + 16 + 8 + 32 + 33 + 1 + 4 + 34 + 1 + 33 + 65
        );
        assert_eq!(
            hex::encode(m.genesis_hash()),
            "77b53378f73774df461b6e6444fdaf4a3f796dce377bb13372aeaee33d1d3cc5"
        );
    }
}
