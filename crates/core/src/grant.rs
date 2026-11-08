//! Grants: one collection key, for one epoch, wrapped to one recipient and signed by whoever
//! wrapped it (sync.md, grants).

use openvault_crypto::hash::{contexts, derive_key};
use openvault_crypto::{Signature, SignatureContext, VerifyingKey, WrappedKey};

use crate::membership::{Membership, Scope};
use crate::{CollectionId, DeviceId, Error, Result, VaultId};

const FORMAT: u8 = 0x01;

/// A grant's id, which peers reconcile in the grants set.
pub type GrantId = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    vault: VaultId,
    collection: CollectionId,
    epoch: u32,
    /// `None` for the recovery key.
    recipient: Option<DeviceId>,
    signer: VerifyingKey,
    wrapped: WrappedKey,
    unsigned: Vec<u8>,
    signature: Signature,
}

impl Grant {
    /// Signs a grant of `wrapped`, which must already be wrapped to the recipient with the
    /// records.md context for `collection` and `epoch`. `sign` signs the unsigned part with
    /// context "key grant", using the key `signer` verifies.
    pub fn sign(
        vault: VaultId,
        collection: CollectionId,
        epoch: u32,
        recipient: Option<DeviceId>,
        wrapped: WrappedKey,
        signer: VerifyingKey,
        sign: impl FnOnce(SignatureContext, &[u8]) -> Result<Signature>,
    ) -> Result<Self> {
        let recipient_bytes = recipient.map_or([0; 16], |device| *device.as_bytes());
        let unsigned = [
            &[FORMAT][..],
            vault.as_bytes(),
            collection.as_bytes(),
            &epoch.to_be_bytes(),
            &recipient_bytes,
            signer.as_bytes(),
            &wrapped.to_bytes(),
        ]
        .concat();
        let signature = sign(SignatureContext::KeyGrant, &unsigned)?;
        Ok(Self {
            vault,
            collection,
            epoch,
            recipient,
            signer,
            wrapped,
            unsigned,
            signature,
        })
    }

    /// Decodes a grant. Its signature and the rules are checked by [`check`](Self::check).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let invalid = || Error::InvalidGrant("bad encoding");
        let (&format, rest) = bytes.split_first().ok_or_else(invalid)?;
        if format != FORMAT {
            return Err(Error::InvalidGrant("unknown format"));
        }
        let (vault, rest) = rest.split_first_chunk::<16>().ok_or_else(invalid)?;
        let (collection, rest) = rest.split_first_chunk::<16>().ok_or_else(invalid)?;
        let (epoch, rest) = rest.split_first_chunk::<4>().ok_or_else(invalid)?;
        let (recipient, rest) = rest.split_first_chunk::<16>().ok_or_else(invalid)?;
        let (signer, rest) = VerifyingKey::split_prefix(rest)?;
        let (wrapped, rest) = WrappedKey::split_prefix(rest)?;
        let unsigned_len = bytes.len() - rest.len();
        let signature = Signature::from_bytes(rest)?;
        Ok(Self {
            vault: VaultId::from_bytes(*vault),
            collection: CollectionId::from_bytes(*collection),
            epoch: u32::from_be_bytes(*epoch),
            recipient: (*recipient != [0; 16]).then(|| DeviceId::from_bytes(*recipient)),
            signer,
            wrapped,
            unsigned: bytes[..unsigned_len].to_vec(),
            signature,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.unsigned[..], self.signature.as_bytes()].concat()
    }

    /// `BLAKE3.derive_key("openvault v1 grant id", unsigned part)`. Like a record id, it never
    /// covers the signature.
    pub fn id(&self) -> GrantId {
        *derive_key(contexts::GRANT_ID, &self.unsigned)
    }

    pub fn collection(&self) -> CollectionId {
        self.collection
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn recipient(&self) -> Option<DeviceId> {
        self.recipient
    }

    pub fn wrapped(&self) -> &WrappedKey {
        &self.wrapped
    }

    /// The rules for keeping a grant (sync.md, accepting grants), against the log so far.
    pub fn check(&self, membership: &Membership) -> Result<()> {
        let fail = |reason| Err(Error::InvalidGrant(reason));
        if self.vault != membership.vault() {
            return fail("the grant is for another vault");
        }
        if membership
            .epoch(self.collection)
            .is_none_or(|current| self.epoch > current)
        {
            return fail("the log hasn't reached the grant's epoch");
        }
        let recipient_key = match self.recipient {
            None => membership.recovery_key(),
            Some(device) => {
                if !membership.had_scope(device, self.collection, self.epoch, Scope::Read) {
                    return fail("the recipient couldn't read the collection at that epoch");
                }
                &membership
                    .device(device)
                    .expect("had a scope")
                    .info
                    .wrap_key
            }
        };
        if recipient_key.kem_id() != self.wrapped.kem_id() {
            return fail("the key isn't wrapped to the recipient's kind of key");
        }
        let signer_could_read = membership.devices().any(|device| {
            device.info.verifying_key == self.signer
                && membership.had_scope(device.info.id, self.collection, self.epoch, Scope::Read)
        });
        let signer_was_admin = membership
            .epoch_admins(self.collection, self.epoch)
            .contains(&self.signer);
        if !signer_could_read && !signer_was_admin {
            return fail("the signer couldn't read the collection at that epoch");
        }
        self.signer
            .verify(SignatureContext::KeyGrant, &self.unsigned, &self.signature)
            .map_err(|_| Error::InvalidGrant("the signature doesn't verify"))
    }
}
