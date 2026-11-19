use pinkvault_crypto::hash::{contexts, derive_key};
use pinkvault_crypto::{
    Signature, SignatureContext, SigningKey, SymmetricKey, UnwrapKey, VerifyingKey, WrapKey,
    WrappedKey,
};
use zeroize::Zeroizing;

use crate::Result;

/// The Ed25519 seed of the device's transport key, its iroh identity, derived from the local
/// key (records.md, local store).
pub fn transport_seed(keys: &(impl DeviceKeys + ?Sized)) -> Zeroizing<[u8; 32]> {
    derive_key(contexts::TRANSPORT, keys.local_key().as_bytes())
}

/// A device's keys, wherever they live: in memory, a file, the Secure Enclave or a TPM.
///
/// Hardware implementations may prompt the user or fail (Touch ID cancelled, TPM locked),
/// so the private-key operations return errors.
pub trait DeviceKeys {
    /// The public wrapping key collection keys are wrapped to.
    fn wrap_key(&self) -> WrapKey;

    fn unwrap(&self, context: &[u8], wrapped: &WrappedKey) -> Result<SymmetricKey>;

    fn verifying_key(&self) -> VerifyingKey;

    fn sign(&self, context: SignatureContext, message: &[u8]) -> Result<Signature>;

    /// The device-only key behind the local store's index (records.md, local store).
    fn local_key(&self) -> &SymmetricKey;
}

impl<T: DeviceKeys + ?Sized> DeviceKeys for &T {
    fn wrap_key(&self) -> WrapKey {
        (**self).wrap_key()
    }

    fn unwrap(&self, context: &[u8], wrapped: &WrappedKey) -> Result<SymmetricKey> {
        (**self).unwrap(context, wrapped)
    }

    fn verifying_key(&self) -> VerifyingKey {
        (**self).verifying_key()
    }

    fn sign(&self, context: SignatureContext, message: &[u8]) -> Result<Signature> {
        (**self).sign(context, message)
    }

    fn local_key(&self) -> &SymmetricKey {
        (**self).local_key()
    }
}

/// Keys held in memory: X25519 wrapping, Ed25519 signing. The file keystore stores these.
pub struct SoftwareKeys {
    unwrap: UnwrapKey,
    signing: SigningKey,
    local: SymmetricKey,
}

impl SoftwareKeys {
    pub fn generate() -> Self {
        Self::from_parts(
            UnwrapKey::generate_x25519(),
            SigningKey::generate_ed25519(),
            SymmetricKey::generate(),
        )
    }

    pub fn from_parts(unwrap: UnwrapKey, signing: SigningKey, local: SymmetricKey) -> Self {
        Self {
            unwrap,
            signing,
            local,
        }
    }

    pub fn parts(&self) -> (&UnwrapKey, &SigningKey, &SymmetricKey) {
        (&self.unwrap, &self.signing, &self.local)
    }
}

impl DeviceKeys for SoftwareKeys {
    fn wrap_key(&self) -> WrapKey {
        self.unwrap.wrap_key()
    }

    fn unwrap(&self, context: &[u8], wrapped: &WrappedKey) -> Result<SymmetricKey> {
        Ok(self.unwrap.unwrap(context, wrapped)?)
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    fn sign(&self, context: SignatureContext, message: &[u8]) -> Result<Signature> {
        Ok(self.signing.sign(context, message))
    }

    fn local_key(&self) -> &SymmetricKey {
        &self.local
    }
}
