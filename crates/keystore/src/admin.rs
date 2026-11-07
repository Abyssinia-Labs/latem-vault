//! The device's admin key (keystore.md, admin key): a Secure Enclave key that asks for Touch ID,
//! or the Mac's password, every time it signs a membership log entry.

use std::path::Path;

use openvault_core::membership;
use openvault_crypto::{Signature, SignatureContext, VerifyingKey};

use crate::{Backend, Error, Result, file};

/// What the dialog says when the caller hasn't said what is being signed.
#[cfg(target_os = "macos")]
const DEFAULT_REASON: &str = "change who is in your OpenVault vault";

/// An admin key, loaded from its file. It signs as a [`membership::AdminKey`].
pub struct AdminKey {
    blob: Vec<u8>,
    verifying_key: VerifyingKey,
    reason: String,
}

impl AdminKey {
    /// Generates an admin key in the Secure Enclave and writes a new file for it at `path`
    /// (mode 0600).
    pub fn create(path: &Path) -> Result<Self> {
        if !Backend::SecureEnclave.is_available() {
            return Err(Error::Unavailable(Backend::SecureEnclave));
        }
        #[cfg(target_os = "macos")]
        {
            let (_, blob) = crate::secure_enclave::generate_admin()?;
            file::write_admin(path, &blob)?;
            // Loading the file back proves the key restores before a vault lists it.
            Self::load(path).inspect_err(|_| {
                let _ = std::fs::remove_file(path);
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = path;
            unreachable!("checked by is_available")
        }
    }

    /// Loads the admin key from its file at `path`. This doesn't ask for Touch ID; signing does.
    pub fn load(path: &Path) -> Result<Self> {
        let blob = file::read_admin(path)?;
        #[cfg(target_os = "macos")]
        {
            let verifying_key = crate::secure_enclave::admin_verifying_key(&blob)?;
            Ok(Self {
                blob,
                verifying_key,
                reason: DEFAULT_REASON.to_owned(),
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            drop(blob);
            Err(Error::Unavailable(Backend::SecureEnclave))
        }
    }

    /// Sets what the Touch ID dialog says the signature is for, such as "create the collection
    /// ssh", so an unexpected request stands out (design §4, known limits).
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }
}

impl membership::AdminKey for AdminKey {
    fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key.clone()
    }

    fn sign(&self, context: SignatureContext, message: &[u8]) -> openvault_core::Result<Signature> {
        #[cfg(target_os = "macos")]
        {
            let input = openvault_crypto::sign::signing_input(context, message);
            Ok(crate::secure_enclave::admin_sign(
                &self.blob,
                &self.reason,
                &input,
            )?)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (context, message, &self.blob, &self.reason);
            unreachable!("an admin key can't be loaded without a Secure Enclave")
        }
    }
}

impl std::fmt::Debug for AdminKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminKey")
            .field("verifying_key", &self.verifying_key)
            .finish_non_exhaustive()
    }
}
