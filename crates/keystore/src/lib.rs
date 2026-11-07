//! Where a device keeps its keys (`docs/spec/keystore.md`).
//!
//! A device's keys live in one key file, apart from the vault database. The file holds either
//! the keys themselves ([`Backend::Software`], protected only by the file's 0600 mode) or
//! Secure Enclave key blobs that only this Mac can use ([`Backend::SecureEnclave`]).
//!
//! A Mac that administers the vault also has an [`AdminKey`], in a file of its own: a Secure
//! Enclave key that asks for Touch ID or the password each time it signs.

mod admin;
mod file;
#[cfg(target_os = "macos")]
mod secure_enclave;

use std::path::{Path, PathBuf};

use openvault_core::{DeviceKeys, SoftwareKeys};
use openvault_crypto::{
    Signature, SignatureContext, SymmetricKey, VerifyingKey, WrapKey, WrappedKey,
};

pub use admin::AdminKey;
#[cfg(target_os = "macos")]
pub use secure_enclave::SecureEnclaveKeys;

/// Where a device's private keys live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// X25519 and Ed25519 keys in the key file.
    Software,
    /// P-256 keys in the Secure Enclave; the key file holds blobs only it can use.
    SecureEnclave,
}

impl Backend {
    /// The Secure Enclave when this device has one, otherwise software keys.
    pub fn best() -> Self {
        if Self::SecureEnclave.is_available() {
            Self::SecureEnclave
        } else {
            Self::Software
        }
    }

    pub fn is_available(self) -> bool {
        match self {
            Self::Software => true,
            #[cfg(target_os = "macos")]
            Self::SecureEnclave => secure_enclave::is_available(),
            #[cfg(not(target_os = "macos"))]
            Self::SecureEnclave => false,
        }
    }
}

/// A device's keys, loaded from its key file.
pub enum Keys {
    Software(SoftwareKeys),
    #[cfg(target_os = "macos")]
    SecureEnclave(SecureEnclaveKeys),
}

impl Keys {
    /// Generates keys in `backend` and writes a new key file at `path` (mode 0600).
    pub fn create(path: &Path, backend: Backend) -> Result<Self> {
        file::create(path, backend)
    }

    /// Loads the keys from the key file at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        file::load(path)
    }

    pub fn backend(&self) -> Backend {
        match self {
            Self::Software(_) => Backend::Software,
            #[cfg(target_os = "macos")]
            Self::SecureEnclave(_) => Backend::SecureEnclave,
        }
    }

    fn inner(&self) -> &dyn DeviceKeys {
        match self {
            Self::Software(keys) => keys,
            #[cfg(target_os = "macos")]
            Self::SecureEnclave(keys) => keys,
        }
    }
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("backend", &self.backend())
            .finish_non_exhaustive()
    }
}

impl DeviceKeys for Keys {
    fn wrap_key(&self) -> WrapKey {
        self.inner().wrap_key()
    }

    fn unwrap(&self, context: &[u8], wrapped: &WrappedKey) -> openvault_core::Result<SymmetricKey> {
        self.inner().unwrap(context, wrapped)
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.inner().verifying_key()
    }

    fn sign(&self, context: SignatureContext, message: &[u8]) -> openvault_core::Result<Signature> {
        self.inner().sign(context, message)
    }

    fn local_key(&self) -> &SymmetricKey {
        self.inner().local_key()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Crypto(#[from] openvault_crypto::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("a key file already exists at {}", .0.display())]
    Exists(PathBuf),
    #[error("no key file at {}", .0.display())]
    NotFound(PathBuf),
    #[error("{} can be read by other users (mode {:o}); it must be 0600", .0.display(), .1)]
    Permissions(PathBuf, u32),
    #[error("not a key file, or a damaged one: {0}")]
    Format(&'static str),
    #[error("{0:?} keys aren't available on this device")]
    Unavailable(Backend),
    #[error("Secure Enclave error: {0}")]
    SecureEnclave(String),
}

impl From<Error> for openvault_core::Error {
    fn from(error: Error) -> Self {
        Self::Keystore(error.to_string())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use openvault_core::{Kind, Vault};
    use openvault_crypto::RecoveryKey;

    use super::*;

    /// Every backend this machine has. Secure Enclave tests are skipped, with a note, on Macs
    /// without one and on other platforms.
    fn backends() -> Vec<Backend> {
        let mut backends = vec![Backend::Software];
        if Backend::SecureEnclave.is_available() {
            backends.push(Backend::SecureEnclave);
        } else {
            eprintln!("no Secure Enclave here; testing software keys only");
        }
        backends
    }

    #[test]
    fn keys_survive_reloading() {
        let dir = tempfile::tempdir().unwrap();
        for backend in backends() {
            let path = dir.path().join(format!("{backend:?}"));
            let created = Keys::create(&path, backend).unwrap();
            let loaded = Keys::load(&path).unwrap();
            assert_eq!(loaded.backend(), backend);
            assert_eq!(loaded.wrap_key(), created.wrap_key());
            assert_eq!(loaded.verifying_key(), created.verifying_key());
            assert_eq!(
                loaded.local_key().as_bytes(),
                created.local_key().as_bytes()
            );

            let signature = created.sign(SignatureContext::Record, b"m").unwrap();
            loaded
                .verifying_key()
                .verify(SignatureContext::Record, b"m", &signature)
                .unwrap();
            let key = SymmetricKey::generate();
            let wrapped = created.wrap_key().wrap(b"epoch 1", &key);
            assert_eq!(
                loaded.unwrap(b"epoch 1", &wrapped).unwrap().as_bytes(),
                key.as_bytes()
            );
            assert!(loaded.unwrap(b"epoch 2", &wrapped).is_err());
        }
    }

    #[test]
    fn secure_enclave_keys_are_p256_and_never_in_the_file() {
        if !Backend::SecureEnclave.is_available() {
            eprintln!("no Secure Enclave here; skipped");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        let keys = Keys::create(&path, Backend::SecureEnclave).unwrap();
        assert_eq!(keys.wrap_key().as_bytes()[..2], [0x00, 0x10]);
        assert_eq!(keys.verifying_key().as_bytes()[0], 0x02);
        let raw = fs::read(&path).unwrap();
        assert!(!raw.windows(32).any(|w| w == keys.local_key().as_bytes()));

        // A damaged blob doesn't restore.
        let mut damaged = raw.clone();
        let blob_start = b"openvault v1 keys\0".len() + 1 + 2;
        damaged[blob_start + 40] ^= 1;
        fs::write(&path, &damaged).unwrap();
        assert!(Keys::load(&path).is_err());
    }

    #[test]
    fn vaults_work_with_every_backend() {
        let dir = tempfile::tempdir().unwrap();
        let recovery = RecoveryKey::generate();
        for backend in backends() {
            let keys_path = dir.path().join(format!("{backend:?}.keys"));
            let vault_path = dir.path().join(format!("{backend:?}.db"));
            let id = {
                let keys = Keys::create(&keys_path, backend).unwrap();
                let mut vault = Vault::create(&vault_path, keys, &recovery, "test", None).unwrap();
                let id = vault
                    .create_collection("latem", &recovery.admin_signing_key())
                    .unwrap();
                vault
                    .set(id, "prod/SENTRY_DSN", Kind::Secret, b"https://sentry")
                    .unwrap();
                id
            };
            let mut vault = Vault::open(&vault_path, Keys::load(&keys_path).unwrap()).unwrap();
            let entry = vault.get(id, "prod/SENTRY_DSN").unwrap().unwrap();
            assert_eq!(&entry.value[..], b"https://sentry");
            assert_eq!(vault.list(id).unwrap().len(), 1);
        }
    }

    #[test]
    fn create_and_load_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        assert!(matches!(Keys::load(&path), Err(Error::NotFound(_))));
        let keys = Keys::create(&path, Backend::Software).unwrap();
        assert!(matches!(
            Keys::create(&path, Backend::Software),
            Err(Error::Exists(_))
        ));
        assert_eq!(
            Keys::load(&path).unwrap().wrap_key(),
            keys.wrap_key(),
            "a failed create leaves the existing file alone"
        );
        #[cfg(not(target_os = "macos"))]
        assert!(matches!(
            Keys::create(&dir.path().join("se"), Backend::SecureEnclave),
            Err(Error::Unavailable(Backend::SecureEnclave))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        Keys::create(&path, Backend::Software).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            Keys::load(&path),
            Err(Error::Permissions(_, 0o640))
        ));
    }

    #[test]
    fn admin_key_file() {
        use openvault_core::membership::AdminKey as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin");
        if !Backend::SecureEnclave.is_available() {
            assert!(matches!(
                AdminKey::create(&path),
                Err(Error::Unavailable(Backend::SecureEnclave))
            ));
            eprintln!("skipped the Secure Enclave part: this device has none");
            return;
        }

        let key = AdminKey::create(&path).unwrap();
        let loaded = AdminKey::load(&path).unwrap();
        assert_eq!(loaded.verifying_key(), key.verifying_key());
        assert!(!key.verifying_key().is_ed25519());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(matches!(AdminKey::create(&path), Err(Error::Exists(_))));

        // An admin key file and a device key file can't be mistaken for each other.
        assert!(matches!(Keys::load(&path), Err(Error::Format(_))));
        let keys = dir.path().join("keys");
        Keys::create(&keys, Backend::Software).unwrap();
        assert!(matches!(AdminKey::load(&keys), Err(Error::Format(_))));

        let good = fs::read(&path).unwrap();
        for damaged in [&good[..good.len() - 1], &[&good[..], &[0]].concat()] {
            fs::write(&path, damaged).unwrap();
            assert!(matches!(AdminKey::load(&path), Err(Error::Format(_))));
        }
    }

    /// Asks for Touch ID or the password, so it runs only when asked:
    /// `cargo test -p openvault-keystore -- --ignored`.
    #[test]
    #[ignore = "asks for Touch ID"]
    fn admin_key_signs_after_touch_id() {
        use openvault_core::membership::AdminKey as _;

        let dir = tempfile::tempdir().unwrap();
        let key = AdminKey::create(&dir.path().join("admin"))
            .unwrap()
            .with_reason("run the openvault admin key test");
        let signature = key.sign(SignatureContext::LogEntry, b"test").unwrap();
        key.verifying_key()
            .verify(SignatureContext::LogEntry, b"test", &signature)
            .unwrap();
    }

    #[test]
    fn rejects_damaged_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        Keys::create(&path, Backend::Software).unwrap();
        let good = fs::read(&path).unwrap();
        let magic = b"openvault v1 keys\0".len();

        let mut cases: Vec<Vec<u8>> = vec![
            good[..good.len() - 1].to_vec(),
            [&good[..], &[0]].concat(),
            good[..magic].to_vec(),
            vec![0; 16 * 1024 + 1],
        ];
        let mut other_version = good.clone();
        other_version[10] = b'2';
        let mut unknown_kind = good.clone();
        unknown_kind[magic] = 0x7f;
        let mut unknown_kem = good.clone();
        unknown_kem[magic + 2] = 0x21;
        cases.extend([other_version, unknown_kind, unknown_kem]);

        for (i, contents) in cases.iter().enumerate() {
            fs::write(&path, contents).unwrap();
            assert!(Keys::load(&path).is_err(), "case {i} loaded");
        }
        fs::write(&path, &good).unwrap();
        Keys::load(&path).unwrap();
    }
}
