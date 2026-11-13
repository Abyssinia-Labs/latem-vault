//! Where a device keeps its keys (`docs/spec/keystore.md`).
//!
//! A device's keys live in one key file, apart from the vault database. The file holds the keys
//! themselves ([`Backend::Software`], protected only by the file's 0600 mode), the same keys
//! sealed with a passphrase ([`Backend::Passphrase`]), or Secure Enclave key blobs that only
//! this Mac can use ([`Backend::SecureEnclave`]).
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
    /// Software keys sealed with a key derived from a passphrase.
    Passphrase,
    /// P-256 keys in the Secure Enclave; the key file holds blobs only it can use.
    SecureEnclave,
}

impl Backend {
    /// The Secure Enclave when this device has one, otherwise a passphrase.
    pub fn best() -> Self {
        if Self::SecureEnclave.is_available() {
            Self::SecureEnclave
        } else {
            Self::Passphrase
        }
    }

    pub fn is_available(self) -> bool {
        match self {
            Self::Software | Self::Passphrase => true,
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
    Passphrase(SoftwareKeys),
    #[cfg(target_os = "macos")]
    SecureEnclave(SecureEnclaveKeys),
}

impl Keys {
    /// Generates keys in `backend` and writes a new key file at `path` (mode 0600). Passphrase
    /// keys come from [`create_with_passphrase`](Self::create_with_passphrase) instead.
    pub fn create(path: &Path, backend: Backend) -> Result<Self> {
        file::create(path, backend)
    }

    /// Generates software keys and writes them to a new key file at `path`, sealed with a key
    /// derived from `passphrase`. The passphrase must pass [`check_passphrase`].
    pub fn create_with_passphrase(path: &Path, passphrase: &str) -> Result<Self> {
        file::create_with_passphrase(path, passphrase)
    }

    /// Loads the keys from the key file at `path`. A file protected by a passphrase gives
    /// [`Error::NeedsPassphrase`]; load it with [`load_with_passphrase`](Self::load_with_passphrase).
    pub fn load(path: &Path) -> Result<Self> {
        file::load(path, None)
    }

    /// Loads the keys from the key file at `path`, using `passphrase` if the file is protected
    /// by one. A wrong passphrase gives [`Error::WrongPassphrase`].
    pub fn load_with_passphrase(path: &Path, passphrase: &str) -> Result<Self> {
        file::load(path, Some(passphrase))
    }

    /// Writes the keys in the key file at `path` again, sealed with `new`, or with no passphrase
    /// when `new` is `None`, in place of the file (keystore.md, changing the protection). They
    /// are the same keys, so the device stays the same device. `current` opens the file if it has
    /// a passphrase now, and `new` must pass [`check_passphrase`]. If anything fails, the file is
    /// as it was. Secure Enclave keys give [`Error::InSecureEnclave`].
    pub fn change_passphrase(
        path: &Path,
        current: Option<&str>,
        new: Option<&str>,
    ) -> Result<Self> {
        file::change_passphrase(path, current, new)
    }

    pub fn backend(&self) -> Backend {
        match self {
            Self::Software(_) => Backend::Software,
            Self::Passphrase(_) => Backend::Passphrase,
            #[cfg(target_os = "macos")]
            Self::SecureEnclave(_) => Backend::SecureEnclave,
        }
    }

    fn inner(&self) -> &dyn DeviceKeys {
        match self {
            Self::Software(keys) | Self::Passphrase(keys) => keys,
            #[cfg(target_os = "macos")]
            Self::SecureEnclave(keys) => keys,
        }
    }
}

/// Fails if a new key file can't use `passphrase`: it must be at least 12 characters and at most
/// 1024 bytes.
pub fn check_passphrase(passphrase: &str) -> Result<()> {
    file::check_passphrase(passphrase)
}

/// How the keys in the key file at `path` are kept, without opening them or asking for a
/// passphrase.
pub fn backend_of(path: &Path) -> Result<Backend> {
    file::backend(path)
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
    #[error("this device's keys are protected by a passphrase")]
    NeedsPassphrase,
    #[error("wrong passphrase, or a damaged key file")]
    WrongPassphrase,
    #[error("{0}")]
    Passphrase(&'static str),
    #[error("{0:?} keys aren't available on this device")]
    Unavailable(Backend),
    #[error(
        "this device's keys are in the Secure Enclave, which they never leave, so they have no \
         passphrase; moving them off it means joining again as a new device"
    )]
    InSecureEnclave,
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

    const PASSPHRASE: &str = "correct horse battery staple";

    /// Every backend this machine has. Secure Enclave tests are skipped, with a note, on Macs
    /// without one and on other platforms.
    fn backends() -> Vec<Backend> {
        let mut backends = vec![Backend::Software, Backend::Passphrase];
        if Backend::SecureEnclave.is_available() {
            backends.push(Backend::SecureEnclave);
        } else {
            eprintln!("no Secure Enclave here; testing software keys only");
        }
        backends
    }

    /// Creates keys in `backend`, with [`PASSPHRASE`] if it needs one.
    fn create(path: &Path, backend: Backend) -> Keys {
        match backend {
            Backend::Passphrase => Keys::create_with_passphrase(path, PASSPHRASE),
            _ => Keys::create(path, backend),
        }
        .unwrap()
    }

    fn load(path: &Path) -> Keys {
        Keys::load_with_passphrase(path, PASSPHRASE).unwrap()
    }

    #[test]
    fn keys_survive_reloading() {
        let dir = tempfile::tempdir().unwrap();
        for backend in backends() {
            let path = dir.path().join(format!("{backend:?}"));
            let created = create(&path, backend);
            let loaded = load(&path);
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
                let keys = create(&keys_path, backend);
                let mut vault = Vault::create(&vault_path, keys, &recovery, "test", None).unwrap();
                let id = vault
                    .create_collection("latem", &recovery.admin_signing_key())
                    .unwrap();
                vault
                    .set(id, "prod/SENTRY_DSN", Kind::Secret, b"https://sentry")
                    .unwrap();
                id
            };
            let mut vault = Vault::open(&vault_path, load(&keys_path)).unwrap();
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
        for backend in [Backend::Software, Backend::Passphrase] {
            let path = dir.path().join(format!("{backend:?}"));
            create(&path, backend);
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );

            // Refused before asking for a passphrase.
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            assert!(matches!(
                Keys::load(&path),
                Err(Error::Permissions(_, 0o640))
            ));
        }
    }

    #[test]
    fn passphrase_keys_need_their_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        assert!(matches!(
            Keys::create(&path, Backend::Passphrase),
            Err(Error::NeedsPassphrase)
        ));
        assert!(!path.exists());

        let keys = create(&path, Backend::Passphrase);
        assert!(matches!(Keys::load(&path), Err(Error::NeedsPassphrase)));
        assert!(matches!(
            Keys::load_with_passphrase(&path, "correct horse battery stapler"),
            Err(Error::WrongPassphrase)
        ));
        assert_eq!(load(&path).wrap_key(), keys.wrap_key());

        // 186 bytes, with no key in the clear.
        let raw = fs::read(&path).unwrap();
        assert_eq!(raw.len(), 18 + 1 + 12 + 16 + 24 + 99 + 16);
        assert!(!raw.windows(32).any(|w| w == keys.local_key().as_bytes()));

        // A passphrase is ignored for a file that isn't protected by one.
        let software = dir.path().join("software");
        Keys::create(&software, Backend::Software).unwrap();
        assert_eq!(load(&software).backend(), Backend::Software);
    }

    /// The same keys through every change of protection (keystore.md, changing the protection).
    #[test]
    fn passphrase_can_be_added_changed_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        let staged = dir.path().join("keys.new");
        let created = Keys::create(&path, Backend::Software).unwrap();
        let same = |keys: &Keys| {
            assert_eq!(keys.wrap_key(), created.wrap_key());
            assert_eq!(keys.verifying_key(), created.verifying_key());
            assert_eq!(keys.local_key().as_bytes(), created.local_key().as_bytes());
        };
        assert_eq!(backend_of(&path).unwrap(), Backend::Software);

        let added = Keys::change_passphrase(&path, None, Some(PASSPHRASE)).unwrap();
        assert_eq!(added.backend(), Backend::Passphrase);
        same(&added);
        assert_eq!(backend_of(&path).unwrap(), Backend::Passphrase);
        assert!(matches!(Keys::load(&path), Err(Error::NeedsPassphrase)));
        same(&load(&path));

        let other = "a different passphrase";
        let changed = Keys::change_passphrase(&path, Some(PASSPHRASE), Some(other)).unwrap();
        same(&changed);
        assert!(matches!(
            Keys::load_with_passphrase(&path, PASSPHRASE),
            Err(Error::WrongPassphrase)
        ));
        same(&Keys::load_with_passphrase(&path, other).unwrap());

        let removed = Keys::change_passphrase(&path, Some(other), None).unwrap();
        assert_eq!(removed.backend(), Backend::Software);
        same(&removed);
        assert_eq!(backend_of(&path).unwrap(), Backend::Software);
        same(&Keys::load(&path).unwrap());

        assert!(!staged.exists());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// A change that can't be made leaves the key file as it was.
    #[test]
    fn changing_the_passphrase_fails_safely() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        let staged = dir.path().join("keys.new");
        create(&path, Backend::Passphrase);
        let before = fs::read(&path).unwrap();

        assert!(matches!(
            Keys::change_passphrase(&path, None, None),
            Err(Error::NeedsPassphrase)
        ));
        assert!(matches!(
            Keys::change_passphrase(&path, Some("not the passphrase"), None),
            Err(Error::WrongPassphrase)
        ));
        assert!(matches!(
            Keys::change_passphrase(&path, Some(PASSPHRASE), Some("too short")),
            Err(Error::Passphrase(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(!staged.exists());

        // A keys.new left by a crash doesn't stop the next change.
        fs::write(&staged, b"half written").unwrap();
        Keys::change_passphrase(&path, Some(PASSPHRASE), None).unwrap();
        assert!(!staged.exists());
        assert_eq!(backend_of(&path).unwrap(), Backend::Software);

        if Backend::SecureEnclave.is_available() {
            let enclave = dir.path().join("enclave");
            Keys::create(&enclave, Backend::SecureEnclave).unwrap();
            let before = fs::read(&enclave).unwrap();
            assert!(matches!(
                Keys::change_passphrase(&enclave, None, Some(PASSPHRASE)),
                Err(Error::InSecureEnclave)
            ));
            assert_eq!(fs::read(&enclave).unwrap(), before);
            assert_eq!(backend_of(&enclave).unwrap(), Backend::SecureEnclave);
        }
    }

    #[test]
    fn passphrase_files_are_authenticated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        create(&path, Backend::Passphrase);
        let good = fs::read(&path).unwrap();
        let cost = b"openvault v1 keys\0".len() + 1;
        let salt = cost + 12;

        // The cost, the salt and the sealed keys are all covered by the tag.
        for i in [cost + 11, salt, salt + 16, good.len() - 1] {
            let mut damaged = good.clone();
            damaged[i] ^= 1;
            fs::write(&path, &damaged).unwrap();
            assert!(
                matches!(
                    Keys::load_with_passphrase(&path, PASSPHRASE),
                    Err(Error::WrongPassphrase)
                ),
                "byte {i}"
            );
        }

        // A cost over the limit, or a wrong length, is refused before asking for the
        // passphrase.
        let mut costly = good.clone();
        costly[cost] = 0xff;
        for damaged in [
            costly,
            good[..good.len() - 1].to_vec(),
            [&good[..], &[0]].concat(),
        ] {
            fs::write(&path, &damaged).unwrap();
            assert!(matches!(Keys::load(&path), Err(Error::Format(_))));
        }
    }

    #[test]
    fn passphrase_rules() {
        check_passphrase("twelve chars").unwrap();
        assert!(matches!(
            check_passphrase("eleven char"),
            Err(Error::Passphrase(_))
        ));
        // Characters, not bytes.
        assert!(check_passphrase(&"é".repeat(11)).is_err());
        check_passphrase(&"é".repeat(12)).unwrap();
        check_passphrase(&"a".repeat(1024)).unwrap();
        assert!(check_passphrase(&"a".repeat(1025)).is_err());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        assert!(matches!(
            Keys::create_with_passphrase(&path, "too short"),
            Err(Error::Passphrase(_))
        ));
        assert!(!path.exists());
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

    /// Asks for Touch ID or the password, once: when the key authenticates, and not for the three
    /// signatures after it. So it runs only when asked: `cargo test -p openvault-keystore --
    /// --ignored`.
    #[test]
    #[ignore = "asks for Touch ID"]
    fn admin_key_signs_after_touch_id() {
        use openvault_core::membership::AdminKey as _;

        let dir = tempfile::tempdir().unwrap();
        let key = AdminKey::create(&dir.path().join("admin"))
            .unwrap()
            .with_reason("run the openvault admin key test (one prompt, then three signatures)");
        key.authenticate().unwrap();
        for message in [&b"first"[..], b"second", b"third"] {
            let signature = key.sign(SignatureContext::LogEntry, message).unwrap();
            key.verifying_key()
                .verify(SignatureContext::LogEntry, message, &signature)
                .unwrap();
        }
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
