//! The key file (keystore.md, key file).

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use pinkvault_core::SoftwareKeys;
use pinkvault_crypto::passphrase::SALT_LEN;
use pinkvault_crypto::{
    PassphraseCost, SigningKey, SymmetricKey, UnwrapKey, WrappedKey, passphrase_key, random_bytes,
};
use zeroize::Zeroizing;

use crate::{Backend, Error, Keys, Result};

const MAGIC: &[u8] = pinkvault_crypto::frozen::KEYS_MAGIC;
const ADMIN_MAGIC: &[u8] = pinkvault_crypto::frozen::ADMIN_KEY_MAGIC;
const KIND_SOFTWARE: u8 = 0x01;
const KIND_SECURE_ENCLAVE: u8 = 0x02;
const KIND_PASSPHRASE: u8 = 0x03;
/// A software body: wrapping private key, signing private key and local key.
const SOFTWARE_LEN: usize = 34 + 33 + 32;
/// The software body sealed with XChaCha20-Poly1305: nonce, ciphertext and tag.
const SEALED_SOFTWARE_LEN: usize = 24 + SOFTWARE_LEN + 16;
/// The shortest passphrase a new key file accepts, in characters.
const MIN_PASSPHRASE_CHARS: usize = 12;
const MAX_PASSPHRASE_LEN: usize = 1024;
/// Key files are a few hundred bytes; anything much larger isn't one.
const MAX_LEN: usize = 16 * 1024;

/// What the key file holds for Secure Enclave keys: two key blobs only this Mac's Secure
/// Enclave can use, and the local key wrapped to the wrapping key.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct EnclaveBlobs {
    pub wrapping: Vec<u8>,
    pub signing: Vec<u8>,
    pub local: WrappedKey,
}

pub(crate) fn create(path: &Path, backend: Backend) -> Result<Keys> {
    if !backend.is_available() {
        return Err(Error::Unavailable(backend));
    }
    let contents = match backend {
        Backend::Software => encode_software(&SoftwareKeys::generate()),
        Backend::Passphrase => return Err(Error::NeedsPassphrase),
        #[cfg(target_os = "macos")]
        Backend::SecureEnclave => {
            encode_enclave(&crate::secure_enclave::SecureEnclaveKeys::generate()?)
        }
        #[cfg(not(target_os = "macos"))]
        Backend::SecureEnclave => unreachable!("checked by is_available"),
    };
    write_new(path, &contents)?;
    // Loading the file back proves the keys restore before anything is encrypted to them.
    load(path, None).inspect_err(|_| {
        let _ = fs::remove_file(path);
    })
}

pub(crate) fn create_with_passphrase(path: &Path, passphrase: &str) -> Result<Keys> {
    check_passphrase(passphrase)?;
    let contents = encode_passphrase(&SoftwareKeys::generate(), passphrase)?;
    write_new(path, &contents)?;
    load(path, Some(passphrase)).inspect_err(|_| {
        let _ = fs::remove_file(path);
    })
}

/// Loads the keys in `path`, using `passphrase` if the file is protected by one.
pub(crate) fn load(path: &Path, passphrase: Option<&str>) -> Result<Keys> {
    decode(&read_private(path)?, passphrase)
}

/// How the keys in `path` are kept, read from the file's kind without opening the keys.
pub(crate) fn backend(path: &Path) -> Result<Backend> {
    let contents = read_private(path)?;
    let body = contents
        .strip_prefix(MAGIC)
        .ok_or(Error::Format("unknown format"))?;
    match body.first() {
        Some(&KIND_SOFTWARE) => Ok(Backend::Software),
        Some(&KIND_PASSPHRASE) => Ok(Backend::Passphrase),
        Some(&KIND_SECURE_ENCLAVE) => Ok(Backend::SecureEnclave),
        Some(_) => Err(Error::Format("unknown key kind")),
        None => Err(Error::Format("truncated")),
    }
}

/// Writes the keys in `path` again, sealed with `new` or with no passphrase, in place of the
/// file (keystore.md, changing the protection). `current` opens the file if it has a passphrase.
pub(crate) fn change_passphrase(
    path: &Path,
    current: Option<&str>,
    new: Option<&str>,
) -> Result<Keys> {
    let keys = match load(path, current)? {
        Keys::Software(keys) | Keys::Passphrase(keys) => keys,
        #[cfg(target_os = "macos")]
        Keys::SecureEnclave(_) => return Err(Error::InSecureEnclave),
    };
    let contents = match new {
        Some(passphrase) => {
            check_passphrase(passphrase)?;
            Zeroizing::new(encode_passphrase(&keys, passphrase)?)
        }
        None => encode_software(&keys),
    };

    let mut staged = path.as_os_str().to_owned();
    staged.push(".new");
    let staged = PathBuf::from(staged);
    // Left over from a crash; nothing reads it.
    match fs::remove_file(&staged) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    write_new(&staged, &contents)?;
    // Loading it back proves it opens, and to the same keys, before it replaces the old file.
    let loaded = match load(&staged, new) {
        Ok(Keys::Software(loaded) | Keys::Passphrase(loaded))
            if encode_software_body(&loaded) == encode_software_body(&keys) =>
        {
            loaded
        }
        Ok(_) => {
            let _ = fs::remove_file(&staged);
            return Err(Error::Format(
                "the new key file doesn't open to the same keys",
            ));
        }
        Err(e) => {
            let _ = fs::remove_file(&staged);
            return Err(e);
        }
    };
    fs::rename(&staged, path)?;
    // The rename is in the directory, which has to reach the disk too.
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        File::open(dir)?.sync_all()?;
    }
    Ok(match new {
        Some(_) => Keys::Passphrase(loaded),
        None => Keys::Software(loaded),
    })
}

pub(crate) fn check_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(Error::Passphrase(
            "the passphrase must be at least 12 characters",
        ));
    }
    if passphrase.len() > MAX_PASSPHRASE_LEN {
        return Err(Error::Passphrase(
            "the passphrase must be at most 1024 bytes",
        ));
    }
    Ok(())
}

/// Writes a new admin key file: the magic, the Secure Enclave kind, and the key's blob
/// (keystore.md, admin key).
#[cfg(target_os = "macos")]
pub(crate) fn write_admin(path: &Path, blob: &[u8]) -> Result<()> {
    let len = u16::try_from(blob.len()).expect("Secure Enclave blobs are a few hundred bytes");
    let contents = [
        ADMIN_MAGIC,
        &[KIND_SECURE_ENCLAVE],
        &len.to_be_bytes(),
        blob,
    ]
    .concat();
    write_new(path, &contents)
}

/// The blob in an admin key file.
pub(crate) fn read_admin(path: &Path) -> Result<Vec<u8>> {
    let contents = read_private(path)?;
    let body = contents
        .strip_prefix(ADMIN_MAGIC)
        .ok_or(Error::Format("unknown format"))?;
    let (&kind, body) = body.split_first().ok_or(Error::Format("truncated"))?;
    if kind != KIND_SECURE_ENCLAVE {
        return Err(Error::Format("unknown key kind"));
    }
    let mut reader = Reader(body);
    let blob = reader.field()?.to_vec();
    reader.finish()?;
    Ok(blob)
}

/// Reads a file that only this user can read, refusing one that others can.
fn read_private(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let file = File::open(path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => Error::NotFound(path.to_owned()),
        _ => e.into(),
    })?;
    #[cfg(unix)]
    {
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(Error::Permissions(path.to_owned(), mode));
        }
    }
    // Sized up front so reading never reallocates and leaves key bytes behind.
    let mut contents = Zeroizing::new(Vec::with_capacity(MAX_LEN + 1));
    file.take(MAX_LEN as u64 + 1).read_to_end(&mut contents)?;
    if contents.len() > MAX_LEN {
        return Err(Error::Format("too large"));
    }
    Ok(contents)
}

fn decode(contents: &[u8], passphrase: Option<&str>) -> Result<Keys> {
    let body = contents
        .strip_prefix(MAGIC)
        .ok_or(Error::Format("unknown format"))?;
    let (&kind, body) = body.split_first().ok_or(Error::Format("truncated"))?;
    let mut reader = Reader(body);
    match kind {
        KIND_SOFTWARE => {
            let keys = decode_software(reader.take(SOFTWARE_LEN)?)?;
            reader.finish()?;
            Ok(Keys::Software(keys))
        }
        KIND_PASSPHRASE => {
            let cost = PassphraseCost {
                memory_kib: reader.u32()?,
                passes: reader.u32()?,
                lanes: reader.u32()?,
            };
            let salt: [u8; SALT_LEN] = reader.take(SALT_LEN)?.try_into().expect("took 16");
            let sealed = reader.take(SEALED_SOFTWARE_LEN)?;
            reader.finish()?;
            // Checked before asking for the passphrase, which a damaged file can't use.
            cost.check()
                .map_err(|_| Error::Format("unsupported passphrase cost"))?;
            let passphrase = passphrase.ok_or(Error::NeedsPassphrase)?;
            let key = passphrase_key(passphrase.as_bytes(), &salt, cost)?;
            let header = &contents[..contents.len() - sealed.len()];
            let body = key
                .open(header, sealed)
                .map_err(|_| Error::WrongPassphrase)?;
            Ok(Keys::Passphrase(decode_software(&body)?))
        }
        KIND_SECURE_ENCLAVE => {
            let blobs = EnclaveBlobs {
                wrapping: reader.field()?.to_vec(),
                signing: reader.field()?.to_vec(),
                local: WrappedKey::from_bytes(reader.field()?)?,
            };
            reader.finish()?;
            restore_enclave(&blobs)
        }
        _ => Err(Error::Format("unknown key kind")),
    }
}

#[cfg(target_os = "macos")]
fn restore_enclave(blobs: &EnclaveBlobs) -> Result<Keys> {
    Ok(Keys::SecureEnclave(
        crate::secure_enclave::SecureEnclaveKeys::restore(blobs)?,
    ))
}

#[cfg(not(target_os = "macos"))]
fn restore_enclave(_: &EnclaveBlobs) -> Result<Keys> {
    Err(Error::Unavailable(Backend::SecureEnclave))
}

/// Decodes a software body: the kind `0x01` body, or the plaintext of a kind `0x03` one.
fn decode_software(body: &[u8]) -> Result<SoftwareKeys> {
    let mut reader = Reader(body);
    let unwrap = UnwrapKey::from_secret_bytes(reader.take(34)?)?;
    let signing = SigningKey::from_secret_bytes(reader.take(33)?)?;
    let local = SymmetricKey::from_bytes(reader.take(32)?.try_into().expect("took 32"));
    reader.finish()?;
    Ok(SoftwareKeys::from_parts(unwrap, signing, local))
}

fn encode_software_body(keys: &SoftwareKeys) -> Zeroizing<Vec<u8>> {
    let (unwrap, signing, local) = keys.parts();
    let mut out = Zeroizing::new(Vec::with_capacity(SOFTWARE_LEN));
    out.extend_from_slice(&unwrap.to_secret_bytes());
    out.extend_from_slice(&signing.to_secret_bytes());
    out.extend_from_slice(local.as_bytes());
    out
}

fn encode_software(keys: &SoftwareKeys) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(MAGIC.len() + 1 + SOFTWARE_LEN));
    out.extend_from_slice(MAGIC);
    out.push(KIND_SOFTWARE);
    out.extend_from_slice(&encode_software_body(keys));
    out
}

/// The software body sealed under a key derived from `passphrase`, with everything before it
/// as the AAD (keystore.md, key file).
fn encode_passphrase(keys: &SoftwareKeys, passphrase: &str) -> Result<Vec<u8>> {
    let cost = PassphraseCost::DEFAULT;
    let salt = random_bytes::<SALT_LEN>();
    let mut out = MAGIC.to_vec();
    out.push(KIND_PASSPHRASE);
    for value in [cost.memory_kib, cost.passes, cost.lanes] {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(salt.as_ref());
    let key = passphrase_key(passphrase.as_bytes(), &salt, cost)?;
    let sealed = key.seal(&out, &encode_software_body(keys));
    out.extend_from_slice(&sealed);
    Ok(out)
}

#[cfg(target_os = "macos")]
fn encode_enclave(blobs: &EnclaveBlobs) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(MAGIC.to_vec());
    out.push(KIND_SECURE_ENCLAVE);
    for field in [&blobs.wrapping, &blobs.signing, &blobs.local.to_bytes()] {
        let len = u16::try_from(field.len()).expect("Secure Enclave blobs are a few hundred bytes");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// Creates `path` with mode 0600, failing if it exists, and removes it again if writing fails.
fn write_new(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(|e| match e.kind() {
        ErrorKind::AlreadyExists => Error::Exists(path.to_owned()),
        _ => e.into(),
    })?;
    if let Err(e) = file.write_all(contents).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(e.into());
    }
    Ok(())
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.0.len() < len {
            return Err(Error::Format("truncated"));
        }
        let (field, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(field)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("took 4"),
        ))
    }

    /// A field with a 2-byte big-endian length prefix.
    fn field(&mut self) -> Result<&'a [u8]> {
        let len = u16::from_be_bytes(self.take(2)?.try_into().expect("took 2"));
        self.take(len.into())
    }

    fn finish(self) -> Result<()> {
        self.0
            .is_empty()
            .then_some(())
            .ok_or(Error::Format("trailing bytes"))
    }
}
