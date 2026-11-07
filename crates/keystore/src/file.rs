//! The key file (keystore.md, key file).

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use openvault_core::SoftwareKeys;
use openvault_crypto::{SigningKey, SymmetricKey, UnwrapKey, WrappedKey};
use zeroize::Zeroizing;

use crate::{Backend, Error, Keys, Result};

const MAGIC: &[u8] = b"openvault v1 keys\0";
const ADMIN_MAGIC: &[u8] = b"openvault v1 admin key\0";
const KIND_SOFTWARE: u8 = 0x01;
const KIND_SECURE_ENCLAVE: u8 = 0x02;
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
        #[cfg(target_os = "macos")]
        Backend::SecureEnclave => {
            encode_enclave(&crate::secure_enclave::SecureEnclaveKeys::generate()?)
        }
        #[cfg(not(target_os = "macos"))]
        Backend::SecureEnclave => unreachable!("checked by is_available"),
    };
    write_new(path, &contents)?;
    // Loading the file back proves the keys restore before anything is encrypted to them.
    load(path).inspect_err(|_| {
        let _ = fs::remove_file(path);
    })
}

pub(crate) fn load(path: &Path) -> Result<Keys> {
    decode(&read_private(path)?)
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

fn decode(contents: &[u8]) -> Result<Keys> {
    let body = contents
        .strip_prefix(MAGIC)
        .ok_or(Error::Format("unknown format"))?;
    let (&kind, body) = body.split_first().ok_or(Error::Format("truncated"))?;
    let mut reader = Reader(body);
    match kind {
        KIND_SOFTWARE => {
            let unwrap = UnwrapKey::from_secret_bytes(reader.take(34)?)?;
            let signing = SigningKey::from_secret_bytes(reader.take(33)?)?;
            let local = SymmetricKey::from_bytes(reader.take(32)?.try_into().expect("took 32"));
            reader.finish()?;
            Ok(Keys::Software(SoftwareKeys::from_parts(
                unwrap, signing, local,
            )))
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

fn encode_software(keys: &SoftwareKeys) -> Zeroizing<Vec<u8>> {
    let (unwrap, signing, local) = keys.parts();
    let mut out = Zeroizing::new(Vec::with_capacity(MAGIC.len() + 1 + 34 + 33 + 32));
    out.extend_from_slice(MAGIC);
    out.push(KIND_SOFTWARE);
    out.extend_from_slice(&unwrap.to_secret_bytes());
    out.extend_from_slice(&signing.to_secret_bytes());
    out.extend_from_slice(local.as_bytes());
    out
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
