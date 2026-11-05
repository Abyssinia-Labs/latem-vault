//! Symmetric encryption of records with XChaCha20-Poly1305.
//!
//! A sealed value is `nonce (24 bytes) || ciphertext || tag (16 bytes)`. Nonces are
//! random; at 192 bits they can't realistically repeat under one key.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, random_bytes};

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// A 256-bit key for XChaCha20-Poly1305: a collection key, or a file key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; 32]);

impl SymmetricKey {
    pub fn generate() -> Self {
        Self(*random_bytes())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encrypts `plaintext`, authenticating `aad` with it.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let nonce = random_bytes::<NONCE_LEN>();
        let ciphertext = self
            .cipher()
            .encrypt(
                &XNonce::from(*nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("XChaCha20-Poly1305 encryption can't fail for in-memory buffers");
        let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(nonce.as_ref());
        sealed.extend_from_slice(&ciphertext);
        sealed
    }

    /// Decrypts a value from [`seal`](Self::seal). Fails if the key, `aad` or any byte differs.
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::Decrypt);
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce).expect("split at the nonce length");
        self.cipher()
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map(zeroize::Zeroizing::new)
            .map_err(|_| Error::Decrypt)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&self.0.into())
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SymmetricKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = SymmetricKey::generate();
        let sealed = key.seal(b"header", b"secret value");
        assert_eq!(sealed.len(), NONCE_LEN + b"secret value".len() + TAG_LEN);
        assert_eq!(
            key.open(b"header", &sealed).unwrap().as_slice(),
            b"secret value"
        );
    }

    #[test]
    fn nonces_differ() {
        let key = SymmetricKey::generate();
        assert_ne!(key.seal(b"", b"same"), key.seal(b"", b"same"));
    }

    #[test]
    fn rejects_wrong_aad_key_or_tampering() {
        let key = SymmetricKey::generate();
        let sealed = key.seal(b"header", b"secret value");

        assert_eq!(key.open(b"other header", &sealed), Err(Error::Decrypt));
        assert_eq!(
            SymmetricKey::generate().open(b"header", &sealed),
            Err(Error::Decrypt)
        );

        for i in [0, NONCE_LEN, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[i] ^= 1;
            assert_eq!(key.open(b"header", &tampered), Err(Error::Decrypt));
        }
        assert_eq!(
            key.open(b"header", &sealed[..NONCE_LEN + TAG_LEN - 1]),
            Err(Error::Decrypt)
        );
    }
}
