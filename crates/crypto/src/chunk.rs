//! Sealing a file's chunks (files.md, chunks).
//!
//! A chunk's nonce is a keyed hash of its plaintext, so the same plaintext under the same
//! collection key and AAD always seals to the same bytes, and a chunk is stored and sent once
//! however many files or versions name it. Equal sealed chunks show that their plaintexts are
//! equal, and nothing else.

use zeroize::Zeroizing;

use crate::Error;
use crate::aead::{NONCE_LEN, SymmetricKey};
use crate::hash::{Hash, contexts, derive_key, keyed_hash};

/// The keys one collection key gives its chunks.
pub struct ChunkKeys {
    key: SymmetricKey,
    nonce_key: Zeroizing<[u8; 32]>,
}

impl ChunkKeys {
    pub fn derive(collection_key: &SymmetricKey) -> Self {
        let material = collection_key.as_bytes();
        Self {
            key: SymmetricKey::from_bytes(*derive_key(contexts::CHUNK_KEY, material)),
            nonce_key: derive_key(contexts::CHUNK_NONCE_KEY, material),
        }
    }

    /// `nonce ‖ ciphertext ‖ tag`, with the nonce taken from the plaintext.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let nonce: [u8; NONCE_LEN] = keyed_hash(&self.nonce_key, plaintext)[..NONCE_LEN]
            .try_into()
            .expect("a hash is longer than a nonce");
        self.key.seal_with_nonce(&nonce, aad, plaintext)
    }

    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.key.open(aad, sealed)
    }
}

/// A sealed chunk's id, which anyone can check without a key.
pub fn chunk_id(sealed: &[u8]) -> Hash {
    *derive_key(contexts::CHUNK_ID, sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_plaintext_seals_the_same_way() {
        let key = SymmetricKey::generate();
        let keys = ChunkKeys::derive(&key);
        let sealed = keys.seal(b"aad", b"a piece of a file");
        assert_eq!(sealed, keys.seal(b"aad", b"a piece of a file"));
        assert_eq!(
            chunk_id(&sealed),
            chunk_id(&keys.seal(b"aad", b"a piece of a file"))
        );
        assert_eq!(
            &keys.open(b"aad", &sealed).unwrap()[..],
            b"a piece of a file"
        );

        // Another plaintext, AAD or collection key seals differently.
        assert_ne!(sealed, keys.seal(b"aad", b"another piece of it"));
        assert_ne!(sealed, keys.seal(b"other aad", b"a piece of a file"));
        let other = ChunkKeys::derive(&SymmetricKey::generate());
        assert_ne!(sealed, other.seal(b"aad", b"a piece of a file"));
        assert!(other.open(b"aad", &sealed).is_err());
        assert!(keys.open(b"other aad", &sealed).is_err());
    }

    #[test]
    fn the_chunk_key_isnt_the_collection_key() {
        let key = SymmetricKey::generate();
        let sealed = ChunkKeys::derive(&key).seal(b"aad", b"x");
        assert!(key.open(b"aad", &sealed).is_err());
    }
}
