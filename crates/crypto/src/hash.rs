//! BLAKE3 hashing and key derivation.

/// A 32-byte BLAKE3 hash.
pub type Hash = [u8; 32];

/// Hashes `data` with BLAKE3.
pub fn hash(data: &[u8]) -> Hash {
    *blake3::hash(data).as_bytes()
}

/// Derives 32 bytes of key material from `material` with BLAKE3's key derivation mode.
///
/// `context` must be one of the constants in [`contexts`], so every derived key has a
/// distinct, documented purpose.
pub fn derive_key(context: &'static str, material: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
    zeroize::Zeroizing::new(blake3::derive_key(context, material))
}

/// A BLAKE3 keyed hash (a MAC) of `data`.
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> Hash {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// Context strings for [`derive_key`]. Changing one changes every key derived from it, so they
/// are frozen in [`crate::frozen`].
pub use crate::frozen::contexts;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_matches_blake3_test_vector() {
        assert_eq!(
            hex::encode(hash(b"")),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn contexts_give_different_keys() {
        let material = [7u8; 32];
        assert_ne!(
            *derive_key(contexts::RECOVERY_ADMIN_SIGNING, &material),
            *derive_key(contexts::RECOVERY_WRAPPING, &material)
        );
    }
}
