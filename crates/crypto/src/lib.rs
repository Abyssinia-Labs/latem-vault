//! OpenVault's cryptographic building blocks.
//!
//! Everything here is a thin layer over audited crates: XChaCha20-Poly1305 for
//! records, HPKE (RFC 9180) for wrapping collection keys, Ed25519 and ECDSA
//! P-256 for signatures, and BLAKE3 for hashing and key derivation. The two
//! exceptions, which no audited crate provides, are Argon2id for passphrases
//! (crypto.md, passphrases) and SPAKE2 for joining (join.md, PAKE). The exact formats are specified in
//! `docs/spec/crypto.md`.
//!
//! Only software keys live here. Secure Enclave and TPM keys belong to the
//! keystore crate, which produces and consumes the same encodings.

pub mod aead;
pub mod chunk;
pub mod frozen;
pub mod hash;
pub mod pake;
pub mod passphrase;
pub mod recovery;
pub mod sign;
pub mod wrap;

pub use aead::SymmetricKey;
pub use chunk::{ChunkKeys, chunk_id};
pub use passphrase::{PassphraseCost, passphrase_key};
pub use recovery::RecoveryKey;
pub use sign::{Signature, SignatureContext, SigningKey, VerifyingKey};
pub use wrap::{UnwrapKey, WrapKey, WrappedKey};

/// Errors from this crate. Messages say what failed, never why a secret didn't match.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("decryption failed")]
    Decrypt,
    #[error("signature is invalid")]
    BadSignature,
    #[error("invalid {0} encoding")]
    Encoding(&'static str),
    #[error("recovery phrase is invalid")]
    RecoveryPhrase,
}

/// Fills an array from the operating system's random number generator.
///
/// Panics if the OS generator fails: there is no safe way to continue without randomness.
pub fn random_bytes<const N: usize>() -> zeroize::Zeroizing<[u8; N]> {
    let mut bytes = zeroize::Zeroizing::new([0u8; N]);
    getrandom::fill(bytes.as_mut()).expect("operating system random number generator failed");
    bytes
}
