//! The recovery key: 256 random bits, shown once as 24 BIP-39 English words.
//!
//! It derives two keys with BLAKE3 (see [`crate::hash::contexts`]): an Ed25519 admin signing
//! key, and an X25519 wrapping key that every collection key is also wrapped to.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::hash::{contexts, derive_key};
use crate::{Error, SigningKey, UnwrapKey, random_bytes};

const WORDS: usize = 24;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; 32]);

impl RecoveryKey {
    pub fn generate() -> Self {
        Self(*random_bytes())
    }

    /// Parses 24 words. Case and spacing don't matter; the BIP-39 checksum must match.
    pub fn from_phrase(phrase: &str) -> Result<Self, Error> {
        let normalized = Zeroizing::new(
            phrase
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase(),
        );
        let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &normalized)
            .map_err(|_| Error::RecoveryPhrase)?;
        if mnemonic.word_count() != WORDS {
            return Err(Error::RecoveryPhrase);
        }
        let (entropy, len) = mnemonic.to_entropy_array();
        let entropy = Zeroizing::new(entropy);
        let secret = entropy[..len]
            .try_into()
            .map_err(|_| Error::RecoveryPhrase)?;
        Ok(Self(secret))
    }

    /// The 24 words, separated by single spaces.
    pub fn to_phrase(&self) -> Zeroizing<String> {
        let mnemonic =
            bip39::Mnemonic::from_entropy(&self.0).expect("32 bytes is a valid BIP-39 length");
        Zeroizing::new(mnemonic.words().collect::<Vec<_>>().join(" "))
    }

    /// The admin signing key the recovery key stands for in the membership log.
    pub fn admin_signing_key(&self) -> SigningKey {
        SigningKey::from_ed25519_seed(&derive_key(contexts::RECOVERY_ADMIN_SIGNING, &self.0))
    }

    /// The wrapping key every collection key is also wrapped to.
    pub fn unwrap_key(&self) -> UnwrapKey {
        UnwrapKey::derive_x25519(derive_key(contexts::RECOVERY_WRAPPING, &self.0).as_ref())
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SignatureContext, SymmetricKey};

    /// BIP-39 test vector for 32 zero bytes.
    const ZERO_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon art";

    #[test]
    fn phrase_matches_bip39_vector() {
        assert_eq!(RecoveryKey([0; 32]).to_phrase().as_str(), ZERO_PHRASE);
        assert_eq!(RecoveryKey::from_phrase(ZERO_PHRASE).unwrap().0, [0; 32]);
    }

    #[test]
    fn phrase_round_trip_ignores_case_and_spacing() {
        let key = RecoveryKey::generate();
        let messy = format!("  {}\n", key.to_phrase().to_uppercase().replace(' ', "   "));
        assert_eq!(RecoveryKey::from_phrase(&messy).unwrap().0, key.0);
    }

    #[test]
    fn rejects_bad_phrases() {
        let wrong_checksum = ZERO_PHRASE.replace("art", "abandon");
        let twelve_words = "abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon about";
        for phrase in [wrong_checksum.as_str(), twelve_words, "", "not a phrase"] {
            assert_eq!(
                RecoveryKey::from_phrase(phrase).unwrap_err(),
                Error::RecoveryPhrase
            );
        }
    }

    #[test]
    fn derived_keys_are_stable() {
        // Pinned so a change to the derivation can't silently orphan existing recovery keys.
        let key = RecoveryKey([0; 32]);
        assert_eq!(
            hex::encode(key.admin_signing_key().verifying_key().as_bytes()),
            "01f03753c8c8e8effcacd1f79e241ba3cde48deccd826954c7f8ccfa2a114a2557"
        );
        assert_eq!(
            hex::encode(key.unwrap_key().wrap_key().as_bytes()),
            "0020cae8d02068d12207a480eb7c48b34cfdcd600bc5d279aaf86197e360e62ec20c"
        );
    }

    #[test]
    fn derived_keys_work() {
        let key = RecoveryKey::generate();
        let signature = key
            .admin_signing_key()
            .sign(SignatureContext::LogEntry, b"add_device");
        key.admin_signing_key()
            .verifying_key()
            .verify(SignatureContext::LogEntry, b"add_device", &signature)
            .unwrap();

        let collection_key = SymmetricKey::generate();
        let wrapped = key.unwrap_key().wrap_key().wrap(b"ctx", &collection_key);
        let restored = RecoveryKey::from_phrase(&key.to_phrase()).unwrap();
        assert_eq!(
            restored
                .unwrap_key()
                .unwrap(b"ctx", &wrapped)
                .unwrap()
                .as_bytes(),
            collection_key.as_bytes()
        );
    }
}
