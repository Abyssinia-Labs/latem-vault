//! Signatures on records and membership log entries: Ed25519, or ECDSA P-256 with SHA-256.
//!
//! Every signature covers `label || 0x00 || message`, where the label names what is being
//! signed (see [`SignatureContext`]), so a record signature can never pass as a log entry.
//! Hardware signers sign the bytes from [`signing_input`].

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use zeroize::Zeroizing;

use crate::{Error, random_bytes};

const ALG_ED25519: u8 = 0x01;
const ALG_P256: u8 = 0x02;

/// What a signature is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureContext {
    Record,
    LogEntry,
    JoinRequest,
    KeyGrant,
}

impl SignatureContext {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Record => b"openvault v1 sig record",
            Self::LogEntry => b"openvault v1 sig log entry",
            Self::JoinRequest => b"openvault v1 sig join request",
            Self::KeyGrant => b"openvault v1 sig key grant",
        }
    }
}

/// The exact bytes a signer signs for `message` in `context`.
pub fn signing_input(context: SignatureContext, message: &[u8]) -> Vec<u8> {
    [context.label(), &[0], message].concat()
}

/// A software signing key: a device's file-based key, or the recovery admin key.
pub enum SigningKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl SigningKey {
    pub fn generate_ed25519() -> Self {
        Self::from_ed25519_seed(&random_bytes())
    }

    pub fn generate_p256() -> Self {
        loop {
            // Fails only for the ~2^-32 of 32-byte strings that aren't a valid scalar.
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(random_bytes::<32>().as_ref()) {
                return Self::P256(key);
            }
        }
    }

    pub fn from_ed25519_seed(seed: &[u8; 32]) -> Self {
        Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// Restores a key from [`to_secret_bytes`](Self::to_secret_bytes).
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match bytes {
            [ALG_ED25519, seed @ ..] => seed
                .try_into()
                .map(Self::from_ed25519_seed)
                .map_err(|_| Error::Encoding("signing key")),
            [ALG_P256, scalar @ ..] if scalar.len() == 32 => {
                p256::ecdsa::SigningKey::from_slice(scalar)
                    .map(Self::P256)
                    .map_err(|_| Error::Encoding("signing key"))
            }
            _ => Err(Error::Encoding("signing key")),
        }
    }

    /// The algorithm byte followed by the 32-byte private key, for a keystore file.
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let (alg, secret) = match self {
            Self::Ed25519(key) => (ALG_ED25519, Zeroizing::new(key.to_bytes().to_vec())),
            Self::P256(key) => (ALG_P256, Zeroizing::new(key.to_bytes().to_vec())),
        };
        let mut bytes = Zeroizing::new(vec![alg]);
        bytes.extend_from_slice(&secret);
        bytes
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        let bytes = match self {
            Self::Ed25519(key) => [&[ALG_ED25519][..], key.verifying_key().as_bytes()].concat(),
            Self::P256(key) => [
                &[ALG_P256][..],
                key.verifying_key().to_sec1_point(false).as_bytes(),
            ]
            .concat(),
        };
        VerifyingKey(bytes)
    }

    pub fn sign(&self, context: SignatureContext, message: &[u8]) -> Signature {
        let input = signing_input(context, message);
        let bytes = match self {
            Self::Ed25519(key) => [&[ALG_ED25519][..], &key.sign(&input).to_bytes()].concat(),
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(&input);
                [&[ALG_P256][..], &signature.to_bytes()].concat()
            }
        };
        Signature(bytes)
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ed25519(_) => "SigningKey::Ed25519(..)",
            Self::P256(_) => "SigningKey::P256(..)",
        })
    }
}

/// A public signing key.
///
/// Encoded as an algorithm byte (`0x01` Ed25519, `0x02` ECDSA P-256 with SHA-256) followed by
/// the key: 32 bytes for Ed25519, 65 bytes (uncompressed SEC1) for P-256.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VerifyingKey(Vec<u8>);

impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let valid = match bytes {
            [ALG_ED25519, key @ ..] => <&[u8; 32]>::try_from(key)
                .is_ok_and(|key| ed25519_dalek::VerifyingKey::from_bytes(key).is_ok()),
            [ALG_P256, key @ ..] => {
                key.len() == 65 && p256::ecdsa::VerifyingKey::from_sec1_bytes(key).is_ok()
            }
            _ => false,
        };
        valid
            .then(|| Self(bytes.to_vec()))
            .ok_or(Error::Encoding("verifying key"))
    }

    /// A P-256 verifying key from its uncompressed SEC1 encoding, as hardware keystores
    /// export it.
    pub fn from_p256_sec1(public: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(&[&[ALG_P256][..], public].concat())
    }

    /// Parses a key at the start of `bytes`, for formats that embed one without a length,
    /// and returns it with the bytes after it.
    pub fn split_prefix(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let len = match bytes.first() {
            Some(&ALG_ED25519) => 1 + 32,
            Some(&ALG_P256) => 1 + 65,
            _ => return Err(Error::Encoding("verifying key")),
        };
        let (key, rest) = bytes
            .split_at_checked(len)
            .ok_or(Error::Encoding("verifying key"))?;
        Ok((Self::from_bytes(key)?, rest))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_ed25519(&self) -> bool {
        self.0[0] == ALG_ED25519
    }

    /// Checks `signature` over `message` in `context`.
    ///
    /// Ed25519 uses strict verification. ECDSA accepts either `s` or `n - s`, because the
    /// Secure Enclave doesn't normalize; nothing hashes signature bytes, so this is harmless.
    pub fn verify(
        &self,
        context: SignatureContext,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), Error> {
        let input = signing_input(context, message);
        let ok = match (self.0.as_slice(), signature.0.as_slice()) {
            ([ALG_ED25519, key @ ..], [ALG_ED25519, sig @ ..]) => {
                let key =
                    ed25519_dalek::VerifyingKey::from_bytes(key.try_into().expect("validated"))
                        .expect("validated on construction");
                let sig = ed25519_dalek::Signature::from_bytes(sig.try_into().expect("validated"));
                key.verify_strict(&input, &sig).is_ok()
            }
            ([ALG_P256, key @ ..], [ALG_P256, sig @ ..]) => {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
                    .expect("validated on construction");
                p256::ecdsa::Signature::from_slice(sig)
                    .is_ok_and(|sig| key.verify(&input, &sig).is_ok())
            }
            _ => false,
        };
        ok.then_some(()).ok_or(Error::BadSignature)
    }
}

/// A signature: the algorithm byte followed by 64 bytes (Ed25519, or ECDSA `r || s`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match bytes {
            [ALG_ED25519 | ALG_P256, sig @ ..] if sig.len() == 64 => Ok(Self(bytes.to_vec())),
            _ => Err(Error::Encoding("signature")),
        }
    }

    /// An ECDSA P-256 signature from the DER encoding hardware signers return.
    pub fn from_p256_der(der: &[u8]) -> Result<Self, Error> {
        let sig =
            p256::ecdsa::Signature::from_der(der).map_err(|_| Error::Encoding("signature"))?;
        Ok(Self([&[ALG_P256][..], &sig.to_bytes()].concat()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn both() -> [SigningKey; 2] {
        [SigningKey::generate_ed25519(), SigningKey::generate_p256()]
    }

    #[test]
    fn sign_and_verify() {
        for key in both() {
            let signature = key.sign(SignatureContext::Record, b"record header");
            let public = VerifyingKey::from_bytes(key.verifying_key().as_bytes()).unwrap();
            let signature = Signature::from_bytes(signature.as_bytes()).unwrap();
            public
                .verify(SignatureContext::Record, b"record header", &signature)
                .unwrap();
        }
    }

    #[test]
    fn rejects_other_context_message_or_key() {
        for key in both() {
            let public = key.verifying_key();
            let signature = key.sign(SignatureContext::Record, b"record header");
            assert_eq!(
                public.verify(SignatureContext::LogEntry, b"record header", &signature),
                Err(Error::BadSignature)
            );
            assert_eq!(
                public.verify(SignatureContext::Record, b"record headeR", &signature),
                Err(Error::BadSignature)
            );
            for other in both() {
                assert!(
                    other
                        .verifying_key()
                        .verify(SignatureContext::Record, b"record header", &signature)
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn rejects_tampered_signature() {
        for key in both() {
            let signature = key.sign(SignatureContext::LogEntry, b"entry");
            let mut bytes = signature.as_bytes().to_vec();
            bytes[10] ^= 1;
            let tampered = Signature::from_bytes(&bytes).unwrap();
            assert!(
                key.verifying_key()
                    .verify(SignatureContext::LogEntry, b"entry", &tampered)
                    .is_err()
            );
        }
    }

    #[test]
    fn keys_survive_encoding() {
        for key in both() {
            let restored = SigningKey::from_secret_bytes(&key.to_secret_bytes()).unwrap();
            assert_eq!(restored.verifying_key(), key.verifying_key());
        }
        assert_eq!(
            SigningKey::generate_ed25519()
                .verifying_key()
                .as_bytes()
                .len(),
            1 + 32
        );
        assert_eq!(
            SigningKey::generate_p256().verifying_key().as_bytes().len(),
            1 + 65
        );
    }

    #[test]
    fn rejects_invalid_encodings() {
        assert!(VerifyingKey::from_bytes(&[ALG_ED25519; 32]).is_err());
        assert!(
            VerifyingKey::from_bytes(&[[ALG_P256, 0x04].as_slice(), &[0u8; 64]].concat()).is_err()
        );
        assert!(VerifyingKey::from_bytes(&[[0x03].as_slice(), &[1u8; 32]].concat()).is_err());
        assert!(Signature::from_bytes(&[ALG_ED25519; 64]).is_err());
        assert!(SigningKey::from_secret_bytes(&[ALG_P256; 33]).is_ok());
        assert!(
            SigningKey::from_secret_bytes(&[[ALG_P256].as_slice(), &[0u8; 32]].concat()).is_err()
        );
    }

    #[test]
    fn signing_input_is_labelled() {
        assert_eq!(
            signing_input(SignatureContext::Record, b"x"),
            b"openvault v1 sig record\0x".to_vec()
        );
    }

    #[test]
    fn ecdsa_accepts_unnormalized_s() {
        // The Secure Enclave returns either s or n - s; both must verify.
        let key = SigningKey::generate_p256();
        let signature = key.sign(SignatureContext::Record, b"m");
        let parsed = p256::ecdsa::Signature::from_slice(&signature.as_bytes()[1..]).unwrap();
        let (r, s) = parsed.split_scalars();
        let flipped = p256::ecdsa::Signature::from_scalars(r, -s).unwrap();
        let flipped = Signature([&[ALG_P256][..], &flipped.to_bytes()].concat());
        assert_ne!(flipped, signature);
        key.verifying_key()
            .verify(SignatureContext::Record, b"m", &flipped)
            .unwrap();
    }

    #[test]
    fn hardware_encodings() {
        // What a hardware signer hands back: an SEC1 public key and a DER signature over
        // signing_input.
        let SigningKey::P256(key) = SigningKey::generate_p256() else {
            unreachable!()
        };
        let sec1 = key.verifying_key().to_sec1_point(false);
        let der: p256::ecdsa::DerSignature =
            key.sign(&signing_input(SignatureContext::Record, b"m"));

        let verifying = VerifyingKey::from_p256_sec1(sec1.as_bytes()).unwrap();
        let signature = Signature::from_p256_der(der.as_bytes()).unwrap();
        verifying
            .verify(SignatureContext::Record, b"m", &signature)
            .unwrap();
        assert!(Signature::from_p256_der(&der.as_bytes()[1..]).is_err());
        assert!(VerifyingKey::from_p256_sec1(&sec1.as_bytes()[1..]).is_err());
    }

    #[test]
    fn split_prefix() {
        for key in [SigningKey::generate_ed25519(), SigningKey::generate_p256()] {
            let key = key.verifying_key();
            let bytes = [key.as_bytes(), b"rest"].concat();
            assert_eq!(
                VerifyingKey::split_prefix(&bytes).unwrap(),
                (key.clone(), &b"rest"[..])
            );
            assert!(
                VerifyingKey::split_prefix(&key.as_bytes()[..key.as_bytes().len() - 1]).is_err()
            );
        }
        assert!(VerifyingKey::split_prefix(&[0x03; 40]).is_err());
        assert!(VerifyingKey::split_prefix(&[]).is_err());
    }
}
