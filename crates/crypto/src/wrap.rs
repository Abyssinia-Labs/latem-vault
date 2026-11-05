//! Wrapping collection keys to devices and the recovery key with HPKE (RFC 9180).
//!
//! Suite: base mode, DHKEM(X25519, HKDF-SHA256) or DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
//! ChaCha20-Poly1305. P-256 is for Secure Enclave and TPM keys; X25519 for keys kept in a file.
//! The HPKE `info` is `"openvault v1 wrap" || 0x00 || context`, where the caller's context
//! names what is being wrapped (vault, collection and epoch), so a wrapped key can't be
//! replayed into another collection or epoch.

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::{DhP256HkdfSha256, X25519HkdfSha256};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::{Error, SymmetricKey};

const INFO_LABEL: &[u8] = b"openvault v1 wrap\0";
const KEM_P256: u16 = 0x0010;
const KEM_X25519: u16 = 0x0020;
/// A wrapped 32-byte key plus the 16-byte ChaCha20-Poly1305 tag.
const WRAPPED_LEN: usize = 32 + 16;

type X25519 = X25519HkdfSha256;
type P256 = DhP256HkdfSha256;

/// The public half of a wrapping key: what a collection key is wrapped *to*.
///
/// Encoded as the RFC 9180 KEM id (2 bytes, big-endian) followed by the serialized public
/// key: 32 bytes for X25519, 65 bytes (uncompressed SEC1) for P-256.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WrapKey(Vec<u8>);

impl WrapKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (kem_id, public) = split_kem_id(bytes)?;
        let valid = match kem_id {
            KEM_X25519 => <X25519 as Kem>::PublicKey::from_bytes(public).is_ok(),
            KEM_P256 => <P256 as Kem>::PublicKey::from_bytes(public).is_ok(),
            _ => false,
        };
        valid
            .then(|| Self(bytes.to_vec()))
            .ok_or(Error::Encoding("wrapping key"))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Wraps `key` so only the holder of the matching [`UnwrapKey`] can recover it.
    pub fn wrap(&self, context: &[u8], key: &SymmetricKey) -> WrappedKey {
        let (kem_id, public) = split_kem_id(&self.0).expect("validated on construction");
        let info = info(context);
        let (enc, ciphertext) = match kem_id {
            KEM_X25519 => seal::<X25519>(public, &info, key),
            KEM_P256 => seal::<P256>(public, &info, key),
            _ => unreachable!("validated on construction"),
        };
        WrappedKey {
            kem_id,
            enc,
            ciphertext,
        }
    }

    fn from_public<K: Kem>(kem_id: u16, public: &K::PublicKey) -> Self {
        let mut bytes = kem_id.to_be_bytes().to_vec();
        bytes.extend_from_slice(&public.to_bytes());
        Self(bytes)
    }
}

/// A software wrapping key: the private half that unwraps collection keys.
pub enum UnwrapKey {
    X25519(<X25519 as Kem>::PrivateKey),
    P256(<P256 as Kem>::PrivateKey),
}

impl UnwrapKey {
    pub fn generate_x25519() -> Self {
        Self::X25519(X25519::gen_keypair().0)
    }

    pub fn generate_p256() -> Self {
        Self::P256(P256::gen_keypair().0)
    }

    /// Derives an X25519 key from secret input keying material (RFC 9180 `DeriveKeyPair`).
    pub fn derive_x25519(ikm: &[u8]) -> Self {
        Self::X25519(X25519::derive_keypair(ikm).0)
    }

    /// Restores a key from [`to_secret_bytes`](Self::to_secret_bytes).
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (kem_id, secret) = split_kem_id(bytes)?;
        let key = match kem_id {
            KEM_X25519 => <X25519 as Kem>::PrivateKey::from_bytes(secret).map(Self::X25519),
            KEM_P256 => <P256 as Kem>::PrivateKey::from_bytes(secret).map(Self::P256),
            _ => return Err(Error::Encoding("unwrapping key")),
        };
        key.map_err(|_| Error::Encoding("unwrapping key"))
    }

    /// The KEM id followed by the 32-byte private key, for a keystore file.
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let (kem_id, secret) = match self {
            Self::X25519(sk) => (KEM_X25519, sk.to_bytes().to_vec()),
            Self::P256(sk) => (KEM_P256, sk.to_bytes().to_vec()),
        };
        let secret = Zeroizing::new(secret);
        let mut bytes = Zeroizing::new(kem_id.to_be_bytes().to_vec());
        bytes.extend_from_slice(&secret);
        bytes
    }

    pub fn wrap_key(&self) -> WrapKey {
        match self {
            Self::X25519(sk) => WrapKey::from_public::<X25519>(KEM_X25519, &X25519::sk_to_pk(sk)),
            Self::P256(sk) => WrapKey::from_public::<P256>(KEM_P256, &P256::sk_to_pk(sk)),
        }
    }

    /// Recovers a key wrapped with the same `context`.
    pub fn unwrap(&self, context: &[u8], wrapped: &WrappedKey) -> Result<SymmetricKey, Error> {
        let info = info(context);
        let plaintext = match (self, wrapped.kem_id) {
            (Self::X25519(sk), KEM_X25519) => open::<X25519>(sk, &info, wrapped)?,
            (Self::P256(sk), KEM_P256) => open::<P256>(sk, &info, wrapped)?,
            _ => return Err(Error::Decrypt),
        };
        let bytes: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| Error::Decrypt)?;
        Ok(SymmetricKey::from_bytes(bytes))
    }
}

impl std::fmt::Debug for UnwrapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::X25519(_) => "UnwrapKey::X25519(..)",
            Self::P256(_) => "UnwrapKey::P256(..)",
        })
    }
}

/// A collection key wrapped to one recipient.
///
/// Encoded as the KEM id (2 bytes, big-endian), the encapsulated key (32 bytes for X25519,
/// 65 for P-256) and the 48-byte ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    kem_id: u16,
    enc: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl WrappedKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.kem_id.to_be_bytes()[..], &self.enc, &self.ciphertext].concat()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (kem_id, rest) = split_kem_id(bytes)?;
        let enc_len = match kem_id {
            KEM_X25519 => 32,
            KEM_P256 => 65,
            _ => return Err(Error::Encoding("wrapped key")),
        };
        if rest.len() != enc_len + WRAPPED_LEN {
            return Err(Error::Encoding("wrapped key"));
        }
        let (enc, ciphertext) = rest.split_at(enc_len);
        Ok(Self {
            kem_id,
            enc: enc.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
    }
}

fn info(context: &[u8]) -> Vec<u8> {
    [INFO_LABEL, context].concat()
}

fn split_kem_id(bytes: &[u8]) -> Result<(u16, &[u8]), Error> {
    match bytes {
        [a, b, rest @ ..] => Ok((u16::from_be_bytes([*a, *b]), rest)),
        _ => Err(Error::Encoding("key")),
    }
}

fn seal<K: Kem>(public: &[u8], info: &[u8], key: &SymmetricKey) -> (Vec<u8>, Vec<u8>) {
    let public = K::PublicKey::from_bytes(public).expect("validated on construction");
    let (enc, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeS::Base,
        &public,
        info,
        key.as_bytes(),
        &[],
    )
    .expect("HPKE sealing to a valid public key can't fail");
    (enc.to_bytes().to_vec(), ciphertext)
}

fn open<K: Kem>(
    secret: &K::PrivateKey,
    info: &[u8],
    wrapped: &WrappedKey,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let enc = K::EncappedKey::from_bytes(&wrapped.enc).map_err(|_| Error::Decrypt)?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeR::Base,
        secret,
        &enc,
        info,
        &wrapped.ciphertext,
        &[],
    )
    .map(Zeroizing::new)
    .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn both() -> [UnwrapKey; 2] {
        [UnwrapKey::generate_x25519(), UnwrapKey::generate_p256()]
    }

    #[test]
    fn round_trip() {
        for recipient in both() {
            let key = SymmetricKey::generate();
            let wrapped = recipient.wrap_key().wrap(b"collection 1 epoch 3", &key);
            let encoded = WrappedKey::from_bytes(&wrapped.to_bytes()).unwrap();
            let unwrapped = recipient.unwrap(b"collection 1 epoch 3", &encoded).unwrap();
            assert_eq!(unwrapped.as_bytes(), key.as_bytes());
        }
    }

    #[test]
    fn rejects_other_context_or_recipient() {
        for recipient in both() {
            let wrapped = recipient
                .wrap_key()
                .wrap(b"epoch 3", &SymmetricKey::generate());
            assert_eq!(
                recipient.unwrap(b"epoch 4", &wrapped).unwrap_err(),
                Error::Decrypt
            );
            for other in both() {
                assert_eq!(
                    other.unwrap(b"epoch 3", &wrapped).unwrap_err(),
                    Error::Decrypt
                );
            }
        }
    }

    #[test]
    fn rejects_tampering() {
        let recipient = UnwrapKey::generate_x25519();
        let bytes = recipient
            .wrap_key()
            .wrap(b"", &SymmetricKey::generate())
            .to_bytes();
        for i in 2..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[i] ^= 1;
            let wrapped = WrappedKey::from_bytes(&tampered).unwrap();
            assert!(recipient.unwrap(b"", &wrapped).is_err());
        }
        assert!(WrappedKey::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn keys_survive_encoding() {
        for recipient in both() {
            let restored = UnwrapKey::from_secret_bytes(&recipient.to_secret_bytes()).unwrap();
            assert_eq!(restored.wrap_key(), recipient.wrap_key());
            let public = recipient.wrap_key();
            assert_eq!(WrapKey::from_bytes(public.as_bytes()).unwrap(), public);
        }
        assert_eq!(
            UnwrapKey::generate_x25519().wrap_key().as_bytes().len(),
            2 + 32
        );
        assert_eq!(
            UnwrapKey::generate_p256().wrap_key().as_bytes().len(),
            2 + 65
        );
    }

    #[test]
    fn rejects_invalid_public_keys() {
        assert!(WrapKey::from_bytes(&[0x00, 0x10, 0x04]).is_err());
        assert!(
            WrapKey::from_bytes(&[[0x00, 0x10, 0x04].as_slice(), &[0u8; 64]].concat()).is_err()
        );
        assert!(WrapKey::from_bytes(&[[0x00, 0x21].as_slice(), &[1u8; 32]].concat()).is_err());
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = UnwrapKey::derive_x25519(&[1u8; 32]).wrap_key();
        assert_eq!(a, UnwrapKey::derive_x25519(&[1u8; 32]).wrap_key());
        assert_ne!(a, UnwrapKey::derive_x25519(&[2u8; 32]).wrap_key());
    }
}
