//! Wrapping collection keys to devices and the recovery key with HPKE (RFC 9180).
//!
//! Suite: base mode, DHKEM(X25519, HKDF-SHA256) or DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
//! ChaCha20-Poly1305. P-256 is for Secure Enclave and TPM keys; X25519 for keys kept in a file.
//! The HPKE `info` is `frozen::WRAP_INFO || context` (the label ends in 0x00), where the caller's context
//! names what is being wrapped (vault, collection and epoch), so a wrapped key can't be
//! replayed into another collection or epoch.
//!
//! Hardware keys can't hand their private key to the `hpke` crate, so
//! [`WrappedKey::unwrap_with`] asks the hardware for the ECDH result only and runs the rest of
//! RFC 9180 here.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, Nonce};
use hkdf::{Hkdf, HkdfExtract};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::{DhP256HkdfSha256, X25519HkdfSha256};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, SymmetricKey};

const INFO_LABEL: &[u8] = crate::frozen::WRAP_INFO;
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

    /// A P-256 wrapping key from its uncompressed SEC1 encoding, as hardware keystores
    /// export it.
    pub fn from_p256_sec1(public: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(&[&KEM_P256.to_be_bytes()[..], public].concat())
    }

    /// Parses a key at the start of `bytes`, for formats that embed one without a length,
    /// and returns it with the bytes after it.
    pub fn split_prefix(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let len = match split_kem_id(bytes) {
            Ok((KEM_X25519, _)) => 2 + 32,
            Ok((KEM_P256, _)) => 2 + 65,
            _ => return Err(Error::Encoding("wrapping key")),
        };
        let (key, rest) = bytes
            .split_at_checked(len)
            .ok_or(Error::Encoding("wrapping key"))?;
        Ok((Self::from_bytes(key)?, rest))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The RFC 9180 KEM id: `0x0020` for X25519, `0x0010` for P-256.
    pub fn kem_id(&self) -> u16 {
        split_kem_id(&self.0).expect("validated on construction").0
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
        to_key(&plaintext)
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

    /// Parses a wrapped key at the start of `bytes`, for formats that embed one without a
    /// length, and returns it with the bytes after it.
    pub fn split_prefix(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let len = match split_kem_id(bytes) {
            Ok((KEM_X25519, _)) => 2 + 32 + WRAPPED_LEN,
            Ok((KEM_P256, _)) => 2 + 65 + WRAPPED_LEN,
            _ => return Err(Error::Encoding("wrapped key")),
        };
        let (wrapped, rest) = bytes
            .split_at_checked(len)
            .ok_or(Error::Encoding("wrapped key"))?;
        Ok((Self::from_bytes(wrapped)?, rest))
    }

    /// The KEM id of the key this was wrapped to, as [`WrapKey::kem_id`].
    pub fn kem_id(&self) -> u16 {
        self.kem_id
    }

    /// Unwraps with a P-256 key held in hardware (the Secure Enclave or a TPM), whose public
    /// half is `recipient`. Gives the same result as [`UnwrapKey::unwrap`].
    ///
    /// `ecdh` receives the sender's ephemeral public key (uncompressed SEC1, already checked
    /// to be on the curve) and returns the x-coordinate of the shared point.
    pub fn unwrap_with<E: From<Error>>(
        &self,
        recipient: &WrapKey,
        context: &[u8],
        ecdh: impl FnOnce(&[u8; 65]) -> Result<Zeroizing<[u8; 32]>, E>,
    ) -> Result<SymmetricKey, E> {
        let (kem_id, public) = split_kem_id(&recipient.0).expect("validated on construction");
        if kem_id != KEM_P256 || self.kem_id != KEM_P256 {
            return Err(Error::Decrypt.into());
        }
        let plaintext = open_p256_with(
            public,
            &self.enc,
            &info(context),
            &[],
            &self.ciphertext,
            ecdh,
        )?;
        Ok(to_key(&plaintext)?)
    }
}

fn info(context: &[u8]) -> Vec<u8> {
    [INFO_LABEL, context].concat()
}

fn to_key(plaintext: &[u8]) -> Result<SymmetricKey, Error> {
    let bytes: [u8; 32] = plaintext.try_into().map_err(|_| Error::Decrypt)?;
    Ok(SymmetricKey::from_bytes(bytes))
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

/// HPKE base-mode `Open` for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305
/// (RFC 9180 §4.1, §5.1), with the ECDH step done by the caller. `public` is the recipient's
/// uncompressed SEC1 key. Checked against the RFC's test vector A.5.1.
fn open_p256_with<E: From<Error>>(
    public: &[u8],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    ecdh: impl FnOnce(&[u8; 65]) -> Result<Zeroizing<[u8; 32]>, E>,
) -> Result<Zeroizing<Vec<u8>>, E> {
    const KEM_SUITE: &[u8] = b"KEM\x00\x10";
    const HPKE_SUITE: &[u8] = b"HPKE\x00\x10\x00\x01\x00\x03";

    let enc: &[u8; 65] = enc.try_into().map_err(|_| Error::Decrypt)?;
    if <P256 as Kem>::PublicKey::from_bytes(enc).is_err() {
        return Err(Error::Decrypt.into());
    }
    let dh = ecdh(enc)?;

    // Decap: ExtractAndExpand(dh, enc || pkRm).
    let eae_prk = labeled_extract(KEM_SUITE, &[], b"eae_prk", &*dh);
    let shared_secret = labeled_expand::<32>(&eae_prk, KEM_SUITE, b"shared_secret", &[enc, public]);

    // KeySchedule in base mode: no PSK.
    let psk_id_hash = labeled_extract(HPKE_SUITE, &[], b"psk_id_hash", &[]);
    let info_hash = labeled_extract(HPKE_SUITE, &[], b"info_hash", info);
    let context: [&[u8]; 3] = [&[0x00], &*psk_id_hash, &*info_hash];
    let secret = labeled_extract(HPKE_SUITE, &*shared_secret, b"secret", &[]);
    let key = labeled_expand::<32>(&secret, HPKE_SUITE, b"key", &context);
    let base_nonce = labeled_expand::<12>(&secret, HPKE_SUITE, b"base_nonce", &context);

    // The first message's nonce is base_nonce itself.
    chacha20poly1305::ChaCha20Poly1305::new(&(*key).into())
        .decrypt(
            &Nonce::from(*base_nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt.into())
}

fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut extract = HkdfExtract::<Sha256>::new(Some(salt));
    for part in [b"HPKE-v1", suite, label, ikm] {
        extract.input_ikm(part);
    }
    Zeroizing::new(extract.finalize().0.into())
}

fn labeled_expand<const N: usize>(
    prk: &[u8; 32],
    suite: &[u8],
    label: &[u8],
    info: &[&[u8]],
) -> Zeroizing<[u8; N]> {
    let length = u16::try_from(N)
        .expect("HPKE output lengths fit in u16")
        .to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![&length, b"HPKE-v1", suite, label];
    parts.extend_from_slice(info);
    let mut okm = Zeroizing::new([0u8; N]);
    Hkdf::<Sha256>::from_prk(prk)
        .expect("a 32-byte PRK is valid for SHA-256")
        .expand_multi_info(&parts, okm.as_mut())
        .expect("HPKE output lengths are within HKDF's limit");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ECDH with a software P-256 key, standing in for the Secure Enclave.
    fn software_ecdh(
        secret: &[u8],
    ) -> impl FnOnce(&[u8; 65]) -> Result<Zeroizing<[u8; 32]>, Error> {
        let secret = p256::SecretKey::from_slice(secret).unwrap();
        move |peer| {
            let peer = p256::PublicKey::from_sec1_bytes(peer).unwrap();
            let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
            Ok(Zeroizing::new(
                shared.raw_secret_bytes().as_slice().try_into().unwrap(),
            ))
        }
    }

    #[test]
    fn external_ecdh_matches_rfc_9180_vector() {
        // RFC 9180 A.5.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, base mode.
        let h = |s: &str| hex::decode(s).unwrap();
        let sk_rm = h("a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b");
        let pk_rm = h(concat!(
            "04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f",
            "40bad9bb726f68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a006"
        ));
        let enc = h(concat!(
            "04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824",
            "fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291"
        ));
        let info = h("4f6465206f6e2061204772656369616e2055726e");
        let aad = h("436f756e742d30");
        let ct = h(concat!(
            "6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4",
            "ccb0d057f03ea2952a27bb458b"
        ));
        let pt = open_p256_with(&pk_rm, &enc, &info, &aad, &ct, software_ecdh(&sk_rm)).unwrap();
        assert_eq!(
            *pt,
            h("4265617574792069732074727574682c20747275746820626561757479")
        );
    }

    #[test]
    fn external_ecdh_unwraps_like_software() {
        let recipient = UnwrapKey::generate_p256();
        let secret = &recipient.to_secret_bytes()[2..];
        let key = SymmetricKey::generate();
        let wrapped = recipient.wrap_key().wrap(b"epoch 3", &key);
        let public = WrapKey::from_p256_sec1(&recipient.wrap_key().as_bytes()[2..]).unwrap();
        assert_eq!(public, recipient.wrap_key());

        let unwrapped = wrapped
            .unwrap_with(&public, b"epoch 3", software_ecdh(secret))
            .unwrap();
        assert_eq!(unwrapped.as_bytes(), key.as_bytes());
        assert_eq!(
            wrapped
                .unwrap_with(&public, b"epoch 4", software_ecdh(secret))
                .unwrap_err(),
            Error::Decrypt
        );

        let x25519 = UnwrapKey::generate_x25519().wrap_key();
        let other = x25519.wrap(b"epoch 3", &key);
        assert_eq!(
            other
                .unwrap_with(&public, b"epoch 3", software_ecdh(secret))
                .unwrap_err(),
            Error::Decrypt
        );
        assert_eq!(
            wrapped
                .unwrap_with(&x25519, b"epoch 3", software_ecdh(secret))
                .unwrap_err(),
            Error::Decrypt
        );
    }

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

    #[test]
    fn split_prefix() {
        for key in [UnwrapKey::generate_x25519(), UnwrapKey::generate_p256()] {
            let key = key.wrap_key();
            let bytes = [key.as_bytes(), b"rest"].concat();
            assert_eq!(
                WrapKey::split_prefix(&bytes).unwrap(),
                (key.clone(), &b"rest"[..])
            );
            assert!(WrapKey::split_prefix(&key.as_bytes()[..key.as_bytes().len() - 1]).is_err());
        }
        assert!(WrapKey::split_prefix(&[0x00, 0x21, 1, 2, 3]).is_err());
        assert!(WrapKey::split_prefix(&[0x00]).is_err());
    }

    #[test]
    fn split_wrapped_prefix() {
        for (key, len) in [
            (UnwrapKey::generate_x25519(), 82),
            (UnwrapKey::generate_p256(), 115),
        ] {
            let wrapped = key.wrap_key().wrap(b"ctx", &SymmetricKey::generate());
            assert_eq!(wrapped.kem_id(), key.wrap_key().kem_id());
            let bytes = [&wrapped.to_bytes()[..], b"rest"].concat();
            assert_eq!(bytes.len(), len + 4);
            assert_eq!(
                WrappedKey::split_prefix(&bytes).unwrap(),
                (wrapped, &b"rest"[..])
            );
            assert!(WrappedKey::split_prefix(&bytes[..len - 1]).is_err());
        }
        assert!(WrappedKey::split_prefix(&[0x00, 0x21, 1, 2, 3]).is_err());
    }
}
