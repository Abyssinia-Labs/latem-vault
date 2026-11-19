//! Device keys in the Secure Enclave (keystore.md, Secure Enclave).
//!
//! The keys aren't stored in the keychain: a Secure Enclave key there needs a keychain access
//! group entitlement, which a binary built with cargo doesn't have (`SecKeyCreateRandomKey`
//! fails with -34018). Instead each key's token object id, an encrypted blob only this Mac's
//! Secure Enclave can use, goes in the key file, and `SecKeyCreateWithData` restores the key
//! from it. The blob is the same one CryptoKit exposes as `dataRepresentation`.

use core_foundation::base::{CFOptionFlags, CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::CFError;
use core_foundation::string::{CFString, CFStringRef};
use objc2::rc::Retained;
use objc2_foundation::NSString;
use objc2_local_authentication::LAContext;
use pinkvault_core::DeviceKeys;
use pinkvault_crypto::sign::signing_input;
use pinkvault_crypto::{
    Signature, SignatureContext, SymmetricKey, VerifyingKey, WrapKey, WrappedKey,
};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlPrivateKeyUsage, kSecAccessControlUserPresence,
};
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeyClassPublic, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave,
    kSecUseAuthenticationContext,
};
use security_framework_sys::key::SecKeyCreateWithData;
use zeroize::Zeroizing;

use crate::file::EnclaveBlobs;
use crate::{Error, Result};

/// `kSecAttrTokenOID`. Apple declares it only in its private `SecItemPriv.h`.
const TOKEN_OBJECT_ID: &str = "toid";
/// The HPKE context the local key is wrapped with (keystore.md).
const LOCAL_KEY_CONTEXT: &[u8] = b"device local key";

pub(crate) fn is_available() -> bool {
    EnclaveKey::generate().is_ok()
}

/// A new admin key: one that needs the user to be present, with Touch ID or the Mac's password,
/// for every signature, and is usable only while the Mac is unlocked (keystore.md, admin key).
/// Returns its verifying key and the blob that restores it.
pub(crate) fn generate_admin() -> Result<(VerifyingKey, Vec<u8>)> {
    let (key, blob) = EnclaveKey::generate_with(
        ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence,
    )?;
    Ok((VerifyingKey::from_p256_sec1(&key.public)?, blob))
}

/// The verifying key of the admin key in `blob`. Restoring the key doesn't ask for Touch ID;
/// only signing does.
pub(crate) fn admin_verifying_key(blob: &[u8]) -> Result<VerifyingKey> {
    Ok(VerifyingKey::from_p256_sec1(
        &EnclaveKey::restore(blob, None)?.public,
    )?)
}

/// The admin key in a blob, restored with one authentication context. Its first signature asks
/// for Touch ID or the password, with a dialog that shows the reason; later ones reuse that
/// authentication, so an approval that signs several things asks once (keystore.md, one
/// approval, one prompt).
pub(crate) struct AdminSigner {
    key: EnclaveKey,
    /// Kept for as long as the key, which signs through it.
    _context: Retained<LAContext>,
}

impl AdminSigner {
    pub(crate) fn new(blob: &[u8], reason: &str) -> Result<Self> {
        // SAFETY: a new LAContext has no preconditions, and the reason is copied when set.
        let context = unsafe {
            let context = LAContext::new();
            context.setLocalizedReason(&NSString::from_str(reason));
            context
        };
        let key = EnclaveKey::restore(blob, Some(&context))?;
        Ok(Self {
            key,
            _context: context,
        })
    }

    pub(crate) fn sign(&self, input: &[u8]) -> Result<Signature> {
        Ok(Signature::from_p256_der(&self.key.sign(input)?)?)
    }

    /// Asks for Touch ID or the password now, by signing [`PRESENCE`], so the signatures that
    /// follow don't ask (keystore.md, asking first).
    pub(crate) fn authenticate(&self) -> Result<()> {
        self.key.sign(PRESENCE).map(drop)
    }
}

/// What an admin key signs to ask for Touch ID ahead of the signatures that need it. Every
/// signature a device checks covers a context label first (`frozen::SIG_*`), so this one
/// can't pass for any of them, and it's dropped as soon as it's made.
const PRESENCE: &[u8] = pinkvault_crypto::frozen::ADMIN_PRESENCE;

/// A device's wrapping and signing keys in the Secure Enclave, plus its local key, which is
/// kept in the key file wrapped to the Secure Enclave wrapping key.
pub struct SecureEnclaveKeys {
    wrapping: EnclaveKey,
    signing: EnclaveKey,
    wrap_key: WrapKey,
    verifying_key: VerifyingKey,
    local: SymmetricKey,
}

impl SecureEnclaveKeys {
    pub(crate) fn generate() -> Result<EnclaveBlobs> {
        let (wrapping, wrapping_blob) = EnclaveKey::generate()?;
        let (_, signing_blob) = EnclaveKey::generate()?;
        let wrap_key = WrapKey::from_p256_sec1(&wrapping.public)?;
        Ok(EnclaveBlobs {
            wrapping: wrapping_blob,
            signing: signing_blob,
            local: wrap_key.wrap(LOCAL_KEY_CONTEXT, &SymmetricKey::generate()),
        })
    }

    pub(crate) fn restore(blobs: &EnclaveBlobs) -> Result<Self> {
        let wrapping = EnclaveKey::restore(&blobs.wrapping, None)?;
        let signing = EnclaveKey::restore(&blobs.signing, None)?;
        let wrap_key = WrapKey::from_p256_sec1(&wrapping.public)?;
        let verifying_key = VerifyingKey::from_p256_sec1(&signing.public)?;
        let local = blobs
            .local
            .unwrap_with(&wrap_key, LOCAL_KEY_CONTEXT, |peer| wrapping.ecdh(peer))?;
        Ok(Self {
            wrapping,
            signing,
            wrap_key,
            verifying_key,
            local,
        })
    }
}

impl DeviceKeys for SecureEnclaveKeys {
    fn wrap_key(&self) -> WrapKey {
        self.wrap_key.clone()
    }

    fn unwrap(&self, context: &[u8], wrapped: &WrappedKey) -> pinkvault_core::Result<SymmetricKey> {
        wrapped.unwrap_with(&self.wrap_key, context, |peer| {
            Ok(self.wrapping.ecdh(peer)?)
        })
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key.clone()
    }

    fn sign(&self, context: SignatureContext, message: &[u8]) -> pinkvault_core::Result<Signature> {
        let der = self.signing.sign(&signing_input(context, message))?;
        Ok(Signature::from_p256_der(&der)?)
    }

    fn local_key(&self) -> &SymmetricKey {
        &self.local
    }
}

/// A P-256 private key in the Secure Enclave and its public key (uncompressed SEC1).
struct EnclaveKey {
    key: SecKey,
    public: Vec<u8>,
}

impl EnclaveKey {
    /// A new device key, usable after the Mac's first unlock since boot, and the blob that
    /// restores it.
    fn generate() -> Result<(Self, Vec<u8>)> {
        Self::generate_with(
            ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAccessControlPrivateKeyUsage,
        )
    }

    fn generate_with(protection: ProtectionMode, flags: CFOptionFlags) -> Result<(Self, Vec<u8>)> {
        let access = SecAccessControl::create_with_protection(Some(protection), flags)
            .map_err(|e| Error::SecureEnclave(e.to_string()))?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_access_control(access);
        let key = SecKey::new(&options).map_err(cf_error)?;
        let blob = key
            .attributes()
            .find(CFString::from_static_string(TOKEN_OBJECT_ID).as_CFTypeRef())
            .and_then(|value| unsafe { CFType::wrap_under_get_rule(*value) }.downcast::<CFData>())
            .ok_or(Error::SecureEnclave(
                "the new key has no token object id".into(),
            ))?
            .to_vec();
        Ok((Self::from_key(key)?, blob))
    }

    /// Restores a key from its blob. A `context` is used when the key asks for the user, and
    /// sets what the dialog says.
    fn restore(blob: &[u8], context: Option<&Retained<LAContext>>) -> Result<Self> {
        let mut attributes = vec![
            (
                unsafe { kSecAttrKeyClass },
                cf(unsafe { kSecAttrKeyClassPrivate }).into_CFType(),
            ),
            (
                unsafe { kSecAttrTokenID },
                cf(unsafe { kSecAttrTokenIDSecureEnclave }).into_CFType(),
            ),
        ];
        if let Some(context) = context {
            // SAFETY: an LAContext is an Objective-C object, which CFRetain and CFRelease
            // manage like any CF type; the CFType holds its own reference.
            let context = unsafe { CFType::wrap_under_get_rule(Retained::as_ptr(context).cast()) };
            attributes.push((unsafe { kSecUseAuthenticationContext }, context));
        }
        let key = create_key(&[], &attributes, Some(blob))?;
        Self::from_key(key)
    }

    fn from_key(key: SecKey) -> Result<Self> {
        let public = key
            .public_key()
            .and_then(|public| public.external_representation())
            .ok_or(Error::SecureEnclave("can't export the public key".into()))?
            .to_vec();
        Ok(Self { key, public })
    }

    /// The x-coordinate of the shared point with `peer` (uncompressed SEC1).
    fn ecdh(&self, peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>> {
        let peer = create_key(
            peer,
            &[(
                unsafe { kSecAttrKeyClass },
                cf(unsafe { kSecAttrKeyClassPublic }).into_CFType(),
            )],
            None,
        )?;
        let shared = Zeroizing::new(
            self.key
                .key_exchange(Algorithm::ECDHKeyExchangeStandard, &peer, 32, None)
                .map_err(cf_error)?,
        );
        <[u8; 32]>::try_from(shared.as_slice())
            .map(Zeroizing::new)
            .map_err(|_| Error::SecureEnclave("unexpected ECDH result length".into()))
    }

    /// A DER-encoded ECDSA signature over SHA-256 of `input`.
    fn sign(&self, input: &[u8]) -> Result<Vec<u8>> {
        self.key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, input)
            .map_err(cf_error)
    }
}

/// `SecKeyCreateWithData` for a P-256 key with the given extra attributes, and the token
/// object id when restoring a Secure Enclave key.
fn create_key(
    data: &[u8],
    attributes: &[(CFStringRef, CFType)],
    token_object_id: Option<&[u8]>,
) -> Result<SecKey> {
    let mut pairs: Vec<(CFString, CFType)> = vec![(
        cf(unsafe { kSecAttrKeyType }),
        cf(unsafe { kSecAttrKeyTypeECSECPrimeRandom }).into_CFType(),
    )];
    pairs.extend(
        attributes
            .iter()
            .map(|(name, value)| (cf(*name), value.clone())),
    );
    if let Some(blob) = token_object_id {
        pairs.push((
            CFString::from_static_string(TOKEN_OBJECT_ID),
            CFData::from_buffer(blob).into_CFType(),
        ));
    }
    let attributes = CFDictionary::from_CFType_pairs(&pairs);
    let data = CFData::from_buffer(data);
    let mut error = std::ptr::null_mut();
    let key = unsafe {
        SecKeyCreateWithData(
            data.as_concrete_TypeRef(),
            attributes.as_concrete_TypeRef(),
            &mut error,
        )
    };
    if !key.is_null() {
        Ok(unsafe { SecKey::wrap_under_create_rule(key) })
    } else if !error.is_null() {
        Err(cf_error(unsafe { CFError::wrap_under_create_rule(error) }))
    } else {
        Err(Error::SecureEnclave("SecKeyCreateWithData failed".into()))
    }
}

fn cf(name: CFStringRef) -> CFString {
    unsafe { CFString::wrap_under_get_rule(name) }
}

fn cf_error(error: CFError) -> Error {
    Error::SecureEnclave(error.description().to_string())
}
