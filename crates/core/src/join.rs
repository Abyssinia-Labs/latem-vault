//! The joiner's request (join.md, messages): its device id, public keys, platform and name,
//! signed by its signing key over the session id, which shows it holds that key in this session.

use openvault_crypto::{Signature, SignatureContext, SigningKey, VerifyingKey, WrapKey};

use crate::membership::DeviceName;
use crate::{DeviceId, DeviceKeys, Error, Result, transport_seed};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequest {
    pub device: DeviceId,
    pub verifying_key: VerifyingKey,
    pub wrap_key: WrapKey,
    /// Must be the joiner's iroh endpoint id, which the connection checks.
    pub transport_key: VerifyingKey,
    pub name: DeviceName,
    /// The fields above, encoded, which the signature covers after the session id.
    fields: Vec<u8>,
    signature: Signature,
}

impl JoinRequest {
    /// The request from `device`, whose keys are `keys`, in the session `session_id`.
    pub fn sign(
        session_id: &[u8; 32],
        device: DeviceId,
        keys: &impl DeviceKeys,
        name: DeviceName,
    ) -> Result<Self> {
        name.check()?;
        let transport_key = SigningKey::from_ed25519_seed(&transport_seed(keys)).verifying_key();
        let (verifying_key, wrap_key) = (keys.verifying_key(), keys.wrap_key());
        let mut fields = [
            &device.as_bytes()[..],
            verifying_key.as_bytes(),
            wrap_key.as_bytes(),
            transport_key.as_bytes(),
        ]
        .concat();
        for text in [&name.platform, &name.name] {
            fields.push(u8::try_from(text.len()).expect("checked against the name rules"));
            fields.extend_from_slice(text.as_bytes());
        }
        let signature = keys.sign(
            SignatureContext::JoinRequest,
            &[&session_id[..], &fields].concat(),
        )?;
        Ok(Self {
            device,
            verifying_key,
            wrap_key,
            transport_key,
            name,
            fields,
            signature,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.fields[..], self.signature.as_bytes()].concat()
    }

    /// Decodes a request and checks its fields. [`verify`](Self::verify) checks the signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let invalid = || Error::InvalidJoin("bad request encoding");
        let (device, rest) = bytes.split_first_chunk::<16>().ok_or_else(invalid)?;
        let (verifying_key, rest) = VerifyingKey::split_prefix(rest)?;
        let (wrap_key, rest) = WrapKey::split_prefix(rest)?;
        let (transport_key, rest) = VerifyingKey::split_prefix(rest)?;
        if !transport_key.is_ed25519() {
            return Err(Error::InvalidJoin("the transport key must be Ed25519"));
        }
        let mut rest = rest;
        let mut text = || {
            let (&len, after) = rest.split_first().ok_or_else(invalid)?;
            let (bytes, after) = after.split_at_checked(len.into()).ok_or_else(invalid)?;
            rest = after;
            String::from_utf8(bytes.to_vec()).map_err(|_| invalid())
        };
        let name = DeviceName {
            platform: text()?,
            name: text()?,
        };
        name.check()?;
        let fields_len = bytes.len() - rest.len();
        let signature = Signature::from_bytes(rest)?;
        Ok(Self {
            device: DeviceId::from_bytes(*device),
            verifying_key,
            wrap_key,
            transport_key,
            name,
            fields: bytes[..fields_len].to_vec(),
            signature,
        })
    }

    /// Checks that the request's signing key signed it in the session `session_id`.
    pub fn verify(&self, session_id: &[u8; 32]) -> Result<()> {
        self.verifying_key
            .verify(
                SignatureContext::JoinRequest,
                &[&session_id[..], &self.fields].concat(),
                &self.signature,
            )
            .map_err(|_| Error::InvalidJoin("the request's signature doesn't verify"))
    }

    /// Whether the request has a hardware signing key (P-256), shown to the admin as `hardware`.
    pub fn is_hardware(&self) -> bool {
        !self.verifying_key.is_ed25519()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SoftwareKeys;

    #[test]
    fn requests_round_trip_and_bind_the_session() {
        let keys = SoftwareKeys::generate();
        let device = DeviceId::random();
        let name = DeviceName {
            platform: "linux".into(),
            name: "Desktop".into(),
        };
        let request = JoinRequest::sign(&[7; 32], device, &keys, name.clone()).unwrap();
        let decoded = JoinRequest::from_bytes(&request.to_bytes()).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(decoded.name, name);
        assert_eq!(decoded.wrap_key, keys.wrap_key());
        decoded.verify(&[7; 32]).unwrap();
        assert!(decoded.verify(&[8; 32]).is_err(), "another session");
        assert!(!decoded.is_hardware());

        let bytes = request.to_bytes();
        assert!(JoinRequest::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        assert!(
            JoinRequest::from_bytes(&tampered)
                .unwrap()
                .verify(&[7; 32])
                .is_err()
        );

        let bad_name = DeviceName {
            platform: "Linux!".into(),
            name: "Desktop".into(),
        };
        assert!(JoinRequest::sign(&[7; 32], device, &keys, bad_name).is_err());
    }
}
