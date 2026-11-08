//! Immutable, signed, sealed records (records.md, records).

use openvault_crypto::hash::{self, Hash, contexts};
use openvault_crypto::{Signature, SignatureContext, SymmetricKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::{CollectionId, DeviceId, DeviceKeys, Error, Result, names};

const FORMAT: u8 = 0x01;
const FLAG_DELETED: u8 = 0x01;
pub const HEADER_LEN: usize = 78;
/// The header bytes before `body_hash`: the body's AAD.
const AAD_LEN: usize = 46;
const SIGNATURE_LEN: usize = 65;
pub const MAX_VALUE_LEN: usize = 1 << 20;

pub type RecordId = [u8; 32];

/// A record's version: the greatest `(lamport, device)` for a name is current.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub lamport: u64,
    pub device: DeviceId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Secret,
    Var,
    /// The collection's own entry: an empty name, whose value is the collection's name.
    Collection,
}

impl Kind {
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Secret => 0x01,
            Self::Var => 0x02,
            Self::Collection => 0x10,
        }
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::Secret),
            0x02 => Some(Self::Var),
            0x10 => Some(Self::Collection),
            _ => None,
        }
    }
}

/// The cleartext header. Devices with `hold` scope sync on headers alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub collection: CollectionId,
    pub epoch: u32,
    pub version: Version,
    pub deleted: bool,
    pub body_hash: Hash,
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        [
            &[FORMAT][..],
            self.collection.as_bytes(),
            &self.epoch.to_be_bytes(),
            &self.version.lamport.to_be_bytes(),
            self.version.device.as_bytes(),
            &[if self.deleted { FLAG_DELETED } else { 0 }],
            &self.body_hash,
        ]
        .concat()
        .try_into()
        .expect("fields add up to the header length")
    }

    fn decode(bytes: &[u8; HEADER_LEN]) -> Result<Self> {
        if bytes[0] != FORMAT {
            return Err(Error::InvalidRecord("unknown format"));
        }
        let flags = bytes[45];
        if flags & !FLAG_DELETED != 0 {
            return Err(Error::InvalidRecord("unknown flags"));
        }
        let field = |range: std::ops::Range<usize>| &bytes[range];
        Ok(Self {
            collection: CollectionId::try_from(field(1..17))?,
            epoch: u32::from_be_bytes(field(17..21).try_into().expect("4 bytes")),
            version: Version {
                lamport: u64::from_be_bytes(field(21..29).try_into().expect("8 bytes")),
                device: DeviceId::try_from(field(29..45))?,
            },
            deleted: flags & FLAG_DELETED != 0,
            body_hash: field(46..78).try_into().expect("32 bytes"),
        })
    }
}

/// A record's plaintext.
pub struct Body {
    pub kind: Kind,
    pub name: String,
    pub value: Zeroizing<Vec<u8>>,
}

impl Body {
    pub fn new(kind: Kind, name: &str, value: &[u8]) -> Self {
        Self {
            kind,
            name: name.to_owned(),
            value: Zeroizing::new(value.to_vec()),
        }
    }

    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let name = u16::try_from(self.name.len()).expect("checked against the name rules");
        let value = u32::try_from(self.value.len()).expect("checked against MAX_VALUE_LEN");
        let mut out = Zeroizing::new(Vec::with_capacity(7 + self.name.len() + self.value.len()));
        out.push(self.kind.code());
        out.extend_from_slice(&name.to_be_bytes());
        out.extend_from_slice(self.name.as_bytes());
        out.extend_from_slice(&value.to_be_bytes());
        out.extend_from_slice(&self.value);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        const MALFORMED: Error = Error::InvalidRecord("malformed body");
        let (&kind, rest) = bytes.split_first().ok_or(MALFORMED)?;
        let kind = Kind::from_code(kind).ok_or(Error::InvalidRecord("unknown kind"))?;
        let (name_len, rest) = rest.split_first_chunk::<2>().ok_or(MALFORMED)?;
        let (name, rest) = rest
            .split_at_checked(u16::from_be_bytes(*name_len).into())
            .ok_or(MALFORMED)?;
        let (value_len, value) = rest.split_first_chunk::<4>().ok_or(MALFORMED)?;
        if value.len() != u32::from_be_bytes(*value_len) as usize {
            return Err(MALFORMED);
        }
        let name =
            std::str::from_utf8(name).map_err(|_| Error::InvalidRecord("name isn't UTF-8"))?;
        Ok(Self::new(kind, name, value))
    }

    fn check(&self, deleted: bool) -> Result<()> {
        if self.value.len() > MAX_VALUE_LEN {
            return Err(Error::ValueTooLarge);
        }
        if deleted && !self.value.is_empty() {
            return Err(Error::InvalidRecord("deleted record has a value"));
        }
        match self.kind {
            Kind::Collection if !self.name.is_empty() => {
                Err(Error::InvalidRecord("collection entry has a name"))
            }
            Kind::Collection if deleted => Ok(()),
            Kind::Collection => std::str::from_utf8(&self.value)
                .map_err(|_| Error::InvalidRecord("collection name isn't UTF-8"))
                .and_then(names::check_collection),
            Kind::Secret | Kind::Var => names::check_entry(&self.name),
        }
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Body")
            .field("kind", &self.kind)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// A signed, sealed record, as stored and synced: `header ‖ signature ‖ sealed body`.
#[derive(Clone)]
pub struct Record {
    header: Header,
    header_bytes: [u8; HEADER_LEN],
    signature: Signature,
    sealed: Vec<u8>,
}

impl Record {
    pub fn seal(
        collection: CollectionId,
        epoch: u32,
        version: Version,
        deleted: bool,
        body: &Body,
        key: &SymmetricKey,
        author: &impl DeviceKeys,
    ) -> Result<Self> {
        body.check(deleted)?;
        let mut header = Header {
            collection,
            epoch,
            version,
            deleted,
            body_hash: [0; 32],
        };
        let sealed = key.seal(&header.encode()[..AAD_LEN], &body.encode());
        header.body_hash = hash::hash(&sealed);
        let header_bytes = header.encode();
        let signature = author.sign(SignatureContext::Record, &header_bytes)?;
        Ok(Self {
            header,
            header_bytes,
            signature,
            sealed,
        })
    }

    /// Parses a record and checks its body hash. The signature is checked by [`open`](Self::open).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (header_bytes, rest) = bytes
            .split_first_chunk::<HEADER_LEN>()
            .ok_or(Error::InvalidRecord("too short"))?;
        let (signature, sealed) = rest
            .split_at_checked(SIGNATURE_LEN)
            .ok_or(Error::InvalidRecord("too short"))?;
        let header = Header::decode(header_bytes)?;
        if hash::hash(sealed) != header.body_hash {
            return Err(Error::InvalidRecord("body doesn't match its hash"));
        }
        Ok(Self {
            header,
            header_bytes: *header_bytes,
            signature: Signature::from_bytes(signature)?,
            sealed: sealed.to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [
            &self.header_bytes[..],
            self.signature.as_bytes(),
            &self.sealed,
        ]
        .concat()
    }

    /// Covers the header, and the body through its hash, but not the signature.
    pub fn id(&self) -> RecordId {
        *hash::derive_key(contexts::RECORD_ID, &self.header_bytes)
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Checks the author's signature over the header.
    pub fn verify(&self, author: &VerifyingKey) -> Result<()> {
        author
            .verify(
                SignatureContext::Record,
                &self.header_bytes,
                &self.signature,
            )
            .map_err(|_| Error::InvalidRecord("the signature doesn't verify"))
    }

    /// Checks the author's signature, then decrypts and checks the body.
    pub fn open(&self, author: &VerifyingKey, key: &SymmetricKey) -> Result<Body> {
        self.verify(author)?;
        let plaintext = key.open(&self.header_bytes[..AAD_LEN], &self.sealed)?;
        let body = Body::decode(&plaintext)?;
        body.check(self.header.deleted)?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SoftwareKeys;

    fn sample(keys: &SoftwareKeys, key: &SymmetricKey, deleted: bool) -> Record {
        let value: &[u8] = if deleted {
            b""
        } else {
            b"https://sentry.example"
        };
        let version = Version {
            lamport: 7,
            device: DeviceId::random(),
        };
        let body = Body::new(Kind::Var, "prod/SENTRY_DSN", value);
        Record::seal(
            CollectionId::random(),
            2,
            version,
            deleted,
            &body,
            key,
            keys,
        )
        .unwrap()
    }

    #[test]
    fn round_trip() {
        let (keys, key) = (SoftwareKeys::generate(), SymmetricKey::generate());
        let record = sample(&keys, &key, false);
        let bytes = record.to_bytes();
        let parsed = Record::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.header(), record.header());
        assert_eq!(parsed.id(), record.id());
        assert_eq!(parsed.header().epoch, 2);

        let body = parsed.open(&keys.verifying_key(), &key).unwrap();
        assert_eq!(
            (body.kind, body.name.as_str()),
            (Kind::Var, "prod/SENTRY_DSN")
        );
        assert_eq!(body.value.as_slice(), b"https://sentry.example");
    }

    #[test]
    fn deleted_records_have_no_value() {
        let (keys, key) = (SoftwareKeys::generate(), SymmetricKey::generate());
        let record = sample(&keys, &key, true);
        assert!(record.header().deleted);
        assert!(
            record
                .open(&keys.verifying_key(), &key)
                .unwrap()
                .value
                .is_empty()
        );

        let body = Body::new(Kind::Var, "x", b"value");
        let version = Version {
            lamport: 1,
            device: DeviceId::random(),
        };
        let sealed = Record::seal(CollectionId::random(), 0, version, true, &body, &key, &keys);
        assert!(matches!(sealed, Err(Error::InvalidRecord(_))));
    }

    #[test]
    fn rejects_tampering() {
        let (keys, key) = (SoftwareKeys::generate(), SymmetricKey::generate());
        let bytes = sample(&keys, &key, false).to_bytes();

        // Any change to the header fails the signature (or the format check).
        for i in 0..HEADER_LEN {
            let mut tampered = bytes.clone();
            tampered[i] ^= 1;
            let opened =
                Record::from_bytes(&tampered).and_then(|r| r.open(&keys.verifying_key(), &key));
            assert!(opened.is_err(), "header byte {i}");
        }
        // Any change to the body fails its hash.
        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(Record::from_bytes(&tampered).is_err());
        assert!(Record::from_bytes(&bytes[..HEADER_LEN + 10]).is_err());
    }

    #[test]
    fn rejects_wrong_author_or_key() {
        let (keys, key) = (SoftwareKeys::generate(), SymmetricKey::generate());
        let record = sample(&keys, &key, false);
        let other = SoftwareKeys::generate();
        assert!(record.open(&other.verifying_key(), &key).is_err());
        assert!(
            record
                .open(&keys.verifying_key(), &SymmetricKey::generate())
                .is_err()
        );
    }

    #[test]
    fn checks_names_and_sizes() {
        let (keys, key) = (SoftwareKeys::generate(), SymmetricKey::generate());
        let version = Version {
            lamport: 1,
            device: DeviceId::random(),
        };
        let seal = |body: Body| {
            Record::seal(
                CollectionId::random(),
                0,
                version,
                false,
                &body,
                &key,
                &keys,
            )
        };

        assert!(seal(Body::new(Kind::Secret, "a//b", b"v")).is_err());
        assert!(seal(Body::new(Kind::Collection, "", b"latem-cloud")).is_ok());
        assert!(seal(Body::new(Kind::Collection, "x", b"latem-cloud")).is_err());
        assert!(seal(Body::new(Kind::Collection, "", b"bad name")).is_err());
        assert!(matches!(
            seal(Body::new(Kind::Secret, "big", &vec![0; MAX_VALUE_LEN + 1])),
            Err(Error::ValueTooLarge)
        ));
    }

    #[test]
    fn versions_order_by_clock_then_device() {
        let (a, b) = (DeviceId::from_bytes([1; 16]), DeviceId::from_bytes([2; 16]));
        let v = |lamport, device| Version { lamport, device };
        assert!(v(2, a) > v(1, b));
        assert!(v(1, b) > v(1, a));
    }
}
