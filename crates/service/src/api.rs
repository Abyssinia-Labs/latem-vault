//! The local API's messages and their encoding (service.md, local API).
//!
//! Each message is `u32 length ‖ type ‖ body`. Buffers that can hold values are sized before
//! they are filled, so they never reallocate and leave copies behind, and are wiped when dropped.

use std::io::{self, Read, Write};

use openvault_core::{DeviceId, Kind};
use zeroize::Zeroizing;

/// The longest message, type and body: a folder of large values still fits.
pub const MAX_MESSAGE: usize = 16 << 20;

/// What the CLI asks the service to do.
#[derive(Debug)]
pub enum Request {
    Collections,
    CreateCollection {
        name: String,
        /// Needed only when this device has no admin key.
        recovery_phrase: Option<Zeroizing<String>>,
    },
    Get {
        collection: String,
        name: String,
    },
    /// Writes every entry in one transaction.
    Set {
        collection: String,
        entries: Vec<Item>,
    },
    Delete {
        collection: String,
        name: String,
    },
    List {
        collection: String,
    },
    /// The current values under `folder/`, for `openvault run`.
    Folder {
        collection: String,
        folder: String,
    },
    Devices,
}

#[derive(Debug)]
pub enum Response {
    Done,
    Names(Vec<String>),
    Entry(Option<Value>),
    Entries(Vec<Item>),
    Listing(Vec<Listed>),
    Deleted(bool),
    Devices(Vec<DeviceSummary>),
    Error { code: ErrorCode, message: String },
}

/// A secret or variable with its name.
pub struct Item {
    pub name: String,
    pub kind: Kind,
    pub value: Zeroizing<Vec<u8>>,
}

pub struct Value {
    pub kind: Kind,
    pub value: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub name: String,
    pub kind: Kind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceSummary {
    pub id: DeviceId,
    pub this: bool,
    pub revoked: bool,
    pub visible: bool,
    /// P-256 keys, in a Secure Enclave or TPM.
    pub hardware: bool,
    /// `None` for a name that doesn't open, which is shown as the device id.
    pub name: Option<(String, String)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    Other,
    RecoveryPhraseNeeded,
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Value")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("bad message: {0}")]
    Bad(&'static str),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl Request {
    /// The whole message, length included.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Self::Collections => frame(0x01, |_| {}),
            Self::CreateCollection {
                name,
                recovery_phrase,
            } => frame(0x02, |w| {
                w.str(name);
                match recovery_phrase {
                    Some(phrase) => {
                        w.u8(1);
                        w.str(phrase);
                    }
                    None => w.u8(0),
                }
            }),
            Self::Get { collection, name } => frame(0x03, |w| {
                w.str(collection);
                w.str(name);
            }),
            Self::Set {
                collection,
                entries,
            } => frame(0x04, |w| {
                w.str(collection);
                w.items(entries);
            }),
            Self::Delete { collection, name } => frame(0x05, |w| {
                w.str(collection);
                w.str(name);
            }),
            Self::List { collection } => frame(0x06, |w| w.str(collection)),
            Self::Folder { collection, folder } => frame(0x07, |w| {
                w.str(collection);
                w.str(folder);
            }),
            Self::Devices => frame(0x08, |_| {}),
        }
    }

    pub fn decode(kind: u8, body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader(body);
        let request = match kind {
            0x01 => Self::Collections,
            0x02 => Self::CreateCollection {
                name: r.string()?,
                recovery_phrase: match r.u8()? {
                    0 => None,
                    1 => Some(Zeroizing::new(r.string()?)),
                    _ => return Err(DecodeError::Bad("has phrase")),
                },
            },
            0x03 => Self::Get {
                collection: r.string()?,
                name: r.string()?,
            },
            0x04 => Self::Set {
                collection: r.string()?,
                entries: r.items()?,
            },
            0x05 => Self::Delete {
                collection: r.string()?,
                name: r.string()?,
            },
            0x06 => Self::List {
                collection: r.string()?,
            },
            0x07 => Self::Folder {
                collection: r.string()?,
                folder: r.string()?,
            },
            0x08 => Self::Devices,
            _ => return Err(DecodeError::Bad("unknown request")),
        };
        r.finish()?;
        Ok(request)
    }
}

impl Response {
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            code: ErrorCode::Other,
            message: message.into(),
        }
    }

    /// The whole message, length included.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Self::Done => frame(0x80, |_| {}),
            Self::Names(names) => frame(0x81, |w| {
                w.count(names.len());
                for name in names {
                    w.str(name);
                }
            }),
            Self::Entry(value) => frame(0x82, |w| match value {
                Some(value) => {
                    w.u8(1);
                    w.kind(value.kind);
                    w.bytes(&value.value);
                }
                None => w.u8(0),
            }),
            Self::Entries(items) => frame(0x83, |w| w.items(items)),
            Self::Listing(listed) => frame(0x84, |w| {
                w.count(listed.len());
                for entry in listed {
                    w.str(&entry.name);
                    w.kind(entry.kind);
                }
            }),
            Self::Deleted(existed) => frame(0x85, |w| w.u8((*existed).into())),
            Self::Devices(devices) => frame(0x86, |w| {
                w.count(devices.len());
                for device in devices {
                    w.put(device.id.as_bytes());
                    let flags = u8::from(device.this)
                        | u8::from(device.revoked) << 1
                        | u8::from(device.visible) << 2
                        | u8::from(device.hardware) << 3;
                    w.u8(flags);
                    let (platform, name) = device
                        .name
                        .as_ref()
                        .map_or(("", ""), |(platform, name)| (platform, name));
                    w.str(platform);
                    w.str(name);
                }
            }),
            Self::Error { code, message } => frame(0x7f, |w| {
                w.u8(match code {
                    ErrorCode::Other => 0x01,
                    ErrorCode::RecoveryPhraseNeeded => 0x02,
                });
                w.str(truncate(message, 4096));
            }),
        }
    }

    pub fn decode(kind: u8, body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader(body);
        let response = match kind {
            0x80 => Self::Done,
            0x81 => {
                let count = r.count()?;
                let mut names = Vec::with_capacity(count);
                for _ in 0..count {
                    names.push(r.string()?);
                }
                Self::Names(names)
            }
            0x82 => Self::Entry(match r.u8()? {
                0 => None,
                1 => Some(Value {
                    kind: r.kind()?,
                    value: r.value()?,
                }),
                _ => return Err(DecodeError::Bad("found")),
            }),
            0x83 => Self::Entries(r.items()?),
            0x84 => {
                let count = r.count()?;
                let mut listed = Vec::with_capacity(count);
                for _ in 0..count {
                    listed.push(Listed {
                        name: r.string()?,
                        kind: r.kind()?,
                    });
                }
                Self::Listing(listed)
            }
            0x85 => Self::Deleted(match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(DecodeError::Bad("existed")),
            }),
            0x86 => {
                let count = r.count()?;
                let mut devices = Vec::with_capacity(count);
                for _ in 0..count {
                    let id = DeviceId::try_from(r.take(16)?)
                        .map_err(|_| DecodeError::Bad("device id"))?;
                    let flags = r.u8()?;
                    if flags >> 4 != 0 {
                        return Err(DecodeError::Bad("device flags"));
                    }
                    let platform = r.string()?;
                    let name = r.string()?;
                    devices.push(DeviceSummary {
                        id,
                        this: flags & 1 != 0,
                        revoked: flags & 2 != 0,
                        visible: flags & 4 != 0,
                        hardware: flags & 8 != 0,
                        name: (!name.is_empty()).then_some((platform, name)),
                    });
                }
                Self::Devices(devices)
            }
            0x7f => Self::Error {
                code: match r.u8()? {
                    0x02 => ErrorCode::RecoveryPhraseNeeded,
                    _ => ErrorCode::Other,
                },
                message: r.string()?,
            },
            _ => return Err(DecodeError::Bad("unknown response")),
        };
        r.finish()?;
        Ok(response)
    }
}

/// Reads one message: its type and body.
pub fn read_message(reader: &mut impl Read) -> Result<(u8, Zeroizing<Vec<u8>>), DecodeError> {
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;
    let mut message = Zeroizing::new(vec![0; message_len(len)?]);
    reader.read_exact(&mut message)?;
    split(message)
}

/// Writes one message from [`Request::encode`] or [`Response::encode`].
pub fn write_message(writer: &mut impl Write, message: &[u8]) -> io::Result<()> {
    writer.write_all(message)?;
    writer.flush()
}

/// The length prefix's value, checked against [`MAX_MESSAGE`].
pub fn message_len(prefix: [u8; 4]) -> Result<usize, DecodeError> {
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > MAX_MESSAGE {
        return Err(DecodeError::Bad("length"));
    }
    Ok(len)
}

/// Splits a message without its length prefix into its type and body.
pub fn split(mut message: Zeroizing<Vec<u8>>) -> Result<(u8, Zeroizing<Vec<u8>>), DecodeError> {
    let kind = message[0];
    // Shifts the body down in place, so no copy is left behind.
    message.copy_within(1.., 0);
    let len = message.len() - 1;
    message.truncate(len);
    Ok((kind, message))
}

/// Builds a message: the body is written twice, once to count it and once into a buffer of
/// exactly that size.
fn frame(kind: u8, body: impl Fn(&mut Writer)) -> Zeroizing<Vec<u8>> {
    let mut counter = Writer { buf: None, len: 0 };
    body(&mut counter);
    let len = 1 + counter.len;
    assert!(len <= MAX_MESSAGE, "callers keep messages within the limit");
    let mut writer = Writer {
        buf: Some(Zeroizing::new(Vec::with_capacity(4 + len))),
        len: 0,
    };
    writer.put(&(len as u32).to_be_bytes());
    writer.u8(kind);
    body(&mut writer);
    writer.buf.expect("filled")
}

struct Writer {
    /// `None` while counting.
    buf: Option<Zeroizing<Vec<u8>>>,
    len: usize,
}

impl Writer {
    fn put(&mut self, bytes: &[u8]) {
        self.len += bytes.len();
        if let Some(buf) = &mut self.buf {
            buf.extend_from_slice(bytes);
        }
    }

    fn u8(&mut self, value: u8) {
        self.put(&[value]);
    }

    fn count(&mut self, count: usize) {
        self.put(
            &u32::try_from(count)
                .expect("bounded by the message limit")
                .to_be_bytes(),
        );
    }

    fn str(&mut self, s: &str) {
        let len = u16::try_from(s.len()).expect("names, phrases and messages are short");
        self.put(&len.to_be_bytes());
        self.put(s.as_bytes());
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.count(bytes.len());
        self.put(bytes);
    }

    fn kind(&mut self, kind: Kind) {
        self.u8(kind_code(kind));
    }

    fn items(&mut self, items: &[Item]) {
        self.count(items.len());
        for item in items {
            self.str(&item.name);
            self.kind(item.kind);
            self.bytes(&item.value);
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        if self.0.len() < len {
            return Err(DecodeError::Bad("truncated"));
        }
        let (field, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(field)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn count(&mut self) -> Result<usize, DecodeError> {
        let count = u32::from_be_bytes(self.take(4)?.try_into().expect("took 4")) as usize;
        // Each item takes at least one byte, so a count beyond the rest is a lie, and
        // allocating for it would let a message ask for any amount of memory.
        if count > self.0.len() {
            return Err(DecodeError::Bad("count"));
        }
        Ok(count)
    }

    fn string(&mut self) -> Result<String, DecodeError> {
        let len = u16::from_be_bytes(self.take(2)?.try_into().expect("took 2"));
        let bytes = self.take(len.into())?;
        String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::Bad("UTF-8"))
    }

    fn value(&mut self) -> Result<Zeroizing<Vec<u8>>, DecodeError> {
        let len = self.count()?;
        Ok(Zeroizing::new(self.take(len)?.to_vec()))
    }

    fn kind(&mut self) -> Result<Kind, DecodeError> {
        match self.u8()? {
            0x01 => Ok(Kind::Secret),
            0x02 => Ok(Kind::Var),
            _ => Err(DecodeError::Bad("kind")),
        }
    }

    fn items(&mut self) -> Result<Vec<Item>, DecodeError> {
        let count = self.count()?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(Item {
                name: self.string()?,
                kind: self.kind()?,
                value: self.value()?,
            });
        }
        Ok(items)
    }

    fn finish(self) -> Result<(), DecodeError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Bad("trailing bytes"))
        }
    }
}

fn kind_code(kind: Kind) -> u8 {
    match kind {
        Kind::Secret => 0x01,
        Kind::Var => 0x02,
        Kind::Collection => unreachable!("collection entries never cross the local API"),
    }
}

/// `message` cut to at most `max` bytes, at a character boundary.
fn truncate(message: &str, max: usize) -> &str {
    if message.len() <= max {
        return message;
    }
    let mut end = max;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    &message[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_request(request: &Request) -> Request {
        let message = request.encode();
        let (kind, body) = read_message(&mut &message[..]).unwrap();
        Request::decode(kind, &body).unwrap()
    }

    fn round_trip_response(response: &Response) -> Response {
        let message = response.encode();
        let (kind, body) = read_message(&mut &message[..]).unwrap();
        Response::decode(kind, &body).unwrap()
    }

    fn item(name: &str, kind: Kind, value: &[u8]) -> Item {
        Item {
            name: name.into(),
            kind,
            value: Zeroizing::new(value.to_vec()),
        }
    }

    #[test]
    fn requests_round_trip() {
        let set = Request::Set {
            collection: "latem".into(),
            entries: vec![
                item("prod/SENTRY_DSN", Kind::Secret, b"https://sentry"),
                item("prod/REGION", Kind::Var, b""),
            ],
        };
        let Request::Set {
            collection,
            entries,
        } = round_trip_request(&set)
        else {
            panic!("not a set");
        };
        assert_eq!(collection, "latem");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "prod/SENTRY_DSN");
        assert_eq!(entries[0].kind, Kind::Secret);
        assert_eq!(&entries[0].value[..], b"https://sentry");
        assert_eq!(entries[1].kind, Kind::Var);
        assert!(entries[1].value.is_empty());

        let create = Request::CreateCollection {
            name: "ssh".into(),
            recovery_phrase: Some(Zeroizing::new("abandon ability".into())),
        };
        let Request::CreateCollection {
            name,
            recovery_phrase,
        } = round_trip_request(&create)
        else {
            panic!("not a create");
        };
        assert_eq!(name, "ssh");
        assert_eq!(
            recovery_phrase.as_deref().map(String::as_str),
            Some("abandon ability")
        );

        for request in [Request::Collections, Request::Devices] {
            let message = request.encode();
            assert_eq!(&message[..], &[0, 0, 0, 1, message[4]]);
            round_trip_request(&request);
        }
    }

    #[test]
    fn responses_round_trip() {
        let devices = vec![
            DeviceSummary {
                id: DeviceId::random(),
                this: true,
                revoked: false,
                visible: false,
                hardware: true,
                name: Some(("macos".into(), "MacBook".into())),
            },
            DeviceSummary {
                id: DeviceId::random(),
                this: false,
                revoked: true,
                visible: true,
                hardware: false,
                name: None,
            },
        ];
        let Response::Devices(decoded) = round_trip_response(&Response::Devices(devices.clone()))
        else {
            panic!("not devices");
        };
        assert_eq!(decoded, devices);

        let Response::Entry(Some(value)) = round_trip_response(&Response::Entry(Some(Value {
            kind: Kind::Var,
            value: Zeroizing::new(b"eu-west".to_vec()),
        }))) else {
            panic!("not an entry");
        };
        assert_eq!((value.kind, &value.value[..]), (Kind::Var, &b"eu-west"[..]));

        let Response::Error { code, message } = round_trip_response(&Response::Error {
            code: ErrorCode::RecoveryPhraseNeeded,
            message: "needs the phrase".into(),
        }) else {
            panic!("not an error");
        };
        assert_eq!(code, ErrorCode::RecoveryPhraseNeeded);
        assert_eq!(message, "needs the phrase");
    }

    #[test]
    fn rejects_bad_messages() {
        let good = Request::Get {
            collection: "latem".into(),
            name: "prod/X".into(),
        }
        .encode();
        let (kind, body) = read_message(&mut &good[..]).unwrap();

        assert!(Request::decode(0x70, &body).is_err(), "unknown type");
        assert!(
            Request::decode(kind, &body[..body.len() - 1]).is_err(),
            "truncated"
        );
        assert!(
            Request::decode(kind, &[&body[..], &[0]].concat()).is_err(),
            "trailing"
        );

        // A count larger than the message can't make the reader allocate for it.
        let lying = [&[0, 5][..], b"latem", &[0xff, 0xff, 0xff, 0xff]].concat();
        assert!(Request::decode(0x04, &lying).is_err());

        for prefix in [[0, 0, 0, 0], ((MAX_MESSAGE + 1) as u32).to_be_bytes()] {
            assert!(read_message(&mut &prefix[..]).is_err());
        }
    }
}
