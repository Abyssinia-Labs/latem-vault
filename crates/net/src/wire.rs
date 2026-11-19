//! Message bodies that joining, sync and the coordinator share (sync.md): hellos, log requests
//! and entries, and items.

use pinkvault_core::VaultId;
use pinkvault_core::membership::LogEntry;
use pinkvault_core::sets::SetId;
use pinkvault_crypto::hash::Hash;

use crate::frame::{FrameError, MAX_MESSAGE};

pub const HELLO: u8 = 0x01;
pub const LOG_REQUEST: u8 = 0x02;
pub const LOG_ENTRIES: u8 = 0x03;
pub const ROOTS: u8 = 0x04;
pub const RECONCILE: u8 = 0x05;
pub const WANT: u8 = 0x06;
pub const ITEMS: u8 = 0x07;

/// Log entries per request (sync.md, log exchange).
pub const LOG_BATCH: u16 = 64;

/// `vault id (16) ‖ log head seq (u64) ‖ head hash (32)`.
pub fn hello(vault: VaultId, seq: u64, hash: &Hash) -> Vec<u8> {
    [&vault.as_bytes()[..], &seq.to_be_bytes(), hash].concat()
}

pub fn parse_hello(body: &[u8]) -> Result<(VaultId, u64, Hash), FrameError> {
    let mut reader = Reader(body);
    let vault = VaultId::from_bytes(reader.array()?);
    let (seq, hash) = (reader.u64()?, reader.array()?);
    reader.finish()?;
    Ok((vault, seq, hash))
}

/// `from seq (u64) ‖ max (u16)`.
pub fn log_request(from: u64, max: u16) -> Vec<u8> {
    [&from.to_be_bytes()[..], &max.to_be_bytes()].concat()
}

pub fn parse_log_request(body: &[u8]) -> Result<(u64, u16), FrameError> {
    let bytes: [u8; 10] = body
        .try_into()
        .map_err(|_| FrameError::Bad("log request"))?;
    Ok((
        u64::from_be_bytes(bytes[..8].try_into().expect("8 bytes")),
        u16::from_be_bytes(bytes[8..].try_into().expect("2 bytes")),
    ))
}

/// `count (u16) ‖ entries, each u32 length ‖ entry`.
pub fn log_entries(entries: &[LogEntry]) -> Vec<u8> {
    let mut out = (entries.len() as u16).to_be_bytes().to_vec();
    for entry in entries {
        let bytes = entry.to_bytes();
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&bytes);
    }
    out
}

pub fn parse_log_entries(body: &[u8]) -> Result<Vec<LogEntry>, FrameError> {
    let mut reader = Reader(body);
    let count = reader.u16()?;
    let mut entries = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        entries
            .push(LogEntry::from_bytes(reader.item()?).map_err(|_| FrameError::Bad("log entry"))?);
    }
    reader.finish()?;
    Ok(entries)
}

/// Items messages for `set`: `set id (17) ‖ count (u16) ‖ items, each u32 length ‖ item`, as many
/// whole items in each as fit in [`MAX_MESSAGE`] (sync.md, items).
pub fn items(set: SetId, items: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let header = || {
        let mut message = set.as_bytes().to_vec();
        message.extend_from_slice(&[0, 0]);
        message
    };
    let mut messages = Vec::new();
    let mut message = header();
    let mut count: u16 = 0;
    for item in items {
        if count > 0 && (1 + message.len() + 4 + item.len() > MAX_MESSAGE || count == u16::MAX) {
            message[17..19].copy_from_slice(&count.to_be_bytes());
            messages.push(std::mem::replace(&mut message, header()));
            count = 0;
        }
        message.extend_from_slice(&(item.len() as u32).to_be_bytes());
        message.extend_from_slice(item);
        count += 1;
    }
    if count > 0 || messages.is_empty() {
        message[17..19].copy_from_slice(&count.to_be_bytes());
        messages.push(message);
    }
    messages
}

pub fn parse_items(body: &[u8]) -> Result<(SetId, Vec<&[u8]>), FrameError> {
    let mut reader = Reader(body);
    let set = reader.set()?;
    let count = reader.u16()?;
    let mut items = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        items.push(reader.item()?);
    }
    reader.finish()?;
    Ok((set, items))
}

/// Reads a message body's fields in order.
pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn take(&mut self, len: usize) -> Result<&'a [u8], FrameError> {
        let (field, rest) = self
            .0
            .split_at_checked(len)
            .ok_or(FrameError::Bad("truncated"))?;
        self.0 = rest;
        Ok(field)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], FrameError> {
        Ok(self.take(N)?.try_into().expect("took N"))
    }

    pub fn u8(&mut self) -> Result<u8, FrameError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, FrameError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, FrameError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub fn set(&mut self) -> Result<SetId, FrameError> {
        SetId::from_bytes(self.array()?).ok_or(FrameError::Bad("unknown set"))
    }

    /// A `u32 length ‖ bytes` item.
    pub fn item(&mut self) -> Result<&'a [u8], FrameError> {
        let len = u32::from_be_bytes(self.array()?) as usize;
        self.take(len)
    }

    pub fn finish(self) -> Result<(), FrameError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(FrameError::Bad("trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_split_across_messages_and_round_trip() {
        let big = vec![7u8; 900 * 1024];
        let all = vec![big.clone(), big.clone(), b"small".to_vec(), big];
        let messages = items(SetId::GRANTS, &all);
        assert_eq!(messages.len(), 2, "two 900 KiB items per 2 MiB message");
        let mut back = Vec::new();
        for message in &messages {
            assert!(message.len() < MAX_MESSAGE, "the type byte fits too");
            let (set, items) = parse_items(message).unwrap();
            assert_eq!(set, SetId::GRANTS);
            back.extend(items.into_iter().map(<[u8]>::to_vec));
        }
        assert_eq!(back, all);
        assert_eq!(
            items(SetId::GRANTS, &[]).len(),
            1,
            "an empty message still says so"
        );
    }
}
