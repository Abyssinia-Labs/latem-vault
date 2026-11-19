//! The sets peers reconcile (sync.md, sets): one of record ids per collection, and one of grant
//! ids. Each is summarized by its item count and the sum of its ids, which a store keeps up to
//! date as items arrive, so a set's root costs one row to read.

use pinkvault_crypto::hash::{contexts, derive_key};

use crate::CollectionId;

/// A record id or a grant id: 32 bytes, ordered bytewise.
pub type ItemId = [u8; 32];

/// A 16-byte summary of a range of items.
pub type Fingerprint = [u8; 16];

/// `0x01 ‖ collection id` for a collection's records, `0x02 ‖ 16 zero bytes` for grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SetId([u8; 17]);

impl SetId {
    pub const GRANTS: Self = {
        let mut id = [0; 17];
        id[0] = 0x02;
        Self(id)
    };

    pub fn records(collection: CollectionId) -> Self {
        let mut id = [0; 17];
        id[0] = 0x01;
        id[1..].copy_from_slice(collection.as_bytes());
        Self(id)
    }

    pub fn from_bytes(bytes: [u8; 17]) -> Option<Self> {
        let set = Self(bytes);
        match bytes[0] {
            0x01 => Some(set),
            0x02 if set == Self::GRANTS => Some(set),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8; 17] {
        &self.0
    }

    /// The collection whose records this set holds, or `None` for the grants set.
    pub fn collection(&self) -> Option<CollectionId> {
        (self.0[0] == 0x01).then(|| {
            CollectionId::from_bytes(self.0[1..].try_into().expect("16 bytes after the tag"))
        })
    }
}

/// A set's or a range's count and sum of ids.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub count: u64,
    /// The ids added as 256-bit big-endian integers, mod 2^256.
    pub sum: [u8; 32],
}

impl Summary {
    pub fn of<'a>(ids: impl IntoIterator<Item = &'a ItemId>) -> Self {
        let mut summary = Self::default();
        for id in ids {
            summary.add(id);
        }
        summary
    }

    pub fn add(&mut self, id: &ItemId) {
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let digit = u16::from(self.sum[i]) + u16::from(id[i]) + carry;
            self.sum[i] = digit as u8;
            carry = digit >> 8;
        }
        self.count += 1;
    }

    /// `first 16 bytes of BLAKE3.derive_key(contexts::SYNC_FINGERPRINT, sum ‖ count)`.
    pub fn fingerprint(&self) -> Fingerprint {
        let key = derive_key(
            contexts::SYNC_FINGERPRINT,
            &[&self.sum[..], &self.count.to_be_bytes()].concat(),
        );
        key[..16].try_into().expect("16 of 32 bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_wrap_and_ignore_order() {
        let mut big = [0xff; 32];
        big[0] = 0x7f;
        let mut a = Summary::default();
        a.add(&big);
        a.add(&big);
        a.add(&[0x01; 32]);
        let b = Summary::of(&[[0x01; 32], big, big]);
        assert_eq!(a, b);
        assert_eq!(a.count, 3);

        let mut wrap = Summary::default();
        wrap.add(&[0xff; 32]);
        wrap.add(&{
            let mut one = [0; 32];
            one[31] = 1;
            one
        });
        assert_eq!(wrap.sum, [0; 32], "the sum is mod 2^256");
        assert_ne!(
            wrap.fingerprint(),
            Summary::default().fingerprint(),
            "the count differs"
        );
    }

    #[test]
    fn set_ids() {
        let collection = CollectionId::random();
        let records = SetId::records(collection);
        assert_eq!(records.collection(), Some(collection));
        assert_eq!(SetId::from_bytes(*records.as_bytes()), Some(records));
        assert_eq!(SetId::GRANTS.collection(), None);
        assert_eq!(
            SetId::from_bytes(*SetId::GRANTS.as_bytes()),
            Some(SetId::GRANTS)
        );
        let mut bad = *SetId::GRANTS.as_bytes();
        bad[5] = 1;
        assert_eq!(SetId::from_bytes(bad), None);
        assert_eq!(SetId::from_bytes([0x03; 17]), None);
    }
}
