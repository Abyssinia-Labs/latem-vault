//! Files (files.md): a file entry's value is its manifest, which holds a small file's bytes
//! and names a larger file's sealed chunks.

use zeroize::Zeroizing;

use crate::record::MAX_VALUE_LEN;
use crate::{Error, Result};

/// The size of every chunk but a file's last.
pub const CHUNK_SIZE: usize = 1 << 20;
/// The largest file kept inline in its manifest.
pub const MAX_INLINE: usize = 64 << 10;
/// As many chunk ids as fit in a record's value.
pub const MAX_CHUNKS: usize = (MAX_VALUE_LEN - CHUNKS_HEADER_LEN) / 32;
/// The largest file: [`MAX_CHUNKS`] full chunks.
pub const MAX_SIZE: u64 = (MAX_CHUNKS * CHUNK_SIZE) as u64;

pub type ChunkId = [u8; 32];

const FORMAT: u8 = 0x01;
const MODE_EXECUTABLE: u8 = 0x01;
const LAYOUT_INLINE: u8 = 0x00;
const LAYOUT_CHUNKS: u8 = 0x01;
/// `format ‖ size ‖ mode ‖ mtime ‖ layout`.
const HEADER_LEN: usize = 19;
/// The header, then `epoch ‖ count`.
const CHUNKS_HEADER_LEN: usize = HEADER_LEN + 8;

/// Where a file's bytes are.
#[derive(Clone, PartialEq, Eq)]
pub enum Content {
    Inline(Zeroizing<Vec<u8>>),
    Chunks {
        /// The collection key the chunks are sealed under (files.md, sealing).
        epoch: u32,
        ids: Vec<ChunkId>,
    },
}

#[derive(Clone, PartialEq, Eq)]
pub struct Manifest {
    pub size: u64,
    pub executable: bool,
    /// Seconds since 1970 UTC, when the file was written.
    pub mtime: i64,
    pub content: Content,
}

impl Manifest {
    /// How many chunks a file of `size` bytes is cut into.
    pub fn chunk_count(size: u64) -> u64 {
        size.div_ceil(CHUNK_SIZE as u64)
    }

    /// The chunks it names, none for an inline file.
    pub fn chunks(&self) -> &[ChunkId] {
        match &self.content {
            Content::Inline(_) => &[],
            Content::Chunks { ids, .. } => ids,
        }
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let len = match &self.content {
            Content::Inline(bytes) => HEADER_LEN + bytes.len(),
            Content::Chunks { ids, .. } => CHUNKS_HEADER_LEN + 32 * ids.len(),
        };
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        out.push(FORMAT);
        out.extend_from_slice(&self.size.to_be_bytes());
        out.push(if self.executable { MODE_EXECUTABLE } else { 0 });
        out.extend_from_slice(&self.mtime.to_be_bytes());
        match &self.content {
            Content::Inline(bytes) => {
                out.push(LAYOUT_INLINE);
                out.extend_from_slice(bytes);
            }
            Content::Chunks { epoch, ids } => {
                out.push(LAYOUT_CHUNKS);
                out.extend_from_slice(&epoch.to_be_bytes());
                let count = u32::try_from(ids.len()).expect("checked against MAX_CHUNKS");
                out.extend_from_slice(&count.to_be_bytes());
                for id in ids {
                    out.extend_from_slice(id);
                }
            }
        }
        out
    }

    /// Decodes and checks a manifest (files.md, manifest).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        const MALFORMED: Error = Error::InvalidManifest("malformed");
        let (header, rest) = bytes.split_first_chunk::<HEADER_LEN>().ok_or(MALFORMED)?;
        if header[0] != FORMAT {
            return Err(Error::InvalidManifest("unknown format"));
        }
        let size = u64::from_be_bytes(header[1..9].try_into().expect("8 bytes"));
        let mode = header[9];
        if mode & !MODE_EXECUTABLE != 0 {
            return Err(Error::InvalidManifest("unknown mode bits"));
        }
        let mtime = i64::from_be_bytes(header[10..18].try_into().expect("8 bytes"));
        let content = match header[18] {
            LAYOUT_INLINE => {
                if rest.len() > MAX_INLINE {
                    return Err(Error::InvalidManifest("inline files are at most 64 KiB"));
                }
                if rest.len() as u64 != size {
                    return Err(Error::InvalidManifest("the inline bytes aren't the size"));
                }
                Content::Inline(Zeroizing::new(rest.to_vec()))
            }
            LAYOUT_CHUNKS => {
                let (epoch, rest) = rest.split_first_chunk::<4>().ok_or(MALFORMED)?;
                let (count, rest) = rest.split_first_chunk::<4>().ok_or(MALFORMED)?;
                let count = u32::from_be_bytes(*count) as usize;
                if count as u64 != Self::chunk_count(size) {
                    return Err(Error::InvalidManifest("the chunk count isn't the size's"));
                }
                if rest.len() != 32 * count {
                    return Err(MALFORMED);
                }
                Content::Chunks {
                    epoch: u32::from_be_bytes(*epoch),
                    ids: rest.as_chunks::<32>().0.to_vec(),
                }
            }
            _ => return Err(Error::InvalidManifest("unknown layout")),
        };
        Ok(Self {
            size,
            executable: mode & MODE_EXECUTABLE != 0,
            mtime,
            content,
        })
    }
}

impl std::fmt::Debug for Manifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("Manifest");
        debug
            .field("size", &self.size)
            .field("executable", &self.executable)
            .field("mtime", &self.mtime);
        match &self.content {
            Content::Inline(_) => debug.field("content", &"inline"),
            Content::Chunks { epoch, ids } => {
                debug.field("epoch", epoch).field("chunks", &ids.len())
            }
        };
        debug.finish()
    }
}

/// The size a manifest gives, read without decoding the rest.
pub(crate) fn size_of(manifest: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(manifest.get(1..9)?.try_into().ok()?))
}

/// `frozen::CHUNK_AAD ‖ vault id ‖ collection id ‖ epoch`: binds a chunk to where it
/// belongs, so it opens nowhere else.
pub(crate) fn chunk_aad(
    vault: crate::VaultId,
    collection: crate::CollectionId,
    epoch: u32,
) -> Vec<u8> {
    [
        pinkvault_crypto::frozen::CHUNK_AAD,
        vault.as_bytes(),
        collection.as_bytes(),
        &epoch.to_be_bytes(),
    ]
    .concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunked(size: u64, count: usize) -> Manifest {
        Manifest {
            size,
            executable: false,
            mtime: 1_762_819_200,
            content: Content::Chunks {
                epoch: 2,
                ids: (0..count).map(|i| [i as u8; 32]).collect(),
            },
        }
    }

    #[test]
    fn round_trip() {
        let inline = Manifest {
            size: 5,
            executable: true,
            mtime: -1,
            content: Content::Inline(Zeroizing::new(b"hello".to_vec())),
        };
        let bytes = inline.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 5);
        assert!(Manifest::decode(&bytes).unwrap() == inline);

        // A 10 MiB file: 10 chunk ids and 27 bytes besides (files.md, cost).
        let ten = chunked(10 << 20, 10);
        let bytes = ten.encode();
        assert_eq!(bytes.len(), 347);
        let decoded = Manifest::decode(&bytes).unwrap();
        assert!(decoded == ten);
        assert_eq!(decoded.chunks().len(), 10);

        let empty = chunked(0, 0);
        assert!(Manifest::decode(&empty.encode()).unwrap() == empty);
    }

    #[test]
    fn the_largest_file_fits_in_a_record() {
        assert_eq!(MAX_CHUNKS, 32_767);
        assert_eq!(MAX_SIZE, (32 << 30) - (1 << 20));
        let largest = chunked(MAX_SIZE, MAX_CHUNKS).encode();
        assert!(largest.len() <= MAX_VALUE_LEN);
        assert!(Manifest::decode(&largest).is_ok());
    }

    #[test]
    fn rejects_what_doesnt_add_up() {
        let good = chunked(3 << 20, 3).encode();
        let mut bad = good.to_vec();
        bad[0] = 2;
        assert!(Manifest::decode(&bad).is_err(), "format");
        let mut bad = good.to_vec();
        bad[9] = 0x02;
        assert!(Manifest::decode(&bad).is_err(), "mode");
        let mut bad = good.to_vec();
        bad[18] = 0x02;
        assert!(Manifest::decode(&bad).is_err(), "layout");
        assert!(
            Manifest::decode(&chunked(3 << 20, 2).encode()).is_err(),
            "count"
        );
        assert!(
            Manifest::decode(&chunked((3 << 20) + 1, 3).encode()).is_err(),
            "count"
        );
        assert!(Manifest::decode(&good[..good.len() - 1]).is_err(), "short");

        let inline = |size, bytes: &[u8]| Manifest {
            size,
            executable: false,
            mtime: 0,
            content: Content::Inline(Zeroizing::new(bytes.to_vec())),
        };
        assert!(
            Manifest::decode(&inline(4, b"abc").encode()).is_err(),
            "size"
        );
        let big = vec![0; MAX_INLINE + 1];
        assert!(Manifest::decode(&inline(big.len() as u64, &big).encode()).is_err());
        assert!(Manifest::decode(&[]).is_err());
    }
}
