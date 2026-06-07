//! Chunk kind discriminator. See DESIGN §3.

use crate::{Error, Result};

/// On-disk chunk kind discriminator. Marked `#[non_exhaustive]`
/// because future format generations may add chunk kinds via the
/// reservation mechanism documented in `docs/en/reference/format.md` §8.
///
/// Reserved discriminator bytes (not exposed as variants):
/// - `0x03` — historically "Data" (direct-data references); never
///   produced. Reserved for future direct-blob storage; current v1
///   reader rejects with `Error::Malformed("unknown chunk kind")`.
/// - `0x04` — historically "Journal" (intent-log for in-place
///   updates); never produced. Superseded by vacuum + scrub; current
///   v1 reader rejects.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChunkKind {
    /// Per-space root pointer + Merkle root.
    Superblock = 0x01,
    /// B+ tree node (Leaf or Internal) of a namespace's KV index.
    IndexNode = 0x02,
    /// Per-Tx commit chunk listing every namespace's IndexRoot.
    Commit = 0x05,
    /// zstd-compressed batch of log entries (DESIGN §11.4).
    /// Used for the message log namespace where a per-message KV
    /// entry would explode the index. See `space::log`.
    DataBatch = 0x06,
}

impl ChunkKind {
    /// Decode a wire-format kind byte into a [`ChunkKind`]. Unknown
    /// values surface as [`Error::Malformed`] — callers MUST NOT log
    /// the raw byte (deniability invariant). Reserved discriminators
    /// 0x03 and 0x04 are treated as unknown by v1 readers.
    pub fn from_u8(b: u8) -> Result<Self> {
        Ok(match b {
            0x01 => Self::Superblock,
            0x02 => Self::IndexNode,
            0x05 => Self::Commit,
            0x06 => Self::DataBatch,
            _ => return Err(Error::Malformed("unknown chunk kind")),
        })
    }
}
