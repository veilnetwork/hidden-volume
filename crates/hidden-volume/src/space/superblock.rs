//! Per-space superblock. See DESIGN §3, §6.
//!
//! Holds a single slot pointer (`root_slot`) to the latest committed
//! Commit chunk plus its plaintext hash (`root_hash`). The Commit
//! chunk in turn references per-namespace IndexNode trees — this is
//! the Merkle-rooted shape verified by `Space::verify_integrity`.

use byteorder::{ByteOrder, LittleEndian};

use crate::{Error, Result};

/// Sentinel value for [`Superblock::root_slot`] meaning "no record committed
/// yet". `u64::MAX` is a slot index unreachable in practice (would imply
/// 2^64 chunks ≈ 64 ZiB file).
pub const NO_RECORD: u64 = u64::MAX;

/// Per-space root pointer + Merkle root. Written at the end of every
/// successful Tx commit (multiple replicas per
/// [`crate::container::DEFAULT_SUPERBLOCK_REPLICAS`]).
/// See `docs/en/reference/format.md` §4.1 for the byte layout.
#[derive(Debug, Clone)]
pub struct Superblock {
    /// Monotonically increasing per-space sequence number; superblock with
    /// the largest seq wins on open (DESIGN §6 Inv-W3).
    pub seq: u64,
    /// Slot index of the most recent committed Commit chunk, or
    /// [`NO_RECORD`] if the space has only an initial superblock.
    /// The Commit chunk holds the per-namespace IndexNode-tree roots.
    pub root_slot: u64,
    /// Hash of the root chunk's plaintext, for cross-check during recovery.
    /// Zero-valued when `root_slot == NO_RECORD`.
    pub root_hash: [u8; 32],
}

impl Superblock {
    /// Total encoded length of a Superblock plaintext payload (48 bytes).
    pub const ENCODED_LEN: usize = 8 + 8 + 32;

    /// Encode this superblock into the fixed 48-byte payload format.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut buf = [0u8; Self::ENCODED_LEN];
        LittleEndian::write_u64(&mut buf[0..8], self.seq);
        LittleEndian::write_u64(&mut buf[8..16], self.root_slot);
        buf[16..48].copy_from_slice(&self.root_hash);
        buf
    }

    /// Decode a 48-byte payload back into a `Superblock`. Errors with
    /// [`Error::Malformed`] if the buffer is not exactly
    /// [`Self::ENCODED_LEN`] bytes.
    ///
    /// **Strict-length contract (audit pass 19 round 2).** A
    /// Superblock payload has a fixed-size encoding; trailing bytes
    /// are reachable only by a key-holder/buggy-writer producing a
    /// non-canonical chunk. Reject them at decode time so two
    /// different on-disk byte strings cannot round-trip to the same
    /// `Superblock`.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(Error::Malformed(
                "superblock payload must be exactly 48 bytes",
            ));
        }
        let seq = LittleEndian::read_u64(&bytes[0..8]);
        let root_slot = LittleEndian::read_u64(&bytes[8..16]);
        let mut root_hash = [0u8; 32];
        root_hash.copy_from_slice(&bytes[16..48]);
        Ok(Self {
            seq,
            root_slot,
            root_hash,
        })
    }
}
