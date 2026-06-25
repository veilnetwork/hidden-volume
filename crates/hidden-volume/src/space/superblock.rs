//! Per-space superblock. See DESIGN §3, §6.
//!
//! Holds a single slot pointer (`root_slot`) to the latest committed
//! Commit chunk plus its plaintext hash (`root_hash`). The Commit
//! chunk in turn references per-namespace IndexNode trees — this is
//! the Merkle-rooted shape verified by `Space::verify_integrity`.
//!
//! It may also carry an **optional** `checkpoint_slot` pointer to a
//! [`crate::chunk::ChunkKind::Checkpoint`] chunk — the open-scan
//! acceleration structure (the "fast-open" optimization). The
//! pointer is forward-inert: a superblock with `checkpoint_slot ==
//! NO_RECORD` is byte-identical to a pre-checkpoint v3 superblock, so
//! existing containers read back unchanged and the checkpoint feature
//! never changes the on-disk format version (it is an optimization
//! hint sealed under the same per-space key as every other chunk, not
//! a correctness-bearing structure — a reader that ignores it is
//! always correct).

use byteorder::{ByteOrder, LittleEndian};

use crate::{Error, Result};

/// Sentinel value for [`Superblock::root_slot`] meaning "no record committed
/// yet". `u64::MAX` is a slot index unreachable in practice (would imply
/// 2^64 chunks ≈ 64 ZiB file).
///
/// Also reused as the sentinel for [`Superblock::checkpoint_slot`]
/// ("no checkpoint chunk written for this space yet") — same
/// unreachable-slot rationale.
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
    /// Slot index of the most recent [`crate::chunk::ChunkKind::Checkpoint`]
    /// chunk for this space, or [`NO_RECORD`] when no checkpoint exists
    /// (every pre-checkpoint container, and any space whose open-scan
    /// has not yet self-healed a checkpoint).
    ///
    /// Carried forward verbatim by `commit_tx` (the commit path never
    /// mints a checkpoint — see `crate::open` for the lazy self-heal
    /// writer), so once a checkpoint is written every subsequent
    /// superblock points at it until the next self-heal supersedes it.
    ///
    /// **Canonical encoding (see [`Self::encode`]).** `NO_RECORD`
    /// encodes as the 48-byte short form (byte-identical to a v3
    /// pre-checkpoint superblock); any other value encodes as the
    /// 56-byte long form. The two forms are in bijection with the
    /// value space, preserving the strict-length canonical-uniqueness
    /// contract below.
    pub checkpoint_slot: u64,
}

impl Superblock {
    /// Encoded length of the **canonical short form** (no checkpoint):
    /// `seq (8) + root_slot (8) + root_hash (32) = 48` bytes. This is
    /// byte-identical to the pre-checkpoint v3 superblock, so existing
    /// containers decode unchanged.
    pub const ENCODED_LEN: usize = 8 + 8 + 32;

    /// Encoded length of the **canonical long form** (checkpoint
    /// present): the short form plus `checkpoint_slot (8) = 56` bytes.
    pub const ENCODED_LEN_WITH_CHECKPOINT: usize = Self::ENCODED_LEN + 8;

    /// Whether `len` is one of the two canonical superblock payload
    /// lengths (48 or 56). Used by the open-scan to length-gate
    /// Superblock-kind candidates before retaining their payload (a
    /// memory bound — audit pass 20 — and now also the
    /// short-vs-long-form discriminator).
    #[must_use]
    pub fn is_valid_encoded_len(len: usize) -> bool {
        len == Self::ENCODED_LEN || len == Self::ENCODED_LEN_WITH_CHECKPOINT
    }

    /// Encode this superblock into its **canonical** payload form.
    ///
    /// - `checkpoint_slot == NO_RECORD` → 48-byte short form
    ///   (`seq ‖ root_slot ‖ root_hash`), byte-identical to a v3
    ///   pre-checkpoint superblock.
    /// - `checkpoint_slot != NO_RECORD` → 56-byte long form
    ///   (short form ‖ `checkpoint_slot`).
    ///
    /// The form is a deterministic function of the value, so each
    /// `Superblock` has exactly one valid byte encoding — see the
    /// canonical-uniqueness contract on [`Self::decode`].
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::ENCODED_LEN_WITH_CHECKPOINT);
        let mut head = [0u8; Self::ENCODED_LEN];
        LittleEndian::write_u64(&mut head[0..8], self.seq);
        LittleEndian::write_u64(&mut head[8..16], self.root_slot);
        head[16..48].copy_from_slice(&self.root_hash);
        buf.extend_from_slice(&head);
        if self.checkpoint_slot != NO_RECORD {
            let mut cp = [0u8; 8];
            LittleEndian::write_u64(&mut cp, self.checkpoint_slot);
            buf.extend_from_slice(&cp);
        }
        buf
    }

    /// Decode a canonical superblock payload (48 or 56 bytes) back into
    /// a `Superblock`. Errors with [`Error::Malformed`] for any other
    /// length, or for a non-canonical 56-byte payload whose
    /// `checkpoint_slot` is `NO_RECORD`.
    ///
    /// **Strict-length canonical-uniqueness contract (audit pass 19
    /// round 2, extended for the checkpoint pointer).** A Superblock
    /// payload has a fixed-by-value encoding; the only two reachable
    /// lengths are 48 (no checkpoint) and 56 (checkpoint present).
    /// Trailing bytes, short reads, and the non-canonical
    /// "56-bytes-but-checkpoint==NO_RECORD" form are all rejected at
    /// decode time so that two different on-disk byte strings can
    /// never round-trip to the same `Superblock`. (The 56-byte
    /// NO_RECORD form is the one redundant encoding the bijection has
    /// to exclude: its canonical encoding is the 48-byte short form.)
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        match bytes.len() {
            Self::ENCODED_LEN => {
                let seq = LittleEndian::read_u64(&bytes[0..8]);
                let root_slot = LittleEndian::read_u64(&bytes[8..16]);
                let mut root_hash = [0u8; 32];
                root_hash.copy_from_slice(&bytes[16..48]);
                Ok(Self {
                    seq,
                    root_slot,
                    root_hash,
                    checkpoint_slot: NO_RECORD,
                })
            },
            Self::ENCODED_LEN_WITH_CHECKPOINT => {
                let seq = LittleEndian::read_u64(&bytes[0..8]);
                let root_slot = LittleEndian::read_u64(&bytes[8..16]);
                let mut root_hash = [0u8; 32];
                root_hash.copy_from_slice(&bytes[16..48]);
                let checkpoint_slot = LittleEndian::read_u64(&bytes[48..56]);
                if checkpoint_slot == NO_RECORD {
                    // Non-canonical: a NO_RECORD checkpoint MUST use the
                    // 48-byte short form. Reject so the encoding stays a
                    // bijection (canonical-uniqueness contract).
                    return Err(Error::Malformed(
                        "non-canonical superblock: 56-byte form with NO_RECORD checkpoint",
                    ));
                }
                Ok(Self {
                    seq,
                    root_slot,
                    root_hash,
                    checkpoint_slot,
                })
            },
            _ => Err(Error::Malformed(
                "superblock payload must be exactly 48 or 56 bytes",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sb(checkpoint_slot: u64) -> Superblock {
        Superblock {
            seq: 7,
            root_slot: 42,
            root_hash: [9u8; 32],
            checkpoint_slot,
        }
    }

    /// Short form round-trips and is exactly 48 bytes — byte-identical
    /// to a pre-checkpoint v3 superblock.
    #[test]
    fn short_form_roundtrip_is_48_bytes() {
        let s = sb(NO_RECORD);
        let enc = s.encode();
        assert_eq!(enc.len(), Superblock::ENCODED_LEN);
        let dec = Superblock::decode(&enc).expect("decode short");
        assert_eq!(dec.seq, s.seq);
        assert_eq!(dec.root_slot, s.root_slot);
        assert_eq!(dec.root_hash, s.root_hash);
        assert_eq!(dec.checkpoint_slot, NO_RECORD);
    }

    /// Long form round-trips and is exactly 56 bytes when a checkpoint
    /// pointer is present.
    #[test]
    fn long_form_roundtrip_is_56_bytes() {
        let s = sb(1234);
        let enc = s.encode();
        assert_eq!(enc.len(), Superblock::ENCODED_LEN_WITH_CHECKPOINT);
        let dec = Superblock::decode(&enc).expect("decode long");
        assert_eq!(dec.seq, s.seq);
        assert_eq!(dec.root_slot, s.root_slot);
        assert_eq!(dec.root_hash, s.root_hash);
        assert_eq!(dec.checkpoint_slot, 1234);
    }

    /// The first 48 bytes of the long form are byte-identical to the
    /// short form (the checkpoint pointer is a pure suffix), so a
    /// checkpoint-unaware reader of the prefix sees the same root.
    #[test]
    fn long_form_prefix_equals_short_form() {
        let short = sb(NO_RECORD).encode();
        let long = sb(99).encode();
        assert_eq!(&long[..Superblock::ENCODED_LEN], &short[..]);
    }

    /// Canonical-uniqueness: a 56-byte payload carrying a NO_RECORD
    /// checkpoint is rejected (its canonical form is the 48-byte short
    /// form). Prevents two byte strings mapping to one value.
    #[test]
    fn rejects_noncanonical_long_form_with_no_record() {
        let mut enc = sb(NO_RECORD).encode();
        // Hand-build the forbidden 56-byte form: short form + NO_RECORD.
        enc.extend_from_slice(&NO_RECORD.to_le_bytes());
        assert_eq!(enc.len(), Superblock::ENCODED_LEN_WITH_CHECKPOINT);
        let err = Superblock::decode(&enc).expect_err("must reject non-canonical");
        assert!(matches!(err, Error::Malformed(_)));
    }

    /// Any non-{48,56} length is rejected.
    #[test]
    fn rejects_wrong_length() {
        for len in [0usize, 1, 47, 49, 55, 57, 64, 128] {
            let buf = vec![0u8; len];
            assert!(
                Superblock::decode(&buf).is_err(),
                "len {len} must be rejected"
            );
        }
        assert!(Superblock::is_valid_encoded_len(48));
        assert!(Superblock::is_valid_encoded_len(56));
        assert!(!Superblock::is_valid_encoded_len(47));
        assert!(!Superblock::is_valid_encoded_len(55));
    }
}
