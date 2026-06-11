//! Commit chunk payload encoding.
//!
//! The Commit chunk anchors a transaction's effect on the KV index.
//! Its plaintext payload encodes a set of "namespace → IndexNode slot"
//! pointers — these are the per-namespace roots after this transaction.
//!
//! On open, recovery picks the highest-seq Superblock; that Superblock's
//! `root_slot` points at this Commit chunk; the Commit's `index_roots`
//! map gives the per-namespace IndexNode slots; reading those chunks
//! reconstructs the live KV state.
//!
//! Layout (inside the AEAD-protected plaintext payload of a Commit chunk):
//!
//! ```text
//!   num_roots    : u16 LE                (≤ MAX_NAMESPACES_PER_TX)
//!   for each root, sorted by namespace ascending:
//!     namespace  : u8
//!     kind       : u8                    0 = Kv, 1 = Log (R-NSKIND)
//!     index_slot : u64 LE                absolute slot of IndexNode chunk
//!     payload_h  : [u8; 32]              BLAKE3 of IndexNodePayload bytes
//!   tx_root_hash : [u8; 32]              BLAKE3 over concat(payload_h_i)
//! ```
//!
//! Size: `2 + 32 + 42 * N`. With `PAYLOAD_CAP ≈ 4040`, ~95 namespaces
//! per Commit, well above any realistic use.
//!
//! **Format-version bump (v1 → v2)**: the `kind` byte was added to
//! close the R-NSKIND mixed-namespace gap (TASKS.md). v1 containers
//! cannot be opened by a v2 reader (`Argon2Params::validate` rejects
//! unknown `format_version`); pre-1.0 — breaking is acceptable.

use byteorder::{ByteOrder, LittleEndian};

use crate::chunk::format::PAYLOAD_CAP;
use crate::space::index::Namespace;
use crate::{Error, Result};

/// Maximum namespaces with roots in one Commit chunk.
pub const MAX_NAMESPACES_PER_TX: usize = (PAYLOAD_CAP - 2 - 32) / (1 + 1 + 8 + 32);

const _: () = assert!(MAX_NAMESPACES_PER_TX >= 64);

/// Per-namespace data shape (R-NSKIND).
///
/// Each `IndexRoot` (and therefore each namespace with at least one
/// committed entry) carries an explicit kind byte that distinguishes
/// KV namespaces from Log namespaces. `Tx::put` / `Tx::delete` can
/// only be called on `Kv` namespaces; `Tx::append_log` can only be
/// called on `Log` namespaces. Mixing in the same namespace is
/// rejected at `Tx`-time with [`Error::WrongNamespaceKind`] —
/// previously the library accepted mixing and silently lost log
/// payloads during repack (audit pass 12 HIGH finding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceKind {
    /// Direct key/value namespace. Read via `Space::get` / `list`,
    /// written via `Tx::put` / `delete`.
    Kv = 0,
    /// Append-only log namespace. Read via `Space::iter_log_*`,
    /// written via `Tx::append_log`. Internally each entry is stored
    /// as a (8-byte log_id BE → 8-byte batch_slot LE) KV pair
    /// pointing into a `DataBatch` chunk.
    Log = 1,
}

impl NamespaceKind {
    /// Wire-format byte.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse a wire-format byte. Returns [`Error::Malformed`] for
    /// unknown discriminants.
    pub fn from_u8(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Self::Kv),
            1 => Ok(Self::Log),
            _ => Err(Error::Malformed("unknown namespace kind discriminant")),
        }
    }
}

/// One per-namespace root pointer inside a Commit payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexRoot {
    /// Namespace this root belongs to.
    pub namespace: Namespace,
    /// Data shape for this namespace (R-NSKIND, format v2).
    pub kind: NamespaceKind,
    /// Slot index of the root IndexNode chunk (Leaf or Internal).
    pub index_slot: u64,
    /// BLAKE3 hash of the root IndexNode's plaintext payload —
    /// the Merkle link CommitPayload → IndexNode.
    pub payload_hash: [u8; 32],
}

/// Payload of a `Commit` chunk — the per-Tx Merkle root over every
/// active namespace's `IndexRoot`. See `docs/en/reference/format.md` §4.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPayload {
    /// Sorted by `namespace.0` ascending.
    pub roots: Vec<IndexRoot>,
    /// BLAKE3 over `concat(roots[i].payload_hash)` in order.
    pub tx_root_hash: [u8; 32],
}

impl CommitPayload {
    /// Encoded byte length of this CommitPayload.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        2 + 32 + self.roots.len() * (1 + 1 + 8 + 32)
    }

    /// Serialize this payload to wire bytes. Errors if `roots` exceeds
    /// [`MAX_NAMESPACES_PER_TX`] or is not strictly sorted by namespace.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.roots.len() > MAX_NAMESPACES_PER_TX {
            return Err(Error::Internal(
                "commit payload exceeds MAX_NAMESPACES_PER_TX",
            ));
        }
        // Verify sortedness.
        for w in self.roots.windows(2) {
            if w[0].namespace.0 >= w[1].namespace.0 {
                return Err(Error::Internal("commit roots not sorted"));
            }
        }
        let mut buf = Vec::with_capacity(self.encoded_len());
        buf.extend_from_slice(&(self.roots.len() as u16).to_le_bytes());
        for r in &self.roots {
            buf.push(r.namespace.0);
            buf.push(r.kind.as_u8());
            buf.extend_from_slice(&r.index_slot.to_le_bytes());
            buf.extend_from_slice(&r.payload_hash);
        }
        buf.extend_from_slice(&self.tx_root_hash);
        Ok(buf)
    }

    /// Parse a wire-format Commit payload. Errors with [`Error::Malformed`]
    /// on truncation, out-of-range `num_roots`, or non-sorted namespaces.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 + 32 {
            return Err(Error::Malformed("commit payload too short"));
        }
        let num = LittleEndian::read_u16(&bytes[0..2]) as usize;
        if num > MAX_NAMESPACES_PER_TX {
            return Err(Error::Malformed("commit payload num_roots too large"));
        }
        let expected = 2 + 32 + num * (1 + 1 + 8 + 32);
        if bytes.len() < expected {
            return Err(Error::Malformed("commit payload truncated"));
        }
        let mut roots = Vec::with_capacity(num);
        let mut off = 2;
        for _ in 0..num {
            let namespace = Namespace(bytes[off]);
            off += 1;
            let kind = NamespaceKind::from_u8(bytes[off])?;
            off += 1;
            let index_slot = LittleEndian::read_u64(&bytes[off..off + 8]);
            off += 8;
            let mut payload_hash = [0u8; 32];
            payload_hash.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            roots.push(IndexRoot {
                namespace,
                kind,
                index_slot,
                payload_hash,
            });
        }
        // Verify sortedness.
        for w in roots.windows(2) {
            if w[0].namespace.0 >= w[1].namespace.0 {
                return Err(Error::Malformed("commit roots not sorted"));
            }
        }
        let mut tx_root_hash = [0u8; 32];
        tx_root_hash.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        // Audit pass 19 round 2: reject trailing bytes after the
        // last `tx_root_hash`. The payload length is exact for any
        // honest writer; trailing bytes are reachable only by a
        // key-holder/buggy-writer producing a non-canonical
        // CommitPayload. Strict decoding closes the canonical-form
        // gap that would otherwise let two different on-disk byte
        // strings round-trip to the same logical Commit.
        if off != bytes.len() {
            return Err(Error::Malformed(
                "commit payload trailing bytes after tx_root_hash",
            ));
        }
        Ok(Self {
            roots,
            tx_root_hash,
        })
    }

    /// Compute tx_root_hash from roots' payload hashes.
    #[must_use]
    pub fn compute_tx_root_hash(roots: &[IndexRoot]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for r in roots {
            hasher.update(&r.payload_hash);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(hasher.finalize().as_bytes());
        out
    }
}

/// BLAKE3 of an arbitrary byte slice (used for IndexNodePayload bytes).
#[must_use]
pub fn blake3_of(payload: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(blake3::hash(payload).as_bytes());
    out
}
