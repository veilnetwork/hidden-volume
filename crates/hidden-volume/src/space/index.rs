//! Per-space KV index. 2-level B+ tree with split-on-overflow.
//!
//! ## Tree shape
//!
//! ```text
//!   Commit
//!     └── roots[ns] ──> IndexNode chunk
//!                           │
//!                           ├── Leaf(small ns)            — fits in one chunk
//!                           │
//!                           └── Internal(large ns)
//!                                  ├── leaf 0
//!                                  ├── leaf 1
//!                                  └── leaf N
//! ```
//!
//! Small namespaces (≤ ~100 entries depending on value sizes) use a
//! single Leaf node — no overhead. When a Leaf overflows on encode, it
//! splits in half and a new Internal node is emitted referencing the
//! two halves; the namespace's root pointer is updated.
//!
//! Internal nodes hold one entry per child: `(first_key, child_slot,
//! child_hash)`. With ~30-byte keys, ~56 children fit in one chunk;
//! at ~100 entries per leaf this caps a namespace at ~5600 entries.
//! Larger namespaces need a deeper tree (not implemented; trigger is a
//! real user hitting the cap) or `DataBatch` (for the message log).
//!
//! ## On-disk encoding
//!
//! IndexNode plaintext payload (inside AEAD region):
//!
//! ```text
//!   node_type   : u8         0 = Leaf, 1 = Internal
//!   namespace   : u8
//!   if Leaf:
//!     num_entries : u16 LE
//!     for each entry, sorted by key:
//!       key_len   : u16 LE
//!       key bytes
//!       value_len : u32 LE
//!       value bytes
//!   if Internal:
//!     num_children: u16 LE
//!     for each child, sorted by first_key:
//!       first_key_len : u16 LE
//!       first_key bytes
//!       child_slot    : u64 LE
//!       child_hash    : [u8; 32]
//! ```

use byteorder::{ByteOrder, LittleEndian};

use crate::chunk::format::PAYLOAD_CAP;
use crate::{Error, Result};

/// Namespace identifier inside a space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct Namespace(pub u8);

impl Namespace {
    /// User settings (theme, language, profile bits).
    pub const SETTINGS: Self = Self(1);
    /// Contact list (one entry per peer).
    pub const CONTACTS: Self = Self(2);
    /// Append-log namespace for the message stream (DataBatch storage).
    pub const MESSAGE_LOG: Self = Self(3);
    /// Media blobs (large values, content-addressed by host-app).
    pub const MEDIA: Self = Self(4);
    /// Reserved namespace ID; do not use for application data.
    pub const RESERVED: Self = Self(0);

    /// Return the underlying byte tag (`Namespace.0`).
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self.0
    }
}

// Audit B5 (2026-05-02): no `impl Default for Namespace`.
// The previous implementation returned `RESERVED`, which is rejected by
// every `Tx::put` / `Tx::delete` / `Tx::append_log` — so `Namespace::default()`
// produced an unusable value that always failed at the next call site.
// Callers must pick an explicit namespace constant (`SETTINGS`, `CONTACTS`,
// `MESSAGE_LOG`, `MEDIA`) or construct via `Namespace(byte)`.

/// Maximum allowed length for a KV key (256 bytes).
pub const MAX_KEY_LEN: usize = 256;
/// Maximum allowed length for a KV value (2048 bytes).
pub const MAX_VALUE_LEN: usize = 2048;

/// Maximum permitted depth of a B+ tree walked by any reader. The
/// writer-side invariant ([`crate::space::Space`]'s
/// `write_tree_for_namespace`) only ever emits trees of depth ≤ 2 (a
/// single Leaf, or one Internal node over a row of Leaves), so the
/// cap = 3 leaves one level of safety margin without constraining
/// any legitimate use.
///
/// ## Semantics of the cap (locked-down 2026-05-28)
///
/// `depth` is incremented every time a walker descends from one
/// `IndexNode::Internal` to the next layer; the root counts as
/// `depth = 0`. Every walker uses the **strict-greater** comparison
/// `depth > MAX_TREE_DEPTH` so that:
///
/// - `depth = 0` (root, may be Internal or Leaf) is always allowed;
/// - `depth = 1, 2, 3` (Internal-over-row, or the legitimate
///   two-level shape, or one extra step) are allowed;
/// - `depth = 4` is the first value that trips the cap.
///
/// The post-v3 (audit pass 19 follow-through) refactor brought every
/// walker — `Space::get`, `collect_leaves_at`, `count_leaves_at`,
/// `log_iter::*`, `integrity::*`, `vacuum::*` — onto the same
/// strict-greater comparison so behaviour is identical across the
/// read paths. Previously `Space::get` used `>=` which capped one
/// step earlier; the inconsistency was cosmetic (writer-side
/// invariant guarantees depth ≤ 2 in well-formed containers) but
/// the unified shape is easier to review.
///
/// The cap is **defense-in-depth** against:
///
/// 1. a writer-bug regression that emits a cycle of `IndexNode`
///    chunks (would otherwise stack-overflow or loop-forever the
///    reader);
/// 2. an adversarial key-holder hand-crafting cyclic `IndexNode`
///    chunks (out of the strict threat model but cheap to defend
///    against — see
///    [`docs/en/security/audits/adversarial-stance.md` F-A5](../../../../docs/en/security/audits/adversarial-stance.md));
/// 3. any future format change that legitimately needs deeper trees
///    — bump this constant alongside the format-version bump (the
///    `R-LOG-INDEX-3L` v1.x candidate in `TASKS.md` would raise it
///    to ≥ 4).
///
/// Walkers exceeding this cap return
/// [`Error::Malformed`](crate::Error::Malformed)
/// (`"tree depth exceeded MAX_TREE_DEPTH"`).
pub(crate) const MAX_TREE_DEPTH: u8 = 3;

const NODE_TYPE_LEAF: u8 = 0;
const NODE_TYPE_INTERNAL: u8 = 1;

const HEADER_LEN: usize = 1 + 1 + 2; // node_type + namespace + count

/// One pointer from an internal node to a child (leaf or another internal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildPointer {
    /// First key in the child subtree (used for binary search).
    pub first_key: Vec<u8>,
    /// Slot index of the child IndexNode chunk.
    pub child_slot: u64,
    /// BLAKE3 hash of the child IndexNode's plaintext payload —
    /// the Merkle link parent → child.
    pub child_hash: [u8; 32],
}

/// A leaf node — terminal `(key, value)` storage.
///
/// Construct via [`LeafNode::new`]. There is no `Default` impl: a
/// default leaf would need a namespace, and there is no sane default
/// (audit B5, 2026-05-02: a previous `impl Default for Namespace`
/// returned `RESERVED` which `Tx::put` / `Tx::delete` /
/// `Tx::append_log` reject — pure footgun).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafNode {
    /// Namespace this leaf belongs to.
    pub namespace: Namespace,
    /// Entries in this leaf, sorted ascending by key.
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
}

/// An internal node — index over children.
///
/// Construct via [`InternalNode::new`]; same rationale as `LeafNode`
/// for not deriving `Default`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalNode {
    /// Namespace this internal node belongs to.
    pub namespace: Namespace,
    /// Child pointers, ordered by `first_key`.
    pub children: Vec<ChildPointer>,
}

/// IndexNode in the chunk format. Either a [`LeafNode`] or [`InternalNode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexNode {
    /// A terminal leaf containing `(key, value)` pairs.
    Leaf(LeafNode),
    /// An internal node containing pointers to child IndexNodes.
    Internal(InternalNode),
}

impl IndexNode {
    /// Encode this node into the IndexNode-chunk plaintext payload
    /// (≤ [`crate::chunk::format::PAYLOAD_CAP`]).
    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::Leaf(l) => l.encode(),
            Self::Internal(i) => i.encode(),
        }
    }

    /// Decode an IndexNode-chunk plaintext payload into the variant
    /// indicated by its leading discriminator byte.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Malformed("index node payload too short"));
        }
        match bytes[0] {
            NODE_TYPE_LEAF => Ok(Self::Leaf(LeafNode::decode(bytes)?)),
            NODE_TYPE_INTERNAL => Ok(Self::Internal(InternalNode::decode(bytes)?)),
            _ => Err(Error::Malformed("unknown index node type")),
        }
    }
}

impl LeafNode {
    /// Create an empty leaf for `namespace`.
    #[must_use]
    pub fn new(namespace: Namespace) -> Self {
        Self {
            namespace,
            entries: Vec::new(),
        }
    }

    /// Encoded byte length of this leaf, useful for fit-checks before
    /// attempting `encode`.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let mut n = HEADER_LEN;
        for (k, v) in &self.entries {
            n += 2 + k.len() + 4 + v.len();
        }
        n
    }

    /// Encode this leaf into the chunk payload format
    /// (`docs/en/reference/format.md` §4.2.1). Errors with
    /// [`Error::Malformed`] if the encoded size would exceed
    /// [`PAYLOAD_CAP`] — caller should split the leaf and use an
    /// internal node above.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let total = self.encoded_len();
        if total > PAYLOAD_CAP {
            return Err(Error::Malformed("leaf node would exceed PAYLOAD_CAP"));
        }
        if self.entries.len() > u16::MAX as usize {
            return Err(Error::Malformed("too many entries in leaf"));
        }
        // Audit pass 7 (C2): encoder/decoder symmetry. `decode`
        // strict-rejects unsorted entries; `encode` previously
        // accepted them silently, breaking encode→decode bijectivity
        // if a writer-bug regression produced unsorted input. The
        // debug-assert fails the regression in tests; release builds
        // pay nothing.
        debug_assert!(
            self.entries.windows(2).all(|w| w[0].0 < w[1].0),
            "LeafNode::encode requires entries sorted ascending by key"
        );
        let mut buf = Vec::with_capacity(total);
        buf.push(NODE_TYPE_LEAF);
        buf.push(self.namespace.0);
        buf.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for (k, v) in &self.entries {
            if k.is_empty() || k.len() > MAX_KEY_LEN {
                return Err(Error::Malformed("invalid key length"));
            }
            if v.len() > MAX_VALUE_LEN {
                return Err(Error::Malformed("value exceeds MAX_VALUE_LEN"));
            }
            buf.extend_from_slice(&(k.len() as u16).to_le_bytes());
            buf.extend_from_slice(k);
            buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
            buf.extend_from_slice(v);
        }
        Ok(buf)
    }

    /// Decode a leaf payload back into a `LeafNode`. Returns
    /// [`Error::Malformed`] for invalid byte layout / out-of-range
    /// lengths / non-leaf discriminator.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN || bytes[0] != NODE_TYPE_LEAF {
            return Err(Error::Malformed("not a leaf node"));
        }
        let namespace = Namespace(bytes[1]);
        let num = LittleEndian::read_u16(&bytes[2..4]) as usize;
        // G2 (audit pass 5): defense-in-depth bound on `num` before
        // pre-allocation. `num` is post-AEAD plaintext — an attacker
        // without the key cannot reach this — but a corrupted writer or
        // on-disk bit flip could ask for ~3 MiB allocation (65535 × 48 B
        // entry size). Each leaf entry needs at minimum
        // `MIN_LEAF_ENTRY_BYTES = 2 (klen) + 1 (key, klen >= 1 enforced
        // below) + 4 (vlen) = 7` bytes, so any honest payload satisfies
        // `num * 7 <= bytes.len() - HEADER_LEN`. Reject larger.
        const MIN_LEAF_ENTRY_BYTES: usize = 2 + 1 + 4;
        if num.saturating_mul(MIN_LEAF_ENTRY_BYTES) > bytes.len() - HEADER_LEN {
            return Err(Error::Malformed("leaf count exceeds payload bound"));
        }
        let mut entries = Vec::with_capacity(num);
        let mut off = HEADER_LEN;
        for _ in 0..num {
            if bytes.len() < off + 2 {
                return Err(Error::Malformed("leaf truncated at key_len"));
            }
            let klen = LittleEndian::read_u16(&bytes[off..off + 2]) as usize;
            off += 2;
            if klen == 0 || klen > MAX_KEY_LEN {
                return Err(Error::Malformed("invalid leaf key length"));
            }
            if bytes.len() < off + klen + 4 {
                return Err(Error::Malformed("leaf truncated at key/value_len"));
            }
            let key = bytes[off..off + klen].to_vec();
            off += klen;
            let vlen = LittleEndian::read_u32(&bytes[off..off + 4]) as usize;
            off += 4;
            if vlen > MAX_VALUE_LEN {
                return Err(Error::Malformed("invalid leaf value length"));
            }
            if bytes.len() < off + vlen {
                return Err(Error::Malformed("leaf truncated at value"));
            }
            let value = bytes[off..off + vlen].to_vec();
            off += vlen;
            entries.push((key, value));
        }
        // Audit pass 19 round 2: reject trailing bytes after the
        // last entry. The leaf encoding is exact-length; trailing
        // bytes are reachable only by a buggy/malicious writer.
        if off != bytes.len() {
            return Err(Error::Malformed(
                "leaf payload trailing bytes after last entry",
            ));
        }
        for w in entries.windows(2) {
            // `windows(2)` yields slices of length 2 by definition; the
            // pattern destructure can only fail if a future `windows`
            // refactor changes that shape. Audit pass 17: previously
            // `unreachable!()` panicked here — replaced with a typed
            // `Internal` error so a hypothetical future invariant
            // regression surfaces as a recoverable error rather than
            // process abort.
            let [a, b] = w else {
                return Err(Error::Internal(
                    "leaf decode: windows(2) returned non-pair slice",
                ));
            };
            if a.0 >= b.0 {
                return Err(Error::Malformed("leaf entries not sorted"));
            }
        }
        Ok(Self { namespace, entries })
    }

    /// Look up `key` in this leaf, returning a slice into the stored
    /// value if present.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        match self
            .entries
            .binary_search_by(|(k, _)| k.as_slice().cmp(key))
        {
            Ok(idx) => Some(self.entries[idx].1.as_slice()),
            Err(_) => None,
        }
    }
}

impl InternalNode {
    /// Create an empty internal node for `namespace`.
    #[must_use]
    pub fn new(namespace: Namespace) -> Self {
        Self {
            namespace,
            children: Vec::new(),
        }
    }

    /// Encoded byte length of this internal node, useful for fit-
    /// checks before attempting `encode`.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let mut n = HEADER_LEN;
        for c in &self.children {
            n += 2 + c.first_key.len() + 8 + 32;
        }
        n
    }

    /// Encode this internal node into the chunk payload format
    /// (`docs/en/reference/format.md` §4.2.2). Errors with [`Error::IndexFull`]
    /// if the encoded size would exceed [`PAYLOAD_CAP`], or
    /// [`Error::Malformed`] if the node would be structurally invalid
    /// (zero children).
    pub fn encode(&self) -> Result<Vec<u8>> {
        // Audit pass 11 (L1): encoder/decoder symmetry. `decode`
        // strict-rejects `num == 0`; refusing to encode it here
        // closes a writer-bug regression vector. A B+ tree internal
        // node MUST have ≥ 1 child by construction.
        if self.children.is_empty() {
            return Err(Error::Malformed("internal node has zero children"));
        }
        let total = self.encoded_len();
        if total > PAYLOAD_CAP {
            return Err(Error::IndexFull);
        }
        if self.children.len() > u16::MAX as usize {
            return Err(Error::Malformed("too many children in internal node"));
        }
        // Audit pass 7 (C2): encoder/decoder symmetry — same
        // rationale as `LeafNode::encode`. `decode` strict-rejects
        // unsorted children; this debug-assert fails a writer-bug
        // regression in tests.
        debug_assert!(
            self.children
                .windows(2)
                .all(|w| w[0].first_key < w[1].first_key),
            "InternalNode::encode requires children sorted ascending by first_key"
        );
        let mut buf = Vec::with_capacity(total);
        buf.push(NODE_TYPE_INTERNAL);
        buf.push(self.namespace.0);
        buf.extend_from_slice(&(self.children.len() as u16).to_le_bytes());
        for c in &self.children {
            if c.first_key.is_empty() || c.first_key.len() > MAX_KEY_LEN {
                return Err(Error::Malformed("invalid first_key length"));
            }
            buf.extend_from_slice(&(c.first_key.len() as u16).to_le_bytes());
            buf.extend_from_slice(&c.first_key);
            buf.extend_from_slice(&c.child_slot.to_le_bytes());
            buf.extend_from_slice(&c.child_hash);
        }
        Ok(buf)
    }

    /// Decode an internal-node payload back into an `InternalNode`.
    /// Returns [`Error::Malformed`] for invalid byte layout / out-of-
    /// range lengths / non-internal discriminator.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN || bytes[0] != NODE_TYPE_INTERNAL {
            return Err(Error::Malformed("not an internal node"));
        }
        let namespace = Namespace(bytes[1]);
        let num = LittleEndian::read_u16(&bytes[2..4]) as usize;
        // Audit pass 11 (L1): an internal node with zero children is
        // structurally invalid — `child_index_for` would return 0 on
        // empty `children`, and `Space::get` would then panic on
        // `children[0]`. A B+ tree node MUST have ≥ 1 child by
        // construction; reject the malformed case here. Threat
        // model: key-holder / buggy writer (post-AEAD path).
        if num == 0 {
            return Err(Error::Malformed("internal node has zero children"));
        }
        // G3 (audit pass 5): same defense-in-depth bound as `LeafNode`.
        // Each child entry is at minimum
        // `MIN_INTERNAL_CHILD_BYTES = 2 (klen) + 1 (first_key) + 8
        // (child_slot) + 32 (child_hash) = 43` bytes.
        const MIN_INTERNAL_CHILD_BYTES: usize = 2 + 1 + 8 + 32;
        if num.saturating_mul(MIN_INTERNAL_CHILD_BYTES) > bytes.len() - HEADER_LEN {
            return Err(Error::Malformed("internal count exceeds payload bound"));
        }
        let mut children = Vec::with_capacity(num);
        let mut off = HEADER_LEN;
        for _ in 0..num {
            if bytes.len() < off + 2 {
                return Err(Error::Malformed("internal truncated at first_key_len"));
            }
            let klen = LittleEndian::read_u16(&bytes[off..off + 2]) as usize;
            off += 2;
            if klen == 0 || klen > MAX_KEY_LEN {
                return Err(Error::Malformed("invalid internal first_key length"));
            }
            if bytes.len() < off + klen + 8 + 32 {
                return Err(Error::Malformed("internal truncated at child entry"));
            }
            let first_key = bytes[off..off + klen].to_vec();
            off += klen;
            let child_slot = LittleEndian::read_u64(&bytes[off..off + 8]);
            off += 8;
            let mut child_hash = [0u8; 32];
            child_hash.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            children.push(ChildPointer {
                first_key,
                child_slot,
                child_hash,
            });
        }
        // Audit pass 19 round 2: reject trailing bytes after the
        // last child entry. Same canonical-form rationale as
        // `LeafNode::decode` / `CommitPayload::decode` /
        // `Superblock::decode`.
        if off != bytes.len() {
            return Err(Error::Malformed(
                "internal payload trailing bytes after last child",
            ));
        }
        for w in children.windows(2) {
            // See `LeafNode::decode`'s identical guard for rationale
            // (audit pass 17: prefer typed Internal error over panic).
            let [a, b] = w else {
                return Err(Error::Internal(
                    "internal decode: windows(2) returned non-pair slice",
                ));
            };
            if a.first_key >= b.first_key {
                return Err(Error::Malformed("internal children not sorted"));
            }
        }
        Ok(Self {
            namespace,
            children,
        })
    }

    /// Find the index of the child responsible for `key` (largest
    /// `first_key ≤ key`). The first child has implicit first_key = -∞.
    #[must_use]
    pub fn child_index_for(&self, key: &[u8]) -> usize {
        // partition_point: first index where first_key > key.
        // The child responsible is the one BEFORE that, but at least 0.
        let pp = self
            .children
            .partition_point(|c| c.first_key.as_slice() <= key);
        if pp == 0 { 0 } else { pp - 1 }
    }
}
