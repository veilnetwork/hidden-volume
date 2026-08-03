//! Per-space KV index. B+ tree of arbitrary depth, grown level by
//! level on overflow.
//!
//! ## Tree shape
//!
//! ```text
//!   Commit
//!     └── roots[ns] ──> IndexNode chunk
//!                           │
//!                           ├── Leaf(small ns)            — fits in one chunk
//!                           │
//!                           ├── Internal(larger ns)
//!                           │      ├── leaf 0
//!                           │      ├── leaf 1
//!                           │      └── leaf N
//!                           │
//!                           └── Internal(larger still)    — and so on, one
//!                                  ├── Internal             new level each
//!                                  │      ├── leaf 0        time the level
//!                                  │      └── leaf 1        below outgrows
//!                                  └── Internal             a single chunk
//!                                         └── leaf 2
//! ```
//!
//! Small namespaces (≤ ~100 entries depending on value sizes) use a
//! single Leaf node — no overhead. Larger ones are cut into a row of
//! Leaves with an Internal node above them; if that row does not fit in
//! one Internal node either, it is cut into a row of Internal nodes and
//! another level goes on top — repeated until one node covers the whole
//! level. There is no depth limit in the format: a namespace grows
//! until the container itself hits [`crate::MAX_OPEN_SCAN_CHUNKS`]
//! (`Error::ContainerTooLarge`).
//!
//! Internal nodes hold one entry per child: `(first_key, child_slot,
//! child_hash)`. With ~30-byte keys, ~56 children fit in one chunk; at
//! ~100 entries per leaf that is ~5 600 entries under a single
//! Internal node, ~313 K under two levels, ~17 M under three — the
//! reason honest depth stays small even for very large namespaces (see
//! `MIN_FULL_INTERNAL_FANOUT` and the traversal guard in
//! `space::walk`, both internal).
//!
//! ## Where the cuts fall (audit HV-16)
//!
//! A level is not packed greedily. Each item carries a boundary hash
//! and ends its node when that hash says so (`boundary_hash` /
//! `is_boundary`, both internal), so **the shape of a tree is a
//! function of its key-value set and of nothing else** — not of the
//! order the entries arrived in, not of how many transactions built
//! them. That is what lets a commit rewrite
//! only the neighbourhood of an edit (`space::tree`) instead of
//! everything to its right, and it is also a deniability property: a
//! history-dependent shape would let an observer holding two snapshots
//! tell a namespace that was written at once from one that was edited
//! into the same state.
//!
//! The price is fill: mean node utilisation is `K/(K+1)` ≈ 86 %
//! against ~98 % for greedy packing.
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

/// Largest an encoded [`ChildPointer`] can be: `first_key_len` (2) +
/// a maximum-length key + `child_slot` (8) + `child_hash` (32).
pub(crate) const MAX_CHILD_ENTRY_BYTES: usize = 2 + MAX_KEY_LEN + 8 + 32;

/// Children an internal node must hold before a content-defined
/// boundary is honoured (the last node of a level is exempt — it is
/// sealed by running out of children, not by the rule).
///
/// Without a floor the boundary rule is a *statistical* fanout, and a
/// key-holder picking keys whose boundary hashes all fire would get a
/// tree of one-child nodes: unbounded depth from a handful of chunks,
/// and a level-growing loop in the writer that never narrows. The floor
/// turns "wide on average" into "wide, guaranteed", which is what the
/// readers' depth bound is derived from.
///
/// Four rather than a larger number because the floor is also the point
/// where locality stops: a node that *must* hold four children cannot
/// put a boundary anywhere in the first three, so an edit inside it
/// shifts them. Four costs nothing in practice (an internal node holds
/// 13 children at the maximum key length and ~79 at 9-byte keys) and
/// bounds depth at 12 for the largest container the format allows.
pub(crate) const MIN_INTERNAL_CHILDREN: usize = 4;

/// Children a non-final internal node is **guaranteed** to hold.
///
/// Two rules can seal an internal node. A content-defined boundary is
/// only honoured at [`MIN_INTERNAL_CHILDREN`] children or more. An
/// overflow seal happens when the next child would not fit, so the node
/// already holds more than `PAYLOAD_CAP - HEADER_LEN -
/// MAX_CHILD_ENTRY_BYTES` bytes of children — at most
/// `MAX_CHILD_ENTRY_BYTES` each, so at least
/// `(PAYLOAD_CAP - HEADER_LEN) / MAX_CHILD_ENTRY_BYTES - 1` of them.
/// The guarantee is the weaker of the two.
///
/// This is what makes tree depth self-limiting: a level is at least
/// this many times wider than the level above it, so depth grows
/// logarithmically in the chunk count and a container can only be as
/// deep as its size permits. [`crate::space::walk::max_depth_for_budget`]
/// turns that into the readers' depth bound.
pub(crate) const MIN_FULL_INTERNAL_FANOUT: usize = {
    let overflow_floor = (PAYLOAD_CAP - HEADER_LEN) / MAX_CHILD_ENTRY_BYTES - 1;
    if overflow_floor < MIN_INTERNAL_CHILDREN {
        overflow_floor
    } else {
        MIN_INTERNAL_CHILDREN
    }
};

// A fanout of 1 would mean a level need not be wider than the one
// above it, i.e. depth would not be bounded by the chunk count at all
// — and the writer's level-growing loop would not terminate.
const _: () = assert!(MIN_FULL_INTERNAL_FANOUT >= 2);

/// Domain separator for [`boundary_hash`]. Changing it reshapes every
/// tree in the format.
const BOUNDARY_DOMAIN: &[u8] = b"hidden-volume/index-boundary/v1";

/// Reciprocal of the boundary hazard — the `K` in
/// "seal with probability `cost / (K × bytes still free)`".
///
/// The hazard reaches 1 exactly when nothing more fits, so a node is
/// always sealed before it overflows, and the sealed-fill distribution
/// is `P(fill > f) = ((PAYLOAD_CAP - f) / PAYLOAD_CAP)^(1/K)`. Mean
/// utilisation is therefore `K / (K + 1)` — 6/7 ≈ 86 % at `K = 6`,
/// against ~98 % for the greedy packing this replaces. That ~12 points
/// is what buys boundaries that move only near an edit instead of
/// everywhere to its right; see [`is_boundary`].
const BOUNDARY_HAZARD_K: u128 = 6;

/// 64 bits of BLAKE3 over `(domain, level, key)` — the coin a node
/// boundary is decided on.
///
/// `level` (0 = leaves) is mixed in so a key that ends a leaf does not
/// thereby also tend to end the internal node above it; each level gets
/// an independent placement of boundaries over the same key space.
///
/// Levels are counted **from the leaves up**, so growing a namespace
/// (which adds levels at the top) never renumbers an existing level and
/// therefore never reshapes the part of the tree that did not change.
pub(crate) fn boundary_hash(level: u8, key: &[u8]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BOUNDARY_DOMAIN);
    hasher.update(&[level]);
    hasher.update(key);
    let digest = hasher.finalize();
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(head)
}

/// Does the item that brought a node to `fill` bytes end it?
///
/// `hash` is that item's [`boundary_hash`] and `cost` its encoded size.
/// The node is sealed with probability `cost / (K × (PAYLOAD_CAP -
/// fill))` — per *byte* of the item, so the answer does not depend on
/// whether a level holds many small items or few large ones, and the
/// mean node size comes out the same either way.
///
/// ## Why boundaries are decided by content and not by counting
///
/// Packing a level greedily left to right is deterministic too, so it
/// also gives one shape per key set. What it does not give is
/// *locality*: inserting one entry pushes the first leaf past capacity,
/// which pushes one entry into the next leaf, and so on to the end of
/// the namespace. Every node right of the edit changes, which is O(N)
/// nodes to hash, encode and write per commit — measured at ~10 700
/// changed leaves for one insert into a 10⁶-entry namespace.
///
/// Deciding the boundary from the item's own hash makes the split
/// points a property of the keys. An insertion perturbs only the run it
/// lands in; the next boundary is the same key it was before, and from
/// there the packing re-synchronises exactly. Measured, the same insert
/// changes 2.2 leaves at N = 10³ and 2.3 at N = 10⁶.
///
/// The alternative — a B+ tree that splits a full node in half in place
/// — is history-dependent by construction: a namespace filled in one
/// pass and the same namespace edited into existence produce different
/// trees, hence different Merkle roots. In a container built for
/// deniability that is an observable difference between "written at
/// once" and "edited over time", and it would also break the
/// content-keyed node reuse this crate relies on (audit HV-14).
pub(crate) fn is_boundary(hash: u64, cost: usize, fill: usize) -> bool {
    debug_assert!(fill <= PAYLOAD_CAP, "fill must never exceed the payload");
    let remaining = PAYLOAD_CAP.saturating_sub(fill) as u128;
    // hash / 2^64 < cost / (K * remaining)
    (hash as u128) * remaining * BOUNDARY_HAZARD_K < (cost as u128) << 64
}

/// Bytes one `(key, value)` pair adds to a [`LeafNode`] encoding.
pub(crate) fn leaf_entry_cost(key: &[u8], value: &[u8]) -> usize {
    2 + key.len() + 4 + value.len()
}

/// Bytes one [`ChildPointer`] adds to an [`InternalNode`] encoding.
pub(crate) fn child_entry_cost(first_key: &[u8]) -> usize {
    2 + first_key.len() + 8 + 32
}

/// Encoded size of a node holding nothing — the starting `fill` of any
/// run. Taken from the encoders so it cannot drift from them.
pub(crate) const NODE_HEADER_LEN: usize = HEADER_LEN;

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
