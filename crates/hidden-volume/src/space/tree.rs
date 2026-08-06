//! Building and updating a namespace's B+ tree (audit HV-16).
//!
//! Two entry points, and they must agree byte for byte:
//!
//! - [`Space::build_tree`] turns a sorted stream of entries into a
//!   whole tree. Used when a namespace has no prior root.
//! - [`Space::update_tree`] applies a set of key operations to an
//!   existing tree by descending to the affected leaf and rewriting the
//!   path above it.
//!
//! ## Why they can agree
//!
//! Where a node ends is decided by [`super::index::is_boundary`] from
//! the item's own hash, not by counting bytes into a fixed budget. The
//! packer is therefore a left-to-right automaton whose entire state is
//! "the items since the last boundary": at any boundary the state is
//! empty, so two runs that reach the same boundary with the same
//! remaining input produce identical output from there on.
//!
//! [`Space::update_tree`] is exactly that observation used twice. It
//! starts at a boundary (the beginning of the leaf it descends to,
//! which nothing to its left has moved), and it stops at the first
//! boundary that coincides with an old node's end after every operation
//! has been applied — from there the old nodes are, byte for byte, what
//! a full rebuild would have produced, so they are left alone. Each
//! level above repeats the argument one level up.
//!
//! The property is load-bearing, not an optimisation: if the two
//! disagreed, the same namespace would hash differently depending on
//! how it was written, which is exactly the history leak the
//! content-defined boundaries exist to prevent. It is pinned by
//! `tests/hv16_incremental_commit.rs`.
//!
//! ## What it costs
//!
//! Reads and writes are proportional to the span of keys the operations
//! touch, plus one node per level. A commit that appends, edits one
//! key, or writes a contiguous batch therefore costs O(batch) and not
//! O(namespace). A commit whose keys are scattered across the whole
//! namespace still costs the span between the outermost two — the same
//! O(namespace) the previous flatten-and-rebuild always paid, so
//! nothing regresses.

use std::collections::{BTreeMap, HashMap, HashSet};

use zeroize::Zeroizing;

use crate::chunk::ChunkKind;
use crate::chunk::format::PAYLOAD_CAP;
use crate::redact::Redacted;
use crate::tx::commit::{IndexRoot, blake3_of};
use crate::{Error, Result};

use super::Space;
use super::index::{
    ChildPointer, IndexNode, InternalNode, LeafNode, MIN_FULL_INTERNAL_FANOUT,
    MIN_INTERNAL_CHILDREN, NODE_HEADER_LEN, Namespace, boundary_hash, child_entry_cost,
    is_boundary, leaf_entry_cost,
};
use super::walk::TreeWalk;

/// The operations of one Tx against one namespace, collapsed to one
/// entry per key in key order. `None` is a delete.
///
/// `Redacted` because this is a **full copy** of the transaction's
/// plaintext — every key and every value it writes — and the `KvOp`s it
/// is built from are themselves redacted (report7 P3). A bare map here
/// let the copy print under `{:?}` and outlive its source's scrub, which
/// is the shape of leak `redact` exists to close: the wrapper on the
/// original said nothing about the derived collection.
pub(super) type KeyOps = Redacted<BTreeMap<Vec<u8>, Option<Vec<u8>>>>;

/// Index chunks of the namespace's **current** tree that a rebuild may
/// point at instead of writing again (audit HV-14), keyed by the BLAKE3
/// the parent already stores as its Merkle link.
///
/// A rebuild that produces a node whose payload hashes to a key in here
/// has produced a node that is already on disk, byte for byte, in a
/// chunk this space owns and currently reaches. Pointing at that chunk
/// is not an optimisation of the encoding — it *is* the same node.
///
/// The hash covers the node-type byte and the namespace byte (they sit
/// in the encoded header), so a match cannot silently swap a leaf for
/// an internal node or graft a chunk from a neighbouring namespace.
///
/// Since HV-16 the map holds only the nodes the update actually read —
/// the path and the rewritten neighbourhood — because those are the
/// only nodes a rebuild can reproduce. Everything else is not rebuilt
/// at all.
type ReusableNodes = HashMap<[u8; 32], u64>;

/// Everything a tree build needs besides the entries themselves.
pub(super) struct Build {
    /// `seq` stamped into every chunk this commit appends.
    seq: u64,
    reuse: ReusableNodes,
    /// Slots already used by this build. Belt-and-braces: a chunk
    /// reachable twice in one walk is a structural failure the readers
    /// reject outright (`space::walk`), and a hostile prior tree is the
    /// input here.
    emitted: HashSet<u64>,
    /// Shared traversal guard for the descent — visited set, chunk
    /// budget and the derived depth bound.
    walk: TreeWalk,
    /// Last key handed to any level-0 node, for the global-order check.
    prev_leaf_key: Option<Vec<u8>>,
    /// Same, per internal level: `prev_level_key[l - 1]`.
    prev_level_key: Vec<Option<Vec<u8>>>,
}

impl Build {
    pub(super) fn new(seq: u64, walk: TreeWalk) -> Self {
        Self {
            seq,
            reuse: ReusableNodes::new(),
            emitted: HashSet::new(),
            walk,
            prev_leaf_key: None,
            prev_level_key: Vec::new(),
        }
    }

    /// Record a node this build has read, so re-deriving it costs no
    /// write. `hash` is the Merkle link its parent stores.
    fn remember(&mut self, hash: [u8; 32], slot: u64) {
        self.reuse.insert(hash, slot);
    }

    /// Reject a key that does not advance the level's key order.
    ///
    /// The per-node decoders only check order *within* a node. The
    /// cross-node order is what the whole update relies on — it is why
    /// merging the operations into the entry stream is a merge at all —
    /// and a key-holder can craft a tree whose child `first_key`s are
    /// sorted while the leaf ranges under them overlap. Rewriting such
    /// a tree would emit unsorted nodes, which the readers then refuse:
    /// the namespace would be bricked by a successful commit. Catch it
    /// on the way in instead (audit pass 20, kept through HV-16).
    fn check_order(&mut self, level: u8, key: &[u8]) -> Result<()> {
        let slot = if level == 0 {
            &mut self.prev_leaf_key
        } else {
            let idx = level as usize - 1;
            if self.prev_level_key.len() <= idx {
                self.prev_level_key.resize(idx + 1, None);
            }
            &mut self.prev_level_key[idx]
        };
        if let Some(prev) = slot.as_deref()
            && prev >= key
        {
            return Err(Error::Malformed(
                "tree nodes are not globally sorted / contain duplicate keys",
            ));
        }
        *slot = Some(key.to_vec());
        Ok(())
    }
}

/// Unsealed level-0 items — the entries of the leaf being formed.
struct LeafRun {
    ns: Namespace,
    /// `Redacted` for the same reason as [`KeyOps`]: these are the
    /// `(key, value)` pairs of a leaf, in the clear, held for as long as
    /// the run is open (report7 P3). `LeafNode` already wears the
    /// wrapper on the identical field; the buffer that feeds it did not.
    entries: Redacted<Vec<(Vec<u8>, Vec<u8>)>>,
    fill: usize,
}

/// Unsealed items of an internal level.
struct NodeRun {
    ns: Namespace,
    /// 1 = the level directly above the leaves.
    level: u8,
    children: Vec<ChildPointer>,
    fill: usize,
}

impl LeafRun {
    fn new(ns: Namespace) -> Self {
        Self {
            ns,
            entries: Redacted::new(Vec::new()),
            fill: NODE_HEADER_LEN,
        }
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl NodeRun {
    fn new(ns: Namespace, level: u8) -> Self {
        Self {
            ns,
            level,
            children: Vec::new(),
            fill: NODE_HEADER_LEN,
        }
    }

    fn is_empty(&self) -> bool {
        self.children.is_empty()
    }
}

/// One level of a root-to-leaf descent: the decoded internal node and
/// the index of the child the descent went through.
#[derive(Clone)]
struct Step {
    node: InternalNode,
    idx: usize,
}

/// A descent that stopped on a leaf, with the path that got there.
struct Descent {
    /// `steps[0]` is the root; `steps.last()` is the leaf's parent.
    /// Empty when the root is itself a leaf.
    steps: Vec<Step>,
    /// Pointer *to* the leaf. Synthesised from the root when the tree
    /// is a single leaf.
    leaf_ptr: ChildPointer,
    leaf: LeafNode,
}

impl<'f> Space<'f> {
    /// Append an index node — or discover it is already on disk.
    ///
    /// A hash hit means the chunk at that slot decrypts to exactly these
    /// bytes: same node type, same namespace, same entries. The chunk is
    /// owned by this space and reachable from the committed tree, so it
    /// is neither foreign, nor scrubbed, nor about to be: it stays
    /// reachable from the tree being built, which is what
    /// `vacuum_orphans` computes reachability against.
    fn emit_index_node(&mut self, bytes: &[u8], b: &mut Build) -> Result<(u64, [u8; 32])> {
        let hash = blake3_of(bytes);
        if let Some(&slot) = b.reuse.get(&hash)
            && b.emitted.insert(slot)
        {
            return Ok((slot, hash));
        }
        let slot = self.place_chunk(ChunkKind::IndexNode, b.seq, bytes)?;
        b.emitted.insert(slot);
        Ok((slot, hash))
    }

    // --- level 0 ---

    fn leaf_push(
        &mut self,
        run: &mut LeafRun,
        key: Vec<u8>,
        value: Vec<u8>,
        b: &mut Build,
        out: &mut Vec<ChildPointer>,
    ) -> Result<()> {
        b.check_order(0, &key)?;
        let cost = leaf_entry_cost(&key, &value);
        if run.entries.is_empty() {
            if NODE_HEADER_LEN + cost > PAYLOAD_CAP {
                return Err(Error::Malformed("single entry too large for any leaf"));
            }
        } else if run.fill + cost > PAYLOAD_CAP {
            self.leaf_seal(run, b, out)?;
        }
        let hash = boundary_hash(0, &key);
        run.fill += cost;
        run.entries.push((key, value));
        if is_boundary(hash, cost, run.fill) {
            self.leaf_seal(run, b, out)?;
        }
        Ok(())
    }

    fn leaf_seal(
        &mut self,
        run: &mut LeafRun,
        b: &mut Build,
        out: &mut Vec<ChildPointer>,
    ) -> Result<()> {
        if run.entries.is_empty() {
            return Ok(());
        }
        let first_key = Redacted::new(run.entries[0].0.clone());
        let node = LeafNode {
            namespace: run.ns,
            entries: Redacted::new(std::mem::take(&mut run.entries)),
        };
        run.fill = NODE_HEADER_LEN;
        // Encoded leaf carries user KV bytes; scrub on drop.
        let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(node.encode()?);
        let (child_slot, child_hash) = self.emit_index_node(&bytes, b)?;
        out.push(ChildPointer {
            first_key,
            child_slot,
            child_hash,
        });
        Ok(())
    }

    // --- internal levels ---

    fn node_push(
        &mut self,
        run: &mut NodeRun,
        child: ChildPointer,
        b: &mut Build,
        out: &mut Vec<ChildPointer>,
    ) -> Result<()> {
        b.check_order(run.level, &child.first_key)?;
        let cost = child_entry_cost(&child.first_key);
        if run.children.is_empty() {
            if NODE_HEADER_LEN + cost > PAYLOAD_CAP {
                // Unreachable via MAX_KEY_LEN (298 bytes at most against
                // a 4 040-byte payload), but a first_key is copied from
                // user data and this is the write path.
                return Err(Error::Malformed(
                    "single child pointer too large for any internal node",
                ));
            }
        } else if run.fill + cost > PAYLOAD_CAP {
            self.node_seal(run, b, out, false)?;
        }
        let hash = boundary_hash(run.level, &child.first_key);
        run.fill += cost;
        run.children.push(child);
        if run.children.len() >= MIN_INTERNAL_CHILDREN && is_boundary(hash, cost, run.fill) {
            self.node_seal(run, b, out, false)?;
        }
        Ok(())
    }

    /// Seal the internal node being formed. `last_of_level` marks the
    /// node that ends its level, which is the only one allowed to be
    /// narrower than [`MIN_FULL_INTERNAL_FANOUT`].
    ///
    /// The width check is the writer refusing to publish a tree its own
    /// readers would reject: their depth bound is the inverse of exactly
    /// this invariant ([`super::walk::max_depth_for_budget`]). The rule
    /// above cannot violate it, so what this catches is a future change
    /// that quietly weakens the packing — which would otherwise commit
    /// successfully and leave the namespace unreadable, the worst
    /// failure this crate has.
    fn node_seal(
        &mut self,
        run: &mut NodeRun,
        b: &mut Build,
        out: &mut Vec<ChildPointer>,
        last_of_level: bool,
    ) -> Result<()> {
        if run.children.is_empty() {
            return Ok(());
        }
        if !last_of_level && run.children.len() < MIN_FULL_INTERNAL_FANOUT {
            return Err(Error::IndexFull);
        }
        let first_key = run.children[0].first_key.clone();
        let node = InternalNode {
            namespace: run.ns,
            children: std::mem::take(&mut run.children),
        };
        run.fill = NODE_HEADER_LEN;
        // Encoded internal node carries user `first_key` bytes; scrub.
        let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(node.encode()?);
        let (child_slot, child_hash) = self.emit_index_node(&bytes, b)?;
        out.push(ChildPointer {
            first_key,
            child_slot,
            child_hash,
        });
        Ok(())
    }

    /// Stack levels on top of `level` until one node covers it. Used by
    /// the full build, and by an update whose root level widened.
    fn grow_levels(
        &mut self,
        ns: Namespace,
        mut level: Vec<ChildPointer>,
        mut lvl: u8,
        b: &mut Build,
    ) -> Result<Option<(u64, [u8; 32])>> {
        while level.len() > 1 {
            let below = level.len();
            let mut run = NodeRun::new(ns, lvl);
            let mut out = Vec::with_capacity(below / MIN_INTERNAL_CHILDREN + 1);
            for child in level {
                self.node_push(&mut run, child, b, &mut out)?;
            }
            self.node_seal(&mut run, b, &mut out, true)?;
            // Every level is strictly narrower than the one below it:
            // a node holds at least MIN_INTERNAL_CHILDREN pointers
            // unless it ends the level. Without progress this would spin
            // forever appending chunks; refuse instead.
            if out.len() >= below {
                return Err(Error::IndexFull);
            }
            level = out;
            lvl = lvl
                .checked_add(1)
                .ok_or(Error::Internal("index level counter overflow"))?;
        }
        Ok(level.pop().map(|r| (r.child_slot, r.child_hash)))
    }

    /// Build a namespace's whole tree from a sorted entry stream.
    /// `Ok(None)` when the stream is empty.
    pub(super) fn build_tree<I>(
        &mut self,
        ns: Namespace,
        entries: I,
        b: &mut Build,
    ) -> Result<Option<(u64, [u8; 32])>>
    where
        I: IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
    {
        let mut run = LeafRun::new(ns);
        let mut level = Vec::new();
        for (key, value) in entries {
            self.leaf_push(&mut run, key, value, b, &mut level)?;
        }
        self.leaf_seal(&mut run, b, &mut level)?;
        if level.is_empty() {
            return Ok(None);
        }
        self.grow_levels(ns, level, 1, b)
    }

    // --- incremental update ---

    /// Read the index node `ptr` names, admitting it to the traversal
    /// guard at `depth` descents and recording it as reusable.
    fn read_node(
        &mut self,
        ptr: &ChildPointer,
        ns: Namespace,
        depth: u8,
        b: &mut Build,
    ) -> Result<IndexNode> {
        b.walk.admit(ptr.child_slot, depth)?;
        let node = self.read_index_node_at_expected(ptr.child_slot, ns)?;
        b.remember(ptr.child_hash, ptr.child_slot);
        Ok(node)
    }

    /// Descend to the leaf responsible for `key`, decoding it.
    fn descend(&mut self, root: &IndexRoot, key: &[u8], b: &mut Build) -> Result<Descent> {
        let mut steps: Vec<Step> = Vec::new();
        let mut ptr = ChildPointer {
            // The root has no parent to name a first_key; it is never
            // used, because the leaf a descent lands on is always
            // rewritten (the key that steered the descent is in it).
            first_key: Redacted::default(),
            child_slot: root.index_slot,
            child_hash: root.payload_hash,
        };
        let mut depth: u8 = 0;
        loop {
            match self.read_node(&ptr, root.namespace, depth, b)? {
                IndexNode::Leaf(leaf) => {
                    return Ok(Descent {
                        steps,
                        leaf_ptr: ptr,
                        leaf,
                    });
                },
                IndexNode::Internal(node) => {
                    let idx = node.child_index_for(key);
                    ptr = node
                        .children
                        .get(idx)
                        .ok_or(Error::Malformed("internal node has zero children"))?
                        .clone();
                    steps.push(Step { node, idx });
                    depth = depth
                        .checked_add(1)
                        .ok_or(Error::Malformed("tree deeper than a u8 can count"))?;
                },
            }
        }
    }

    /// Move the cursor for tree-depth `di` (`1..=steps.len()`) one node
    /// to the right, reading whatever internal nodes that requires.
    /// `Ok(None)` at the end of that level.
    ///
    /// `steps[di]` is *not* updated — the caller decides whether the
    /// node behind the returned pointer is a leaf or another internal
    /// node and reads it accordingly.
    fn advance_cursor(
        &mut self,
        steps: &mut [Step],
        di: usize,
        ns: Namespace,
        b: &mut Build,
    ) -> Result<Option<ChildPointer>> {
        let mut j = di - 1;
        loop {
            if steps[j].idx + 1 < steps[j].node.children.len() {
                steps[j].idx += 1;
                break;
            }
            if j == 0 {
                return Ok(None);
            }
            j -= 1;
        }
        // Re-descend leftmost from the level we bumped down to `di - 1`.
        for k in (j + 1)..di {
            let ptr = steps[k - 1].node.children[steps[k - 1].idx].clone();
            let depth = u8::try_from(k).map_err(|_| Error::Malformed("tree depth overflow"))?;
            match self.read_node(&ptr, ns, depth, b)? {
                IndexNode::Internal(node) => steps[k] = Step { node, idx: 0 },
                IndexNode::Leaf(_) => {
                    return Err(Error::Malformed("leaf found above the tree's leaf level"));
                },
            }
        }
        let last = &steps[di - 1];
        Ok(Some(last.node.children[last.idx].clone()))
    }

    /// Apply `ops` to the tree rooted at `root`, rewriting only the
    /// nodes the change reaches. `Ok(None)` when the namespace ends up
    /// empty and should be dropped from the commit.
    ///
    /// See the module docs for why the result is byte-identical to
    /// [`Self::build_tree`] over the same resulting entry set.
    pub(super) fn update_tree(
        &mut self,
        ns: Namespace,
        root: &IndexRoot,
        ops: &KeyOps,
        b: &mut Build,
    ) -> Result<Option<(u64, [u8; 32])>> {
        let Some(first_op) = ops.keys().next() else {
            return Ok(Some((root.index_slot, root.payload_hash)));
        };
        let orig = self.descend(root, first_op, b)?;
        let depth = orig.steps.len();
        let leaf_depth =
            u8::try_from(depth).map_err(|_| Error::Malformed("tree depth overflow"))?;
        let mut cur = orig.steps.clone();

        // --- level 0: stream leaves from the descent target onward ---
        let mut run = LeafRun::new(ns);
        let mut below: Vec<ChildPointer> = Vec::new();
        let mut pending = ops.iter().peekable();
        let mut decoded = Some(orig.leaf);
        let mut leaf_ptr = orig.leaf_ptr;
        let mut past_last_leaf = false;
        loop {
            let node = match decoded.take() {
                Some(leaf) => leaf,
                None => match self.read_node(&leaf_ptr, ns, leaf_depth, b)? {
                    IndexNode::Leaf(leaf) => leaf,
                    IndexNode::Internal(_) => {
                        return Err(Error::Malformed(
                            "internal node found at the tree's leaf level",
                        ));
                    },
                },
            };
            for (key, value) in node.entries.into_inner() {
                // Operations sorted below this entry are insertions.
                while pending
                    .peek()
                    .is_some_and(|(k, _)| k.as_slice() < key.as_slice())
                {
                    if let Some((op_key, Some(v))) = pending.next() {
                        self.leaf_push(&mut run, op_key.clone(), v.clone(), b, &mut below)?;
                    }
                }
                if pending
                    .peek()
                    .is_some_and(|(k, _)| k.as_slice() == key.as_slice())
                {
                    // Overwrite or delete: either way the stored entry
                    // does not survive.
                    if let Some((_, Some(v))) = pending.next() {
                        self.leaf_push(&mut run, key, v.clone(), b, &mut below)?;
                    }
                } else {
                    self.leaf_push(&mut run, key, value, b, &mut below)?;
                }
            }
            // The end of an old node — the only place the new packing
            // may be compared against the old one. An empty run here
            // means the packer's whole state matches what it was at
            // this boundary before the edit, so everything to the right
            // re-packs identically and is left alone.
            if depth == 0 {
                past_last_leaf = true;
                break;
            }
            if run.is_empty() && pending.peek().is_none() {
                break;
            }
            match self.advance_cursor(&mut cur, depth, ns, b)? {
                Some(next) => leaf_ptr = next,
                None => {
                    past_last_leaf = true;
                    break;
                },
            }
        }
        if past_last_leaf {
            // Past the last entry of the namespace: whatever operations
            // are left are insertions beyond the high end.
            for (key, value) in pending {
                if let Some(v) = value {
                    self.leaf_push(&mut run, key.clone(), v.clone(), b, &mut below)?;
                }
            }
            self.leaf_seal(&mut run, b, &mut below)?;
        }

        let mut at_head = (0..depth).all(|j| orig.steps[j].idx == 0);
        let mut at_tail = cursor_at_level_end(&cur, depth);

        // --- levels 1..=depth ---
        for level in 1..=depth {
            // A level the rewrite covered end to end and reduced to one
            // node *is* the tree's root; the levels that used to sit
            // above it are gone. Anything less than end-to-end coverage
            // leaves old nodes beside the new ones, so the level is
            // wider than one and the tree keeps its height.
            if at_head && at_tail {
                match below.len() {
                    0 => return Ok(None),
                    1 => return Ok(Some((below[0].child_slot, below[0].child_hash))),
                    _ => {},
                }
            }
            let di = depth - level;
            let lvl = u8::try_from(level).map_err(|_| Error::Malformed("tree depth overflow"))?;
            let mut run = NodeRun::new(ns, lvl);
            let mut out: Vec<ChildPointer> = Vec::new();

            // The children of the level-`level` node the descent went
            // through, up to the child it went through: unchanged, and
            // exactly the packer state a full rebuild would hold on
            // arriving at that child.
            let prefix = orig.steps[di].node.children[..orig.steps[di].idx].to_vec();
            // ...and the children after the last one the level below
            // consumed.
            let suffix = cur[di].node.children[cur[di].idx + 1..].to_vec();
            for child in prefix.into_iter().chain(below).chain(suffix) {
                self.node_push(&mut run, child, b, &mut out)?;
            }

            at_head = (0..di).all(|j| orig.steps[j].idx == 0);
            while !run.is_empty() && di > 0 {
                match self.advance_cursor(&mut cur, di, ns, b)? {
                    Some(ptr) => {
                        let node_depth = u8::try_from(di)
                            .map_err(|_| Error::Malformed("tree depth overflow"))?;
                        match self.read_node(&ptr, ns, node_depth, b)? {
                            IndexNode::Internal(node) => {
                                for child in node.children {
                                    self.node_push(&mut run, child, b, &mut out)?;
                                }
                            },
                            IndexNode::Leaf(_) => {
                                return Err(Error::Malformed(
                                    "leaf found above the tree's leaf level",
                                ));
                            },
                        }
                    },
                    None => break,
                }
            }
            at_tail = cursor_at_level_end(&cur, di);
            if at_tail {
                self.node_seal(&mut run, b, &mut out, true)?;
            }
            below = out;
        }

        // The root level. `below` is what replaces it; one node is the
        // new root, more than one means the tree gained levels.
        match below.len() {
            0 => Ok(None),
            1 => Ok(Some((below[0].child_slot, below[0].child_hash))),
            _ => {
                let lvl =
                    u8::try_from(depth + 1).map_err(|_| Error::Malformed("tree depth overflow"))?;
                self.grow_levels(ns, below, lvl, b)
            },
        }
    }
}

/// Is the cursor sitting on the last node of the level at tree-depth
/// `di`? That node is picked by `steps[di - 1].idx`, so the level ends
/// here exactly when that index and every index above it is the last of
/// its node. `di == 0` is the root's level, which is one node wide.
fn cursor_at_level_end(steps: &[Step], di: usize) -> bool {
    (0..di).all(|j| steps[j].idx + 1 == steps[j].node.children.len())
}

/// The two properties the incremental update exists for, checked
/// against the tree's actual shape and against the chunk reads a
/// commit performs.
///
/// These live in-crate rather than under `tests/` because both need to
/// see past the public API: the shape of a tree is not observable
/// through `get`/`list`, and "how much did that commit cost" has to be
/// counted in chunk reads — wall time is fsync-bound and would make the
/// assertion a stopwatch race on a loaded runner.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Container;
    use crate::container::ContainerOptions;
    use crate::crypto::kdf::Argon2Params;
    use crate::padding::PaddingPolicy;
    use crate::space::CHUNK_READS;

    fn opts() -> ContainerOptions {
        ContainerOptions {
            argon2: Argon2Params::MIN,
            initial_garbage_chunks: 0,
            padding_policy: PaddingPolicy::None,
            superblock_replicas: 1,
        }
    }

    /// `KeyOps` — the collapsed copy of a whole transaction's plaintext
    /// — must be the redacted type, not a bare map (report7 P3).
    ///
    /// Asserted on the ALIAS rather than on the `Secret` impl, because
    /// the way this regresses is someone writing `BTreeMap<..>` back
    /// into the type definition, which leaves every `Secret`
    /// implementation intact and passing. The `Debug` header is the
    /// cheapest observable difference between the two.
    #[test]
    fn key_ops_is_the_redacted_type() {
        let mut ops = KeyOps::default();
        ops.insert(b"k".to_vec(), Some(b"a-plaintext-value".to_vec()));

        let printed = format!("{ops:?}");
        assert!(
            printed.starts_with("Redacted"),
            "KeyOps is a bare map again — a full copy of the Tx plaintext \
             that prints itself and does not scrub: {printed}"
        );
        assert!(
            !printed.contains("a-plaintext-value"),
            "value leaked through Debug: {printed}"
        );
    }

    fn scratch() -> std::path::PathBuf {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let p = tmp.path().to_owned();
        drop(tmp);
        p
    }

    fn key(i: usize) -> Vec<u8> {
        format!("k{i:08}").into_bytes()
    }

    /// Every node of `ns`'s tree, depth-first, as
    /// `(descents, node kind, the keys it holds)`.
    ///
    /// This is the tree's shape with the slot numbers left out — and
    /// the slot numbers are the only thing that legitimately differs
    /// between two containers holding the same data, because an
    /// append-only file hands out positions in write order. Two equal
    /// fingerprints mean the same entries cut at the same places, all
    /// the way up: identical node payloads bar those positions.
    fn shape(s: &mut Space<'_>, ns: Namespace) -> Vec<(u8, char, Vec<Vec<u8>>)> {
        fn walk(
            s: &mut Space<'_>,
            slot: u64,
            ns: Namespace,
            depth: u8,
            out: &mut Vec<(u8, char, Vec<Vec<u8>>)>,
        ) {
            match s.read_index_node_at_expected(slot, ns).unwrap() {
                IndexNode::Leaf(l) => {
                    out.push((
                        depth,
                        'L',
                        l.entries.iter().map(|(k, _)| k.clone()).collect(),
                    ));
                },
                IndexNode::Internal(i) => {
                    out.push((
                        depth,
                        'I',
                        i.children.iter().map(|c| c.first_key.to_vec()).collect(),
                    ));
                    for c in &i.children {
                        walk(s, c.child_slot, ns, depth + 1, out);
                    }
                },
            }
        }
        let root = s.find_root_slot(ns).unwrap().expect("namespace has a root");
        let mut out = Vec::new();
        walk(s, root, ns, 0, &mut out);
        out
    }

    /// Run `build` against a fresh container and return the resulting
    /// shape of `Namespace::SETTINGS`.
    fn shape_after(build: impl FnOnce(&mut Space<'_>)) -> Vec<(u8, char, Vec<Vec<u8>>)> {
        let path = scratch();
        let out = {
            let mut c = Container::create_with_options(&path, opts()).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            build(&mut s);
            shape(&mut s, Namespace::SETTINGS)
        };
        let _ = std::fs::remove_file(&path);
        out
    }

    fn put_all(s: &mut Space<'_>, keys: impl IntoIterator<Item = usize>, vlen: usize) {
        let mut tx = s.begin_tx();
        for i in keys {
            tx.put(Namespace::SETTINGS, &key(i), &vec![b'v'; vlen])
                .unwrap();
        }
        tx.commit().unwrap();
    }

    /// **The property this whole design exists for.** The same set of
    /// key-value pairs must produce the same tree no matter how it was
    /// arrived at.
    ///
    /// A B+ tree that splits a full node in half in place fails this:
    /// its shape records the insertion order. In a container built for
    /// deniability that is a leak — an adversary who obtains the key
    /// could tell a namespace that was written in one go from one that
    /// was edited into the same state — and it would also break the
    /// content-keyed node reuse of audit HV-14, which assumes that
    /// re-deriving an untouched node reproduces its bytes.
    #[test]
    fn a_namespace_has_one_shape_however_it_was_written() {
        const N: usize = 300;

        let at_once = shape_after(|s| put_all(s, 0..N, 64));
        assert!(
            at_once.len() > 1,
            "the fixture must be big enough to have a shape at all"
        );

        let ascending = shape_after(|s| {
            for i in 0..N {
                put_all(s, [i], 64);
            }
        });
        assert_eq!(ascending, at_once, "one entry per Tx, in order");

        let descending = shape_after(|s| {
            for i in (0..N).rev() {
                put_all(s, [i], 64);
            }
        });
        assert_eq!(descending, at_once, "one entry per Tx, backwards");

        let scattered = shape_after(|s| {
            // A fixed permutation with a long stride: every insert lands
            // in the middle of an existing run.
            for step in 0..N {
                put_all(s, [(step * 97) % N], 64);
            }
        });
        assert_eq!(scattered, at_once, "one entry per Tx, scattered");

        let overshoot_then_delete = shape_after(|s| {
            put_all(s, 0..N + 60, 64);
            let mut tx = s.begin_tx();
            for i in N..N + 60 {
                tx.delete(Namespace::SETTINGS, &key(i)).unwrap();
            }
            tx.commit().unwrap();
        });
        assert_eq!(
            overshoot_then_delete, at_once,
            "written wider then trimmed back"
        );

        let interleaved = shape_after(|s| {
            // Deletes and re-inserts of keys that stay in the final set,
            // so the tree is churned through shapes it must forget.
            put_all(s, (0..N).step_by(2), 64);
            put_all(s, (1..N).step_by(2), 64);
            let mut tx = s.begin_tx();
            for i in (0..N).step_by(3) {
                tx.delete(Namespace::SETTINGS, &key(i)).unwrap();
            }
            tx.commit().unwrap();
            put_all(s, (0..N).step_by(3), 64);
        });
        assert_eq!(interleaved, at_once, "churned into the same final set");
    }

    /// The same, at a size that needs three levels — the level above
    /// the leaves has its own boundaries to place, and they must be as
    /// history-free as the leaves'.
    #[test]
    fn a_deep_namespace_has_one_shape_however_it_was_written() {
        const N: usize = 20_000;

        let at_once = shape_after(|s| put_all(s, 0..N, 64));
        let levels = at_once.iter().map(|(d, _, _)| *d).max().unwrap();
        assert!(levels >= 2, "fixture must be at least three levels deep");

        let forward_batches = shape_after(|s| {
            for batch in 0..40 {
                put_all(s, (batch * 500)..(batch * 500 + 500), 64);
            }
        });
        assert_eq!(forward_batches, at_once, "40 ascending batches");

        let backward_batches = shape_after(|s| {
            for batch in (0..40).rev() {
                put_all(s, (batch * 500)..(batch * 500 + 500), 64);
            }
        });
        assert_eq!(backward_batches, at_once, "40 descending batches");

        let striped = shape_after(|s| {
            for offset in 0..4 {
                put_all(s, (offset..N).step_by(4), 64);
            }
        });
        assert_eq!(striped, at_once, "four interleaved strides");
    }

    /// Chunks a commit reads, for one `put` into a namespace of `n`.
    fn reads_for_one_edit(n: usize) -> u64 {
        let path = scratch();
        let reads = {
            let mut c = Container::create_with_options(&path, opts()).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            put_all(&mut s, 0..n, 64);
            CHUNK_READS.with(|r| r.set(0));
            put_all(&mut s, [n / 2], 64);
            CHUNK_READS.with(|r| r.get())
        };
        let _ = std::fs::remove_file(&path);
        reads
    }

    /// **The other property.** Editing one key must cost the path to
    /// it, not the namespace.
    ///
    /// Before HV-16 a commit flattened the whole tree first, so this
    /// number was the leaf count: ~50 reads at N = 2 000 and ~2 300 at
    /// N = 100 000. It is now the descent plus the leaf, so it moves
    /// only when the tree gains a level.
    #[test]
    fn one_edit_reads_the_path_and_not_the_namespace() {
        let small = reads_for_one_edit(2_000);
        let medium = reads_for_one_edit(20_000);
        let large = reads_for_one_edit(100_000);

        // A 50x namespace may cost at most a couple more reads (one per
        // extra level), and never a couple more *hundred*.
        assert!(
            large <= small + 3,
            "a 50x larger namespace must not make an edit read more \
             (2k={small}, 20k={medium}, 100k={large} chunks)"
        );
        assert!(
            large <= 10,
            "a one-key edit should read the path and the leaf, got {large}"
        );
    }

    /// Splitting a seed into transactions must not re-read what is
    /// already there. This is the "97 s and 2.9 GiB for 500 Txs"
    /// measurement in `docs/en/contributing/benchmarks.md`, in the form
    /// a test can assert.
    #[test]
    fn seeding_in_batches_does_not_re_read_the_namespace_each_time() {
        fn reads_for_batched_seed(n: usize, batches: usize) -> u64 {
            let path = scratch();
            let reads = {
                let mut c = Container::create_with_options(&path, opts()).unwrap();
                let mut s = c.create_space(b"pw").unwrap();
                CHUNK_READS.with(|r| r.set(0));
                let per = n / batches;
                for b in 0..batches {
                    put_all(&mut s, (b * per)..(b * per + per), 64);
                }
                CHUNK_READS.with(|r| r.get())
            };
            let _ = std::fs::remove_file(&path);
            reads
        }

        const BATCHES: usize = 20;
        let small = reads_for_batched_seed(5_000, BATCHES);
        let large = reads_for_batched_seed(50_000, BATCHES);

        // Ten times the data through the same number of commits. The
        // old flatten-per-commit made this ratio ten as well; a commit
        // that only touches its own neighbourhood keeps it flat.
        assert!(
            large <= small * 2,
            "10x the entries in the same {BATCHES} commits must not cost \
             10x the reads (5k={small}, 50k={large} chunks)"
        );
    }

    /// Levels appear and disappear by content, so a namespace grown
    /// past a level boundary and shrunk back must land on exactly the
    /// shape it had — including collapsing the extra level rather than
    /// leaving a one-child node behind.
    #[test]
    fn growing_past_a_level_and_shrinking_back_restores_the_shape() {
        const SMALL: usize = 400;
        const BIG: usize = 12_000;

        let plain = shape_after(|s| put_all(s, 0..SMALL, 64));
        let there_and_back = shape_after(|s| {
            put_all(s, 0..BIG, 64);
            for batch in (SMALL..BIG).collect::<Vec<_>>().chunks(2_000) {
                let mut tx = s.begin_tx();
                for &i in batch {
                    tx.delete(Namespace::SETTINGS, &key(i)).unwrap();
                }
                tx.commit().unwrap();
            }
        });
        assert_eq!(
            there_and_back, plain,
            "a namespace that grew levels and lost them again must not \
             remember having had them"
        );
    }
}
