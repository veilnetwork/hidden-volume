//! Per-call decoded index reuse for bounded exact-key reads. Only one Space invocation may use this cache. No range scan,
//! accepted view, or plaintext survives the caller's synchronous operation.
use std::{collections::HashMap, rc::Rc};

use super::{
    Space,
    index::{ChildPointer, IndexNode, Namespace},
};
use crate::Result;

const MAX_NODES: usize = 64;
const MAX_NODE_BYTES: usize = 1024 * 1024;

struct Entry {
    node: Rc<IndexNode>,
    bytes: usize,
    tick: u64,
}

pub(super) struct PointIndexCache {
    entries: HashMap<u64, Entry>,
    bytes: usize,
    tick: u64,
    max_nodes: usize,
    max_bytes: usize,
}

impl PointIndexCache {
    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            bytes: 0,
            tick: 0,
            max_nodes: MAX_NODES,
            max_bytes: MAX_NODE_BYTES,
        }
    }

    fn node_bytes(node: &IndexNode) -> usize {
        let base = std::mem::size_of::<IndexNode>()
            + 2 * std::mem::size_of::<usize>()
            + std::mem::size_of::<Entry>()
            + std::mem::size_of::<u64>();
        base + match node {
            IndexNode::Leaf(leaf) => {
                leaf.entries.capacity() * std::mem::size_of::<(Vec<u8>, Vec<u8>)>()
                    + leaf
                        .entries
                        .iter()
                        .map(|(k, v)| k.capacity() + v.capacity())
                        .sum::<usize>()
            },
            IndexNode::Internal(internal) => {
                internal.children.capacity() * std::mem::size_of::<ChildPointer>()
                    + internal
                        .children
                        .iter()
                        .map(|c| c.first_key.capacity())
                        .sum::<usize>()
            },
        }
    }

    fn read(
        &mut self,
        space: &mut Space<'_>,
        slot: u64,
        expected: Namespace,
    ) -> Result<Rc<IndexNode>> {
        self.tick += 1;
        if let Some(entry) = self.entries.get_mut(&slot) {
            // A cached node does not authorize a different namespace.
            entry.node.check_namespace(expected)?;
            entry.tick = self.tick;
            return Ok(Rc::clone(&entry.node));
        }
        let node = Rc::new(space.read_index_node_at_expected(slot, expected)?);
        let bytes = Self::node_bytes(&node);
        if self.max_nodes == 0 || bytes > self.max_bytes {
            return Ok(node);
        }
        while self.entries.len() >= self.max_nodes
            || self.bytes.saturating_add(bytes) > self.max_bytes
        {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.tick)
                .map(|(&k, _)| k)
            else {
                break;
            };
            if let Some(old) = self.entries.remove(&oldest) {
                self.bytes -= old.bytes;
            }
        }
        self.bytes += bytes;
        self.entries.insert(
            slot,
            Entry {
                node: Rc::clone(&node),
                bytes,
                tick: self.tick,
            },
        );
        Ok(node)
    }
}

// Owned on the scalar path: no Rc allocation is added to ordinary get().
enum PointNode {
    Owned(IndexNode),
    Cached(Rc<IndexNode>),
}
impl AsRef<IndexNode> for PointNode {
    fn as_ref(&self) -> &IndexNode {
        match self {
            Self::Owned(node) => node,
            Self::Cached(node) => node,
        }
    }
}

impl Space<'_> {
    pub(super) fn get_from_root(
        &mut self,
        namespace: Namespace,
        key: &[u8],
        root_slot: u64,
        mut cache: Option<&mut PointIndexCache>,
    ) -> Result<Option<Vec<u8>>> {
        // Each key has its OWN guarded descent. Cache hits must still pass
        // cycle, owned-slot and depth admission before the node is consulted.
        let mut walk = self.new_tree_walk();
        let mut depth: u8 = 0;
        let mut slot = root_slot;
        loop {
            walk.admit(slot, depth)?;
            let node = match cache.as_deref_mut() {
                Some(cache) => PointNode::Cached(cache.read(self, slot, namespace)?),
                None => PointNode::Owned(self.read_index_node_at_expected(slot, namespace)?),
            };
            match node.as_ref() {
                IndexNode::Leaf(leaf) => return Ok(leaf.get(key).map(|value| value.to_vec())),
                IndexNode::Internal(internal) => {
                    slot = internal.children[internal.child_index_for(key)].child_slot;
                    depth += 1;
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        CHUNK_READS,
        index::{InternalNode, LeafNode},
    };
    use super::*;
    use crate::chunk::ChunkKind;
    use crate::{Container, Error, crypto::kdf::Argon2Params, redact::Redacted};

    fn leaf(ns: Namespace, key: &[u8], value: &[u8]) -> IndexNode {
        IndexNode::Leaf(LeafNode {
            namespace: ns,
            entries: Redacted::new(vec![(key.to_vec(), value.to_vec())]),
        })
    }
    fn internal(ns: Namespace, children: &[(u64, &[u8])]) -> IndexNode {
        IndexNode::Internal(InternalNode {
            namespace: ns,
            children: children
                .iter()
                .map(|(slot, key)| ChildPointer {
                    first_key: Redacted::new(key.to_vec()),
                    child_slot: *slot,
                    child_hash: [0; 32],
                })
                .collect(),
        })
    }
    fn seal(space: &mut Space<'_>, node: &IndexNode) -> u64 {
        space
            .place_chunk(ChunkKind::IndexNode, 1, &node.encode().unwrap())
            .unwrap()
    }
    fn cached(cache: &mut PointIndexCache, slot: u64, node: IndexNode) {
        let bytes = PointIndexCache::node_bytes(&node);
        cache.bytes += bytes;
        cache.entries.insert(
            slot,
            Entry {
                node: Rc::new(node),
                bytes,
                tick: 0,
            },
        );
    }

    #[test]
    fn branches_reuse_nodes_but_have_independent_walks() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Container::create(dir.path().join("tree.hv"), Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let ns = Namespace::MESSAGE_LOG;
        let left = seal(&mut s, &leaf(ns, b"a", b"one"));
        let right = seal(&mut s, &leaf(ns, b"z", b"two"));
        let root = seal(&mut s, &internal(ns, &[(left, b"a"), (right, b"z")]));
        let mut cache = PointIndexCache::new();
        CHUNK_READS.with(|n| n.set(0));
        for _ in 0..3 {
            for (key, expected) in [(b"a", b"one"), (b"z", b"two"), (b"a", b"one")] {
                assert_eq!(
                    s.get_from_root(ns, key, root, Some(&mut cache))
                        .unwrap()
                        .as_deref(),
                    Some(expected.as_slice())
                );
            }
        }
        assert_eq!(CHUNK_READS.with(|n| n.get()), 3);
        // A cache hit retains the namespace guard; it is not fresh authorization.
        assert!(matches!(
            cache.read(&mut s, left, Namespace::SETTINGS),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn eviction_and_oversized_fallback_are_bounded_and_transparent() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Container::create(dir.path().join("bounded.hv"), Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let ns = Namespace::MESSAGE_LOG;
        let nodes = [
            leaf(ns, b"a", b"one"),
            leaf(ns, b"b", b"two"),
            leaf(ns, b"c", b"three"),
        ];
        let slots: Vec<_> = nodes.iter().map(|n| seal(&mut s, n)).collect();
        for byte_limit in [usize::MAX, 1] {
            let mut cache = PointIndexCache::new();
            cache.max_nodes = 1;
            cache.max_bytes = byte_limit;
            for _ in 0..2 {
                for (&slot, expected) in slots.iter().zip(&nodes) {
                    let node = cache.read(&mut s, slot, ns).unwrap();
                    assert_eq!(node.encode().unwrap(), expected.encode().unwrap());
                    assert!(cache.entries.len() <= 1);
                    assert!(cache.bytes <= byte_limit);
                    assert_eq!(cache.bytes, cache.entries.values().map(|e| e.bytes).sum());
                }
            }
            if byte_limit == 1 {
                assert!(cache.entries.is_empty());
            }
        }
    }

    #[test]
    fn cache_hits_cannot_bypass_cycle_slot_or_depth_admission() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Container::create(dir.path().join("guards.hv"), Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let ns = Namespace::MESSAGE_LOG;
        let root = seal(&mut s, &leaf(ns, b"a", b"one"));
        let mut cache = PointIndexCache::new();
        // Inject decoded nodes to exercise the guard specifically on cache hits.
        cached(&mut cache, root, internal(ns, &[(root, b"a")]));
        assert!(matches!(
            s.get_from_root(ns, b"a", root, Some(&mut cache)),
            Err(Error::Malformed(_))
        ));
        cached(&mut cache, u64::MAX, leaf(ns, b"a", b"one"));
        assert!(matches!(
            s.get_from_root(ns, b"a", u64::MAX, Some(&mut cache)),
            Err(Error::Malformed(_))
        ));
        let depth = super::super::walk::max_depth_for_budget(s.state.owned_slots.len());
        let mut slots = vec![root];
        for _ in 0..=depth {
            slots.push(seal(&mut s, &leaf(ns, b"a", b"one")));
        }
        // Derive a chain longer than the current space's admissible depth.
        let depth = super::super::walk::max_depth_for_budget(s.state.owned_slots.len());
        while slots.len() <= usize::from(depth) + 1 {
            slots.push(seal(&mut s, &leaf(ns, b"a", b"one")));
        }
        let mut cache = PointIndexCache::new();
        for pair in slots.windows(2) {
            cached(&mut cache, pair[0], internal(ns, &[(pair[1], b"a")]));
        }
        cached(&mut cache, *slots.last().unwrap(), leaf(ns, b"a", b"one"));
        assert!(
            matches!(s.get_from_root(ns, b"a", root, Some(&mut cache)), Err(Error::Malformed(detail)) if detail.contains("deeper than"))
        );
    }
}
