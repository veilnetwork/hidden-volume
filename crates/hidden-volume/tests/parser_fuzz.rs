//! Parser-level fuzz tests on stable Rust via proptest.
//!
//! Validates that every public `decode` function:
//!   1. Never panics on arbitrary byte input (returns Err on malformed).
//!   2. Roundtrips with its `encode` counterpart for valid inputs.
//!   3. Handles edge cases: empty bytes, exact-boundary, oversized fields.
//!
//! These tests exist because:
//!   - AEAD passes only on bytes WE wrote, but a bug in our writer could
//!     produce a "valid-looking" plaintext that the decoder mishandles.
//!   - Container files are read from untrusted sources (sync, backup,
//!     external storage). Even though AEAD prevents adversary corruption,
//!     a torn write or our own format bug could produce nonsense.
//!   - On stable Rust, proptest is the closest we get to cargo-fuzz
//!     coverage for parser robustness.

use hidden_volume::chunk::format::Plaintext;
use hidden_volume::container::Header;
use hidden_volume::crypto::kdf::{Argon2Params, PARAMS_VERSION};
use hidden_volume::space::index::{IndexNode, InternalNode, LeafNode, Namespace};
use hidden_volume::space::log::{decode_batch, encode_batch};
use hidden_volume::space::superblock::Superblock;
use hidden_volume::tx::commit::{CommitPayload, IndexRoot};
use proptest::prelude::*;

// ============================================================
// Phase 1: decode-doesn't-panic on arbitrary bytes.
// ============================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn plaintext_decode_doesnt_panic(bytes in prop::collection::vec(any::<u8>(), 0..=8192)) {
        let _ = Plaintext::decode(&bytes);
    }

    #[test]
    fn argon2_params_decode_doesnt_panic(bytes in prop::collection::vec(any::<u8>(), 0..=64)) {
        let _ = Argon2Params::decode(&bytes);
    }

    #[test]
    fn header_decode_doesnt_panic(bytes in prop::collection::vec(any::<u8>(), 0..=4096)) {
        let _ = Header::decode(&bytes);
    }

    #[test]
    fn superblock_decode_doesnt_panic(bytes in prop::collection::vec(any::<u8>(), 0..=4096)) {
        let _ = Superblock::decode(&bytes);
    }

    #[test]
    fn commit_payload_decode_doesnt_panic(bytes in prop::collection::vec(any::<u8>(), 0..=8192)) {
        let _ = CommitPayload::decode(&bytes);
    }

    #[test]
    fn leaf_node_decode_doesnt_panic(bytes in prop::collection::vec(any::<u8>(), 0..=8192)) {
        let _ = LeafNode::decode(&bytes);
    }

    #[test]
    fn internal_node_decode_doesnt_panic(bytes in prop::collection::vec(any::<u8>(), 0..=8192)) {
        let _ = InternalNode::decode(&bytes);
    }

    #[test]
    fn index_node_decode_doesnt_panic(bytes in prop::collection::vec(any::<u8>(), 0..=8192)) {
        let _ = IndexNode::decode(&bytes);
    }

    #[test]
    fn batch_decode_doesnt_panic(bytes in prop::collection::vec(any::<u8>(), 0..=4096)) {
        // decode_batch wraps zstd; we want to ensure malformed bytes
        // (including non-zstd byte streams) return Err, not panic.
        let _ = decode_batch(&bytes);
    }
}

// ============================================================
// Phase 2: encode → decode roundtrip for valid inputs.
// ============================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn argon2_params_roundtrip(
        m_cost_kib in (Argon2Params::MIN.m_cost_kib)..=(1u32 << 20),
        t_cost in (Argon2Params::MIN.t_cost)..=64u32,
        p_cost in 1u32..=8,
    ) {
        let p = Argon2Params { m_cost_kib, t_cost, p_cost, version: PARAMS_VERSION as u32 };
        let bytes = p.encode();
        let p2 = Argon2Params::decode(&bytes).unwrap();
        prop_assert_eq!(p, p2);
    }

    #[test]
    fn superblock_roundtrip(
        seq: u64,
        root_slot: u64,
        root_hash: [u8; 32],
    ) {
        let sb = Superblock { seq, root_slot, root_hash };
        let bytes = sb.encode();
        let sb2 = Superblock::decode(&bytes).unwrap();
        prop_assert_eq!(sb.seq, sb2.seq);
        prop_assert_eq!(sb.root_slot, sb2.root_slot);
        prop_assert_eq!(sb.root_hash, sb2.root_hash);
    }

    /// LeafNode roundtrip with random sorted entries.
    /// Entries must be sorted-and-unique by key, otherwise encode rejects.
    #[test]
    fn leaf_node_roundtrip(
        ns: u8,
        // Generate up to 30 small entries; constraint by size to fit in one chunk.
        raw_entries in prop::collection::vec(
            (
                prop::collection::vec(any::<u8>(), 1..=20),
                prop::collection::vec(any::<u8>(), 0..=40),
            ),
            0..=30,
        ),
    ) {
        // Dedup + sort to satisfy LeafNode invariants.
        let mut sorted: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
        for (k, v) in raw_entries {
            sorted.insert(k, v);
        }
        let entries: Vec<(Vec<u8>, Vec<u8>)> = sorted.into_iter().collect();
        let leaf = LeafNode { namespace: Namespace(ns), entries: entries.clone() };
        let bytes = match leaf.encode() {
            Ok(b) => b,
            Err(_) => return Ok(()), // overflow, skip
        };
        let leaf2 = LeafNode::decode(&bytes).unwrap();
        prop_assert_eq!(leaf2.namespace.0, ns);
        prop_assert_eq!(&leaf2.entries, &entries);

        // And via the IndexNode enum path:
        let node = IndexNode::Leaf(leaf);
        let bytes2 = node.encode().unwrap();
        let node2 = IndexNode::decode(&bytes2).unwrap();
        match node2 {
            IndexNode::Leaf(l) => prop_assert_eq!(l.entries, entries),
            IndexNode::Internal(_) => prop_assert!(false, "expected Leaf"),
        }
    }

    #[test]
    fn internal_node_roundtrip(
        ns: u8,
        raw_children in prop::collection::vec(
            (
                prop::collection::vec(any::<u8>(), 1..=20),
                any::<u64>(),
                [any::<u8>(); 32],
            ),
            0..=30,
        ),
    ) {
        // Dedup by first_key (must be sorted-unique).
        let mut by_key: std::collections::BTreeMap<Vec<u8>, (u64, [u8; 32])> = Default::default();
        for (k, slot, hash) in raw_children {
            by_key.insert(k, (slot, hash));
        }
        let children: Vec<hidden_volume::space::index::ChildPointer> = by_key
            .into_iter()
            .map(|(k, (slot, hash))| hidden_volume::space::index::ChildPointer {
                first_key: k,
                child_slot: slot,
                child_hash: hash,
            })
            .collect();
        let node = InternalNode {
            namespace: Namespace(ns),
            children: children.clone(),
        };
        let bytes = match node.encode() {
            Ok(b) => b,
            Err(_) => return Ok(()), // IndexFull on too many children, skip
        };
        let node2 = InternalNode::decode(&bytes).unwrap();
        prop_assert_eq!(node2.namespace.0, ns);
        prop_assert_eq!(node2.children, children);
    }

    #[test]
    fn commit_payload_roundtrip(
        raw_roots in prop::collection::vec(
            (any::<u8>(), any::<u64>(), [any::<u8>(); 32]),
            0..=20,
        ),
    ) {
        // Dedup by namespace.
        let mut by_ns: std::collections::BTreeMap<u8, (u64, [u8; 32])> = Default::default();
        for (ns, slot, hash) in raw_roots {
            by_ns.insert(ns, (slot, hash));
        }
        let roots: Vec<IndexRoot> = by_ns
            .into_iter()
            .enumerate()
            .map(|(i, (ns_byte, (slot, hash)))| IndexRoot {
                namespace: Namespace(ns_byte),
                // R-NSKIND: alternate kind so the proptest exercises
                // both encode/decode discriminants.
                kind: if i % 2 == 0 {
                    hidden_volume::tx::NamespaceKind::Kv
                } else {
                    hidden_volume::tx::NamespaceKind::Log
                },
                index_slot: slot,
                payload_hash: hash,
            })
            .collect();
        let cp = CommitPayload {
            roots: roots.clone(),
            tx_root_hash: [0xFFu8; 32],
        };
        let bytes = cp.encode().unwrap();
        let cp2 = CommitPayload::decode(&bytes).unwrap();
        prop_assert_eq!(cp.tx_root_hash, cp2.tx_root_hash);
        prop_assert_eq!(cp.roots.len(), cp2.roots.len());
        for (a, b) in cp.roots.iter().zip(cp2.roots.iter()) {
            prop_assert_eq!(a.namespace.0, b.namespace.0);
            prop_assert_eq!(a.index_slot, b.index_slot);
            prop_assert_eq!(a.payload_hash, b.payload_hash);
        }
    }

    #[test]
    fn batch_roundtrip(
        raw_records in prop::collection::vec(
            (any::<u64>(), prop::collection::vec(any::<u8>(), 0..=64)),
            0..=50,
        ),
    ) {
        // Dedup by log_id (find_in_batch returns last; we test simpler unique case).
        let mut by_id: std::collections::BTreeMap<u64, Vec<u8>> = Default::default();
        for (id, p) in raw_records {
            by_id.insert(id, p);
        }
        let records: Vec<(u64, Vec<u8>)> = by_id.into_iter().collect();
        let bytes = match encode_batch(&records) {
            Ok(b) => b,
            Err(_) => return Ok(()), // payload too large after compression
        };
        let records2 = decode_batch(&bytes).unwrap();
        prop_assert_eq!(records, records2);
    }
}

// ============================================================
// Phase 3: edge cases that proptest might miss.
// ============================================================

#[test]
fn all_decoders_handle_empty_bytes() {
    assert!(Plaintext::decode(&[]).is_err());
    assert!(Argon2Params::decode(&[]).is_err());
    assert!(Header::decode(&[]).is_err());
    assert!(Superblock::decode(&[]).is_err());
    assert!(CommitPayload::decode(&[]).is_err());
    assert!(LeafNode::decode(&[]).is_err());
    assert!(InternalNode::decode(&[]).is_err());
    assert!(IndexNode::decode(&[]).is_err());
    assert!(decode_batch(&[]).is_err());
}

#[test]
fn all_decoders_handle_single_byte() {
    let one = [0u8];
    let _ = Plaintext::decode(&one);
    let _ = Argon2Params::decode(&one);
    let _ = Header::decode(&one);
    let _ = Superblock::decode(&one);
    let _ = CommitPayload::decode(&one);
    let _ = LeafNode::decode(&one);
    let _ = InternalNode::decode(&one);
    let _ = IndexNode::decode(&one);
    let _ = decode_batch(&one);
    // Just must not panic.
}

#[test]
fn all_decoders_handle_max_size_zeros() {
    // Strings of zeros at common max boundaries.
    for size in [64usize, 256, 1024, 4096, 8192] {
        let zs = vec![0u8; size];
        let _ = Plaintext::decode(&zs);
        let _ = Argon2Params::decode(&zs);
        let _ = Header::decode(&zs);
        let _ = Superblock::decode(&zs);
        let _ = CommitPayload::decode(&zs);
        let _ = LeafNode::decode(&zs);
        let _ = InternalNode::decode(&zs);
        let _ = IndexNode::decode(&zs);
        let _ = decode_batch(&zs);
    }
}

#[test]
fn all_decoders_handle_max_size_ones() {
    for size in [64usize, 256, 1024, 4096, 8192] {
        let os = vec![0xFFu8; size];
        let _ = Plaintext::decode(&os);
        let _ = Argon2Params::decode(&os);
        let _ = Header::decode(&os);
        let _ = Superblock::decode(&os);
        let _ = CommitPayload::decode(&os);
        let _ = LeafNode::decode(&os);
        let _ = InternalNode::decode(&os);
        let _ = IndexNode::decode(&os);
        let _ = decode_batch(&os);
    }
}

#[test]
fn unknown_chunk_kind_in_plaintext() {
    use hidden_volume::CHUNK_SIZE;
    use hidden_volume::NONCE_LEN;
    use hidden_volume::TAG_LEN;
    // Build a plaintext-shaped buffer with "magic" prefix but unknown kind=0xFF.
    let plaintext_len = CHUNK_SIZE - NONCE_LEN - TAG_LEN;
    let mut buf = vec![0u8; plaintext_len];
    buf[0..4].copy_from_slice(b"HVC1");
    buf[4] = 0xFF; // unknown kind
    let result = Plaintext::decode(&buf);
    assert!(result.is_err(), "unknown ChunkKind must be rejected");
}

#[test]
fn unknown_index_node_type_rejected() {
    let mut buf = vec![0u8; 16];
    buf[0] = 99; // unknown node_type
    assert!(IndexNode::decode(&buf).is_err());
}

#[test]
fn argon2_params_unknown_version_rejected_on_validate() {
    let mut bytes = [0u8; 16];
    // Fill with valid m/t/p but unknown version.
    bytes[0..4].copy_from_slice(&(64 * 1024u32).to_le_bytes());
    bytes[4..8].copy_from_slice(&3u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
    let p = Argon2Params::decode(&bytes).unwrap();
    assert!(p.validate().is_err(), "unknown version must fail validate");
}

#[test]
fn batch_decode_rejects_random_non_zstd() {
    // Pure random bytes are extremely unlikely to be valid zstd.
    let bytes: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let result = decode_batch(&bytes);
    // Must be Err, not panic.
    assert!(result.is_err());
}

#[test]
fn header_decode_short_input_rejected() {
    // HEADER_LEN = 80; anything shorter must be rejected.
    for size in 0..80 {
        let buf = vec![0u8; size];
        assert!(Header::decode(&buf).is_err(), "size={size} should reject");
    }
}

#[test]
fn superblock_decode_short_input_rejected() {
    // ENCODED_LEN = 48; anything shorter must be rejected.
    for size in 0..Superblock::ENCODED_LEN {
        let buf = vec![0u8; size];
        assert!(
            Superblock::decode(&buf).is_err(),
            "size={size} should reject"
        );
    }
}

#[test]
fn argon2_params_decode_short_input_rejected() {
    // HEADER_PARAMS_LEN = 16; anything shorter must be rejected.
    for size in 0..16 {
        let buf = vec![0u8; size];
        assert!(
            Argon2Params::decode(&buf).is_err(),
            "size={size} should reject"
        );
    }
}
