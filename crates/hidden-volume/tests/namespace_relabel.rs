//! Regression test for the root-relabel attack closed by audit
//! pass 19 round 6 (user-report 2026-05-28).
//!
//! ## Threat model
//!
//! A key-holder / buggy writer could engineer a container whose
//! `CommitPayload.roots[i].namespace` byte disagrees with the
//! `IndexNode.namespace` byte of the tree it points at. The Merkle
//! hash chain stays consistent — `compute_tx_root_hash` only folds
//! `payload_hash` (which covers the IndexNode bytes including the
//! namespace byte) — so the relabel itself does not break any
//! existing hash-equality check. Pre-fix `verify_integrity` and
//! `Space::get/list/count/log_iter` walked the IndexNode tree
//! without ever cross-checking that its namespace byte agreed with
//! the parent IndexRoot's. Net: a logically renamed root passed
//! through as if it were honest.
//!
//! ## Forge mechanics
//!
//! 1. Create a container with a single KV entry in
//!    [`Namespace::SETTINGS`] (= 1).
//! 2. Commit. The container now has a `Commit` chunk whose
//!    `CommitPayload.roots = [IndexRoot { namespace: 1, kind: Kv,
//!    index_slot: X, payload_hash: H }]`.
//! 3. Decrypt the Commit chunk in-place using the derived
//!    `SpaceKeys`, flip the namespace byte from 1 to a different
//!    value (e.g. [`Namespace::CONTACTS`] = 2), and re-encrypt
//!    with the original nonce + per-slot key + AAD. The chunk is
//!    now perfectly Merkle-consistent — `SB.root_hash` /
//!    `CommitPayload.tx_root_hash` still equal
//!    `BLAKE3(payload_hash)` — yet the IndexRoot lies about the
//!    namespace it indexes.
//! 4. Reopen and call `verify_integrity` + a `Space::get` on the
//!    target namespace.
//!
//! Expected post-fix:
//!   - `verify_integrity` returns
//!     `IntegrityFailure { detail: "IndexNode.namespace != IndexRoot.namespace", … }`.
//!   - `Space::get(forged_ns, …)` returns
//!     `Error::Malformed("IndexNode.namespace != expected (relabel attempt or writer bug)")`.
//!
//! Pre-fix both calls returned `Ok` (silently traversing
//! namespace-A data via a namespace-B claim).

use hidden_volume::CHUNK_SIZE;
use hidden_volume::Container;
use hidden_volume::Error;
use hidden_volume::crypto::aead::{ChunkAead, make_aad};
use hidden_volume::crypto::derive::{SpaceKeys, derive_chunk_key};
use hidden_volume::crypto::{Argon2Params, derive_master_key};
use hidden_volume::space::index::Namespace;
use std::io::{Read, Seek, SeekFrom, Write};

mod common;
use common::{fast_params, scratch_path};

/// Per-slot decrypt → mutate plaintext → re-encrypt. Reuses the
/// original chunk's nonce so the AAD-bound `(container_id, slot)`
/// tuple stays valid (the AAD itself is unchanged). The mutation
/// closure runs on the **decrypted plaintext bytes** — its return
/// value is the bytes to re-seal.
///
/// Used here to forge a namespace-relabeled Commit chunk that's
/// still Merkle-consistent on the hash side; the same primitive
/// is the right shape for any future "tamper a post-AEAD field
/// while keeping the chunk AEAD-valid" test.
fn rewrite_chunk_plaintext(
    path: &std::path::Path,
    password: &[u8],
    slot: u64,
    mutator: impl FnOnce(&mut [u8]),
) {
    // 1. Read raw chunk bytes.
    let offset = (1 + slot) * CHUNK_SIZE as u64;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    let mut chunk = vec![0u8; CHUNK_SIZE];
    f.read_exact(&mut chunk).unwrap();

    // 2. Read header for KDF salt + params.
    let mut header_bytes = vec![0u8; CHUNK_SIZE];
    f.seek(SeekFrom::Start(0)).unwrap();
    f.read_exact(&mut header_bytes).unwrap();
    let salt: [u8; 32] = header_bytes[0..32].try_into().unwrap();
    let params = Argon2Params::decode(&header_bytes[32..48]).unwrap();

    // 3. Derive per-slot key and AAD using the v3 chain.
    let master = derive_master_key(password, &salt, params).unwrap();
    let keys = SpaceKeys::from_master(&master);
    let key = derive_chunk_key(&keys.aead_root, &keys.container_id, slot);
    let aead = ChunkAead::new(&key);
    let aad = make_aad(&keys.container_id, slot);

    // 4. Split chunk into (nonce, ct+tag) and decrypt.
    let nonce: [u8; 24] = chunk[..24].try_into().unwrap();
    let ct = &chunk[24..];
    let mut pt = aead.open(&nonce, ct, aad).expect("chunk must AEAD-decrypt");

    // 5. Mutate plaintext.
    mutator(pt.as_mut_slice());

    // 6. Re-seal with the SAME nonce (so we can write back the
    // ciphertext over the original slot bytes without altering the
    // 24-byte nonce header). The standard ChunkAead::seal generates
    // a fresh nonce — we bypass it here by calling lower-level
    // chacha20poly1305 directly via... actually, we just rebuild
    // the chunk: nonce stays, ciphertext is fresh. `seal` produces
    // its own nonce; we'd need to overwrite nonce + ct. That's
    // fine — write the freshly-sealed chunk verbatim.
    let (new_nonce, new_ct) = aead.seal(&pt, aad).unwrap();
    let mut new_chunk = Vec::with_capacity(CHUNK_SIZE);
    new_chunk.extend_from_slice(&new_nonce);
    new_chunk.extend_from_slice(&new_ct);
    assert_eq!(new_chunk.len(), CHUNK_SIZE);

    f.seek(SeekFrom::Start(offset)).unwrap();
    f.write_all(&new_chunk).unwrap();
    f.sync_all().unwrap();
}

/// Locate the Commit chunk's slot index. The first commit writes
/// chunks in order: IndexNode leaf (slot 0), Commit (slot 1),
/// Superblock × N replicas (slots 2..2+N). The exact ordering is
/// stable but we discover it via plaintext-kind inspection rather
/// than hard-coding, so a future ordering change doesn't silently
/// break this test.
fn find_commit_slot(path: &std::path::Path, password: &[u8]) -> u64 {
    use hidden_volume::chunk::ChunkKind;
    use hidden_volume::chunk::format::Plaintext;

    let f = std::fs::File::open(path).unwrap();
    let total = (f.metadata().unwrap().len() / CHUNK_SIZE as u64) - 1;
    drop(f);

    let mut header_bytes = vec![0u8; CHUNK_SIZE];
    let mut f = std::fs::File::open(path).unwrap();
    f.read_exact(&mut header_bytes).unwrap();
    let salt: [u8; 32] = header_bytes[0..32].try_into().unwrap();
    let params = Argon2Params::decode(&header_bytes[32..48]).unwrap();
    let master = derive_master_key(password, &salt, params).unwrap();
    let keys = SpaceKeys::from_master(&master);

    for slot in 0..total {
        let offset = (1 + slot) * CHUNK_SIZE as u64;
        f.seek(SeekFrom::Start(offset)).unwrap();
        let mut chunk = vec![0u8; CHUNK_SIZE];
        f.read_exact(&mut chunk).unwrap();
        let key = derive_chunk_key(&keys.aead_root, &keys.container_id, slot);
        let aead = ChunkAead::new(&key);
        let nonce: [u8; 24] = chunk[..24].try_into().unwrap();
        let aad = make_aad(&keys.container_id, slot);
        let Ok(pt_bytes) = aead.open(&nonce, &chunk[24..], aad) else {
            continue;
        };
        let Ok(pt) = Plaintext::decode(&pt_bytes) else {
            continue;
        };
        if pt.kind == ChunkKind::Commit {
            return slot;
        }
    }
    panic!("no Commit chunk found in container");
}

#[test]
fn namespace_relabel_via_commit_tamper_is_rejected_by_verify_integrity() {
    let path = scratch_path();

    // Sanity round-trip first.
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"username", b"alice").unwrap();
        tx.commit().unwrap();
        // Baseline: verify_integrity passes on the honest container.
        let report = s.verify_integrity().unwrap();
        assert_eq!(report.namespaces_verified, 1);
    }

    // Locate the Commit chunk and forge the IndexRoot's namespace.
    let commit_slot = find_commit_slot(&path, b"pw");
    rewrite_chunk_plaintext(&path, b"pw", commit_slot, |pt| {
        // Plaintext layout: magic(4) + kind(1) + flags(1) + seq(8) +
        // payload_len(2) + payload. CommitPayload layout
        // (docs/en/reference/format.md §4.3):
        //   roots_len(2) + roots[]
        //   roots[i] = namespace(1) + kind(1) + index_slot(8) + payload_hash(32)
        //   tx_root_hash(32)
        // The first root's namespace byte sits at:
        //   PLAINTEXT_HEADER_LEN(16) + roots_len(2) = 18
        let idx = 16 + 2;
        let original = pt[idx];
        assert_eq!(
            original,
            Namespace::SETTINGS.0,
            "expected forged-target byte to be SETTINGS = 1"
        );
        // Flip to CONTACTS (=2) — a different valid namespace, so
        // the integrity walk reaches the IndexNode and only the
        // namespace cross-check trips.
        pt[idx] = Namespace::CONTACTS.0;
    });

    // Reopen. verify_integrity must fail with the new cross-check.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let err = s.verify_integrity().unwrap_err();
    match err {
        Error::IntegrityFailure { detail, .. } => {
            assert_eq!(
                detail, "IndexNode.namespace != IndexRoot.namespace",
                "expected the namespace cross-check to fire; got: {detail:?}"
            );
        },
        other => panic!("expected IntegrityFailure; got {other:?}"),
    }
}

#[test]
fn namespace_relabel_caught_by_space_get() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"username", b"alice").unwrap();
        tx.commit().unwrap();
    }

    let commit_slot = find_commit_slot(&path, b"pw");
    rewrite_chunk_plaintext(&path, b"pw", commit_slot, |pt| {
        pt[18] = Namespace::CONTACTS.0;
    });

    let mut c = Container::open(&path).unwrap();
    // open_space currently auto-runs vacuum_orphans; on the relabel
    // forge vacuum sees the now-CONTACTS root pointing at an
    // IndexNode that physically claims SETTINGS — but vacuum walks
    // via `read_index_node_at` (the *unchecked* variant by design,
    // since vacuum is a reachability sweep not a correctness audit),
    // so it traverses without complaining. The relabel-check fires
    // only on `Space::get / list / count / log_iter` — exactly the
    // namespace-aware read paths.
    let mut s = c.open_space(b"pw").unwrap();
    let err = s.get(Namespace::CONTACTS, b"username").unwrap_err();
    match err {
        Error::Malformed(msg) => {
            assert!(
                msg.contains("namespace != expected"),
                "expected the read_index_node_at_expected gate to fire; got: {msg:?}"
            );
        },
        other => panic!("expected Malformed; got {other:?}"),
    }
}
