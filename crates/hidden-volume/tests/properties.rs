//! Property tests covering v0.2 invariants.
//!
//! Properties verified:
//!
//!   P1. Chunk plaintext encode -> decode is a bijection on (kind, seq,
//!       flags, payload) for any payload up to PAYLOAD_CAP.
//!
//!   P2. Scan is deterministic: opening the same file with the same
//!       password produces an identical observable KV state, regardless
//!       of how many times we open it.
//!
//!   P3. Wrong-password never produces a Superblock: for any password
//!       not used to create a space, `open_space` returns AuthFailed.
//!       This is the security-critical property — failing it would mean
//!       an adversary can detect space presence by trial-decrypt.

use hidden_volume::chunk::ChunkKind;
use hidden_volume::chunk::format::{PAYLOAD_CAP, Plaintext};
use hidden_volume::space::index::Namespace;
use hidden_volume::{Container, Error};
use proptest::prelude::*;
use std::collections::BTreeMap;

mod common;
use common::fast_params;

struct ScratchFile(std::path::PathBuf);
impl ScratchFile {
    fn new() -> Self {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let p = tmp.path().to_owned();
        drop(tmp);
        Self(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for ScratchFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ---------- P1 ----------

fn arbitrary_chunk_kind() -> impl Strategy<Value = ChunkKind> {
    prop_oneof![
        Just(ChunkKind::Superblock),
        Just(ChunkKind::IndexNode),
        Just(ChunkKind::Commit),
        Just(ChunkKind::DataBatch),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn p1_chunk_plaintext_roundtrip(
        kind in arbitrary_chunk_kind(),
        seq: u64,
        payload in proptest::collection::vec(any::<u8>(), 0..=PAYLOAD_CAP),
    ) {
        let pt = Plaintext { kind, seq, payload: payload.clone() };
        let encoded = pt.encode().unwrap();
        let decoded = Plaintext::decode(&encoded).unwrap();

        prop_assert_eq!(decoded.kind, kind);
        prop_assert_eq!(decoded.seq, seq);
        prop_assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn p1_oversized_payload_rejected(
        excess in 1usize..=64usize,
    ) {
        let payload = vec![0xAAu8; PAYLOAD_CAP + excess];
        let pt = Plaintext {
            kind: ChunkKind::Superblock,
            seq: 0,
            payload,
        };
        prop_assert!(pt.encode().is_err());
    }

    /// Strict-mode forward-compat: byte 5 (reserved flags) must be 0.
    /// A v1 reader must reject a v2-format chunk that uses the byte
    /// for new semantics. Audit B3.
    #[test]
    fn p1_non_zero_reserved_flags_byte_rejected(
        non_zero in 1u8..=255u8,
    ) {
        let pt = Plaintext {
            kind: ChunkKind::Superblock,
            seq: 0,
            payload: Vec::new(),
        };
        let mut encoded = pt.encode().unwrap();
        encoded[5] = non_zero;
        let res = Plaintext::decode(&encoded);
        prop_assert!(res.is_err(), "non-zero flags byte must be rejected");
    }
}

// ---------- P2 ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    /// Build a KV state by applying a random sequence of put/delete in
    /// 1–4 transactions, then verify three independent reopens see the
    /// exact same state (key→value mapping).
    #[test]
    fn p2_scan_determinism(
        password in proptest::collection::vec(any::<u8>(), 1..=32),
        ops in proptest::collection::vec(
            (
                proptest::collection::vec(any::<u8>(), 1..=16),  // key
                proptest::collection::vec(any::<u8>(), 0..=64),  // value
                any::<bool>(),                                   // is_delete?
            ),
            1..=8,
        ),
    ) {
        let scratch = ScratchFile::new();
        let path = scratch.path().to_owned();

        // Reference model: apply ops to a BTreeMap, that's the
        // expected final state.
        let mut expected: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for (k, v, del) in &ops {
            if *del {
                expected.remove(k);
            } else {
                expected.insert(k.clone(), v.clone());
            }
        }

        // Build container.
        {
            let mut c = Container::create(&path, fast_params()).unwrap();
            let mut s = c.create_space(&password).unwrap();
            // Apply each op as its own Tx (exercises sequential commits).
            for (k, v, del) in &ops {
                let mut tx = s.begin_tx();
                if *del {
                    tx.delete(Namespace::CONTACTS, k).unwrap();
                } else {
                    tx.put(Namespace::CONTACTS, k, v).unwrap();
                }
                tx.commit().unwrap();
            }
        }

        // Three independent opens — must be identical.
        for _ in 0..3 {
            let mut c = Container::open(&path).unwrap();
            let mut s = c.open_space(&password).unwrap();
            let listed = s.list(Namespace::CONTACTS).unwrap();
            let actual: BTreeMap<Vec<u8>, Vec<u8>> = listed.into_iter().collect();
            prop_assert_eq!(&actual, &expected);
        }
    }
}

// ---------- P3 ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(6))]

    /// SECURITY-CRITICAL: any password not used to create a space
    /// MUST result in AuthFailed.
    #[test]
    fn p3_wrong_password_returns_auth_failed(
        real_password in proptest::collection::vec(any::<u8>(), 1..=32),
        wrong_passwords in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 1..=32),
            4..=8,
        ),
    ) {
        let scratch = ScratchFile::new();
        let path = scratch.path().to_owned();

        {
            let mut c = Container::create(&path, fast_params()).unwrap();
            let mut s = c.create_space(&real_password).unwrap();
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", b"protected").unwrap();
            tx.commit().unwrap();
        }

        let mut c = Container::open(&path).unwrap();

        for wp in &wrong_passwords {
            if wp == &real_password {
                continue;
            }
            match c.open_space(wp) {
                Err(Error::AuthFailed) => {}
                Ok(_) => prop_assert!(false, "wrong password opened a space"),
                Err(other) => prop_assert!(
                    false,
                    "expected AuthFailed for wrong password, got {other:?}"
                ),
            }
        }

        let mut s = c.open_space(&real_password).unwrap();
        let got = s.get(Namespace::SETTINGS, b"k").unwrap();
        prop_assert_eq!(got.as_deref(), Some(&b"protected"[..]));
    }
}
