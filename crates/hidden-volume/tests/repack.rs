//! Repack / compaction tests.
//!
//! Verifies that:
//! - All live state is preserved through Container::repack.
//! - Deleted KV entries do NOT survive repack (closes the v0.2 vacuum gap).
//! - Deleted log entries do NOT survive repack (closes the DataBatch leak).
//! - Hidden spaces (passwords NOT supplied) are destroyed by compact_known.
//! - Atomic rename: failed repack leaves source intact.

use hidden_volume::container::RepackOptions;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::Namespace;
use hidden_volume::space::log::log_id_key;
use hidden_volume::{Container, Error};

mod common;
use common::{fast_params, scratch_path};

fn fast_repack_options() -> RepackOptions {
    RepackOptions {
        argon2: fast_params(),
        ..Default::default()
    }
}

#[test]
fn repack_preserves_kv_data() {
    let src = scratch_path();
    let dst = scratch_path();

    {
        let mut c = Container::create(&src, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..50u32 {
            tx.put(
                Namespace::CONTACTS,
                format!("k{i:02}").as_bytes(),
                format!("v{i}").as_bytes(),
            )
            .unwrap();
        }
        tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
        tx.commit().unwrap();
    }

    Container::repack(&src, &dst, &[b"pw"], fast_repack_options()).unwrap();

    let mut c = Container::open(&dst).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 50);
    assert_eq!(
        s.get(Namespace::SETTINGS, b"theme").unwrap().as_deref(),
        Some(&b"dark"[..])
    );
    for i in 0..50u32 {
        let want = format!("v{i}");
        assert_eq!(
            s.get(Namespace::CONTACTS, format!("k{i:02}").as_bytes())
                .unwrap()
                .as_deref(),
            Some(want.as_bytes())
        );
    }

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}

#[test]
fn repack_preserves_log_data() {
    let src = scratch_path();
    let dst = scratch_path();

    {
        let mut c = Container::create(&src, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 1..=200u64 {
            tx.append_log(Namespace::MESSAGE_LOG, i, format!("msg{i:03}").as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
    }

    Container::repack(&src, &dst, &[b"pw"], fast_repack_options()).unwrap();

    let mut c = Container::open(&dst).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::MESSAGE_LOG).unwrap(), 200);
    for i in [1u64, 7, 50, 100, 199, 200] {
        let want = format!("msg{i:03}");
        assert_eq!(
            s.read_log(Namespace::MESSAGE_LOG, i).unwrap().as_deref(),
            Some(want.as_bytes())
        );
    }

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}

#[test]
fn repack_drops_deleted_kv_data() {
    let src = scratch_path();
    let dst = scratch_path();

    {
        let mut c = Container::create(&src, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, b"alice", b"a").unwrap();
        tx.put(Namespace::CONTACTS, b"bob", b"b").unwrap();
        tx.commit().unwrap();
        let mut tx = s.begin_tx();
        tx.delete(Namespace::CONTACTS, b"alice").unwrap();
        tx.commit().unwrap();
    }

    Container::repack(&src, &dst, &[b"pw"], fast_repack_options()).unwrap();

    let mut c = Container::open(&dst).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 1);
    assert!(s.get(Namespace::CONTACTS, b"alice").unwrap().is_none());
    assert_eq!(
        s.get(Namespace::CONTACTS, b"bob").unwrap().as_deref(),
        Some(&b"b"[..])
    );

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}

#[test]
fn repack_drops_deleted_log_messages() {
    // Closes the v0.2 DataBatch leak: in source, deleted message bytes
    // remain in the on-disk batch chunk. After repack, those bytes
    // are gone (only live messages were copied to new batches).
    let src = scratch_path();
    let dst = scratch_path();

    {
        let mut c = Container::create(&src, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 1..=10u64 {
            tx.append_log(Namespace::MESSAGE_LOG, i, format!("msg{i}").as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
        // Delete every other message.
        let mut tx = s.begin_tx();
        for i in (1..=10u64).step_by(2) {
            tx.delete(Namespace::MESSAGE_LOG, &log_id_key(i)).unwrap();
        }
        tx.commit().unwrap();
    }

    Container::repack(&src, &dst, &[b"pw"], fast_repack_options()).unwrap();

    let mut c = Container::open(&dst).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::MESSAGE_LOG).unwrap(), 5);
    for i in 1..=10u64 {
        let got = s.read_log(Namespace::MESSAGE_LOG, i).unwrap();
        if i % 2 == 1 {
            assert!(got.is_none(), "msg{i} should be gone");
        } else {
            assert_eq!(got.as_deref(), Some(format!("msg{i}").as_bytes()));
        }
    }

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}

#[test]
fn repack_multiple_spaces() {
    let src = scratch_path();
    let dst = scratch_path();

    {
        let mut c = Container::create(&src, fast_params()).unwrap();
        let mut a = c.create_space(b"alice").unwrap();
        let mut tx = a.begin_tx();
        tx.put(Namespace::SETTINGS, b"name", b"Alice").unwrap();
        tx.commit().unwrap();
        drop(a);
        let mut b = c.create_space(b"bob").unwrap();
        let mut tx = b.begin_tx();
        tx.put(Namespace::SETTINGS, b"name", b"Bob").unwrap();
        tx.commit().unwrap();
    }

    Container::repack(&src, &dst, &[b"alice", b"bob"], fast_repack_options()).unwrap();

    let mut c = Container::open(&dst).unwrap();
    let mut a = c.open_space(b"alice").unwrap();
    assert_eq!(
        a.get(Namespace::SETTINGS, b"name").unwrap().as_deref(),
        Some(&b"Alice"[..])
    );
    drop(a);
    let mut b = c.open_space(b"bob").unwrap();
    assert_eq!(
        b.get(Namespace::SETTINGS, b"name").unwrap().as_deref(),
        Some(&b"Bob"[..])
    );

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}

#[test]
fn repack_drops_hidden_space_when_password_not_supplied() {
    // The fundamental compact_known semantic: only spaces whose
    // passwords are given survive.
    let src = scratch_path();
    let dst = scratch_path();

    {
        let mut c = Container::create(&src, fast_params()).unwrap();
        let mut a = c.create_space(b"main").unwrap();
        let mut tx = a.begin_tx();
        tx.put(Namespace::SETTINGS, b"main-data", b"visible")
            .unwrap();
        tx.commit().unwrap();
        drop(a);
        let mut h = c.create_space(b"hidden").unwrap();
        let mut tx = h.begin_tx();
        tx.put(Namespace::SETTINGS, b"hidden-data", b"secret")
            .unwrap();
        tx.commit().unwrap();
    }

    // Repack with only the main password.
    Container::repack(&src, &dst, &[b"main"], fast_repack_options()).unwrap();

    let mut c = Container::open(&dst).unwrap();
    let mut a = c.open_space(b"main").unwrap();
    assert_eq!(
        a.get(Namespace::SETTINGS, b"main-data").unwrap().as_deref(),
        Some(&b"visible"[..])
    );
    drop(a);

    // Hidden space is gone — even with the password, it doesn't open.
    match c.open_space(b"hidden").unwrap_err() {
        Error::AuthFailed => {},
        other => panic!("expected AuthFailed for dropped space, got {other:?}"),
    }

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}

#[test]
fn compact_known_in_place() {
    let path = scratch_path();

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..30u32 {
            tx.put(Namespace::CONTACTS, format!("k{i:02}").as_bytes(), b"value")
                .unwrap();
        }
        tx.commit().unwrap();
        // Replace many keys to generate orphans.
        for round in 0..5u8 {
            let mut tx = s.begin_tx();
            for i in 0..30u32 {
                tx.put(
                    Namespace::CONTACTS,
                    format!("k{i:02}").as_bytes(),
                    &[round, b'v'],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
    }

    let size_before = std::fs::metadata(&path).unwrap().len();

    Container::compact_known(&path, &[b"pw"], fast_repack_options()).unwrap();

    let size_after = std::fs::metadata(&path).unwrap().len();

    // After compact, file should be smaller (orphan history is gone).
    assert!(
        size_after < size_before,
        "compact should shrink: before={size_before} after={size_after}"
    );

    // Data integrity preserved.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 30);
    for i in 0..30u32 {
        let got = s
            .get(Namespace::CONTACTS, format!("k{i:02}").as_bytes())
            .unwrap();
        assert_eq!(got.as_deref(), Some(&[4u8, b'v'][..]));
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn compact_all_alias_works() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }
    Container::compact_known(&path, &[b"pw"], fast_repack_options()).unwrap();
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(
        s.get(Namespace::SETTINGS, b"k").unwrap().as_deref(),
        Some(&b"v"[..])
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn repack_rejects_same_source_and_dest() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let _ = c.create_space(b"pw").unwrap();
    }
    match Container::repack(&path, &path, &[b"pw"], fast_repack_options()) {
        Err(Error::Internal(_)) => {},
        other => panic!("expected Internal, got {other:?}"),
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn repack_rejects_wrong_password() {
    let src = scratch_path();
    let dst = scratch_path();
    {
        let mut c = Container::create(&src, fast_params()).unwrap();
        let _ = c.create_space(b"correct").unwrap();
    }
    match Container::repack(&src, &dst, &[b"wrong"], fast_repack_options()) {
        Err(Error::AuthFailed) => {},
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}

#[test]
fn repack_with_param_rotation() {
    // Repack as a way to up-tune Argon2 cost (e.g., user upgraded phone).
    let src = scratch_path();
    let dst = scratch_path();
    {
        let mut c = Container::create(&src, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }

    let new_params = Argon2Params {
        m_cost_kib: 16 * 1024,
        t_cost: 3,
        p_cost: 1,
        version: hidden_volume::crypto::kdf::PARAMS_VERSION as u32,
    };
    let options = RepackOptions {
        argon2: new_params,
        ..Default::default()
    };
    Container::repack(&src, &dst, &[b"pw"], options).unwrap();

    // Dest has new params, and the password still works.
    let mut c = Container::open(&dst).unwrap();
    assert_eq!(c.params(), new_params);
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(
        s.get(Namespace::SETTINGS, b"k").unwrap().as_deref(),
        Some(&b"v"[..])
    );

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}

#[test]
fn realistic_messenger_compaction() {
    // Full workload: contacts + settings + log entries with deletes.
    // After compaction, only live state remains.
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        let mut tx = s.begin_tx();
        for i in 0..20u32 {
            tx.put(
                Namespace::CONTACTS,
                format!("c{i:02}").as_bytes(),
                format!("contact{i}").as_bytes(),
            )
            .unwrap();
        }
        tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
        for i in 1..=300u64 {
            tx.append_log(Namespace::MESSAGE_LOG, i, format!("msg{i}").as_bytes())
                .unwrap();
        }
        // Tx has too many records for one batch — need to split.
        // Actually 300 < MAX_RECORDS_PER_BATCH (1024) so OK. Commit.
        tx.commit().unwrap();

        // Delete half the messages and one contact.
        let mut tx = s.begin_tx();
        for i in 1..=150u64 {
            tx.delete(Namespace::MESSAGE_LOG, &log_id_key(i)).unwrap();
        }
        tx.delete(Namespace::CONTACTS, b"c05").unwrap();
        tx.commit().unwrap();
    }

    Container::compact_known(&path, &[b"pw"], fast_repack_options()).unwrap();

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 19);
    assert!(s.get(Namespace::CONTACTS, b"c05").unwrap().is_none());
    assert_eq!(s.count(Namespace::MESSAGE_LOG).unwrap(), 150);
    for i in 151..=300u64 {
        let want = format!("msg{i}");
        assert_eq!(
            s.read_log(Namespace::MESSAGE_LOG, i).unwrap().as_deref(),
            Some(want.as_bytes())
        );
    }
    for i in 1..=150u64 {
        assert!(s.read_log(Namespace::MESSAGE_LOG, i).unwrap().is_none());
    }

    std::fs::remove_file(&path).ok();
}

/// Repack must classify log namespaces from their persisted
/// `NamespaceKind` byte (format v2 / R-NSKIND, audit pass 13)
/// even when the namespace tag is non-standard. This guards
/// against the historical pass-7-era L1 HIGH defect where a
/// custom log namespace was silently re-`put` into dest as raw
/// KV with bogus 8-byte slot pointers — invisible data loss.
#[test]
fn repack_auto_detects_unlisted_log_namespace() {
    let src = scratch_path();
    let dst = scratch_path();

    // A custom log namespace OTHER than MESSAGE_LOG.
    let custom_log_ns = Namespace(7);

    {
        let mut c = Container::create(&src, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 1..=20u64 {
            tx.append_log(custom_log_ns, i, format!("event{i}").as_bytes())
                .unwrap();
        }
        tx.put(Namespace::CONTACTS, b"alice", b"alice@example.com")
            .unwrap();
        tx.commit().unwrap();
    }

    // Repack with DEFAULT options. Pre-pass-7 this would silently
    // corrupt because the v1 heuristic miscategorized custom log
    // namespaces. Pass-13's R-NSKIND format v2 stores the kind
    // byte on disk, so repack reads ground-truth and classifies
    // correctly regardless of any options-side hint.
    let pw: &[u8] = b"pw";
    Container::repack(&src, &dst, &[pw], fast_repack_options()).unwrap();

    let mut c = Container::open(&dst).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // KV namespace preserved.
    assert_eq!(
        s.get(Namespace::CONTACTS, b"alice").unwrap().as_deref(),
        Some(&b"alice@example.com"[..])
    );
    // Custom log namespace fully preserved as a log (not corrupted).
    assert_eq!(s.count(custom_log_ns).unwrap(), 20);
    for i in 1..=20u64 {
        let want = format!("event{i}");
        assert_eq!(
            s.read_log(custom_log_ns, i).unwrap().as_deref(),
            Some(want.as_bytes()),
            "log_id {i} should round-trip through repack auto-detection"
        );
    }

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}

/// Audit pass 16 R-STREAMING-REPACK: repack of a large log namespace
/// (5000 entries spread across multiple `DataBatch` chunks) must
/// preserve every entry. The pre-pass-16 implementation collected
/// the entire log into an in-memory `Vec` before writing the dest;
/// the streaming implementation pages through it via
/// `iter_log_after`, working set bounded by one page (~512 entries
/// × MAX_LOG_PAYLOAD_LEN ≈ 4 MiB) regardless of total size.
#[test]
fn streaming_repack_preserves_large_log_namespace() {
    let src = scratch_path();
    let dst = scratch_path();

    const N: u64 = 5000;
    {
        let mut c = Container::create(&src, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        // Write in chunks of 256 to stay under the per-Tx
        // MAX_RECORDS_PER_BATCH limit while still producing many
        // Txs and many DataBatch chunks on disk.
        const PER_TX: u64 = 256;
        let mut written: u64 = 0;
        while written < N {
            let mut tx = s.begin_tx();
            let stop = (written + PER_TX).min(N);
            for i in written..stop {
                // Variable-length payload to exercise the index +
                // batch-split path.
                let payload = format!("msg-{i:06}-payload-{}", "x".repeat((i % 64) as usize));
                tx.append_log(Namespace::MESSAGE_LOG, i, payload.as_bytes())
                    .unwrap();
            }
            tx.commit().unwrap();
            written = stop;
        }
        // Sanity: source has all N entries.
        let pre_count = s.count(Namespace::MESSAGE_LOG).unwrap();
        assert_eq!(pre_count, N as usize);
    }

    // Streaming repack — should NOT load the full log into memory.
    Container::repack(&src, &dst, &[b"pw"], fast_repack_options()).unwrap();

    // Dest has every entry, in order, with the original payloads.
    let mut c = Container::open(&dst).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let post_count = s.count(Namespace::MESSAGE_LOG).unwrap();
    assert_eq!(post_count, N as usize);

    // Spot-check a few entries (don't decode all 5000 — the test's
    // own memory budget would make the streaming win moot).
    for i in [0u64, 1, 42, 1000, 2500, N - 1] {
        let want = format!("msg-{i:06}-payload-{}", "x".repeat((i % 64) as usize));
        let got = s.read_log(Namespace::MESSAGE_LOG, i).unwrap();
        assert_eq!(
            got.as_deref(),
            Some(want.as_bytes()),
            "log_id {i} round-trip mismatch"
        );
    }

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}

/// Audit pass 16: streaming repack handles the multi-space, mixed-
/// kind case correctly. Two passwords, each with a Kv namespace
/// + a Log namespace; the dest must have both spaces, each with
///   both namespaces preserved.
#[test]
fn streaming_repack_multi_space_mixed_kinds() {
    let src = scratch_path();
    let dst = scratch_path();

    {
        let mut c = Container::create(&src, fast_params()).unwrap();
        // Space A.
        {
            let mut s = c.create_space(b"alice").unwrap();
            let mut tx = s.begin_tx();
            tx.put(Namespace::CONTACTS, b"key-a", b"alice-value")
                .unwrap();
            for i in 0..100u64 {
                tx.append_log(Namespace::MESSAGE_LOG, i, format!("a-msg{i}").as_bytes())
                    .unwrap();
            }
            tx.commit().unwrap();
        }
        // Space B.
        {
            let mut s = c.create_space(b"bob").unwrap();
            let mut tx = s.begin_tx();
            tx.put(Namespace::CONTACTS, b"key-b", b"bob-value").unwrap();
            for i in 0..200u64 {
                tx.append_log(Namespace::MESSAGE_LOG, i, format!("b-msg{i}").as_bytes())
                    .unwrap();
            }
            tx.commit().unwrap();
        }
    }

    Container::repack(&src, &dst, &[b"alice", b"bob"], fast_repack_options()).unwrap();

    // Verify both spaces preserved.
    let mut c = Container::open(&dst).unwrap();
    {
        let mut a = c.open_space(b"alice").unwrap();
        assert_eq!(
            a.get(Namespace::CONTACTS, b"key-a").unwrap().as_deref(),
            Some(&b"alice-value"[..])
        );
        assert_eq!(a.count(Namespace::MESSAGE_LOG).unwrap(), 100);
        assert_eq!(
            a.read_log(Namespace::MESSAGE_LOG, 50).unwrap().as_deref(),
            Some(&b"a-msg50"[..])
        );
    }
    {
        let mut b = c.open_space(b"bob").unwrap();
        assert_eq!(
            b.get(Namespace::CONTACTS, b"key-b").unwrap().as_deref(),
            Some(&b"bob-value"[..])
        );
        assert_eq!(b.count(Namespace::MESSAGE_LOG).unwrap(), 200);
        assert_eq!(
            b.read_log(Namespace::MESSAGE_LOG, 150).unwrap().as_deref(),
            Some(&b"b-msg150"[..])
        );
    }

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}
