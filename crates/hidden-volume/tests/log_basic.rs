//! DataBatch / log namespace tests.
//!
//! Tx::append_log routes through the message-log path: zstd-compressed
//! batches stored as DataBatch chunks, KV index gets 8-byte slot
//! pointers per record. This tests the externally visible behavior.

use hidden_volume::space::index::Namespace;
use hidden_volume::space::log::{MAX_LOG_PAYLOAD_LEN, MAX_RECORDS_PER_BATCH};
use hidden_volume::{Container, Error};

mod common;
use common::fast_params;

/// Deterministic xorshift64 stream — produces high-entropy, effectively
/// incompressible bytes for split-path tests. Reproducible across runs
/// from the same `(seed, counter)`.
fn pseudo_random(seed: u64, counter: u64, len: usize) -> Vec<u8> {
    let mut state = seed
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(counter);
    if state == 0 {
        state = 1;
    }
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = state.to_le_bytes();
        let take = (len - out.len()).min(8);
        out.extend_from_slice(&bytes[..take]);
    }
    out
}

#[test]
fn single_log_entry_round_trip() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.append_log(Namespace::MESSAGE_LOG, 42, b"hello world")
            .unwrap();
        tx.commit().unwrap();

        let got = s.read_log(Namespace::MESSAGE_LOG, 42).unwrap();
        assert_eq!(got.as_deref(), Some(&b"hello world"[..]));
        // Missing id returns None.
        assert!(s.read_log(Namespace::MESSAGE_LOG, 99).unwrap().is_none());
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let got = s.read_log(Namespace::MESSAGE_LOG, 42).unwrap();
    assert_eq!(got.as_deref(), Some(&b"hello world"[..]));

    std::fs::remove_file(&path).ok();
}

#[test]
fn many_log_entries_one_tx_share_one_batch() {
    // 100 short messages should fit in one DataBatch chunk after
    // compression. All readable individually.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for i in 0..100u64 {
        let payload = format!("msg-{i:03}-with-some-text-to-compress");
        tx.append_log(Namespace::MESSAGE_LOG, i, payload.as_bytes())
            .unwrap();
    }
    tx.commit().unwrap();

    for i in 0..100u64 {
        let want = format!("msg-{i:03}-with-some-text-to-compress");
        let got = s.read_log(Namespace::MESSAGE_LOG, i).unwrap();
        assert_eq!(got.as_deref(), Some(want.as_bytes()));
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn many_txs_make_many_batches() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    // 50 separate txs of 10 messages each = 50 batches, 500 messages.
    for tx_idx in 0..50u64 {
        let mut tx = s.begin_tx();
        for i in 0..10u64 {
            let log_id = tx_idx * 10 + i;
            let payload = format!("tx{tx_idx}-msg{i}");
            tx.append_log(Namespace::MESSAGE_LOG, log_id, payload.as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
    }

    // Sample-check across all batches.
    for log_id in [0u64, 5, 99, 100, 250, 499] {
        let tx_idx = log_id / 10;
        let i = log_id % 10;
        let want = format!("tx{tx_idx}-msg{i}");
        let got = s.read_log(Namespace::MESSAGE_LOG, log_id).unwrap();
        assert_eq!(got.as_deref(), Some(want.as_bytes()), "log_id={log_id}");
    }

    // After 50 commits, seq is 51 (initial + 50 txs).
    assert_eq!(s.commit_seq(), 51);

    std::fs::remove_file(&path).ok();
}

#[test]
fn log_namespace_count_matches_distinct_ids() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for i in 0..50u64 {
        tx.append_log(Namespace::MESSAGE_LOG, i, b"x").unwrap();
    }
    tx.commit().unwrap();

    // Each log entry is one KV entry under the hood.
    assert_eq!(s.count(Namespace::MESSAGE_LOG).unwrap(), 50);

    std::fs::remove_file(&path).ok();
}

#[test]
fn log_and_kv_in_different_namespaces_coexist() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"username", b"alice").unwrap();
    tx.put(Namespace::CONTACTS, b"bob", b"bob@example.com")
        .unwrap();
    tx.append_log(Namespace::MESSAGE_LOG, 1, b"first message")
        .unwrap();
    tx.append_log(Namespace::MESSAGE_LOG, 2, b"second message")
        .unwrap();
    tx.commit().unwrap();

    assert_eq!(
        s.get(Namespace::SETTINGS, b"username").unwrap().as_deref(),
        Some(&b"alice"[..])
    );
    assert_eq!(
        s.get(Namespace::CONTACTS, b"bob").unwrap().as_deref(),
        Some(&b"bob@example.com"[..])
    );
    assert_eq!(
        s.read_log(Namespace::MESSAGE_LOG, 1).unwrap().as_deref(),
        Some(&b"first message"[..])
    );
    assert_eq!(
        s.read_log(Namespace::MESSAGE_LOG, 2).unwrap().as_deref(),
        Some(&b"second message"[..])
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn append_log_replaces_with_same_id_in_one_tx() {
    // Last write wins for repeated log_id within one tx.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.append_log(Namespace::MESSAGE_LOG, 7, b"first").unwrap();
    tx.append_log(Namespace::MESSAGE_LOG, 7, b"second").unwrap();
    tx.append_log(Namespace::MESSAGE_LOG, 7, b"third").unwrap();
    tx.commit().unwrap();

    let got = s.read_log(Namespace::MESSAGE_LOG, 7).unwrap();
    assert_eq!(got.as_deref(), Some(&b"third"[..]));
    // Only one entry stored.
    assert_eq!(s.count(Namespace::MESSAGE_LOG).unwrap(), 1);

    std::fs::remove_file(&path).ok();
}

#[test]
fn append_log_replace_across_txs() {
    // Tx2 with same log_id replaces Tx1's value.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    let mut tx = s.begin_tx();
    tx.append_log(Namespace::MESSAGE_LOG, 100, b"old").unwrap();
    tx.commit().unwrap();

    let mut tx = s.begin_tx();
    tx.append_log(Namespace::MESSAGE_LOG, 100, b"new").unwrap();
    tx.commit().unwrap();

    let got = s.read_log(Namespace::MESSAGE_LOG, 100).unwrap();
    assert_eq!(got.as_deref(), Some(&b"new"[..]));

    std::fs::remove_file(&path).ok();
}

#[test]
fn oversized_log_payload_rejected() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    let big = vec![0u8; MAX_LOG_PAYLOAD_LEN + 1];
    match tx.append_log(Namespace::MESSAGE_LOG, 1, &big).unwrap_err() {
        Error::PayloadTooLarge => {},
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn batch_record_count_capped() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for i in 0..MAX_RECORDS_PER_BATCH as u64 {
        tx.append_log(Namespace::MESSAGE_LOG, i, b"x").unwrap();
    }
    // One past the limit must error before commit.
    match tx
        .append_log(Namespace::MESSAGE_LOG, MAX_RECORDS_PER_BATCH as u64, b"x")
        .unwrap_err()
    {
        Error::PayloadTooLarge => {},
        other => panic!("expected PayloadTooLarge for overflow, got {other:?}"),
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn cross_space_log_isolation() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();

        let mut a = c.create_space(b"alice").unwrap();
        let mut tx = a.begin_tx();
        tx.append_log(Namespace::MESSAGE_LOG, 1, b"alice msg 1")
            .unwrap();
        tx.append_log(Namespace::MESSAGE_LOG, 2, b"alice msg 2")
            .unwrap();
        tx.commit().unwrap();
        drop(a);

        let mut b = c.create_space(b"bob").unwrap();
        let mut tx = b.begin_tx();
        tx.append_log(Namespace::MESSAGE_LOG, 1, b"bob msg 1")
            .unwrap();
        tx.append_log(Namespace::MESSAGE_LOG, 2, b"bob msg 2")
            .unwrap();
        tx.commit().unwrap();
    }

    let mut c = Container::open(&path).unwrap();

    let mut a = c.open_space(b"alice").unwrap();
    assert_eq!(
        a.read_log(Namespace::MESSAGE_LOG, 1).unwrap().as_deref(),
        Some(&b"alice msg 1"[..])
    );
    drop(a);

    let mut b = c.open_space(b"bob").unwrap();
    assert_eq!(
        b.read_log(Namespace::MESSAGE_LOG, 1).unwrap().as_deref(),
        Some(&b"bob msg 1"[..])
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn realistic_messenger_workload() {
    // Simulate a small chat: 5 conversations, ~100 messages each, mixed
    // with contact updates and settings changes. Verifies the full
    // workflow under realistic Tx granularity.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    // Setup: settings + contacts.
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"profile", b"alice").unwrap();
    tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
    for i in 0..5u32 {
        tx.put(
            Namespace::CONTACTS,
            format!("peer{i:02}").as_bytes(),
            format!("Peer #{i}").as_bytes(),
        )
        .unwrap();
    }
    tx.commit().unwrap();

    // Conversations: each tx commits a batch of incoming + outgoing.
    let mut next_msg_id: u64 = 1;
    for _conv in 0..5 {
        for _round in 0..20 {
            let mut tx = s.begin_tx();
            for _msg in 0..5 {
                let payload = format!("msg-content-{next_msg_id:06}");
                tx.append_log(Namespace::MESSAGE_LOG, next_msg_id, payload.as_bytes())
                    .unwrap();
                next_msg_id += 1;
            }
            tx.commit().unwrap();
        }
    }
    let total_msgs = next_msg_id - 1;
    assert_eq!(total_msgs, 500);

    // Reopen + verify.
    drop(s);
    drop(c);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::MESSAGE_LOG).unwrap(), 500);
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 5);
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 2);

    // Sample-check messages.
    for id in [1u64, 7, 100, 250, 500] {
        let want = format!("msg-content-{id:06}");
        let got = s.read_log(Namespace::MESSAGE_LOG, id).unwrap();
        assert_eq!(got.as_deref(), Some(want.as_bytes()), "id={id}");
    }

    std::fs::remove_file(&path).ok();
}

/// Many large incompressible payloads in one Tx must auto-split into
/// multiple DataBatch chunks. The whole set is several PAYLOAD_CAPs
/// worth of high-entropy bytes — no single batch could hold it. Every
/// record must remain individually readable.
#[test]
fn auto_split_large_incompressible_records_one_tx() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    // 32 records × 2 KiB random bytes ≈ 64 KiB raw. Even if zstd
    // managed a 50% ratio (it won't on random data), that's 32 KiB —
    // 8× over PAYLOAD_CAP. Splitter must produce ≥ 8 batches.
    let n: u64 = 32;
    let payload_size = 2048;
    let payloads: Vec<Vec<u8>> = (0..n)
        .map(|i| pseudo_random(0xCAFE_BABE_DEAD_BEEF, i, payload_size))
        .collect();

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let slots_before = s.audit_owned_chunk_count();
        let mut tx = s.begin_tx();
        for (i, p) in payloads.iter().enumerate() {
            tx.append_log(Namespace::MESSAGE_LOG, i as u64, p).unwrap();
        }
        // Must succeed despite payloads being incompressible.
        tx.commit().unwrap();

        let slots_after = s.audit_owned_chunk_count();
        // We expect the commit to have written multiple DataBatch chunks
        // plus the IndexNode + Commit + Superblock. Sanity check: the
        // delta is much greater than what a single-batch commit would
        // produce (1 DataBatch + 1 leaf + 1 commit + 1 sb = 4).
        assert!(
            slots_after - slots_before >= 8,
            "expected ≥8 chunks for split commit, got {}",
            slots_after - slots_before
        );

        for (i, want) in payloads.iter().enumerate() {
            let got = s.read_log(Namespace::MESSAGE_LOG, i as u64).unwrap();
            assert_eq!(got.as_deref(), Some(&want[..]), "log_id={i}");
        }
    }

    // Reopen + verify durability.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::MESSAGE_LOG).unwrap(), n as usize);
    for (i, want) in payloads.iter().enumerate() {
        let got = s.read_log(Namespace::MESSAGE_LOG, i as u64).unwrap();
        assert_eq!(got.as_deref(), Some(&want[..]), "post-reopen log_id={i}");
    }

    std::fs::remove_file(&path).ok();
}

/// Pagination must work transparently across split-batch boundaries:
/// `iter_log_after` / `iter_log_before` follow KV pointers, not batch
/// boundaries, so the result should be a contiguous run regardless of
/// how the underlying batches are sliced.
#[test]
fn pagination_works_across_split_batches() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let n: u64 = 24;
    let payloads: Vec<Vec<u8>> = (0..n)
        .map(|i| pseudo_random(0xFEED_FACE_F00D, i, 1500))
        .collect();

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for (i, p) in payloads.iter().enumerate() {
        tx.append_log(Namespace::MESSAGE_LOG, i as u64, p).unwrap();
    }
    tx.commit().unwrap();

    // Forward pagination, page size 5: must return all 24 in order.
    let mut got: Vec<u64> = Vec::new();
    let mut after: Option<u64> = None;
    loop {
        let page = s.iter_log_after(Namespace::MESSAGE_LOG, after, 5).unwrap();
        if page.is_empty() {
            break;
        }
        for (id, _) in &page {
            got.push(*id);
        }
        after = Some(page.last().unwrap().0);
    }
    assert_eq!(got, (0..n).collect::<Vec<_>>());

    // Reverse pagination, page size 7: must return all 24 in reverse.
    let mut got_rev: Vec<u64> = Vec::new();
    let mut before: Option<u64> = None;
    loop {
        let page = s
            .iter_log_before(Namespace::MESSAGE_LOG, before, 7)
            .unwrap();
        if page.is_empty() {
            break;
        }
        for (id, _) in &page {
            got_rev.push(*id);
        }
        before = Some(page.last().unwrap().0);
    }
    assert_eq!(got_rev, (0..n).rev().collect::<Vec<_>>());

    std::fs::remove_file(&path).ok();
}
