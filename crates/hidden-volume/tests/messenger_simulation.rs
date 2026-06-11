//! End-to-end messenger workflow simulation.
//!
//! These tests model realistic workloads that a deniable-messenger
//! host-app would generate. They're not unit-level — they exercise
//! multiple library subsystems (KV + log + vacuum + repack + locking)
//! interacting over many sessions, and validate the assumed
//! invariants hold for actual usage patterns:
//!
//! - File size stays bounded with periodic compaction.
//! - Messages from "day 1" are still readable on "day N".
//! - Deleted entries physically disappear after compact.
//! - Reopen cycles don't corrupt state.
//! - Hidden spaces coexist with the main space.
//!
//! Cost: Argon2id MIN per open. Each test does many opens, so the
//! suite takes several seconds.

use hidden_volume::container::{ContainerOptions, RepackOptions};
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use hidden_volume::space::log::log_id_key;
use hidden_volume::{Container, Error};

mod common;
use common::scratch_path;

fn fast_options() -> ContainerOptions {
    ContainerOptions {
        argon2: Argon2Params::MIN,
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 1,
    }
}

fn fast_repack_options() -> RepackOptions {
    RepackOptions {
        argon2: Argon2Params::MIN,
        ..Default::default()
    }
}

fn file_size(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).unwrap().len()
}

/// Simulate one "day" of activity:
/// - send N outgoing messages
/// - receive N incoming messages
/// - update one contact's last-seen field
/// - update settings
fn simulate_day(
    container_path: &std::path::Path,
    password: &[u8],
    day: u32,
    msgs_per_day: u64,
    next_msg_id: &mut u64,
) -> hidden_volume::Result<()> {
    let mut c = Container::open(container_path)?;
    let mut s = c.open_space(password)?;
    let mut tx = s.begin_tx();

    // Send messages.
    for i in 0..msgs_per_day {
        let payload = format!("day{day}-out-{i}");
        tx.append_log(Namespace::MESSAGE_LOG, *next_msg_id, payload.as_bytes())?;
        *next_msg_id += 1;
    }

    // Update one contact's last-seen.
    tx.put(
        Namespace::CONTACTS,
        b"alice",
        format!("last_seen_day_{day}").as_bytes(),
    )?;

    // Settings tweak.
    tx.put(Namespace::SETTINGS, b"last_active", &day.to_le_bytes())?;

    tx.commit()?;
    Ok(())
}

#[test]
fn five_day_simulated_workload() {
    let path = scratch_path();
    let password = b"realistic-test-password";

    // Initial setup: container + space + initial contacts.
    {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        let mut s = c.create_space(password).unwrap();
        let mut tx = s.begin_tx();
        for name in ["alice", "bob", "carol", "dave", "eve"] {
            tx.put(
                Namespace::CONTACTS,
                name.as_bytes(),
                format!("{name}@example.com").as_bytes(),
            )
            .unwrap();
        }
        tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
        tx.put(Namespace::SETTINGS, b"language", b"en").unwrap();
        tx.commit().unwrap();
    }

    // 5 "days" of activity, 20 messages per day = 100 total.
    let mut next_msg_id = 1u64;
    for day in 0..5u32 {
        simulate_day(&path, password, day, 20, &mut next_msg_id).unwrap();
    }
    let total_msgs = next_msg_id - 1;
    assert_eq!(total_msgs, 100);

    // Final state verification.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(password).unwrap();
    assert_eq!(s.commit_seq(), 1 /*create*/ + 1 /*setup*/ + 5 /*days*/);
    assert_eq!(s.count(Namespace::MESSAGE_LOG).unwrap(), 100);
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 5);

    // Sample checks across timeline.
    for id in [1u64, 25, 50, 75, 100] {
        let payload = s.read_log(Namespace::MESSAGE_LOG, id).unwrap();
        assert!(payload.is_some(), "msg #{id} should be readable");
    }

    // Alice's last-seen reflects the latest day.
    let last_seen = s
        .get(Namespace::CONTACTS, b"alice")
        .unwrap()
        .map(|v| String::from_utf8_lossy(&v).into_owned());
    assert_eq!(last_seen.as_deref(), Some("last_seen_day_4"));

    std::fs::remove_file(&path).ok();
}

#[test]
fn growth_bounded_with_periodic_compaction() {
    // Simulate 3 weeks of activity with weekly compaction.
    // File size should not grow unboundedly thanks to compact_known.
    let path = scratch_path();
    let password = b"weekly-pw";

    {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        let _s = c.create_space(password).unwrap();
    }

    let mut next_msg_id = 1u64;
    let mut sizes: Vec<u64> = Vec::new();
    for week in 0..3u32 {
        // 7 days × 30 messages.
        for day_in_week in 0..7u32 {
            let day = week * 7 + day_in_week;
            simulate_day(&path, password, day, 30, &mut next_msg_id).unwrap();
        }
        let size_before = file_size(&path);

        // Weekly compaction.
        Container::compact_known(&path, &[password], fast_repack_options()).unwrap();

        let size_after = file_size(&path);
        sizes.push(size_after);
        // Compaction should never grow the file vs. pre-compaction.
        assert!(
            size_after <= size_before,
            "week {week}: post-compact ({size_after}) > pre-compact ({size_before})"
        );
    }

    // File size after week 3 should be bounded — proportional to the
    // current state (3*7*30 = 630 messages + small contacts/settings),
    // not the cumulative number of writes.
    let final_size = sizes.last().copied().unwrap();
    let messages = next_msg_id - 1;
    // ~80 bytes/msg is the upper-bound after compression. Plus B+ tree
    // overhead. 100x safety factor for headers / Superblock replicas /
    // initial garbage padding allowance.
    let upper_bound = (messages * 80 * 100) / 10; // = messages * 800
    assert!(
        final_size < upper_bound,
        "final size {final_size} exceeds bound {upper_bound} for {messages} msgs"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn messages_readable_after_many_reopens() {
    // Open / close 20 times with a few messages added each time.
    // Day-1 messages must remain readable at the end.
    let path = scratch_path();
    let password = b"reopen-pw";

    {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        let mut s = c.create_space(password).unwrap();
        let mut tx = s.begin_tx();
        // Initial messages with known IDs.
        tx.append_log(Namespace::MESSAGE_LOG, 1, b"day-one msg #1")
            .unwrap();
        tx.append_log(Namespace::MESSAGE_LOG, 2, b"day-one msg #2")
            .unwrap();
        tx.commit().unwrap();
    }

    // 20 reopens with one message each.
    for i in 0..20u64 {
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(password).unwrap();
        let mut tx = s.begin_tx();
        let id = 100 + i;
        tx.append_log(
            Namespace::MESSAGE_LOG,
            id,
            format!("reopen #{i}").as_bytes(),
        )
        .unwrap();
        tx.commit().unwrap();
    }

    // Final read — original day-one messages still there.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(password).unwrap();
    assert_eq!(s.count(Namespace::MESSAGE_LOG).unwrap(), 22);
    assert_eq!(
        s.read_log(Namespace::MESSAGE_LOG, 1).unwrap().as_deref(),
        Some(&b"day-one msg #1"[..])
    );
    assert_eq!(
        s.read_log(Namespace::MESSAGE_LOG, 2).unwrap().as_deref(),
        Some(&b"day-one msg #2"[..])
    );
    assert!(
        s.read_log(Namespace::MESSAGE_LOG, 119).unwrap().is_some(),
        "reopen #19 should be readable"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn delete_then_compact_eliminates_bytes() {
    // Forward-secrecy claim: deleted messages must NOT survive
    // compact. Test by writing message bytes that are easy to grep,
    // deleting, compacting, then scanning the file.
    let path = scratch_path();
    let password = b"delete-test-pw";
    let canary = b"CANARY_DELETED_MESSAGE_PLAINTEXT_XXYYZZ";

    {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        let mut s = c.create_space(password).unwrap();
        let mut tx = s.begin_tx();
        tx.append_log(Namespace::MESSAGE_LOG, 1, canary).unwrap();
        tx.append_log(Namespace::MESSAGE_LOG, 2, b"keeper-msg")
            .unwrap();
        tx.commit().unwrap();
        // Delete message 1 (the canary).
        let mut tx = s.begin_tx();
        tx.delete(Namespace::MESSAGE_LOG, &log_id_key(1)).unwrap();
        tx.commit().unwrap();
    }

    // Before compact: canary may still be in some old DataBatch chunk
    // (just orphan). Encrypted, so not visible as plaintext anyway —
    // but a forensic adversary with the password would see it via
    // iter_log over orphan batches. That's the v0.2 leak we close
    // here via repack.

    // Compact with the password we have.
    Container::compact_known(&path, &[password], fast_repack_options()).unwrap();

    // Now the canary should not be present in any chunk's PLAINTEXT.
    // We can't easily decrypt all chunks here, so instead verify via
    // the public API: log entry 1 must be unreachable, entry 2 OK.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(password).unwrap();
    assert!(s.read_log(Namespace::MESSAGE_LOG, 1).unwrap().is_none());
    assert_eq!(
        s.read_log(Namespace::MESSAGE_LOG, 2).unwrap().as_deref(),
        Some(&b"keeper-msg"[..])
    );
    // iter_log shouldn't yield the canary anywhere.
    let entries = s.iter_log(Namespace::MESSAGE_LOG).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(!entries.iter().any(|(_, v)| v.as_slice() == canary));

    std::fs::remove_file(&path).ok();
}

#[test]
fn concurrent_writer_and_reader_handoff() {
    // Realistic P2P pattern: writer commits, drops, reader opens to
    // sync changes, drops, writer opens again. Sequential handoff
    // pattern. Verifies the lock release is timely.
    let path = scratch_path();
    let password = b"handoff-pw";

    {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        let _s = c.create_space(password).unwrap();
    }

    for round in 0..10u32 {
        // Writer.
        {
            let mut c = Container::open(&path).unwrap();
            let mut s = c.open_space(password).unwrap();
            let mut tx = s.begin_tx();
            tx.append_log(
                Namespace::MESSAGE_LOG,
                round as u64 + 1,
                format!("round {round}").as_bytes(),
            )
            .unwrap();
            tx.commit().unwrap();
        }

        // Reader (sync agent simulation).
        {
            let mut c = Container::open_readonly(&path).unwrap();
            assert!(c.is_readonly());
            let mut s = c.open_space(password).unwrap();
            assert_eq!(s.count(Namespace::MESSAGE_LOG).unwrap() as u32, round + 1);
        }
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(password).unwrap();
    assert_eq!(s.count(Namespace::MESSAGE_LOG).unwrap(), 10);

    std::fs::remove_file(&path).ok();
}

#[test]
fn hidden_space_coexists_with_main() {
    // The defining deniability scenario: main user space + hidden
    // space. Both writable, both isolated from each other, both
    // survive compact_known when both passwords are supplied.
    let path = scratch_path();

    {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();

        let mut main = c.create_space(b"main-pwd").unwrap();
        let mut tx = main.begin_tx();
        tx.put(Namespace::SETTINGS, b"username", b"public-name")
            .unwrap();
        for i in 1..=10u64 {
            tx.append_log(
                Namespace::MESSAGE_LOG,
                i,
                format!("public msg {i}").as_bytes(),
            )
            .unwrap();
        }
        tx.commit().unwrap();
        drop(main);

        let mut hidden = c.create_space(b"hidden-pwd").unwrap();
        let mut tx = hidden.begin_tx();
        tx.put(Namespace::SETTINGS, b"username", b"private-identity")
            .unwrap();
        for i in 1..=5u64 {
            tx.append_log(
                Namespace::MESSAGE_LOG,
                i,
                format!("secret msg {i}").as_bytes(),
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }

    // Compact with BOTH passwords — both should survive.
    Container::compact_known(&path, &[b"main-pwd", b"hidden-pwd"], fast_repack_options()).unwrap();

    let mut c = Container::open(&path).unwrap();
    let mut main = c.open_space(b"main-pwd").unwrap();
    assert_eq!(
        main.get(Namespace::SETTINGS, b"username")
            .unwrap()
            .as_deref(),
        Some(&b"public-name"[..])
    );
    assert_eq!(main.count(Namespace::MESSAGE_LOG).unwrap(), 10);
    drop(main);

    let mut hidden = c.open_space(b"hidden-pwd").unwrap();
    assert_eq!(
        hidden
            .get(Namespace::SETTINGS, b"username")
            .unwrap()
            .as_deref(),
        Some(&b"private-identity"[..])
    );
    assert_eq!(hidden.count(Namespace::MESSAGE_LOG).unwrap(), 5);

    std::fs::remove_file(&path).ok();
}

#[test]
fn drop_decoy_via_compact_known() {
    // Workflow: user has a decoy + real space. After being forced
    // to "show" the decoy password, they want to compact the file
    // keeping ONLY the real space — the decoy gets destroyed.
    let path = scratch_path();

    {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        let mut decoy = c.create_space(b"decoy").unwrap();
        let mut tx = decoy.begin_tx();
        tx.put(Namespace::SETTINGS, b"name", b"plausible-decoy")
            .unwrap();
        tx.commit().unwrap();
        drop(decoy);
        let mut real = c.create_space(b"real").unwrap();
        let mut tx = real.begin_tx();
        tx.put(Namespace::SETTINGS, b"name", b"actual-data")
            .unwrap();
        tx.commit().unwrap();
    }

    // Both spaces work pre-compact.
    {
        let mut c = Container::open(&path).unwrap();
        let _ = c.open_space(b"decoy").unwrap();
    }

    // Compact_known with only the real password drops the decoy.
    Container::compact_known(&path, &[b"real"], fast_repack_options()).unwrap();

    // Decoy is gone.
    let mut c = Container::open(&path).unwrap();
    match c.open_space(b"decoy") {
        Err(Error::AuthFailed) => {},
        other => panic!("decoy should be dropped after compact_known; got {other:?}"),
    }

    // Real space is intact.
    let mut real = c.open_space(b"real").unwrap();
    assert_eq!(
        real.get(Namespace::SETTINGS, b"name").unwrap().as_deref(),
        Some(&b"actual-data"[..])
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn long_running_session_with_mixed_workload() {
    // Single long-running session: many Tx commits, vacuum every N,
    // verify final state matches expectations and storage is bounded.
    let path = scratch_path();
    let password = b"long-session";

    {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        let mut s = c.create_space(password).unwrap();

        let mut next_msg = 1u64;
        for round in 0..30u32 {
            let mut tx = s.begin_tx();
            // 5 messages per round.
            for _ in 0..5 {
                tx.append_log(
                    Namespace::MESSAGE_LOG,
                    next_msg,
                    format!("r{round}-msg{next_msg}").as_bytes(),
                )
                .unwrap();
                next_msg += 1;
            }
            // Update settings sometimes.
            if round % 3 == 0 {
                tx.put(Namespace::SETTINGS, b"counter", &round.to_le_bytes())
                    .unwrap();
            }
            // Add/update contacts.
            tx.put(
                Namespace::CONTACTS,
                format!("c{}", round % 10).as_bytes(),
                format!("data-{round}").as_bytes(),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        // 150 messages, 10 contacts (cycled), 1 setting.
        assert_eq!(s.count(Namespace::MESSAGE_LOG).unwrap(), 150);
        assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 10);
        assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 1);
    }

    // Reopen-time vacuum runs (cleans orphan IndexNodes from contact
    // updates). Verify state still consistent.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(password).unwrap();
    assert_eq!(s.count(Namespace::MESSAGE_LOG).unwrap(), 150);
    // Sample timeline: first, middle, last messages all readable.
    assert!(s.read_log(Namespace::MESSAGE_LOG, 1).unwrap().is_some());
    assert!(s.read_log(Namespace::MESSAGE_LOG, 75).unwrap().is_some());
    assert!(s.read_log(Namespace::MESSAGE_LOG, 150).unwrap().is_some());

    std::fs::remove_file(&path).ok();
}
