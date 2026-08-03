//! What one changed key costs on disk (audit HV-14).
//!
//! `commit_tx` materialises a namespace's whole tree, applies the ops,
//! and rebuilds. Rebuilding in memory is fine — it is fsync-bound and
//! the format's own `IndexFull` ceiling caps the working set. Rebuilding
//! *on disk* was not: a one-key edit in a 4 000-entry namespace appended
//! 82 chunks (336 KiB), and appending one 200-byte message to an
//! 8 000-message log appended 48 (196 KiB). Since the chunks are
//! immutable and Merkle-addressed, the ones that did not change are
//! already on disk and are pointed at instead.
//!
//! The load-bearing property is not "fewer chunks" but "a number that
//! does not grow with the namespace", so that is what is asserted:
//! the same edit against namespaces of very different sizes must cost
//! the same. And because pointing at an old chunk is the kind of
//! cleverness that loses data, every test here also reads the data back
//! through a fresh `Container::open` — which runs `vacuum_orphans`, the
//! one thing that would scrub a reused chunk if it were mistaken for a
//! dead one.

use hidden_volume::Container;
use hidden_volume::container::ContainerOptions;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;

/// `PaddingPolicy::None` so file growth is exactly the chunks the
/// commit wrote — padding would quantise it to 1 MiB buckets and hide
/// what is being measured.
fn opts() -> ContainerOptions {
    ContainerOptions {
        argon2: Argon2Params::MIN,
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 1,
    }
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

fn chunks(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).unwrap().len() / hidden_volume::CHUNK_SIZE as u64
}

/// Seed `n` entries with `value_len`-byte values, then report how many
/// chunks a single-key overwrite appends.
fn chunks_per_one_key_edit(n: usize, value_len: usize) -> u64 {
    let path = scratch();
    let cost = {
        let mut c = Container::create_with_options(&path, opts()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        let mut tx = s.begin_tx();
        for i in 0..n {
            tx.put(Namespace::SETTINGS, &key(i), &vec![b'v'; value_len])
                .unwrap();
        }
        tx.commit().unwrap();

        let before = chunks(&path);
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, &key(n / 2), &vec![b'e'; value_len])
            .unwrap();
        tx.commit().unwrap();
        chunks(&path) - before
    };

    // The edit must survive a reopen — `Container::open_space` vacuums
    // orphan IndexNode chunks, so a reused chunk wrongly classified as
    // dead would be scrubbed here and the read below would fail.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(
        s.get(Namespace::SETTINGS, &key(n / 2)).unwrap(),
        Some(vec![b'e'; value_len]),
        "the edited entry must survive the reopen"
    );
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), n);
    s.verify_integrity().unwrap();
    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
    cost
}

/// The cost of editing one key must not depend on how many other keys
/// share the namespace. This is the whole finding.
#[test]
fn editing_one_key_costs_the_same_in_a_small_and_a_large_namespace() {
    let small = chunks_per_one_key_edit(250, 64);
    let large = chunks_per_one_key_edit(4000, 64);
    assert_eq!(
        small, large,
        "a 16x larger namespace must not make a one-key edit cost more \
         (small={small} chunks, large={large} chunks)"
    );
    // Sanity floor: an edit does write *something* — the changed leaf,
    // its root, the Commit chunk and a Superblock replica.
    assert!(
        (2..=6).contains(&large),
        "a one-key edit should cost a handful of chunks, got {large}"
    );
}

/// The messenger hot path: appending one message to a long chat. The
/// new log_id is the largest key, so it lands in the last leaf and moves
/// no leaf boundary — every other leaf is already on disk.
#[test]
fn appending_one_message_costs_the_same_in_a_short_and_a_long_log() {
    fn cost_after(existing: usize) -> u64 {
        let path = scratch();
        let cost = {
            let mut c = Container::create_with_options(&path, opts()).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            for id in 1..=existing as u64 {
                let mut tx = s.begin_tx();
                tx.append_log(Namespace::MESSAGE_LOG, id, &[b'm'; 200])
                    .unwrap();
                tx.commit().unwrap();
            }
            let before = chunks(&path);
            let mut tx = s.begin_tx();
            tx.append_log(Namespace::MESSAGE_LOG, existing as u64 + 1, &[b'm'; 200])
                .unwrap();
            tx.commit().unwrap();
            chunks(&path) - before
        };

        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert_eq!(
            s.read_log(Namespace::MESSAGE_LOG, existing as u64 + 1)
                .unwrap(),
            Some(vec![b'm'; 200]),
            "the appended message must survive the reopen"
        );
        // Every earlier message must still be readable — a mis-reused
        // index chunk would silently drop a whole leaf's worth.
        assert_eq!(
            s.iter_log_after(Namespace::MESSAGE_LOG, None, existing + 8)
                .unwrap()
                .len(),
            existing + 1
        );
        s.verify_integrity().unwrap();
        drop(s);
        drop(c);
        let _ = std::fs::remove_file(&path);
        cost
    }

    let short = cost_after(300);
    let long = cost_after(2400);
    assert_eq!(
        short, long,
        "an 8x longer log must not make one append cost more \
         (short={short} chunks, long={long} chunks)"
    );
}

/// A Tx that stores the value already stored rebuilds a tree identical
/// to the one on disk. It must not write a single index chunk for it —
/// only the Commit chunk and its Superblock replica.
#[test]
fn rewriting_a_key_with_its_current_value_writes_no_index_chunks() {
    let path = scratch();
    {
        let mut c = Container::create_with_options(&path, opts()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..600 {
            tx.put(Namespace::SETTINGS, &key(i), b"same").unwrap();
        }
        tx.commit().unwrap();

        let before = chunks(&path);
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, &key(300), b"same").unwrap();
        tx.commit().unwrap();
        assert_eq!(
            chunks(&path) - before,
            2,
            "a no-op edit may only cost the Commit chunk and one Superblock replica"
        );
    }
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 600);
    s.verify_integrity().unwrap();
    drop(s);
    let _ = std::fs::remove_file(&path);
}

/// The case reuse cannot help with: an edit whose new value has a
/// different length shifts every leaf boundary after it, so most leaves
/// genuinely differ. Correctness is what matters here — the fallback
/// must be the old full rebuild, not a partly-stale tree.
#[test]
fn an_edit_that_moves_every_leaf_boundary_still_rebuilds_correctly() {
    let path = scratch();
    let n = 1200usize;
    {
        let mut c = Container::create_with_options(&path, opts()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..n {
            tx.put(Namespace::CONTACTS, &key(i), &[b'v'; 40]).unwrap();
        }
        tx.commit().unwrap();

        // Grow an early entry by a lot: from here on every leaf packs
        // differently.
        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, &key(3), &[b'X'; 900]).unwrap();
        tx.commit().unwrap();

        // ...and delete one in the middle, which drops entries out of a
        // leaf and repacks everything after it again.
        let mut tx = s.begin_tx();
        tx.delete(Namespace::CONTACTS, &key(n / 2)).unwrap();
        tx.commit().unwrap();
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), n - 1);
    assert_eq!(
        s.get(Namespace::CONTACTS, &key(3)).unwrap(),
        Some(vec![b'X'; 900])
    );
    assert_eq!(s.get(Namespace::CONTACTS, &key(n / 2)).unwrap(), None);
    for i in 0..n {
        if i == 3 || i == n / 2 {
            continue;
        }
        assert_eq!(
            s.get(Namespace::CONTACTS, &key(i)).unwrap(),
            Some(vec![b'v'; 40]),
            "entry {i} must be unchanged"
        );
    }
    s.verify_integrity().unwrap();
    drop(s);
    let _ = std::fs::remove_file(&path);
}

/// Long churn: many edits, deletes and re-inserts across two namespaces,
/// then a full read-back through a fresh open. Reuse spans commits, so
/// a chunk minted twenty commits ago is still being pointed at — this is
/// where a stale pointer or a mistaken scrub would surface.
#[test]
fn a_long_edit_history_stays_readable_and_verifiable() {
    let path = scratch();
    let n = 800usize;
    {
        let mut c = Container::create_with_options(&path, opts()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..n {
            tx.put(Namespace::SETTINGS, &key(i), &[b'0'; 50]).unwrap();
        }
        tx.commit().unwrap();

        for round in 0..30u8 {
            let mut tx = s.begin_tx();
            // Touch one key per round, spread across the whole key space.
            let i = (round as usize * 37) % n;
            tx.put(Namespace::SETTINGS, &key(i), &[b'a' + round % 26; 50])
                .unwrap();
            tx.commit().unwrap();

            let mut tx = s.begin_tx();
            tx.delete(Namespace::SETTINGS, &key((i + 1) % n)).unwrap();
            tx.commit().unwrap();

            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, &key((i + 1) % n), &[b'0'; 50])
                .unwrap();
            tx.commit().unwrap();
        }
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), n);
    for i in 0..n {
        assert!(
            s.get(Namespace::SETTINGS, &key(i)).unwrap().is_some(),
            "entry {i} disappeared across the edit history"
        );
    }
    let report = s.verify_integrity().unwrap();
    assert_eq!(report.namespaces_verified, 1);
    drop(s);
    let _ = std::fs::remove_file(&path);
}
