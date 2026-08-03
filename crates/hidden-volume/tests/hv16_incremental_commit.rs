//! What a commit costs, and what it must still get right (audit HV-16).
//!
//! `commit_tx` used to materialise a namespace's whole tree on every
//! write. The disk cost of an edit was already the path to it (audit
//! HV-14), but the CPU and RAM were the namespace: writing 10⁶ entries
//! as 500 transactions cost 97 s and 2.9 GiB, against 1.6 s and 414 MiB
//! for the same data in one.
//!
//! It now descends to the affected leaf and rewrites only what the
//! change reaches. That is only possible because node boundaries are
//! decided from the entries' own hashes rather than by packing greedily
//! — otherwise inserting one entry shifts every boundary to its right
//! and there is nothing to descend to.
//!
//! The shape properties (one shape per key set, whatever order it was
//! written in; an edit reads the path and not the namespace) are pinned
//! in `src/space/tree.rs`, where the tree's actual shape and the chunk
//! reads are visible. What is left for here is everything a host-app
//! can see: that the data is right, that the container does not grow
//! with the number of transactions used to write it, and that a
//! one-key edit still costs a handful of chunks at any size.

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

/// The same content written in `batches` transactions must end up
/// indistinguishable from the same content written in one — same
/// entries, same tree size, same depth. Anything else and the number of
/// transactions a host-app happened to use would be recoverable from
/// the container.
#[test]
fn the_number_of_transactions_leaves_no_trace_in_the_tree() {
    fn build(n: usize, batches: usize, reverse: bool) -> (usize, usize, u8, Vec<Vec<u8>>) {
        let path = scratch();
        {
            let mut c = Container::create_with_options(&path, opts()).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            let per = n.div_ceil(batches);
            let order: Vec<usize> = if reverse {
                (0..batches).rev().collect()
            } else {
                (0..batches).collect()
            };
            for b in order {
                let mut tx = s.begin_tx();
                for i in (b * per)..((b * per + per).min(n)) {
                    tx.put(Namespace::CONTACTS, &key(i), &[b'v'; 96]).unwrap();
                }
                tx.commit().unwrap();
            }
        }
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        let report = s.verify_integrity().unwrap();
        let keys: Vec<Vec<u8>> = s
            .list(Namespace::CONTACTS)
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        let out = (
            s.count(Namespace::CONTACTS).unwrap(),
            report.chunks_verified,
            report.max_depth,
            keys,
        );
        drop(s);
        drop(c);
        let _ = std::fs::remove_file(&path);
        out
    }

    let n = 8_000;
    let one = build(n, 1, false);
    assert_eq!(one.0, n);
    assert!(one.2 >= 3, "fixture must be at least three levels deep");

    for (label, other) in [
        ("16 batches", build(n, 16, false)),
        ("16 batches, backwards", build(n, 16, true)),
        ("200 batches", build(n, 200, false)),
    ] {
        assert_eq!(other.0, one.0, "{label}: entry count");
        assert_eq!(other.3, one.3, "{label}: keys");
        assert_eq!(
            other.1, one.1,
            "{label}: a namespace written in pieces must have exactly as \
             many index chunks as one written in a single Tx"
        );
        assert_eq!(other.2, one.2, "{label}: tree depth");
    }
}

/// A one-key overwrite that does not change the value's length moves no
/// boundary at all, so it costs the Commit chunk, one Superblock
/// replica and exactly one index node per level — at any namespace size.
#[test]
fn a_one_key_edit_costs_the_path_at_every_size() {
    fn cost(n: usize, value_len: usize) -> (u64, u8) {
        let path = scratch();
        let appended = {
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
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert_eq!(
            s.get(Namespace::SETTINGS, &key(n / 2)).unwrap(),
            Some(vec![b'e'; value_len]),
            "the edited entry must survive a reopen (which vacuums)"
        );
        assert_eq!(s.count(Namespace::SETTINGS).unwrap(), n);
        let levels = s.verify_integrity().unwrap().max_depth;
        drop(s);
        drop(c);
        let _ = std::fs::remove_file(&path);
        (appended, levels)
    }

    for (n, value_len) in [(500usize, 64usize), (5_000, 64), (50_000, 64), (2_000, 512)] {
        let (appended, levels) = cost(n, value_len);
        assert_eq!(
            appended,
            2 + u64::from(levels),
            "n={n} vlen={value_len}: a one-key edit must append the \
             Commit chunk, a Superblock replica and one node per level \
             ({levels} levels), got {appended}"
        );
    }
}

/// The messenger's hot path. Appending at the high end of a log moves
/// no boundary below the last leaf, so the cost is the path and the
/// number of chunks read is the depth — however long the log is.
#[test]
fn appending_to_a_long_log_costs_the_same_as_appending_to_a_short_one() {
    fn cost(existing: usize) -> u64 {
        let path = scratch();
        let appended = {
            let mut c = Container::create_with_options(&path, opts()).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            for batch in 0..existing.div_ceil(200) {
                let mut tx = s.begin_tx();
                for id in (batch * 200 + 1)..=((batch * 200 + 200).min(existing)) {
                    tx.append_log(Namespace::MESSAGE_LOG, id as u64, &[b'm'; 200])
                        .unwrap();
                }
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
            Some(vec![b'm'; 200])
        );
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
        appended
    }

    let short = cost(400);
    let long = cost(20_000);
    assert!(
        long <= short + 1,
        "a 50x longer log may cost at most one more level for an append \
         (short={short} chunks, long={long})"
    );
}

/// Everything the incremental path can get wrong at once: inserts below
/// the smallest key, above the largest, into the middle of a leaf, over
/// leaf boundaries, deletes that empty a leaf entirely, and value
/// lengths that move boundaries. Read back through a fresh open, which
/// also vacuums — a node the update wrongly left unreferenced would be
/// scrubbed here and the read would fail.
#[test]
fn a_long_churn_of_edits_stays_correct() {
    let path = scratch();
    let mut expected: std::collections::BTreeMap<usize, Vec<u8>> =
        std::collections::BTreeMap::new();
    {
        let mut c = Container::create_with_options(&path, opts()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        let mut tx = s.begin_tx();
        for i in (1_000..6_000).step_by(2) {
            let v = vec![b'v'; 40];
            tx.put(Namespace::MEDIA, &key(i), &v).unwrap();
            expected.insert(i, v);
        }
        tx.commit().unwrap();

        for round in 0..24usize {
            let mut tx = s.begin_tx();
            // Below everything, above everything, and scattered through
            // the middle with a value length that shifts boundaries.
            let low = 500 - round;
            let high = 9_000 + round;
            let v = vec![b'a' + (round % 26) as u8; 20 + round * 37];
            tx.put(Namespace::MEDIA, &key(low), &v).unwrap();
            tx.put(Namespace::MEDIA, &key(high), &v).unwrap();
            expected.insert(low, v.clone());
            expected.insert(high, v.clone());
            for step in 0..12usize {
                let i = 1_000 + (round * 211 + step * 37) % 5_000;
                tx.put(Namespace::MEDIA, &key(i), &v).unwrap();
                expected.insert(i, v.clone());
            }
            tx.commit().unwrap();

            // Delete a contiguous run — enough to empty whole leaves.
            let mut tx = s.begin_tx();
            for i in (2_000 + round * 60)..(2_000 + round * 60 + 55) {
                tx.delete(Namespace::MEDIA, &key(i)).unwrap();
                expected.remove(&i);
            }
            tx.commit().unwrap();
        }
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let stored = s.list(Namespace::MEDIA).unwrap();
    let want: Vec<(Vec<u8>, Vec<u8>)> =
        expected.iter().map(|(i, v)| (key(*i), v.clone())).collect();
    assert_eq!(stored.len(), want.len(), "entry count after the churn");
    assert_eq!(stored, want, "every key and value after the churn");
    assert_eq!(s.count(Namespace::MEDIA).unwrap(), want.len());
    let report = s.verify_integrity().unwrap();
    assert_eq!(report.namespaces_verified, 1);
    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

/// Deleting a namespace down to nothing must drop it from the commit,
/// and re-filling it must build a fresh tree — the incremental path has
/// to hand back to the from-scratch one and vice versa.
#[test]
fn a_namespace_emptied_and_refilled_comes_back_clean() {
    let path = scratch();
    {
        let mut c = Container::create_with_options(&path, opts()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..3_000 {
            tx.put(Namespace::SETTINGS, &key(i), &[b'v'; 64]).unwrap();
        }
        tx.commit().unwrap();

        assert_eq!(s.erase_namespace(Namespace::SETTINGS).unwrap(), 3_000);
        assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 0);
        assert!(!s.list_namespaces().unwrap().contains(&Namespace::SETTINGS));

        let mut tx = s.begin_tx();
        for i in 0..1_500 {
            tx.put(Namespace::SETTINGS, &key(i), &[b'w'; 64]).unwrap();
        }
        tx.commit().unwrap();
    }
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 1_500);
    assert_eq!(
        s.get(Namespace::SETTINGS, &key(700)).unwrap(),
        Some(vec![b'w'; 64])
    );
    s.verify_integrity().unwrap();
    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

/// A Tx whose puts store the values already stored rebuilds the same
/// tree, and must not write a single index chunk for it (audit HV-14,
/// still true through the incremental path).
#[test]
fn rewriting_keys_with_their_current_values_writes_no_index_chunks() {
    let path = scratch();
    {
        let mut c = Container::create_with_options(&path, opts()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..4_000 {
            tx.put(Namespace::SETTINGS, &key(i), b"same").unwrap();
        }
        tx.commit().unwrap();

        let before = chunks(&path);
        let mut tx = s.begin_tx();
        for i in [17usize, 1_900, 3_999] {
            tx.put(Namespace::SETTINGS, &key(i), b"same").unwrap();
        }
        tx.commit().unwrap();
        assert_eq!(
            chunks(&path) - before,
            2,
            "a no-op edit may only cost the Commit chunk and one \
             Superblock replica"
        );
    }
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 4_000);
    s.verify_integrity().unwrap();
    drop(s);
    let _ = std::fs::remove_file(&path);
}
