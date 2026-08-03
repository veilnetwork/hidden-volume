//! What a namespace can hold (audit HV-15).
//!
//! The writer used to emit exactly two levels — a row of Leaves and one
//! Internal node above them — so a namespace could hold no more entries
//! than fit under a single root. Measured on this format, that ceiling
//! was 4 029 entries with 64-byte values, 553 with 512-byte values and
//! **79 with 2 048-byte values**; one more and the commit failed with
//! `Error::IndexFull`, with no way for a host-app to store the data at
//! all.
//!
//! The writer now grows a level whenever the level below outgrows a
//! single chunk, so the only remaining limit is the container's own
//! (`MAX_OPEN_SCAN_CHUNKS` → `Error::ContainerTooLarge`). These tests
//! pin that: the exact N that used to fail, sizes far past it, and the
//! properties that must survive the extra levels — everything reads
//! back through a fresh `Container::open` (which runs `vacuum_orphans`,
//! the one thing that would scrub a live node if the deeper tree
//! confused reachability), `verify_integrity` walks every link, and a
//! one-key edit still costs a handful of chunks rather than the whole
//! namespace (audit HV-14).

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

/// Seed `n` entries of `value_len` bytes, in Txs of at most 2 000 puts.
fn seed(space: &mut hidden_volume::space::Space<'_>, n: usize, value_len: usize) {
    let mut done = 0usize;
    while done < n {
        let upto = (done + 2000).min(n);
        let mut tx = space.begin_tx();
        for i in done..upto {
            tx.put(Namespace::SETTINGS, &key(i), &vec![b'v'; value_len])
                .unwrap();
        }
        tx.commit().unwrap();
        done = upto;
    }
}

/// The exact entry counts that used to fail. Each of these is the
/// measured `IndexFull` boundary + 1 for its value size — under the old
/// two-level writer every one of them was unstorable.
#[test]
fn the_entry_counts_that_used_to_be_unstorable_now_store() {
    for (value_len, n) in [(64usize, 4030usize), (512, 554), (2048, 80)] {
        let path = scratch();
        {
            let mut c = Container::create_with_options(&path, opts()).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            seed(&mut s, n, value_len);
        }
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert_eq!(
            s.count(Namespace::SETTINGS).unwrap(),
            n,
            "{n} entries of {value_len}-byte values must survive the reopen"
        );
        assert_eq!(
            s.get(Namespace::SETTINGS, &key(n - 1)).unwrap(),
            Some(vec![b'v'; value_len]),
            "the entry one past the old ceiling must be readable"
        );
        s.verify_integrity().unwrap();
        drop(s);
        drop(c);
        let _ = std::fs::remove_file(&path);
    }
}

/// Far past the old ceiling, and the whole namespace read back key by
/// key — not just counted. 2 048-byte values are the worst case for the
/// old shape (one entry per leaf), so 2 000 of them is 25× a ceiling
/// that used to be 79.
#[test]
fn a_namespace_far_past_the_old_ceiling_reads_back_entry_by_entry() {
    let path = scratch();
    let n = 2000usize;
    let value_len = 2048usize;
    {
        let mut c = Container::create_with_options(&path, opts()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        seed(&mut s, n, value_len);
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let report = s.verify_integrity().unwrap();
    assert!(
        report.max_depth >= 3,
        "this many 2 KiB values cannot fit under one internal root; the \
         writer must have grown a third level (got {} levels)",
        report.max_depth
    );
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), n);
    for i in 0..n {
        assert_eq!(
            s.get(Namespace::SETTINGS, &key(i)).unwrap(),
            Some(vec![b'v'; value_len]),
            "entry {i} of {n} must be readable through the deeper tree"
        );
    }
    // The other read path: a full listing must agree, in order.
    let listed = s.list(Namespace::SETTINGS).unwrap();
    assert_eq!(listed.len(), n);
    for (i, (k, _)) in listed.iter().enumerate() {
        assert_eq!(
            k,
            &key(i),
            "listing must stay globally sorted across levels"
        );
    }
    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

/// Four levels. "Teach the writer to emit a third level" would have
/// been a plausible half-fix — it moves the 2 KiB-value ceiling from 79
/// entries to ~6 200 and stops there. This test sits just past that
/// second wall, so nothing short of growing levels on demand passes it.
///
/// 2 048-byte values put exactly one entry in a leaf, which is the
/// cheapest way to buy leaves: 6 300 entries is 6 300 leaves, 80
/// internal nodes over them, 2 over those, and a root.
///
/// The one-key edit is measured here too, and not only in
/// [`one_key_edit_costs_one_chunk_per_level_not_one_per_leaf`]: a reuse
/// map that covered the top two levels instead of all of them would be
/// complete for a three-level tree and lose every leaf here.
#[test]
fn a_four_level_tree_is_built_and_read_back() {
    let path = scratch();
    let n = 6300usize;
    let value_len = 2048usize;
    let levels;
    {
        let mut c = Container::create_with_options(&path, opts()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        // One Tx: the point is the shape of the tree, not commit churn.
        let mut tx = s.begin_tx();
        for i in 0..n {
            tx.put(Namespace::SETTINGS, &key(i), &vec![b'v'; value_len])
                .unwrap();
        }
        tx.commit().unwrap();

        levels = s.verify_integrity().unwrap().max_depth;
        assert!(
            levels >= 4,
            "{n} × {value_len} B needs a fourth level; got {levels} — a \
             writer that emits a fixed number of levels would stop here"
        );

        let before = chunks(&path);
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, &key(n / 2), &vec![b'e'; value_len])
            .unwrap();
        tx.commit().unwrap();
        assert_eq!(
            chunks(&path) - before,
            2 + u64::from(levels),
            "a one-key edit four levels down must still be the Commit \
             chunk, one Superblock replica and one index node per level"
        );
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let report = s.verify_integrity().unwrap();
    assert_eq!(report.max_depth, levels);
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), n);
    assert_eq!(
        s.get(Namespace::SETTINGS, &key(n / 2)).unwrap(),
        Some(vec![b'e'; value_len]),
        "the edited entry must survive the reopen"
    );
    // Spot-check across the whole key space rather than all 6 300:
    // `count` and `verify_integrity` above already touched every node.
    for i in [0usize, 1, n / 79, n / 2 - 1, n / 2 + 1, n - 79, n - 1] {
        assert_eq!(
            s.get(Namespace::SETTINGS, &key(i)).unwrap(),
            Some(vec![b'v'; value_len]),
            "entry {i} must be reachable through four levels"
        );
    }
    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

/// A log namespace past the ~15 K unique-`log_id` cap the two-level
/// shape imposed, exercised through the paginating read paths rather
/// than `get`.
#[test]
fn a_log_namespace_scales_past_the_old_log_id_cap() {
    let path = scratch();
    let n = 20_000u64;
    {
        let mut c = Container::create_with_options(&path, opts()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut id = 1u64;
        while id <= n {
            let upto = (id + 999).min(n);
            let mut tx = s.begin_tx();
            for i in id..=upto {
                tx.append_log(Namespace::MESSAGE_LOG, i, format!("m{i}").as_bytes())
                    .unwrap();
            }
            tx.commit().unwrap();
            id = upto + 1;
        }
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let report = s.verify_integrity().unwrap();
    assert!(
        report.max_depth >= 3,
        "20 K log ids do not fit under one internal root (got {} levels)",
        report.max_depth
    );
    assert_eq!(s.count(Namespace::MESSAGE_LOG).unwrap(), n as usize);

    // Forward pagination must cross every leaf and every level.
    let mut seen = 0u64;
    let mut after = None;
    loop {
        let page = s
            .iter_log_after(Namespace::MESSAGE_LOG, after, 500)
            .unwrap();
        if page.is_empty() {
            break;
        }
        for (id, payload) in &page {
            seen += 1;
            assert_eq!(*id, seen, "forward pagination must not skip a log id");
            assert_eq!(payload, format!("m{id}").as_bytes());
        }
        after = page.last().map(|(id, _)| *id);
    }
    assert_eq!(seen, n, "forward pagination must reach every entry");

    // ...and the reverse walk, which descends children right-to-left.
    let newest = s.iter_log_before(Namespace::MESSAGE_LOG, None, 3).unwrap();
    assert_eq!(
        newest.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        vec![n, n - 1, n - 2]
    );
    assert_eq!(
        s.read_log(Namespace::MESSAGE_LOG, n / 2).unwrap(),
        Some(format!("m{}", n / 2).into_bytes())
    );
    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

/// The HV-14 property at depth. Rewriting one key must cost the path to
/// it — one node per level — and nothing else. The old reuse map only
/// held the root's own children, which is the whole tree at two levels
/// and one row out of many at three, so a half-lifted ceiling would
/// quietly re-append every leaf again.
#[test]
fn one_key_edit_costs_one_chunk_per_level_not_one_per_leaf() {
    fn cost_and_levels(n: usize, value_len: usize) -> (u64, u8) {
        let path = scratch();
        let out = {
            let mut c = Container::create_with_options(&path, opts()).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            seed(&mut s, n, value_len);
            let levels = s.verify_integrity().unwrap().max_depth;

            let before = chunks(&path);
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, &key(n / 2), &vec![b'e'; value_len])
                .unwrap();
            tx.commit().unwrap();
            (chunks(&path) - before, levels)
        };

        // The edit must survive the reopen — `open_space` vacuums orphan
        // IndexNode chunks, so a reused chunk wrongly classified as dead
        // would be scrubbed here.
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert_eq!(
            s.get(Namespace::SETTINGS, &key(n / 2)).unwrap(),
            Some(vec![b'e'; value_len])
        );
        assert_eq!(s.count(Namespace::SETTINGS).unwrap(), n);
        s.verify_integrity().unwrap();
        drop(s);
        drop(c);
        let _ = std::fs::remove_file(&path);
        out
    }

    // Two levels: the shape the old writer could also produce.
    let (shallow_cost, shallow_levels) = cost_and_levels(1000, 64);
    // Three: only reachable now, and 8x the entries.
    let (deep_cost, deep_levels) = cost_and_levels(8000, 512);
    assert_eq!(shallow_levels, 2, "1 000 × 64 B is a two-level tree");
    assert!(
        deep_levels >= 3,
        "8 000 × 512 B must have grown past two levels (got {deep_levels})"
    );

    // The floor is 2 — the Commit chunk and one Superblock replica.
    for (cost, levels, what) in [
        (shallow_cost, shallow_levels, "two-level"),
        (deep_cost, deep_levels, "deeper"),
    ] {
        assert_eq!(
            cost,
            2 + u64::from(levels),
            "a one-key edit in the {what} namespace must append the Commit \
             chunk, one Superblock replica and exactly one index node per \
             level ({levels}) — got {cost} chunks"
        );
    }
}

/// Levels are not a ratchet: deleting back down must collapse them
/// again, or a namespace that once peaked keeps paying for depth it no
/// longer needs. This is the merge half of split/merge.
#[test]
fn deleting_back_down_collapses_the_levels_again() {
    let path = scratch();
    let n = 1200usize;
    let value_len = 2048usize;
    let peak_levels;
    {
        let mut c = Container::create_with_options(&path, opts()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        seed(&mut s, n, value_len);
        peak_levels = s.verify_integrity().unwrap().max_depth;
        assert!(peak_levels >= 3, "expected a deep tree, got {peak_levels}");

        // Drop all but 20 entries, in Txs the writer must re-pack.
        let mut done = 20usize;
        while done < n {
            let upto = (done + 500).min(n);
            let mut tx = s.begin_tx();
            for i in done..upto {
                tx.delete(Namespace::SETTINGS, &key(i)).unwrap();
            }
            tx.commit().unwrap();
            done = upto;
        }
        let after = s.verify_integrity().unwrap().max_depth;
        assert!(
            after < peak_levels,
            "20 entries must not still need {peak_levels} levels (got {after})"
        );
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 20);
    for i in 0..20 {
        assert_eq!(
            s.get(Namespace::SETTINGS, &key(i)).unwrap(),
            Some(vec![b'v'; value_len]),
            "entry {i} must survive the collapse"
        );
    }
    assert_eq!(s.get(Namespace::SETTINGS, &key(500)).unwrap(), None);
    s.verify_integrity().unwrap();
    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

/// Churn across levels: repeated grow/shrink cycles around the point
/// where a level is added, with a full read-back. A boundary that is
/// crossed in both directions is where an off-by-one in the packing
/// (a level built over the wrong row, a root left pointing at a
/// superseded node) shows up.
#[test]
fn growing_and_shrinking_across_a_level_boundary_stays_consistent() {
    let path = scratch();
    let value_len = 2048usize;
    // 79 entries is the old ceiling — exactly where the second level
    // used to give out, and where the third now starts.
    let low = 60usize;
    let high = 200usize;
    {
        let mut c = Container::create_with_options(&path, opts()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        // The survivors: present throughout, so every round's packing
        // has to place them again.
        let mut tx = s.begin_tx();
        for i in 0..low {
            tx.put(Namespace::CONTACTS, &key(i), &vec![b'z'; value_len])
                .unwrap();
        }
        tx.commit().unwrap();

        for round in 0..4u8 {
            let mut tx = s.begin_tx();
            for i in low..high {
                tx.put(Namespace::CONTACTS, &key(i), &vec![b'a' + round; value_len])
                    .unwrap();
            }
            tx.commit().unwrap();
            assert_eq!(s.count(Namespace::CONTACTS).unwrap(), high);

            let mut tx = s.begin_tx();
            for i in low..high {
                tx.delete(Namespace::CONTACTS, &key(i)).unwrap();
            }
            tx.commit().unwrap();
            assert_eq!(s.count(Namespace::CONTACTS).unwrap(), low);
        }
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), low);
    for i in 0..low {
        assert_eq!(
            s.get(Namespace::CONTACTS, &key(i)).unwrap(),
            Some(vec![b'z'; value_len]),
            "entry {i} must survive four grow/shrink rounds"
        );
    }
    let report = s.verify_integrity().unwrap();
    assert_eq!(report.namespaces_verified, 1);
    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}
