//! Slot reuse + decoy churn (DESIGN §9.1).
//!
//! In-crate rather than under `tests/`: what these assert — which slot a
//! chunk landed in, what the pool holds, whether the churn ran — is not
//! observable through the public API, and a test that could only see the
//! public surface would pass against a writer that quietly stopped
//! reusing.
//!
//! The prohibition these tests replace was load-bearing, so what they
//! guard is not "reuse happens" but the three things that make reuse
//! safe to have happened:
//!
//! 1. a reused slot never carries data any recoverable era still needs
//!    — crash recovery is unchanged;
//! 2. the pool never names a slot that is live — the accounting cannot
//!    drift into data loss;
//! 3. a reused slot and a churned decoy are the same kind of event on
//!    disk — the distinguisher the prohibition existed to prevent does
//!    not come back through the churn.

use crate::container::ContainerOptions;
use crate::crypto::kdf::Argon2Params;
use crate::padding::PaddingPolicy;
use crate::space::index::Namespace;
use crate::{Container, Error, Space};

fn scratch() -> std::path::PathBuf {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let p = tmp.path().to_owned();
    drop(tmp);
    p
}

struct Cleanup(std::path::PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn options(initial_garbage: u64, padding: PaddingPolicy) -> ContainerOptions {
    ContainerOptions {
        argon2: Argon2Params::MIN,
        initial_garbage_chunks: initial_garbage,
        padding_policy: padding,
        superblock_replicas: 1,
    }
}

/// Chunk-granular snapshot of the file, for offset-level diffing.
fn slots(path: &std::path::Path) -> Vec<Vec<u8>> {
    let bytes = std::fs::read(path).unwrap();
    bytes.chunks(4096).skip(1).map(<[u8]>::to_vec).collect()
}

/// Indices where two snapshots differ.
fn changed(a: &[Vec<u8>], b: &[Vec<u8>]) -> Vec<usize> {
    (0..a.len().min(b.len()))
        .filter(|&i| a[i] != b[i])
        .collect()
}

/// Drive a space until it has retired enough slots to have a pool, and
/// leave the file closed with that pool recorded in a checkpoint.
///
/// Every commit here supersedes the previous KV index, so the orphan
/// IndexNode chunks accumulate and the auto-vacuum on the next open
/// retires them.
fn build_with_pool(path: &std::path::Path, keys: u32) {
    let mut c = Container::create_with_options(path, options(0, PaddingPolicy::None)).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    for i in 0..keys {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, format!("k{i}").as_bytes(), b"v")
            .unwrap();
        tx.commit().unwrap();
    }
    // Retire the orphans and record the resulting pool. Forced rather
    // than waiting for the size threshold so the fixture stays small.
    s.vacuum_orphans().unwrap();
    s.write_self_heal_checkpoint().unwrap();
}

/// THE property the slot-reuse prohibition was protecting: a container
/// that reuses slots must still come back after a crash.
///
/// Reuse is only safe because a pool slot is one `vacuum_orphans` has
/// already proved unreachable from the era on disk. If that proof were
/// ever wrong — if reuse could land on a chunk a recoverable superblock
/// still points at — the failure would look exactly like this test
/// failing: the file reopens on an era whose tree has a hole in it.
#[test]
fn a_container_that_reuses_slots_still_reopens_with_every_value() {
    let path = scratch();
    let _c = Cleanup(path.clone());
    build_with_pool(&path, 40);

    // Reopen: the pool comes back from the checkpoint, and these commits
    // are the ones that reuse.
    let reused;
    {
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert!(
            s.stats().unwrap().reusable_slot_count > 0,
            "fixture must hand this test a non-empty pool, or it proves nothing"
        );
        for i in 0..40u32 {
            let mut tx = s.begin_tx();
            tx.put(
                Namespace::SETTINGS,
                format!("k{i}").as_bytes(),
                format!("second-{i}").as_bytes(),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        reused = s.state.reuse_count;
        assert!(reused > 0, "no slot was reused, so nothing here is tested");
    }

    // The reopen is the assertion. Every value must be the second one,
    // and nothing may be missing.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    for i in 0..40u32 {
        assert_eq!(
            s.get(Namespace::SETTINGS, format!("k{i}").as_bytes())
                .unwrap()
                .as_deref(),
            Some(format!("second-{i}").as_bytes()),
            "k{i} did not survive a container that reused {reused} slots"
        );
    }
    s.verify_integrity()
        .expect("the tree a reusing writer left must verify");
}

/// The accounting invariant, stated where it can actually fail: no slot
/// is ever in the pool and owned at the same time.
///
/// A slot in both is a live chunk offered to the allocator, which is
/// data loss on the next commit and is precisely what "the free-slot
/// counter drifted from reality" means here. Checked across a workload
/// that exercises every path a slot can take into or out of the pool —
/// commit, vacuum, reuse, churn, checkpoint refresh — and after the
/// reopen that rebuilds the pool from disk.
#[test]
fn no_slot_is_ever_both_pooled_and_owned() {
    let path = scratch();
    let _c = Cleanup(path.clone());
    build_with_pool(&path, 30);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    for round in 0..12u32 {
        for i in 0..10u32 {
            let mut tx = s.begin_tx();
            tx.put(
                Namespace::SETTINGS,
                format!("k{i}").as_bytes(),
                format!("r{round}").as_bytes(),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        s.vacuum_orphans().unwrap();
        let (owned, pool) = (s.state.owned_slots.clone(), s.state.pool.sorted());
        let owned_set: std::collections::BTreeSet<u64> = owned.iter().copied().collect();
        let overlap: Vec<u64> = pool
            .iter()
            .copied()
            .filter(|s| owned_set.contains(s))
            .collect();
        assert!(
            overlap.is_empty(),
            "round {round}: slots {overlap:?} are in the pool AND owned — the \
             allocator may hand out live data"
        );
    }
    drop(s);
    drop(c);

    // And after the pool is rebuilt from disk, where the subtraction of
    // the scan's owned set is the only thing keeping them apart.
    let mut c = Container::open(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    let (owned, pool) = (s.state.owned_slots.clone(), s.state.pool.sorted());
    let owned_set: std::collections::BTreeSet<u64> = owned.iter().copied().collect();
    let overlap: Vec<u64> = pool
        .iter()
        .copied()
        .filter(|s| owned_set.contains(s))
        .collect();
    assert!(
        overlap.is_empty(),
        "after reopen: slots {overlap:?} are in the pool AND owned"
    );
}

/// A stale recorded pool must not hand out a slot that has since gone
/// live.
///
/// The checkpoint is refreshed lazily, so a recorded pool routinely
/// names slots a later commit already reused. This drives that state
/// directly — record a pool, consume from it without refreshing the
/// checkpoint, reopen — and asserts the reopened pool has dropped every
/// slot that came back as owned. Without the subtraction in
/// `finalize_scan_at` this is the shape that loses data.
#[test]
fn a_stale_recorded_pool_drops_the_slots_that_went_live() {
    let path = scratch();
    let _c = Cleanup(path.clone());
    // A pool deliberately much larger than the consuming commits below
    // will drain. Sized at 40 keys the pool ran dry, the reopened pool
    // came back EMPTY, and this test then agreed with any build at all —
    // including one whose fast open never looked at the pool slots. A
    // vacuous pass is the failure mode this fixture exists to avoid, so
    // the leftovers are asserted rather than assumed.
    build_with_pool(&path, 120);

    let consumed: Vec<u64>;
    {
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        let before = s.state.pool.sorted();
        // Commits only — no vacuum, no checkpoint refresh — so the
        // on-disk pool record keeps naming what these commits consume.
        for i in 0..5u32 {
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, format!("n{i}").as_bytes(), b"v")
                .unwrap();
            tx.commit().unwrap();
        }
        let after = s.state.pool.sorted();
        let after_set: std::collections::BTreeSet<u64> = after.iter().copied().collect();
        consumed = before
            .into_iter()
            .filter(|s| !after_set.contains(s))
            .collect();
        assert!(
            !consumed.is_empty(),
            "the fixture consumed nothing from the pool, so staleness is untested"
        );
    }

    // Read-only, so the auto-vacuum does NOT run. That matters: a
    // writable reopen retires those same slots again the moment it
    // vacuums, and they legitimately come back to the pool — which would
    // make this test pass on a build with no subtraction at all. What is
    // under test is the state `finalize_scan_at` hands back, before any
    // maintenance has had a chance to be right by accident.
    crate::open::test_hooks::set_disable(false);
    crate::open::test_hooks::reset_hits();
    let mut c = Container::open_readonly(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    assert!(
        crate::open::test_hooks::hits() >= 1,
        "the reopen took the full scan, which recovers no pool at all — this \
         test only says anything about the checkpoint-driven path"
    );
    let pool = s.state.pool.sorted();
    assert!(
        pool.len() > consumed.len(),
        "the recorded pool ({}) did not outlast what the commits consumed \
         ({}), so an empty result would satisfy the assertion below",
        pool.len(),
        consumed.len()
    );
    let pool_set: std::collections::BTreeSet<u64> = pool.iter().copied().collect();
    let still_offered: Vec<u64> = consumed
        .iter()
        .copied()
        .filter(|s| pool_set.contains(s))
        .collect();
    assert!(
        still_offered.is_empty(),
        "the recorded pool still offers slots {still_offered:?} that a later \
         commit wrote to — the next allocation overwrites live data"
    );
}

/// Exactly how much of the per-commit growth reuse takes away — and,
/// just as much, how much it does NOT.
///
/// A commit writes three kinds of chunk: the rebuilt `IndexNode` path,
/// one `Commit` chunk, and `superblock_replicas` `Superblock` chunks.
/// Reuse recycles the first kind and only the first kind, because
/// `vacuum_orphans` retires `IndexNode` / `DataBatch` chunks and
/// deliberately leaves superseded `Commit` and `Superblock` chunks
/// alone — they are the crash-recovery fallbacks and the
/// `commit_history` anchors. So the steady state is
/// `1 + replicas` appended per commit, not zero.
///
/// Pinned with literals at `replicas = 1`, where the arithmetic has no
/// slack to hide in: 24 commits must append 48 slots (one Commit and one
/// Superblock each) and reuse at least 24. Append-only, the same 24
/// commits appended 72. A regression that stopped reusing lands on 72
/// and a regression that reused a slot it should not lands below 48.
#[test]
fn reuse_recycles_the_index_tree_and_nothing_else() {
    let path = scratch();
    let _c = Cleanup(path.clone());
    build_with_pool(&path, 24);

    let mut c = Container::open(&path).unwrap();
    // `Container::open` resets this to the default 3; the numbers below
    // are stated for one replica, so say so rather than inherit it.
    c.set_superblock_replicas(1).unwrap();
    let mut s = c.open_space(b"pw").unwrap();

    // Settle: one sweep to reach the steady state (the pool starts
    // over-full from the fixture's vacuum).
    for i in 0..24u32 {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, format!("k{i}").as_bytes(), b"a")
            .unwrap();
        tx.commit().unwrap();
        s.vacuum_orphans().unwrap();
    }

    let before_slots = s.file.slot_count();
    let before_reuse = s.state.reuse_count;
    for i in 0..24u32 {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, format!("k{i}").as_bytes(), b"b")
            .unwrap();
        tx.commit().unwrap();
        s.vacuum_orphans().unwrap();
    }
    let grew = s.file.slot_count() - before_slots;
    let reused = s.state.reuse_count - before_reuse;

    assert!(
        reused >= 24,
        "24 commits reused only {reused} slots — the index path is being \
         appended, not recycled"
    );
    assert_eq!(
        grew, 48,
        "24 commits appended {grew} slots; 48 is one Commit plus one \
         Superblock each, and 72 is what append-only cost"
    );
}

/// Same as [`build_with_pool`], but under a padding policy that actually
/// appends — the only fixture in which the post-commit padding step runs at
/// all, and therefore the only one in which it can be made to fail.
fn build_with_pool_and_padding(path: &std::path::Path, keys: u32) {
    let mut c = Container::create_with_options(
        path,
        options(0, PaddingPolicy::BucketGrowth { bucket_chunks: 64 }),
    )
    .unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    for i in 0..keys {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, format!("k{i}").as_bytes(), b"v")
            .unwrap();
        tx.commit().unwrap();
    }
    s.vacuum_orphans().unwrap();
    s.write_self_heal_checkpoint().unwrap();
}

/// Churn must survive a padding failure, because the commit does.
///
/// `commit_tx` publishes the superblock BEFORE it pads, and it deliberately
/// does not fail afterwards (audit pass 18) — the data is durable, so a late
/// error would be a lie. Both post-commit obligations therefore run on a
/// commit that has already happened, and they used to run as one `and_then`
/// chain: padding first, churn inside it. A padding failure skipped the churn
/// silently and `commit_tx` still returned `Ok`.
///
/// What that leaves on disk is precisely the snapshot pair §9.1 exists to
/// deny: real writes landed in reused slots, no decoy moved, so every offset
/// that changed below the tail holds live data. And padding fails on a full
/// disk — an adversary who can fill one can ask for that pair.
#[test]
fn a_padding_failure_does_not_cost_the_commit_its_churn() {
    let path = scratch();
    let _c = Cleanup(path.clone());
    build_with_pool_and_padding(&path, 40);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let pool = s.stats().unwrap().reusable_slot_count;
    assert!(pool >= 4, "fixture pool too small: {pool}");

    let seq = {
        let _fault = crate::container::file::ForcedGarbageAppendFailure::arm();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k0", b"changed").unwrap();
        // The commit is durable before padding is even attempted, so this
        // must still be Ok — the audit-pass-18 invariant.
        tx.commit().unwrap()
    };
    assert!(seq > 0, "commit returned no sequence");

    // NOT vacuous: if the arm had missed — a policy that padded zero chunks,
    // a path that never reached `append_garbage_chunks` — there would be no
    // padding failure to survive, and everything below would pass on a commit
    // that was never in the state under test.
    assert!(
        s.state.last_padding_error.is_some(),
        "the padding fault never fired, so this test proves nothing"
    );

    let reused = s.state.reuse_count;
    let churned = s.state.churn_count;
    assert!(reused > 0, "the commit appended instead of reusing");
    assert_eq!(
        churned, reused,
        "padding failed and took the churn with it: {reused} slots reused, \
         {churned} decoys churned"
    );
}

/// A pool too small to fund the churn must bound the reuse, not the churn.
///
/// Reuse and churn draw from the SAME pool, and reuse goes first: it `take`s
/// slots out, the churn then samples what is left. `sample_distinct` returns
/// `n.min(len)` — it truncates in silence — so a commit that reused the pool
/// down to nothing churned nothing, `commit_tx` returned `Ok`, and
/// `churn_count` simply stopped tracking `reuse_count` with nothing to say so.
///
/// The end state is the same disk the padding-failure case leaves: real writes
/// in reused slots, no decoy moved, every changed offset below the tail live.
/// A small pool is not an exotic condition either — it is what a container has
/// right after its first `vacuum_orphans`.
///
/// So the budget is reserved before the reuse: a commit reuses at most the
/// share of the pool whose churn the rest can still fund, and appends past
/// that. Growing the file slightly is the cost; DESIGN §9.1 already prices it
/// ("the anonymity set for a reused slot is the pool, not the file").
#[test]
fn a_small_pool_bounds_the_reuse_and_not_the_churn() {
    let path = scratch();
    let _c = Cleanup(path.clone());
    build_with_pool(&path, 40);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();

    // Starve the pool down to two slots. Taken rather than staged by a
    // smaller fixture so the size is exact: at two, one reuse is fundable
    // and a second is not, which is the boundary the budget has to find.
    while s.state.pool.len() > 2 {
        s.state.pool.take().unwrap().unwrap();
    }
    assert_eq!(s.state.pool.len(), 2);

    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"k0", b"changed").unwrap();
    tx.commit().unwrap();

    let reused = s.state.reuse_count;
    let churned = s.state.churn_count;
    // Not vacuous: a budget that simply banned reuse on a small pool would
    // satisfy the equality below while giving up the feature entirely.
    assert!(
        reused > 0,
        "the budget stopped reuse altogether on a pool of two"
    );
    assert_eq!(
        churned, reused,
        "the pool could not fund the churn and the reuse went ahead anyway: \
         {reused} slots reused, {churned} decoys churned"
    );
}

/// The invariant behind both of the cases above, guarded structurally: after
/// every write this space can be asked to do, the churn matches the reuse.
///
/// The two cases each found one way to break it — a padding failure that took
/// the churn with it, a pool too small to fund one — and a third was sitting
/// in `write_self_heal_checkpoint`, which reused pool slots for its Superblock
/// replicas while `commit_tx` remained the only caller of `churn_decoys`. All
/// three leave the same disk. Rather than add a fourth test the next time,
/// this one drives a mixed workload and checks the equality after every step,
/// so any new path that reuses without churning fails here whether or not
/// anyone thought to test it.
#[test]
fn every_write_path_churns_what_it_reuses() {
    let path = scratch();
    let _c = Cleanup(path.clone());
    build_with_pool(&path, 40);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();

    let check = |s: &Space<'_>, step: &str| {
        assert_eq!(
            s.state.churn_count, s.state.reuse_count,
            "after {step}: {} slots reused, {} decoys churned",
            s.state.reuse_count, s.state.churn_count
        );
    };

    for round in 0..6 {
        for i in 0..4 {
            let mut tx = s.begin_tx();
            tx.put(
                Namespace::SETTINGS,
                format!("r{round}k{i}").as_bytes(),
                b"v",
            )
            .unwrap();
            tx.commit().unwrap();
            check(&s, &format!("commit r{round}i{i}"));
        }
        s.vacuum_orphans().unwrap();
        check(&s, &format!("vacuum_orphans r{round}"));
        s.write_self_heal_checkpoint().unwrap();
        check(&s, &format!("checkpoint r{round}"));
    }

    // Non-vacuous: an equality between two counters that both stayed at zero
    // would hold against a writer that stopped reusing entirely.
    assert!(
        s.state.reuse_count > 0,
        "nothing was reused, so the equality proves nothing"
    );
}

/// The distinguisher the prohibition existed to prevent, checked as an
/// observation rather than as an implementation detail.
///
/// A T2' adversary diffs snapshots and asks, of each offset that
/// changed: does this hold real data? The answer must not be readable
/// off the offset. So a commit that reuses slots must dirty offsets that
/// do NOT hold real data too — and the churn is what puts them there.
/// Without it, every changed offset below the tail is a live chunk and
/// the diff is a map of the space's contents.
#[test]
fn a_commit_that_reuses_slots_also_dirties_decoys() {
    let path = scratch();
    let _c = Cleanup(path.clone());
    build_with_pool(&path, 40);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // A pool with room for both jobs at once; otherwise "churn happened"
    // and "reuse happened" cannot be told apart by counting.
    let pool = s.stats().unwrap().reusable_slot_count;
    assert!(
        pool >= 4,
        "fixture pool too small to observe the split: {pool}"
    );

    let before = slots(&path);
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"k0", b"changed").unwrap();
    tx.commit().unwrap();
    let reused = s.state.reuse_count;
    let churned = s.state.churn_count;
    // Drop the handle so the file on disk is whole before diffing.
    drop(s);
    drop(c);
    let after = slots(&path);

    assert!(reused > 0, "the commit appended instead of reusing");
    assert_eq!(
        churned, reused,
        "the churn must match the reuse one-for-one: {reused} reused, \
         {churned} churned"
    );

    let dirty = changed(&before, &after);
    assert!(
        dirty.len() >= 2 * reused as usize,
        "a commit that reused {reused} slots dirtied only {} offsets — there \
         are not enough decoys among them for the real writes to hide in",
        dirty.len()
    );

    // And the churned offsets must be indistinguishable from the reused
    // ones by size: every dirty offset is one whole chunk.
    for i in &dirty {
        assert_eq!(after[*i].len(), 4096, "offset {i} is not a whole chunk");
    }
}

/// Churn must not touch a slot that is not this space's to touch.
///
/// The pool is the only thing standing between the churn and another
/// hidden space's data: a writer cannot tell garbage from a foreign
/// chunk by looking. Two spaces in one container, one of them idle —
/// the idle one's chunks must come back byte-for-byte after the other
/// has reused and churned for a while.
#[test]
fn churn_never_touches_another_spaces_chunks() {
    let path = scratch();
    let _c = Cleanup(path.clone());

    // Space B writes first and then goes quiet; space A does the work.
    {
        let mut c = Container::create_with_options(&path, options(0, PaddingPolicy::None)).unwrap();
        let mut b = c.create_space(b"pw-b").unwrap();
        for i in 0..12u32 {
            let mut tx = b.begin_tx();
            tx.put(
                Namespace::SETTINGS,
                format!("b{i}").as_bytes(),
                format!("value-b-{i}").as_bytes(),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        drop(b);
        let mut a = c.create_space(b"pw-a").unwrap();
        for i in 0..40u32 {
            let mut tx = a.begin_tx();
            tx.put(Namespace::SETTINGS, format!("a{i}").as_bytes(), b"v")
                .unwrap();
            tx.commit().unwrap();
        }
        a.vacuum_orphans().unwrap();
        a.write_self_heal_checkpoint().unwrap();
    }

    {
        let mut c = Container::open(&path).unwrap();
        let mut a = c.open_space(b"pw-a").unwrap();
        for round in 0..8u32 {
            for i in 0..20u32 {
                let mut tx = a.begin_tx();
                tx.put(
                    Namespace::SETTINGS,
                    format!("a{i}").as_bytes(),
                    format!("r{round}").as_bytes(),
                )
                .unwrap();
                tx.commit().unwrap();
            }
            a.vacuum_orphans().unwrap();
        }
        assert!(
            a.state.reuse_count > 0,
            "space A never reused, so it never churned either"
        );
    }

    let mut c = Container::open(&path).unwrap();
    let mut b = c.open_space(b"pw-b").unwrap();
    for i in 0..12u32 {
        assert_eq!(
            b.get(Namespace::SETTINGS, format!("b{i}").as_bytes())
                .unwrap()
                .as_deref(),
            Some(format!("value-b-{i}").as_bytes()),
            "space A's reuse or churn destroyed space B's key b{i}"
        );
    }
    b.verify_integrity()
        .expect("the quiet space's tree must be intact");
}

/// Reuse must refuse under exactly the conditions `vacuum_orphans`
/// refuses, because it rests on the same proof.
///
/// A publish that may have landed leaves this handle naming an era the
/// file may already have moved past. "Unreachable from the era I can
/// see" is then not a statement about the era a reopen would pick, so
/// the pool's slots are no longer known-dead and the writer must append.
#[test]
fn an_uncertain_publish_stops_reuse_the_way_it_stops_vacuum() {
    let path = scratch();
    let _c = Cleanup(path.clone());
    build_with_pool(&path, 40);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert!(s.stats().unwrap().reusable_slot_count > 0);

    // Control: with the publish settled, the commit reuses.
    let before = s.state.reuse_count;
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"ctl", b"v").unwrap();
    tx.commit().unwrap();
    assert!(
        s.state.reuse_count > before,
        "control: a settled handle must reuse, or the test below proves nothing"
    );

    // A publish of the next seq reached the disk and then failed — the
    // state `commit_tx` leaves before its first replica append.
    s.state.attempted_seq = s.commit_seq() + 1;
    assert!(
        matches!(s.vacuum_orphans(), Err(Error::PublishUncertain(_))),
        "precondition: this is the state that stops a vacuum"
    );

    let before = s.state.reuse_count;
    let slots_before = s.stats().unwrap().total_slot_count;
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"after", b"v").unwrap();
    tx.commit().expect("committing must stay available");
    assert_eq!(
        s.state.reuse_count, before,
        "a commit on a handle whose publish may have landed reused a pool \
         slot — the proof that slot is dead was made about a different era"
    );
    assert!(
        s.stats().unwrap().total_slot_count > slots_before,
        "the commit must have appended instead"
    );
}

/// A wrong password must not learn anything from the pool, and a
/// read-only handle must not churn.
///
/// Both are the same rule as everywhere else in this crate — writes are
/// writer-only, and nothing post-authentication is reachable without the
/// key — restated for the two new write paths.
#[test]
fn readonly_handles_neither_reuse_nor_churn() {
    let path = scratch();
    let _c = Cleanup(path.clone());
    build_with_pool(&path, 40);

    let before = std::fs::read(&path).unwrap();
    {
        let mut c = Container::open_readonly(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        // Reads work; the write path is refused before it can touch a slot.
        assert!(s.get(Namespace::SETTINGS, b"k0").unwrap().is_some());
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k0", b"nope").unwrap();
        assert!(matches!(tx.commit(), Err(Error::ReadOnly)));
        assert_eq!(s.state.churn_count, 0);
    }
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "a read-only handle changed the file"
    );
}

/// A checkpoint chain must never be built out of pool slots.
///
/// This is the one place reuse cannot go, and the reason is a crash
/// window rather than a reachability argument. `write_self_heal_checkpoint`
/// retires the chain it supersedes — those slots join the pool — and only
/// then publishes the superblock naming the new chain. In between, the
/// superblock on disk still points at the OLD head. If the new chain were
/// allowed to allocate from the pool it could land a `Checkpoint` chunk
/// on exactly that slot, and a crash there would leave a chain that reads
/// as valid and is a suffix of the new one: a silently incomplete owned
/// set, which is a forward-secrecy hole that no reader can detect. Any
/// other chunk kind landing on the old head decodes as the wrong kind and
/// the reader falls back to a full scan, which is correct.
///
/// Asserted structurally — no chunk of the chain may be a slot the pool
/// was offering — rather than by trying to provoke the collision, which
/// depends on a random draw. The structural rule is what implies the
/// collision cannot happen.
#[test]
fn a_checkpoint_chain_is_never_built_out_of_pool_slots() {
    let path = scratch();
    let _c = Cleanup(path.clone());
    build_with_pool(&path, 120);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    for i in 0..30u32 {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, format!("k{i}").as_bytes(), b"x")
            .unwrap();
        tx.commit().unwrap();
    }
    s.vacuum_orphans().unwrap();

    let offered: std::collections::BTreeSet<u64> = s.state.pool.sorted().into_iter().collect();
    assert!(
        offered.len() >= 8,
        "pool of {} is too thin for this to mean anything",
        offered.len()
    );

    // A REFRESH, not a first write: this is the call that retires a chain
    // into the pool and then writes another one.
    s.write_self_heal_checkpoint().unwrap();

    // Walk the published chain and check every hop.
    let mut cur = s.state.superblock.checkpoint_slot;
    let mut hops = 0;
    while cur != crate::space::superblock::NO_RECORD {
        assert!(
            !offered.contains(&cur),
            "checkpoint chain chunk at slot {cur} came out of the decoy pool; \
             a crash before the publish would leave the old head holding a \
             chunk of the new chain"
        );
        let pt = s.read_owned_chunk(cur).unwrap();
        cur = crate::space::checkpoint::CheckpointChunk::decode(&pt.payload)
            .unwrap()
            .next_slot;
        hops += 1;
        assert!(hops < 64, "chain did not terminate");
    }
    assert!(hops >= 1, "no chain was written, so nothing was checked");
}

/// Post-commit padding must land in the pool.
///
/// This is the second of the two decoy populations, and in production it
/// is the larger one by far: a space that has just been created has
/// retired nothing, so without the padding the churn would have almost
/// no anonymity set to draw on, and the pool would only fill as the user
/// deleted things. Padding is garbage THIS space appended at a slot range
/// it watched itself write, which is exactly the proof the pool requires.
///
/// Pinned to literals at `BucketGrowth { 64 }`: a commit that leaves the
/// file at `n` slots is padded up to the next multiple of 64, so a pool
/// smaller than 32 means the padding is being written and then forgotten.
#[test]
fn post_commit_padding_becomes_churnable_decoy() {
    let path = scratch();
    let _c = Cleanup(path.clone());
    let mut c = Container::create_with_options(
        &path,
        options(0, PaddingPolicy::BucketGrowth { bucket_chunks: 64 }),
    )
    .unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    // A fresh space has retired nothing, so anything in the pool after
    // this commit came from the padding and from nowhere else.
    assert_eq!(s.state.pool.len(), 0, "precondition: nothing retired yet");
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
    tx.commit().unwrap();

    let total = s.file.slot_count();
    assert_eq!(
        total % 64,
        0,
        "the padding policy did not run; {total} is not a bucket boundary"
    );
    assert!(
        s.state.pool.len() >= 32,
        "only {} padded slots reached the pool out of a 64-slot bucket — the \
         churn has almost nothing to hide the real writes among",
        s.state.pool.len()
    );

    // And they are usable: the next commits must consume them rather than
    // grow the file.
    let before = s.file.slot_count();
    for i in 0..5u32 {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, format!("k{i}").as_bytes(), b"v")
            .unwrap();
        tx.commit().unwrap();
    }
    assert!(s.state.reuse_count > 0, "padded slots were not reused");
    assert_eq!(
        s.file.slot_count(),
        before,
        "the file grew although the bucket still had padded slots free"
    );
}
