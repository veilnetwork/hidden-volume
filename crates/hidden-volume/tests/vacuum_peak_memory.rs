//! `Space::vacuum_orphans` must not cost several words of heap per
//! owned slot (audit HV-03).
//!
//! It built a `HashSet<u64>` of reachable slots, cloned the whole
//! `owned_slots` vector, and built a second `HashSet<u64>` of slots to
//! drop — three structures whose baseline was already the owned-slot
//! count, multiplied by hashing's per-member overhead. Slot indices are
//! dense and bounded by the file's own slot count, so one bit each says
//! the same thing.
//!
//! ## Why this is more than an allocation win
//!
//! `vacuum_orphans` runs automatically at the end of every writable
//! `Container::open_space`. A container that has grown to the point
//! where the vacuum cannot allocate stops opening **at all** — the
//! person who filled it has locked themselves out of their own data,
//! with no adversary anywhere in the story.
//!
//! ## Why this test measures allocation
//!
//! Nothing about the vacuum's RESULT changes: the same chunks are
//! scrubbed and the same slots leave `owned_slots`, which is what
//! `tests/scrub.rs` and `tests/vacuum_data_batches.rs` already check
//! and what they checked before this change too. The defect is
//! invisible in the return value.
//!
//! **This file must hold exactly one `#[test]`.** `PEAK` / `LIVE` are
//! process-global and `cargo test` runs a binary's tests on parallel
//! threads, so a second test here would measure the first one's
//! allocations.

use hidden_volume::Container;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::Namespace;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Pass-through allocator tracking live bytes and their high-water
/// mark. `realloc` / `alloc_zeroed` are left at their defaults, which
/// route through `alloc` + `dealloc` here.
struct Tracking;

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Tracking = Tracking;

fn peak_growth<T>(f: impl FnOnce() -> T) -> (usize, T) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let value = f();
    let peak = PEAK.load(Ordering::Relaxed);
    (peak.saturating_sub(before), value)
}

const NAMESPACE: Namespace = Namespace::SETTINGS;
/// Commit counts for the small and large fixtures. Each commit orphans
/// the IndexNode it rewrote and leaves a Commit chunk and Superblock
/// replicas behind, so owned slots grow with commits while the live
/// tree stays one leaf.
///
/// **Why the live tree is deliberately held constant.** The pass
/// removed three structures whose size followed the owned-slot count:
/// the `owned_slots` clone, the drop set, and a reachable set that was
/// a duplicate of the traversal guard's own visited set. What remains
/// is that guard — one hashed `u64` per chunk the LIVE tree holds —
/// and it is shared with every other walker in the crate, so shrinking
/// it is a different question with different trade-offs (a point `get`
/// would then pay a slot-count-sized allocation to read three nodes).
/// A fixture whose live tree grew alongside its history would let that
/// term dominate the measurement and hide the ones this pass is about.
const SMALL_COMMITS: usize = 200;
const LARGE_COMMITS: usize = 800;

fn scratch(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "hv03-{tag}-{}-{:?}.bin",
        std::process::id(),
        std::thread::current().id()
    ))
}

struct Cleanup(Vec<std::path::PathBuf>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Build a container with `commits` commits' worth of history and,
/// **without closing it** (an open would auto-vacuum the history away),
/// measure one `vacuum_orphans`. Returns `(owned_slots, peak_bytes)`.
fn vacuum_peak(path: &std::path::Path, commits: usize) -> (usize, usize) {
    let _ = std::fs::remove_file(path);
    let mut c = Container::create(path, Argon2Params::MIN).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    for i in 0..commits {
        let mut tx = s.begin_tx();
        tx.put(NAMESPACE, b"k", &(i as u64).to_be_bytes()).unwrap();
        tx.commit().unwrap();
    }
    let owned = s.audit_owned_chunk_count();
    let (peak, scrubbed) = peak_growth(|| s.vacuum_orphans().unwrap());
    assert!(
        scrubbed > 0,
        "the fixture produced no orphans, so the vacuum measured nothing"
    );
    (owned, peak)
}

/// The vacuum's peak must be flat-ish in the owned-slot count: one bit
/// per slot, not one hashed `u64` per slot several times over.
///
/// The assertion is on the SLOPE between two fixtures rather than on an
/// absolute number, because everything else in the peak (the traversal
/// guard's visited set, one decoded chunk) is a constant of the live
/// tree, and an absolute budget would have to be loose enough to hide
/// exactly what is being measured.
#[test]
fn vacuum_peak_does_not_scale_with_the_owned_slot_count() {
    let small = scratch("small");
    let large = scratch("large");
    let _cleanup = Cleanup(vec![small.clone(), large.clone()]);

    // Warm anything lazily initialised on first use.
    let _ = vacuum_peak(&small, 8);

    let (owned_small, peak_small) = vacuum_peak(&small, SMALL_COMMITS);
    let (owned_large, peak_large) = vacuum_peak(&large, LARGE_COMMITS);

    let extra_slots = owned_large.saturating_sub(owned_small);
    assert!(
        extra_slots > 1000,
        "the two fixtures differ by only {extra_slots} owned slots \
         ({owned_small} vs {owned_large}), too few to measure a \
         per-slot cost against"
    );

    let growth = peak_large.saturating_sub(peak_small);

    // Two bitmaps of one bit per slot each is 0.25 bytes per slot. The
    // structures this replaced were a `Vec<u64>` clone (8 bytes per
    // owned slot, unconditionally) plus two `HashSet<u64>`s whose
    // buckets and control bytes come to roughly 9 more per member at
    // hashbrown's load factor — call it 20 bytes per slot against 0.25.
    // The budget sits an order of magnitude below the old cost and an
    // order of magnitude above the new one, so it distinguishes them
    // without pinning either exactly.
    let budget = extra_slots * 2;
    assert!(
        growth < budget,
        "vacuum_orphans peaked at {peak_small} bytes over {owned_small} \
         owned slots and {peak_large} over {owned_large} — it grew by \
         {growth} bytes for {extra_slots} extra slots (budget {budget}), \
         which is per-slot heap the slot bitmap was supposed to remove"
    );

    // Calibration: a `Vec<u64>` clone of the owned-slot list — the
    // cheapest of the three structures the old vacuum built, and the
    // one it built unconditionally — already exceeds the budget on this
    // fixture. Without this, a fixture too small to show any per-slot
    // cost would satisfy the assertion above while proving nothing.
    let clone_cost = extra_slots * std::mem::size_of::<u64>();
    assert!(
        clone_cost > budget,
        "calibration failed: even an 8-byte-per-slot clone would grow \
         by only {clone_cost} bytes across {extra_slots} extra slots, \
         under the {budget}-byte budget — this fixture cannot tell a \
         per-slot cost from a per-bit one"
    );

    // --- second half: the batch vacuum's pointer scan ---
    //
    // `vacuum_data_batches` reached its referenced-slot set through
    // `collect_leaves`, which materialises every `(log_id_key,
    // batch_slot)` pair of every log namespace before a single one is
    // read — and then hashed each pointer into a `HashSet<u64>`. Both
    // halves scaled with the container's log-record count; the pass
    // replaced them with a page-at-a-time scan feeding the same slot
    // bitmap.
    //
    // Measured here rather than in its own file because the tracking
    // allocator is process-global: a second `#[test]` in this binary
    // would run on another thread and see this one's allocations.
    let small_log = scratch("smalllog");
    let large_log = scratch("largelog");
    let _cleanup_log = Cleanup(vec![small_log.clone(), large_log.clone()]);

    // No warm-up pass here: the process is already warm from the half
    // above, and every fixture costs a key derivation.
    let peak_small_log = batch_vacuum_peak(&small_log, SMALL_RECORDS);
    let peak_large_log = batch_vacuum_peak(&large_log, LARGE_RECORDS);

    let extra_records = LARGE_RECORDS - SMALL_RECORDS;
    let log_growth = peak_large_log.saturating_sub(peak_small_log);
    // A materialised pair is 16 bytes of payload in a `Vec` of two
    // `Vec<u8>`s — 48 bytes of headers on top — plus a hashed `u64` for
    // the pointer. Budget at 8 bytes per record: far under that, far
    // over the fraction of a byte per record the paged scan costs.
    let log_budget = extra_records * 8;
    assert!(
        log_growth < log_budget,
        "vacuum_data_batches peaked at {peak_small_log} bytes over \
         {SMALL_RECORDS} log records and {peak_large_log} over \
         {LARGE_RECORDS} — it grew by {log_growth} bytes for \
         {extra_records} extra records (budget {log_budget}), so the \
         pointer scan is still materialising the namespace"
    );
}

/// Log-record counts for the batch-vacuum halves of the test.
const SMALL_RECORDS: usize = 2000;
const LARGE_RECORDS: usize = 8000;
const LOG_NAMESPACE: Namespace = Namespace::MESSAGE_LOG;

/// Build a log namespace of `records` entries, orphan a few batches by
/// replacing entries in place, and measure one `vacuum_data_batches`.
fn batch_vacuum_peak(path: &std::path::Path, records: usize) -> usize {
    let _ = std::fs::remove_file(path);
    let mut c = Container::create(path, Argon2Params::MIN).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    for batch in 0..records.div_ceil(500) {
        let mut tx = s.begin_tx();
        for i in 0..500usize {
            let id = (batch * 500 + i) as u64;
            if id as usize >= records {
                break;
            }
            tx.append_log(LOG_NAMESPACE, id, &id.to_le_bytes()).unwrap();
        }
        tx.commit().unwrap();
    }
    // Last-write-wins: re-appending moves these ids to fresh batches.
    // It has to be a WHOLE commit's worth of ids — a batch stays
    // referenced while any one of the records it holds still points at
    // it, so replacing a prefix orphans nothing.
    {
        let mut tx = s.begin_tx();
        for id in 0..500u64 {
            tx.append_log(LOG_NAMESPACE, id, b"replaced").unwrap();
        }
        tx.commit().unwrap();
    }
    let (peak, scrubbed) = peak_growth(|| s.vacuum_data_batches().unwrap());
    assert!(
        scrubbed > 0,
        "the fixture orphaned no DataBatch chunks, so the vacuum measured nothing"
    );
    peak
}
