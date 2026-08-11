//! What the FAST open path costs per slot in the file (report11 HV-M1).
//!
//! `open_peak_memory.rs` measures the full scan. It cannot measure this one:
//! its fixtures are 200 and 800 single-KV commits, which come out at 1004 and
//! 4004 slots, and `Space::maybe_self_heal_checkpoint` declines to write a
//! checkpoint below `CHECKPOINT_MIN_TOTAL = 4096` slots. With no checkpoint
//! there is nothing for the fast path to start from, so both of that file's
//! fixtures take the full scan on every open — measured, `test_hooks::hits()`
//! is 0 for both, on the first open and on every one after. The large fixture
//! misses the threshold by 92 slots, which is why this had to be checked
//! rather than assumed.
//!
//! So the fast path had no peak-allocation budget at all, and it is the path
//! with the term that scales:
//!
//! ```text
//! head_owned = owned_below ∪ pool_below      (open/mod.rs, phase C)
//! ```
//!
//! Built as a `Vec<u64>` that CHAINED the two inputs, the union held a second
//! eight-bytes-per-slot copy of both alongside the originals — peak `2N`, plus
//! an O(N log N) sort to restore the ascending order both inputs already had.
//! It is an `OwnedSet` now (one bit per slot, ascending and deduplicated by
//! construction), so the copy is a bitmap and the sort is gone.
//!
//! ## Why the denominator is file slots, not owned slots
//!
//! `audit_owned_chunk_count` PLATEAUS: the orphan vacuum and `ANCHOR_HORIZON`
//! cap the live set, so every fixture above a few hundred commits lands near
//! the same owned count — measured 4119, 4134, 4164 and 4224 for 1500, 3000,
//! 6000 and 12000 commits. Forty-five slots apart per doubling is far too few
//! to fit a slope to. What grows is the FILE, and with it the decoy pool the
//! vacuum feeds: 7522, 15037, 30067 and 60127 slots for those same fixtures.
//! `pool_below` is the half of the union that tracks the file, which is
//! exactly the finding — peak proportional to a file the user already owns and
//! has already unlocked.
//!
//! ## Severity
//!
//! LOW, not medium. At `MAX_OPEN_SCAN_CHUNKS = 16 * 1024 * 1024` the cap
//! corresponds to a 64 GiB container (`CHUNK_SIZE` 4096), so even the old `2N`
//! union was ~0.39% of the file size, reached only by a file its owner has
//! already unlocked. This is a proportionality bound worth keeping, not a
//! denial-of-service surface.
//!
//! **This file must hold exactly one `#[test]`.** `PEAK` / `LIVE` are
//! process-global and `cargo test` runs a binary's tests on parallel threads,
//! so a second test here would measure the first one's allocations. It is a
//! separate binary from `open_peak_memory.rs` for the same reason.
//!
//! **Feature-gated, and a bare `cargo test` therefore runs NOTHING here** —
//! it needs `test-hooks` to ask which scan path it measured. The canonical
//! gate covers it: `scripts/pre-tag-gate.sh` runs
//! `cargo test --workspace --all-features`. Run it that way, or with
//! `--features test-hooks`; a green plain `cargo test` says nothing about
//! this file.
#![cfg(feature = "test-hooks")]

use hidden_volume::Container;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::Namespace;
use hidden_volume::test_hooks;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Pass-through allocator tracking live bytes and their high-water mark.
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

/// Both above `CHECKPOINT_MIN_TOTAL` (4096 slots) so the checkpoint exists,
/// and far enough apart to fit a slope to: measured 7522 vs 30067 file slots.
///
/// The spread is load-bearing, not conservatism. Peak-vs-slots is not linear
/// at the bottom of the range — a `Vec` that doubles overshoots hardest when
/// it is small, and the 7522-slot fixture reads 25.46 B/slot against an
/// asymptote of 20.82. A 1500/3000 pair straddles only that anomaly and
/// inverts: it reported 16.16 B/slot for the `Vec<u64>` union and 17.42 for
/// the `OwnedSet` that uses strictly less memory. Measured across
/// 1500/6000 the two separate cleanly — 19.27 against 13.55.
const SMALL_COMMITS: usize = 1500;
const LARGE_COMMITS: usize = 6000;

fn scratch(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "hvm1-{tag}-{}-{:?}.bin",
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

fn build(path: &std::path::Path, commits: usize) {
    let _ = std::fs::remove_file(path);
    let mut c = Container::create(path, Argon2Params::MIN).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    for i in 0..commits {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", &(i as u64).to_be_bytes())
            .unwrap();
        tx.commit().unwrap();
    }
}

/// One writable open, whose `maybe_self_heal_checkpoint` writes the checkpoint
/// the NEXT open's fast path starts from. Not measured — this open is itself a
/// full scan, since there is no checkpoint yet.
fn prime(path: &std::path::Path) {
    let mut c = Container::open(path).unwrap();
    let _ = c.open_space(b"pw").unwrap();
}

fn slot_count(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).unwrap().len() / 4096
}

/// Measure one fast-path `open_space`. Returns `(slots, peak_bytes, hits)`.
///
/// `shadow` makes the open retain eight bytes per FILE slot — the
/// representation the union used to have. It is the positive control: an upper
/// bound is satisfied by a measurement that sees nothing, and the only way to
/// know this one sees something is to give it something to see.
fn open_peak_fast(path: &std::path::Path, shadow: bool) -> (u64, usize, u64) {
    let slots = slot_count(path);
    // READ-ONLY on purpose. A writable open also runs `vacuum_orphans` and
    // `maybe_self_heal_checkpoint` inside the measured region, and both
    // allocate with the file: measured through `Container::open`, they moved
    // the slope by more than the union does and the number stopped being about
    // the union at all (16.16 → 17.42 across a change that lowered BOTH peaks).
    // A read-only open is the scan and nothing else.
    let mut c = Container::open_readonly(path).unwrap();
    // Keys derived OUTSIDE the measurement: `Argon2Params::MIN` still asks for
    // eight mebibytes of KDF working memory, orders of magnitude above the
    // per-slot term under test, and it would flatten the slope to zero.
    let keys = c.derive_space_keys(b"pw").unwrap();
    test_hooks::set_disable(false);
    test_hooks::reset_hits();
    let (peak, ()) = peak_growth(|| {
        // Held ACROSS the open, not after it. Allocated afterwards it is
        // invisible: the scan has already freed its temporaries by then, so
        // live+shadow stays under the peak the scan itself reached and the
        // control reads exactly the same number as the measurement it is
        // supposed to be a control for (measured: 13.55 either way). Live
        // across the open it adds to the same high-water mark.
        let held: Vec<u64> = if shadow {
            (0..slots).collect()
        } else {
            Vec::new()
        };
        std::hint::black_box(&held);
        let s = c.open_space_with_keys(keys).unwrap();
        std::hint::black_box(&s);
        std::hint::black_box(&held);
        drop(held);
    });
    (slots, peak, test_hooks::hits())
}

/// The fast open path must not cost bytes per slot in the file.
///
/// The assertion is on the SLOPE between two fixtures rather than an absolute
/// number: everything else in the peak (one decoded chunk, the reverse-scan
/// candidate window, the auto-vacuum's traversal guard) is a constant of the
/// live tree, and an absolute budget would have to be loose enough to hide
/// what is being measured.
#[test]
fn fast_open_peak_does_not_scale_with_the_recorded_union() {
    let small = scratch("small");
    let large = scratch("large");
    let _cleanup = Cleanup(vec![small.clone(), large.clone()]);

    // Warm anything lazily initialised on first use.
    build(&small, 8);
    prime(&small);
    let _ = open_peak_fast(&small, false);

    build(&small, SMALL_COMMITS);
    build(&large, LARGE_COMMITS);
    prime(&small);
    prime(&large);

    let (slots_small, peak_small, hits_small) = open_peak_fast(&small, false);
    let (slots_large, peak_large, hits_large) = open_peak_fast(&large, false);

    // The assertion this whole file exists for: the measurement above ran the
    // FAST path. Without this, the budget below would silently be a second,
    // worse copy of `open_peak_memory.rs` — which is exactly the gap being
    // closed, since that file's fixtures never reach a checkpoint.
    assert_eq!(
        (hits_small, hits_large),
        (1, 1),
        "both measured opens must take the fast path (got {hits_small} and \
         {hits_large} fast-path engagements). A 0 means no checkpoint was \
         written — check the fixture is above CHECKPOINT_MIN_TOTAL slots."
    );

    let extra_slots = slots_large.saturating_sub(slots_small);
    assert!(
        extra_slots > 20000,
        "the two fixtures differ by only {extra_slots} file slots \
         ({slots_small} vs {slots_large}), too few to measure a per-slot cost \
         against"
    );

    let growth = peak_large.saturating_sub(peak_small);
    let per_slot = growth as f64 / extra_slots as f64;

    // The budget separates the two representations without pretending to a
    // precision the fixture has not got.
    //
    // `owned_below` and `pool_below` arrive from the checkpoint record as
    // `Vec<u64>`, and `pool_below` is RETAINED — it becomes the space's
    // recovered pool — so a per-slot floor is inherent here and is not what
    // this measures. What it measures is the SECOND copy: chaining both into
    // another `Vec<u64>` added one more eight-byte word per union slot, plus
    // the doubling that reached it. Measured over 1500/6000 commits, the
    // `OwnedSet` union reads 13.55 B/file-slot and the `Vec<u64>` it replaced
    // reads 19.27 (asymptotically 11.61 against 20.82 — see the four-point
    // sweep in the commit that added this file). Sixteen sits between them
    // with room on both sides.
    assert!(
        per_slot < 16.0,
        "the fast open peaked at {peak_small} bytes over {slots_small} file \
         slots and {peak_large} over {slots_large} — {growth} bytes for \
         {extra_slots} extra slots, {per_slot:.2} per slot. At the {} slot \
         open-scan cap that is {:.0} MiB.",
        hidden_volume::MAX_OPEN_SCAN_CHUNKS,
        (per_slot * hidden_volume::MAX_OPEN_SCAN_CHUNKS as f64) / (1024.0 * 1024.0)
    );

    // The positive control, and the assertion that matters most here.
    //
    // The budget above is an upper bound, and an upper bound is satisfied by a
    // measurement that sees NOTHING — the failure mode `open_peak_memory.rs`
    // records, where Argon2's working buffer dominated both fixtures and the
    // test reported 0.0 bytes per slot. So: run it again with eight bytes per
    // file slot deliberately held live and require the harness to see it.
    let (_, control_small, _) = open_peak_fast(&small, true);
    let (_, control_large, _) = open_peak_fast(&large, true);
    let control_per_slot = control_large.saturating_sub(control_small) as f64 / extra_slots as f64;
    assert!(
        control_per_slot > 18.0,
        "the harness measures {control_per_slot:.2} bytes per slot for an open \
         that deliberately holds EIGHT per slot ON TOP of the union — it \
         cannot see a per-slot term of that size, so the budget above is not \
         measuring anything"
    );

    println!(
        "fast-open peak: {per_slot:.2} B/file slot → {:.1} MiB at the {} slot \
         cap (control, holding 8 B/slot on top: {control_per_slot:.2})",
        (per_slot * hidden_volume::MAX_OPEN_SCAN_CHUNKS as f64) / (1024.0 * 1024.0),
        hidden_volume::MAX_OPEN_SCAN_CHUNKS
    );
}
