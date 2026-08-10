//! What opening a space costs per owned slot (report9 HV-13).
//!
//! The audit put the open scan's peak at "256+ MiB for a container at the
//! 64 GiB cap" and left it there. That is arithmetic on an assumed per-slot
//! cost, and an assumed number is not something a cap can be chosen against —
//! so this measures it.
//!
//! The scan is meant to be streaming: each decrypted Plaintext is dropped at
//! the end of its iteration and only `owned_slots` (8 bytes per owned chunk)
//! and `commit_history` (8 per commit) are retained. What the arithmetic then
//! turns on is whether that is really all, and whether the parallel path's
//! reduce holds two copies while it merges.
//!
//! ## Why this measures allocation
//!
//! Nothing about the open's RESULT changes with the cost: the same superblock
//! is selected and the same state is recovered, which `streaming_open.rs`
//! already checks. A regression that started retaining a Plaintext per owned
//! chunk would pass every functional test in the crate and make a large
//! container refuse to open on a phone.
//!
//! **This file must hold exactly one `#[test]`.** `PEAK` / `LIVE` are
//! process-global and `cargo test` runs a binary's tests on parallel threads,
//! so a second test here would measure the first one's allocations.

use hidden_volume::Container;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::Namespace;
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

const SMALL_COMMITS: usize = 200;
const LARGE_COMMITS: usize = 800;

fn scratch(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "hv13-{tag}-{}-{:?}.bin",
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

/// Build a container with `commits` commits of history, close it, then measure
/// one `open_space`. Returns `(owned_slots, peak_bytes)`.
///
/// Closed and reopened on purpose: the scan under measurement is the one a
/// COLD open runs, which is the case a phone has to survive.
fn open_peak(path: &std::path::Path, commits: usize) -> (usize, usize) {
    let _ = std::fs::remove_file(path);
    {
        let mut c = Container::create(path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..commits {
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", &(i as u64).to_be_bytes())
                .unwrap();
            tx.commit().unwrap();
        }
    }
    let mut c = Container::open(path).unwrap();
    // Keys derived OUTSIDE the measurement. `Argon2Params::MIN` still asks for
    // eight mebibytes of KDF working memory, which is three orders of
    // magnitude above the per-slot term this is trying to see: measured
    // through `open_space`, both fixtures peak on that same buffer and the
    // slope comes out flat. A first version of this test did exactly that and
    // reported "0.0 B per slot", which is not a measurement — it is the KDF
    // hiding the thing under test.
    let keys = c.derive_space_keys(b"pw").unwrap();
    let (peak, owned) = peak_growth(|| {
        let s = c.open_space_with_keys(keys).unwrap();
        s.audit_owned_chunk_count()
    });
    (owned, peak)
}

/// Opening must cost a few words per owned slot, not a chunk.
///
/// The assertion is on the SLOPE between two fixtures rather than on an
/// absolute number: everything else in the peak (one decoded chunk, the
/// traversal guard of the auto-vacuum that runs at the end of a writable open)
/// is a constant of the live tree, and an absolute budget would have to be
/// loose enough to hide what is being measured.
#[test]
fn open_peak_does_not_scale_with_the_chunk_payload() {
    let small = scratch("small");
    let large = scratch("large");
    let _cleanup = Cleanup(vec![small.clone(), large.clone()]);

    // Warm anything lazily initialised on first use.
    let _ = open_peak(&small, 8);

    let (owned_small, peak_small) = open_peak(&small, SMALL_COMMITS);
    let (owned_large, peak_large) = open_peak(&large, LARGE_COMMITS);

    let extra_slots = owned_large.saturating_sub(owned_small);
    assert!(
        extra_slots > 500,
        "the two fixtures differ by only {extra_slots} owned slots \
         ({owned_small} vs {owned_large}), too few to measure a per-slot \
         cost against"
    );

    let growth = peak_large.saturating_sub(peak_small);
    let per_slot = growth as f64 / extra_slots as f64;

    // 128 bytes per slot: an order of magnitude above what the streaming scan
    // is meant to retain (8 for `owned_slots`, 8 for a commit, and the
    // parallel reduce's transient second copy of the first) and an order of
    // magnitude below retaining one 4 KiB Plaintext per owned chunk, which is
    // the regression this exists to catch.
    let budget = extra_slots * 128;
    assert!(
        growth < budget,
        "open_space peaked at {peak_small} bytes over {owned_small} owned \
         slots and {peak_large} over {owned_large} — {growth} bytes for \
         {extra_slots} extra slots, {per_slot:.1} per slot (budget 128). \
         At the {} slot open-scan cap that is {:.0} MiB.",
        hidden_volume::MAX_OPEN_SCAN_CHUNKS,
        (per_slot * hidden_volume::MAX_OPEN_SCAN_CHUNKS as f64) / (1024.0 * 1024.0)
    );

    // Non-vacuity, and this is the assertion that matters most here.
    //
    // The budget above is an upper bound, and an upper bound is satisfied by a
    // measurement that sees NOTHING. That is not hypothetical: measured
    // through `open_space`, Argon2's eight-mebibyte working buffer dominated
    // both fixtures and this came out at 0.0 bytes per slot — a green that
    // proved only that the KDF is bigger than the thing under test.
    //
    // The scan retains `owned_slots` at eight bytes per owned chunk by its own
    // documentation, so anything below half of that means the per-slot term is
    // being masked again and the upper bound above is meaningless.
    assert!(
        per_slot >= 4.0,
        "the measurement sees {per_slot:.1} bytes per slot across \
         {extra_slots} extra slots — below the eight the scan retains for \
         `owned_slots` alone, so something is masking the per-slot cost and \
         the budget above is not measuring anything"
    );

    // The number itself, for whoever next reasons about the scan cap.
    println!(
        "open peak: {per_slot:.1} B/owned slot → {:.0} MiB at the {} slot cap",
        (per_slot * hidden_volume::MAX_OPEN_SCAN_CHUNKS as f64) / (1024.0 * 1024.0),
        hidden_volume::MAX_OPEN_SCAN_CHUNKS
    );
}
