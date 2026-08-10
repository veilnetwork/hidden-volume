//! What opening a space costs per owned slot (report9 HV-13).
//!
//! The audit put the open scan's peak at "256+ MiB for a container at the
//! 64 GiB cap" and left it there. That is arithmetic on an assumed per-slot
//! cost, and an assumed number is not something a cap can be chosen against —
//! so this measures it. Measured, it was 27.5 bytes per owned slot: 440 MiB at
//! the cap, worse than the audit's estimate and far past what a phone has.
//!
//! Three things carried that cost, and all three are gone:
//!
//!  * `owned_slots` was a `Vec<u64>` — eight bytes per owned chunk, retained
//!    for the life of the handle. It is a bitmap now (`space::slots`), one bit
//!    per slot in the file.
//!  * the commit-anchor list took a push per superblock CHUNK, so replicas
//!    inflated it several-fold before the final dedup, and the doubling that
//!    reached that size briefly held one and a half copies.
//!  * the backward superblock hunt kept every distinct-seq candidate in its
//!    window — up to `REVERSE_SCAN_BUDGET` payloads. It runs on EVERY open,
//!    before the fast path decides it cannot proceed, and it was the actual
//!    peak: an 800-commit fixture held 800 payloads at once.
//!
//! ## Why this measures allocation
//!
//! Nothing about the open's RESULT changes with the cost: the same superblock
//! is selected and the same state is recovered, which `streaming_open.rs`
//! already checks. A regression that started retaining a payload per owned
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

/// Measure one `open_space` on an existing container. Returns
/// `(owned_slots, peak_bytes)`.
///
/// `shadow` makes the open retain eight bytes per owned slot — the
/// representation this test exists to keep out. It is the positive control:
/// an upper bound is satisfied by a measurement that sees nothing, and the
/// only way to know this one sees something is to give it something to see.
///
/// Opened cold on purpose: the scan under measurement is the one a COLD open
/// runs, which is the case a phone has to survive.
fn open_peak(path: &std::path::Path, shadow: bool) -> (usize, usize) {
    let mut c = Container::open(path).unwrap();
    // Keys derived OUTSIDE the measurement. `Argon2Params::MIN` still asks for
    // eight mebibytes of KDF working memory, which is orders of magnitude
    // above the per-slot term this is trying to see: measured through
    // `open_space`, both fixtures peak on that same buffer and the slope comes
    // out flat. A first version of this test did exactly that and reported
    // "0.0 B per slot", which is not a measurement — it is the KDF hiding the
    // thing under test.
    let keys = c.derive_space_keys(b"pw").unwrap();
    let (peak, owned) = peak_growth(|| {
        let s = c.open_space_with_keys(keys).unwrap();
        let owned = s.audit_owned_chunk_count();
        if shadow {
            let held: Vec<u64> = (0..owned as u64).collect();
            std::hint::black_box(&held);
        }
        owned
    });
    (owned, peak)
}

/// Opening must not cost bytes per owned slot.
///
/// The assertion is on the SLOPE between two fixtures rather than on an
/// absolute number: everything else in the peak (one decoded chunk, the
/// candidate window, the traversal guard of the auto-vacuum that runs at the
/// end of a writable open) is a constant of the live tree, and an absolute
/// budget would have to be loose enough to hide what is being measured.
#[test]
fn open_peak_does_not_scale_with_the_owned_set() {
    let small = scratch("small");
    let large = scratch("large");
    let _cleanup = Cleanup(vec![small.clone(), large.clone()]);

    // Warm anything lazily initialised on first use.
    build(&small, 8);
    let _ = open_peak(&small, false);

    build(&small, SMALL_COMMITS);
    build(&large, LARGE_COMMITS);

    let (owned_small, peak_small) = open_peak(&small, false);
    let (owned_large, peak_large) = open_peak(&large, false);

    let extra_slots = owned_large.saturating_sub(owned_small);
    assert!(
        extra_slots > 500,
        "the two fixtures differ by only {extra_slots} owned slots \
         ({owned_small} vs {owned_large}), too few to measure a per-slot \
         cost against"
    );

    let growth = peak_large.saturating_sub(peak_small);
    let per_slot = growth as f64 / extra_slots as f64;

    // One byte per slot: eight times the bitmap's one bit and eight times
    // BELOW the `Vec<u64>` this replaced, so it separates the two
    // representations without pretending to a precision the fixture has not
    // got. The bitmap measures 0.125 B/slot, which is the bit exactly.
    assert!(
        per_slot < 1.0,
        "open_space peaked at {peak_small} bytes over {owned_small} owned \
         slots and {peak_large} over {owned_large} — {growth} bytes for \
         {extra_slots} extra slots, {per_slot:.2} per slot. At the {} slot \
         open-scan cap that is {:.0} MiB.",
        hidden_volume::MAX_OPEN_SCAN_CHUNKS,
        (per_slot * hidden_volume::MAX_OPEN_SCAN_CHUNKS as f64) / (1024.0 * 1024.0)
    );

    // The positive control, and the assertion that matters most here.
    //
    // The budget above is an upper bound, and an upper bound is satisfied by
    // a measurement that sees NOTHING. That is not hypothetical: measured
    // through `open_space`, Argon2's eight-mebibyte working buffer dominated
    // both fixtures and an earlier version of this test came out at 0.0 bytes
    // per slot — a green that proved only that the KDF is bigger than the
    // thing under test.
    //
    // So: run the same measurement again with eight bytes per owned slot
    // deliberately held live — the representation `owned_slots` used to have
    // — and require the harness to see it. The bar is four rather than eight:
    // the shadow reuses memory the scan has freed, so it reads a little under
    // what it holds (measured 6.3), and the real number it has to be told
    // apart from is 0.16.
    let (_, control_small) = open_peak(&small, true);
    let (_, control_large) = open_peak(&large, true);
    let control_per_slot = control_large.saturating_sub(control_small) as f64 / extra_slots as f64;
    assert!(
        control_per_slot > 4.0,
        "the harness measures {control_per_slot:.2} bytes per slot for an \
         open that deliberately holds EIGHT per slot — it cannot see a \
         per-slot term of that size, so the budget above is not measuring \
         anything"
    );

    // The number itself, for whoever next reasons about the scan cap.
    println!(
        "open peak: {per_slot:.2} B/owned slot → {:.1} MiB at the {} slot cap \
         (control, holding 8 B/slot: {control_per_slot:.2})",
        (per_slot * hidden_volume::MAX_OPEN_SCAN_CHUNKS as f64) / (1024.0 * 1024.0),
        hidden_volume::MAX_OPEN_SCAN_CHUNKS
    );
}
