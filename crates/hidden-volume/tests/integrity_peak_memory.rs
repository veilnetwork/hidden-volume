//! `Space::verify_integrity` must not pool every log namespace's
//! `DataBatch` pointers before checking any of them (audit HV-03).
//!
//! The tree walk pushed one `(batch_slot, log_id)` pair per log record
//! into a single `VerifyCtx::log_pairs` vector and verified the lot
//! after the last namespace root. Peak was therefore 16 bytes times
//! every log record in the CONTAINER, when it only ever needed one
//! namespace's worth at a time.
//!
//! The flush cannot go finer than a namespace: the batch pass admits
//! each slot to the shared traversal guard, which refuses a second read
//! of any chunk, and log_ids inside one batch need not be contiguous —
//! so a boundary inside a namespace could split one batch's pointers
//! across two flushes and turn a healthy container into a reported
//! integrity failure. Across namespaces there is no such hazard: two
//! roots reaching one chunk is exactly what the shared guard exists to
//! report.
//!
//! ## Why this test measures allocation
//!
//! `verify_integrity` returns the same `IntegrityReport` either way and
//! `tests/integrity.rs` checks that report thoroughly — before this
//! change as much as after. The pooling is invisible in the result.
//!
//! **This file must hold exactly one `#[test]`.** `PEAK` / `LIVE` are
//! process-global and `cargo test` runs a binary's tests on parallel
//! threads.

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

/// Log records per namespace. Held constant between the two fixtures —
/// only the NUMBER of namespaces varies, so a peak that tracks the sum
/// separates cleanly from one that tracks the largest.
const RECORDS_PER_NS: usize = 2000;
const FEW_NAMESPACES: usize = 2;
const MANY_NAMESPACES: usize = 8;
/// One `(batch_slot, log_id)` pair, as `VerifyCtx` stores it.
const PAIR_BYTES: usize = 16;

fn scratch(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "hv03i-{tag}-{}-{:?}.bin",
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

/// Build a container holding `namespaces` log namespaces of
/// `RECORDS_PER_NS` records each, then measure one `verify_integrity`.
/// The open is outside the measured region so the KDF's buffer does not
/// mask the walk.
fn verify_peak(path: &std::path::Path, namespaces: usize) -> usize {
    let _ = std::fs::remove_file(path);
    let mut c = Container::create(path, Argon2Params::MIN).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    for n in 0..namespaces {
        // Namespace 0 is reserved; anything else is free-form.
        let ns = Namespace(10 + n as u8);
        for batch in 0..RECORDS_PER_NS.div_ceil(500) {
            let mut tx = s.begin_tx();
            for i in 0..500usize {
                let id = (batch * 500 + i) as u64;
                if id as usize >= RECORDS_PER_NS {
                    break;
                }
                tx.append_log(ns, id, &id.to_le_bytes()).unwrap();
            }
            tx.commit().unwrap();
        }
    }
    let (peak, report) = peak_growth(|| s.verify_integrity().unwrap());
    assert_eq!(
        report.namespaces_verified, namespaces,
        "the walk did not visit every namespace, so it measured nothing"
    );
    assert!(
        report.data_batches_verified > 0,
        "no DataBatch chunks were verified, so the pooled buffer was never filled"
    );
    peak
}

/// The walk's peak must track the LARGEST log namespace, not the sum of
/// them.
///
/// Two fixtures with identical per-namespace size and different
/// namespace counts: a peak that pools grows with the count, a peak
/// that flushes per namespace does not.
#[test]
fn integrity_peak_does_not_scale_with_the_namespace_count() {
    let few = scratch("few");
    let many = scratch("many");
    let _cleanup = Cleanup(vec![few.clone(), many.clone()]);

    // Warm anything lazily initialised on first use.
    let _ = verify_peak(&few, 1);

    let peak_few = verify_peak(&few, FEW_NAMESPACES);
    let peak_many = verify_peak(&many, MANY_NAMESPACES);

    let extra_pairs = (MANY_NAMESPACES - FEW_NAMESPACES) * RECORDS_PER_NS;
    let pooled_cost = extra_pairs * PAIR_BYTES;
    let growth = peak_many.saturating_sub(peak_few);

    // A pooling walk holds 16 bytes for every extra record. Budget at a
    // quarter of that: well above the per-chunk bookkeeping that does
    // legitimately grow with the namespace count (the traversal guard's
    // visited set, a few bytes per chunk), and well below the pooling
    // cost itself.
    let budget = pooled_cost / 4;
    assert!(
        growth < budget,
        "verify_integrity peaked at {peak_few} bytes over \
         {FEW_NAMESPACES} log namespaces and {peak_many} over \
         {MANY_NAMESPACES} — it grew by {growth} bytes for \
         {extra_pairs} extra records (budget {budget}), so the \
         DataBatch pointers are still being pooled across namespaces"
    );

    // Calibration: the pooled cost this fixture would impose has to
    // clear the budget by a real margin, or the assertion above is
    // satisfied by a container too small to show the difference.
    assert!(
        pooled_cost > 4 * budget / 2,
        "calibration failed: pooling every pair would cost only \
         {pooled_cost} bytes on this fixture, too close to the \
         {budget}-byte budget to distinguish pooling from flushing"
    );
}
