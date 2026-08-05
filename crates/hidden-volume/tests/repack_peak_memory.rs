//! `Container::repack` must not hold a whole KV namespace, let alone
//! two copies of one (audit HV-02).
//!
//! The KV leg did `src_space.list(ns)` — every key and every value of
//! the namespace in one `Vec` — and then handed each pair to `Tx::put`,
//! which copies it into the destination transaction. Both were live at
//! the same moment, so the peak was twice the namespace's plaintext.
//!
//! That was written under a bound that no longer holds: the index was
//! two levels deep and capped around 10 K entries, and audit HV-15
//! removed the cap without revisiting the callers that leaned on it.
//! Comments in `repack` still described the cap as the reason the leg
//! was safe.
//!
//! ## Why this test measures allocation
//!
//! Every assertion about *what the destination contains* passes just as
//! happily against the materialising implementation — `tests/repack.rs`
//! is full of them and all of them were green before this change. The
//! defect is invisible in the result, so a correctness test cannot
//! catch a regression here and this file's job is to be the one that
//! can.
//!
//! **This file must hold exactly one `#[test]`.** `PEAK` / `LIVE` are
//! process-global and `cargo test` runs a binary's tests on parallel
//! threads, so a second test here would measure the first one's
//! allocations. Cargo gives every `tests/*.rs` its own binary, so the
//! tracking allocator does not reach the rest of the suite.

use hidden_volume::Container;
use hidden_volume::container::RepackOptions;
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

/// Run `f` and return how far live heap bytes rose above where they
/// started.
fn peak_growth<T>(f: impl FnOnce() -> T) -> (usize, T) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let value = f();
    let peak = PEAK.load(Ordering::Relaxed);
    (peak.saturating_sub(before), value)
}

const NAMESPACE: Namespace = Namespace::CONTACTS;
/// The small and large fixtures. The assertion is on the SLOPE between
/// them, so what matters is the ratio, not either absolute size.
const SMALL: usize = 1500;
const LARGE: usize = 6000;
/// `MAX_VALUE_LEN`, so the namespace's plaintext is dominated by values
/// and the key bookkeeping cannot be confused for it.
const VALUE_LEN: usize = 2048;

fn scratch(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "hv02-{tag}-{}-{:?}.bin",
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

/// Bytes of key + value plaintext a fixture of `entries` holds.
fn plaintext_of(entries: usize) -> usize {
    entries * (VALUE_LEN + 8)
}

fn build(path: &std::path::Path, entries: usize, params: Argon2Params) {
    let mut c = Container::create(path, params).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    // Several transactions rather than one, so building the fixture
    // does not itself need the whole namespace resident — every
    // measurement below is about the call it wraps, not about this
    // loop.
    for batch in 0..entries.div_ceil(500) {
        let mut tx = s.begin_tx();
        for i in 0..500usize {
            let n = batch * 500 + i;
            if n >= entries {
                break;
            }
            tx.put(
                NAMESPACE,
                &(n as u64).to_be_bytes(),
                &vec![0xAB_u8; VALUE_LEN],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
}

/// Peak growth of one `repack` of `src` into a fresh `dst`.
fn repack_peak(src: &std::path::Path, dst: &std::path::Path, params: Argon2Params) -> usize {
    let _ = std::fs::remove_file(dst);
    let (peak, ()) = peak_growth(|| {
        Container::repack(
            src,
            dst,
            &[b"pw"],
            RepackOptions {
                argon2: Some(params),
                ..Default::default()
            },
        )
        .unwrap()
    });
    peak
}

/// Peak growth of one whole-namespace `Space::list` of `path`.
///
/// The open — and with it `derive_keys`' 8 MiB Argon2 buffer — is
/// deliberately OUTSIDE the measured region, so this returns the walk's
/// own high-water mark and nothing else. That is what makes it usable
/// as a calibration: it shows the slope a materialising walk has on
/// this fixture, undiluted.
fn list_peak(path: &std::path::Path) -> usize {
    let mut c = Container::open_readonly(path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let (peak, _) = peak_growth(|| s.list(NAMESPACE).unwrap());
    peak
}

/// The peak must be flat in the namespace's size — not merely "small",
/// which a fixed KDF buffer would satisfy on its own.
///
/// Measuring the SLOPE rather than an absolute bound is what makes this
/// robust: `Argon2Params::MIN` allocates 8 MiB during `derive_keys` and
/// that alone dominates any correct repack's high-water mark, so an
/// absolute budget would have to sit above it and would then be blind
/// to a several-MiB namespace being materialised underneath.
#[test]
fn repack_peak_does_not_scale_with_namespace_size() {
    let small = scratch("small");
    let large = scratch("large");
    let dst = scratch("dst");
    let _cleanup = Cleanup(vec![small.clone(), large.clone(), dst.clone()]);
    for p in [&small, &large, &dst] {
        let _ = std::fs::remove_file(p);
    }

    let params = Argon2Params::MIN;
    build(&small, SMALL, params);
    build(&large, LARGE, params);

    // Warm anything lazily initialised on first use, so the first
    // measurement is not charged for it.
    let _ = repack_peak(&small, &dst, params);

    let peak_small = repack_peak(&small, &dst, params);
    let peak_large = repack_peak(&large, &dst, params);

    // Sanity: the large repack really did copy everything. Without
    // this, "the peak did not grow" would also be satisfied by copying
    // nothing.
    {
        let mut c = Container::open(&dst).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert_eq!(
            s.count(NAMESPACE).unwrap(),
            LARGE,
            "repack did not copy every entry"
        );
        assert_eq!(
            s.get(NAMESPACE, &(LARGE as u64 - 1).to_be_bytes())
                .unwrap()
                .as_deref(),
            Some(&vec![0xAB_u8; VALUE_LEN][..]),
            "repack did not copy the last entry's value"
        );
    }

    let extra_plaintext = plaintext_of(LARGE) - plaintext_of(SMALL);
    let growth = peak_large.saturating_sub(peak_small);

    // Calibration first: on THIS fixture, a walk that does materialise
    // the namespace has to show the slope the assertion below rejects.
    // `Space::list` is still in the tree (the commit flatten uses it),
    // so it can play that role on the very containers being measured.
    // Without this, a fixture too small to tell the two apart would
    // make the assertion pass while proving nothing.
    let list_growth = list_peak(&large).saturating_sub(list_peak(&small));
    assert!(
        list_growth > extra_plaintext / 2,
        "calibration failed: a materialising walk grew by only \
         {list_growth} bytes across {extra_plaintext} extra bytes of \
         namespace, so this fixture cannot distinguish a paged copy \
         from a materialising one"
    );

    // The finding itself. A materialising repack grows by at least the
    // extra plaintext (twice it, in fact — `list` and then the Tx's
    // copy). A paged one grows by nothing that depends on namespace
    // size; the slack is for allocator and fixture noise.
    let budget = extra_plaintext / 4;
    assert!(
        growth < budget,
        "repack peaked at {peak_small} bytes on a \
         {}-byte namespace and {peak_large} on a {}-byte one — it grew \
         by {growth} bytes for {extra_plaintext} extra bytes of \
         plaintext (budget {budget}), so the namespace is being \
         materialised rather than paged",
        plaintext_of(SMALL),
        plaintext_of(LARGE),
    );
}
