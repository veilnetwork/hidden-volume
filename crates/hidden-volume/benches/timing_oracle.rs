//! TM1 — open-time scan timing-oracle micro-bench.
//!
//! Threat-model open question: an attacker with a same-host shared
//! filesystem (or similar low-privilege observation) might measure
//! the wall-clock time of `Container::open_space` and try to infer
//! "how many of the slots in this file actually belong to the
//! supplied password". The discovery scan tries each slot through
//! AEAD-decrypt; it's documented as constant-work-per-slot, but
//! cache-effects (success path stores in `owned_slots`,
//! `commit_history`, `sb_candidates` while skip path returns
//! immediately) could in principle leak the owned-fraction.
//!
//! This bench measures `open_space` wall-clock time as a function
//! of `(owned_slot_count, total_slot_count)`. A *successful*
//! verification has the timing distribution for "X owned" overlap
//! the distribution for "Y owned" within criterion's noise floor —
//! i.e. an attacker observing one open-time can't distinguish
//! ownership ratios.
//!
//! Run with: `cargo bench --bench timing_oracle -- --quick`
//! (full statistical run takes ~5 min; `--quick` gives directional
//! signal in ~30 s).
//!
//! ## What "passes" looks like
//!
//! For a fixed `total_slot_count`, the measured open-time should
//! be:
//!
//!  - **Linear in `total_slot_count`** (Θ(N) per the design — every
//!    slot AEAD-trial-decrypted regardless of ownership).
//!  - **Independent of `owned_slot_count`** within a few percent
//!    (cache effects on the bookkeeping vectors are dominated by
//!    the AEAD-decrypt cost per slot).
//!
//! If we measure (owned=10%, owned=50%, owned=90%) at
//! `total=1000` and the means differ by < 5%, the timing-oracle
//! attack is empirically ineffective at single-observation
//! resolution. The exact threshold depends on storage jitter — on
//! NVMe / Linux page cache the per-slot variance is large enough
//! to swamp any cache-effect signal.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use hidden_volume::Container;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::Namespace;
use std::time::Duration;

/// Build a container with `total_slots` data chunks of which
/// `owned_slots` belong to the named password. Fills the rest with
/// initial-garbage chunks. Returns (path, password) for benchmark
/// iterations to consume.
///
/// Strategy: create container with `(total - owned)` initial garbage
/// chunks, then commit `owned / 2` Tx's each adding 2 KV entries
/// (so each Tx produces ~1 IndexNode + 1 Commit + replicas
/// Superblocks ≈ owned-ish chunks; tune to match exactly).
///
/// We aim for *approximate* owned counts — exact equality is hard
/// because vacuum-on-open scrubs orphans, and the SB replicas
/// fluctuate. Empirical ratios are close enough for the cache-effect
/// signal we're hunting for.
fn build_container(
    path: &std::path::Path,
    password: &[u8],
    total_slots: u64,
    target_owned_fraction: f64,
) -> u64 {
    let initial_garbage = (total_slots as f64 * (1.0 - target_owned_fraction)) as u64;
    let opts = hidden_volume::container::ContainerOptions {
        argon2: Argon2Params::MIN,
        initial_garbage_chunks: initial_garbage,
        padding_policy: hidden_volume::padding::PaddingPolicy::None,
        superblock_replicas: 3,
    };
    let mut c = Container::create_with_options(path, opts).unwrap();
    let mut s = c.create_space(password).unwrap();

    // Commit Tx's to grow `owned_slots` toward target.
    let target_owned = (total_slots as f64 * target_owned_fraction) as u64;
    let target_owned = target_owned.max(4); // at least one commit's worth
    let mut commits_done = 0u64;
    while s.audit_owned_chunk_count() < target_owned as usize && commits_done < 200 {
        let mut tx = s.begin_tx();
        for i in 0..4u64 {
            let id = commits_done * 4 + i;
            let key = format!("k{id:08}");
            let val = format!("v{id:08}");
            tx.put(Namespace::CONTACTS, key.as_bytes(), val.as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
        commits_done += 1;
    }
    s.audit_owned_chunk_count() as u64
}

/// Scan-mode dispatcher used by every bench group. Lets a single
/// fraction-sweep be reused across the three scan implementations
/// (sequential / parallel-scan / mmap). Audit pass 3 SC-INFO2:
/// originally only the sequential path was characterised; this
/// dispatch lets each feature variant be timing-profiled side by
/// side so the per-variant TM1 leak shape is on record.
#[derive(Copy, Clone)]
enum ScanMode {
    Sequential,
    #[cfg(all(feature = "parallel-scan", unix))]
    Parallel,
    #[cfg(all(feature = "mmap", unix))]
    Mmap,
}

impl ScanMode {
    fn label(self) -> &'static str {
        match self {
            ScanMode::Sequential => "sequential",
            #[cfg(all(feature = "parallel-scan", unix))]
            ScanMode::Parallel => "parallel",
            #[cfg(all(feature = "mmap", unix))]
            ScanMode::Mmap => "mmap",
        }
    }

    fn open_space(self, c: &mut Container, password: &[u8]) -> hidden_volume::Result<()> {
        match self {
            ScanMode::Sequential => c.open_space(password).map(|_| ()),
            #[cfg(all(feature = "parallel-scan", unix))]
            ScanMode::Parallel => c.open_space_parallel(password).map(|_| ()),
            #[cfg(all(feature = "mmap", unix))]
            ScanMode::Mmap => c.open_space_mmap(password).map(|_| ()),
        }
    }
}

fn enabled_scan_modes() -> Vec<ScanMode> {
    // `mut` may be unused under default features (both cfg-blocks
    // below removed). Acceptable; suppress the lint.
    #[allow(unused_mut)]
    let mut out = vec![ScanMode::Sequential];
    #[cfg(all(feature = "parallel-scan", unix))]
    out.push(ScanMode::Parallel);
    #[cfg(all(feature = "mmap", unix))]
    out.push(ScanMode::Mmap);
    out
}

fn bench_open_by_owned_fraction(c: &mut Criterion) {
    const TOTAL_SLOTS: u64 = 500;

    for mode in enabled_scan_modes() {
        let group_name = format!("tm1_open_time_by_owned_fraction_{}", mode.label());
        let mut group = c.benchmark_group(group_name);
        // Lower sample size — these benches involve disk I/O, full
        // statistical runs are expensive. We're looking for directional
        // signal, not 5-sigma confidence.
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(10));

        for &fraction in &[0.10, 0.50, 0.90] {
            let label = format!("frac_{:.2}", fraction);
            group.bench_function(label, |b| {
                // Build per-iteration so cache state is fresh-ish.
                // BatchSize::SmallInput tells criterion this is OK to
                // include setup cost in iteration cost — mostly we
                // care about the per-op shape, not the absolute number.
                b.iter_batched(
                    || {
                        let tmp = tempfile::NamedTempFile::new().unwrap();
                        let path = tmp.path().to_owned();
                        drop(tmp);
                        let _actual_owned =
                            build_container(&path, b"benchpw", TOTAL_SLOTS, fraction);
                        path
                    },
                    |path| {
                        let mut c = Container::open(&path).unwrap();
                        mode.open_space(&mut c, b"benchpw").unwrap();
                        drop(c);
                        let _ = std::fs::remove_file(&path);
                    },
                    BatchSize::SmallInput,
                );
            });
        }
        group.finish();
    }
}

fn bench_open_by_total_slots(c: &mut Criterion) {
    // Sanity check: open-time should scale linearly with total
    // slot count regardless of ownership fraction. Fix fraction
    // at 0.5; vary total. Run per scan-mode so we capture the
    // linearity-slope shape for each (parallel may flatten under
    // work-stealing, mmap may shift due to page-fault pattern).
    for mode in enabled_scan_modes() {
        let group_name = format!("tm1_open_time_linearity_{}", mode.label());
        let mut group = c.benchmark_group(group_name);
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(10));

        for &total in &[100u64, 500, 1000] {
            let label = format!("total_{total}");
            group.bench_function(label, |b| {
                b.iter_batched(
                    || {
                        let tmp = tempfile::NamedTempFile::new().unwrap();
                        let path = tmp.path().to_owned();
                        drop(tmp);
                        let _ = build_container(&path, b"benchpw", total, 0.5);
                        path
                    },
                    |path| {
                        let mut c = Container::open(&path).unwrap();
                        mode.open_space(&mut c, b"benchpw").unwrap();
                        drop(c);
                        let _ = std::fs::remove_file(&path);
                    },
                    BatchSize::SmallInput,
                );
            });
        }
        group.finish();
    }
}

criterion_group!(
    benches,
    bench_open_by_owned_fraction,
    bench_open_by_total_slots
);
criterion_main!(benches);
