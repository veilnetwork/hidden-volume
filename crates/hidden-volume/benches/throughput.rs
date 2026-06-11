//! Throughput benchmarks for the hidden-volume container.
//!
//! Run with: `cargo bench --bench throughput`
//!
//! ## What's measured
//!
//! - **create_space**: end-to-end Container::create + create_space. Dominated
//!   by Argon2id (~30 ms at MIN params). Represents the cost of "first run
//!   on this device".
//! - **open_space**: Container::open + open_space on a 1-space container with
//!   a single committed record. Measures Argon2id + scan + initial vacuum.
//! - **commit_single_kv**: single put-then-commit on an open Space. Excludes
//!   Argon2id; pure storage logic + AEAD + 3 fsyncs.
//! - **commit_100_kv**: same with 100 puts in one Tx.
//! - **commit_1000_kv**: same with 1000 puts (forces B+ tree split).
//! - **commit_log_100**: 100 append_log entries → one DataBatch chunk.
//! - **read_log**: lookup of a known message id from a 1000-msg log
//!   spanning 10 DataBatch chunks.
//! - **get_random_kv**: KV lookup against a 1000-entry namespace.
//! - **repack_1000**: full repack of a 1000-entry container.
//!
//! All benches use [`Argon2Params::MIN`] to keep per-run unlock cost low; in
//! production with [`Argon2Params::DEFAULT`] open paths take ~3-4× longer.
//!
//! ## Reading the numbers
//!
//! Criterion reports times per iteration. Use a low sample size to keep
//! wall-clock manageable — these are sanity / regression benchmarks,
//! not statistical analyses.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use hidden_volume::Container;
use hidden_volume::container::ContainerOptions;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use std::time::Duration;

fn fast_options() -> ContainerOptions {
    ContainerOptions {
        argon2: Argon2Params::MIN,
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 1,
    }
}

fn scratch_path() -> std::path::PathBuf {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let p = tmp.path().to_owned();
    drop(tmp);
    p
}

fn bench_create_space(c: &mut Criterion) {
    c.bench_function("create_space (Argon2id MIN)", |b| {
        b.iter_batched(
            scratch_path,
            |path| {
                let mut c = Container::create_with_options(&path, fast_options()).unwrap();
                let _s = c.create_space(b"pw").unwrap();
                drop(c);
                let _ = std::fs::remove_file(&path);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_open_space(c: &mut Criterion) {
    // Setup: file with one committed record. Reused across iterations.
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }
    c.bench_function("open_space (Argon2id MIN + scan)", |b| {
        b.iter(|| {
            let mut c = Container::open(&path).unwrap();
            let _s = c.open_space(b"pw").unwrap();
        });
    });
    let _ = std::fs::remove_file(&path);
}

fn bench_commit_single_kv(c: &mut Criterion) {
    c.bench_function("commit_single_kv (no Argon2)", |b| {
        b.iter_batched(
            || {
                let path = scratch_path();
                {
                    let mut cont = Container::create_with_options(&path, fast_options()).unwrap();
                    let _s = cont.create_space(b"pw").unwrap();
                } // drop releases lock so we reopen below
                path
            },
            |path| {
                {
                    let mut cont = Container::open(&path).unwrap();
                    let mut s = cont.open_space(b"pw").unwrap();
                    let mut tx = s.begin_tx();
                    tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
                    tx.commit().unwrap();
                }
                let _ = std::fs::remove_file(&path);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_commit_100_kv(c: &mut Criterion) {
    c.bench_function("commit_100_kv", |b| {
        b.iter_batched(
            || {
                let path = scratch_path();
                {
                    let mut cont = Container::create_with_options(&path, fast_options()).unwrap();
                    let _ = cont.create_space(b"pw").unwrap();
                }
                path
            },
            |path| {
                {
                    let mut cont = Container::open(&path).unwrap();
                    let mut s = cont.open_space(b"pw").unwrap();
                    let mut tx = s.begin_tx();
                    for i in 0..100u32 {
                        let k = format!("k{i:03}");
                        tx.put(Namespace::CONTACTS, k.as_bytes(), b"v").unwrap();
                    }
                    tx.commit().unwrap();
                }
                let _ = std::fs::remove_file(&path);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_commit_1000_kv(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_1000_kv");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(5));
    group.bench_function("forces B+ tree split", |b| {
        b.iter_batched(
            || {
                let path = scratch_path();
                {
                    let mut cont = Container::create_with_options(&path, fast_options()).unwrap();
                    let _ = cont.create_space(b"pw").unwrap();
                }
                path
            },
            |path| {
                {
                    let mut cont = Container::open(&path).unwrap();
                    let mut s = cont.open_space(b"pw").unwrap();
                    let mut tx = s.begin_tx();
                    for i in 0..1000u32 {
                        let k = format!("k{i:04}");
                        tx.put(Namespace::CONTACTS, k.as_bytes(), b"value").unwrap();
                    }
                    tx.commit().unwrap();
                }
                let _ = std::fs::remove_file(&path);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_commit_log_100(c: &mut Criterion) {
    c.bench_function("commit_log_100 (zstd batch)", |b| {
        b.iter_batched(
            || {
                let path = scratch_path();
                {
                    let mut cont = Container::create_with_options(&path, fast_options()).unwrap();
                    let _ = cont.create_space(b"pw").unwrap();
                }
                path
            },
            |path| {
                {
                    let mut cont = Container::open(&path).unwrap();
                    let mut s = cont.open_space(b"pw").unwrap();
                    let mut tx = s.begin_tx();
                    for i in 0..100u64 {
                        let payload = format!("message-content-{i:03}");
                        tx.append_log(Namespace::MESSAGE_LOG, i, payload.as_bytes())
                            .unwrap();
                    }
                    tx.commit().unwrap();
                }
                let _ = std::fs::remove_file(&path);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_get_random_kv(c: &mut Criterion) {
    // Setup: container with 1000 KV entries.
    let path = scratch_path();
    {
        let mut cont = Container::create_with_options(&path, fast_options()).unwrap();
        let mut s = cont.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..1000u32 {
            let k = format!("k{i:04}");
            tx.put(
                Namespace::CONTACTS,
                k.as_bytes(),
                format!("v{i}").as_bytes(),
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }

    c.bench_function("get_random_kv (1000 entries, 2-level B+)", |b| {
        let mut cont = Container::open(&path).unwrap();
        let mut s = cont.open_space(b"pw").unwrap();
        let mut counter = 0u32;
        b.iter(|| {
            let i = counter % 1000;
            counter += 1;
            let k = format!("k{i:04}");
            let _ = s.get(Namespace::CONTACTS, k.as_bytes()).unwrap();
        });
    });

    let _ = std::fs::remove_file(&path);
}

fn bench_read_log(c: &mut Criterion) {
    // Setup: container with 1000 log entries (10 batches of 100).
    let path = scratch_path();
    {
        let mut cont = Container::create_with_options(&path, fast_options()).unwrap();
        let mut s = cont.create_space(b"pw").unwrap();
        for batch in 0..10u64 {
            let mut tx = s.begin_tx();
            for i in 0..100u64 {
                let log_id = batch * 100 + i;
                tx.append_log(
                    Namespace::MESSAGE_LOG,
                    log_id,
                    format!("msg-{log_id:04}").as_bytes(),
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
    }

    c.bench_function("read_log (1000 msgs, 10 batches)", |b| {
        let mut cont = Container::open(&path).unwrap();
        let mut s = cont.open_space(b"pw").unwrap();
        let mut counter = 0u64;
        b.iter(|| {
            let id = counter % 1000;
            counter += 1;
            let _ = s.read_log(Namespace::MESSAGE_LOG, id).unwrap();
        });
    });

    let _ = std::fs::remove_file(&path);
}

fn bench_repack_1000(c: &mut Criterion) {
    let mut group = c.benchmark_group("repack_1000");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(5));
    group.bench_function("1000 KV + 100 log msgs", |b| {
        b.iter_batched(
            || {
                let src = scratch_path();
                {
                    let mut cont = Container::create_with_options(&src, fast_options()).unwrap();
                    let mut s = cont.create_space(b"pw").unwrap();
                    let mut tx = s.begin_tx();
                    for i in 0..1000u32 {
                        let k = format!("k{i:04}");
                        tx.put(Namespace::CONTACTS, k.as_bytes(), b"value").unwrap();
                    }
                    for i in 0..100u64 {
                        tx.append_log(Namespace::MESSAGE_LOG, i, format!("msg{i}").as_bytes())
                            .unwrap();
                    }
                    tx.commit().unwrap();
                }
                let dst = scratch_path();
                (src, dst)
            },
            |(src, dst)| {
                use hidden_volume::container::RepackOptions;
                let opts = RepackOptions {
                    argon2: Argon2Params::MIN,
                    ..Default::default()
                };
                Container::repack(&src, &dst, &[b"pw"], opts).unwrap();
                let _ = std::fs::remove_file(&src);
                let _ = std::fs::remove_file(&dst);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

/// Build a realistically-sized messenger container: 5000 KV + 1000 log
/// entries inflated with 10 000 garbage chunks of decoy padding to
/// reach a ~40 MiB file. Each garbage chunk still requires a trial
/// AEAD-decrypt during scan, so the container's slot count drives
/// scan cost — that's exactly the workload `parallel-scan` targets.
fn build_large_container(path: &std::path::Path) {
    let opts = ContainerOptions {
        argon2: Argon2Params::MIN,
        initial_garbage_chunks: 10_000,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 1,
    };
    let mut cont = Container::create_with_options(path, opts).unwrap();
    let mut s = cont.create_space(b"pw").unwrap();

    // KV — committed in one tx; B+ tree splits cleanly.
    {
        let mut tx = s.begin_tx();
        for i in 0..5000u32 {
            tx.put(Namespace::CONTACTS, format!("k{i:05}").as_bytes(), b"value")
                .unwrap();
        }
        tx.commit().unwrap();
    }
    // Log — chunk into 200-entry batches so each DataBatch fits under
    // PAYLOAD_CAP. 1000 / 200 = 5 batches × 5 commits.
    for chunk_start in (1..=1000u64).step_by(200) {
        let mut tx = s.begin_tx();
        let end = (chunk_start + 199).min(1000);
        for id in chunk_start..=end {
            tx.append_log(Namespace::MESSAGE_LOG, id, format!("msg{id:04}").as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
    }
}

fn bench_open_large_sequential(c: &mut Criterion) {
    let path = scratch_path();
    build_large_container(&path);
    c.bench_function("open_large_sequential (5000 KV + 1000 log)", |b| {
        b.iter(|| {
            let mut c = Container::open(&path).unwrap();
            let _s = c.open_space(b"pw").unwrap();
        });
    });
    let _ = std::fs::remove_file(&path);
}

#[cfg(all(feature = "parallel-scan", unix))]
fn bench_open_large_parallel(c: &mut Criterion) {
    let path = scratch_path();
    build_large_container(&path);
    c.bench_function("open_large_parallel (5000 KV + 1000 log)", |b| {
        b.iter(|| {
            let mut c = Container::open(&path).unwrap();
            let _s = c.open_space_parallel(b"pw").unwrap();
        });
    });
    let _ = std::fs::remove_file(&path);
}

/// Builds a "huge" container with `garbage` initial-garbage chunks to
/// stress-test the scan path at messenger-realistic scale (≥ 200 MiB).
/// The owned chunks (real messenger data) are tiny relative to the
/// garbage chunks, which dominate scan time.
fn build_huge_container(path: &std::path::Path, garbage: u64) {
    let opts = ContainerOptions {
        argon2: Argon2Params::MIN,
        initial_garbage_chunks: garbage,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 1,
    };
    let mut cont = Container::create_with_options(path, opts).unwrap();
    let mut s = cont.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for i in 0..200u32 {
        tx.put(Namespace::CONTACTS, format!("k{i:03}").as_bytes(), b"v")
            .unwrap();
    }
    tx.commit().unwrap();
}

fn bench_open_50k_sequential(c: &mut Criterion) {
    let path = scratch_path();
    build_huge_container(&path, 50_000);
    let mut group = c.benchmark_group("open_50k");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(8));
    group.bench_function("sequential (~200 MiB / 50K slots)", |b| {
        b.iter(|| {
            let mut c = Container::open(&path).unwrap();
            let _s = c.open_space(b"pw").unwrap();
        });
    });
    group.finish();
    let _ = std::fs::remove_file(&path);
}

#[cfg(all(feature = "parallel-scan", unix))]
fn bench_open_50k_parallel(c: &mut Criterion) {
    let path = scratch_path();
    build_huge_container(&path, 50_000);
    let mut group = c.benchmark_group("open_50k");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(8));
    group.bench_function("parallel (~200 MiB / 50K slots)", |b| {
        b.iter(|| {
            let mut c = Container::open(&path).unwrap();
            let _s = c.open_space_parallel(b"pw").unwrap();
        });
    });
    group.finish();
    let _ = std::fs::remove_file(&path);
}

fn bench_open_100k_sequential(c: &mut Criterion) {
    let path = scratch_path();
    build_huge_container(&path, 100_000);
    let mut group = c.benchmark_group("open_100k");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(15));
    group.bench_function("sequential (~400 MiB / 100K slots)", |b| {
        b.iter(|| {
            let mut c = Container::open(&path).unwrap();
            let _s = c.open_space(b"pw").unwrap();
        });
    });
    group.finish();
    let _ = std::fs::remove_file(&path);
}

#[cfg(all(feature = "parallel-scan", unix))]
fn bench_open_100k_parallel(c: &mut Criterion) {
    let path = scratch_path();
    build_huge_container(&path, 100_000);
    let mut group = c.benchmark_group("open_100k");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(15));
    group.bench_function("parallel (~400 MiB / 100K slots)", |b| {
        b.iter(|| {
            let mut c = Container::open(&path).unwrap();
            let _s = c.open_space_parallel(b"pw").unwrap();
        });
    });
    group.finish();
    let _ = std::fs::remove_file(&path);
}

fn bench_iter_log_full(c: &mut Criterion) {
    // Set up 1000-msg log (across 5 batches via repeated commits).
    let path = scratch_path();
    {
        let mut cont = Container::create_with_options(&path, fast_options()).unwrap();
        let mut s = cont.create_space(b"pw").unwrap();
        for chunk_start in (1..=1000u64).step_by(200) {
            let mut tx = s.begin_tx();
            let end = (chunk_start + 199).min(1000);
            for id in chunk_start..=end {
                tx.append_log(Namespace::MESSAGE_LOG, id, format!("msg{id:04}").as_bytes())
                    .unwrap();
            }
            tx.commit().unwrap();
        }
    }
    let mut cont = Container::open(&path).unwrap();
    let mut s = cont.open_space(b"pw").unwrap();
    c.bench_function("iter_log_full (1000 msgs, 5 batches)", |b| {
        b.iter(|| {
            let _ = s.iter_log(Namespace::MESSAGE_LOG).unwrap();
        });
    });
    drop(s);
    drop(cont);
    let _ = std::fs::remove_file(&path);
}

fn bench_iter_log_paged_50(c: &mut Criterion) {
    // Same 1000-msg log; bench the messenger-typical "load 50 newest".
    let path = scratch_path();
    {
        let mut cont = Container::create_with_options(&path, fast_options()).unwrap();
        let mut s = cont.create_space(b"pw").unwrap();
        for chunk_start in (1..=1000u64).step_by(200) {
            let mut tx = s.begin_tx();
            let end = (chunk_start + 199).min(1000);
            for id in chunk_start..=end {
                tx.append_log(Namespace::MESSAGE_LOG, id, format!("msg{id:04}").as_bytes())
                    .unwrap();
            }
            tx.commit().unwrap();
        }
    }
    let mut cont = Container::open(&path).unwrap();
    let mut s = cont.open_space(b"pw").unwrap();
    c.bench_function("iter_log_before_50 (1000-msg log, newest 50)", |b| {
        b.iter(|| {
            let _ = s.iter_log_before(Namespace::MESSAGE_LOG, None, 50).unwrap();
        });
    });
    drop(s);
    drop(cont);
    let _ = std::fs::remove_file(&path);
}

fn bench_verify_integrity(c: &mut Criterion) {
    // Multi-namespace tree to exercise the full Merkle walk.
    let path = scratch_path();
    {
        let mut cont = Container::create_with_options(&path, fast_options()).unwrap();
        let mut s = cont.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..1000u32 {
            tx.put(Namespace::CONTACTS, format!("k{i:04}").as_bytes(), b"v")
                .unwrap();
        }
        for i in 0..100u32 {
            tx.put(Namespace::SETTINGS, format!("s{i:03}").as_bytes(), b"v")
                .unwrap();
        }
        tx.commit().unwrap();
    }
    let mut cont = Container::open(&path).unwrap();
    let mut s = cont.open_space(b"pw").unwrap();
    c.bench_function("verify_integrity (1000 KV + 100 KV, 2 namespaces)", |b| {
        b.iter(|| {
            let _ = s.verify_integrity().unwrap();
        });
    });
    drop(s);
    drop(cont);
    let _ = std::fs::remove_file(&path);
}

#[cfg(not(all(feature = "parallel-scan", unix)))]
fn bench_open_large_parallel(_c: &mut Criterion) {
    // Sequential build only — parallel-scan bench is no-op without the feature.
}

#[cfg(not(all(feature = "parallel-scan", unix)))]
fn bench_open_50k_parallel(_c: &mut Criterion) {}

#[cfg(not(all(feature = "parallel-scan", unix)))]
fn bench_open_100k_parallel(_c: &mut Criterion) {}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .measurement_time(Duration::from_secs(3))
        .warm_up_time(Duration::from_millis(500));
    targets =
        bench_create_space,
        bench_open_space,
        bench_commit_single_kv,
        bench_commit_100_kv,
        bench_commit_1000_kv,
        bench_commit_log_100,
        bench_get_random_kv,
        bench_read_log,
        bench_repack_1000,
        bench_open_large_sequential,
        bench_open_large_parallel,
        bench_open_50k_sequential,
        bench_open_50k_parallel,
        bench_open_100k_sequential,
        bench_open_100k_parallel,
        bench_iter_log_full,
        bench_iter_log_paged_50,
        bench_verify_integrity
}
criterion_main!(benches);
