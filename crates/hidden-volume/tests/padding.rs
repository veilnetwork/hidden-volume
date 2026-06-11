//! Padding & pre-allocation integration tests.
//!
//! Verifies that:
//! - `initial_garbage_chunks` makes the file appear "preset-sized".
//! - `PaddingPolicy::BucketGrowth` quantizes file growth to bucket
//!   boundaries — observers see only discrete jumps.
//! - `PaddingPolicy::None` keeps the v0.2-default behavior (file
//!   grows by exact data amount).
//! - Padding does not affect data correctness (KV / log content).

use hidden_volume::container::ContainerOptions;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use hidden_volume::{CHUNK_SIZE, Container};

mod common;
use common::fast_params;

fn file_size(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).unwrap().len()
}

#[test]
fn initial_garbage_makes_file_appear_preset_sized() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let options = ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 100,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 1,
    };
    {
        let _c = Container::create_with_options(&path, options).unwrap();
    }

    // 1 header chunk + 100 garbage chunks = 101 * CHUNK_SIZE bytes.
    let expected = 101 * CHUNK_SIZE as u64;
    assert_eq!(file_size(&path), expected);

    // Reopen — file unchanged.
    {
        let _c = Container::open(&path).unwrap();
    }
    assert_eq!(file_size(&path), expected);

    std::fs::remove_file(&path).ok();
}

#[test]
fn bucket_growth_quantizes_file_size_after_commits() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let options = ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::BucketGrowth { bucket_chunks: 64 },
        superblock_replicas: 1,
    };
    let mut c = Container::create_with_options(&path, options).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    // After create_space (1 SB), the policy should have rounded the
    // file up to the next multiple of 64 chunks. Wait, no — padding
    // applies after commit_tx, and create_space writes a Superblock
    // directly without going through commit_tx. So slot_count = 1,
    // unrelated to bucket. Let's force a commit instead.
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
    tx.commit().unwrap();
    // After commit: slot_count should be a multiple of 64.
    let total_chunks = file_size(&path) / CHUNK_SIZE as u64;
    let slot_count = total_chunks - 1; // minus header
    assert_eq!(
        slot_count % 64,
        0,
        "slot_count={slot_count} not on bucket boundary"
    );

    // Multiple small commits stay within the same bucket.
    let baseline = slot_count;
    for i in 0..5u8 {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", &[i]).unwrap();
        tx.commit().unwrap();
    }
    let total_chunks = file_size(&path) / CHUNK_SIZE as u64;
    let new_slot_count = total_chunks - 1;
    // Each commit added 3 chunks (IndexNode + Commit + SB) = 15 total,
    // PLUS vacuum scrubs of orphans (don't grow file). Bucket is 64,
    // so expectation is: new_slot_count is still a multiple of 64,
    // either equal to baseline or one bucket up.
    assert_eq!(new_slot_count % 64, 0);
    assert!(new_slot_count >= baseline);

    std::fs::remove_file(&path).ok();
}

#[test]
fn no_padding_default_grows_by_exact_data() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let options = ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 1,
    };
    let mut c = Container::create_with_options(&path, options).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    let before = file_size(&path);
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
    tx.commit().unwrap();
    let after = file_size(&path);

    // Exactly 3 chunks added: 1 IndexNode + 1 Commit + 1 Superblock.
    assert_eq!(after - before, 3 * CHUNK_SIZE as u64);

    std::fs::remove_file(&path).ok();
}

#[test]
fn padding_does_not_corrupt_data() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let options = ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 50,
        padding_policy: PaddingPolicy::BucketGrowth { bucket_chunks: 32 },
        superblock_replicas: 1,
    };
    {
        let mut c = Container::create_with_options(&path, options).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..20u32 {
            let k = format!("key{i:02}");
            let v = format!("value{i}");
            tx.put(Namespace::CONTACTS, k.as_bytes(), v.as_bytes())
                .unwrap();
        }
        for i in 0..30u64 {
            tx.append_log(Namespace::MESSAGE_LOG, i, format!("msg{i}").as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 20);
    for i in 0..20u32 {
        let k = format!("key{i:02}");
        let want = format!("value{i}");
        assert_eq!(
            s.get(Namespace::CONTACTS, k.as_bytes()).unwrap().as_deref(),
            Some(want.as_bytes()),
        );
    }
    for i in 0..30u64 {
        let want = format!("msg{i}");
        let got = s.read_log(Namespace::MESSAGE_LOG, i).unwrap();
        assert_eq!(got.as_deref(), Some(want.as_bytes()));
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn padding_policy_can_change_at_runtime() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    assert_eq!(c.padding_policy(), PaddingPolicy::None);

    c.set_padding_policy(PaddingPolicy::BucketGrowth { bucket_chunks: 128 })
        .unwrap();
    assert_eq!(
        c.padding_policy(),
        PaddingPolicy::BucketGrowth { bucket_chunks: 128 }
    );

    // Commit one Tx — file should round up to next multiple of 128.
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
    tx.commit().unwrap();

    let total_chunks = file_size(&path) / CHUNK_SIZE as u64;
    let slot_count = total_chunks - 1;
    assert_eq!(slot_count % 128, 0);

    std::fs::remove_file(&path).ok();
}

#[test]
fn fixed_ratio_padding_appends_proportional_garbage() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let options = ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        // 200% = 2 garbage chunks per real chunk.
        padding_policy: PaddingPolicy::FixedRatio {
            garbage_per_real_x100: 200,
        },
        superblock_replicas: 1,
    };
    let mut c = Container::create_with_options(&path, options).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    let before = file_size(&path);
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
    tx.commit().unwrap();
    let after = file_size(&path);
    let added_chunks = (after - before) / CHUNK_SIZE as u64;

    // Real: 1 IndexNode + 1 Commit + 1 SB = 3 chunks.
    // Padding: 3 * 2 = 6 garbage chunks. Total = 9.
    assert_eq!(added_chunks, 9);

    std::fs::remove_file(&path).ok();
}

#[test]
fn open_restores_persisted_padding() {
    // Audit pass 8 (S1 full): padding policy IS persisted in the
    // cleartext header now (1-byte preset index in
    // Argon2Params.version bits 16..24). The 64-bucket preset is
    // representable (index 1), so reopen restores it.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let options = ContainerOptions {
            argon2: fast_params(),
            initial_garbage_chunks: 0,
            padding_policy: PaddingPolicy::BucketGrowth { bucket_chunks: 64 },
            superblock_replicas: 1,
        };
        let mut c = Container::create_with_options(&path, options).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }

    let c = Container::open(&path).unwrap();
    assert_eq!(
        c.padding_policy(),
        PaddingPolicy::BucketGrowth { bucket_chunks: 64 }
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn many_commits_with_bucket_growth_stay_quantized() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let options = ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::BucketGrowth { bucket_chunks: 32 },
        superblock_replicas: 1,
    };
    let mut c = Container::create_with_options(&path, options).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    // Force many commits; check file size is ALWAYS on bucket boundary
    // after every commit.
    for i in 0..30u32 {
        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, format!("k{i}").as_bytes(), b"v")
            .unwrap();
        tx.commit().unwrap();

        let slot_count = file_size(&path) / CHUNK_SIZE as u64 - 1;
        assert_eq!(
            slot_count % 32,
            0,
            "after commit {i}: slot_count={slot_count} not on 32-bucket boundary"
        );
    }

    std::fs::remove_file(&path).ok();
}

/// Audit pass 8 (S1 full): padding policy is persisted in the
/// cleartext header (Argon2Params.version bits 16..24) at create
/// time, and auto-applied on every reopen. Previously, host-app had
/// to call `set_padding_policy` after every open or risk silently
/// degrading multi-snapshot privacy (the policy was runtime-only).
#[test]
fn padding_policy_persists_across_reopen() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    // Create with the 1 MiB-bucket preset (persistable).
    let opts = ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::BucketGrowth { bucket_chunks: 256 },
        superblock_replicas: 1,
    };
    {
        let mut c = Container::create_with_options(&path, opts).unwrap();
        let _ = c.create_space(b"pw").unwrap();
        // Confirm policy is active.
        assert_eq!(
            c.padding_policy(),
            PaddingPolicy::BucketGrowth { bucket_chunks: 256 }
        );
    }

    // Reopen — policy should be auto-restored from the header.
    {
        let c = Container::open(&path).unwrap();
        assert_eq!(
            c.padding_policy(),
            PaddingPolicy::BucketGrowth { bucket_chunks: 256 },
            "create-time padding policy must persist across reopen"
        );
    }

    std::fs::remove_file(&path).ok();
}

/// Audit pass 10 (I1): preset index 3 (16 MiB buckets) round-trip
/// across reopen. The existing `padding_policy_persists_across_reopen`
/// covers index 2 (1 MiB / `bucket_chunks: 256`, the DEFAULT preset);
/// this one exercises the largest preset, which is the desktop-class
/// recommendation and the one most likely to surface a bit-shift bug
/// in the high end of `padding_policy_index`.
#[test]
fn padding_policy_persists_across_reopen_idx3() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let opts = ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        // Index 3 → 16 MiB buckets = 4096 chunks.
        padding_policy: PaddingPolicy::BucketGrowth {
            bucket_chunks: 4096,
        },
        superblock_replicas: 1,
    };
    {
        let mut c = Container::create_with_options(&path, opts).unwrap();
        let _ = c.create_space(b"pw").unwrap();
        assert_eq!(
            c.padding_policy(),
            PaddingPolicy::BucketGrowth {
                bucket_chunks: 4096
            }
        );
    }

    let c = Container::open(&path).unwrap();
    assert_eq!(
        c.padding_policy(),
        PaddingPolicy::BucketGrowth {
            bucket_chunks: 4096
        },
        "16 MiB-bucket preset (idx 3) must persist across reopen"
    );

    std::fs::remove_file(&path).ok();
}

/// Audit pass 10 (I1): preset index 1 (256 KiB buckets) round-trip.
/// Lowest preset, intended for embedded / weak phones.
#[test]
fn padding_policy_persists_across_reopen_idx1() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let opts = ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::BucketGrowth { bucket_chunks: 64 },
        superblock_replicas: 1,
    };
    {
        let mut c = Container::create_with_options(&path, opts).unwrap();
        let _ = c.create_space(b"pw").unwrap();
    }

    let c = Container::open(&path).unwrap();
    assert_eq!(
        c.padding_policy(),
        PaddingPolicy::BucketGrowth { bucket_chunks: 64 },
        "256 KiB-bucket preset (idx 1) must persist across reopen"
    );

    std::fs::remove_file(&path).ok();
}

/// Audit pass 10 (I1): preset index 0 (None) round-trip. The
/// degenerate but still-load-bearing case — pre-pass-8 containers
/// have version=1 (upper bits all zero) and must continue to decode
/// as `PaddingPolicy::None`.
#[test]
fn padding_policy_persists_across_reopen_idx0() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let opts = ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 1,
    };
    {
        let mut c = Container::create_with_options(&path, opts).unwrap();
        let _ = c.create_space(b"pw").unwrap();
    }

    let c = Container::open(&path).unwrap();
    assert_eq!(
        c.padding_policy(),
        PaddingPolicy::None,
        "None (idx 0) must persist across reopen — covers pre-pass-8 backward-compat"
    );

    std::fs::remove_file(&path).ok();
}

/// Custom (non-preset) padding policies cannot be encoded into the
/// 1-byte header field — for those, the host-app must still call
/// `set_padding_policy` after every open. This test confirms that:
/// on reopen of a container created with `FixedRatio`, the policy
/// resets to `None` (default for unknown / unrepresentable index).
#[test]
fn custom_padding_policy_not_persisted() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let opts = ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::FixedRatio {
            garbage_per_real_x100: 50,
        },
        superblock_replicas: 1,
    };
    {
        let mut c = Container::create_with_options(&path, opts).unwrap();
        let _ = c.create_space(b"pw").unwrap();
    }

    let c = Container::open(&path).unwrap();
    // FixedRatio doesn't fit the 1-byte preset table → resets to None.
    assert_eq!(c.padding_policy(), PaddingPolicy::None);

    std::fs::remove_file(&path).ok();
}
