//! What `StatsInfo` carries across the boundary, and what it used to drop
//! (report10 HV-04).
//!
//! Two numbers the core has always held never reached a foreign caller:
//!
//! * `reusable_slot_count` — the decoy pool. Without it a host deciding
//!   whether to `compact_known` has only `utilization_ratio`, and that half
//!   answers wrongly in both directions: it reads a healthily recycling
//!   container as sparse (so the host rewrites the whole file and rotates the
//!   `container_id` for nothing) and cannot distinguish it from one that
//!   genuinely needs compaction.
//! * the post-commit hardening record — whether a commit's padding, churn or
//!   fsync failed. The commit is durable; its MASKING is not what was
//!   promised, and nobody downstream could be told.
//!
//! The hardening record's own stickiness is proved in the core, where the
//! fault-injection hooks live (`space::reuse_tests`). What this file holds is
//! the boundary: that the field exists, that it decodes as absent on a healthy
//! space rather than being hardcoded to anything, that the acknowledgement is
//! reachable and idempotent, and that `reusable_slot_count` arrives carrying
//! THE CORE'S value rather than a plausible constant.

use hidden_volume::Container;
use hidden_volume::container::ContainerOptions;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use hidden_volume_ffi::SpaceHandle;

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

/// Leave a container whose next open will retire orphan index chunks into a
/// pool. Every commit here supersedes the previous KV index, so the superseded
/// IndexNode chunks accumulate and the vacuum on the NEXT open collects them.
///
/// Built through the CORE api on purpose: a fixture that produced its pool
/// through the FFI would be asserting against a number the FFI itself chose.
fn build_orphans(path: &std::path::Path) {
    let mut c = Container::create_with_options(
        path,
        ContainerOptions {
            argon2: Argon2Params::MIN,
            initial_garbage_chunks: 0,
            padding_policy: PaddingPolicy::None,
            superblock_replicas: 1,
        },
    )
    .unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    for i in 0..40u32 {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, format!("k{i}").as_bytes(), b"v")
            .unwrap();
        tx.commit().unwrap();
    }
}

/// The pool size the core holds is the pool size the host is told.
///
/// Asserted as EQUALITY against the core reading the same file, not as
/// "greater than zero". A plumbing bug that reported `total_slot_count`, or the
/// owned count, or any other number this struct already carries would satisfy a
/// non-zero check and be wrong by exactly the amount that matters — the whole
/// point of the field is that it is a different quantity from the ratio the
/// host already had.
#[test]
fn reusable_slot_count_crosses_carrying_the_core_s_value() {
    let path = scratch();
    let _c = Cleanup(path.clone());
    build_orphans(&path);

    // TWO byte-identical copies, one per reader. The orphan vacuum that builds
    // the pool WRITES — it scrubs what it retires — so running both readers
    // against one file would leave the second with nothing to collect and an
    // empty pool to report. Same input bytes and the same vacuum on each side
    // is what makes the two numbers comparable at all.
    let twin = scratch();
    let _t = Cleanup(twin.clone());
    std::fs::copy(&path, &twin).unwrap();

    let across = {
        let handle =
            SpaceHandle::open(path.to_string_lossy().into_owned(), b"pw".to_vec()).unwrap();
        // The constant-time open defers the orphan vacuum (audit HV-01), so the
        // pool this reports is built here rather than during `open`.
        handle.vacuum_after_open().unwrap();
        handle.stats().unwrap()
    };

    let core = {
        let mut c = Container::open(&twin).unwrap();
        // `open_space` auto-vacuums on a writable handle — the same collection
        // the call above ran explicitly.
        let mut s = c.open_space(b"pw").unwrap();
        s.stats().unwrap()
    };

    assert!(
        core.reusable_slot_count > 0,
        "the fixture produced no pool, so this test cannot tell a correct \
         plumbing from one that returns zero"
    );
    assert_eq!(
        across.reusable_slot_count, core.reusable_slot_count,
        "the pool size did not survive the boundary"
    );
    // And it is not one of the numbers that were already crossing. If the field
    // were wired to either of those, the equality above would still hold only
    // by coincidence — this says the coincidence is not available.
    assert_ne!(
        across.reusable_slot_count, across.total_slot_count,
        "reusable_slot_count is indistinguishable from total_slot_count in \
         this fixture, so the assertion above proves nothing about which one \
         was plumbed"
    );
    assert_ne!(
        across.reusable_slot_count, across.owned_chunk_count,
        "same, for owned_chunk_count"
    );
}

/// A healthy space reports no hardening failure, and the acknowledgement is
/// reachable from the foreign side.
///
/// `None` here is the honest answer, not a stub: the core-side tests prove the
/// field becomes `Some(_)` when a step actually fails, and this proves that
/// what crosses on a good commit is absence rather than a default the plumbing
/// invents.
#[test]
fn a_healthy_space_reports_no_hardening_failure_and_can_be_acknowledged() {
    let path = scratch();
    let _c = Cleanup(path.clone());

    let handle = SpaceHandle::create(
        path.to_string_lossy().into_owned(),
        b"pw".to_vec(),
        hidden_volume_ffi::ArgonPreset::Min,
        0,
        1,
    )
    .unwrap();
    handle
        .commit(vec![hidden_volume_ffi::WriteOp::Put {
            namespace: 1,
            key: b"k".to_vec(),
            value: b"v".to_vec(),
        }])
        .unwrap();

    let before = handle.stats().unwrap();
    assert!(
        before.hardening_failure.is_none(),
        "a commit whose padding, churn and fsync all ran reported a failure: \
         {:?}",
        before.hardening_failure
    );

    // Idempotent on an empty record, and it must not disturb the rest of the
    // struct — a host is expected to call this on a schedule, not only when it
    // has something to dismiss.
    handle.acknowledge_hardening_error().unwrap();
    handle.acknowledge_hardening_error().unwrap();

    let after = handle.stats().unwrap();
    assert!(after.hardening_failure.is_none());
    assert_eq!(after.commit_seq, before.commit_seq);
    assert_eq!(after.total_entries, before.total_entries);
    assert_eq!(after.reusable_slot_count, before.reusable_slot_count);
}
