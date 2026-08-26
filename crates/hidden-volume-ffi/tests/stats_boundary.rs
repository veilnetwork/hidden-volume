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

/// The 64-byte `SpaceKeys` wire form the FFI takes: container_id then
/// aead_root.
///
/// Derived from a THROWAWAY COPY. A writable `open_space` auto-vacuums, which
/// collects exactly the orphan pool these fixtures are built to measure — so
/// deriving from the file under test drained it before the reader ever saw it,
/// and the comparison became 0 against 39.
fn space_keys_of(path: &std::path::Path) -> Vec<u8> {
    let scratch_copy = scratch();
    let _c = Cleanup(scratch_copy.clone());
    std::fs::copy(path, &scratch_copy).unwrap();

    let mut c = Container::open(&scratch_copy).unwrap();
    let s = c.open_space(b"pw").unwrap();
    let k = s.space_keys();
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&k.container_id);
    out.extend_from_slice(&k.aead_root);
    out
}

// ── The multi-space handle had no stats at all ──────────────────────────────
//
// A host running several identities over ONE container is exactly the
// configuration that got no answer: its storage layer reported `null` for both
// the utilization and the hardening record, and `null` is indistinguishable
// from "nothing is wrong". A masking, churn or sync step that failed after a
// commit was therefore never shown to anybody, on the container where it was
// least visible — and the acknowledgement had nothing to call, so it either did
// nothing while reporting success or refused outright (report16 XV-08).

/// The multi-space handle answers with the SAME numbers the core does for the
/// same space.
///
/// Equality against the core, for the reason the single-space test above gives:
/// a plumbing bug that returned some other field this struct already carries
/// would satisfy any "looks plausible" check.
#[test]
fn multi_space_stats_carry_the_core_s_values() {
    use hidden_volume_ffi::MultiSpaceHandle;

    let path = scratch();
    let _c = Cleanup(path.clone());
    build_orphans(&path);

    let twin = scratch();
    let _t = Cleanup(twin.clone());
    std::fs::copy(&path, &twin).unwrap();

    let keys = space_keys_of(&path);

    let across = {
        let handle = MultiSpaceHandle::open(path.to_string_lossy().into_owned()).unwrap();
        let id = handle.open_space(keys.clone()).unwrap();
        // The constant-time open defers the orphan vacuum (audit HV-01), same
        // as the single-space path.
        handle.vacuum_space(id).unwrap();
        handle.stats(id).unwrap()
    };

    let core = {
        let mut c = Container::open(&twin).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        s.stats().unwrap()
    };

    assert_eq!(across.reusable_slot_count, core.reusable_slot_count);
    assert_eq!(across.total_slot_count, core.total_slot_count);
    assert_eq!(across.commit_seq, core.commit_seq);
    assert!(
        across.reusable_slot_count > 0,
        "premise: the fixture must leave a pool, or the equality above is \
         0 == 0 and proves nothing"
    );
}

/// A healthy space reports NO hardening failure — the field is read, not
/// hardcoded — and the acknowledgement is reachable and idempotent.
///
/// The stickiness of the record itself is proved in the core, where the
/// fault-injection hooks live. What is pinned here is that this surface exists
/// at all: it did not, which is why the layer above answered `null` and called
/// it "nothing is wrong".
#[test]
fn multi_space_hardening_is_reported_and_acknowledgeable() {
    use hidden_volume_ffi::MultiSpaceHandle;

    let path = scratch();
    let _c = Cleanup(path.clone());
    build_orphans(&path);

    let keys = space_keys_of(&path);

    let handle = MultiSpaceHandle::open(path.to_string_lossy().into_owned()).unwrap();
    let id = handle.open_space(keys.clone()).unwrap();

    assert!(
        handle.stats(id).unwrap().hardening_failure.is_none(),
        "a healthy space must report nothing, or a host cannot tell a real \
         record from a constant"
    );

    handle.acknowledge_hardening_error(id).unwrap();
    handle
        .acknowledge_hardening_error(id)
        .expect("acknowledging twice is not an error");
    assert!(handle.stats(id).unwrap().hardening_failure.is_none());
}

/// A space id nobody hosts is refused rather than answered for somebody else.
#[test]
fn multi_space_stats_refuse_an_id_that_is_not_hosted() {
    use hidden_volume_ffi::MultiSpaceHandle;

    let path = scratch();
    let _c = Cleanup(path.clone());
    build_orphans(&path);

    let handle = MultiSpaceHandle::open(path.to_string_lossy().into_owned()).unwrap();
    assert!(handle.stats(0).is_err(), "stats for a space nobody opened");
    assert!(
        handle.acknowledge_hardening_error(0).is_err(),
        "acknowledged a record on a space nobody opened"
    );
}

/// A hardening failure that DID happen crosses, and the acknowledgement
/// clears it.
///
/// The test above can only see a healthy space, and "reports nothing" is what
/// a surface that reports nothing whatever happens also does — which is the
/// defect, not the fix. Broken by returning `None` unconditionally, that test
/// stayed green.
///
/// The core's `hardening_hooks` seam makes the post-commit fsync fail on this
/// thread. It needs `--features test-hooks`; without it this case is skipped
/// rather than silently absent.
#[cfg(feature = "test-hooks")]
#[test]
fn multi_space_reports_a_hardening_failure_that_happened() {
    use hidden_volume::space::hardening_hooks;
    use hidden_volume_ffi::MultiSpaceHandle;

    let path = scratch();
    let _c = Cleanup(path.clone());
    build_orphans(&path);
    let keys = space_keys_of(&path);

    let handle = MultiSpaceHandle::open(path.to_string_lossy().into_owned()).unwrap();
    let id = handle.open_space(keys).unwrap();
    assert!(
        handle.stats(id).unwrap().hardening_failure.is_none(),
        "premise: nothing recorded before the forced failure"
    );

    hardening_hooks::set_sync_fails(true);
    let commit = handle.commit(
        id,
        vec![hidden_volume_ffi::WriteOp::Put {
            namespace: hidden_volume::space::index::Namespace::SETTINGS.as_u8(),
            key: b"k".to_vec(),
            value: b"v".to_vec(),
        }],
    );
    hardening_hooks::set_sync_fails(false);
    commit.expect("the commit itself is durable — only its masking failed");

    let recorded = handle
        .stats(id)
        .unwrap()
        .hardening_failure
        .expect("the failed step never reached the host");
    assert!(
        format!("{recorded:?}").to_lowercase().contains("sync"),
        "the step is not named: {recorded:?}"
    );

    handle.acknowledge_hardening_error(id).unwrap();
    assert!(
        handle.stats(id).unwrap().hardening_failure.is_none(),
        "the acknowledgement did not clear the record"
    );
}
