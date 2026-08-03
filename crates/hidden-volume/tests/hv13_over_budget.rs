//! Audit HV-13 — an over-budget container is too big, not broken.
//!
//! `MAX_OPEN_SCAN_CHUNKS` caps the open scan at 16M chunks (64 GiB). Both
//! sides of the cap have been symmetric since audit pass 17 B: the write side
//! refuses to produce a file the read side would reject. What was NOT
//! symmetric was the ANSWER. The write side said `ContainerTooLarge { .. }`,
//! naming the cap and the count; the read side said
//! `Malformed("container exceeds open-scan budget")` — the corruption error.
//!
//! Those two demand opposite responses from a host app. A malformed container
//! has lost its data and the user needs to be told so. An over-budget one has
//! lost nothing: every byte is what the writer wrote, and it is reachable
//! again by splitting the file. Reporting the first for the second is an
//! availability failure dressed as a data-loss one.
//!
//! Scope of the finding, for the record: growing a container past the cap
//! needs write access to the file, and the threat model already concedes
//! denial of service to an adversary who has that ("the adversary already has
//! T2 (file write) access — at that point DoS is largely conceded"). Someone
//! who can append 64 GiB can equally `truncate -s 0`. So this file does not
//! test a defence against that adversary; it tests that when a container IS
//! over budget — for whatever reason — the library says which problem it is.

use hidden_volume::Container;
use hidden_volume::container::ContainerOptions;

mod common;
use common::{fast_params, scratch_path};

const CAP: u64 = hidden_volume::MAX_OPEN_SCAN_CHUNKS;
const CHUNK: u64 = 4096;

/// The write side. Nothing new — this pins the shape the read side must now
/// match, so the two cannot drift apart again silently.
#[test]
fn a_write_over_the_budget_names_the_budget() {
    let path = scratch_path();

    let err = Container::create_with_options(
        &path,
        ContainerOptions {
            argon2: fast_params(),
            initial_garbage_chunks: CAP + 1,
            padding_policy: hidden_volume::padding::PaddingPolicy::None,
            superblock_replicas: 1,
        },
    )
    .expect_err("a container larger than the open-scan budget must be refused");

    match err {
        hidden_volume::Error::ContainerTooLarge { chunks, cap } => {
            assert_eq!(cap, CAP, "the error must name the actual cap");
            assert!(
                chunks > cap,
                "the error must name the count that tripped it ({chunks} vs {cap})"
            );
        },
        other => panic!("expected ContainerTooLarge, got {other:?}"),
    }

    let _ = std::fs::remove_file(&path);
}

/// The read side. An intact container that happens to sit past the cap must
/// report `ContainerTooLarge`, NOT `Malformed`.
///
/// Unix-only, and skipped on any filesystem that does not do sparse files: the
/// container is a real one grown to 64 GiB with `set_len`, which allocates
/// nothing on APFS / ext4 / xfs / btrfs. The test verifies that before it
/// proceeds rather than filling somebody's disk to make a point.
#[cfg(unix)]
#[test]
fn an_over_budget_container_is_reported_as_too_large_not_as_malformed() {
    use std::os::unix::fs::MetadataExt as _;

    let path = scratch_path();
    {
        let mut c = Container::create_with_options(
            &path,
            ContainerOptions {
                argon2: fast_params(),
                initial_garbage_chunks: 0,
                padding_policy: hidden_volume::padding::PaddingPolicy::None,
                superblock_replicas: 1,
            },
        )
        .unwrap();
        let _ = c.create_space(b"pw").unwrap();
    }

    // slot_count is `len / CHUNK_SIZE - 1`, so this leaves CAP + 1 slots: one
    // past the budget, the nearest possible miss. A test that overshot by a
    // wide margin would still pass if the comparison were `>=` instead of `>`.
    let target = (CAP + 2) * CHUNK;
    {
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(target).unwrap();
    }

    let allocated = std::fs::metadata(&path).unwrap().blocks() * 512;
    if allocated > 64 * 1024 * 1024 {
        // No sparse support here — do not proceed to fill the disk.
        let _ = std::fs::remove_file(&path);
        eprintln!("skipped: filesystem materialised the sparse extent ({allocated} bytes)");
        return;
    }

    let mut c = Container::open(&path).expect("the header is intact, so the open itself works");
    let err = c
        .open_space(b"pw")
        .expect_err("a container past the open-scan budget must not be scanned");

    match err {
        hidden_volume::Error::ContainerTooLarge { chunks, cap } => {
            assert_eq!(cap, CAP);
            assert_eq!(
                chunks,
                CAP + 1,
                "the error must name the observed slot count"
            );
        },
        hidden_volume::Error::Malformed(m) => panic!(
            "an intact container was reported as CORRUPT ({m:?}) for being large; a host \
             app cannot tell that from real data loss, and the two need opposite responses"
        ),
        other => panic!("expected ContainerTooLarge, got {other:?}"),
    }

    let _ = std::fs::remove_file(&path);
}

/// The same answer for the wrong password.
///
/// The budget check runs before any key material is touched, so it cannot
/// depend on which password was supplied — and it must not start to. If a
/// correct password produced one error and a wrong one another, the size gate
/// would have become a password oracle on files large enough to trip it.
#[cfg(unix)]
#[test]
fn the_budget_answer_does_not_depend_on_the_password() {
    use std::os::unix::fs::MetadataExt as _;

    let path = scratch_path();
    {
        let mut c = Container::create_with_options(
            &path,
            ContainerOptions {
                argon2: fast_params(),
                initial_garbage_chunks: 0,
                padding_policy: hidden_volume::padding::PaddingPolicy::None,
                superblock_replicas: 1,
            },
        )
        .unwrap();
        let _ = c.create_space(b"right").unwrap();
    }
    {
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len((CAP + 2) * CHUNK).unwrap();
    }
    if std::fs::metadata(&path).unwrap().blocks() * 512 > 64 * 1024 * 1024 {
        let _ = std::fs::remove_file(&path);
        return;
    }

    let mut c = Container::open(&path).unwrap();
    let with_right = format!("{:?}", c.open_space(b"right").unwrap_err());
    let with_wrong = format!("{:?}", c.open_space(b"wrong").unwrap_err());
    assert_eq!(
        with_right, with_wrong,
        "the size gate answered differently for a right and a wrong password"
    );

    let _ = std::fs::remove_file(&path);
}
