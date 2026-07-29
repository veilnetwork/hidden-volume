//! A new container must be readable by its owner only.
//!
//! The bytes inside are encrypted, so this is not what keeps them secret. It
//! matters because the container is *deniable*: a world-readable file tells
//! every other local account that it exists and how big it is, which is the
//! single fact the design spends its whole budget hiding. It also lets that
//! account copy the ciphertext and attack it offline, unhurried.
//!
//! `OpenOptions::create_new` alone leaves the mode to the process umask — 0644
//! on a typical desktop.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use hidden_volume::Container;

mod common;
use common::fast_params;

#[test]
fn a_new_container_is_owner_only() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let container = Container::create(&path, fast_params()).unwrap();
    drop(container);

    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "group and other must not be able to stat or copy the container"
    );

    let _ = std::fs::remove_file(&path);
}

/// A create that fails must not leave the path occupied.
///
/// `ContainerFile::create` writes the header first and opens with
/// `create_new`, so a failure afterwards — an over-large initial-garbage
/// request, ENOSPC on a full disk — used to return Err and leave a 4096-byte
/// stub behind. The retry the caller obviously makes next then hit
/// AlreadyExists, and the path stayed unusable until someone deleted a file
/// they never knowingly created.
#[test]
fn a_failed_create_leaves_no_file_behind() {
    use hidden_volume::container::ContainerOptions;
    use hidden_volume::padding::PaddingPolicy;

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    // Past the write-side budget, so this fails on arithmetic rather than by
    // trying to write tens of gigabytes.
    let doomed = ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: u64::MAX / 2,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 1,
    };
    assert!(
        Container::create_with_options(&path, doomed).is_err(),
        "the oversized request should have been refused"
    );
    assert!(
        !path.exists(),
        "a failed create left the path occupied; the retry below is what a \
         caller actually does next, and it could not succeed"
    );

    // And the obvious retry works.
    let ok = Container::create_with_options(
        &path,
        ContainerOptions {
            argon2: fast_params(),
            initial_garbage_chunks: 0,
            padding_policy: PaddingPolicy::None,
            superblock_replicas: 1,
        },
    );
    assert!(ok.is_ok(), "retry after a failed create must succeed");
    drop(ok);
    let _ = std::fs::remove_file(&path);
}
