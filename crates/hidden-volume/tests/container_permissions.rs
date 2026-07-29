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
