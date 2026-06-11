//! Shared helpers for the integration test suite. Audit C5+C6
//! (2026-05-03): previously every test file (~27 of 35) defined its
//! own `fast_params()` returning `Argon2Params::MIN`, and ~20 defined
//! its own `scratch_path()` creating a tempfile, dropping the handle,
//! and returning the path. Centralised here.
//!
//! ## Why `common/mod.rs` and not `common.rs`?
//!
//! Cargo treats `tests/*.rs` as separate integration-test crates,
//! each with `#[test]` discovery. A bare `tests/common.rs` would
//! become a test crate of its own (with zero tests, producing a
//! noisy "no tests run" line). Putting helpers in
//! `tests/common/mod.rs` is the canonical Rust idiom: cargo treats
//! the directory as a non-test module that other test files include
//! via `mod common;`.
//!
//! Per-test-file usage:
//!
//! ```ignore
//! mod common;
//! use common::{fast_params, scratch_path};
//! ```
//!
//! `#[allow(dead_code)]` on each helper because not every including
//! test file uses both — Rust would otherwise warn about the unused
//! one in some files.

use hidden_volume::crypto::kdf::Argon2Params;

/// Minimum-cost Argon2id params (~30 ms on commodity x86, lower on
/// dev hosts with larger caches). Use in any test that doesn't
/// specifically target Argon2 cost — full DEFAULT params would add
/// ~100 ms per `create_space` / `open_space` call across 300+ tests.
#[allow(
    dead_code,
    reason = "consumed by ~27 test files; not all use it directly"
)]
pub fn fast_params() -> Argon2Params {
    Argon2Params::MIN
}

/// Allocate a scratch path that does not exist on disk: create a
/// `NamedTempFile`, take its path, drop the handle (so `Container::create`
/// can claim the path itself), and return the `PathBuf`.
///
/// Caller is responsible for `std::fs::remove_file` on cleanup if the
/// test creates the file. (Most tests do this in a `let _ =
/// std::fs::remove_file(&path);` line at the end.)
#[allow(
    dead_code,
    reason = "consumed by ~20 test files; not all use it directly"
)]
pub fn scratch_path() -> std::path::PathBuf {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let p = tmp.path().to_owned();
    drop(tmp);
    p
}
