//! Container paths given as a **bare file name** (report5 HV-P0).
//!
//! `Path::parent()` answers `Some("")` — not `None` — for `"store.hv"`,
//! so `parent().unwrap_or(Path::new("."))` never fired and the
//! parent-directory fsync opened `""`, i.e. ENOENT. The blast radius was
//! not a missing fsync:
//!
//! - `Container::create("store.hv")` returned `Err(Io(NotFound))` **and**
//!   its `UnlinkOnDrop` guard deleted the container it had just written,
//!   so the caller was left with neither a handle nor a file;
//! - `change_passwords` / `compact_known` over a bare name returned
//!   `RenameVisibleDurabilityUncertain` — and for a rotation that is not
//!   a durability caveat, it is "your password was NOT changed" wearing
//!   a durability error's clothes.
//!
//! `"./store.hv"` worked and `"store.hv"` did not, which is not a
//! distinction any caller can be expected to know about.
//!
//! ## Why these tests own the process's current directory
//!
//! A bare file name only means anything relative to a cwd, so there is
//! no way to exercise the defect without setting one. `set_current_dir`
//! is process-global while `cargo test` runs a binary's tests on
//! parallel threads — but cargo gives every `tests/*.rs` file its OWN
//! binary, so the blast radius is this file, and `CWD_LOCK` serializes
//! the tests inside it. Nothing else in this file may use a relative
//! path outside the lock.
//!
//! Each test asserts the **artifact**, never just the return code: the
//! `create` regression returned an error while ALSO removing the file,
//! and a test that only looked at `Ok`/`Err` on the rotation path would
//! have called a container whose password never changed a success.

use hidden_volume::container::RepackOptions;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use hidden_volume::{Container, Error};
use std::path::Path;
use std::sync::Mutex;

mod common;
use common::fast_params;

/// Serializes the cwd-mutating tests in this binary. Poisoning is
/// ignored on purpose: a panicking test has already reported its
/// failure, and turning that into a cascade of `PoisonError` unwraps in
/// the sibling tests hides which one actually broke.
static CWD_LOCK: Mutex<()> = Mutex::new(());

/// Run `f` with the process cwd set to a fresh temp directory, holding
/// [`CWD_LOCK`] throughout, and restore the previous cwd afterwards.
fn in_scratch_dir<F: FnOnce()>(f: F) {
    let guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let previous = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    // Restore before releasing the lock, and before resuming any panic,
    // so a failing test cannot strand the binary in a deleted directory.
    std::env::set_current_dir(&previous).unwrap();
    drop(dir);
    drop(guard);
    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
}

fn fast_repack_options() -> RepackOptions {
    RepackOptions {
        argon2: Some(fast_params()),
        initial_garbage_chunks: 0,
        padding_policy: Some(PaddingPolicy::None),
        superblock_replicas: 3,
    }
}

/// Build a one-space container at `path` with a known KV entry.
fn build_at(path: &Path, password: &[u8]) {
    let mut c = Container::create(path, fast_params()).unwrap();
    let mut s = c.create_space(password).unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"who", b"alice").unwrap();
    tx.commit().unwrap();
}

/// Assert `path` opens under `password` and still holds the entry
/// `build_at` wrote.
fn assert_intact(path: &Path, password: &[u8]) {
    let mut c = Container::open(path).unwrap();
    let mut s = c.open_space(password).unwrap();
    assert_eq!(
        s.get(Namespace::SETTINGS, b"who").unwrap().as_deref(),
        Some(&b"alice"[..]),
        "container at {} lost its payload",
        path.display()
    );
}

/// `Container::create` over a bare file name must produce a container
/// that is STILL THERE when it returns.
///
/// The `Ok(_)` assertion alone is the weak test that let the regression
/// through: the failing `create` removed the file on its way out, so the
/// file-exists assertion below is the one that pins the guard's
/// behaviour rather than just the error type.
#[test]
fn create_over_bare_file_name_leaves_the_file_on_disk() {
    in_scratch_dir(|| {
        let bare = Path::new("bare-create.hv");
        let container = Container::create(bare, fast_params());
        assert!(
            container.is_ok(),
            "create over a bare file name failed: {:?}",
            container.err()
        );
        drop(container);

        assert!(
            bare.exists(),
            "create returned Ok but the container file is gone — the \
             UnlinkOnDrop guard ran on a successful create"
        );
        // Not merely present: a container the caller can actually use.
        // A stub left behind by a half-finished create would satisfy
        // `exists()` and nothing else.
        let mut c = Container::open(bare).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"who", b"alice").unwrap();
        tx.commit().unwrap();
        drop(c);
        assert_intact(bare, b"pw");
    });
}

/// `"./x.hv"` and `"x.hv"` name the same file and must behave the same
/// way. The defect made exactly this pair disagree.
#[test]
fn create_agrees_between_bare_and_dot_slash_forms() {
    in_scratch_dir(|| {
        Container::create(Path::new("./dot-form.hv"), fast_params()).unwrap();
        Container::create(Path::new("bare-form.hv"), fast_params()).unwrap();
        assert!(Path::new("./dot-form.hv").exists());
        assert!(
            Path::new("bare-form.hv").exists(),
            "the './' form survived create and the bare form did not"
        );
    });
}

/// Password rotation addressed by bare file name must actually rotate.
///
/// Built at an ABSOLUTE path on purpose: if the build used the bare name
/// too, a `create`-side regression would fail this test before the
/// rotation ran, and the rotation path would go untested.
#[test]
fn change_passwords_over_bare_file_name_rotates() {
    in_scratch_dir(|| {
        let dir = std::env::current_dir().unwrap();
        let absolute = dir.join("bare-rotate.hv");
        build_at(&absolute, b"old-pw");

        let bare = Path::new("bare-rotate.hv");
        let rotated = Container::change_passwords(
            bare,
            &[(&b"old-pw"[..], &b"new-pw"[..])],
            fast_repack_options(),
        );
        assert!(
            rotated.is_ok(),
            "rotation over a bare file name failed: {:?}",
            rotated.err()
        );

        // The outcome that matters, and the one an `is_ok()`-only test
        // would miss: the OLD password must be dead and the NEW one live.
        // The regression reported a durability caveat on a rotation that
        // had not happened at all.
        let mut c = Container::open(bare).unwrap();
        assert!(
            matches!(c.open_space(b"old-pw"), Err(Error::AuthFailed)),
            "old password still opens the space — rotation did not take effect"
        );
        drop(c);
        assert_intact(bare, b"new-pw");
    });
}

/// In-place compaction addressed by bare file name must succeed and
/// preserve the space it was told to keep.
#[test]
fn compact_known_over_bare_file_name_succeeds() {
    in_scratch_dir(|| {
        let dir = std::env::current_dir().unwrap();
        let absolute = dir.join("bare-compact.hv");
        build_at(&absolute, b"pw");

        let bare = Path::new("bare-compact.hv");
        let compacted = Container::compact_known(bare, &[&b"pw"[..]], fast_repack_options());
        assert!(
            compacted.is_ok(),
            "compaction over a bare file name failed: {:?}",
            compacted.err()
        );
        assert!(
            bare.exists(),
            "compaction reported success but left no file at the path"
        );
        assert_intact(bare, b"pw");
    });
}
