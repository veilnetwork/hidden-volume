//! report16 HV16-M1 — the mmap scan path must not reach a shipped build.
//!
//! `Mmap::map` is `unsafe` because mutation under the mapping breaks Rust's
//! aliasing rules, and a `ftruncate` under it raises SIGBUS — the process
//! ends, and no caller sees an `Err`. What was supposed to exclude that is
//! `flock`, and `flock(2)` is ADVISORY: it excludes writers that ASK for the
//! lock. A process of the same user that opens the file and truncates it is
//! excluded by nothing, on any filesystem, however well that filesystem
//! honours locks. The safety note named only NFS/SMB/FUSE, which is a
//! narrower and different problem.
//!
//! The precondition is therefore about WHERE the host puts its containers,
//! and the library cannot check it. What it can check is that nothing here
//! quietly turns the feature on: the default path reads through `pread`,
//! where the same truncate is a short read.
//!
//! Cargo manifests, because that is what the fact is about. A test that
//! opened a container would prove nothing — with the feature off the path
//! does not exist, and with it on it works fine right up until somebody
//! truncates the file.

use std::path::Path;

/// Everything between `[features]` and the next `[section]`.
fn features_section(manifest: &str) -> &str {
    let at = manifest
        .find("\n[features]")
        .expect("no [features] section")
        + 1;
    let rest = &manifest[at..];
    let end = rest[1..].find("\n[").map(|i| i + 1).unwrap_or(rest.len());
    &rest[..end]
}

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn mmap_is_not_on_by_default() {
    let manifest = read("hidden-volume/Cargo.toml");
    let features = features_section(&manifest);

    assert!(
        features.contains("mmap = ["),
        "premise: the feature is declared here"
    );

    // `default = [...]` may be absent entirely, which is the same answer.
    let default_line = features
        .lines()
        .find(|l| l.trim_start().starts_with("default"))
        .unwrap_or("");
    assert!(
        !default_line.contains("mmap"),
        "the unsafe scan path is on for every consumer that says nothing: \
         {default_line}"
    );
}

#[test]
fn nothing_shipped_from_this_workspace_turns_it_on() {
    // The FFI cdylib is what the mobile and desktop apps load; the async and
    // rt crates sit under it. None may enable the feature — a host that wants
    // it must ask for it in its own manifest, having decided the directory is
    // safe.
    for crate_name in [
        "hidden-volume-ffi",
        "hidden-volume-rt",
        "hidden-volume-async",
    ] {
        let manifest = read(&format!("{crate_name}/Cargo.toml"));
        let dependency = manifest
            .lines()
            .find(|l| l.trim_start().starts_with("hidden-volume = "))
            .unwrap_or_else(|| panic!("{crate_name} does not depend on hidden-volume any more"));

        assert!(
            !dependency.contains("mmap"),
            "{crate_name} turns the unsafe scan path on for every app that \
             loads it: {dependency}"
        );
    }
}

/// And the note that explains the boundary has to still be there, saying the
/// thing that is true. It read "we rely on the flock to exclude that case",
/// which is exactly the claim an advisory lock does not support.
#[test]
fn the_safety_note_says_what_the_lock_actually_does() {
    let source = read("hidden-volume/src/open/mod.rs");
    let at = source
        .find("pub(crate) fn scan_and_recover_mmap(")
        .expect("the mmap scan moved — this guard no longer watches it");
    // The doc comment sits ABOVE the item; take the text before it, back to
    // the previous item.
    let note = &source[..at];
    let note = &note[note.rfind("/// Memory-mapped variant").expect("no doc")..];

    assert!(
        note.contains("ADVISORY"),
        "the note claims the lock excludes concurrent writers without saying \
         it only excludes the ones that ask"
    );
    assert!(
        note.contains("SIGBUS"),
        "the note does not say what happens when the file is truncated under \
         the mapping — which is the whole reason the precondition matters"
    );
}
