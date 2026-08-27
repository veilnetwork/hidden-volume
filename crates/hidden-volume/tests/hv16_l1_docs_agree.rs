//! report16 HV16-L1 — the documents must not contradict the code or each other.
//!
//! Three drifts, all of the kind a reader resolves in whichever direction costs
//! them more:
//!
//! * the integration guide promised "on any failure the temp is removed and the
//!   original `path` is untouched", with no qualifier — while four outcomes are
//!   reported AFTER the rename, in each of which the old container is already
//!   gone from that path. Somebody reading it retries a password rotation with
//!   the old password;
//! * `DESIGN.md` said the library enforces no hard cap on slot count, in a
//!   section eleven headings below the one documenting `MAX_OPEN_SCAN_CHUNKS`
//!   as exactly that;
//! * the threat model called itself a pre-release document that would not
//!   change before v1.0, long after v2 shipped.
//!
//! Checked here rather than left to review because a document nobody executes
//! is where a stale claim survives longest.

use std::path::{Path, PathBuf};

/// `len` bytes from `at`, moved back to a char boundary.
///
/// These files are UTF-8 and the Russian one is not ASCII: slicing at an
/// arbitrary byte index panics inside a multi-byte character, which is how the
/// first version of this test failed.
fn window(text: &str, at: usize, len: usize) -> &str {
    let mut end = (at + len).min(text.len());
    while end > at && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[at..end]
}

fn repo(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn the_integration_guides_qualify_the_untouched_promise() {
    for guide in [
        "docs/en/guide/integration.md",
        "docs/ru/guide/integration.md",
    ] {
        let text = repo(guide);
        // The claim itself must still be there — this is not "delete the
        // sentence", it is "say when it holds".
        let claim = text
            .find("hv-rotate")
            .expect("the rotation mechanics section moved");
        let section = window(&text, claim, 1800);

        assert!(
            section.contains("RenameVisibleDurabilityUncertain"),
            "{guide} promises an untouched original without naming the \
             outcomes reported after the rename"
        );
        assert!(
            section.contains("RenameVisibleAliasesNotRevoked"),
            "{guide} does not mention the outcome added for hard links"
        );
        assert!(
            section.contains("SourceIsNotARegularFile"),
            "{guide} does not mention the refusal added for symlinks"
        );
    }
}

#[test]
fn design_does_not_deny_the_cap_it_documents() {
    let design = repo("DESIGN.md");

    assert!(
        design.contains("MAX_OPEN_SCAN_CHUNKS"),
        "premise: the cap is documented here"
    );
    assert!(
        !design.contains("the library does not enforce a hard cap"),
        "DESIGN.md denies the cap it documents eleven headings above"
    );
}

#[test]
fn the_threat_model_does_not_call_a_shipped_release_pre_release() {
    let version = repo("crates/hidden-volume/Cargo.toml")
        .lines()
        .find_map(|l| {
            l.strip_prefix("version = \"")
                .map(|v| v.trim_end_matches('"').to_owned())
        })
        .expect("the crate has a version");
    assert!(
        version.starts_with('2'),
        "this guard is written for the v2 line; the crate says {version}"
    );

    for model in [
        "docs/en/security/threat-model.md",
        "docs/ru/security/threat-model.md",
    ] {
        let text = repo(model);
        let status_at = text
            .find("Status.")
            .or_else(|| text.find("Статус."))
            .unwrap_or_else(|| panic!("{model} has no status line"));
        // The first sentence only: the correction below it explains what the
        // line used to say, and a window that swallowed the explanation found
        // the phrase in the text that corrects it. Same trap as a source guard
        // reading its own assertion.
        let status = window(&text, status_at, 200);
        assert!(
            !status.contains("v1.0"),
            "{model} still says its shape holds until v1.0, and the crate is \
             at {version}"
        );
    }
}
