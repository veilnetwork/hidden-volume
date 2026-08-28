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
        // Widened from 1800 when report17 HV17-L2 split the pre-open refusal
        // into its own table below the post-rename ones: the section grew, and
        // the Russian file is not ASCII so its bytes grow faster than its
        // words.
        let section = window(&text, claim, 3200);

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

/// The design documents the cap the code actually enforces — as a NUMBER.
///
/// This replaces a guard that asserted one sentence was absent
/// (`!contains("the library does not enforce a hard cap")`). A negative on an
/// exact rendering can only ever catch the rendering that was already fixed:
/// the same denial in any other words kept it green, and so did the constant
/// changing under a design table that still quoted the old figure. Nothing
/// about it could fail again, which is the definition of a test that is no
/// longer testing (report17, the dead-code section).
///
/// What is checked instead is agreement: the value in §10 of each design
/// document, multiplied out of however it is written, must equal the constant
/// in `open/mod.rs`, and the §11 entry that once denied the cap must still
/// name it. A shape-scan for denials was considered and rejected — §11
/// EXPLAINS the old false claim, so a scan for "a negation near a hard cap"
/// fires on the very text that corrects it, the same trap as a guard reading
/// its own assertion.
#[test]
fn the_design_states_the_cap_the_code_enforces() {
    let cap = const_u64(
        &repo("crates/hidden-volume/src/open/mod.rs"),
        "MAX_OPEN_SCAN_CHUNKS",
    );

    for design in ["DESIGN.md", "DESIGN.ru.md"] {
        let text = repo(design);
        let row = text
            .lines()
            .find(|l| l.starts_with("| `MAX_OPEN_SCAN_CHUNKS`"))
            .unwrap_or_else(|| panic!("{design} has no §10 row for the cap"));
        let cell = row
            .split('|')
            .nth(2)
            .unwrap_or_else(|| panic!("{design}: the cap row has no value column"));

        assert_eq!(
            product_of_integers(cell.split('(').next().unwrap_or(cell)),
            cap,
            "{design} states {cell:?} for a cap the code sets to {cap}"
        );

        // §11's entry is the one that used to say no cap was enforced. It has
        // to keep pointing at the constant, or the two halves of the document
        // can drift apart again with nothing to notice.
        let entry_at = text
            .find("Maximum slot count")
            .or_else(|| text.find("Максимальное количество слотов"))
            .unwrap_or_else(|| panic!("{design} lost the §11 slot-count entry"));
        assert!(
            window(&text, entry_at, 700).contains("MAX_OPEN_SCAN_CHUNKS"),
            "{design}: the slot-count entry no longer names the cap it resolves to"
        );
    }
}

/// The value of `pub const NAME: u64 = <a product of integers>;`.
///
/// Written out rather than read from the compiled crate on purpose: the point
/// is to compare what the SOURCE says with what the document says, and a test
/// that imported the constant would agree with itself if the source line and
/// the published constant ever parted company.
fn const_u64(source: &str, name: &str) -> u64 {
    let needle = format!("pub const {name}: u64 =");
    let line = source
        .lines()
        .find(|l| l.trim_start().starts_with(&needle))
        .unwrap_or_else(|| panic!("no `{needle}` in the source"));
    let expr = line
        .split('=')
        .nth(1)
        .and_then(|e| e.split(';').next())
        .unwrap_or_else(|| panic!("`{needle}` has no value"));
    product_of_integers(expr)
}

/// Every integer in [text], multiplied. `16 × 1024 × 1024`, `16 * 1024 * 1024`
/// and `16777216` all come out the same, so the documents stay free to write
/// the figure the way a reader wants it.
fn product_of_integers(text: &str) -> u64 {
    let mut product = 1u64;
    let mut seen = false;
    for token in text.split(|c: char| !c.is_ascii_digit()) {
        if token.is_empty() {
            continue;
        }
        seen = true;
        product = product.saturating_mul(token.parse::<u64>().expect("an integer"));
    }
    assert!(seen, "no number at all in {text:?}");
    product
}

/// The threat model says which release it is current for, and means it.
///
/// It used to call itself pre-release long after v2 shipped, and the guard
/// written for that asserted the string `v1.0` was absent from the status
/// line. That could only ever catch the one version it was written against:
/// the same staleness spelled `v1.5`, or a status line left at `v2.0.x` while
/// the crate moved to `v2.1`, kept it green. The claim is checked against the
/// crate instead, so the line goes stale the moment the crate does.
#[test]
fn the_threat_model_is_current_for_the_release_it_names() {
    let version = repo("crates/hidden-volume/Cargo.toml")
        .lines()
        .find_map(|l| {
            l.strip_prefix("version = \"")
                .map(|v| v.trim_end_matches('"').to_owned())
        })
        .expect("the crate has a version");
    let mut parts = version.split('.');
    let shipped = format!(
        "{}.{}",
        parts.next().expect("a major"),
        parts.next().expect("a minor")
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
        // The first sentence only: the paragraph below it explains what the
        // line used to say, and a window that swallowed the explanation would
        // read the correction as the claim. Same trap as a source guard
        // reading its own assertion.
        let status = window(&text, status_at, 200);

        let named = status
            .split('v')
            .find_map(|rest| {
                let digits: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                let mut it = digits.split('.');
                let major = it.next().filter(|s| !s.is_empty())?;
                let minor = it.next().filter(|s| !s.is_empty())?;
                Some(format!("{major}.{minor}"))
            })
            .unwrap_or_else(|| panic!("{model} names no version: {status:?}"));

        assert_eq!(
            named, shipped,
            "{model} says it is current for v{named}.x while the crate is at {version}"
        );
    }
}

/// report17 HV17-L2 — every rewrite outcome the code can return is documented.
///
/// The drift this catches is not a wrong sentence but a MISSING one: two
/// variants were added to the error enum after the integration guides were
/// written, and every substring assertion about those guides stayed green
/// because nothing asked what the code actually returns. The expectation is
/// derived from `error.rs` rather than listed here, so a variant added
/// tomorrow fails until both guides mention it.
#[test]
fn every_rename_outcome_is_in_both_integration_guides() {
    let errors = repo("crates/hidden-volume/src/error.rs");
    let variants: Vec<&str> = errors
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let name = l.strip_prefix("RenameVisible")?;
            // The declaration line, not a doc-comment mention: variants end in
            // `,` (unit), `(` (tuple) or ` {` (struct).
            let end = name.find(['(', ',', ' '])?;
            Some(&l[..("RenameVisible".len() + end)])
        })
        .collect();

    assert!(
        variants.len() >= 4,
        "the outcome family shrank to {variants:?} — re-anchor this test"
    );

    for guide in [
        "docs/en/guide/integration.md",
        "docs/ru/guide/integration.md",
    ] {
        let text = repo(guide);
        for v in &variants {
            assert!(
                text.contains(v),
                "{guide} does not document {v}; a caller reading it cannot know \
                 what the call can answer"
            );
        }
    }
}

/// And the outcome that happens BEFORE anything is opened is not filed with
/// the ones that happen after the rename.
///
/// The guides introduced the table with "the old container is already gone
/// from that path in every one of them" and then listed a pre-open refusal in
/// it. A reader following that sentence stops trusting the old password after
/// a call that did nothing at all.
#[test]
fn the_pre_open_refusal_is_not_listed_as_having_applied() {
    for (guide, phrase) in [
        ("docs/en/guide/integration.md", "Nothing ran"),
        ("docs/ru/guide/integration.md", "Ничего не выполнялось"),
    ] {
        let text = repo(guide);
        let at = text
            .find("SourceIsNotARegularFile")
            .unwrap_or_else(|| panic!("{guide} stopped documenting the pre-open refusal"));
        assert!(
            window(&text, at, 400).contains(phrase),
            "{guide} lists the pre-open refusal without saying nothing ran"
        );
    }
}

/// The threat model no longer claims an advisory lock satisfies the mapping's
/// contract.
///
/// It said `flock` "satisfies the contract" on local filesystems and filed the
/// risk under network mounts — which told a server operator their local
/// deployment was safe when a same-user process that never asks for the lock
/// can truncate the file and kill theirs (report17 HV17-L2, following
/// HV16-M1 and HV17-L3).
#[test]
fn the_threat_model_does_not_promise_the_lock_is_enough() {
    for (guide, forbidden, required) in [
        (
            "docs/en/security/threat-model.md",
            "satisfies the contract: another writer",
            "advisory",
        ),
        (
            "docs/ru/security/threat-model.md",
            "удовлетворяет\nконтракт",
            "рекомендательная",
        ),
    ] {
        let text = repo(guide);
        assert!(
            !text.contains(forbidden),
            "{guide} still promises the lock is enough"
        );
        assert!(
            text.contains(required),
            "{guide} does not say the lock is advisory"
        );
        assert!(
            text.contains("SIGBUS"),
            "{guide} does not name what actually happens"
        );
    }
}
