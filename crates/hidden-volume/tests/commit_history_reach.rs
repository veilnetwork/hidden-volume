//! The commit-anchor list must stay complete however it is built.
//!
//! `commit_history` is the host-app's rollback evidence (DESIGN §11.2): the
//! app stores the value after a commit and compares it on the next open, and
//! a missing anchor is a commit the app can no longer prove happened.
//!
//! The scan builds the list by pushing a seq per owned Superblock CHUNK, so
//! replicas inflate it several-fold over the distinct anchors it ends up
//! holding — enough that its growth doubling was a measurable part of the
//! open's peak (report9 HV-13). The list therefore collapses itself before it
//! doubles past `COMMIT_HISTORY_DEDUP_AT`, and this fixture is sized to cross
//! that threshold: below it the collapse never runs and the test would be
//! measuring the ordinary path twice.
//!
//! Nothing else in the suite noticed when that collapse was replaced with one
//! that DROPS anchors instead of deduplicating them — every other fixture is
//! too small to reach the threshold, so a break-check on it stayed green
//! across the whole workspace. That gap is what this file closes.

use hidden_volume::Container;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::Namespace;

/// Comfortably past `COMMIT_HISTORY_DEDUP_AT` (1024) in pushes: each commit
/// publishes several superblock replicas, so this crosses it several times
/// over and the collapse runs repeatedly.
const COMMITS: u64 = 1400;

#[test]
fn every_commit_leaves_an_anchor_even_past_the_collapse_threshold() {
    let path = std::env::temp_dir().join(format!(
        "hv-history-reach-{}-{:?}.bin",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    {
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..COMMITS {
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", &i.to_be_bytes()).unwrap();
            tx.commit().unwrap();
        }
    }

    // Read-only: no vacuum, so every superblock this session wrote is still
    // on disk and the anchor list must name all of them. A writable open
    // would retire the superseded ones, which is correct and would make the
    // expected set a moving target.
    let mut c = Container::open_readonly(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    let seq = s.commit_seq();
    let history = s.commit_history();

    let expected: Vec<u64> = (1..=seq).collect();
    assert_eq!(
        history,
        expected.as_slice(),
        "the anchor list holds {} of the {seq} commits on disk — a host-app \
         comparing a stored anchor against this would read a commit that \
         happened as one that did not",
        history.len()
    );

    let _ = std::fs::remove_file(&path);
}
