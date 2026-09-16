//! An anchor inside the documented window must be identifiable after a reopen.
//!
//! The multi-device guide tells a host that `current_seq - anchor_seq` within
//! `ANCHOR_HORIZON` is inside the window, and that a pair missing from
//! `commit_history_with_roots()` inside that window means a FORK. After a
//! reopen the history could only IDENTIFY the newest 64 eras — the superblock
//! candidate cache was capped there — so an anchor 65 commits old was reported
//! as a fork of a container nobody had forked (report24 HV24-02).

use hidden_volume::Container;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::Namespace;

/// Comfortably past the old 64-era ceiling and well inside `ANCHOR_HORIZON`.
const COMMITS: u64 = 200;

#[test]
fn an_anchor_two_hundred_commits_back_is_still_identifiable() {
    let path = std::env::temp_dir().join(format!(
        "hv-anchor-horizon-{}-{:?}.bin",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);

    // Anchor taken early, then two hundred more commits on top.
    let anchor = {
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v0").unwrap();
        tx.commit().unwrap();
        let anchor = *s
            .commit_history_with_roots()
            .last()
            .expect("the first commit leaves an anchor");
        for i in 0..COMMITS {
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", &i.to_be_bytes()).unwrap();
            tx.commit().unwrap();
        }
        anchor
    };

    // Reopen: this is where the history is rebuilt from the scan.
    let mut c = Container::open(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    let history = s.commit_history_with_roots();

    assert!(
        s.commit_seq() - anchor.0 < hidden_volume::ANCHOR_HORIZON,
        "premise: the anchor is inside the documented window"
    );
    assert!(
        history.contains(&anchor),
        "an anchor {} commits back is inside the window and absent from a \
         {}-era history, which the guide says to read as a fork",
        s.commit_seq() - anchor.0,
        history.len()
    );

    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

/// Past the horizon the window STOPS — it does not follow the container.
///
/// The retention is a published number, and it is bounded for the same reason
/// the recovery cache is: every entry comes from a chunk that AEAD-passed, so
/// a key-holder decides how many there are. This is the other side of the test
/// above: the window reaches back `ANCHOR_HORIZON` eras, and not one further.
#[test]
fn the_identifiable_window_stops_at_the_horizon() {
    let path = std::env::temp_dir().join(format!(
        "hv-anchor-bound-{}-{:?}.bin",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);

    // Past the horizon, so the numeric history and the identifiable one have
    // somewhere to disagree.
    let target = hidden_volume::ANCHOR_HORIZON + 200;
    // Comfortably inside the window at the end, and comfortably outside the
    // old 64-era ceiling.
    let inside_at = target - 500;

    let inside = {
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut inside = None;
        while s.commit_seq() < target {
            let value = s.commit_seq().to_be_bytes();
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", &value).unwrap();
            tx.commit().unwrap();
            if s.commit_seq() == inside_at {
                inside = Some(*s.commit_history_with_roots().last().unwrap());
            }
        }
        inside.expect("the anchor was taken on the way past")
    };

    // READ-ONLY, so what is measured is the scan's own answer. A writable
    // open publishes a self-heal checkpoint on its way in, and that is a new
    // era pushed onto the list — the retention bounds what a scan RECOVERS,
    // while a session's own commits go on top and `vacuum` trims them again.
    let mut c = Container::open_readonly(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    let eras = s.commit_history_with_roots();
    let numeric = s.commit_history();

    // INCLUSIVE: the guide's own test is `current - anchor > HORIZON` → out of
    // range, so the era exactly `HORIZON` commits back is in range, and the
    // window that answers for it is `HORIZON + 1` entries wide.
    let window = hidden_volume::ANCHOR_HORIZON as usize + 1;
    assert!(
        eras.len() <= window,
        "the window holds {} eras, past an inclusive horizon of {}",
        eras.len(),
        window
    );
    assert!(
        eras.contains(&inside),
        "an anchor {} commits back is inside the horizon and missing from a \
         {}-era window",
        s.commit_seq() - inside.0,
        eras.len()
    );
    // The BOUNDARY itself, which is what report27 H06 was about. `vacuum`
    // keeps every era at `seq >= current - HORIZON` and the guide calls that
    // one in range; a window one entry short dropped it on the way back in,
    // leaving an era that is still on disk with no root to answer with — and
    // the guide reads an in-range anchor missing from the history as a fork
    // nobody made.
    let boundary = s.commit_seq() - hidden_volume::ANCHOR_HORIZON;
    assert_eq!(
        eras.first().map(|e| e.0),
        Some(boundary),
        "the oldest identifiable era is {:?}, but the inclusive window reaches \
         back to {} — an in-range anchor with no root reads as a fork",
        eras.first().map(|e| e.0),
        boundary
    );
    // The two lists are allowed to differ, and this is the only place they do:
    // a seq the scan read but whose era fell past the horizon is still LISTED.
    // An era we cannot identify is not one to offer a root for, and a numeric
    // history that outran the window is what that looks like from outside.
    if numeric.len() > window {
        assert_eq!(
            eras.len(),
            window,
            "past the horizon the window is the horizon, not the container"
        );
    }

    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}
