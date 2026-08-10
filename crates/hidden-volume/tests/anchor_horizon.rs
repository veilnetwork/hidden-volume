//! A space's state must stop growing with the number of commits it has taken.
//!
//! Every commit leaves two chunks nothing later reaches: the Superblock of
//! that era and the Commit chunk it points at. Old IndexNodes are already
//! collected — the orphan vacuum walks from the CURRENT root — but those two
//! were kept forever, one as a decode fallback and one as what that fallback
//! points at.
//!
//! Measured before this: a fixture rewriting a single eight-byte value grew
//! the container by ~17 KB per commit with no plateau — 21 MB for one key
//! after 1200 rewrites, and rising. That is the shape of the reference case
//! this project already carried in its comments, 7.0 GB of file against
//! 4.8 MB of content.
//!
//! [`hidden_volume::ANCHOR_HORIZON`] bounds it: `vacuum_orphans` retires the
//! pair for every era below `current_seq - ANCHOR_HORIZON`. The cost of the
//! bound is that a host's rollback anchor older than the horizon is no longer
//! on disk to compare against — `docs/en/guide/multi-device.md` says what a
//! host must do about that, and `the_anchor_list_keeps_the_horizon` below
//! pins the arithmetic.

use hidden_volume::Container;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;

/// Per session. Five sessions carry the fixture past the 1024-era horizon
/// with room for two post-horizon sessions to be compared against each other.
const PER_SESSION: usize = 400;
const SESSIONS: usize = 6;

struct Cleanup(std::path::PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn scratch(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "hv-anchor-{tag}-{}-{:?}.bin",
        std::process::id(),
        std::thread::current().id()
    ))
}

/// One writable session: open (which vacuums), commit, close. Returns the
/// owned-chunk count at the end.
fn session(path: &std::path::Path, commits: usize) -> usize {
    let mut c = Container::open(path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    s.set_padding_policy(PaddingPolicy::BucketGrowth { bucket_chunks: 64 })
        .unwrap();
    for i in 0..commits {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"hot", format!("{i}").as_bytes())
            .unwrap();
        tx.commit().unwrap();
    }
    s.audit_owned_chunk_count()
}

fn create(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let mut c = Container::create(path, Argon2Params::MIN).unwrap();
    let _ = c.create_space(b"pw").unwrap();
}

#[test]
fn owned_state_stops_scaling_with_the_commit_count() {
    let path = scratch("plateau");
    let _c = Cleanup(path.clone());
    create(&path);

    let mut owned = Vec::new();
    for _ in 0..SESSIONS {
        owned.push(session(&path, PER_SESSION));
    }

    // Non-vacuity first: the fixture has to have crossed the horizon, or the
    // plateau below is just "a short history does not need collecting".
    let commits_made = SESSIONS * PER_SESSION;
    assert!(
        commits_made as u64 > hidden_volume::ANCHOR_HORIZON,
        "the fixture made {commits_made} commits against a horizon of {} — it \
         never reached the point this test is about",
        hidden_volume::ANCHOR_HORIZON
    );

    // The property. Two consecutive post-horizon sessions each add
    // PER_SESSION commits; the owned set must not grow with them.
    //
    // Across TWO consecutive boundaries, not one. A single flat step could be
    // a session that happened to reuse what it retired; two in a row cannot.
    //
    // Not "no growth at all": the pool holds back a share of retired slots for
    // churn (DESIGN §9.1), so a session can end a few chunks up or down. Ten
    // per cent of a session's commits is an order of magnitude below the two
    // chunks per commit this replaces, and an order above that noise.
    //
    // Deliberately NOT an absolute ceiling on the owned count. A first version
    // asserted one and failed at 6115 against a guessed 5696 while the plateau
    // itself was plainly there ([2003, 3604, 5204, 6115, 6116, 6115]) — the
    // number of chunks an era costs is replica policy, and a test that pins it
    // is testing the guess. What must not scale with the commit count is the
    // growth, and that is what this measures.
    let budget = PER_SESSION / 10;
    for step in [SESSIONS - 2, SESSIONS - 1] {
        let grew = owned[step].saturating_sub(owned[step - 1]);
        assert!(
            grew <= budget,
            "the owned set grew by {grew} chunks over a session of \
             {PER_SESSION} commits (budget {budget}) at step {step} — state \
             is still scaling with the number of commits taken. \
             Sessions: {owned:?}"
        );
    }
}

#[test]
fn the_data_survives_every_retirement() {
    // The other half, and the one that matters most: retiring an era means
    // scrubbing chunks, and a mistake there is silent data loss rather than a
    // failed assertion somewhere.
    let path = scratch("data");
    let _c = Cleanup(path.clone());
    create(&path);

    // Distinct keys so the live tree is more than a single leaf, rewritten
    // often enough to carry the fixture past the horizon.
    const KEYS: usize = 16;
    for round in 0..(SESSIONS - 2) {
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        for i in 0..PER_SESSION {
            let mut tx = s.begin_tx();
            let k = format!("k{:02}", i % KEYS);
            tx.put(
                Namespace::SETTINGS,
                k.as_bytes(),
                format!("r{round}-{i}").as_bytes(),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        // Every key must read back inside the session that wrote it.
        for j in 0..KEYS {
            let k = format!("k{j:02}");
            assert!(
                s.get(Namespace::SETTINGS, k.as_bytes()).unwrap().is_some(),
                "key {k} vanished during round {round}"
            );
        }
        s.verify_integrity().expect("integrity after retirement");
    }

    // And after a reopen, which is where a wrongly scrubbed chunk shows up:
    // the scan reconstructs from what is actually on disk.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    for j in 0..KEYS {
        let k = format!("k{j:02}");
        let v = s.get(Namespace::SETTINGS, k.as_bytes()).unwrap();
        assert!(
            v.is_some(),
            "key {k} did not survive the reopen after its eras were retired"
        );
    }
    s.verify_integrity()
        .expect("integrity after reopen following retirement");
}

#[test]
fn the_anchor_list_keeps_the_horizon() {
    // What a host is entitled to. The list must hold the newest eras, in
    // order, and stop at the horizon rather than at some accident of layout.
    let path = scratch("anchors");
    let _c = Cleanup(path.clone());
    create(&path);
    for _ in 0..SESSIONS {
        session(&path, PER_SESSION);
    }

    // READ-ONLY on purpose. A writable open vacuums, and the vacuum also
    // prunes the in-memory anchor list — so asking the session that just did
    // the retiring reports the list it *intends*, not the one the disk holds.
    // A break-check that disabled the retirement entirely passed this test
    // through the writable path for exactly that reason: the list looked
    // bounded while every era was still on disk. Read-only reconstructs from
    // what is there.
    let mut c = Container::open_readonly(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    let seq = s.commit_seq();
    let history = s.commit_history();

    assert!(
        history.windows(2).all(|w| w[0] < w[1]),
        "the anchor list is not strictly ascending"
    );
    assert_eq!(
        history.last().copied(),
        Some(seq),
        "the newest anchor must be the era the space is on"
    );
    // The window is bounded — by the horizon, plus whatever has been
    // committed since the last time it was applied.
    //
    // Retirement happens when a writable open vacuums, not continuously, so
    // the threshold that was in force is the one from the START of the last
    // session. A first version of this test compared against the threshold at
    // the END and failed by exactly one era (first anchor 1380 against a
    // threshold of 1381), which is the fixture's own 400 commits showing up,
    // not a retirement that missed.
    // The slack is one session's commits for the retirement running at OPEN
    // rather than continuously, and one more for the eras the maintenance
    // itself publishes — a checkpoint self-heal writes a superblock of its
    // own, and pinning how many would be pinning a policy this test has no
    // business asserting. The other side of the window is held by the
    // `len() >= ANCHOR_HORIZON` check below, so a retirement that took MORE
    // than it promised cannot hide inside this slack.
    let span = seq - history.first().copied().unwrap_or(0);
    let allowed = hidden_volume::ANCHOR_HORIZON + 2 * PER_SESSION as u64;
    assert!(
        span <= allowed,
        "the anchor list spans {span} eras where the horizon plus one \
         session's commits allows {allowed} — retired eras are still being \
         reported as anchors"
    );
    // ...and everything within it does. A horizon that retired MORE than it
    // promised would pass the bound above and quietly shorten the window a
    // host is told it has.
    assert!(
        history.len() as u64 >= hidden_volume::ANCHOR_HORIZON,
        "the list holds {} anchors where the horizon promises at least {} — \
         a host comparing an anchor inside the window would read a fork",
        history.len(),
        hidden_volume::ANCHOR_HORIZON
    );
}
