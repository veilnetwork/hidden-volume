//! `MultiSpace`: several spaces of one container open at once under a single
//! file lock, writes serialized in-core. The storage foundation for a host that
//! runs several identities simultaneously over one deniable container.

use hidden_volume::container::{Container, ContainerOptions};
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use hidden_volume::{Error, MultiSpace};

mod common;
use common::{fast_params, scratch_path};

fn fast_options() -> ContainerOptions {
    ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 1,
    }
}

#[test]
fn two_spaces_coexist_and_isolate_under_one_container() {
    let path = scratch_path();

    // Create a container holding two spaces, capture each space's keys.
    let (ka, kb) = {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        c.create_space(b"pa").unwrap();
        c.create_space(b"pb").unwrap();
        let ka = c.derive_space_keys(b"pa").unwrap();
        let kb = c.derive_space_keys(b"pb").unwrap();
        (ka, kb)
    }; // container dropped → exclusive lock released

    // Host BOTH spaces open at once under a single re-opened container/lock.
    let mut ms = MultiSpace::new(Container::open(&path).unwrap());
    let a = ms.open_space(ka).unwrap();
    let b = ms.open_space(kb).unwrap();
    assert_eq!(ms.len(), 2);

    // Interleave writes to A and B — both go through the one file lock.
    ms.with_space(a, |s| {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"who", b"alice").unwrap();
        tx.commit().unwrap();
    })
    .unwrap();
    ms.with_space(b, |s| {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"who", b"bob").unwrap();
        tx.commit().unwrap();
    })
    .unwrap();
    // A second write to A after B's write — proves the spaces stay independently
    // usable (no re-open) across interleaved operations.
    ms.with_space(a, |s| {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"city", b"riga").unwrap();
        tx.commit().unwrap();
    })
    .unwrap();

    // Each space reads back only its OWN data — full isolation.
    let who_a = ms
        .with_space(a, |s| s.get(Namespace::SETTINGS, b"who").unwrap())
        .unwrap();
    let who_b = ms
        .with_space(b, |s| s.get(Namespace::SETTINGS, b"who").unwrap())
        .unwrap();
    let city_a = ms
        .with_space(a, |s| s.get(Namespace::SETTINGS, b"city").unwrap())
        .unwrap();
    let city_b = ms
        .with_space(b, |s| s.get(Namespace::SETTINGS, b"city").unwrap())
        .unwrap();
    assert_eq!(who_a.as_deref(), Some(&b"alice"[..]));
    assert_eq!(who_b.as_deref(), Some(&b"bob"[..]));
    assert_eq!(city_a.as_deref(), Some(&b"riga"[..]));
    assert_eq!(city_b, None, "space B never wrote `city`");

    // Durability: drop the MultiSpace, reopen each space the classic way.
    drop(ms);
    let mut c = Container::open(&path).unwrap();
    let mut sa = c.open_space(b"pa").unwrap();
    assert_eq!(
        sa.get(Namespace::SETTINGS, b"who").unwrap().as_deref(),
        Some(&b"alice"[..])
    );
}

#[test]
fn open_space_with_wrong_keys_is_auth_failed() {
    let path = scratch_path();
    let kb = {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        c.create_space(b"pa").unwrap();
        c.derive_space_keys(b"pb").unwrap() // keys for a space that doesn't exist
    };
    let mut ms = MultiSpace::new(Container::open(&path).unwrap());
    match ms.open_space(kb) {
        Err(Error::AuthFailed) => {},
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

#[test]
fn double_hosting_one_space_is_rejected_and_data_survives() {
    // Regression: hosting the same space through two ids let each detached
    // SpaceState compute the next commit seq from its own stale superblock, so
    // two commits landed at the same seq with different payloads and one
    // acknowledged commit was silently lost on reopen. The guard must reject
    // the second host, and a single hosted handle must persist correctly.
    let path = scratch_path();
    let ka = {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        c.create_space(b"pa").unwrap();
        c.derive_space_keys(b"pa").unwrap()
    };

    let mut ms = MultiSpace::new(Container::open(&path).unwrap());
    let a = ms.open_space(ka.clone()).unwrap();

    // A second host of the very same space (by keys) is refused.
    match ms.open_space(ka.clone()) {
        Err(Error::SpaceAlreadyExists) => {},
        other => panic!("expected SpaceAlreadyExists, got {other:?}"),
    }
    // create_space with the same keys is likewise refused before touching disk.
    match ms.create_space(ka) {
        Err(Error::SpaceAlreadyExists) => {},
        other => panic!("expected SpaceAlreadyExists, got {other:?}"),
    }
    assert_eq!(ms.len(), 1, "no extra space slot was pushed");

    // The single hosted handle commits normally...
    ms.with_space(a, |s| {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v1").unwrap();
        tx.commit().unwrap();
    })
    .unwrap();
    ms.with_space(a, |s| {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v2").unwrap();
        tx.commit().unwrap();
    })
    .unwrap();
    drop(ms);

    // ...and both commits are intact on reopen (latest value wins, no loss).
    let mut ms = MultiSpace::new(Container::open(&path).unwrap());
    let kre = ms.derive_space_keys(b"pa").unwrap();
    let a = ms.open_space(kre).unwrap();
    let got = ms
        .with_space(a, |s| s.get(Namespace::SETTINGS, b"k").unwrap())
        .unwrap();
    assert_eq!(got.as_deref(), Some(&b"v2"[..]));
}

#[test]
fn with_space_rejects_unknown_id() {
    let path = scratch_path();
    {
        Container::create_with_options(&path, fast_options())
            .unwrap()
            .create_space(b"pa")
            .unwrap();
    }
    let mut ms = MultiSpace::new(Container::open(&path).unwrap());
    let ka = ms.derive_space_keys(b"pa").unwrap();
    ms.open_space(ka).unwrap();
    match ms.with_space(99, |s| s.commit_seq()) {
        Err(Error::Malformed(_)) => {},
        other => panic!("expected Malformed, got {other:?}"),
    }
}

/// Hosting a space here must not be quietly weaker than opening it through
/// [`Container`].
///
/// `Container::open_space*` vacuums orphans on every writable handle, so the
/// index nodes a previous session deleted or overwrote stop being decryptable
/// — they remain valid AEAD otherwise, and anyone who later obtains the
/// password plus an old snapshot of the file can read the deleted values back.
/// `MultiSpace::open_space` went straight from the recovery scan to a stored
/// state and skipped that step entirely, which is the path xVeil's all-online
/// mode takes for every identity on every unlock.
#[test]
fn hosting_a_space_vacuums_what_a_single_space_open_would() {
    let path = scratch_path();
    let keys = {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        c.create_space(b"pw").unwrap();
        c.derive_space_keys(b"pw").unwrap()
    };

    // Leave orphans behind: write several keys, then delete them. The deletes
    // retire index nodes that stay decryptable until something scrubs them.
    {
        let mut ms = MultiSpace::new(Container::open(&path).unwrap());
        let id = ms.open_space(keys.clone()).unwrap();
        ms.with_space(id, |s| {
            let mut tx = s.begin_tx();
            for i in 0..16u8 {
                tx.put(Namespace::SETTINGS, &[i], &[i; 64]).unwrap();
            }
            tx.commit().unwrap();
            let mut tx = s.begin_tx();
            for i in 0..16u8 {
                tx.delete(Namespace::SETTINGS, &[i]).unwrap();
            }
            tx.commit().unwrap();
        })
        .unwrap();
    } // dropped → lock released, orphans still on disk

    // Re-host it. The open itself must do the scrubbing.
    let mut ms = MultiSpace::new(Container::open(&path).unwrap());
    let id = ms.open_space(keys).unwrap();
    let left = ms.with_space(id, |s| s.vacuum_orphans().unwrap()).unwrap();
    assert_eq!(
        left, 0,
        "open_space left {left} decryptable orphan(s) behind; a deleted value \
         is still readable to anyone who later gets the password"
    );
}

/// The constant-time open leaves the scrub undone — on purpose — and
/// `vacuum_hosted` is what finishes it.
///
/// `finalize_open` used to vacuum inline for every hosted open. That leaked:
/// the scrub's duration depends on how much a space has deleted over its life,
/// so a real space took measurably longer to open than a decoy, and the
/// ChaCha20 timing-equalizer that makes a wrong password cost the same as a
/// right one stopped hiding which was which (audit HV-02).
///
/// Moving it out is only safe if the erase still happens. This pins both
/// halves: the constant-time open does NOT reclaim, and the explicit call
/// does.
#[test]
fn constant_time_open_defers_the_scrub_and_vacuum_hosted_performs_it() {
    let path = scratch_path();

    let keys = {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        // Write, then delete: the deletion only unlinks. Until a vacuum runs,
        // those chunks are still on disk and still decryptable with the
        // password — which is exactly what an adversary holding an old
        // snapshot would go after.
        let mut tx = s.begin_tx();
        for i in 0..20u32 {
            tx.put(Namespace::SETTINGS, format!("k{i:02}").as_bytes(), b"v")
                .unwrap();
        }
        tx.commit().unwrap();
        let mut tx = s.begin_tx();
        for i in 0..20u32 {
            tx.delete(Namespace::SETTINGS, format!("k{i:02}").as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
        c.derive_space_keys(b"pw").unwrap()
    };

    let mut ms = MultiSpace::new(Container::open(&path).unwrap());
    let id = ms.open_space_constant_time(keys).unwrap();

    let after_open = ms.with_space(id, |s| s.audit_owned_chunk_count()).unwrap();
    assert!(
        after_open > 0,
        "precondition: the deleted entries' chunks must still be owned right \
         after a constant-time open — if they were already gone, this test \
         would pass without the explicit vacuum doing anything"
    );

    ms.vacuum_hosted(id).unwrap();
    let after_vacuum = ms.with_space(id, |s| s.audit_owned_chunk_count()).unwrap();

    assert!(
        after_vacuum < after_open,
        "vacuum_hosted must reclaim what the deferred open left behind \
         ({after_open} → {after_vacuum})"
    );
}
