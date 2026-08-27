//! report16 HV16-M1 — a truncate under a reader, on the path everybody uses.
//!
//! The optional `mmap` scan is unsafe because mutation under the mapping
//! breaks Rust's aliasing rules, and a `ftruncate` under it raises SIGBUS: the
//! process ends, and no caller sees an `Err`. What was supposed to exclude
//! that is `flock`, and `flock(2)` is advisory — it excludes writers that ASK
//! for the lock, which a hostile process of the same user does not.
//!
//! The answer given there is that the DEFAULT path reads through `pread`,
//! where the same truncate is a short read rather than a signal, and that the
//! feature stays off. This is that claim, checked rather than asserted: the
//! same mutilation applied to a container, read back through the ordinary
//! open, comes out as an error the caller can act on and a process still
//! running to act on it.
//!
//! What this does NOT do is provoke the SIGBUS. That needs the mapping, and a
//! process that survives it — a child. The hazard is documented where the
//! unsafe block is; what is worth holding in a test is that the alternative
//! the documentation points at actually works.

#![cfg(unix)]

use hidden_volume::Container;
use hidden_volume::container::ContainerOptions;
use hidden_volume::space::index::Namespace;

mod common;
use common::{fast_params, scratch_path};

fn options() -> ContainerOptions {
    ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 64,
        padding_policy: hidden_volume::padding::PaddingPolicy::None,
        superblock_replicas: 1,
    }
}

struct Cleanup(std::path::PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Half the file taken away underneath, and the reader lives to say so.
#[test]
fn a_container_truncated_under_the_default_path_answers_rather_than_dies() {
    let path = scratch_path();
    let _cleanup = Cleanup(path.clone());

    {
        let mut c = Container::create_with_options(&path, options()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }

    let whole = std::fs::metadata(&path).unwrap().len();
    assert!(whole > 0, "premise: the container has a size to lose");

    // Exactly what a non-cooperating writer of the same user can do: it never
    // asked for the lock, so nothing stopped it.
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(whole / 2).unwrap();
    drop(file);

    // The header survived — it is the first chunk — so the container opens,
    // and the space does not: its slots are gone.
    let mut container = Container::open(&path).expect("the header is intact");
    let answer = container.open_space(b"pw");

    assert!(
        matches!(answer, Err(hidden_volume::Error::AuthFailed)),
        "a container missing half its slots answered {answer:?}"
    );

    // AuthFailed and not "truncated", because nothing can tell the two apart:
    // the format records no length, so a file with half its slots removed is
    // indistinguishable from a container that was always that size. The scan
    // finds no space matching the password, and that is what it says. What
    // matters here is that it SAYS something — a mapping would have taken the
    // process down instead.
    //
    // Not `Ok` either: serving data out of a mutilated container would be the
    // real defect, and this is what would catch it.
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        whole / 2,
        "premise: the truncate really happened"
    );
}

/// Vacuity guard: an UNtruncated container of the same shape opens and reads.
///
/// Without it the test above is satisfied by an open that fails for any
/// reason, including a fixture that never wrote a container at all.
#[test]
fn the_same_container_untouched_opens_and_reads() {
    let path = scratch_path();
    let _cleanup = Cleanup(path.clone());

    {
        let mut c = Container::create_with_options(&path, options()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }

    let mut c = Container::open(&path).expect("an untouched container opens");
    let mut s = c.open_space(b"pw").expect("and its space opens");
    assert_eq!(
        s.get(Namespace::SETTINGS, b"k").unwrap(),
        Some(b"v".to_vec()),
        "and reads back what was committed"
    );
}
