//! Coalescing several operations on one key inside a single transaction.
//!
//! Two things have to hold, and only one of them can be observed from outside:
//!
//!  * the LAST write wins on disk — checked here directly;
//!  * the value it displaced does not go back to the allocator unwiped
//!    (report24 HV24-07). That one cannot be tested by reading the buffer
//!    afterwards: it has been freed, and reading freed memory is undefined
//!    behaviour that reports whatever the allocator did next. The source guard
//!    below checks the thing that was actually wrong instead — the displaced
//!    value being dropped rather than cleared.

use hidden_volume::Container;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::Namespace;

#[test]
fn the_last_write_in_a_transaction_is_the_one_that_lands() {
    let path = std::env::temp_dir().join(format!(
        "hv-coalesce-{}-{:?}.bin",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);

    let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"a", b"first secret").unwrap();
    tx.put(Namespace::SETTINGS, b"a", b"second value").unwrap();
    tx.put(Namespace::SETTINGS, b"b", b"doomed secret").unwrap();
    tx.delete(Namespace::SETTINGS, b"b").unwrap();
    tx.commit().unwrap();

    assert_eq!(
        s.get(Namespace::SETTINGS, b"a").unwrap().as_deref(),
        Some(&b"second value"[..]),
        "the last write must win"
    );
    assert!(
        s.get(Namespace::SETTINGS, b"b").unwrap().is_none(),
        "a delete after a put must leave nothing"
    );

    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn coalescing_clears_the_value_it_displaces() {
    // The guard for the half that cannot be measured safely. It reads the
    // production source and requires that the replace path takes the displaced
    // value out and zeroes it — the shape a bare `insert` whose return value is
    // discarded does not have.
    let src = include_str!("../src/space/commit.rs");
    let start = src
        .find("let mut keyed = KeyOps::default();")
        .expect("the coalescing map is built in commit_tx");
    let body = &src[start..start + 2000];
    assert!(
        body.contains("std::mem::replace(slot,") && body.contains("zeroize()"),
        "coalescing no longer clears the value it displaces: a key written \
         twice in one transaction hands the first value back to the allocator \
         with the secret still in it"
    );
    assert!(
        !body.contains("keyed.insert(key.clone(), Some(value.clone()));"),
        "the bare insert is back, and its return value is the displaced secret"
    );
}
