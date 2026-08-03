//! `Space::list_keys` / `Space::list_keys_after` — keys-only enumeration
//! and its cursor (report5 HV-04).
//!
//! The KV counterpart of `tests/log_pagination.rs`. `list_keys` is the
//! value-discarding twin of `list`; `list_keys_after` is the bounded
//! form, and the one an FFI caller should reach for on a namespace whose
//! size it does not control.
//!
//! The *memory* property these exist for — that no value is ever
//! materialised — is not observable in a return value and is pinned
//! separately, by allocation measurement, in
//! `crates/hidden-volume-ffi/tests/kv_keys_memory.rs`. Everything here
//! would pass just as well against the old `list`-based implementation;
//! that is precisely why the other test had to exist.

use hidden_volume::space::index::Namespace;
use hidden_volume::{Container, Space};

mod common;
use common::{fast_params, scratch_path};

const NS: Namespace = Namespace::SETTINGS;
/// Enough entries to force internal nodes, so the recursive descent is
/// exercised and not just a single root leaf.
const ENTRIES: u64 = 400;
const VALUE_LEN: usize = 512;

fn key_of(i: u64) -> Vec<u8> {
    format!("key-{i:06}").into_bytes()
}

/// Every key `key-000000 .. key-000399`, ascending — the order the tree
/// stores them in, and therefore the order every walk must report.
fn expected_keys() -> Vec<Vec<u8>> {
    let mut keys: Vec<Vec<u8>> = (0..ENTRIES).map(key_of).collect();
    keys.sort();
    keys
}

fn build(path: &std::path::Path) {
    let mut container = Container::create(path, fast_params()).unwrap();
    let mut space = container.create_space(b"pw").unwrap();
    let mut tx = space.begin_tx();
    for i in 0..ENTRIES {
        tx.put(NS, &key_of(i), &vec![0x5A; VALUE_LEN]).unwrap();
    }
    tx.commit().unwrap();
}

/// Collect every key by paging with `limit`, following the cursor the
/// way a host app would. Also returns the size of each page so a caller
/// can assert the limit was honoured.
fn page_through(space: &mut Space<'_>, limit: usize) -> (Vec<Vec<u8>>, Vec<usize>) {
    let mut all = Vec::new();
    let mut sizes = Vec::new();
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let page = space.list_keys_after(NS, cursor.as_deref(), limit).unwrap();
        if page.is_empty() {
            break;
        }
        sizes.push(page.len());
        cursor = Some(page.last().unwrap().clone());
        all.extend(page);
        // A cursor bug that fails to advance would otherwise spin here
        // until the machine gives out rather than failing a test.
        assert!(
            all.len() <= ENTRIES as usize,
            "paging produced more keys than the namespace holds — the \
             cursor is not advancing"
        );
    }
    (all, sizes)
}

#[test]
fn list_keys_returns_exactly_the_keys_of_list() {
    let path = scratch_path();
    build(&path);
    let mut container = Container::open(&path).unwrap();
    let mut space = container.open_space(b"pw").unwrap();

    let from_list: Vec<Vec<u8>> = space
        .list(NS)
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    let from_list_keys = space.list_keys(NS).unwrap();

    assert_eq!(
        from_list_keys,
        expected_keys(),
        "wrong keys, or wrong order"
    );
    assert_eq!(
        from_list_keys, from_list,
        "list_keys and list disagree about the namespace's keys"
    );

    drop(container);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn pages_reassemble_into_the_whole_key_set() {
    let path = scratch_path();
    build(&path);
    let mut container = Container::open(&path).unwrap();
    let mut space = container.open_space(b"pw").unwrap();

    let (paged, sizes) = page_through(&mut space, 7);
    assert_eq!(
        paged,
        expected_keys(),
        "paging lost, duplicated or reordered keys"
    );
    assert!(
        sizes.iter().all(|&n| n <= 7),
        "a page exceeded its limit: {sizes:?}"
    );
    // 400 keys at 7 per page: 57 full pages and a 1-key remainder. A
    // `limit` that were quietly ignored would show up as one page here.
    assert_eq!(sizes.len(), 58, "unexpected page count: {sizes:?}");
    assert_eq!(*sizes.last().unwrap(), 1, "unexpected final page size");

    drop(container);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn after_is_exclusive_and_ordered() {
    let path = scratch_path();
    build(&path);
    let mut container = Container::open(&path).unwrap();
    let mut space = container.open_space(b"pw").unwrap();

    let all = expected_keys();
    let cursor = all[9].clone();
    let page = space.list_keys_after(NS, Some(&cursor), 5).unwrap();
    assert_eq!(
        page,
        all[10..15].to_vec(),
        "`after` is not strictly-greater, or the page did not start at \
         the cursor"
    );

    // A cursor past the last key ends the enumeration rather than
    // wrapping around to the beginning.
    let past_end = space.list_keys_after(NS, Some(b"zzzz"), 10).unwrap();
    assert!(
        past_end.is_empty(),
        "cursor past the end returned {past_end:?}"
    );

    // A cursor that is not itself a key still positions correctly: the
    // contract is "greater than", not "after this exact entry".
    let between = space.list_keys_after(NS, Some(b"key-000009x"), 2).unwrap();
    assert_eq!(between, all[10..12].to_vec());

    drop(container);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn zero_limit_and_untouched_namespace_are_empty() {
    let path = scratch_path();
    build(&path);
    let mut container = Container::open(&path).unwrap();
    let mut space = container.open_space(b"pw").unwrap();

    assert!(space.list_keys_after(NS, None, 0).unwrap().is_empty());
    // Never written to — not an error, just nothing.
    assert!(space.list_keys(Namespace::CONTACTS).unwrap().is_empty());
    assert!(
        space
            .list_keys_after(Namespace::CONTACTS, None, 10)
            .unwrap()
            .is_empty()
    );

    drop(container);
    let _ = std::fs::remove_file(&path);
}

/// `erase_namespace` enumerates by key now; it must still erase.
#[test]
fn erase_namespace_still_removes_every_entry() {
    let path = scratch_path();
    build(&path);
    let mut container = Container::open(&path).unwrap();
    let mut space = container.open_space(b"pw").unwrap();

    let removed = space.erase_namespace(NS).unwrap();
    assert_eq!(removed as u64, ENTRIES);
    assert!(space.list_keys(NS).unwrap().is_empty());
    assert_eq!(space.count(NS).unwrap(), 0);

    drop(container);
    let _ = std::fs::remove_file(&path);
}
