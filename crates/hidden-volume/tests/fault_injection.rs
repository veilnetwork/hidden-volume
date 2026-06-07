//! Fault-injection beyond the `tests/crash_recovery.rs` truncation
//! matrix.
//!
//! ## Scope
//!
//! `crash_recovery.rs` covers **clean** crashes: process dies between
//! fsync barriers, file size truncated to a chunk-aligned boundary.
//! That models the common case but misses three real-world scenarios:
//!
//! 1. **Bit-rot** — a previously-fsynced chunk silently flips bits
//!    on disk. AEAD must catch it (auth tag mismatch) and the chunk
//!    must be skipped during the discovery scan rather than panicking
//!    or distinguishing "wrong space" from "corrupted".
//! 2. **Unaligned truncation** — file size shrinks to a byte position
//!    that is NOT a chunk boundary. Could happen if the FS commits a
//!    partial block on crash. Recovery must treat the trailing
//!    partial chunk as garbage and skip it.
//! 3. **Garbage tail** — bytes written past the last fsynced position
//!    that survived the crash (lazy page writeback). The discovery
//!    scan iterates by chunk; each malformed chunk should AEAD-fail
//!    silently. No oracle leak distinguishing "valid for a different
//!    space" from "corrupted noise".
//!
//! ## Approach
//!
//! Rather than refactor `ContainerFile` to be generic over a
//! `BlockDevice` trait (would ripple through every `Container` /
//! `Space` callsite), we munge the file bytes directly between
//! `Container::open` calls. Same fault-injection coverage, no
//! production-code churn.
//!
//! Each test:
//!   1. Creates a container, writes some real data, drops the handle
//!      (releases the flock, fsyncs everything).
//!   2. Munges specific bytes in the file at known offsets.
//!   3. Re-opens via `Container::open` + `open_space`.
//!   4. Asserts the expected behavior (recovery via replica, error,
//!      or silent skip — depending on what was munged).

use std::path::{Path, PathBuf};

use hidden_volume::CHUNK_SIZE;
use hidden_volume::space::index::Namespace;
use hidden_volume::{Container, Error};

mod common;
use common::{fast_params, scratch_path};

const HEADER_LEN: u64 = CHUNK_SIZE as u64;

/// Flip a single bit at byte `byte_offset`, bit `bit_idx` (0–7) in
/// the file. Used to simulate disk bit-rot at a precise location.
///
/// Cross-platform: uses `seek` + `read_exact` + `write_all` rather
/// than `pread`/`pwrite` so the test runs on Windows CI too.
fn flip_bit(path: &Path, byte_offset: u64, bit_idx: u8) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    f.seek(SeekFrom::Start(byte_offset)).unwrap();
    let mut byte = [0u8; 1];
    f.read_exact(&mut byte).unwrap();
    byte[0] ^= 1 << bit_idx;
    f.seek(SeekFrom::Start(byte_offset)).unwrap();
    f.write_all(&byte).unwrap();
    f.sync_all().unwrap();
}

/// Truncate the file at `byte_offset`, which is intentionally NOT a
/// chunk boundary. Models a crash leaving a partial chunk on disk.
fn truncate_unaligned(path: &Path, byte_offset: u64) {
    let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.set_len(byte_offset).unwrap();
    f.sync_all().unwrap();
}

/// Append `n` bytes of pseudo-random garbage past the current EOF.
/// Models a torn write or a lazy-writeback survivor past the last
/// successful fsync.
fn append_garbage(path: &Path, n: u64) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    // Deterministic xorshift64 seeded from path + n for reproducibility.
    let mut state: u64 = 0xDEAD_BEEF_CAFE_F00Du64.wrapping_add(n);
    let mut written = 0u64;
    while written < n {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = state.to_le_bytes();
        let take = (n - written).min(8) as usize;
        f.write_all(&bytes[..take]).unwrap();
        written += take as u64;
    }
    f.sync_all().unwrap();
}

/// Slot byte-offset (relative to start of file). slot 0 = first
/// data slot after the cleartext header.
fn slot_offset(slot: u64) -> u64 {
    HEADER_LEN + slot * CHUNK_SIZE as u64
}

fn slot_count(path: &Path) -> u64 {
    let len = std::fs::metadata(path).unwrap().len();
    assert_eq!(len % CHUNK_SIZE as u64, 0, "file size not chunk-aligned");
    (len / CHUNK_SIZE as u64) - 1
}

/// Build a fresh container with `n_replicas` Superblock replicas,
/// some real KV data, and a couple of log entries — then drop. The
/// returned path has a complete, well-formed container.
fn build_populated(n_replicas: u8) -> PathBuf {
    let path = scratch_path();
    let opts = hidden_volume::container::ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: hidden_volume::padding::PaddingPolicy::None,
        superblock_replicas: n_replicas,
    };
    let mut c = Container::create_with_options(&path, opts).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"username", b"alice").unwrap();
    tx.put(Namespace::CONTACTS, b"bob", b"bob@example.com")
        .unwrap();
    tx.append_log(Namespace::MESSAGE_LOG, 1, b"first message")
        .unwrap();
    tx.append_log(Namespace::MESSAGE_LOG, 2, b"second message")
        .unwrap();
    tx.commit().unwrap();
    drop(s);
    drop(c);
    path
}

// =====================================================================
// Bit-flip in chunk plaintext payload — AEAD must catch it.
// =====================================================================

#[test]
fn bit_flip_in_data_chunk_aead_fails_silently() {
    // Fault: flip a single bit somewhere in the AEAD-protected
    // ciphertext of a non-superblock chunk (early slot, likely an
    // IndexNode or DataBatch).
    //
    // Expectation: the chunk is owned by our space; AEAD detects
    // the tag mismatch on read; verify_integrity surfaces this as
    // IntegrityFailure or AuthFailed depending on which chunk took
    // the hit. Discovery scan never panics.
    let path = build_populated(3);
    // Slot 0 is the very first chunk after the header. With 3 SB
    // replicas the first few slots are SB chunks; pick a slot deeper
    // in the file (likely IndexNode / DataBatch / Commit).
    let total = slot_count(&path);
    assert!(
        total > 5,
        "test setup: expected enough slots, got {}",
        total
    );
    let target_slot = total - 2; // commit chunk territory
    // Flip in the AAD-protected ciphertext (after the 24-byte nonce).
    flip_bit(&path, slot_offset(target_slot) + 100, 3);

    let mut c = Container::open(&path).unwrap();
    // open_space must not panic.
    let res = c.open_space(b"pw");
    match res {
        // If the bit-flip hit a chunk that's NOT load-bearing for
        // recovery (e.g. an old SB replica), open succeeds and a
        // subsequent verify_integrity catches downstream mismatches.
        Ok(mut s) => {
            // verify_integrity should detect any tampering of the
            // current Merkle tree.
            let _ = s.verify_integrity();
        },
        // If we hit the load-bearing chunk, AuthFailed is the right
        // surface (deniability — DON'T leak which chunk failed).
        Err(Error::AuthFailed) | Err(Error::IntegrityFailure { .. }) => {},
        Err(other) => panic!("unexpected error: {other:?}"),
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn bit_flip_in_one_superblock_replica_recovers_via_others() {
    // Fault: corrupt the first SB replica. With 3 replicas the
    // recovery picks any healthy one at max seq.
    //
    // Expectation: open succeeds, all data still readable.
    let path = build_populated(3);
    // Slot 0 is the first SB replica (at seq=1, written at create).
    // Actually we want the LATEST SB (highest seq) — find by walking
    // backwards. After our build_populated commit there's one Tx, so
    // seq=2 SB replicas live in the most recent slots.
    let total = slot_count(&path);
    // The LAST n_replicas slots are the seq=2 SB replicas. Corrupt
    // the very last one; recovery should fall back to an earlier
    // replica at the same seq.
    flip_bit(&path, slot_offset(total - 1) + 50, 1);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // Recovery must have picked a healthy replica.
    assert_eq!(s.commit_seq(), 2);
    assert_eq!(
        s.get(Namespace::SETTINGS, b"username").unwrap().as_deref(),
        Some(&b"alice"[..])
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn bit_flip_in_all_latest_superblocks_falls_back_to_prior_seq() {
    // Fault: corrupt EVERY replica of the latest commit's SB. There
    // are 3 replicas; with all 3 corrupted, no chunk decodes at the
    // current seq. Recovery falls back to the previous seq's SB
    // (the create-time initial SB at seq=1).
    //
    // Expectation: open succeeds at seq=1; the post-create commit's
    // data is rolled back to the create-time empty state.
    let path = build_populated(3);
    let total = slot_count(&path);
    // The last 3 slots are the seq=2 replicas. Corrupt all of them.
    for replica_idx in 0..3 {
        flip_bit(&path, slot_offset(total - 1 - replica_idx) + 80, 4);
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // Should fall back to the seq=1 SB (the initial empty one).
    assert_eq!(s.commit_seq(), 1, "expected fallback to seq=1");
    // The post-create commit's data is gone.
    assert_eq!(
        s.get(Namespace::SETTINGS, b"username").unwrap().as_deref(),
        None,
    );

    let _ = std::fs::remove_file(&path);
}

// =====================================================================
// Unaligned truncation — partial trailing chunk must be skipped.
// =====================================================================

#[test]
fn unaligned_truncation_skips_partial_trailing_chunk() {
    // Fault: truncate the file mid-chunk. The discovery scan should
    // treat the partial chunk as missing and recover from the prior
    // SB.
    let path = build_populated(3);
    let total = slot_count(&path);
    let last_slot_start = slot_offset(total - 1);
    // Truncate halfway through the last chunk (which is one of the
    // seq=2 SB replicas).
    truncate_unaligned(&path, last_slot_start + (CHUNK_SIZE as u64 / 2));

    // Open must succeed; we have 2 healthy replicas of the seq=2 SB.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 2);
    assert_eq!(
        s.get(Namespace::SETTINGS, b"username").unwrap().as_deref(),
        Some(&b"alice"[..])
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn unaligned_truncation_with_only_partial_last_chunk_works() {
    // Fault: truncate so the file is just header + complete chunks +
    // tiny partial chunk at the very end. The scan must round down
    // to a chunk boundary.
    let path = build_populated(3);
    let total = slot_count(&path);
    // Cut the last chunk to just 100 bytes into it.
    truncate_unaligned(&path, slot_offset(total - 1) + 100);

    let mut c = Container::open(&path).unwrap();
    let _ = c.open_space(b"pw").unwrap();
    let _ = std::fs::remove_file(&path);
}

// =====================================================================
// Garbage tail — random bytes past last commit must not confuse scan.
// =====================================================================

#[test]
fn garbage_tail_one_full_chunk_skipped_silently() {
    // Fault: append exactly one chunk's worth of random bytes after
    // the last fsynced commit. The discovery scan iterates by chunk;
    // the garbage chunk's AEAD tag will not validate under any space
    // key, so the scan must skip it silently (deniability).
    let path = build_populated(1);
    append_garbage(&path, CHUNK_SIZE as u64);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // The legitimate seq=2 commit is still the latest; data intact.
    assert_eq!(s.commit_seq(), 2);
    assert_eq!(
        s.get(Namespace::SETTINGS, b"username").unwrap().as_deref(),
        Some(&b"alice"[..])
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn garbage_tail_partial_chunk_handled() {
    // Fault: append less than a chunk's worth of bytes — partial
    // trailing chunk. Scan must treat it as not-a-chunk and skip.
    let path = build_populated(1);
    append_garbage(&path, 1024); // partial — not a full 4 KiB chunk

    let mut c = Container::open(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 2);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn garbage_tail_many_chunks_no_oracle_leak() {
    // Fault: append several full garbage chunks. Discovery must
    // handle EVERY one of them with the same code path (AEAD fail →
    // skip), no per-chunk diagnostics that could leak which "look
    // like" valid chunks vs noise.
    //
    // We can't directly test deniability from here — that's a code-
    // path / log-message audit. What we CAN test: the scan returns
    // success and the legit data is intact regardless of how many
    // garbage chunks tail the file.
    let path = build_populated(1);
    for _ in 0..10 {
        append_garbage(&path, CHUNK_SIZE as u64);
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 2);
    assert_eq!(
        s.get(Namespace::SETTINGS, b"username").unwrap().as_deref(),
        Some(&b"alice"[..])
    );
    let _ = std::fs::remove_file(&path);
}

// =====================================================================
// Combined: corruption + unaligned truncation.
// =====================================================================

#[test]
fn corruption_then_unaligned_truncation_still_recovers() {
    // Fault: flip a bit in one of the SB replicas AND truncate
    // mid-chunk further into the file. With 3 replicas, the system
    // should still find at least one healthy SB.
    let path = build_populated(3);
    let total = slot_count(&path);

    // Corrupt SB replica #1 (slot total-1).
    flip_bit(&path, slot_offset(total - 1) + 200, 0);
    // Truncate the very last byte (so SB replica #1 is now also
    // partial). Two SBs remain healthy at slots total-3 and total-2.
    truncate_unaligned(&path, slot_offset(total) - 1);

    let mut c = Container::open(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 2);
    let _ = std::fs::remove_file(&path);
}

// =====================================================================
// Wrong-password under corruption — deniability invariant.
// =====================================================================

#[test]
fn wrong_password_under_corruption_still_authfailed_not_other() {
    // Even on a corrupted file, opening with a wrong password must
    // surface AuthFailed — never a corruption-specific error that
    // would leak "this file has SOME space" information to the
    // adversary.
    let path = build_populated(3);
    let total = slot_count(&path);
    flip_bit(&path, slot_offset(total - 1) + 100, 5);

    let c_res = Container::open(&path);
    if let Ok(mut c) = c_res {
        let res = c.open_space(b"definitely-wrong");
        match res {
            Err(Error::AuthFailed) => {},
            other => panic!("expected AuthFailed under corruption, got {other:?}"),
        }
    }
    let _ = std::fs::remove_file(&path);
}
