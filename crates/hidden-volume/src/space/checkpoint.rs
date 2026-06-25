//! Open-scan acceleration checkpoint (the "fast-open" optimization).
//!
//! The discovery scan ([`crate::open`]) is O(total slots): it
//! trial-decrypts every slot to find the ones this space owns. A
//! long-history / low-utilization container (a messenger store bloated
//! by per-commit padding, say) makes every unlock pay a full sweep.
//!
//! A **checkpoint** is a chain of [`crate::chunk::ChunkKind::Checkpoint`]
//! chunks that records the *complete* set of slots this space owned as
//! of a past open (post-vacuum). A later open can then trial-decrypt
//! only that recorded working set plus the tail appended since
//! (`[cp_high_water, slot_count)`), instead of every slot — an
//! O(working-set + tail) open. See [`crate::open`] for the reader.
//!
//! **It is an optimization hint, never a correctness-bearing
//! structure.** A reader that ignores the checkpoint, or that finds it
//! unreadable, always falls back to the full scan and is correct. The
//! reconstructed `owned_slots` is provably identical to a full scan's:
//! the checkpoint records the owned set below `cp_high_water`; the
//! reader re-validates each recorded slot by trial-decrypt (so a slot
//! scrubbed since the checkpoint is dropped exactly as a full scan
//! would drop it), and appends-only + scrub-only-removes-ownership
//! guarantee no slot below `cp_high_water` becomes *newly* owned after
//! the checkpoint. So forward-secrecy (`vacuum_orphans` /
//! `vacuum_data_batches` iterate the full `owned_slots`) and
//! `commit_history` are preserved bit-for-bit.
//!
//! **Lazy self-heal, never per-commit.** `commit_tx` never writes a
//! checkpoint (zero per-commit overhead — it only carries the pointer
//! forward). The checkpoint is (re)written at most once per open, and
//! only when it actually helps: the container is large enough that a
//! full scan is slow, and the un-checkpointed tail has grown past the
//! working set. This amortizes checkpoint writes and honors the "don't
//! thrash the disk" constraint.
//!
//! **Deniability.** Each checkpoint chunk is AEAD-sealed under the same
//! per-space key as every other chunk (opaque random bytes to a
//! foreign adversary) and is the same `CHUNK_SIZE` as every other
//! chunk, so it adds no size/structure signal beyond the appends/
//! in-place-rewrites that commit + padding + vacuum already produce.
//! Checkpoints are per-space only — never aggregated across spaces.

use byteorder::{ByteOrder, LittleEndian};

use crate::chunk::ChunkKind;
use crate::chunk::format::PAYLOAD_CAP;
use crate::{Error, Result};

use super::Space;
use super::superblock::{NO_RECORD, Superblock};

/// Fixed header bytes of a checkpoint chunk's payload, before the
/// owned-slot list: `cp_seq (8) ‖ cp_high_water (8) ‖ next_slot (8) ‖
/// count (4)`.
const CP_HEADER_LEN: usize = 8 + 8 + 8 + 4;

/// Owned-slot entries (each a `u64` LE) that fit in one checkpoint
/// chunk after its header.
pub(crate) const CP_ENTRIES_PER_CHUNK: usize = (PAYLOAD_CAP - CP_HEADER_LEN) / 8;

// Compile-time guarantees: at least one entry fits, and a full chunk's
// header + entry list never exceeds the per-chunk payload cap.
const _: () = assert!(CP_ENTRIES_PER_CHUNK > 0);
const _: () = assert!(CP_HEADER_LEN + CP_ENTRIES_PER_CHUNK * 8 <= PAYLOAD_CAP);

/// Below this total slot count a full scan is already fast (≈ tens of
/// ms), so the self-heal writer skips checkpointing entirely — keeping
/// small containers byte-for-byte free of checkpoint chunks (and so
/// forward-compatible with a pre-checkpoint reader). `4096` chunks ≈
/// 16 MiB.
pub(crate) const CHECKPOINT_MIN_TOTAL: u64 = 4096;

/// The self-heal writer refreshes the checkpoint when the
/// un-checkpointed tail has grown past `max(owned_count,
/// CHECKPOINT_MIN_TAIL_REFRESH)`. The floor keeps tiny tails from
/// triggering a rewrite on every open.
pub(crate) const CHECKPOINT_MIN_TAIL_REFRESH: u64 = 2048;

/// Upper bound on checkpoint-chain hops while reading or scrubbing,
/// defending against an adversarial/buggy cyclic or over-long chain.
/// `MAX_OPEN_SCAN_CHUNKS` entries / `CP_ENTRIES_PER_CHUNK` per chunk,
/// plus slack.
pub(crate) const MAX_CHECKPOINT_CHAIN: u64 =
    crate::open::MAX_OPEN_SCAN_CHUNKS / (CP_ENTRIES_PER_CHUNK as u64) + 2;

/// One decoded checkpoint chunk: the shared header plus this chunk's
/// slice of the owned-slot list and the pointer to the next chunk in
/// the chain (or [`NO_RECORD`] at the tail).
#[derive(Debug, Clone)]
pub(crate) struct CheckpointChunk {
    /// Superblock seq this checkpoint was published under (the
    /// checkpoint "commit"). Same value in every chunk of one chain.
    pub cp_seq: u64,
    /// Slot count at checkpoint-write time. Every recorded owned slot
    /// is `< cp_high_water`; the reader scans `[cp_high_water, total)`
    /// fresh. Same value in every chunk of one chain.
    pub cp_high_water: u64,
    /// Slot of the next checkpoint chunk in the chain, or [`NO_RECORD`].
    pub next_slot: u64,
    /// This chunk's slice of the sorted owned-slot list.
    pub owned: Vec<u64>,
}

impl CheckpointChunk {
    /// Encode to the checkpoint payload bytes (header ‖ owned u64 LE
    /// list). Errors if the slice exceeds [`CP_ENTRIES_PER_CHUNK`].
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        if self.owned.len() > CP_ENTRIES_PER_CHUNK {
            return Err(Error::Internal("checkpoint chunk overfull"));
        }
        let mut buf = Vec::with_capacity(CP_HEADER_LEN + self.owned.len() * 8);
        let mut hdr = [0u8; CP_HEADER_LEN];
        LittleEndian::write_u64(&mut hdr[0..8], self.cp_seq);
        LittleEndian::write_u64(&mut hdr[8..16], self.cp_high_water);
        LittleEndian::write_u64(&mut hdr[16..24], self.next_slot);
        LittleEndian::write_u32(&mut hdr[24..28], self.owned.len() as u32);
        buf.extend_from_slice(&hdr);
        for &s in &self.owned {
            let mut b = [0u8; 8];
            LittleEndian::write_u64(&mut b, s);
            buf.extend_from_slice(&b);
        }
        Ok(buf)
    }

    /// Decode a checkpoint payload. Strict on length: the trailing
    /// owned-list must be exactly `count * 8` bytes (no trailing
    /// slack), `count` must fit one chunk. Errors as
    /// [`Error::Malformed`] otherwise — the reader treats any error as
    /// "no usable checkpoint" and falls back to the full scan.
    pub(crate) fn decode(payload: &[u8]) -> Result<Self> {
        if payload.len() < CP_HEADER_LEN {
            return Err(Error::Malformed("checkpoint chunk shorter than header"));
        }
        let cp_seq = LittleEndian::read_u64(&payload[0..8]);
        let cp_high_water = LittleEndian::read_u64(&payload[8..16]);
        let next_slot = LittleEndian::read_u64(&payload[16..24]);
        let count = LittleEndian::read_u32(&payload[24..28]) as usize;
        if count > CP_ENTRIES_PER_CHUNK {
            return Err(Error::Malformed(
                "checkpoint count exceeds per-chunk capacity",
            ));
        }
        let need = CP_HEADER_LEN + count * 8;
        if payload.len() != need {
            return Err(Error::Malformed("checkpoint chunk length mismatch"));
        }
        let mut owned = Vec::with_capacity(count);
        for i in 0..count {
            let off = CP_HEADER_LEN + i * 8;
            owned.push(LittleEndian::read_u64(&payload[off..off + 8]));
        }
        Ok(Self {
            cp_seq,
            cp_high_water,
            next_slot,
            owned,
        })
    }
}

impl<'f> Space<'f> {
    /// Lazily (re)write this space's open-scan checkpoint so the next
    /// open is O(working-set). Returns `true` if a checkpoint was
    /// written.
    ///
    /// Called once per open, AFTER `vacuum_orphans` (so the recorded
    /// owned set reflects the post-vacuum truth), on writable handles
    /// only. No-op when:
    /// - the handle is read-only (forward-secrecy / checkpoint writes
    ///   are writer-only),
    /// - the container is smaller than [`CHECKPOINT_MIN_TOTAL`] (a full
    ///   scan is already fast; keep small containers checkpoint-free),
    /// - a checkpoint already covers all but a small tail (no churn).
    ///
    /// The write is published like a tiny no-data commit: the owned
    /// set is recorded in a fresh checkpoint chain, then a superblock
    /// with a **bumped seq** (same `root_slot` / `root_hash`, new
    /// `checkpoint_slot`) is appended so the next open's max-seq
    /// superblock points at the new chain. Seq is bumped (not reused)
    /// to preserve the same-seq-replicas-are-bit-equal invariant.
    pub(crate) fn maybe_self_heal_checkpoint(&mut self) -> Result<bool> {
        if self.file.lock_mode == crate::container::file::LockMode::Shared {
            return Ok(false);
        }
        let total = self.file.slot_count();
        if total < CHECKPOINT_MIN_TOTAL {
            return Ok(false);
        }

        let old_head = self.state.superblock.checkpoint_slot;
        // Existing checkpoint's coverage (its high-water). Unreadable /
        // absent ⇒ treat as zero coverage so we (re)write.
        let existing_high_water = if old_head == NO_RECORD {
            0
        } else {
            // Unreadable / absent head ⇒ zero coverage ⇒ (re)write.
            self.read_checkpoint_head_high_water(old_head)
                .unwrap_or_default()
        };
        let tail = total.saturating_sub(existing_high_water);
        let owned_count = self.state.owned_slots.len() as u64;
        let refresh = old_head == NO_RECORD || tail > owned_count.max(CHECKPOINT_MIN_TAIL_REFRESH);
        if !refresh {
            return Ok(false);
        }

        self.write_self_heal_checkpoint()?;
        Ok(true)
    }

    /// The checkpoint write itself, independent of the size/refresh
    /// policy in [`Self::maybe_self_heal_checkpoint`]. Scrubs the chain
    /// it supersedes, snapshots the (post-vacuum) owned set, writes a
    /// fresh chain, and publishes a bumped-seq superblock pointing at
    /// it. Returns [`Error::ReadOnly`] on a shared-locked handle.
    pub(crate) fn write_self_heal_checkpoint(&mut self) -> Result<()> {
        if self.file.lock_mode == crate::container::file::LockMode::Shared {
            return Err(Error::ReadOnly);
        }
        let total = self.file.slot_count();
        let old_head = self.state.superblock.checkpoint_slot;

        // Scrub the chain we are about to supersede *first*, so the
        // fresh owned snapshot does not record the soon-dead chunks.
        // Crash-safe: if we die before publishing the new superblock,
        // the on-disk superblock still points at the (now-scrubbed)
        // old head, so the next open's fast-path read fails and falls
        // back to a full scan + re-heal. No data is referenced through
        // a checkpoint, so a dangling pointer only costs one slow open.
        if old_head != NO_RECORD {
            self.scrub_checkpoint_chain(old_head)?;
        }

        // cp_high_water = current slot count: every slot now on disk is
        // < total, so the reader scans nothing twice. Scrubbing above
        // does not change slot_count (in-place overwrite), so `total`
        // sampled before the scrub is still the high-water.
        let cp_high_water = total;
        let mut owned: Vec<u64> = self.state.owned_slots.clone();
        owned.sort_unstable();
        owned.dedup();
        debug_assert!(
            owned.last().map(|&s| s < cp_high_water).unwrap_or(true),
            "owned slots must be below the checkpoint high-water"
        );

        let cp_seq = self
            .state
            .superblock
            .seq
            .checked_add(1)
            .ok_or(Error::Internal("checkpoint seq overflow"))?;

        let head = self.write_checkpoint_chain(cp_seq, cp_high_water, &owned)?;
        self.file.fsync()?;

        // Publish: new superblock, bumped seq, unchanged root, pointing
        // at the new checkpoint head. Replicas are bit-equal (same seq,
        // same payload) so the open-scan dedup invariant holds.
        let new_sb = Superblock {
            seq: cp_seq,
            root_slot: self.state.superblock.root_slot,
            root_hash: self.state.superblock.root_hash,
            checkpoint_slot: head,
        };
        let replicas = self.file.superblock_replicas.max(1);
        for _ in 0..replicas {
            self.append_superblock(&new_sb)?;
        }
        self.file.fsync()?;
        self.state.superblock = new_sb;
        // cp_seq is strictly greater than every prior entry (bumped from
        // the max), so push preserves sort + uniqueness.
        self.state.commit_history.push(cp_seq);
        Ok(())
    }

    /// Read the head checkpoint chunk and return its `cp_high_water`,
    /// or `None` if it is unreadable / not a checkpoint. Used only for
    /// the refresh-decision heuristic (the authoritative read is on the
    /// open path).
    fn read_checkpoint_head_high_water(&mut self, head: u64) -> Option<u64> {
        if head >= self.file.slot_count() {
            return None;
        }
        let pt = self.read_owned_chunk(head).ok()?;
        if pt.kind != ChunkKind::Checkpoint {
            return None;
        }
        CheckpointChunk::decode(&pt.payload)
            .ok()
            .map(|c| c.cp_high_water)
    }

    /// Write `owned` (sorted, all `< cp_high_water`) as a fresh
    /// checkpoint chain, returning the head slot. The chain is written
    /// tail-first so each chunk's `next_slot` is known before it is
    /// sealed. An empty `owned` still writes one (empty) chunk so the
    /// pointer is always valid.
    fn write_checkpoint_chain(
        &mut self,
        cp_seq: u64,
        cp_high_water: u64,
        owned: &[u64],
    ) -> Result<u64> {
        // Groups of CP_ENTRIES_PER_CHUNK, in forward order. Empty owned
        // ⇒ a single empty group.
        let groups: Vec<&[u64]> = if owned.is_empty() {
            vec![&[][..]]
        } else {
            owned.chunks(CP_ENTRIES_PER_CHUNK).collect()
        };
        let mut next = NO_RECORD;
        // Write last group first so `next` always points at an
        // already-written successor; after the reverse walk `next` is
        // the first group's slot = the chain head.
        for group in groups.iter().rev() {
            let cc = CheckpointChunk {
                cp_seq,
                cp_high_water,
                next_slot: next,
                owned: group.to_vec(),
            };
            let payload = cc.encode()?;
            next = self.append_chunk(ChunkKind::Checkpoint, cp_seq, &payload)?;
        }
        Ok(next)
    }

    /// Scrub (overwrite with random) every chunk of the checkpoint
    /// chain rooted at `head`, removing them from `owned_slots`. Stops
    /// at the first unreadable / non-checkpoint hop (a partially
    /// scrubbed chain from a prior crash) and is bounded by
    /// [`MAX_CHECKPOINT_CHAIN`]. Best-effort cleanup of a superseded
    /// chain — not correctness-bearing (orphan checkpoint chunks left
    /// by a crash are reclaimed by the next `compact_known`).
    fn scrub_checkpoint_chain(&mut self, head: u64) -> Result<()> {
        let mut cur = head;
        let mut scrubbed: Vec<u64> = Vec::new();
        let mut hops = 0u64;
        while cur != NO_RECORD && hops < MAX_CHECKPOINT_CHAIN {
            hops += 1;
            if cur >= self.file.slot_count() {
                break;
            }
            let pt = match self.read_owned_chunk(cur) {
                Ok(p) => p,
                // Already scrubbed / not ours — stop walking.
                Err(Error::AuthFailed) => break,
                Err(other) => return Err(other),
            };
            if pt.kind != ChunkKind::Checkpoint {
                break;
            }
            let next = match CheckpointChunk::decode(&pt.payload) {
                Ok(c) => c.next_slot,
                Err(_) => NO_RECORD,
            };
            self.file.scrub_slot(cur)?;
            scrubbed.push(cur);
            cur = next;
        }
        if !scrubbed.is_empty() {
            self.file.fsync()?;
            let drop: std::collections::HashSet<u64> = scrubbed.into_iter().collect();
            self.state.owned_slots.retain(|s| !drop.contains(s));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_chunk_roundtrip() {
        let cc = CheckpointChunk {
            cp_seq: 5,
            cp_high_water: 1000,
            next_slot: 42,
            owned: vec![1, 7, 9, 900],
        };
        let enc = cc.encode().unwrap();
        let dec = CheckpointChunk::decode(&enc).unwrap();
        assert_eq!(dec.cp_seq, 5);
        assert_eq!(dec.cp_high_water, 1000);
        assert_eq!(dec.next_slot, 42);
        assert_eq!(dec.owned, vec![1, 7, 9, 900]);
    }

    #[test]
    fn checkpoint_chunk_empty_owned() {
        let cc = CheckpointChunk {
            cp_seq: 1,
            cp_high_water: 0,
            next_slot: NO_RECORD,
            owned: vec![],
        };
        let enc = cc.encode().unwrap();
        assert_eq!(enc.len(), CP_HEADER_LEN);
        let dec = CheckpointChunk::decode(&enc).unwrap();
        assert!(dec.owned.is_empty());
        assert_eq!(dec.next_slot, NO_RECORD);
    }

    #[test]
    fn checkpoint_chunk_rejects_trailing_slack() {
        let mut enc = CheckpointChunk {
            cp_seq: 1,
            cp_high_water: 10,
            next_slot: NO_RECORD,
            owned: vec![3],
        }
        .encode()
        .unwrap();
        enc.push(0); // one trailing byte
        assert!(CheckpointChunk::decode(&enc).is_err());
    }

    #[test]
    fn checkpoint_chunk_rejects_overlarge_count() {
        let mut enc = CheckpointChunk {
            cp_seq: 1,
            cp_high_water: 10,
            next_slot: NO_RECORD,
            owned: vec![3],
        }
        .encode()
        .unwrap();
        // Force count to a huge value without supplying the bytes.
        LittleEndian::write_u32(&mut enc[24..28], u32::MAX);
        assert!(CheckpointChunk::decode(&enc).is_err());
    }

    // --- End-to-end fast-open behavior (uses the public Container API
    //     plus in-crate test seams in `crate::open::test_hooks`). ---

    use crate::Container;
    use crate::crypto::kdf::Argon2Params;
    use crate::open::test_hooks;
    use crate::space::index::Namespace;

    fn scratch_path() -> std::path::PathBuf {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let p = tmp.path().to_owned();
        drop(tmp);
        p
    }

    /// Reconstructed-state fingerprint for fast-vs-full equivalence.
    #[derive(PartialEq, Debug)]
    struct StateSnap {
        owned: Vec<u64>,
        history: Vec<u64>,
        seq: u64,
        root_slot: u64,
        present: Vec<(u32, Vec<u8>)>,
    }

    const N_KEYS: u32 = 40;
    const DELETED: [u32; 3] = [5, 17, 33];

    /// Build a container: write `N_KEYS` settings KV entries (one commit
    /// each, so each commit supersedes the prior index → orphan
    /// IndexNodes accumulate), delete a few, then force-write a
    /// checkpoint. Leaves the file closed and ready to reopen.
    fn build_with_checkpoint(path: &std::path::Path) {
        let mut c = Container::create(path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..N_KEYS {
            let mut tx = s.begin_tx();
            tx.put(
                Namespace::SETTINGS,
                format!("k{i}").as_bytes(),
                format!("v{i}").as_bytes(),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        for &d in &DELETED {
            let mut tx = s.begin_tx();
            tx.delete(Namespace::SETTINGS, format!("k{d}").as_bytes())
                .unwrap();
            tx.commit().unwrap();
        }
        // Force the checkpoint regardless of the size threshold so the
        // mechanism is exercised on a small (fast) container.
        s.write_self_heal_checkpoint().unwrap();
        assert_ne!(
            s.state.superblock.checkpoint_slot, NO_RECORD,
            "checkpoint pointer must be set after a forced write"
        );
    }

    /// Open read-only (no vacuum, no mutation, sequential scan) and
    /// fingerprint the reconstructed state + the live KV data.
    fn snapshot_readonly(path: &std::path::Path) -> StateSnap {
        let mut c = Container::open_readonly(path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        let mut owned = s.state.owned_slots.clone();
        owned.sort_unstable();
        let history = s.state.commit_history.clone();
        let seq = s.state.superblock.seq;
        let root_slot = s.state.superblock.root_slot;
        let mut present = Vec::new();
        for i in 0..N_KEYS {
            if let Some(v) = s
                .get(Namespace::SETTINGS, format!("k{i}").as_bytes())
                .unwrap()
            {
                present.push((i, v));
            }
        }
        StateSnap {
            owned,
            history,
            seq,
            root_slot,
            present,
        }
    }

    /// The fast-open scan must reconstruct byte-for-byte the same state
    /// (owned_slots, commit_history, superblock, live data) as a full
    /// scan — and must actually engage.
    #[test]
    fn fast_path_matches_full_scan_and_engages() {
        let path = scratch_path();
        build_with_checkpoint(&path);

        test_hooks::set_disable(false);
        test_hooks::reset_hits();
        let fast = snapshot_readonly(&path);
        assert!(
            test_hooks::hits() >= 1,
            "fast path must engage when a checkpoint is present"
        );

        test_hooks::set_disable(true);
        let full = snapshot_readonly(&path);
        test_hooks::set_disable(false);

        assert_eq!(fast, full, "fast-open state must equal the full scan");
        let expected: usize = (N_KEYS as usize) - DELETED.len();
        assert_eq!(fast.present.len(), expected);
        for (i, v) in &fast.present {
            assert!(!DELETED.contains(i));
            assert_eq!(v.as_slice(), format!("v{i}").as_bytes());
        }
        let _ = std::fs::remove_file(&path);
    }

    /// A corrupt (scrubbed) checkpoint head must make the fast-path
    /// decline and fall back to the full scan — with all data intact.
    #[test]
    fn corrupt_checkpoint_falls_back_to_full_scan() {
        let path = scratch_path();
        {
            let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            for i in 0..N_KEYS {
                let mut tx = s.begin_tx();
                tx.put(
                    Namespace::SETTINGS,
                    format!("k{i}").as_bytes(),
                    format!("v{i}").as_bytes(),
                )
                .unwrap();
                tx.commit().unwrap();
            }
            s.write_self_heal_checkpoint().unwrap();
            let head = s.state.superblock.checkpoint_slot;
            assert_ne!(head, NO_RECORD);
            s.file.scrub_slot(head).unwrap();
            s.file.fsync().unwrap();
        }
        test_hooks::set_disable(false);
        test_hooks::reset_hits();
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert_eq!(
            test_hooks::hits(),
            0,
            "an unreadable checkpoint must fall back to the full scan"
        );
        for i in 0..N_KEYS {
            assert_eq!(
                s.get(Namespace::SETTINGS, format!("k{i}").as_bytes())
                    .unwrap()
                    .as_deref(),
                Some(format!("v{i}").as_bytes()),
                "key k{i} must survive the fallback"
            );
        }
        drop(s);
        drop(c);
        let _ = std::fs::remove_file(&path);
    }

    /// Opening through the fast path then vacuuming must scrub exactly
    /// the orphans a full-scan-driven vacuum would (forward secrecy is
    /// not weakened by the reduced scan): the post-vacuum owned-chunk
    /// count is identical via either scan path. Compared on two copies
    /// of the same file so the only difference is the scan.
    #[test]
    fn fast_path_open_drives_complete_vacuum() {
        let path = scratch_path();
        build_with_checkpoint(&path);
        let path_fast = scratch_path();
        let path_full = scratch_path();
        std::fs::copy(&path, &path_fast).unwrap();
        std::fs::copy(&path, &path_full).unwrap();

        let fast_owned = {
            test_hooks::set_disable(false);
            test_hooks::reset_hits();
            let mut c = Container::open(&path_fast).unwrap();
            let s = c.open_space(b"pw").unwrap();
            assert!(test_hooks::hits() >= 1, "fast path must engage");
            s.audit_owned_chunk_count()
        };
        let full_owned = {
            test_hooks::set_disable(true);
            let mut c = Container::open(&path_full).unwrap();
            let s = c.open_space(b"pw").unwrap();
            s.audit_owned_chunk_count()
        };
        test_hooks::set_disable(false);
        assert_eq!(
            fast_owned, full_owned,
            "fast-path-driven vacuum must reclaim the same orphans as full-scan-driven vacuum"
        );
        for p in [&path, &path_fast, &path_full] {
            let _ = std::fs::remove_file(p);
        }
    }

    /// The constant-time open path also engages the fast path and
    /// returns all data.
    #[test]
    fn constant_time_open_uses_fast_path() {
        let path = scratch_path();
        build_with_checkpoint(&path);
        test_hooks::set_disable(false);
        test_hooks::reset_hits();
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space_constant_time(b"pw").unwrap();
        assert!(
            test_hooks::hits() >= 1,
            "constant-time open must also engage the fast path"
        );
        for i in 0..N_KEYS {
            let want = if DELETED.contains(&i) {
                None
            } else {
                Some(format!("v{i}").into_bytes())
            };
            assert_eq!(
                s.get(Namespace::SETTINGS, format!("k{i}").as_bytes())
                    .unwrap(),
                want
            );
        }
        drop(s);
        drop(c);
        let _ = std::fs::remove_file(&path);
    }

    /// A wrong password must NOT engage the fast path (it cannot decrypt
    /// the checkpoint), so it pays a full scan and fails with
    /// AuthFailed — the post-authentication property that keeps the
    /// fast-vs-slow timing from being a password oracle.
    #[test]
    fn wrong_password_does_not_engage_fast_path() {
        let path = scratch_path();
        build_with_checkpoint(&path);
        test_hooks::set_disable(false);
        test_hooks::reset_hits();
        let mut c = Container::open(&path).unwrap();
        let err = c.open_space(b"WRONG").err();
        assert!(matches!(err, Some(crate::Error::AuthFailed)));
        assert_eq!(
            test_hooks::hits(),
            0,
            "a wrong password must never engage the (post-auth) fast path"
        );
        drop(c);
        let _ = std::fs::remove_file(&path);
    }

    /// Re-running the self-heal scrubs the chain it supersedes, so the
    /// owned-chunk count does not grow by a whole chain on each refresh.
    #[test]
    fn refresh_scrubs_old_checkpoint_chain() {
        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..N_KEYS {
            let mut tx = s.begin_tx();
            tx.put(
                Namespace::SETTINGS,
                format!("k{i}").as_bytes(),
                format!("v{i}").as_bytes(),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        s.write_self_heal_checkpoint().unwrap();
        let after_first = s.audit_owned_chunk_count();
        // A second self-heal with no new data appends one fresh chain +
        // replicas and scrubs the old chain, so net growth is small.
        s.write_self_heal_checkpoint().unwrap();
        let after_second = s.audit_owned_chunk_count();
        let replicas = 8usize; // generous upper bound on replica count
        assert!(
            after_second <= after_first + replicas,
            "refresh must scrub the superseded chain (was {after_first}, now {after_second})"
        );
        drop(s);
        drop(c);
        let _ = std::fs::remove_file(&path);
    }
}
