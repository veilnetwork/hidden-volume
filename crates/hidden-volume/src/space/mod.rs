//! Per-space state and public API. See DESIGN §4–§7, §12.

pub mod index;
pub mod log;
pub mod superblock;

// Audit pass 8 (E7): subtree-specific implementations
// extracted from this file. Each contains an
// `impl<'f> Space<'f>` block with the methods listed.
pub(crate) mod checkpoint;
mod commit;
mod integrity;
mod log_iter;
mod tree;
mod vacuum;
mod walk;

use zeroize::Zeroizing;

use crate::cancel::CancelToken;
use crate::chunk::ChunkKind;
use crate::chunk::format::Plaintext;
use crate::container::ContainerFile;
use crate::crypto::aead::{ChunkAead, make_aad};
use crate::crypto::derive::{SpaceKeys, derive_chunk_key};
use crate::open::{scan_and_recover, scan_and_recover_with_cancel};
use crate::redact::{Redacted, redacted_debug};
use crate::tx::Tx;
use crate::tx::commit::{CommitPayload, IndexRoot};
use crate::{CHUNK_SIZE, Error, NONCE_LEN, Result};

use self::index::{IndexNode, Namespace};
use self::superblock::{NO_RECORD, Superblock};
use self::walk::TreeWalk;

#[cfg(test)]
thread_local! {
    /// Chunks this thread has AEAD-opened through [`Space`], ever.
    ///
    /// The cost of a commit is the point of audit HV-16, and wall time
    /// is the wrong way to assert it — it is fsync-bound, machine-
    /// dependent and flaky under a loaded test runner. Chunk reads are
    /// the thing that used to scale with the namespace, and counting
    /// them is exact.
    ///
    /// Thread-local rather than a global counter: integration and unit
    /// tests run concurrently in one process, and a shared `AtomicU64`
    /// would have each of them measuring the others' work.
    pub(crate) static CHUNK_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };

    /// Test-only write fault: `Some((kind, n))` fails the `n`-th
    /// [`Space::append_chunk`] of `kind` counted from the moment it was armed.
    ///
    /// The superblock-publish window cannot be entered from outside. It opens
    /// on a file the crate has just written to successfully and closes an
    /// `fsync` later, so the only way to fail it — a full disk, a failing
    /// device — is to inject the failure. `n > 1` is the interesting setting:
    /// it lets the FIRST replica land on the disk before the next append
    /// fails, which is the state the whole uncertainty is about.
    ///
    /// Thread-local, not a `static AtomicU64`: `cargo test` runs a binary's
    /// tests on parallel threads, and a process-wide fault would fire inside
    /// whatever unrelated commit happened to be in flight (the lesson the
    /// `CREATE_FSYNC_FAILS` hook in `container/file.rs` records).
    static FORCED_APPEND_FAILURE: std::cell::Cell<Option<(ChunkKind, u32)>> =
        const { std::cell::Cell::new(None) };
}

/// Arm [`FORCED_APPEND_FAILURE`] on this thread; restores on drop so a panicking
/// test cannot leak the fault into whatever runs next in the same thread.
#[cfg(test)]
pub(crate) struct ForcedAppendFailure;

#[cfg(test)]
impl ForcedAppendFailure {
    /// Fail the `nth` (1-based) append of `kind` from now.
    pub(crate) fn arm(kind: ChunkKind, nth: u32) -> Self {
        assert!(nth >= 1, "nth is 1-based");
        FORCED_APPEND_FAILURE.with(|c| c.set(Some((kind, nth))));
        Self
    }
}

#[cfg(test)]
impl Drop for ForcedAppendFailure {
    fn drop(&mut self) {
        FORCED_APPEND_FAILURE.with(|c| c.set(None));
    }
}

/// Countdown + verdict for the armed fault, if it names `kind`.
#[cfg(test)]
fn forced_append_failure(kind: ChunkKind) -> bool {
    FORCED_APPEND_FAILURE.with(|c| match c.get() {
        Some((armed, 1)) if armed == kind => {
            c.set(None);
            true
        },
        Some((armed, n)) if armed == kind => {
            c.set(Some((armed, n - 1)));
            false
        },
        _ => false,
    })
}

/// Aggregate statistics for a [`Space`] — the structured form host-apps
/// typically render in a "Storage" / "About this profile" UI page.
///
/// Cheap to compute: walks the per-namespace KV-index trees once
/// (same cost as calling [`Space::count`] for every namespace).
/// Does NOT walk DataBatch chunks or verify integrity — for that use
/// [`Space::verify_integrity`].
///
/// Marked `#[non_exhaustive]` — host-apps construct nothing; the
/// library may add fields (e.g. `total_log_entries`, `bytes_owned`)
/// in future minor releases without bumping major.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SpaceStats {
    /// Current monotonic commit counter (same as [`Space::commit_seq`]).
    pub commit_seq: u64,
    /// Number of distinct seqs in [`Space::commit_history`] —
    /// recoverable Superblocks still on disk.
    pub commit_history_len: usize,
    /// Number of chunks owned by this space (decryptable under its
    /// key). Includes Superblock replicas, Commit chunks, IndexNode
    /// chunks, and DataBatch chunks.
    pub owned_chunk_count: usize,
    /// Total slot count of the underlying container file (excluding
    /// the cleartext header chunk). The host-app uses this together
    /// with [`Self::owned_chunk_count`] to decide when to call
    /// [`crate::Container::compact_known`] — see
    /// [`Self::utilization_ratio`] for the convenience accessor.
    /// Audit pass 17: surfaced so the "is the file too sparse?"
    /// trigger does not require a separate `Container::file_chunks()`
    /// call after dropping the `Space` handle.
    pub total_slot_count: u64,
    /// Per-namespace `(namespace, entry_count)` pairs in ascending
    /// `Namespace.0` order. For KV namespaces `entry_count` is the
    /// KV pair count; for log namespaces it is the log-entry count
    /// (which equals the KV-index entry count, since each log
    /// record is one KV pointer).
    pub namespace_counts: Vec<(Namespace, usize)>,
}

impl SpaceStats {
    /// Total entries across all namespaces (sum of `namespace_counts`
    /// values). Useful for a single "items in this profile" headline
    /// number in a UI.
    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.namespace_counts.iter().map(|(_, n)| *n).sum()
    }

    /// Fraction of the container file's slot grid that is owned by
    /// **this space**, in `[0.0, 1.0]`. A multi-space container will
    /// have ratios that sum to less than 1.0 (the rest is garbage
    /// padding + foreign hidden spaces); a single-space container
    /// approaches 1.0 minus padding overhead.
    ///
    /// **Use as a `compact_known` trigger.** The append-only write
    /// invariant (DESIGN §9) means scrubbed slots are NOT reused —
    /// they remain on disk as uniform-random bytes. Over the lifetime
    /// of a heavy-delete workload (e.g. a messenger that erases
    /// expired conversations), the file's high-water mark drifts
    /// upward while the "live" content shrinks. When this ratio drops
    /// below a host-app-chosen threshold (e.g. `0.5`), it's time to
    /// call [`crate::Container::compact_known`] to physically reclaim
    /// the disk space and rotate the `container_id`. See
    /// `docs/en/guide/operations.md` §3 "Reclaiming disk space".
    ///
    /// Returns `0.0` for an empty container (no slots), avoiding
    /// division by zero.
    #[must_use]
    pub fn utilization_ratio(&self) -> f64 {
        if self.total_slot_count == 0 {
            0.0
        } else {
            self.owned_chunk_count as f64 / self.total_slot_count as f64
        }
    }
}

/// Result of a successful [`Space::verify_integrity`] walk.
///
/// All counts are over chunks reachable from the current Superblock;
/// older Superblock or Commit chunks (kept on disk as crash-recovery
/// fallbacks) are excluded. Since the M2 audit fix (2026-05-10)
/// `DataBatch` chunks of log namespaces ARE covered — see
/// [`Self::data_batches_verified`].
///
/// Marked `#[non_exhaustive]` — only the library constructs this;
/// future fields (e.g. integrity walk duration, branch factor stats)
/// may be added in minor releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct IntegrityReport {
    /// Number of namespaces whose Merkle subtree was verified end-to-end.
    pub namespaces_verified: usize,
    /// Total IndexNode + Commit chunks read and hash-matched against
    /// their parent's recorded hash.
    pub chunks_verified: usize,
    /// Maximum tree depth observed across all namespaces, counted in
    /// levels: 0 = empty space, 1 = single-leaf namespace, 2 =
    /// leaf-and-internal split, and one more per level the writer had
    /// to add. Not capped by the format — a namespace grows a level
    /// whenever the level below outgrows one chunk — but bounded in
    /// practice by how many chunks a container may hold at all
    /// ([`crate::MAX_OPEN_SCAN_CHUNKS`]): 13 levels at 64 GiB, since
    /// audit HV-16 recomputed the fanout that bound derives from. See
    /// DESIGN §11.4.
    pub max_depth: u8,
    /// Total `DataBatch` chunks visited while walking log namespaces.
    /// AEAD-decrypted and `decode_batch`-validated; counts each batch
    /// slot once even if multiple log entries point at the same batch.
    /// Closes the M2 audit gap (2026-05-10): prior versions of this
    /// walker stopped at Leaf nodes, which left payload-bearing
    /// `DataBatch` chunks unverified.
    pub data_batches_verified: usize,
}

/// In-memory state of an opened space. Not part of the public API — the
/// public surface is [`Space`].
pub(crate) struct SpaceState {
    /// Zeroized on drop. Read `keys.container_id` for the space's binding id —
    /// `SpaceState` used to carry a second, plain `[u8; 32]` copy of it, which
    /// was a secret-derived value in a field nothing erases (audit H-06). It
    /// also made the memory-audit doc wrong, which described the duplicate as
    /// public cleartext; in v3 `container_id` is derived from the versioned
    /// master key and is not public at all.
    pub keys: SpaceKeys,
    pub superblock: Superblock,
    pub owned_slots: Vec<u64>,
    /// Sorted-ascending, deduplicated `seq` values of every Superblock
    /// chunk that AEAD-decrypted under this space's key during the open
    /// scan. Updated on every successful `commit_tx` by appending the
    /// new seq. Exposed via [`Space::commit_history`] for host-app
    /// rollback / multi-device anchor logic.
    pub commit_history: Vec<u64>,
    /// Audit M1 (2026-05-10). Last error encountered in the post-
    /// commit padding step (DESIGN §8). Does NOT affect durability of
    /// the commit itself — see [`commit_tx`](crate::space::Space::commit_tx)
    /// docs. Exposed read-only via [`Space::last_padding_error`] so
    /// host-apps can surface a privacy-hardening warning without
    /// confusing it with a commit failure.
    pub last_padding_error: Option<crate::Error>,
    /// Why the last superblock publish failed, if one did (report8 H-09).
    ///
    /// [`Space::publish_superblock`] answers [`Error::PublishUncertain`] for
    /// every failure inside its window, because that is the only thing the
    /// caller can act on: the seq is burnt, a replica may be on the disk, and
    /// the remedy is a reopen no matter which step broke. That answer is
    /// deliberately uniform, so the underlying cause — ENOSPC, EIO, a revoked
    /// device — would otherwise be discarded at exactly the moment an operator
    /// wants it. Parked here instead, the same way `last_padding_error` parks
    /// the cause of a skipped padding round. Cleared by the next successful
    /// publish.
    ///
    /// Diagnostic only. It says nothing about whether the era landed — nothing
    /// on this side of a reopen can.
    pub last_publish_error: Option<crate::Error>,
    /// Per-`seq` cache of the decrypted `Commit`-chunk payload bytes (the
    /// `CommitPayload` wire bytes living at `superblock.root_slot`), so the
    /// read-hot [`Space::load_prior_roots`] does not re-read + re-AEAD-decrypt
    /// the same Commit chunk on every namespace lookup — a 50-namespace read
    /// sweep was 50 redundant XChaCha20-Poly1305 opens of one chunk.
    ///
    /// `(seq, bytes)`: served ONLY while `seq == superblock.seq`. A successful
    /// `commit_tx` advances `superblock.seq` and clears this, and the `seq`
    /// equality check is a backstop, so a stale era can never be served (`seq`
    /// is strictly monotonic per space — DESIGN §6 Inv-W3). The bytes are
    /// decrypted plaintext, held in [`Redacted`] and scrubbed on drop / replace
    /// so they never outlive their commit era in cleartext.
    ///
    /// It used to be a [`Zeroizing`], which scrubs but does **not** redact:
    /// the upstream crate derives `Debug` on that wrapper, so this field
    /// printed a decrypted commit payload byte for byte through any `{:?}`
    /// that reached it (audit HV-01).
    pub roots_payload_cache: Option<(u64, Redacted<Vec<u8>>)>,
    /// Highest `seq` for which a Superblock replica may already be on disk,
    /// whether or not the publish that wrote it completed.
    ///
    /// Both publishers (`commit_tx`, `write_self_heal_checkpoint`) append N
    /// replicas and adopt `superblock` only after the final `fsync`. A failure
    /// in between — ENOSPC on the second replica, a failed `fsync` — leaves a
    /// replica of that seq on disk while `superblock.seq` still names the
    /// previous era. Deriving the next seq from `superblock.seq` alone then
    /// re-used that number for a DIFFERENT payload, and the open scan resolves
    /// a same-seq collision by slot order: one of the two commits vanished
    /// silently, with `verify_integrity` satisfied (the winner is
    /// self-consistent) and the commit-history anchor showing no fork.
    ///
    /// Seeded from the highest seq observed ANYWHERE in the open scan, not
    /// from the winning superblock, so a seq burnt by a crash is skipped
    /// across restarts too.
    pub attempted_seq: u64,
    /// A Superblock chunk that decrypted under THIS space's key, carried a
    /// HIGHER `seq` than the one we settled on, and could not be parsed.
    ///
    /// AEAD-passing means it is genuinely ours, not noise — so this is a
    /// writer we do not understand having published state newer than the state
    /// we are about to present. The open still succeeds from the best readable
    /// superblock (a corrupt or forged superblock must not be able to brick a
    /// space — that fallback is deliberate), but everything that would ACT on
    /// the stale view is refused:
    ///
    ///  * `vacuum_orphans`, which would delete every chunk unreachable from the
    ///    stale root — including all of the newer writer's;
    ///  * `commit_tx`, which would branch the space by committing on top of it;
    ///  * the checkpoint self-heal, which would record the stale set as truth.
    ///
    /// This is the invariant whose absence turned a format extension into
    /// silent data loss: the scan dropped the superblock it could not parse,
    /// fell back to an older one, and proceeded straight to destructive
    /// maintenance. A version gate stops one known case; this stops the class.
    pub unreadable_newer_superblock: Option<u64>,
}

// `keys` redacts itself and `roots_payload_cache` is [`Redacted`], so both
// are safe to name; the allow-list shape means a field added later prints
// nothing until someone adds it here (audit HV-01).
redacted_debug!(SpaceState {
    keys,
    superblock,
    commit_history,
    last_padding_error,
    last_publish_error,
    roots_payload_cache,
    attempted_seq,
    unreadable_newer_superblock
});

impl SpaceState {
    /// `container_id` is no longer a parameter: it was always
    /// `keys.container_id` at every call site, and taking it separately is what
    /// let the two copies exist (audit H-06).
    pub(crate) fn fresh(keys: SpaceKeys) -> Self {
        Self {
            keys,
            unreadable_newer_superblock: None,
            superblock: Superblock {
                seq: 0,
                root_slot: NO_RECORD,
                root_hash: [0u8; 32],
                checkpoint_slot: NO_RECORD,
            },
            owned_slots: Vec::new(),
            commit_history: Vec::new(),
            last_padding_error: None,
            last_publish_error: None,
            roots_payload_cache: None,
            attempted_seq: 0,
        }
    }
}

/// An opened space inside a container.
///
/// Holds an exclusive `&mut` borrow on the underlying file for the
/// duration of the borrow — drop the `Space` to release. Lifetime `'f`
/// ties the space to the file handle that opened it; this statically
/// prevents using a stale `Space` after the container is closed or
/// reopened.
pub struct Space<'f> {
    file: &'f mut ContainerFile,
    state: SpaceState,
}

redacted_debug!(Space<'f> { state });

impl<'f> Space<'f> {
    /// Open an existing space identified by `keys`. Performs the
    /// trial-decrypt scan (DESIGN §5) and returns the recovered
    /// state. `cancel` polls at periodic checkpoints inside the scan
    /// loop; pass `None` for non-cancellable behaviour. Audit pass 8
    /// (D10): the previous `open(file, keys)` and `open_with_cancel(...)`
    /// pair is consolidated into this single method.
    pub(crate) fn open_with_cancel(
        file: &'f mut ContainerFile,
        keys: SpaceKeys,
        cancel: Option<&CancelToken>,
    ) -> Result<Self> {
        let state = scan_and_recover_with_cancel(file, keys, cancel)?;
        Ok(Self { file, state })
    }

    /// Parallel variant of [`Self::open`] (feature `parallel-scan`,
    /// Unix only). Uses rayon's work-stealing pool to parallelize
    /// AEAD-decrypts across slots.
    #[cfg(all(feature = "parallel-scan", unix))]
    pub(crate) fn open_parallel(file: &'f mut ContainerFile, keys: SpaceKeys) -> Result<Self> {
        let state = crate::open::scan_and_recover_parallel(file, keys)?;
        Ok(Self { file, state })
    }

    /// Constant-time companion to [`Self::open_parallel`] — closes
    /// the dominant component of the TM1 timing oracle on the
    /// parallel scan path. See [`crate::open::scan_and_recover_parallel_constant_time`].
    #[cfg(all(feature = "parallel-scan", unix))]
    pub(crate) fn open_parallel_constant_time(
        file: &'f mut ContainerFile,
        keys: SpaceKeys,
    ) -> Result<Self> {
        let state = crate::open::scan_and_recover_parallel_constant_time(file, keys)?;
        Ok(Self { file, state })
    }

    /// Memory-mapped variant of [`Self::open`] (feature `mmap`,
    /// Unix only). Maps the entire file once and slices each chunk
    /// out of the mapping for AEAD-decryption — zero allocation per
    /// chunk on the read path.
    #[cfg(all(feature = "mmap", unix))]
    pub(crate) fn open_mmap(file: &'f mut ContainerFile, keys: SpaceKeys) -> Result<Self> {
        let state = crate::open::scan_and_recover_mmap(file, keys)?;
        Ok(Self { file, state })
    }

    /// Constant-time companion to [`Self::open_mmap`] — closes the
    /// dominant component of the TM1 timing oracle on the mmap scan
    /// path. See [`crate::open::scan_and_recover_mmap_constant_time`].
    #[cfg(all(feature = "mmap", unix))]
    pub(crate) fn open_mmap_constant_time(
        file: &'f mut ContainerFile,
        keys: SpaceKeys,
    ) -> Result<Self> {
        let state = crate::open::scan_and_recover_mmap_constant_time(file, keys)?;
        Ok(Self { file, state })
    }

    /// Constant-time-scan variant of [`Self::open_with_cancel`] —
    /// closes the TM1 timing oracle for the sequential path by
    /// running a ChaCha20 timing-equalizer on every MAC-fail. See
    /// [`crate::Container::open_space_constant_time`] for the
    /// public entry point + threat-model §4.4 F-TM1.
    pub(crate) fn open_constant_time(file: &'f mut ContainerFile, keys: SpaceKeys) -> Result<Self> {
        let state = crate::open::scan_and_recover_constant_time(file, keys)?;
        Ok(Self { file, state })
    }

    /// Bootstrap a new space with `keys`: scans first to refuse collision,
    /// then writes an initial superblock chunk so future `open` finds it.
    pub(crate) fn create(file: &'f mut ContainerFile, keys: SpaceKeys) -> Result<Self> {
        match scan_and_recover(file, keys.clone()) {
            Ok(_) => return Err(Error::SpaceAlreadyExists),
            Err(Error::AuthFailed) => {},
            Err(other) => return Err(other),
        }

        // v3: container_id is derived per-space inside SpaceKeys::from_master,
        // no longer stored in the cleartext header — and read from there, not
        // copied out.
        let mut space = Self {
            file,
            state: SpaceState::fresh(keys),
        };

        // Initial Superblock with seq=1, no namespaces yet (root_slot
        // = NO_RECORD; future Tx commits link in a Commit chunk).
        // Multiple replicas for resilience (DESIGN §7).
        let initial = Superblock {
            seq: 1,
            root_slot: NO_RECORD,
            root_hash: [0u8; 32],
            checkpoint_slot: NO_RECORD,
        };
        let replicas = space.file.superblock_replicas.max(1);
        for _ in 0..replicas {
            space.append_superblock(&initial)?;
        }
        space.file.fsync()?;
        space.state.superblock = initial;
        space.state.commit_history.push(1);
        Ok(space)
    }

    /// Re-attach a previously [detached](Self::into_state) [`SpaceState`] to a
    /// container file, yielding a usable `Space` again. The seam that lets a
    /// host hold MANY spaces' states at once (each detached) and bind one to the
    /// file per operation — see [`crate::MultiSpace`]. The `'f` borrow is only
    /// held for the duration of the bound operation, so the single file (and its
    /// exclusive lock) is shared serially across all hosted spaces.
    pub(crate) fn from_state(file: &'f mut ContainerFile, state: SpaceState) -> Self {
        Self { file, state }
    }

    /// Detach this space's [`SpaceState`], dropping the file borrow so the file
    /// is free for another hosted space. Companion to [`Self::from_state`].
    pub(crate) fn into_state(self) -> SpaceState {
        self.state
    }

    /// Per-space monotonic commit counter. Exposed for host-app rollback
    /// detection (DESIGN §11.2): host-app stores this value externally
    /// after a successful commit, then on the next open compares the
    /// stored value to whatever this returns. If the new value is lower,
    /// the file has been rolled back.
    ///
    /// **Privacy contract.** Do NOT anchor decoy/duress spaces — anchoring
    /// presence reveals presence. Anchoring is host-app policy.
    #[must_use]
    pub fn commit_seq(&self) -> u64 {
        self.state.superblock.seq
    }

    /// This space's [`SpaceKeys`] — the per-space decryption root, derived at
    /// open time from the password (Argon2id + version-bind). Returns a clone so
    /// a host-app can persist it for keys-only reopen via
    /// [`crate::Container::open_space_with_keys`] (the documented external-keyring
    /// / master-space workflow; see [`crate::Container::derive_space_keys`]).
    ///
    /// **Sensitive.** These bytes bypass Argon2 on reopen, so storing them
    /// outside the process forfeits the brute-force protection of the password.
    /// Keep them only inside another deniable space (e.g. a master roster);
    /// never log or persist them in the clear. Do NOT expose for decoy/duress
    /// spaces whose presence must stay hidden.
    #[must_use]
    pub fn space_keys(&self) -> SpaceKeys {
        self.state.keys.clone()
    }

    /// All recoverable commit-anchor seq numbers for this space, sorted
    /// ascending. Each entry is a `seq` whose Superblock chunk is still
    /// present on disk (one or more replicas) and decrypts under this
    /// space's key.
    ///
    /// Use cases (host-app, see `docs/en/guide/multi-device.md`):
    /// - **Rollback verification.** After reopening, the host-app's
    ///   externally-stored anchor `seq_a` should appear in this list. If
    ///   `commit_seq() < seq_a`, the file was rolled back. If
    ///   `commit_seq() >= seq_a` but `seq_a` is absent, the file was
    ///   forked (different timeline) — treat as adversarial.
    /// - **P2P sync state.** Devices that share a container can compare
    ///   histories to detect divergent timelines and decide reconciliation
    ///   strategy at the host-app layer (the library does not perform
    ///   sync — see `docs/en/guide/multi-device.md`).
    ///
    /// **What is in the list.** Every Superblock chunk that AEAD-decrypts
    /// under this space's key contributes one seq, deduplicated across
    /// replicas. The initial Superblock (`seq = 1`, written at
    /// [`Container::create_space`](crate::Container::create_space) time)
    /// counts.
    ///
    /// **What is NOT in the list.** Seqs whose Superblock replicas have
    /// all been physically removed from disk — most importantly, after
    /// [`Container::compact_known`](crate::Container::compact_known) /
    /// [`compact_known`](crate::Container::compact_known) the destination
    /// container is fresh and its history starts at `[1]` regardless of
    /// the source's history. Hosts must re-anchor after compaction.
    ///
    /// **Privacy contract.** Same as [`Space::commit_seq`]: do NOT
    /// publish the history of a decoy/duress space. The shape of the
    /// list (length, gaps if any) is metadata about activity that an
    /// adversary with side-channel access to the host-app could exploit.
    #[must_use]
    pub fn commit_history(&self) -> &[u64] {
        &self.state.commit_history
    }

    /// Set the post-commit padding policy on the underlying
    /// container. Equivalent to calling
    /// [`crate::Container::set_padding_policy`] before opening this
    /// space — the policy is held by `ContainerFile` and shared
    /// between Container and any active Space. Audit pass 7 (S1):
    /// added so FFI / async wrappers can configure padding without
    /// dropping the open handle.
    ///
    /// Returns [`Error::ReadOnly`] when called on a handle that was
    /// opened via [`crate::Container::open_readonly`] (`LOCK_SH`).
    /// Audit pass 10 (M1): closes a strict-RO contract violation —
    /// previously this method silently mutated `padding_policy` on
    /// RO handles, contradicting `Container::set_padding_policy`'s
    /// `Err(ReadOnly)` behaviour and breaking the asymmetry that
    /// async / FFI wrappers depend on (they route through
    /// `with_space_mut()`).
    pub fn set_padding_policy(&mut self, policy: crate::padding::PaddingPolicy) -> Result<()> {
        if !self.file.lock_mode.allows_writes() {
            return Err(Error::ReadOnly);
        }
        self.file.padding_policy = policy;
        Ok(())
    }

    /// Current post-commit padding policy. See
    /// [`Self::set_padding_policy`].
    #[must_use]
    pub fn padding_policy(&self) -> crate::padding::PaddingPolicy {
        self.file.padding_policy
    }

    /// Last error from the post-commit padding step, if any. Audit M1
    /// (2026-05-10): padding failures DO NOT downgrade a durable
    /// commit — `Tx::commit` returns `Ok(seq)` even if this field is
    /// `Some(_)`. Host-apps may surface this as a privacy-hardening
    /// warning (the affected commit's size is observable to a
    /// multi-snapshot adversary) without confusing it with a commit
    /// failure. Cleared on every successful padding round.
    #[must_use]
    pub fn last_padding_error(&self) -> Option<&crate::Error> {
        self.state.last_padding_error.as_ref()
    }

    /// Why the last superblock publish failed, if one did (report8 H-09).
    ///
    /// A failed publish answers [`Error::PublishUncertain`], which names the
    /// remedy (reopen) rather than the cause, because the remedy is the same
    /// whichever step broke. The cause is kept here for logs and bug reports:
    /// a device that is out of space and one that is failing want different
    /// things from an operator, and `PublishUncertain` alone cannot tell them
    /// apart. Cleared on the next successful publish.
    ///
    /// Diagnostic only — it does NOT say whether the era reached the disk.
    #[must_use]
    pub fn last_publish_error(&self) -> Option<&crate::Error> {
        self.state.last_publish_error.as_ref()
    }

    /// Number of chunks owned by this space — chunks that AEAD-decrypt
    /// under our key. Useful for verifying scrub behavior in tests
    /// (after delete + commit, this should not grow indefinitely).
    /// Production callers usually don't need this.
    #[must_use]
    pub fn audit_owned_chunk_count(&self) -> usize {
        self.state.owned_slots.len()
    }

    /// Aggregate statistics for this space — the structured form most
    /// host-app UIs render in a "Storage" / "About this profile"
    /// section. Returns commit-seq, history length, owned-chunk count,
    /// and per-namespace entry counts in one call.
    ///
    /// **Cost.** Walks the KV-index tree of every active namespace
    /// once (same cost as [`Self::count`] per namespace summed). Does
    /// NOT walk DataBatch chunks and does NOT verify integrity — for
    /// that use [`Self::verify_integrity`].
    ///
    /// **Read-only safe.** No writes occur; this method works on a
    /// handle returned by [`crate::Container::open_readonly`].
    pub fn stats(&mut self) -> Result<SpaceStats> {
        let namespaces = self.list_namespaces()?;
        let mut namespace_counts = Vec::with_capacity(namespaces.len());
        for ns in namespaces {
            let count = self.count(ns)?;
            namespace_counts.push((ns, count));
        }
        Ok(SpaceStats {
            commit_seq: self.commit_seq(),
            commit_history_len: self.commit_history().len(),
            owned_chunk_count: self.audit_owned_chunk_count(),
            total_slot_count: self.file.slot_count(),
            namespace_counts,
        })
    }

    /// Open a new transaction. Single concurrent tx per space; the tx
    /// borrows the space mutably until committed or dropped.
    pub fn begin_tx<'s>(&'s mut self) -> Tx<'s, 'f> {
        Tx::new(self)
    }

    /// Read a single value from `namespace` by `key`. `Ok(None)` if the
    /// key is absent or the namespace has never been written to.
    ///
    /// Errors with [`Error::Malformed`] if the descent leaves the shape
    /// a tree can have — deeper than this space's chunk count could
    /// hold, or through a chunk it has already read (a cycle).
    /// Defense-in-depth against a writer-bug regression or an
    /// adversarial key-holder; see the `space::walk` guard and
    /// [`docs/en/security/audits/adversarial-stance.md` F-A5](../../../docs/en/security/audits/adversarial-stance.md).
    pub fn get(&mut self, namespace: Namespace, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let root_slot = match self.find_root_slot(namespace)? {
            Some(s) => s,
            None => return Ok(None),
        };
        // Walk down to the leaf containing `key` under the same guard
        // every other walker uses — a `get` is a one-path walk, but the
        // path is still attacker-shaped: a cyclic Internal→Internal
        // chain would otherwise loop forever. The guard is consulted on
        // *entry* to each node — BEFORE matching Leaf vs Internal — so
        // a forged tree presenting a `Leaf` below the depth bound is
        // rejected identically to `collect_leaves_at` /
        // `count_leaves_at` (audit pass 20: the prior placement inside
        // the `Internal` arm let `get` accept a Leaf one level deeper
        // than every other walker).
        // `read_index_node_at_expected` additionally gates
        // `IndexNode.namespace == namespace` (audit pass 19 round 6
        // root-relabel closure).
        let mut walk = self.new_tree_walk();
        let mut depth: u8 = 0;
        let mut slot = root_slot;
        loop {
            walk.admit(slot, depth)?;
            match self.read_index_node_at_expected(slot, namespace)? {
                IndexNode::Leaf(l) => return Ok(l.get(key).map(|v| v.to_vec())),
                IndexNode::Internal(i) => {
                    let idx = i.child_index_for(key);
                    slot = i.children[idx].child_slot;
                    depth += 1;
                },
            }
        }
    }

    /// List all `(key, value)` pairs in `namespace`, sorted by key.
    /// Empty Vec for namespaces that have never been written to.
    ///
    /// **Peak is the namespace's entire plaintext**, by construction —
    /// that is what the call is. Callers that only need the keys have
    /// [`Self::list_keys`]; callers that can work a page at a time have
    /// [`Self::list_after`], whose peak is bounded by `limit` instead
    /// (audit HV-02).
    pub fn list(&mut self, namespace: Namespace) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let root_slot = match self.find_root_slot(namespace)? {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        self.collect_leaves(root_slot, namespace, &mut out)?;
        Ok(out)
    }

    /// Keys of every entry in `namespace`, sorted ascending. Empty Vec
    /// for namespaces that have never been written to.
    ///
    /// The keys-only counterpart to [`Self::list`]. Both walk the same
    /// leaves and decode the same chunks; the difference is what
    /// survives the walk. `list` keeps every value too, so its peak is
    /// the namespace's entire plaintext — but the enumerate-then-act
    /// callers (host-app GC of stale bookkeeping keys,
    /// [`Self::erase_namespace`], the FFI `kv_keys`) never look at those
    /// values, and were paying for them anyway. Here each leaf's values
    /// are dropped as the leaf is consumed, so the walk peaks at one
    /// decoded node the way [`Self::count`] does.
    ///
    /// The *result* is still O(total key bytes) by construction: it is
    /// every key. Callers that can work a page at a time should use
    /// [`Self::list_keys_after`], whose result is bounded by `limit`.
    pub fn list_keys(&mut self, namespace: Namespace) -> Result<Vec<Vec<u8>>> {
        self.list_keys_after(namespace, None, usize::MAX)
    }

    /// Paginate forward through a namespace's keys.
    ///
    /// Returns up to `limit` keys strictly greater than `after`, in
    /// ascending key order. Pass `after = None` for the first page and
    /// `after = Some(last_key_of_previous_page)` for each subsequent
    /// one — the KV counterpart of [`Self::iter_log_after`], which is
    /// the same walk keyed on `log_id` instead.
    ///
    /// Memory bound: `limit` keys plus one decoded node, independent of
    /// the namespace's total size.
    ///
    /// Read bound: the descent to `after` plus the leaves the page
    /// actually consumes. The walk seeks — at every internal node it
    /// starts at [`child_index_for(after)`][index::InternalNode::child_index_for]
    /// instead of at child 0, because every earlier sibling's subtree
    /// ends below `after` and cannot hold a key the filter would keep.
    ///
    /// Until audit HV-05 it did start at 0 and filtered in the leaf, so
    /// each page re-read the whole prefix it had already returned and
    /// paging through an N-key namespace was O(N) chunk reads *per
    /// page*. The keys came back correct either way — this is a cost
    /// fix, and the test that pins it counts chunk reads.
    pub fn list_keys_after(
        &mut self,
        namespace: Namespace,
        after: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let root_slot = match self.find_root_slot(namespace)? {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };
        // Cap the pre-allocation: `list_keys` passes `usize::MAX` to mean
        // "everything", and `Vec::with_capacity` panics on overflow.
        let mut out: Vec<Vec<u8>> = Vec::with_capacity(limit.min(1024));
        let mut walk = self.new_tree_walk();
        self.collect_leaf_keys_after_at(
            root_slot, namespace, after, limit, 0, &mut walk, &mut out,
        )?;
        Ok(out)
    }

    /// Paginate forward through a namespace's `(key, value)` pairs.
    ///
    /// The pair-carrying twin of [`Self::list_keys_after`], and the
    /// bounded-peak alternative to [`Self::list`]: up to `limit` entries
    /// whose key is strictly greater than `after`, in ascending key
    /// order. `after = None` starts at the beginning; pass the last key
    /// of the previous page for each page after that.
    ///
    /// Memory bound: `limit` entries plus one decoded node, independent
    /// of the namespace's total size. This is the difference that
    /// matters for a copy loop — [`crate::Container::repack`] used to
    /// `list` a whole namespace and then hand every pair to `Tx::put`,
    /// which copies each one, so the peak was **twice** the namespace's
    /// plaintext with no bound on either half (audit HV-02).
    ///
    /// Read bound: as in [`Self::list_keys_after`], the descent to
    /// `after` plus the leaves the page consumes — internal nodes are
    /// entered at [`child_index_for(after)`][index::InternalNode::child_index_for],
    /// so a page does not re-read the prefix it already returned. And as
    /// there, `limit` bounds the OUTPUT, not the number of chunks read;
    /// on adversarial input it is the traversal guard that terminates
    /// the walk.
    pub fn list_after(
        &mut self,
        namespace: Namespace,
        after: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let root_slot = match self.find_root_slot(namespace)? {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };
        // Cap the pre-allocation the way `list_keys_after` does: a
        // caller may pass `usize::MAX` to mean "everything", and
        // `Vec::with_capacity` panics on overflow.
        let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(limit.min(1024));
        let mut walk = self.new_tree_walk();
        self.collect_leaf_pairs_after_at(
            root_slot, namespace, after, limit, 0, &mut walk, &mut out,
        )?;
        Ok(out)
    }

    /// Number of entries in `namespace`. Walks all leaves of the tree
    /// — O(N) but only chunk reads, no decode of values. There is no
    /// count cache: `count` is rarely on a UI hot path.
    pub fn count(&mut self, namespace: Namespace) -> Result<usize> {
        let root_slot = match self.find_root_slot(namespace)? {
            Some(s) => s,
            None => return Ok(0),
        };
        self.count_leaves(root_slot, namespace)
    }

    /// Erase **every** entry in `namespace` in a single transaction.
    /// Returns the number of entries removed.
    ///
    /// Use case (messenger): "Clear chat history" or "Wipe contacts" —
    /// the user wants to drop a whole namespace's worth of data with
    /// one click. Doing this via per-key `Tx::delete` requires the
    /// host-app to enumerate keys first, which is awkward and easy to
    /// get wrong; this method does the right thing in one call.
    ///
    /// ## Mechanics
    ///
    /// 1. Enumerate the namespace's keys via [`Self::list_keys`] — keys
    ///    only, since a delete is addressed by key.
    /// 2. Open a single `Tx`, issue a `delete` for each key, commit.
    /// 3. The new commit omits this namespace from its `IndexRoot` set
    ///    (since the rebuilt tree is empty). Old IndexNode chunks
    ///    become orphans.
    /// 4. The next `Container::open_space` (or an explicit
    ///    [`Self::vacuum_orphans`] call now) scrubs those orphan
    ///    IndexNode chunks → forward-secrecy for the keys themselves.
    ///
    /// ## Forward-secrecy caveat for log namespaces
    ///
    /// `vacuum_orphans` does NOT scrub `DataBatch` chunks (a single
    /// batch may still contain live entries from other log_ids; safe
    /// scrub requires repacking). For log namespaces, calling
    /// `erase_namespace` followed by an immediate
    /// [`crate::Container::compact_known`] is the recipe that
    /// physically eliminates message bytes. Until compaction, an
    /// adversary with the password can still recover erased messages
    /// from their (no-longer-pointed-to but still-AEAD-decryptable)
    /// `DataBatch` chunks.
    ///
    /// ## Cost
    ///
    /// One Tx → 3-fsync barrier. Pending state: `O(N)` in-memory
    /// `Delete { key }` ops where `N` is the namespace's entry count.
    /// For a 10 K-entry namespace this is ~300 KiB of pending state —
    /// fine for any device class.
    ///
    /// ## Idempotence
    ///
    /// Erasing an already-empty namespace is a no-op (returns `0`)
    /// and does NOT produce a commit (the underlying `Tx` is dropped
    /// without commit when there is nothing to do).
    pub fn erase_namespace(&mut self, namespace: Namespace) -> Result<usize> {
        // R-NSKIND: works on both Kv AND Log namespaces. Internally
        // we walk the KV index via `list_keys` (which enumerates keys
        // regardless of the namespace's kind — for Log namespaces those
        // are the `log_id_key_be` keys) and queue Delete ops tagged
        // `KvOrigin::Erase`, the one origin `commit_tx` lets disagree
        // with the recorded kind (audit HV-04). It used to be that ANY
        // pure-Delete op set was let through, which is the same
        // permission stated by shape instead of by intent — and by
        // shape it also covered a `Tx::delete` aimed at a log record.
        //
        // `list_keys`, not `list`: a delete is addressed by key, so the
        // values this used to materialise alongside them were read,
        // held for the length of the whole transaction, and never
        // looked at. On a namespace holding megabytes of message bodies
        // that is the difference between peaking at the keys and
        // peaking at the entire plaintext (report5 HV-04).
        let mut keys = self.list_keys(namespace)?;
        if keys.is_empty() {
            return Ok(0);
        }
        let count = keys.len();
        let mut tx = self.begin_tx();
        // `drain`, not `&keys`: every key is about to exist a second
        // time as a `Delete` op, and moving it means the two copies are
        // never both live. The op list itself stays whole — the erase
        // is one transaction by contract (audit HV-03).
        for key in keys.drain(..) {
            tx.delete_internal(namespace, key, crate::tx::KvOrigin::Erase)?;
        }
        tx.commit()?;
        Ok(count)
    }

    /// List all namespaces with data in the latest commit. Useful for
    /// inspection / compaction tooling. Returned in ascending namespace
    /// order (matches the on-disk Commit roots layout).
    pub fn list_namespaces(&mut self) -> Result<Vec<Namespace>> {
        let prior_roots = self.load_prior_roots()?;
        Ok(prior_roots.into_iter().map(|r| r.namespace).collect())
    }

    /// List all namespaces with their data shape
    /// ([`crate::tx::NamespaceKind`]). R-NSKIND: each `IndexRoot`
    /// carries an explicit `kind` byte (format v2); this method
    /// surfaces the persisted classification so external tools
    /// (`Container::repack`, host-app introspection) can route by
    /// kind without re-running the v1 content-shape heuristic.
    /// Returns pairs in ascending namespace order.
    pub fn list_namespaces_with_kind(
        &mut self,
    ) -> Result<Vec<(Namespace, crate::tx::NamespaceKind)>> {
        let prior_roots = self.load_prior_roots()?;
        Ok(prior_roots
            .into_iter()
            .map(|r| (r.namespace, r.kind))
            .collect())
    }

    // --- tree walks ---
    //
    // Cross-submodule helpers below are `pub(super)` so the
    // `commit.rs` / `vacuum.rs` / `log_iter.rs` / `integrity.rs`
    // submodules (each contains an `impl<'f> Space<'f>` block) can
    // share the canonical implementation. Audit pass 8 (E7) split
    // factored these out of a single 1578-LOC file. Keep contracts
    // documented here.

    /// A fresh traversal guard sized for this space: at most one read
    /// per owned chunk, and no deeper than that many chunks could be
    /// arranged into. Every tree walk starts here — see [`walk`] for
    /// why one of those bounds alone is not enough, and why the depth
    /// bound is derived from the chunk count rather than fixed.
    pub(in crate::space) fn new_tree_walk(&self) -> TreeWalk {
        TreeWalk::with_budget(self.state.owned_slots.len())
    }

    /// Recursively flatten every IndexNode subtree rooted at `slot`
    /// into a flat `(key, value)` Vec. Used by `Space::list` and the
    /// `commit.rs` flatten-and-rebuild path.
    ///
    /// **Errors:** propagates AEAD failure or `Malformed` from
    /// [`Self::read_index_node_at`]; returns `Malformed` if the walk
    /// descends deeper than this space's chunk count could hold, if a
    /// chunk is reachable twice, or if the walk outruns its traversal
    /// budget.
    pub(super) fn collect_leaves(
        &mut self,
        slot: u64,
        namespace: Namespace,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        let mut walk = self.new_tree_walk();
        self.collect_leaves_at(slot, namespace, 0, &mut walk, out)
    }

    fn collect_leaves_at(
        &mut self,
        slot: u64,
        namespace: Namespace,
        depth: u8,
        walk: &mut TreeWalk,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        walk.admit(slot, depth)?;
        let node = self.read_index_node_at_expected(slot, namespace)?;
        match node {
            IndexNode::Leaf(l) => {
                out.extend(l.entries.into_inner());
                Ok(())
            },
            IndexNode::Internal(i) => {
                for c in i.children {
                    self.collect_leaves_at(c.child_slot, namespace, depth + 1, walk, out)?;
                }
                Ok(())
            },
        }
    }

    /// Walk leaves left-to-right, pushing the KEYS of entries greater
    /// than `after` (all of them if `after` is `None`) into `out` and
    /// dropping each entry's value as the leaf is consumed. Stops once
    /// `out.len() >= limit`.
    ///
    /// The value-discarding twin of
    /// [`log_iter`](super::log_iter)'s `collect_leaves_after_at`; it is
    /// separate rather than a filter over that one because the whole
    /// point is that no `Vec<(Vec<u8>, Vec<u8>)>` is ever built.
    ///
    /// Guarded like every other walker: `limit` bounds `out`, not the
    /// number of chunks read, so on adversarial input it is the
    /// traversal guard that terminates this — see [`super::walk`].
    /// `after` prunes it in the honest case (audit HV-05), which is a
    /// different property and does not replace the guard.
    #[allow(clippy::too_many_arguments)]
    fn collect_leaf_keys_after_at(
        &mut self,
        slot: u64,
        namespace: Namespace,
        after: Option<&[u8]>,
        limit: usize,
        depth: u8,
        walk: &mut TreeWalk,
        out: &mut Vec<Vec<u8>>,
    ) -> Result<()> {
        if out.len() >= limit {
            return Ok(());
        }
        walk.admit(slot, depth)?;
        let node = self.read_index_node_at_expected(slot, namespace)?;
        match node {
            IndexNode::Leaf(l) => {
                // `for (k, _value) in l.entries` — by value, so each value's
                // allocation is freed at the end of its iteration instead of
                // being carried to the end of the walk.
                for (k, _value) in l.entries.into_inner() {
                    if out.len() >= limit {
                        break;
                    }
                    if let Some(a) = after
                        && k.as_slice() <= a
                    {
                        continue;
                    }
                    out.push(k);
                }
                Ok(())
            },
            IndexNode::Internal(i) => {
                // Seek instead of scan (audit HV-05). Children are
                // sorted and `first_key` is the low bound of a child's
                // subtree, so every sibling before
                // `child_index_for(after)` ends strictly below `after`
                // and holds nothing this page would keep. The child AT
                // that index straddles the cursor and must still be
                // descended into.
                let first = after.map_or(0, |a| i.child_index_for(a));
                for c in i.children.into_iter().skip(first) {
                    if out.len() >= limit {
                        break;
                    }
                    self.collect_leaf_keys_after_at(
                        c.child_slot,
                        namespace,
                        after,
                        limit,
                        depth + 1,
                        walk,
                        out,
                    )?;
                }
                Ok(())
            },
        }
    }

    /// Walk leaves left-to-right, pushing the `(key, value)` PAIRS of
    /// entries greater than `after` into `out` and stopping once
    /// `out.len() >= limit`.
    ///
    /// Shape-identical to [`Self::collect_leaf_keys_after_at`] — same
    /// cursor filter, same `child_index_for` seek, same guard — with the
    /// value kept instead of dropped. Written out rather than layered on
    /// `get`-per-key because a page must cost one descent, not `limit`
    /// of them.
    #[allow(clippy::too_many_arguments)]
    fn collect_leaf_pairs_after_at(
        &mut self,
        slot: u64,
        namespace: Namespace,
        after: Option<&[u8]>,
        limit: usize,
        depth: u8,
        walk: &mut TreeWalk,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        if out.len() >= limit {
            return Ok(());
        }
        walk.admit(slot, depth)?;
        let node = self.read_index_node_at_expected(slot, namespace)?;
        match node {
            IndexNode::Leaf(l) => {
                for (k, value) in l.entries.into_inner() {
                    if out.len() >= limit {
                        break;
                    }
                    if let Some(a) = after
                        && k.as_slice() <= a
                    {
                        continue;
                    }
                    out.push((k, value));
                }
                Ok(())
            },
            IndexNode::Internal(i) => {
                // Seek instead of scan (audit HV-05): every sibling
                // before `child_index_for(after)` ends strictly below
                // the cursor. See `collect_leaf_keys_after_at`.
                let first = after.map_or(0, |a| i.child_index_for(a));
                for c in i.children.into_iter().skip(first) {
                    if out.len() >= limit {
                        break;
                    }
                    self.collect_leaf_pairs_after_at(
                        c.child_slot,
                        namespace,
                        after,
                        limit,
                        depth + 1,
                        walk,
                        out,
                    )?;
                }
                Ok(())
            },
        }
    }

    fn count_leaves(&mut self, slot: u64, namespace: Namespace) -> Result<usize> {
        let mut walk = self.new_tree_walk();
        self.count_leaves_at(slot, namespace, 0, &mut walk)
    }

    fn count_leaves_at(
        &mut self,
        slot: u64,
        namespace: Namespace,
        depth: u8,
        walk: &mut TreeWalk,
    ) -> Result<usize> {
        walk.admit(slot, depth)?;
        let node = self.read_index_node_at_expected(slot, namespace)?;
        match node {
            IndexNode::Leaf(l) => Ok(l.entries.len()),
            IndexNode::Internal(i) => {
                let mut total = 0;
                for c in i.children {
                    total += self.count_leaves_at(c.child_slot, namespace, depth + 1, walk)?;
                }
                Ok(total)
            },
        }
    }

    /// Locate the root IndexNode slot for `namespace` at the
    /// **current** commit. Returns `Ok(None)` if the namespace does
    /// not appear in the current `CommitPayload` (i.e. has never
    /// been written to OR was fully erased). `Ok(Some(slot))`
    /// otherwise. Used by reads (`Space::get`, `list`, `count`,
    /// `iter_log_*`, `read_log`).
    pub(super) fn find_root_slot(&mut self, namespace: Namespace) -> Result<Option<u64>> {
        let prior_roots = self.load_prior_roots()?;
        Ok(prior_roots
            .iter()
            .find(|r| r.namespace == namespace)
            .map(|r| r.index_slot))
    }

    /// Like [`Self::find_root_slot`] but returns the whole
    /// [`crate::tx::commit::IndexRoot`] — in particular its persisted
    /// [`crate::tx::NamespaceKind`] byte. The log read paths
    /// (`iter_log_*`, `read_log`) use this to enforce the kind
    /// contract from the persisted byte instead of inferring "this is
    /// a log namespace" from the 8-byte-key / DataBatch-pointer shape
    /// downstream (audit pass 20: R-NSKIND parity — vacuum/repack were
    /// already kind-driven; the read iterators still relied on the
    /// shape heuristic, giving an unpredictable error taxonomy when a
    /// KV namespace happened to hold 8-byte keys *and* values).
    pub(super) fn find_root(
        &mut self,
        namespace: Namespace,
    ) -> Result<Option<crate::tx::commit::IndexRoot>> {
        let prior_roots = self.load_prior_roots()?;
        Ok(prior_roots.into_iter().find(|r| r.namespace == namespace))
    }

    // --- internals ---

    /// Decode the current commit's `CommitPayload` and return its
    /// per-namespace root list. `Ok(vec![])` if the space has no
    /// commits yet (`superblock.root_slot == NO_RECORD`).
    ///
    /// **Errors:** AEAD failure on the Commit chunk → `AuthFailed`;
    /// `Malformed` if the chunk's kind is wrong or `CommitPayload::decode`
    /// fails. Used by `find_root_slot`, `commit_tx`, and vacuum paths.
    pub(super) fn load_prior_roots(&mut self) -> Result<Vec<IndexRoot>> {
        if self.state.superblock.root_slot == NO_RECORD {
            return Ok(Vec::new());
        }
        let seq = self.state.superblock.seq;
        // Warm cache: decode straight from the cached payload bytes for this
        // commit era, skipping the disk read + AEAD open. Decoding is pure
        // parsing (no crypto), so the AEAD — the dominant per-read cost — is paid
        // once per commit instead of once per namespace lookup. The `seq`
        // equality gate means a stale era can never be served.
        if let Some((cached_seq, bytes)) = &self.state.roots_payload_cache
            && *cached_seq == seq
        {
            return Ok(CommitPayload::decode(bytes)?.roots);
        }
        let pt = self.read_owned_chunk(self.state.superblock.root_slot)?;
        if pt.kind != ChunkKind::Commit {
            return Err(Error::Malformed(
                "superblock root_slot is not a Commit chunk",
            ));
        }
        let cp = CommitPayload::decode(&pt.payload)?;
        // Cache the verified, AEAD-decrypted payload bytes (Zeroizing) keyed by
        // the current seq for subsequent lookups in the same commit era.
        self.state.roots_payload_cache = Some((seq, Redacted::new(pt.payload)));
        Ok(cp.roots)
    }

    /// Read the IndexNode at `slot` (assumed owned by this space).
    /// Wraps [`Self::read_owned_chunk`] with a kind check + decode.
    ///
    /// **Errors:** `AuthFailed` if the slot is foreign; `Malformed`
    /// if the kind is not `IndexNode` or `IndexNode::decode` fails.
    /// Used by reachability sweeps (vacuum / orphan collection)
    /// that don't carry a namespace context; namespace-aware
    /// read paths use [`Self::read_index_node_at_expected`].
    pub(super) fn read_index_node_at(&mut self, slot: u64) -> Result<IndexNode> {
        let pt = self.read_owned_chunk(slot)?;
        if pt.kind != ChunkKind::IndexNode {
            return Err(Error::Malformed("commit root pointer not an IndexNode"));
        }
        IndexNode::decode(&pt.payload)
    }

    /// Namespace-checked variant of [`Self::read_index_node_at`]:
    /// reads + decodes the chunk, then verifies the decoded node's
    /// `namespace` byte matches `expected`. Closes the root-relabel
    /// surface (audit pass 19 round 6 user-report 2026-05-28): a
    /// key-holder / buggy writer could otherwise have an
    /// `IndexRoot` declare `namespace = A` while the actual tree's
    /// nodes carry `namespace = B`, and the regular read path
    /// would silently traverse foreign-namespace data. Used by
    /// `Space::get` / `list` / `count` and the log-iter walkers —
    /// every path with a `namespace: Namespace` parameter.
    pub(super) fn read_index_node_at_expected(
        &mut self,
        slot: u64,
        expected: Namespace,
    ) -> Result<IndexNode> {
        let node = self.read_index_node_at(slot)?;
        let node_ns = match &node {
            IndexNode::Leaf(l) => l.namespace,
            IndexNode::Internal(i) => i.namespace,
        };
        if node_ns != expected {
            return Err(Error::Malformed(
                "IndexNode.namespace != expected (relabel attempt or writer bug)",
            ));
        }
        Ok(node)
    }

    /// Encode + append a Superblock chunk. Thin wrapper over
    /// [`Self::append_chunk`] with the right `ChunkKind` and seq.
    /// Used by `commit_tx` (writes one or more replicas per commit).
    pub(super) fn append_superblock(&mut self, sb: &Superblock) -> Result<u64> {
        self.append_chunk(ChunkKind::Superblock, sb.seq, &sb.encode())
    }

    /// Publish `sb`: burn its seq, append every replica, make them durable.
    ///
    /// The single writer of a new era. Both publishers — `commit_tx` and
    /// `write_self_heal_checkpoint` — go through here so the window below has
    /// one definition instead of two copies that drift.
    ///
    /// **Every failure from here is [`Error::PublishUncertain`]** (report8
    /// H-09). The window opens when the seq is burnt, one instruction before
    /// the first replica can reach the disk, and closes when the final `fsync`
    /// returns. Inside it a replica of `sb.seq` may already be on the disk
    /// while `state.superblock` still names the previous era — which is not a
    /// write that failed but a handle that is now behind the file, and the only
    /// thing that settles which era landed is the open scan. Reporting the raw
    /// `Io` error described the syscall and misdescribed the situation: it
    /// reads as "nothing happened", and a caller who believes that will retry
    /// or vacuum on a stale root. The cause is not lost — it is parked on
    /// [`SpaceState::last_publish_error`].
    ///
    /// `what` names what the caller must reopen before doing; it renders as
    /// "reopen before {what}".
    ///
    /// **Committing is NOT blocked afterwards** (audit HV-01): the next seq is
    /// derived from `attempted_seq`, so a later commit skips the burnt number
    /// rather than publishing a second payload under it. What IS refused is the
    /// destructive maintenance that would act on the stale root — see
    /// `vacuum_orphans`.
    ///
    /// On success the caller still owns the `state.superblock = sb` swap: only
    /// it knows what else belongs in the same era transition.
    pub(super) fn publish_superblock(&mut self, sb: &Superblock, what: &'static str) -> Result<()> {
        let replicas = self.file.superblock_replicas.max(1);
        // Burn the number BEFORE the first replica can reach the disk: if one
        // lands and a later replica (or the fsync) fails, this seq must never
        // be handed out again.
        self.state.attempted_seq = sb.seq;
        let outcome = (|| -> Result<()> {
            for _ in 0..replicas {
                self.append_superblock(sb)?;
            }
            self.file.fsync()
        })();
        if let Err(cause) = outcome {
            self.state.last_publish_error = Some(cause);
            return Err(Error::PublishUncertain(what));
        }
        self.state.last_publish_error = None;
        Ok(())
    }

    /// AEAD-seal `payload` at the next free slot with the given kind
    /// and seq, append the ciphertext chunk, and record the slot in
    /// `state.owned_slots`. Returns the new slot index.
    ///
    /// **Errors:** Any I/O error from `file.append_slot`; AEAD seal
    /// failure (effectively impossible — XChaCha20-Poly1305 with
    /// random nonce never errors on input).
    ///
    /// **Side effects:** appends to `state.owned_slots`. On caller
    /// error mid-`commit_tx`, `state.owned_slots` may include slots
    /// that aren't yet reachable from any committed Superblock —
    /// the next `vacuum_orphans` reclaims them.
    pub(super) fn append_chunk(
        &mut self,
        kind: ChunkKind,
        seq: u64,
        payload: &[u8],
    ) -> Result<u64> {
        #[cfg(test)]
        if forced_append_failure(kind) {
            return Err(Error::Io(std::io::Error::other(
                "test hook: forced chunk append failure",
            )));
        }
        let slot = self.file.slot_count();
        let key = derive_chunk_key(
            &self.state.keys.aead_root,
            &self.state.keys.container_id,
            slot,
        );
        let aead = ChunkAead::new(&key);
        let pt = Plaintext {
            kind,
            seq,
            payload: payload.to_vec(),
        };
        // Encoded plaintext sits on the stack as a 4040-byte array; wrap
        // in Zeroizing so that when this stack slot is reclaimed at end
        // of function, the plaintext bytes are scrubbed before the slot
        // can be reused for unrelated data.
        let pt_bytes: Zeroizing<[u8; crate::PLAINTEXT_LEN]> = Zeroizing::new(pt.encode()?);
        let aad = make_aad(&self.state.keys.container_id, slot);
        let (nonce, ct) = aead.seal(&pt_bytes[..], aad)?;
        let mut chunk = [0u8; CHUNK_SIZE];
        chunk[..NONCE_LEN].copy_from_slice(&nonce);
        chunk[NONCE_LEN..].copy_from_slice(&ct);
        self.file.append_slot(&chunk)?;
        self.state.owned_slots.push(slot);
        Ok(slot)
    }

    /// Read + AEAD-decrypt the chunk at `slot` under this space's
    /// per-slot key. Used by every read path (integrity walk, log
    /// iteration, vacuum classification, find_root_slot).
    ///
    /// **Errors:**
    ///
    /// | Error | Meaning |
    /// |---|---|
    /// | `Io(...)` | Filesystem I/O failed reading the slot |
    /// | `AuthFailed` | The slot is NOT owned by this space (AEAD-decrypt failed under our per-slot key) |
    /// | `Malformed(...)` | AEAD passed but `Plaintext::decode` rejected the bytes (writer-bug regression or bit-flip past AEAD) |
    ///
    /// **Caller-side mapping note (audit pass 8 E7):** `integrity.rs`
    /// translates `AuthFailed` here into `IntegrityFailure` (the
    /// integrity walk's contract is "AEAD-fail on a chunk we expected
    /// to own = corruption"); `commit.rs` / `log_iter.rs` /
    /// `vacuum.rs` propagate as-is.
    pub(super) fn read_owned_chunk(&mut self, slot: u64) -> Result<Plaintext> {
        #[cfg(test)]
        CHUNK_READS.with(|n| n.set(n.get() + 1));
        let chunk = self.file.read_slot(slot)?;
        let key = derive_chunk_key(
            &self.state.keys.aead_root,
            &self.state.keys.container_id,
            slot,
        );
        let aead = ChunkAead::new(&key);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&chunk[..NONCE_LEN]);
        let ct = &chunk[NONCE_LEN..];
        let aad = make_aad(&self.state.keys.container_id, slot);
        // `aead.open` returns Zeroizing<Vec<u8>> — the AEAD-decrypted
        // bytes are scrubbed on drop. `Plaintext::decode` borrows
        // immutably; the wrapper drops at end of this function,
        // scrubbing the heap region.
        let pt_bytes = aead.open(&nonce, ct, aad)?;
        Plaintext::decode(&pt_bytes)
    }
}

/// What a page of pagination costs, in chunk reads (audit HV-05).
///
/// These live in-crate for the same reason the HV-16 commit-cost tests
/// do: the number is not observable through the public API, and wall
/// time would make the assertion a stopwatch race. And it has to be the
/// *number of reads* — every one of these walkers returned the correct
/// keys before the fix too, so a test that only checks the page content
/// passes against the defect.
#[cfg(test)]
mod pagination_cost_tests {
    use super::*;
    use crate::Container;
    use crate::container::ContainerOptions;
    use crate::crypto::kdf::Argon2Params;
    use crate::padding::PaddingPolicy;

    /// Big enough that the tree has interior levels to prune. Small
    /// enough that seeding it stays under a second in debug.
    const N: u64 = 20_000;
    /// One page, as a chat screen would ask for it.
    const PAGE: usize = 50;

    fn kv_key(i: u64) -> Vec<u8> {
        format!("k{i:08}").into_bytes()
    }

    fn scratch() -> std::path::PathBuf {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let p = tmp.path().to_owned();
        drop(tmp);
        p
    }

    /// Chunk reads performed by `f`, plus whatever `f` returned.
    fn reads<R>(f: impl FnOnce() -> R) -> (u64, R) {
        CHUNK_READS.with(|r| r.set(0));
        let out = f();
        (CHUNK_READS.with(|r| r.get()), out)
    }

    /// A space holding `N` KV keys and `N` log entries, handed to `f`.
    fn with_seeded_space<R>(f: impl FnOnce(&mut Space<'_>) -> R) -> R {
        let path = scratch();
        let out = {
            let mut c = Container::create_with_options(
                &path,
                ContainerOptions {
                    argon2: Argon2Params::MIN,
                    initial_garbage_chunks: 0,
                    padding_policy: PaddingPolicy::None,
                    superblock_replicas: 1,
                },
            )
            .unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            for batch in 0..(N / 1_000) {
                let mut tx = s.begin_tx();
                for i in (batch * 1_000)..(batch * 1_000 + 1_000) {
                    tx.put(Namespace::SETTINGS, &kv_key(i), b"v").unwrap();
                    tx.append_log(Namespace::MESSAGE_LOG, i, b"m").unwrap();
                }
                tx.commit().unwrap();
            }
            f(&mut s)
        };
        let _ = std::fs::remove_file(&path);
        out
    }

    /// What a seeking page may cost over the cheapest possible page.
    ///
    /// Measured, it is currently **zero** — a page from the tail reads
    /// exactly what a page from the head reads. Two is headroom for one
    /// extra descent, not a licence to scan: at N = 20 000 the unpruned
    /// walkers cost 94 (KV) and 130 (log) reads against 4 and 5, so
    /// every probe that half-disables a seek lands far outside this.
    const SLACK: u64 = 2;

    #[test]
    fn a_kv_page_far_from_the_start_costs_what_the_first_page_costs() {
        with_seeded_space(|s| {
            let (first_reads, first) =
                reads(|| s.list_keys_after(Namespace::SETTINGS, None, PAGE).unwrap());
            assert_eq!(first.len(), PAGE, "fixture must fill a page");
            assert_eq!(first[0], kv_key(0));

            let cursor = kv_key(N - PAGE as u64 - 1);
            let (far_reads, far) = reads(|| {
                s.list_keys_after(Namespace::SETTINGS, Some(&cursor), PAGE)
                    .unwrap()
            });
            assert_eq!(far.len(), PAGE, "the tail page must be full too");
            assert_eq!(
                far[0],
                kv_key(N - PAGE as u64),
                "and start after the cursor"
            );

            assert!(
                far_reads <= first_reads + SLACK,
                "list_keys_after re-read the prefix it had already returned: \
                 first page {first_reads} chunks, page at key {} {far_reads} chunks",
                N - PAGE as u64
            );
        });
    }

    #[test]
    fn a_log_page_far_from_the_start_costs_what_the_first_page_costs() {
        with_seeded_space(|s| {
            let (first_reads, first) = reads(|| {
                s.iter_log_after(Namespace::MESSAGE_LOG, None, PAGE)
                    .unwrap()
            });
            assert_eq!(first.len(), PAGE, "fixture must fill a page");
            assert_eq!(first[0].0, 0);

            let cursor = N - PAGE as u64 - 1;
            let (far_reads, far) = reads(|| {
                s.iter_log_after(Namespace::MESSAGE_LOG, Some(cursor), PAGE)
                    .unwrap()
            });
            assert_eq!(far.len(), PAGE, "the tail page must be full too");
            assert_eq!(far[0].0, cursor + 1, "and start after the cursor");

            assert!(
                far_reads <= first_reads + SLACK,
                "iter_log_after re-read the whole history below the cursor: \
                 first page {first_reads} chunks, page after {cursor} {far_reads} chunks"
            );
        });
    }

    #[test]
    fn a_backwards_log_page_near_the_start_costs_what_the_last_page_costs() {
        with_seeded_space(|s| {
            let (last_reads, last) = reads(|| {
                s.iter_log_before(Namespace::MESSAGE_LOG, None, PAGE)
                    .unwrap()
            });
            assert_eq!(last.len(), PAGE, "fixture must fill a page");
            assert_eq!(last[0].0, N - 1, "descending from the newest entry");

            // Mirror image of the forward case: walking backwards, it is
            // the entries ABOVE the cursor that must not be read.
            let cursor = PAGE as u64 + 1;
            let (near_reads, near) = reads(|| {
                s.iter_log_before(Namespace::MESSAGE_LOG, Some(cursor), PAGE)
                    .unwrap()
            });
            assert_eq!(near.len(), PAGE, "the head page must be full too");
            assert_eq!(near[0].0, cursor - 1, "and start below the cursor");

            assert!(
                near_reads <= last_reads + SLACK,
                "iter_log_before re-read the whole history above the cursor: \
                 last page {last_reads} chunks, page before {cursor} {near_reads} chunks"
            );
        });
    }

    /// The one the app actually calls for chat scrollback — and the one
    /// the audit report did not name. It stopped early on the upper
    /// bound and scanned from the root on the lower one.
    #[test]
    fn a_ranged_log_page_far_from_the_start_costs_what_the_first_page_costs() {
        with_seeded_space(|s| {
            let (first_reads, first) = reads(|| {
                s.iter_log_range(Namespace::MESSAGE_LOG, None, None, PAGE)
                    .unwrap()
            });
            assert_eq!(first.len(), PAGE, "fixture must fill a page");
            assert_eq!(first[0].0, 0);

            let start = N - PAGE as u64;
            let (far_reads, far) = reads(|| {
                s.iter_log_range(Namespace::MESSAGE_LOG, Some(start), None, PAGE)
                    .unwrap()
            });
            assert_eq!(far.len(), PAGE, "the tail page must be full too");
            assert_eq!(far[0].0, start, "and start at the lower bound");

            assert!(
                far_reads <= first_reads + SLACK,
                "iter_log_range ignored its lower bound while descending: \
                 first page {first_reads} chunks, page from {start} {far_reads} chunks"
            );
        });
    }
}
