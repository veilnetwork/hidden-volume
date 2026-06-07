//! Container-level operations: header, append-only file, slot grid, and
//! the public [`Container`] entry point. See DESIGN §2, §6, §12.

pub mod file;
pub mod header;

use std::path::Path;

pub use file::{ContainerFile, DEFAULT_SUPERBLOCK_REPLICAS};
pub use header::Header;

use crate::crypto::derive::SpaceKeys;
use crate::crypto::kdf::{Argon2Params, derive_master_key};
use crate::padding::PaddingPolicy;
use crate::space::Space;
use crate::space::log::MAX_RECORDS_PER_BATCH;
use crate::{Error, Result};

/// Options for [`Container::create_with_options`]. Use [`ContainerOptions::default`]
/// for a minimal config and tweak fields as needed.
///
/// Defaults:
/// - `argon2`: [`Argon2Params::DEFAULT`]
/// - `initial_garbage_chunks`: 0 (no decoy size)
/// - `padding_policy`: [`PaddingPolicy::None`]
///
/// For a real messenger deployment, populate at least
/// `initial_garbage_chunks` (decoy "this file has always been ~N MiB")
/// and `padding_policy` (mask per-commit growth).
///
/// **Semver note.** This struct is NOT `#[non_exhaustive]` —
/// `#[non_exhaustive]` would forbid struct-expression construction
/// entirely (even with FRU `..Default::default()`), forcing every
/// caller into a `let mut opts = ContainerOptions::default(); opts.x = ...`
/// pattern. Instead we accept that adding fields here is a major
/// (post-1.0) breaking change and budget for it via the
/// `docs/en/reference/semver.md` policy. Until v1.0 we add fields freely; after
/// v1.0 a new field is a 2.0 ticket.
#[derive(Debug, Clone)]
pub struct ContainerOptions {
    /// Argon2id KDF parameters baked into the new container's header.
    pub argon2: Argon2Params,
    /// Garbage chunks pre-written at create time. The file's apparent
    /// initial size is `(1 + initial_garbage_chunks) * CHUNK_SIZE`.
    /// 0 means no decoy (file starts at one chunk = the header).
    pub initial_garbage_chunks: u64,
    /// Policy applied at the end of each successful Tx commit. See
    /// [`PaddingPolicy`].
    pub padding_policy: PaddingPolicy,
    /// Number of Superblock chunks to write per commit (≥ 1). Default
    /// 3 — see [`crate::container::DEFAULT_SUPERBLOCK_REPLICAS`].
    /// Setting to 1 disables resilience (single torn-write breaks the
    /// space); setting to 0 is normalized to 1 at write time.
    pub superblock_replicas: u8,
}

impl Default for ContainerOptions {
    fn default() -> Self {
        Self {
            argon2: Argon2Params::DEFAULT,
            initial_garbage_chunks: 0,
            padding_policy: PaddingPolicy::None,
            superblock_replicas: file::DEFAULT_SUPERBLOCK_REPLICAS,
        }
    }
}

/// Options for [`Container::repack`] / [`Container::compact_known`].
///
/// The `argon2`, `initial_garbage_chunks`, and `padding_policy` fields
/// are applied to the destination container — repack is a chance to
/// "rotate" container parameters (e.g. up-tune Argon2 cost as a device
/// gets faster, or change the decoy size).
///
/// After audit pass 13 (R-NSKIND), repack routes namespaces by their
/// persisted [`crate::tx::NamespaceKind`] byte read from the source's
/// on-disk `IndexRoot`s, not by any heuristic. The previous v1-era
/// hint field `log_namespaces` was removed in pass-13 (TASKS.md
/// R-NSKIND closed); the format v2 bump made it inert.
///
/// **Semver note.** Same as [`ContainerOptions`] — no
/// `#[non_exhaustive]`; field additions are a major bump after v1.0.
#[derive(Debug, Clone)]
pub struct RepackOptions {
    /// Argon2id KDF parameters for the destination container (use
    /// this to up-tune Argon2 cost during a repack).
    pub argon2: Argon2Params,
    /// Decoy initial garbage chunks for the destination — same role
    /// as in [`ContainerOptions`].
    pub initial_garbage_chunks: u64,
    /// Padding policy applied to the destination on each commit
    /// during repack.
    pub padding_policy: PaddingPolicy,
    /// Superblock replica count for the destination's commits.
    pub superblock_replicas: u8,
}

impl Default for RepackOptions {
    fn default() -> Self {
        Self {
            argon2: Argon2Params::DEFAULT,
            initial_garbage_chunks: 0,
            padding_policy: PaddingPolicy::None,
            superblock_replicas: file::DEFAULT_SUPERBLOCK_REPLICAS,
        }
    }
}

/// Public entry point: an open hidden-volume container file. Wraps a
/// [`ContainerFile`] (low-level slot grid) and exposes per-space
/// operations.
///
/// ## Lifecycle
///
/// ```text
/// Container::create(path, params)  —> Container
/// Container::open(path)            —> Container
///       │
///       ├── create_space(password) —> Space<'_>
///       └── open_space(password)   —> Space<'_>
/// ```
///
/// Only one [`Space`] may be borrowed at a time (rust borrow checker
/// enforces). Drop the `Space` to use a different one. This restriction
/// is intentional: concurrent access from two spaces would require
/// reasoning about cross-space writes that the format does not need.
#[derive(Debug)]
pub struct Container {
    pub(crate) file: ContainerFile,
}

impl Container {
    /// Create a new empty container with default options (no initial
    /// garbage, no post-commit padding). Equivalent to
    /// [`create_with_options`][Self::create_with_options] with default
    /// `ContainerOptions` overriding only `argon2`.
    pub fn create<P: AsRef<Path>>(path: P, params: Argon2Params) -> Result<Self> {
        Self::create_with_options(
            path,
            ContainerOptions {
                argon2: params,
                ..Default::default()
            },
        )
    }

    /// Create a new empty container with the given options. Errors if the
    /// file exists or `options.argon2` is below [`Argon2Params::MIN`].
    ///
    /// `options.initial_garbage_chunks` controls the file's apparent
    /// starting size — pre-allocated random bytes that mask "this is a
    /// fresh empty container".
    ///
    /// `options.padding_policy` is applied at the end of every Tx
    /// commit; it masks per-commit file growth from a multi-snapshot
    /// adversary.
    pub fn create_with_options<P: AsRef<Path>>(path: P, options: ContainerOptions) -> Result<Self> {
        // Audit pass 8 (S1 full): if the requested padding policy
        // maps to a 1-byte preset index, persist it in the cleartext
        // header (Argon2Params.version bits 16..24). On reopen,
        // `Container::open` will auto-apply the stored policy. For
        // custom values that don't map to a preset (FixedRatio, custom
        // bucket size), the policy is runtime-only — host-app must
        // call `set_padding_policy` after every open.
        let argon2_for_header = match options.padding_policy.to_persisted_index() {
            Some(idx) => options.argon2.with_padding_policy_index(idx),
            None => options.argon2,
        };
        let mut file = ContainerFile::create(path, argon2_for_header)?;
        if options.initial_garbage_chunks > 0 {
            file.append_garbage_chunks(options.initial_garbage_chunks)?;
            file.fsync()?;
        }
        file.padding_policy = options.padding_policy;
        file.superblock_replicas = options.superblock_replicas.max(1);
        Ok(Self { file })
    }

    /// Open an existing container. Reads the cleartext header and
    /// validates its Argon2 params against the floor — refuses to open
    /// if the file declares unknown version or below-floor params.
    ///
    /// Acquires an exclusive flock — fails with [`Error::Busy`] if
    /// another process or open file description holds either an
    /// exclusive or shared lock. For read-only access concurrent with
    /// a writer, see [`Container::open_readonly`].
    ///
    /// Padding policy: as of audit pass 8 (S1 full), the policy
    /// index used at create time is persisted in the cleartext
    /// header and **auto-applied here**. Containers created with one
    /// of the preset policies (`PaddingPolicy::None`,
    /// `BucketGrowth { bucket_chunks: 64 | 256 | 4096 }`) will have
    /// the same policy active after reopen — no need for the
    /// host-app to call [`Container::set_padding_policy`] just to
    /// restore the privacy property. Custom values (`FixedRatio`,
    /// non-preset bucket size) are NOT persisted; for those, the
    /// host-app must still call `set_padding_policy` after open.
    ///
    /// [`Error::Busy`]: crate::Error::Busy
    ///
    /// **Recovery semantics (design choice).** When a subsequent
    /// `open_space` runs the discovery scan, the highest-`seq`
    /// Superblock that AEAD-decrypts AND `Superblock::decode`s is
    /// selected (audit pass 1 D2 made this iterate candidates on
    /// decode failure). The library does NOT additionally validate
    /// that the Superblock's `root_slot` points to a structurally
    /// valid Commit chunk before declaring success — `read_index_node_at`
    /// during the first read will surface a downstream
    /// `Error::AuthFailed` / `Error::Malformed` if the chain is
    /// corrupt. This is intentional: silent rollback to a prior
    /// Superblock would mask writer bugs and contradict the
    /// `commit_history` rollback-anchor contract documented in
    /// [`docs/en/guide/multi-device.md`](../../docs/en/guide/multi-device.md).
    /// Hosts that prefer "open into the latest GUARANTEED-readable
    /// state" can implement that policy on top of the public
    /// `commit_history` API.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = ContainerFile::open(path)?;
        // S1 full: restore persisted padding policy.
        let idx = file.header.params.padding_policy_index();
        file.padding_policy = PaddingPolicy::from_persisted_index(idx);
        Ok(Self { file })
    }

    /// Open an existing container in **read-only mode** with a shared
    /// flock. Multiple read-only handles may coexist concurrently;
    /// blocks (returns [`Error::Busy`]) if any writer holds the
    /// exclusive lock.
    ///
    /// All write paths return [`Error::ReadOnly`]:
    /// - [`Container::create_space`]
    /// - [`Container::set_padding_policy`] / [`Container::set_superblock_replicas`]
    /// - Any `Tx::commit` performed on a `Space` opened from this handle
    /// - [`Space::vacuum_orphans`] returns [`Error::ReadOnly`] (audit
    ///   pass 7 L5 made this strict; the auto-vacuum that
    ///   `Container::open_space` would normally run is suppressed for
    ///   shared-locked handles, see `open_space_with_keys_inner_opts`)
    ///
    /// Use case: a P2P sync agent reading the container while the main
    /// app process is writing, OR a forensics / backup tool inspecting
    /// without risk of corruption.
    ///
    /// [`Error::Busy`]: crate::Error::Busy
    /// [`Error::ReadOnly`]: crate::Error::ReadOnly
    pub fn open_readonly<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = ContainerFile::open_readonly(path)?;
        // S1 full: restore persisted padding policy. RO handles never
        // write, so the policy is informational here, but keeping the
        // semantics consistent with `open` avoids surprises.
        let idx = file.header.params.padding_policy_index();
        file.padding_policy = PaddingPolicy::from_persisted_index(idx);
        Ok(Self { file })
    }

    /// Whether this container handle was opened with shared (read-only)
    /// or exclusive (read-write) flock.
    #[must_use]
    pub fn is_readonly(&self) -> bool {
        matches!(self.file.lock_mode, file::LockMode::Shared)
    }

    /// Replace the post-commit padding policy. Affects future commits
    /// only; does not retroactively pad. Errors with [`Error::ReadOnly`]
    /// if the container was opened with [`Container::open_readonly`].
    pub fn set_padding_policy(&mut self, policy: PaddingPolicy) -> Result<()> {
        if self.is_readonly() {
            return Err(Error::ReadOnly);
        }
        self.file.padding_policy = policy;
        Ok(())
    }

    /// Current post-commit padding policy.
    #[must_use]
    pub fn padding_policy(&self) -> PaddingPolicy {
        self.file.padding_policy
    }

    /// Replace the number of Superblock replicas to write per commit.
    /// Values < 1 are clamped to 1. Affects future commits only.
    /// Errors with [`Error::ReadOnly`] on a read-only container.
    pub fn set_superblock_replicas(&mut self, replicas: u8) -> Result<()> {
        if self.is_readonly() {
            return Err(Error::ReadOnly);
        }
        self.file.superblock_replicas = replicas.max(1);
        Ok(())
    }

    /// Current Superblock replica count.
    #[must_use]
    pub fn superblock_replicas(&self) -> u8 {
        self.file.superblock_replicas
    }

    /// Borrow a read-only view of the cleartext header. Useful for
    /// host-app to inspect the Argon2 params currently used by this
    /// container (e.g. to decide whether to migrate).
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.file.header
    }

    /// The Argon2 params this container was created with.
    #[must_use]
    pub fn params(&self) -> Argon2Params {
        self.file.header.params
    }

    /// Bootstrap a new space inside this container, identified by
    /// `password`. Errors with [`Error::SpaceAlreadyExists`] if a space
    /// for this password already exists.
    ///
    /// Cost: one Argon2 derivation (per the container's params) plus an
    /// O(N) scan over current slots to detect collision.
    ///
    /// [`Error::SpaceAlreadyExists`]: crate::Error::SpaceAlreadyExists
    pub fn create_space(&mut self, password: &[u8]) -> Result<Space<'_>> {
        // Audit pass 7 (L4): fail fast on read-only. Without this
        // check, the call would burn ~100ms+ on Argon2id derivation
        // and run the collision-check scan, then fail inside
        // `append_chunk → check_writable` with `Error::ReadOnly`.
        // Slow on weak ARM and a minor timing side-channel (caller
        // can observe whether the password collided with an existing
        // space before getting `ReadOnly`).
        if self.is_readonly() {
            return Err(Error::ReadOnly);
        }
        let keys = self.derive_keys(password)?;
        Space::create(&mut self.file, keys)
    }

    /// Open the space identified by `password`. Returns
    /// [`Error::AuthFailed`] if no such space exists — same error path
    /// as wrong-password (deniability invariant D2).
    ///
    /// On success, automatically vacuums orphan IndexNode chunks (see
    /// [`Space::vacuum_orphans`]) so that prior "deleted" KV entries
    /// can no longer be recovered by forensics with this password.
    ///
    /// Cost: one Argon2 derivation + O(N) scan + small post-scan vacuum.
    ///
    /// Delegates to `open_space_with_keys_inner` (non-cancellable path)
    /// after Argon2.
    ///
    /// [`Error::AuthFailed`]: crate::Error::AuthFailed
    pub fn open_space(&mut self, password: &[u8]) -> Result<Space<'_>> {
        let keys = self.derive_keys(password)?;
        self.open_space_with_keys(keys)
    }

    /// Strict-mode open: like [`Self::open_space`] but additionally
    /// runs [`Space::verify_integrity`] before returning, so any
    /// Merkle-chain or AEAD failure surfaces at open time rather
    /// than at first read.
    ///
    /// Audit pass 14 finding: standard `open_space` selects the
    /// highest-seq Superblock that AEAD-decrypts AND structurally
    /// decodes (with the post-pass-14 cross-check that
    /// `Superblock.seq == Plaintext.seq`), but it does NOT walk
    /// the full `Commit → IndexRoot → IndexNode` chain. A
    /// downstream `Space::get` / `iter_log` would surface a
    /// mid-walk failure as `Error::AuthFailed` /
    /// `Error::Malformed` /
    /// `Error::IntegrityFailure`. Most host-apps prefer this
    /// "fail visibly on first use" semantics because silent
    /// rollback to an older Superblock would mask writer bugs and
    /// contradict the `commit_history` rollback-anchor contract.
    ///
    /// Strict mode flips the trade-off: pay the cost of a full
    /// Merkle walk up-front (one-time, bounded by the namespace
    /// count + index depth) and reject the open if the chain is
    /// inconsistent. Suitable for:
    /// - Forensics / backup tooling that wants a binary
    ///   "openable / not" answer.
    /// - Security-paranoid host-apps that want eager corruption
    ///   detection rather than first-read surfacing.
    /// - CI / health-check scripts.
    ///
    /// Returns the same `Space<'_>` as `open_space` on success.
    /// On verify failure, returns the underlying
    /// `Error::IntegrityFailure` / `Malformed` / `AuthFailed` and
    /// the lock is released with **no observable mutation** — audit
    /// pass 17 A: the auto-vacuum that `open_space` would normally
    /// run is suppressed here until `verify_integrity` succeeds, so
    /// a forensics / backup tool can be confident a failed verified
    /// open never scrubbed orphan IndexNode chunks.
    ///
    /// On success the auto-vacuum runs after verification, preserving
    /// the post-open forward-secrecy invariant (orphan IndexNode
    /// chunks are scrubbed before the handle is returned).
    ///
    /// **Cost.** One additional Merkle walk over every namespace's
    /// IndexNode tree. For a typical messenger profile (a handful
    /// of namespaces, a few thousand entries each) this is single-
    /// digit milliseconds; for multi-GiB log namespaces it scales
    /// linearly with chunk count. Use the standard `open_space`
    /// for low-latency mobile launches and `open_space_verified`
    /// only when the explicit guarantee is needed. Argon2id and
    /// the discovery scan run exactly once (the same `Space`
    /// handle is returned after `verify_integrity` succeeds).
    pub fn open_space_verified(&mut self, password: &[u8]) -> Result<Space<'_>> {
        let keys = self.derive_keys(password)?;
        self.open_space_with_keys_verified(keys)
    }

    /// Strict-mode equivalent of [`Self::open_space_with_keys`] —
    /// runs [`Space::verify_integrity`] before returning. See
    /// [`Self::open_space_verified`] for the design rationale and
    /// cost model.
    pub fn open_space_with_keys_verified(&mut self, keys: SpaceKeys) -> Result<Space<'_>> {
        // Audit pass 17 A: open WITHOUT auto-vacuum, run integrity
        // walk, only THEN scrub. A failure of `verify_integrity`
        // returns with no mutation having happened — important for
        // forensics / backup tooling that wants the file untouched
        // when its integrity is already in question.
        let is_ro = self.is_readonly();
        let mut space =
            self.open_space_with_keys_inner_opts(keys, None, /* auto_vacuum */ false)?;
        space.verify_integrity()?;
        // Verification passed; restore the standard `open_space`
        // forward-secrecy invariant by running the deferred vacuum.
        if !is_ro {
            space.vacuum_orphans()?;
        }
        Ok(space)
    }

    /// Derive the per-space keys from a password without opening the
    /// space. Useful for caching keys across application sessions to
    /// avoid Argon2id on every launch:
    ///
    /// 1. **First unlock** — call this once, persist [`SpaceKeys`] in an
    ///    OS-level secret store (Keychain on macOS/iOS, Secret Service
    ///    on Linux, Android Keystore).
    /// 2. **Subsequent unlocks** — load `SpaceKeys` from the keyring
    ///    and pass to [`Self::open_space_with_keys`], skipping the
    ///    ~100 ms Argon2id derivation.
    ///
    /// # Security trade-off
    ///
    /// Storing `SpaceKeys` outside the process bypasses Argon2's
    /// brute-force resistance. An attacker who compromises BOTH the
    /// container file AND the host OS's keyring recovers data without
    /// needing to brute-force the password. Use platform-native secure
    /// storage (Keychain / Secret Service / Keystore — all encrypted
    /// under user login) and document this trade-off in the host-app's
    /// security policy.
    ///
    /// For containers that should NEVER be unlockable without the
    /// password (max paranoia), don't cache — every unlock pays the
    /// Argon2id cost.
    pub fn derive_space_keys(&self, password: &[u8]) -> Result<SpaceKeys> {
        self.derive_keys(password)
    }

    /// Open a space using pre-derived [`SpaceKeys`]. Skips the Argon2
    /// derivation — only does the O(N) scan + vacuum.
    ///
    /// Returns [`Error::AuthFailed`] if the keys don't match any space
    /// in the container (same path as `open_space` with wrong password).
    ///
    /// See [`Self::derive_space_keys`] for the cross-session caching
    /// workflow and its security trade-off.
    ///
    /// Delegates to `open_space_with_keys_inner` (non-cancellable path).
    ///
    /// [`Error::AuthFailed`]: crate::Error::AuthFailed
    pub fn open_space_with_keys(&mut self, keys: SpaceKeys) -> Result<Space<'_>> {
        self.open_space_with_keys_inner(keys, None)
    }

    /// Cancellable [`Self::open_space`]. Polls `cancel` at periodic
    /// checkpoints inside the O(N) scan loop and bails with
    /// [`crate::Error::Cancelled`] if fired. Argon2 derivation is NOT
    /// cancellable (RustCrypto's `argon2::Argon2::hash_password` is
    /// uninterruptible) — the cancel pathway covers the variable-time
    /// scan, which dominates wall-clock for large containers.
    ///
    /// Mid-cancel state: no observable side effects. Internal Vecs from
    /// the partial scan drop on the early return; the file is unchanged.
    pub fn open_space_cancellable(
        &mut self,
        password: &[u8],
        cancel: &crate::cancel::CancelToken,
    ) -> Result<Space<'_>> {
        let keys = self.derive_keys(password)?;
        // Allow caller to abort between the (uninterruptible) Argon2 step
        // and the (cancellable) scan step.
        cancel.check()?;
        self.open_space_with_keys_inner(keys, Some(cancel))
    }

    /// Cancellable [`Self::open_space_with_keys`]. See
    /// [`Self::open_space_cancellable`] for the cancel-path semantics.
    pub fn open_space_with_keys_cancellable(
        &mut self,
        keys: SpaceKeys,
        cancel: &crate::cancel::CancelToken,
    ) -> Result<Space<'_>> {
        self.open_space_with_keys_inner(keys, Some(cancel))
    }

    /// Internal: unified open path used by all four public variants
    /// (`open_space`, `open_space_with_keys`, `open_space_cancellable`,
    /// `open_space_with_keys_cancellable`). Audit pass 8 (D10):
    /// previously each public variant had its own open + auto-vacuum
    /// body — minor duplication that's now consolidated. The cancel
    /// argument is `Option<&CancelToken>`; `None` skips polling.
    ///
    /// Default behavior matches the public `open_space*` contract:
    /// auto-vacuum on writable handles. Audit pass 17 A added the
    /// `_opts` variant to let `open_space_verified` defer the vacuum
    /// until after `verify_integrity` succeeds, preserving the
    /// "no observable mutation on verify failure" guarantee.
    fn open_space_with_keys_inner(
        &mut self,
        keys: SpaceKeys,
        cancel: Option<&crate::cancel::CancelToken>,
    ) -> Result<Space<'_>> {
        self.open_space_with_keys_inner_opts(keys, cancel, /* auto_vacuum */ true)
    }

    /// Audit pass 17 A: the `auto_vacuum`-aware sibling of
    /// [`Self::open_space_with_keys_inner`]. Pass `false` to suppress
    /// the post-scan `vacuum_orphans` call — used by
    /// `open_space_verified` so a failed integrity check never
    /// scrubs anything. Pass `true` for the standard contract.
    fn open_space_with_keys_inner_opts(
        &mut self,
        keys: SpaceKeys,
        cancel: Option<&crate::cancel::CancelToken>,
        auto_vacuum: bool,
    ) -> Result<Space<'_>> {
        let is_ro = self.is_readonly();
        let mut space = Space::open_with_cancel(&mut self.file, keys, cancel)?;
        // Audit pass 7 (L5): only auto-vacuum on writable handles.
        // `vacuum_orphans` is now strict (`Err(ReadOnly)` on shared
        // locks); the early-skip here is what makes `open_readonly`
        // work without violating the strict semantics. Vacuum is
        // intentionally non-cancellable (~M chunk reads, M ≪ N; fast
        // in practice) so the post-open forward-secrecy invariant
        // always holds when this returns Ok.
        if auto_vacuum && !is_ro {
            space.vacuum_orphans()?;
        }
        Ok(space)
    }

    /// Parallel-scan variant of [`Self::open_space`] (feature
    /// `parallel-scan`, Unix only). Uses rayon's work-stealing pool
    /// to parallelize the AEAD-decrypts during the discovery scan.
    /// Behaviorally identical to `open_space` — same `Space` state,
    /// same vacuum semantics on success.
    ///
    /// **When to use.** Multi-core hosts (desktop / server) opening
    /// containers larger than ~64 MiB (where the sequential scan
    /// starts feeling slow). For mobile / single-core hosts the
    /// sequential path is at least as fast and the feature should
    /// stay disabled to avoid pulling rayon (~6 MiB).
    #[cfg(all(feature = "parallel-scan", unix))]
    pub fn open_space_parallel(&mut self, password: &[u8]) -> Result<Space<'_>> {
        let keys = self.derive_keys(password)?;
        self.open_space_with_keys_parallel(keys)
    }

    /// Parallel-scan variant of [`Self::open_space_with_keys`]. See
    /// [`Self::open_space_parallel`] for when to use.
    #[cfg(all(feature = "parallel-scan", unix))]
    pub fn open_space_with_keys_parallel(&mut self, keys: SpaceKeys) -> Result<Space<'_>> {
        let is_ro = self.is_readonly();
        let mut space = Space::open_parallel(&mut self.file, keys)?;
        if !is_ro {
            space.vacuum_orphans()?;
        }
        Ok(space)
    }

    /// Memory-mapped variant of [`Self::open_space`] (feature `mmap`,
    /// Unix only). Maps the entire container file via `mmap(2)` and
    /// slices each chunk out of the mapping during the discovery
    /// scan — zero allocation per chunk on the read path.
    /// Behaviorally identical to `open_space` — same `Space` state,
    /// same vacuum semantics on success.
    ///
    /// **When to use.** Cold-cache opens of large containers
    /// (multi-GiB), where avoiding the per-chunk syscall overhead of
    /// the streaming `pread` path produces a measurable wall-clock
    /// win. On warm-cache repeat opens the difference is small. The
    /// feature trades a `memmap2` dependency (~80 KiB compiled) and
    /// an `unsafe` Mmap construction for that win — disable for
    /// minimum-trust profiles.
    ///
    /// **Concurrency.** The flock acquired by `Container::open`
    /// (LOCK_EX) excludes concurrent writers; the mmap stays
    /// consistent for the lifetime of the call. On filesystems that
    /// don't honour `flock(2)` (some NFS, FUSE), the safety
    /// assumption is weaker — see `docs/en/guide/multi-device.md`.
    #[cfg(all(feature = "mmap", unix))]
    pub fn open_space_mmap(&mut self, password: &[u8]) -> Result<Space<'_>> {
        let keys = self.derive_keys(password)?;
        self.open_space_with_keys_mmap(keys)
    }

    /// mmap variant of [`Self::open_space_with_keys`]. See
    /// [`Self::open_space_mmap`] for when to use.
    #[cfg(all(feature = "mmap", unix))]
    pub fn open_space_with_keys_mmap(&mut self, keys: SpaceKeys) -> Result<Space<'_>> {
        let is_ro = self.is_readonly();
        let mut space = Space::open_mmap(&mut self.file, keys)?;
        if !is_ro {
            space.vacuum_orphans()?;
        }
        Ok(space)
    }

    /// **Constant-time-scan** variant of [`Self::open_space`] — opt-in
    /// mitigation for the TM1 open-time timing oracle
    /// ([threat-model §4.4 F-TM1](https://github.com/veilnetwork/hidden-volume/blob/master/docs/en/security/threat-model.md)).
    ///
    /// The default sequential / parallel-scan / mmap paths short-
    /// circuit on AEAD MAC failure, which leaks the owned-fraction of
    /// the container to a process-level wall-clock observer (≈ 40-75
    /// µs/chunk swing, hardware-dependent). This entry runs a
    /// ChaCha20 timing-equalizer on every MAC-fail so the per-chunk
    /// wall-clock is independent of ownership on the dominant
    /// component; aggregate open-time becomes mostly a function of
    /// total slot count.
    ///
    /// **Cost.** Approximately doubles the open-time on garbage-
    /// heavy containers — the equalizer cost is paid for every
    /// non-owned chunk. On a 100-MiB sparse container the extra
    /// wall-clock is in the hundreds of ms range. Default callers
    /// should stick with [`Self::open_space`] unless their threat
    /// model includes a process-level timing observer.
    ///
    /// **Honest scope.** The equalizer closes the ChaCha20-body
    /// cost component (~1-3 µs per chunk); the parsing + allocation
    /// residual on MAC-pass remains and contributes the rest of the
    /// per-chunk swing. See threat-model §4.4 honest-scope table.
    ///
    /// **Scope (v1.0).** Sequential, parallel-scan, AND mmap all
    /// have CT companions:
    /// [`Self::open_space_constant_time`] (sequential),
    /// `Self::open_space_parallel_constant_time` (parallel-scan,
    /// feature `parallel-scan`),
    /// `Self::open_space_mmap_constant_time` (mmap, feature `mmap`).
    /// The latter two are intentionally plain-code (not
    /// intra-doc-linked) so `cargo doc --no-default-features`
    /// stays green; they exist only when the corresponding feature
    /// is enabled. All three use the same per-chunk equalizer and
    /// produce identical `Space` state.
    ///
    /// **Read-only safe.** Like every other open variant, works on
    /// a `LOCK_SH` handle returned by [`Self::open_readonly`].
    pub fn open_space_constant_time(&mut self, password: &[u8]) -> Result<Space<'_>> {
        let keys = self.derive_keys(password)?;
        self.open_space_with_keys_constant_time(keys)
    }

    /// `SpaceKeys`-driven variant of [`Self::open_space_constant_time`].
    /// Use when the host-app has cached the derived keys (skips
    /// Argon2id re-derivation); the constant-time-scan property is
    /// preserved.
    pub fn open_space_with_keys_constant_time(&mut self, keys: SpaceKeys) -> Result<Space<'_>> {
        let is_ro = self.is_readonly();
        let mut space = Space::open_constant_time(&mut self.file, keys)?;
        if !is_ro {
            space.vacuum_orphans()?;
        }
        Ok(space)
    }

    /// Parallel-scan **constant-time** companion. Shipped in v1.0
    /// (closes the residual TM1 scope from threat-model §4.4 that
    /// previously read "Sequential-scan only"). Combines the
    /// parallel-scan speedup with the per-chunk ChaCha20 timing
    /// equalizer used by [`Self::open_space_constant_time`].
    ///
    /// **When to use.** Multi-core hosts where the open-time
    /// observer is in scope. The equalizer cost is paid on every
    /// non-owned chunk, but rayon distributes the work across cores
    /// so the wall-clock penalty is mitigated proportional to the
    /// thread count cap.
    ///
    /// **Honest scope.** Same as
    /// [`Self::open_space_constant_time`] — closes the ChaCha20-body
    /// component; parsing/alloc residual remains.
    #[cfg(all(feature = "parallel-scan", unix))]
    pub fn open_space_parallel_constant_time(&mut self, password: &[u8]) -> Result<Space<'_>> {
        let keys = self.derive_keys(password)?;
        self.open_space_with_keys_parallel_constant_time(keys)
    }

    /// `SpaceKeys`-driven companion to
    /// [`Self::open_space_parallel_constant_time`].
    #[cfg(all(feature = "parallel-scan", unix))]
    pub fn open_space_with_keys_parallel_constant_time(
        &mut self,
        keys: SpaceKeys,
    ) -> Result<Space<'_>> {
        let is_ro = self.is_readonly();
        let mut space = Space::open_parallel_constant_time(&mut self.file, keys)?;
        if !is_ro {
            space.vacuum_orphans()?;
        }
        Ok(space)
    }

    /// mmap-scan **constant-time** companion. Shipped in v1.0
    /// alongside [`Self::open_space_parallel_constant_time`] to close
    /// the residual TM1 scope. Combines the zero-allocation mmap read
    /// path with the per-chunk ChaCha20 timing equalizer.
    ///
    /// **When to use.** Multi-GiB cold-cache opens on
    /// `flock`-honouring storage where the open-time observer is in
    /// scope. The mmap path's `unsafe Mmap::map` precondition still
    /// applies — see [`Self::open_space_mmap`] for the safety story.
    ///
    /// **Honest scope.** Same as
    /// [`Self::open_space_constant_time`].
    #[cfg(all(feature = "mmap", unix))]
    pub fn open_space_mmap_constant_time(&mut self, password: &[u8]) -> Result<Space<'_>> {
        let keys = self.derive_keys(password)?;
        self.open_space_with_keys_mmap_constant_time(keys)
    }

    /// `SpaceKeys`-driven companion to
    /// [`Self::open_space_mmap_constant_time`].
    #[cfg(all(feature = "mmap", unix))]
    pub fn open_space_with_keys_mmap_constant_time(
        &mut self,
        keys: SpaceKeys,
    ) -> Result<Space<'_>> {
        let is_ro = self.is_readonly();
        let mut space = Space::open_mmap_constant_time(&mut self.file, keys)?;
        if !is_ro {
            space.vacuum_orphans()?;
        }
        Ok(space)
    }

    fn derive_keys(&self, password: &[u8]) -> Result<SpaceKeys> {
        let master = derive_master_key(password, &self.file.header.salt, self.file.header.params)?;
        Ok(SpaceKeys::from_master(&master))
    }

    /// Repack the container at `source` into a NEW file at `dest`,
    /// keeping only the spaces unlocked by `passwords`. Anything not
    /// recoverable with the supplied passwords is treated as garbage
    /// and dropped.
    ///
    /// Effects:
    /// - Orphan chunks (old IndexNodes from prior commits, history of
    ///   Superblocks, Commits) are gone — they don't exist in `dest`.
    /// - DataBatch chunks are repacked: old "soft-deleted" log entries
    ///   are physically eliminated. Closes the v0.2 batch leak.
    /// - The destination has fresh `salt` and `container_id` — even
    ///   the same password derives different per-chunk keys. Forensics
    ///   on a backup of `source` finds no help in `dest`.
    /// - `dest` gets `options.argon2` / `initial_garbage_chunks` /
    ///   `padding_policy` (parameter rotation opportunity).
    ///
    /// Errors:
    /// - [`Error::Internal`] if `source == dest` or any password fails
    ///   (`AuthFailed`).
    /// - Any error from open/decode of source, write of dest.
    ///
    /// Failure semantics: if repack errors after partial dest
    /// construction, dest is in an undefined state. Caller should
    /// remove it. Source is never modified by `repack` itself —
    /// in-place compaction (`compact_known`) handles the safe rename.
    ///
    /// **Concurrency on `dest`.** `Container::create_with_options`
    /// uses `create_new(true)` on `dest`, so two concurrent `repack`
    /// calls racing on the same `dest` path resolve atomically: one
    /// winner produces a valid container, the loser receives
    /// `Error::Io(AlreadyExists)`. No corruption is possible. But
    /// callers that **expect** both to succeed (e.g. for parallel
    /// migrations to distinct outputs) MUST pass distinct `dest`
    /// paths — there is no fan-out coordination inside the library.
    /// In-place `compact_known` / `change_passwords` use a different
    /// flow that holds source `LOCK_EX` through rename and is safe
    /// against concurrent invocations on `path`.
    ///
    /// **Concurrency on `source` — snapshot-at-Phase-1 semantics.**
    /// `repack` acquires `LOCK_EX` on `source` while reading state
    /// (Phase 1) and continues to hold it through Phase 2 (writing
    /// `dest`). The `dest` thus reflects `source`'s state at the
    /// moment Phase 1 acquired the lock — a **point-in-time
    /// snapshot**, not a "live" mirror. Concurrent processes that
    /// try to `Container::open(source)` during a repack get
    /// `Error::Busy` until this call returns. For atomic
    /// snapshot-and-rename use the in-place
    /// [`Self::compact_known`] / [`Self::change_passwords`] APIs,
    /// which additionally rename `dest` over `source` while still
    /// holding the source lock (audit pass 11 M1).
    ///
    /// **Memory footprint of `repack`.** Audit pass 16
    /// (R-STREAMING-REPACK) made the log-namespace path streaming:
    /// log entries are paged in via `iter_log_after(ns, cursor,
    /// PAGE_SIZE)` and committed to `dest` per page, so the working
    /// set is bounded by **one page (~4 MiB) regardless of total log
    /// size**. KV namespaces still collect once per namespace because
    /// the source-side iterator has no pagination, but their working
    /// set is structurally bounded by the 2-level B+ tree cap (≤ ~10K
    /// entries × `MAX_VALUE_LEN` per namespace). Multi-GiB log
    /// namespaces no longer OOM the host.
    pub fn repack(
        source: &std::path::Path,
        dest: &std::path::Path,
        passwords: &[&[u8]],
        options: RepackOptions,
    ) -> Result<()> {
        Self::repack_inner(source, dest, passwords, options, None)
    }

    /// Cancellable variant of [`Self::repack`]. Polls the supplied
    /// [`crate::cancel::CancelToken`] at every namespace boundary
    /// (during the read phase) and at every commit boundary (during
    /// the write phase). On fire, returns [`crate::Error::Cancelled`]
    /// after dropping any partial state in `dest` (no Container is
    /// returned; the caller is responsible for removing `dest` if it
    /// shouldn't linger — `compact_*_cancellable` does this for the
    /// in-place variant).
    ///
    /// Cancellation is **not atomic mid-Tx**: an in-progress Tx
    /// completes its 3-fsync sequence before the next checkpoint. The
    /// resulting `dest` is therefore always at a clean Tx boundary
    /// (the write phase is naturally checkpointed by Tx).
    pub fn repack_cancellable(
        source: &std::path::Path,
        dest: &std::path::Path,
        passwords: &[&[u8]],
        options: RepackOptions,
        cancel: &crate::cancel::CancelToken,
    ) -> Result<()> {
        Self::repack_inner(source, dest, passwords, options, Some(cancel))
    }

    fn repack_inner(
        source: &std::path::Path,
        dest: &std::path::Path,
        passwords: &[&[u8]],
        options: RepackOptions,
        cancel: Option<&crate::cancel::CancelToken>,
    ) -> Result<()> {
        // The general primitive supports password rotation; degenerate
        // case is "open with X, write as X" (no change).
        let mapping: Vec<(&[u8], &[u8])> = passwords.iter().map(|p| (*p, *p)).collect();
        Self::repack_inner_mapped(source, dest, &mapping, options, cancel)
    }

    /// Generalized repack that supports rotating each space's password.
    /// `password_map[i] = (open_with, write_as)` — open the i-th source
    /// space using `open_with`, write the i-th destination space using
    /// `write_as`. Use `open_with == write_as` to preserve, distinct
    /// values to rotate. Spaces NOT listed are dropped (same behavior
    /// as `repack_inner` w.r.t. unlisted passwords).
    fn repack_inner_mapped(
        source: &std::path::Path,
        dest: &std::path::Path,
        password_map: &[(&[u8], &[u8])],
        options: RepackOptions,
        cancel: Option<&crate::cancel::CancelToken>,
    ) -> Result<()> {
        if source == dest {
            return Err(Error::Internal("repack: source and dest must differ"));
        }
        // Out-of-place repack. `src` is held by `&mut` for the
        // entire duration of `repack_into_dest`, so source `LOCK_EX`
        // is held through BOTH Phase 1 (read) AND Phase 2 (write
        // dest). After this function returns, `src` drops and the
        // lock is released — at that point the public `repack` API
        // is done; rename of `dest` over `source` (if desired) is
        // the caller's responsibility, but the in-place
        // `compact_known` / `change_passwords` flows go through a
        // different helper (`atomic_rewrite_under_source_lock`)
        // that holds the lock through rename and parent-dir fsync.
        // Audit pass 13 doc-correction: the previous comment here
        // claimed the lock was "dropped after Phase 1", which was
        // wrong — pass-11 M1 already plumbed `&mut src` through
        // both phases.
        let mut src = Container::open(source)?;
        Self::repack_into_dest(&mut src, dest, password_map, options, cancel)
    }

    /// Read live state from an already-open `src` and write a fresh
    /// container at `dest`. Audit pass 11 (M1 HIGH): extracted from
    /// `repack_inner_mapped` so callers that need to hold the source
    /// flock through a subsequent atomic-rename (in-place
    /// `compact_known` / `change_passwords`) can do so safely. The
    /// previous flow opened+dropped source inside this function,
    /// leaving an unlocked window between Phase 1 read and the
    /// caller's `rename`, in which a second process could acquire
    /// LOCK_EX, commit fresh writes, drop, and have those commits
    /// silently overwritten by our rename.
    fn repack_into_dest(
        src: &mut Container,
        dest: &std::path::Path,
        password_map: &[(&[u8], &[u8])],
        options: RepackOptions,
        cancel: Option<&crate::cancel::CancelToken>,
    ) -> Result<()> {
        // R-NSKIND (pass-13): namespace kind is read from each
        // `IndexRoot`'s persisted byte via `list_namespaces_with_kind`.
        // The v1-era `RepackOptions::log_namespaces` hint was removed
        // entirely in this pass.
        let check = |c: Option<&crate::cancel::CancelToken>| -> Result<()> {
            if let Some(t) = c { t.check() } else { Ok(()) }
        };

        // R-STREAMING-REPACK (audit pass 16): pre-pass-16 the flow
        // collected EVERY live KV entry and EVERY live log record
        // for EVERY source space into in-memory `Vec`s before
        // writing the destination — O(total plaintext) RAM, which
        // OOM'd on multi-GiB log namespaces. The streaming flow
        // below interleaves source-read and dest-write per
        // namespace:
        //
        // - **KV namespaces** are bounded by the 2-level B+ tree
        //   cap (≤ ~5-10 K entries × MAX_VALUE_LEN bytes per
        //   namespace). We still collect them once via
        //   `space.list(ns)` because there's no streaming
        //   alternative on the source side, but the working set
        //   is bounded.
        // - **Log namespaces** can hold ~10K-20K unique log_id
        //   pointers and the underlying `DataBatch` chunks can
        //   total many MiB. We page through them via
        //   `space.iter_log_after(ns, cursor, PAGE_SIZE)` and
        //   commit each page directly to the destination's Tx.
        //   Working set per page: ≤ `PAGE_SIZE × MAX_LOG_PAYLOAD_LEN`
        //   = `512 × 8 KiB` = 4 MiB, **independent of total log
        //   size**.
        //
        // Source and destination are different Container instances
        // each holding its own `LOCK_EX` flock, so interleaving
        // reads from one with writes to the other is safe.
        //
        // Open the destination ONCE up-front so we can
        // create_space(...) inside the per-password loop without
        // re-paying the LOCK_EX dance. (LOCK_EX is held on `dest`
        // for the duration of this whole function.)
        let dst_options = ContainerOptions {
            argon2: options.argon2,
            initial_garbage_chunks: options.initial_garbage_chunks,
            padding_policy: options.padding_policy,
            superblock_replicas: options.superblock_replicas,
        };
        let mut dst = Container::create_with_options(dest, dst_options)?;

        // Page size for log streaming. Half the per-batch cap so
        // each Tx commits one DataBatch chunk worst-case (no
        // auto-split fanout overhead).
        let log_page_size = MAX_RECORDS_PER_BATCH / 2;

        for (open_with, write_as) in password_map {
            check(cancel)?;
            let mut src_space = match cancel {
                Some(t) => src.open_space_cancellable(open_with, t)?,
                None => src.open_space(open_with)?,
            };
            let namespaces_with_kind = src_space.list_namespaces_with_kind()?;

            // Open the dest space — must drop `src_space` first
            // because both `src` and `dst` are `&mut Container`
            // and Rust's borrow checker prohibits holding both
            // open spaces at once on the SAME container. They're
            // different Containers though, so we can hold one
            // open at a time per Container, alternating: read a
            // page from src_space, drop it, open dst_space, write
            // page, drop, repeat.
            //
            // Concretely, the borrow checker accepts:
            //   let mut src_space = src.open_space(...);   // &mut src
            //   let mut dst_space = dst.create_space(...); // &mut dst (independent)
            //   // ... use both ...
            // because `src` and `dst` are independent owners.
            let mut dst_space = dst.create_space(write_as)?;

            for (ns, kind) in namespaces_with_kind {
                check(cancel)?;
                match kind {
                    crate::tx::NamespaceKind::Kv => {
                        // KV: bounded; one-shot list + one-shot Tx.
                        let entries = src_space.list(ns)?;
                        if entries.is_empty() {
                            continue;
                        }
                        let mut tx = dst_space.begin_tx();
                        for (key, value) in &entries {
                            tx.put(ns, key, value)?;
                        }
                        tx.commit()?;
                    },
                    crate::tx::NamespaceKind::Log => {
                        // Log: stream one page at a time. Each
                        // page is a separate Tx (and therefore one
                        // 3-fsync barrier), so write throughput is
                        // bounded by fsync latency; for typical
                        // ext4/xfs that's ≈ 1-5 ms per page.
                        let mut cursor: Option<u64> = None;
                        loop {
                            check(cancel)?;
                            let page = src_space.iter_log_after(ns, cursor, log_page_size)?;
                            if page.is_empty() {
                                break;
                            }
                            // Advance cursor BEFORE the dest Tx
                            // — `page.last()` is moved into the
                            // Tx loop below.
                            let last_id = page.last().expect("non-empty by check above").0;
                            let mut tx = dst_space.begin_tx();
                            for (log_id, payload) in &page {
                                tx.append_log(ns, *log_id, payload)?;
                            }
                            tx.commit()?;
                            cursor = Some(last_id);
                        }
                    },
                }
            }
        }

        Ok(())
    }

    /// In-place compaction. Caller asserts that `passwords` is the set
    /// of spaces they want to KEEP — anything else (including any
    /// hidden spaces with passwords NOT supplied) will be permanently
    /// destroyed in the rewrite.
    ///
    /// Use case: user has lost a password and wants to clean up; or
    /// user wants to "drop the decoy" after using it once.
    ///
    /// Mechanics: writes the new file at `path.tmp`, then atomically
    /// renames over `path`. Original file's blocks are released to
    /// the FS — for forensic-grade scrub of the underlying storage,
    /// host-app must run a separate tool.
    pub fn compact_known(
        path: &std::path::Path,
        passwords: &[&[u8]],
        options: RepackOptions,
    ) -> Result<()> {
        compact_in_place_impl(path, passwords, options, None)
    }

    /// Cancellable [`Self::compact_known`]. On cancel, removes the
    /// temp `dest.hv-compact-tmp` file and returns
    /// [`crate::Error::Cancelled`] without modifying `path`.
    pub fn compact_known_cancellable(
        path: &std::path::Path,
        passwords: &[&[u8]],
        options: RepackOptions,
        cancel: &crate::cancel::CancelToken,
    ) -> Result<()> {
        compact_in_place_impl(path, passwords, options, Some(cancel))
    }

    // Audit B7 (2026-05-02): `Container::compact_all` /
    // `compact_all_cancellable` removed. Both had bit-identical bodies
    // to `compact_known` / `_cancellable` — the supposed semantic
    // difference ("caller asserts they have all passwords") was
    // documentation-only and not enforced anywhere. Use
    // `compact_known` directly; the docstring there now covers the
    // destructive-drop semantics for spaces without supplied passwords.

    /// Rotate one or more space passwords in-place. The atomic-rename
    /// pattern is the same as [`Self::compact_known`]: write to a
    /// temp file, then `rename(2)` over `path`. On any failure the
    /// temp is removed and the original `path` is untouched.
    ///
    /// `mapping[i] = (open_with, write_as)`:
    /// - `open_with == write_as` — preserve verbatim (no rotation).
    /// - `open_with != write_as` — rotate to the new password.
    ///
    /// Spaces NOT mentioned in `mapping` are **dropped** (same destructive
    /// semantics as `compact_known`). To preserve them, list each as a
    /// no-op `(p, p)` pair.
    ///
    /// Validation: every `open_with` must currently match a space; every
    /// `write_as` must be unique within the mapping. The library checks
    /// the first via `Error::AuthFailed` and the second via
    /// `Error::SpaceAlreadyExists` (raised by the implicit
    /// `create_space(write_as)` for the second collision).
    ///
    /// Use case (single password change):
    /// ```no_run
    /// # use hidden_volume::Container;
    /// # use hidden_volume::container::RepackOptions;
    /// # fn run(path: &std::path::Path) -> hidden_volume::Result<()> {
    /// // Change "old-pw" → "new-pw"; keep the hidden space untouched.
    /// let other_kept: &[u8] = b"hidden-pw";
    /// Container::change_passwords(
    ///     path,
    ///     &[(b"old-pw", b"new-pw"), (other_kept, other_kept)],
    ///     RepackOptions::default(),
    /// )?;
    /// # Ok(()) }
    /// ```
    ///
    /// **Forward-secrecy note.** After a successful rotation the OLD
    /// container's blocks are released to the filesystem. The
    /// allocator may reuse those blocks for unrelated data; for
    /// forensic-grade scrub of the underlying storage, host-app must
    /// run a separate tool (e.g. dd-overwrite the original file before
    /// rename). On flash storage the FTL further obscures the original
    /// blocks but does not strongly guarantee deletion.
    pub fn change_passwords(
        path: &std::path::Path,
        mapping: &[(&[u8], &[u8])],
        options: RepackOptions,
    ) -> Result<()> {
        change_passwords_impl(path, mapping, options, None)
    }

    /// Cancellable [`Self::change_passwords`]. On cancel, removes the
    /// temp file and returns [`crate::Error::Cancelled`] without
    /// modifying `path`.
    pub fn change_passwords_cancellable(
        path: &std::path::Path,
        mapping: &[(&[u8], &[u8])],
        options: RepackOptions,
        cancel: &crate::cancel::CancelToken,
    ) -> Result<()> {
        change_passwords_impl(path, mapping, options, Some(cancel))
    }
}

/// Atomic in-place rewrite primitive used by `compact_known` and
/// `change_passwords`. Audit pass 11 M1+M2+M3 + pass-18 M3-hardening
/// (2026-05-10):
///
/// 1. **M1 (HIGH lost-update race fix)** — opens `source` once and
///    holds its `LOCK_EX` flock through `rename`. Previously the
///    source `Container` was dropped between Phase 1 read and the
///    rename, leaving a window in which a second process could
///    acquire LOCK_EX, commit, drop, and then have those commits
///    silently overwritten by our rename.
/// 2. **M2** — `fsync_parent_dir` after rename so the directory
///    entry change is durable on ext4/xfs across crash.
/// 3. **M3** — random temp filename via `getrandom`; uses
///    `create_new = true` so we never blind-delete a sibling file
///    that happens to share our prefix.
/// 4. **M3-hardening (2026-05-10)** — between the writer Container's
///    drop (end of `write` closure) and the `rename`, we hold our
///    own `LOCK_EX` fd on tmp and verify (a) the file's first
///    `HEADER_LEN` bytes decode to `Argon2Params` that pass
///    `validate()` (the cleartext header is the only well-defined
///    structure at file offset 0 — we deliberately avoid a fixed
///    magic byte to preserve deniability against an offline observer,
///    DESIGN §11.1 / D1) and (b) on Unix, the inode of tmp at rename
///    time still matches the inode we just opened. This closes the
///    audit-M3 race window where an attacker with directory write+read
///    access could substitute tmp's content between Container drop
///    and rename.
///
/// **Precondition for cryptographic safety** — `path.parent()` must
/// be a directory that the attacker model in
/// [`docs/en/security/threat-model.md`](../../../docs/en/security/threat-model.md)
/// treats as trusted. Concretely: app-private storage on mobile
/// (`/data/data/<pkg>/files/...` on Android, app sandbox container on
/// iOS), `~/.config/<app>/...` on Linux, `%LOCALAPPDATA%\<app>\...` on
/// Windows. Shared-storage / world-writable directories are out of
/// scope (T-active not defended) — the per-file flock + LOCK_EX inode
/// pin still gives best-effort protection but the threat-model
/// guarantees do not extend there.
fn atomic_rewrite_under_source_lock<F>(
    path: &std::path::Path,
    prefix: &str,
    cancel: Option<&crate::cancel::CancelToken>,
    write: F,
) -> Result<()>
where
    F: FnOnce(&mut Container, &std::path::Path, Option<&crate::cancel::CancelToken>) -> Result<()>,
{
    // Hold source flock for the entire critical section. Container::open
    // acquires LOCK_EX (try_lock_exclusive); concurrent processes that
    // try to open `path` while we work get Error::Busy and bail
    // cleanly. After our rename, the old inode (still held by `src`)
    // is unlinked but live; new openers see the NEW inode and can
    // acquire its lock independently.
    let mut src = Container::open(path)?;

    let tmp = unique_temp_path_in_parent(path, prefix)?;

    if let Err(e) = write(&mut src, &tmp, cancel) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // M3-hardening: re-open tmp ourselves and hold an LOCK_EX fd on
    // it through the rename. Verify the file we hold (a) is
    // non-empty, (b) starts with our format magic — defends against
    // a directory-writer attacker substituting tmp between the
    // writer's Container drop and our open.
    let tmp_handle = match std::fs::OpenOptions::new().read(true).open(&tmp) {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Io(e));
        },
    };
    #[cfg(not(target_os = "android"))]
    {
        // Best-effort exclusive lock pin. WouldBlock would mean an
        // attacker raced and acquired LOCK_EX first — refuse the
        // rename rather than ship attacker content into `path`.
        match tmp_handle.try_lock() {
            Ok(()) => {},
            Err(std::fs::TryLockError::WouldBlock) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(Error::Busy);
            },
            Err(std::fs::TryLockError::Error(_)) => {
                // Filesystem doesn't support flock — proceed (Android
                // skip path goes through the `cfg(target_os="android")`
                // arm; this branch is for exotic non-Unix FS).
            },
        }
    }
    // Verify the writer produced a real container — at minimum a
    // valid cleartext header (v3 layout: 48 bytes = salt(32) +
    // Argon2 params(16) at offset 32..48 that pass `validate()`).
    // A substituted tmp full of zeros, random bytes, or
    // attacker-chosen content (e.g. an old container with weak
    // Argon2) is rejected. We deliberately avoid a fixed magic
    // constant — the file format is meant to be indistinguishable
    // from random except for the 16-byte Argon2 params field, which
    // IS validated on every open.
    {
        use crate::crypto::kdf::Argon2Params;
        use crate::{HEADER_LEN, HEADER_PARAMS_LEN, HEADER_PARAMS_OFFSET};
        use std::io::Read as _;
        let mut header = [0u8; HEADER_LEN];
        if let Err(e) = (&tmp_handle).read_exact(&mut header) {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Io(e));
        }
        let params_bytes: [u8; HEADER_PARAMS_LEN] = header
            [HEADER_PARAMS_OFFSET..HEADER_PARAMS_OFFSET + HEADER_PARAMS_LEN]
            .try_into()
            .expect("HEADER_PARAMS_LEN bytes statically");
        let header_ok = Argon2Params::decode(&params_bytes)
            .ok()
            .map(|p| p.validate().is_ok())
            .unwrap_or(false);
        if !header_ok {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Internal(
                "M3-hardening: tmp file substituted before rename (header validate failed)",
            ));
        }
    }
    // Capture inode for post-rename verification (Unix only — Windows
    // has no stable equivalent before NTFS file_id).
    #[cfg(unix)]
    let pre_rename_inode = {
        use std::os::unix::fs::MetadataExt as _;
        tmp_handle.metadata().ok().map(|m| (m.dev(), m.ino()))
    };

    // Atomic rename — on POSIX this overwrites `path` atomically.
    // On Windows, std's rename is also atomic since 1.43 (uses MoveFileEx
    // with MOVEFILE_REPLACE_EXISTING).
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        drop(tmp_handle);
        return Err(Error::Io(e));
    }

    // M3-hardening (Unix): post-rename inode pin — the path now MUST
    // resolve to the same inode our `tmp_handle` references. If it
    // doesn't, an attacker substituted between our magic-check and the
    // rename. (Hard to mount this attack with our LOCK_EX held, but
    // belt-and-suspenders.)
    #[cfg(unix)]
    if let Some((pre_dev, pre_ino)) = pre_rename_inode {
        use std::os::unix::fs::MetadataExt as _;
        if let Ok(post) = std::fs::metadata(path)
            && (post.dev() != pre_dev || post.ino() != pre_ino)
        {
            drop(tmp_handle);
            return Err(Error::Internal(
                "M3-hardening: post-rename inode mismatch (tmp substituted under us)",
            ));
        }
    }

    // M2: fsync parent directory so the rename is durable. On Unix
    // ext4/xfs/etc. without this, a crash after rename can revert the
    // directory entry. Best-effort (Windows has no equivalent and
    // some FS error out — we tolerate that).
    fsync_parent_dir(path);

    drop(tmp_handle);
    drop(src); // explicit: release lock on the (now-orphan) old inode
    Ok(())
}

/// Build a unique temp filename in `path`'s parent directory using 16
/// hex chars of entropy. Creates and immediately closes the file with
/// `create_new = true` so we hold a true reservation; `repack_into_dest`
/// will subsequently `Container::create` over it, which uses the same
/// `create_new` flag — so we delete our reservation just before so the
/// re-create succeeds. Returns the validated path.
fn unique_temp_path_in_parent(path: &std::path::Path, prefix: &str) -> Result<std::path::PathBuf> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = path.file_name().and_then(|s| s.to_str()).unwrap_or("hv");
    // Track the last AlreadyExists kind we observed so the final
    // error surfaces a useful diagnostic. With 8 random bytes
    // (~1/2^64 collision per try) all 16 tries hitting AlreadyExists
    // is astronomically unlikely from real collisions; the realistic
    // failure mode is a permission / FS issue that surfaces as
    // AlreadyExists due to races or odd filesystem semantics.
    let mut last_kind: Option<std::io::ErrorKind> = None;
    for _ in 0..16 {
        let mut rand = [0u8; 8];
        crate::crypto::rng::fill(&mut rand)?;
        let mut suffix = String::with_capacity(16);
        for b in rand {
            use std::fmt::Write as _;
            let _ = write!(&mut suffix, "{b:02x}");
        }
        let candidate = parent.join(format!(".{stem}.{prefix}.{suffix}.tmp"));
        // Atomic reservation: create_new(true) fails with AlreadyExists
        // if the path is taken. We never blind-delete a sibling.
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(f) => {
                drop(f);
                // Container::create_with_options uses create_new(true);
                // remove our 0-byte reservation so it can take the slot.
                // Removing only OUR just-created file is safe — random
                // suffix means we can't collide with a victim.
                let _ = std::fs::remove_file(&candidate);
                return Ok(candidate);
            },
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_kind = Some(e.kind());
                continue;
            },
            Err(e) => return Err(Error::Io(e)),
        }
    }
    // Diagnostic includes the observed io::ErrorKind so a host-app
    // hitting this on, e.g., a read-only parent dir gets a useful
    // hint instead of an opaque "could not allocate" message.
    let msg = match last_kind {
        Some(std::io::ErrorKind::AlreadyExists) => {
            "could not allocate unique temp path after 16 tries (AlreadyExists)"
        },
        Some(_) => "could not allocate unique temp path after 16 tries (unexpected io kind)",
        None => "could not allocate unique temp path after 16 tries",
    };
    Err(Error::Internal(msg))
}

/// fsync the parent directory of `path` so a recent `rename(2)` becomes
/// crash-durable on ext4/xfs/btrfs. On Windows there is no parent-dir
/// fsync concept and `MoveFileEx` already provides metadata durability;
/// we no-op there. Best-effort: any I/O error here is silently
/// swallowed, since a successful rename is what we care about — failing
/// the entire compaction because the parent dir couldn't be opened
/// would be worse than the small loss-of-durability window.
fn fsync_parent_dir(path: &std::path::Path) {
    #[cfg(unix)]
    {
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path; // no-op on Windows
    }
}

fn compact_in_place_impl(
    path: &std::path::Path,
    passwords: &[&[u8]],
    options: RepackOptions,
    cancel: Option<&crate::cancel::CancelToken>,
) -> Result<()> {
    let mapping: Vec<(&[u8], &[u8])> = passwords.iter().map(|p| (*p, *p)).collect();
    atomic_rewrite_under_source_lock(path, "hv-compact", cancel, |src, tmp, cancel| {
        Container::repack_into_dest(src, tmp, &mapping, options, cancel)
    })
}

fn change_passwords_impl(
    path: &std::path::Path,
    mapping: &[(&[u8], &[u8])],
    options: RepackOptions,
    cancel: Option<&crate::cancel::CancelToken>,
) -> Result<()> {
    atomic_rewrite_under_source_lock(path, "hv-rotate", cancel, |src, tmp, cancel| {
        Container::repack_into_dest(src, tmp, mapping, options, cancel)
    })
}
