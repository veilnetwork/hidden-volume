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
/// `initial_garbage_chunks` and `superblock_replicas` are applied to the
/// destination as given. `argon2` and `padding_policy` are **`Option`al,
/// and `None` means "keep what the source had"** — repack is still the
/// chance to rotate container parameters (up-tune Argon2 cost as a device
/// gets faster, change the decoy size), but it takes saying so.
///
/// ## Why those two preserve by default (audit HV-09)
///
/// They used to be plain fields whose `Default` was
/// [`Argon2Params::DEFAULT`] and [`PaddingPolicy::None`] — and all three
/// production callers (the FFI `compact_known` / `change_passwords`, the
/// `hv repack` CLI) passed `RepackOptions::default()`. So a container
/// created at 256 MiB / t4 / p4 came out of a password rotation at
/// 64 MiB / t3 / p1: a factor of four off an offline brute force, written
/// into the header for good, with nothing said to the user. The KDF half
/// needed no user action at all — the host app calls compaction itself on
/// a size threshold. Padding went the same way, from a persisted preset
/// to none, un-masking per-commit growth for a multi-snapshot observer.
///
/// The two fields must travel together: [`Container::create_with_options`]
/// re-derives the header's padding bits from `padding_policy`, so
/// carrying the source's `Argon2Params` while defaulting the policy would
/// write a header whose cost is preserved and whose padding index is
/// zeroed.
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
    /// Argon2id KDF parameters for the destination container. `None`
    /// — keep the source's, which is what maintenance wants; `Some(p)`
    /// — rotate to `p`, which is a deliberate re-parameterisation.
    pub argon2: Option<Argon2Params>,
    /// Decoy initial garbage chunks for the destination — same role
    /// as in [`ContainerOptions`].
    pub initial_garbage_chunks: u64,
    /// Padding policy applied to the destination on each commit during
    /// repack, and persisted in its header. `None` — keep the source's
    /// persisted policy.
    pub padding_policy: Option<PaddingPolicy>,
    /// Superblock replica count for the destination's commits.
    pub superblock_replicas: u8,
}

impl Default for RepackOptions {
    /// Preserve the source's security posture; change only what the
    /// caller names. See the struct docs for why `argon2` and
    /// `padding_policy` are not `Argon2Params::DEFAULT` /
    /// `PaddingPolicy::None` here.
    fn default() -> Self {
        Self {
            argon2: None,
            initial_garbage_chunks: 0,
            padding_policy: None,
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
        //
        // The custom arm must ZERO the index, not pass `options.argon2`
        // through (report7 P2). `Argon2Params` carries the index in bits
        // 16..24 of its version word, so "leave it alone" means "keep
        // whatever index arrived in the caller's params" — and the
        // caller is not always writing them from scratch. `repack`
        // builds the destination's params from the SOURCE's header,
        // which already carries the source's index; ask that repack for
        // a custom policy and the new container's header claimed the old
        // container's preset while nothing at runtime applied it. The
        // next open then read that index back and applied the WRONG
        // policy, silently, to a container whose owner had explicitly
        // asked for a different one.
        let argon2_for_header = match options.padding_policy.to_persisted_index() {
            Some(idx) => options.argon2.with_padding_policy_index(idx),
            None => options.argon2.with_padding_policy_index(0),
        };
        let path = path.as_ref();
        let mut file = ContainerFile::create(path, argon2_for_header)?;
        // A failure AFTER the file exists must not leave it behind. The header
        // is written by `create`, so a create that then fails to lay down its
        // initial garbage — `ContainerTooLarge` for an over-large request,
        // ENOSPC on a full disk — used to return Err and leave a 4096-byte
        // stub. `ContainerFile::create` opens with `create_new`, so the retry
        // the caller obviously makes next hits AlreadyExists and the path is
        // unusable until someone deletes a file they never knowingly made.
        let filled = (|| -> Result<()> {
            if options.initial_garbage_chunks > 0 {
                file.append_garbage_chunks(options.initial_garbage_chunks)?;
                file.fsync()?;
            }
            Ok(())
        })();
        if let Err(e) = filled {
            // Drop first: the handle holds the exclusive flock, and unlinking
            // under it is needlessly platform-dependent.
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(e);
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

    /// Open an existing container under an **exclusive** flock that
    /// nonetheless refuses every write — the maintenance-free read.
    ///
    /// [`Container::open`] takes the same exclusive lock but is a
    /// read-WRITE handle, and the `open_space*` family on a read-write
    /// handle performs maintenance of its own accord: `vacuum_orphans`
    /// scrubs orphan IndexNode chunks and the self-heal checkpoint
    /// publishes a bumped-seq superblock. Both rewrite the file. That is
    /// correct for an app opening its own store; it is wrong for a reader
    /// whose contract says the file is untouched.
    ///
    /// This handle behaves exactly like [`Container::open_readonly`] —
    /// [`Self::is_readonly`] is true, every write path answers
    /// [`Error::ReadOnly`], the auto-vacuum skips itself — while holding
    /// `LOCK_EX` rather than `LOCK_SH`, so no other process can write the
    /// file while the handle lives.
    ///
    /// Use it when both properties are needed at once:
    /// - **in-place rewrite** (`compact_known` / `change_passwords`) —
    ///   the lock must be unbroken from first read through rename, and a
    ///   rewrite abandoned before that rename must leave the source
    ///   byte-identical (audit HV-06);
    /// - **forensic / backup copies** that must hash-match the original
    ///   and must not race a concurrent writer.
    ///
    /// Fails with [`Error::Busy`] if any other holder has the file open
    /// under either lock.
    ///
    /// [`Error::Busy`]: crate::Error::Busy
    /// [`Error::ReadOnly`]: crate::Error::ReadOnly
    pub fn open_exclusive_readonly<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = ContainerFile::open_exclusive_readonly(path)?;
        let idx = file.header.params.padding_policy_index();
        file.padding_policy = PaddingPolicy::from_persisted_index(idx);
        Ok(Self { file })
    }

    /// Whether this handle refuses writes.
    ///
    /// True for [`Container::open_readonly`] (shared flock) and for
    /// [`Container::open_exclusive_readonly`] (exclusive flock, writes
    /// refused). The name answers "may this handle modify the file", not
    /// "which flock does it hold" — every caller in the crate wants the
    /// former, and the auto-vacuum gates below are exactly those callers.
    #[must_use]
    pub fn is_readonly(&self) -> bool {
        !self.file.lock_mode.allows_writes()
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
    /// ## If this call is interrupted
    ///
    /// It writes `superblock_replicas` copies of one initial Superblock
    /// (`seq = 1`, `root_slot = NO_RECORD`) and fsyncs. A crash, a kill
    /// or a cancelled future partway through leaves some replicas on
    /// disk and no return value — but what is on disk is a **complete,
    /// empty space**, not a half-built one. There is nothing yet for a
    /// partial write to make inconsistent: the space owns no namespaces,
    /// no Commit chunk and no data.
    ///
    /// So reconciliation is just **opening it again with the same
    /// password**. [`Self::open_space`] finds the replica that landed and
    /// hands back exactly the space this call would have returned. A
    /// second `create_space` with that password answers
    /// [`Error::SpaceAlreadyExists`], which is the truth and not a
    /// symptom — the space exists, and the retry the caller wants is an
    /// open.
    ///
    /// There is deliberately no third outcome here (no
    /// "created-but-unconfirmed"). A caller cannot act differently on it
    /// than on either of the two, and every space this API can leave
    /// behind is openable.
    ///
    /// [`Error::SpaceAlreadyExists`]: crate::Error::SpaceAlreadyExists
    pub fn create_space(&mut self, password: &[u8]) -> Result<Space<'_>> {
        // Audit pass 7 (L4): fail fast on read-only. Without this
        // check, the call would burn ~100ms+ on Argon2id derivation
        // and run the collision-check scan, then fail inside
        // `place_chunk → check_writable` with `Error::ReadOnly`.
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
            // Fast-open self-heal (opportunistic; never fails the open).
            let _ = space.maybe_self_heal_checkpoint();
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
            // Fast-open self-heal: lazily (re)write the open-scan
            // checkpoint so the next open is O(working-set). Runs after
            // vacuum so the recorded owned set is the post-scrub truth.
            // Opportunistic — a failure here never fails a successful
            // open (the checkpoint is an optimization hint, not
            // correctness-bearing; the next open re-tries). See
            // `crate::space::checkpoint`.
            let _ = space.maybe_self_heal_checkpoint();
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
    ///
    /// ## ⚠️ This open does NOT vacuum. [`Space::vacuum_after_open`] does
    ///
    /// Every other writable `open_space*` scrubs orphan `IndexNode`
    /// chunks before it returns. This one deliberately does not, and the
    /// caller owes that scrub (audit HV-01).
    ///
    /// It used to. The equalizer above spends microseconds per chunk to
    /// make the scan's duration independent of whether anything matched;
    /// the scrub that followed it walked the tree, read every non-visible
    /// chunk among the reachable ones, overwrote the orphans and fsynced.
    /// Milliseconds and disk writes, both proportional to how much history
    /// the space has — and reached only when the password was right, since
    /// a wrong one returns before this line. So the wall-clock difference
    /// the equalizer removes was handed straight back, and an observer
    /// watching the process or the filesystem at the moment a password is
    /// typed could read the answer off it. That is exactly the coercion
    /// setting this entry point exists for.
    ///
    /// [`MultiSpace::open_space_constant_time`][crate::MultiSpace::open_space_constant_time]
    /// splits it the same way, with
    /// [`MultiSpace::vacuum_hosted`][crate::MultiSpace::vacuum_hosted]
    /// as the separate step.
    ///
    /// **Honest cost of the split.** Forward secrecy after a
    /// constant-time open is now the caller's to complete rather than a
    /// property of the open. Call [`Space::vacuum_after_open`] — but *not*
    /// on the heels of the unlock, or the same duration simply moves a few
    /// milliseconds to the right and stays correlated with success. Pick a
    /// moment the unlock did not cause: a randomised delay, the screen
    /// going off, the first user-initiated write. The Flutter plugin arms
    /// a randomised delay for its callers; see
    /// `experimental/flutter_plugin/hidden_volume`.
    pub fn open_space_constant_time(&mut self, password: &[u8]) -> Result<Space<'_>> {
        let keys = self.derive_keys(password)?;
        self.open_space_with_keys_constant_time(keys)
    }

    /// `SpaceKeys`-driven variant of [`Self::open_space_constant_time`].
    /// Use when the host-app has cached the derived keys (skips
    /// Argon2id re-derivation); the constant-time-scan property is
    /// preserved.
    ///
    /// ⚠️ **No maintenance here** — see the note on
    /// [`Self::open_space_constant_time`] and call
    /// [`Space::vacuum_after_open`] later (audit HV-01).
    pub fn open_space_with_keys_constant_time(&mut self, keys: SpaceKeys) -> Result<Space<'_>> {
        Space::open_constant_time(&mut self.file, keys)
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
    /// [`Self::open_space_parallel_constant_time`]. Performs no
    /// maintenance — [`Space::vacuum_after_open`] is owed afterwards
    /// (audit HV-01).
    #[cfg(all(feature = "parallel-scan", unix))]
    pub fn open_space_with_keys_parallel_constant_time(
        &mut self,
        keys: SpaceKeys,
    ) -> Result<Space<'_>> {
        Space::open_parallel_constant_time(&mut self.file, keys)
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
    /// [`Self::open_space_mmap_constant_time`]. Performs no
    /// maintenance — [`Space::vacuum_after_open`] is owed afterwards
    /// (audit HV-01).
    #[cfg(all(feature = "mmap", unix))]
    pub fn open_space_with_keys_mmap_constant_time(
        &mut self,
        keys: SpaceKeys,
    ) -> Result<Space<'_>> {
        Space::open_mmap_constant_time(&mut self.file, keys)
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
    /// - `dest` gets `options.initial_garbage_chunks` /
    ///   `superblock_replicas`, and — where `options` names them —
    ///   `argon2` / `padding_policy` (parameter rotation opportunity).
    ///   Where it does not, those two are copied from `source`; see
    ///   [`RepackOptions`] for why maintenance must not silently
    ///   re-parameterise a container (audit HV-09).
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
    /// **Memory footprint of `repack`.** Both legs stream. Log entries
    /// are paged in via `iter_log_after(ns, cursor, PAGE_SIZE)` (audit
    /// pass 16, R-STREAMING-REPACK) and KV entries via
    /// `list_after(ns, cursor, PAGE_SIZE)` (audit HV-02), each page
    /// committed to `dest` before the next is read. The working set is
    /// **one page regardless of namespace size** — ~4 MiB for a log
    /// page, ~1 MiB for a KV page.
    ///
    /// The KV leg used to `list` a whole namespace and then hand every
    /// pair to `Tx::put`, which copies it, so the peak was twice that
    /// namespace's plaintext. It was written that way under a bound
    /// that no longer exists: the index was two levels deep and capped
    /// at roughly 10 K entries per namespace, and audit HV-15 removed
    /// the cap (the tree grows a level whenever the level below
    /// outgrows one chunk) without revisiting the callers that had been
    /// relying on it. The only ceiling left is the container's own,
    /// [`crate::MAX_OPEN_SCAN_CHUNKS`].
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
        // READ-ONLY source. An out-of-place repack documents the source as
        // untouched, and a writable open broke that quietly: `open_space` runs
        // the auto-vacuum, so reading the source to copy it rewrote its bytes.
        // A backup taken this way no longer matches the hash of what it was
        // taken from, which is exactly what a forensic copy is for.
        //
        // A shared lock still excludes writers — `LOCK_SH` blocks `LOCK_EX` —
        // so the consistency the exclusive open provided is unchanged; what is
        // gone is our own ability to mutate. The auto-vacuum skips itself on a
        // read-only handle, so nothing here needs to opt out of it.
        let mut src = Container::open_readonly(source)?;
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

        // R-STREAMING-REPACK (audit pass 16) + audit HV-02: pre-pass-16
        // the flow collected EVERY live KV entry and EVERY live log
        // record for EVERY source space into in-memory `Vec`s before
        // writing the destination — O(total plaintext) RAM, which
        // OOM'd on multi-GiB log namespaces. Pass 16 fixed the log leg;
        // HV-02 fixed the KV leg, which had been left collecting a
        // whole namespace on the strength of a two-level index cap of
        // ~10 K entries that audit HV-15 had already removed. Both legs
        // now interleave source-read and dest-write per namespace:
        //
        // - **KV namespaces** page through
        //   `space.list_after(ns, cursor, KV_PAGE_SIZE)` and commit
        //   each page to the destination's Tx. Working set per page:
        //   ≤ `KV_PAGE_SIZE × (MAX_KEY_LEN + MAX_VALUE_LEN)`
        //   = `512 × 2304 B` ≈ 1.1 MiB, independent of namespace size.
        // - **Log namespaces** page through
        //   `space.iter_log_after(ns, cursor, LOG_PAGE_SIZE)` the same
        //   way. Working set per page:
        //   ≤ `LOG_PAGE_SIZE × MAX_LOG_PAYLOAD_LEN` = `512 × 8 KiB`
        //   = 4 MiB.
        //
        // Splitting one namespace's copy across several destination
        // transactions is sound HERE specifically because the
        // destination is a file this call created: a failure between
        // pages leaves a partially-populated `dest` that the caller
        // discards along with the temp (the in-place flows in
        // `atomic_rewrite_under_source_lock` only rename it over the
        // source once the whole repack returned Ok). This is not a
        // general licence to split transactions.
        //
        // Source and destination are different Container instances
        // each holding its own `LOCK_EX` flock, so interleaving
        // reads from one with writes to the other is safe.
        //
        // Open the destination ONCE up-front so we can
        // create_space(...) inside the per-password loop without
        // re-paying the LOCK_EX dance. (LOCK_EX is held on `dest`
        // for the duration of this whole function.)
        // Audit HV-09: an unspecified field is the SOURCE's, not the
        // library's default. `src` is held under an exclusive lock for
        // this whole function, so reading its header here cannot race a
        // writer; `padding_policy()` is the policy the open decoded out
        // of that same header's bits 16..24.
        //
        // Both must be read, not just `argon2`: `create_with_options`
        // re-derives the destination header's padding index from
        // `padding_policy`, so preserving the Argon2 cost while letting
        // the policy fall back to `None` would zero the index of a
        // container whose cost it had just faithfully carried over.
        let dst_options = ContainerOptions {
            argon2: options.argon2.unwrap_or_else(|| src.params()),
            initial_garbage_chunks: options.initial_garbage_chunks,
            padding_policy: options
                .padding_policy
                .unwrap_or_else(|| src.padding_policy()),
            superblock_replicas: options.superblock_replicas,
        };
        let mut dst = Container::create_with_options(dest, dst_options)?;

        // Page size for log streaming. Half the per-batch cap so
        // each Tx commits one DataBatch chunk worst-case (no
        // auto-split fanout overhead).
        let log_page_size = MAX_RECORDS_PER_BATCH / 2;
        // Page size for KV streaming (audit HV-02). Same count as the
        // log page, which at the KV per-entry worst case
        // (`MAX_KEY_LEN + MAX_VALUE_LEN` = 2304 B) is ≈ 1.1 MiB read
        // plus the same again copied into the Tx.
        let kv_page_size = MAX_RECORDS_PER_BATCH / 2;

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
                        // KV: stream one page at a time, cursor on the
                        // last key of the previous page (audit HV-02).
                        // Each page is its own Tx, so the pairs a page
                        // read are dropped before the next page is.
                        let mut cursor: Option<Vec<u8>> = None;
                        loop {
                            check(cancel)?;
                            let mut page =
                                src_space.list_after(ns, cursor.as_deref(), kv_page_size)?;
                            if page.is_empty() {
                                break;
                            }
                            // Advance the cursor BEFORE the Tx — the
                            // page's entries are drained below.
                            cursor = Some(page.last().expect("non-empty by check above").0.clone());
                            let mut tx = dst_space.begin_tx();
                            // `drain`, not `&page`: `Tx::put` copies, so
                            // iterating by reference would hold the page
                            // and the Tx's copy of it at the same time.
                            // Draining frees each entry as the Tx takes
                            // it, and the peak stays one page rather
                            // than two.
                            for (key, value) in page.drain(..) {
                                tx.put(ns, &key, &value)?;
                            }
                            tx.commit()?;
                        }
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
    ///
    /// **On any failure BEFORE the rename, `path` is left
    /// BYTE-IDENTICAL.** The source is read under an exclusive lock that
    /// refuses writes, so neither the auto-vacuum nor the self-heal
    /// checkpoint runs against it — an abandoned compaction leaves
    /// nothing behind to show it was attempted (audit HV-06).
    ///
    /// The qualifier is not decoration. `rename(2)` is the point of no
    /// return, and two outcomes are reported after it, both meaning the
    /// old file is already gone:
    /// [`Error::RenameVisibleDurabilityUncertain`] (the rewrite is in
    /// place; whether the directory entry survives a crash is unknown)
    /// and [`Error::RenameVisibleContentUnverified`] (the path resolves
    /// to a file this call did not write). Neither is a failure to
    /// retry against the old container, because there is no old
    /// container left to retry against.
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
    /// temp file, then `rename(2)` over `path`. On any failure **before
    /// the rename** the temp is removed and the original `path` is left
    /// byte-identical — see [`Self::compact_known`] for what that took
    /// (audit HV-06) and for the two outcomes reported after the rename,
    /// where the old file is already gone.
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
    // Hold source flock for the entire critical section.
    // `open_exclusive_readonly` acquires LOCK_EX (try_lock_exclusive);
    // concurrent processes that try to open `path` while we work get
    // Error::Busy and bail cleanly. After our rename, the old inode
    // (still held by `src`) is unlinked but live; new openers see the
    // NEW inode and can acquire its lock independently.
    //
    // MAINTENANCE-FREE, not merely locked (audit HV-06). This used to be
    // `Container::open` — a read-WRITE handle — and the `open_space` the
    // write closure performs on it runs `vacuum_orphans` plus the
    // self-heal checkpoint on its own initiative. Both rewrite the source.
    // So the contract three lines below this function's title — "on any
    // failure the temp is removed and the original `path` is untouched" —
    // was false for every caller: a rotation that failed at the very last
    // step, or one the user cancelled, had already scrubbed chunks out of
    // the file it promised not to touch. For a deniable container that is
    // not a cosmetic difference; the bytes an observer captured before the
    // abandoned rotation no longer match the bytes after it, which is
    // evidence that something ran.
    //
    // The exclusive lock is unchanged — it is the write PERMISSION that is
    // dropped, and only until the rename, which is a directory operation
    // and needs nothing from this descriptor.
    let mut src = Container::open_exclusive_readonly(path)?;

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
    // Exclusive lock pin on the tmp we are about to rename into place.
    // WouldBlock means an attacker raced us and holds LOCK_EX first —
    // refuse the rename rather than ship attacker content into `path`.
    //
    // Audit HV-09: this used to be an inline `File::try_lock` behind
    // `#[cfg(not(target_os = "android"))]`, so on Android the pin was
    // ABSENT and the substitute-tmp race was bounded only by the
    // header-validate + inode-pin checks below. std's `try_lock` really
    // does answer `Err(Unsupported)` there, which is why the *container*
    // locks were routed through libc `flock(2)` back in v1.0 — this third
    // site was simply never wired to the same helper, and the comment
    // beside it recorded that as a follow-up instead of doing it. It now
    // goes through `file::try_lock_exclusive`, the one dispatcher both
    // container locks already use, so Android gets the same real
    // `flock(LOCK_EX | LOCK_NB)` as every other Unix.
    match file::try_lock_exclusive(&tmp_handle) {
        Ok(()) => {},
        Err(Error::Busy) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Busy);
        },
        Err(_) => {
            // The filesystem does not honour flock (an exotic non-Unix
            // FS; on Android an errno other than EWOULDBLOCK) — proceed;
            // the header-validate + inode pin below remain the active
            // substitution guards. Same degradation the container locks
            // accept, and the same one this site accepted before.
        },
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

    // M2: fsync parent directory so the rename is durable. On Unix
    // ext4/xfs/etc. without this, a crash after rename can revert the
    // directory entry — restoring the OLD inode, and with it the old password
    // or the spaces this rewrite removed.
    //
    // This used to be swallowed and the call returned `Ok`, which told a caller
    // who had just rotated a leaked password that the old one was dead without
    // grounds to say so (audit HV-03). The rename IS visible either way, so the
    // failure is reported as its own outcome rather than as "the rewrite
    // failed" — see `Error::RenameVisibleDurabilityUncertain`.
    let durability = fsync_parent_dir(path);

    drop(tmp_handle);
    drop(src); // explicit: release lock on the (now-orphan) old inode

    // M3-hardening (Unix): post-rename inode pin. Reported BEFORE the
    // durability outcome, because "the file at this path is not the one
    // we wrote" is strictly worse news than "it is, and might not
    // survive a crash".
    #[cfg(unix)]
    verify_renamed_inode(path, pre_rename_inode)?;

    if durability.is_err() {
        return Err(Error::RenameVisibleDurabilityUncertain(
            "parent-directory fsync failed after a successful rename",
        ));
    }
    Ok(())
}

/// After the rename, `path` must resolve to the very inode the rewrite
/// pinned and renamed. A mismatch means something renamed over `path` in
/// the window between the pin and our rename, so the file a reader will
/// find there is not the one this call wrote. (Hard to mount with our
/// `LOCK_EX` held — belt-and-suspenders.)
///
/// **The failure is post-rename, and the error has to say so** (report6
/// P2). It used to be an [`Error::Internal`], which reads as a crate bug
/// and, by implication, as "nothing was done" — while in fact the
/// rename had already happened and the previous inode was already
/// unlinked. That is the same shape audit HV-03 fixed one branch below
/// for the parent-directory fsync, left unfixed here; and it is why the
/// `compact_known` / `change_passwords` contract now says "before the
/// rename" rather than "on any failure".
///
/// `pinned == None` means the pre-rename `metadata` call failed, and a
/// check with nothing to compare against passes. Likewise a `metadata`
/// that fails now: the answer is unknown, not wrong, and inventing a
/// failure would make an unreadable directory look like an attack.
#[cfg(unix)]
fn verify_renamed_inode(path: &std::path::Path, pinned: Option<(u64, u64)>) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let Some((pre_dev, pre_ino)) = pinned else {
        return Ok(());
    };
    let Ok(post) = std::fs::metadata(path) else {
        return Ok(());
    };
    if post.dev() != pre_dev || post.ino() != pre_ino {
        return Err(Error::RenameVisibleContentUnverified(
            "post-rename inode mismatch (tmp substituted under us)",
        ));
    }
    Ok(())
}

/// The directory that holds `path` — for opening a handle to fsync, or
/// for placing a sibling temp file.
///
/// **`Path::parent` does not answer `None` for a bare file name.** For
/// `"store.hv"` it answers `Some("")`, so the obvious
/// `parent().unwrap_or(Path::new("."))` never fires and the caller ends
/// up at `File::open("")` — ENOENT. That single mistake, copied to three
/// call sites, made every relative-basename path fail: `Container::create`
/// returned `Err(NotFound)` *and* its `UnlinkOnDrop` guard then deleted
/// the container it had just successfully written, and
/// `change_passwords` / `compact_known` returned
/// `RenameVisibleDurabilityUncertain` (report5 HV-P0). `"./store.hv"`
/// worked and `"store.hv"` did not, which is not a distinction any caller
/// can be expected to know about.
///
/// One helper rather than a condition to re-remember: the empty-parent
/// case is exactly the kind of thing a fourth call site gets wrong again.
///
/// Note the two shapes that are NOT the empty case and must keep their
/// own answer: `"/store.hv"` → `"/"`, and `"/"` → `None` (no parent at
/// all), for which `"."` is as good an answer as any — it is not a
/// container path.
fn parent_dir_for(path: &std::path::Path) -> &std::path::Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => std::path::Path::new("."),
    }
}

/// Build a unique temp filename in `path`'s parent directory using 16
/// hex chars of entropy. Creates and immediately closes the file with
/// `create_new = true` so we hold a true reservation; `repack_into_dest`
/// will subsequently `Container::create` over it, which uses the same
/// `create_new` flag — so we delete our reservation just before so the
/// re-create succeeds. Returns the validated path.
fn unique_temp_path_in_parent(path: &std::path::Path, prefix: &str) -> Result<std::path::PathBuf> {
    let parent = parent_dir_for(path);
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
fn fsync_parent_dir(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        #[cfg(test)]
        if fsync_parent_dir_should_fail() {
            return Err(std::io::Error::other(
                "test hook: forced parent-dir fsync failure",
            ));
        }
        // Retry once on EINTR — a signal arriving mid-fsync is not a durability
        // problem, and surfacing it as one would fail rotations for no reason.
        // `parent_dir_for` handles the bare-file-name case, whose parent is
        // `Some("")` rather than `None`; opening "" is ENOENT, which surfaced
        // to the caller as `RenameVisibleDurabilityUncertain` on every
        // rotation or compaction addressed by basename (report5 HV-P0).
        let dir = std::fs::File::open(parent_dir_for(path))?;
        match dir.sync_all() {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => dir.sync_all(),
            other => other,
        }
    }
    #[cfg(not(unix))]
    {
        // Windows has no parent-dir fsync concept; `MoveFileEx` already gives
        // metadata durability, so there is nothing here that can fail.
        let _ = path;
        Ok(())
    }
}

#[cfg(all(test, unix))]
thread_local! {
    /// Test-only switch that makes [`fsync_parent_dir`] report failure.
    ///
    /// The condition it simulates cannot be provoked from outside: revoking
    /// read permission on the parent directory would break the temp-file
    /// write long before the fsync, so there is no way to reach only this
    /// step.
    ///
    /// Thread-local for the same reason as
    /// `container::file::CREATE_FSYNC_FAILS`: a process-global switch armed
    /// every parallel test in the binary, not the one call the arming test
    /// makes.
    static FSYNC_PARENT_DIR_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(all(test, unix))]
fn fsync_parent_dir_should_fail() -> bool {
    FSYNC_PARENT_DIR_FAILS.with(std::cell::Cell::get)
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

/// The post-rename inode pin must report a POST-rename outcome
/// (report6 P2).
///
/// Driven at the helper rather than through `compact_known`, because
/// reaching the mismatch through the public API means renaming another
/// file over `path` in the window between our pin and our rename, while
/// we hold `LOCK_EX` — a race that decides at random whether the test
/// proves anything. The helper takes the pinned inode as a parameter
/// precisely so that "the path is not what we pinned" can be stated
/// directly.
#[cfg(all(test, unix))]
mod post_rename_inode_tests {
    use super::verify_renamed_inode;
    use crate::Error;

    struct Scratch(std::path::PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn scratch_file(tag: &str) -> Scratch {
        let p = std::env::temp_dir().join(format!(
            "hv-inode-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&p, b"container-ish").expect("scratch file");
        Scratch(p)
    }

    fn inode_of(path: &std::path::Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt as _;
        let m = std::fs::metadata(path).expect("metadata");
        (m.dev(), m.ino())
    }

    /// The whole point: a mismatch is not [`Error::Internal`].
    ///
    /// `Internal` is documented as a crate bug, which a caller reads as
    /// "nothing happened" — and here the rename HAS happened and the
    /// old inode is already unlinked. Asserting the variant is the
    /// assertion, because the detection itself was never broken.
    #[test]
    fn a_mismatch_reports_the_rename_as_visible_not_as_an_internal_bug() {
        let f = scratch_file("mismatch");
        let (dev, ino) = inode_of(&f.0);
        // Any inode but this file's. `ino + 1` is not guaranteed to be
        // allocated, which is fine — the check compares, it does not
        // resolve.
        let err = verify_renamed_inode(&f.0, Some((dev, ino.wrapping_add(1))))
            .expect_err("a different inode must not pass the pin");
        assert!(
            matches!(err, Error::RenameVisibleContentUnverified(_)),
            "post-rename substitution reported as {err:?}, which tells the \
             caller the rewrite did not happen"
        );
    }

    /// The honest case still passes, or the check would fail every
    /// rewrite and the test above would be satisfied by a stub that
    /// always errors.
    #[test]
    fn the_pinned_inode_passes() {
        let f = scratch_file("match");
        assert!(verify_renamed_inode(&f.0, Some(inode_of(&f.0))).is_ok());
    }

    /// Nothing pinned, and a path that cannot be read, are both
    /// "unknown" rather than "wrong". Inventing a failure there would
    /// make an unreadable directory look like an attack.
    #[test]
    fn an_unknown_answer_is_not_a_failure() {
        let f = scratch_file("unknown");
        assert!(verify_renamed_inode(&f.0, None).is_ok());
        let missing = f.0.with_extension("does-not-exist");
        assert!(verify_renamed_inode(&missing, Some((0, 0))).is_ok());
    }
}

#[cfg(test)]
mod hv06_tests {
    use super::*;
    use crate::padding::PaddingPolicy;
    use crate::space::index::Namespace;

    fn options() -> ContainerOptions {
        ContainerOptions {
            argon2: Argon2Params::MIN,
            initial_garbage_chunks: 0,
            padding_policy: PaddingPolicy::None,
            superblock_replicas: 1,
        }
    }

    struct Scratch(std::path::PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(name: &str) -> (Scratch, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("hv06-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("c.hv");
        (Scratch(dir), path)
    }

    /// A CANCELLED rewrite must leave the source byte-identical.
    ///
    /// Cancellation is driven at the primitive rather than through
    /// `compact_known_cancellable`, because a token fired before that call
    /// trips the repack's first `check(cancel)` BEFORE the source space is
    /// ever opened — the exact step the maintenance hangs off. Reaching a
    /// cancel that lands after a source open through the public API needs a
    /// second thread firing the token mid-flight, which decides at random
    /// whether the test proves anything.
    ///
    /// The closure below does what the real one does up to that point — it
    /// opens a source space with a real password — and then returns
    /// `Cancelled`, which is how a mid-flight cancel exits.
    #[test]
    fn a_cancelled_rewrite_leaves_the_source_byte_identical() {
        let (_guard, path) = scratch("cancel");

        // Leave an orphan IndexNode behind: put + commit, delete + commit,
        // then drop without reopening, so nothing has vacuumed it yet.
        {
            let mut c = Container::create_with_options(&path, options()).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            let mut tx = s.begin_tx();
            tx.put(Namespace::CONTACTS, b"alice", b"a").unwrap();
            tx.commit().unwrap();
            let mut tx = s.begin_tx();
            tx.delete(Namespace::CONTACTS, b"alice").unwrap();
            tx.commit().unwrap();
        }

        let before = std::fs::read(&path).unwrap();

        let err = atomic_rewrite_under_source_lock(&path, "hv-compact", None, |src, _tmp, _c| {
            // The step that used to mutate the source: a read-write handle
            // vacuums here, and publishes a self-heal checkpoint after that.
            let mut space = src.open_space(b"pw")?;
            assert!(space.get(Namespace::CONTACTS, b"alice")?.is_none());
            Err(Error::Cancelled)
        })
        .expect_err("the closure cancelled, so the rewrite must fail");
        assert!(matches!(err, Error::Cancelled), "got {err:?}");

        let after = std::fs::read(&path).unwrap();
        assert!(
            before == after,
            "the source was modified by a rewrite the caller cancelled"
        );
    }

    /// The source handle the primitive hands to its closure must refuse
    /// writes outright, not merely skip the automatic ones. A closure that
    /// tries to commit into the source is a bug, and it must surface as one.
    #[test]
    fn the_primitive_hands_its_closure_a_source_that_refuses_writes() {
        let (_guard, path) = scratch("refuses");
        {
            let mut c = Container::create_with_options(&path, options()).unwrap();
            let _ = c.create_space(b"pw").unwrap();
        }

        let err = atomic_rewrite_under_source_lock(&path, "hv-compact", None, |src, _tmp, _c| {
            assert!(src.is_readonly(), "the source handle must be read-only");
            let mut space = src.open_space(b"pw")?;
            let mut tx = space.begin_tx();
            tx.put(Namespace::CONTACTS, b"bob", b"b")?;
            match tx.commit() {
                Err(Error::ReadOnly) => Err(Error::Cancelled),
                other => panic!("a write into the rewrite source must be refused, got {other:?}"),
            }
        })
        .expect_err("the closure returned an error");
        assert!(matches!(err, Error::Cancelled), "got {err:?}");
    }

    /// Audit HV-09: the tmp-file pin must actually be taken.
    ///
    /// Someone else holding `LOCK_EX` on the tmp between the writer
    /// finishing and the rename is the substitution race the pin exists to
    /// stop, and the rewrite must refuse rather than publish whatever is at
    /// that path. Until this pass the whole pin sat behind
    /// `#[cfg(not(target_os = "android"))]`, so on Android it was not taken
    /// at all — this test cannot see that target, but it fails the moment
    /// the pin is compiled out of whichever one it does run on.
    ///
    /// The closure writes a *valid* container at `tmp` on purpose: the
    /// header-validate and inode-pin below the lock would otherwise refuse
    /// it for their own reasons and the test would pass without the pin
    /// existing. The competing holder is a second `open()` in this same
    /// process, which is a separate open file description and therefore
    /// contends for `flock(2)` exactly as another process would (see
    /// `tests/locking.rs`).
    #[cfg(unix)]
    #[test]
    fn the_tmp_pin_refuses_a_tmp_someone_else_has_locked() {
        let (_guard, path) = scratch("tmp-pin");
        {
            let mut c = Container::create_with_options(&path, options()).unwrap();
            let _ = c.create_space(b"pw").unwrap();
        }
        let before = std::fs::read(&path).unwrap();

        let mut rival = None;
        let err = atomic_rewrite_under_source_lock(&path, "hv-compact", None, |_src, tmp, _c| {
            let mut out = Container::create_with_options(tmp, options())?;
            let _ = out.create_space(b"pw")?;
            drop(out);

            let handle = std::fs::OpenOptions::new().read(true).open(tmp)?;
            file::try_lock_exclusive(&handle)
                .expect("the rival must get the lock first for this test to mean anything");
            rival = Some(handle);
            Ok(())
        })
        .expect_err("a locked tmp must not be renamed into place");
        assert!(matches!(err, Error::Busy), "got {err:?}");
        drop(rival);

        assert!(
            std::fs::read(&path).unwrap() == before,
            "the rewrite published something despite refusing"
        );
    }
}

#[cfg(all(test, unix))]
mod hv03_tests {
    use super::*;
    use crate::padding::PaddingPolicy;

    /// Restores the fsync-failure switch even if the test panics, so a failure
    /// here cannot leak into whatever runs next in the same process.
    struct ForcedFsyncFailure;

    impl ForcedFsyncFailure {
        fn arm() -> Self {
            FSYNC_PARENT_DIR_FAILS.with(|c| c.set(true));
            Self
        }
    }

    impl Drop for ForcedFsyncFailure {
        fn drop(&mut self) {
            FSYNC_PARENT_DIR_FAILS.with(|c| c.set(false));
        }
    }

    fn fast_options() -> ContainerOptions {
        ContainerOptions {
            argon2: Argon2Params::MIN,
            initial_garbage_chunks: 0,
            padding_policy: PaddingPolicy::None,
            superblock_replicas: 1,
        }
    }

    /// A parent-directory fsync that fails must not be reported as success.
    ///
    /// The rewrite swallowed it and returned `Ok`, which told someone who had
    /// just rotated a leaked password that the old one was dead — while a crash
    /// in that window can restore the old inode and the old password with it
    /// (audit HV-03).
    ///
    /// It must also not be reported as "the rotation failed": the rename IS
    /// visible, the new password IS in effect, and a caller who retried with
    /// the old password would be working from a false picture. This pins both
    /// halves.
    #[test]
    fn rotation_reports_an_unconfirmed_fsync_without_lying_about_what_applied() {
        let dir = std::env::temp_dir().join(format!("hv03-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.bin");
        let _cleanup = scopeguard(&dir);

        {
            let mut c = Container::create_with_options(&path, fast_options()).unwrap();
            let mut s = c.create_space(b"old").unwrap();
            let mut tx = s.begin_tx();
            tx.put(crate::space::index::Namespace::SETTINGS, b"k", b"v")
                .unwrap();
            tx.commit().unwrap();
        }

        let err = {
            let _armed = ForcedFsyncFailure::arm();
            Container::change_passwords(&path, &[(b"old", b"new")], RepackOptions::default())
                .expect_err("a failed durability fsync must not be reported as success")
        };
        assert!(
            matches!(err, Error::RenameVisibleDurabilityUncertain(_)),
            "expected the durability-specific outcome, got {err:?}"
        );

        // The rotation APPLIED. Anyone reading the error as "nothing happened"
        // would be wrong in the one direction that matters.
        let mut c = Container::open(&path).unwrap();
        let mut s = c
            .open_space(b"new")
            .expect("the new password must open the container");
        assert_eq!(
            s.get(crate::space::index::Namespace::SETTINGS, b"k")
                .unwrap(),
            Some(b"v".to_vec()),
            "the rewritten container must still hold its data"
        );
        drop(c);

        let mut c = Container::open(&path).unwrap();
        assert!(
            c.open_space(b"old").is_err(),
            "the old password must be dead — that is what the caller rotated for"
        );
    }

    fn scopeguard(dir: &std::path::Path) -> impl Drop {
        struct G(std::path::PathBuf);
        impl Drop for G {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        G(dir.to_path_buf())
    }
}
