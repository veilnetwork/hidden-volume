//! `hidden-volume-ffi` — uniffi-based FFI bindings for the
//! [`hidden_volume`] container library.
//!
//! ## What this crate is
//!
//! A thin, FFI-friendly wrapper around the sync `hidden-volume` core,
//! exposed via [uniffi] proc-macros. Two sibling surfaces:
//!
//! - **Sync** — [`SpaceHandle`]. Methods take `&self`, block the
//!   calling thread on the underlying mutex + sync-core call. Right
//!   for: iOS/GCD-only legacy code, embedded ARM (no Tokio),
//!   server-side single-threaded scripts.
//! - **Async** — [`AsyncSpaceHandle`]. Every method is `async fn` and
//!   offloads work to `tokio::task::spawn_blocking`. Right for:
//!   Kotlin coroutines, Swift `async/await`, Tokio-based servers.
//!
//! Both share the same internal [`hidden_volume_rt::OwnedSpace`]
//! (boxed Container + ManuallyDrop'd Space behind Mutex) — one
//! storage path, two API flavors.
//!
//! From this crate, the uniffi toolchain generates idiomatic bindings
//! for:
//!
//! - **Kotlin** (Android / desktop JVM) — primary messenger target
//! - **Swift** (iOS / macOS) — primary messenger target
//! - **Python** — host-app prototyping & test scripts
//! - **Ruby** — same
//!
//! ## Why uniffi (over flutter_rust_bridge / cbindgen / cxx)
//!
//! See [`docs/en/reference/ffi.md`](../../../docs/en/reference/ffi.md) for the full ADR.
//! Short version: uniffi is the only mature choice that produces
//! **memory-safe, idiomatic** Kotlin and Swift bindings from a single
//! Rust source of truth, with first-class error mapping, opaque
//! handle types, and a small runtime cost. Flutter Rust Bridge is
//! Flutter-only; cbindgen / cxx require hand-writing wrapper code in
//! every host language.
//!
//! ## API shape
//!
//! Two exported objects:
//!
//! - [`SpaceHandle`] — the workhorse. Combines container open + space
//!   open into one call ([`SpaceHandle::create`] /
//!   [`SpaceHandle::open`]). Holds `Box<Container>` + a `Space<'_>`
//!   borrowing from it via the standard self-referential pattern (see
//!   [`hidden_volume_rt::OwnedSpace`] for the safety argument).
//!   All read methods (`get`,
//!   `count`, `read_log`, `iter_log_range`, `verify_integrity`,
//!   `commit_seq`) take `&self` and lock briefly. Writes go through
//!   [`SpaceHandle::commit`] which accepts a `Vec<WriteOp>` (one
//!   commit chunk per call — host-app batches at the call site).
//!
//! - Top-level free functions: [`header_info`] for password-less
//!   header inspection.
//!
//! Error type: [`HvError`] — flat enum, one variant per
//! [`hidden_volume::Error`] case. uniffi maps this to typed
//! exceptions on the foreign side (Kotlin: sealed class hierarchy,
//! Swift: enum with associated values).
//!
//! ## Threading
//!
//! Each handle is `Arc<Self>` (uniffi default for `#[derive(uniffi::Object)]`).
//! Internal state is wrapped in `Mutex`; concurrent calls from foreign
//! threads serialize on the lock. Per the sync core's design, only one
//! `Tx` may be active per `Space` at a time — the mutex enforces this
//! at the FFI boundary.
//!
//! ## What is NOT in this crate (deferred)
//!
//! - **Cancellation tokens across the FFI boundary**: would need
//!   uniffi callback-interface support; defer to actual demand.
//! - **Streaming `iter_log_*`**: currently returns `Vec<LogEntry>` per
//!   call. For unbounded scrollback, host-app pages via `iter_log_range`
//!   in a loop. Native-streaming primitives would need callback
//!   interfaces or foreign-side adapters (Kotlin `Flow`, Swift
//!   `AsyncSequence`); defer. Pure-Rust callers should use
//!   `hidden-volume-async`'s `AsyncSpace::stream_log_pages_*` for
//!   `Stream`-style APIs.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(rust_2018_idioms)]
#![deny(missing_docs)]

use std::path::PathBuf;
use std::sync::Mutex;

use hidden_volume::Container;
use hidden_volume::MultiSpace;
use hidden_volume::Space;
use hidden_volume::cancel::CancelToken;
use hidden_volume::container::ContainerOptions;
use hidden_volume::crypto::SpaceKeys;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use hidden_volume_rt::{OpLedger, OwnedSpace};

/// Length of a serialized [`SpaceKeys`] across the FFI: `container_id` (32) ‖
/// `aead_root` (32). These bytes are the per-space decryption root — opaque,
/// sensitive, **never logged**; they live only inside a master space.
const SPACE_KEYS_LEN: usize = 64;

uniffi::setup_scaffolding!();

// ---------- Error mapping ----------

/// FFI-friendly error. One variant per [`hidden_volume::Error`] case.
/// `flat_error` makes uniffi treat this as a flat tagged-union — every
/// variant becomes its own typed exception on the foreign side.
///
/// **This enum is append-only.** uniffi transports a `flat_error` as its
/// ordinal, and the hand-written Dart bindings turn that ordinal back
/// into a name through a positional list (`_hvErrorKinds` in
/// `experimental/flutter_plugin/hidden_volume/lib/src/bindings.dart`).
/// Inserting a variant in the middle renames every error after it on the
/// Dart side, silently and at runtime. Add new variants at the END, and
/// append the matching name to that list in the same commit.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
#[non_exhaustive]
pub enum HvError {
    /// Filesystem I/O error. Message includes the OS error string.
    #[error("io: {0}")]
    Io(String),
    /// Wrong password OR no space exists for this password.
    /// Callers MUST NOT branch on which (deniability invariant).
    #[error("authentication failed")]
    AuthFailed,
    /// `create_space` was called with a password that already has a space.
    #[error("space already exists for this password")]
    SpaceAlreadyExists,
    /// Container file is locked by another process or fd. Retry later.
    #[error("container is busy")]
    Busy,
    /// Tried to write through a handle opened read-only.
    #[error("operation requires a writable container handle")]
    ReadOnly,
    /// Malformed on-disk state (truncation, magic mismatch, framing error).
    #[error("malformed: {0}")]
    Malformed(String),
    /// KDF failure (parameter validation, OOM, etc.).
    #[error("kdf: {0}")]
    Kdf(String),
    /// Internal invariant violation. Indicates a bug.
    #[error("internal: {0}")]
    Internal(String),
    /// Per-chunk capacity exceeded.
    #[error("payload exceeds chunk capacity")]
    PayloadTooLarge,
    /// A namespace's index could not be built. Not a capacity limit
    /// since audit HV-15 — see `hidden_volume::Error::IndexFull`.
    #[error("index full")]
    IndexFull,
    /// zstd compression / decompression failure.
    #[error("compression: {0}")]
    Compression(String),
    /// Cooperative cancellation fired.
    ///
    /// There is still no token in the FFI signatures — this is raised when
    /// a caller drops the future of an [`AsyncSpaceHandle`] call before it
    /// reported back and the work had not yet reached the container
    /// (audit HV-02). **It is a proof of no effect**, so the call is safe
    /// to retry even when it is not idempotent. An abandoned call that had
    /// already started does *not* surface here at all — the caller is gone;
    /// [`AsyncSpaceHandle::abandoned_operations`] is where its verdict goes.
    #[error("cancelled")]
    Cancelled,
    /// Wrong API for this namespace's kind. e.g. `read_log` /
    /// `iter_log_range` called on a regular KV namespace, or vice
    /// versa. Audit pass 7 (L1).
    #[error("wrong namespace kind: {0}")]
    WrongNamespaceKind(String),
    /// Tx touched more than 16 distinct namespaces. Commit + start a
    /// new Tx. Audit pass 7 (L2).
    #[error("transaction touches too many namespaces (limit {limit})")]
    TooManyNamespaces {
        /// The cap.
        limit: u64,
    },
    /// Hash-chain mismatch during `verify_integrity`.
    #[error("integrity: {detail} at slot {slot}")]
    IntegrityFailure {
        /// Diagnostic detail about which Merkle link failed.
        detail: String,
        /// Slot index of the offending chunk.
        slot: u64,
    },
    /// The container is past the open-scan budget
    /// (`MAX_OPEN_SCAN_CHUNKS`) — raised both by a write that would push
    /// it over and by an open of a file already over (audit HV-13; the
    /// read side used to surface as [`HvError::Malformed`], which told a
    /// foreign-side caller its intact container was corrupt).
    ///
    /// Caller-actionable: shrink `initial_garbage_chunks`, pick a lighter
    /// [`PaddingPreset`], or partition the container. NOT a crate bug —
    /// distinct from [`HvError::Internal`].
    #[error("container exceeds open-scan budget ({chunks} chunks > cap {cap})")]
    ContainerTooLarge {
        /// The chunk count that tripped the budget.
        chunks: u64,
        /// Hard cap (`MAX_OPEN_SCAN_CHUNKS`).
        cap: u64,
    },

    // ---- report7 P1: four core variants that used to be erased here ----
    //
    // All four reached the catch-all and arrived on the foreign side as
    // `Internal("unknown error variant")` — whose own doc comment says it
    // indicates a bug in the library. Every one of them is instead a
    // normal outcome with a specific remedy, and three of the four are
    // reachable from the main path, not from a fault-injection harness.
    /// The container holds state written by a NEWER format this build
    /// cannot read. The space is **readable** — the open fell back to the
    /// newest superblock it understands — but anything that would act on
    /// that stale view is refused: `vacuum_orphans` and `commit_tx`.
    ///
    /// Reachable without any exotic setup: the Dart plugin arms deferred
    /// orphan cleanup on **every open**, so a container touched by a
    /// newer build raises this on each one. As `Internal` it told the
    /// host its library was broken; the real remedy is to upgrade, or to
    /// open the container with the version that wrote it.
    ///
    /// Not a deniability leak: reaching it requires the space key.
    #[error("this container holds state written by a newer format this build cannot read")]
    UnreadableNewerState,
    /// An atomic rewrite's `rename` **succeeded and is visible**, but the
    /// parent-directory `fsync` that makes the directory entry survive a
    /// crash did not.
    ///
    /// **The operation applied.** After a password change this means the
    /// NEW passwords are in effect and the old ones no longer open the
    /// container. Do not retry with the old password and do not read this
    /// as "the rotation failed" — which is exactly what `Internal` said.
    /// What is unconfirmed is only whether the directory entry survives a
    /// power loss.
    ///
    /// Remedy: fsync the containing directory by whatever means the
    /// platform offers, or accept the window knowingly.
    #[error("rename is visible but its durability is unconfirmed: {0}")]
    RenameVisibleDurabilityUncertain(String),
    /// An atomic rewrite's `rename` **succeeded**, and the file now at
    /// that path is **not the one we wrote** — something renamed over it
    /// in the window between pinning the temp inode and re-reading the
    /// path's.
    ///
    /// **The old container is gone either way.** Not a failed operation
    /// to retry: the rename happened and the previous inode is unlinked.
    /// Remedy is to restore from backup and to treat the directory as
    /// writable by someone else.
    #[error("rename is visible but the file at that path is not the one written: {0}")]
    RenameVisibleContentUnverified(String),
    /// A previous publish got at least one Superblock replica onto the
    /// disk and then failed, so this handle's view may be one era behind
    /// what a reopen would select. Raised for the DESTRUCTIVE operations
    /// only — a vacuum on this handle would erase chunks belonging to an
    /// era that is already visible on disk.
    ///
    /// Reachable on the main path for the same reason as
    /// [`Self::UnreadableNewerState`]: orphan cleanup raises it, and the
    /// Dart plugin arms deferred cleanup on every open. **Remedy is to
    /// reopen the container** — which, reported as `Internal`, never
    /// reached the host at all. Committing is not blocked.
    #[error("a previous publish may have reached the disk; reopen before {0}")]
    PublishUncertain(String),
    /// The path names something other than a plain file — a symlink, a
    /// device node, a directory.
    ///
    /// **Nothing was touched.** An in-place rewrite ends in a rename over
    /// the path, and a rename replaces the NAME: through a symlink it
    /// replaces the LINK and leaves the container it points at unchanged,
    /// old password and all. Refused rather than reported as success.
    ///
    /// Remedy: pass the path the link resolves to, if that is what was
    /// meant.
    #[error("path is not a regular file this library can rewrite in place: {0}")]
    SourceIsNotARegularFile(String),
    /// An atomic rewrite **applied at the path it was given**, and the
    /// previous file is still reachable under this many OTHER names.
    ///
    /// **The operation applied.** After a password change the new password
    /// is in force at the path that was named. What is qualified is the
    /// REVOCATION: a hard link is a second name for the same file, so
    /// every other name still opens the pre-rotation container with the
    /// old password and the spaces this rewrite removed.
    ///
    /// Not a failure to retry — retrying rewrites the same name again.
    /// Remedy: find and remove the other names, or accept knowingly that a
    /// copy of the pre-rotation container exists.
    #[error("rewrite is visible but the old file is still reachable under {others} other name(s)")]
    RenameVisibleAliasesNotRevoked {
        /// How many OTHER names still resolve to the pre-rewrite file.
        others: u64,
    },
    /// Another caller holds the handle's operation permit, and this one
    /// asked not to wait.
    ///
    /// **Nothing ran.** Raised only by the `try_run` family. Retrying is
    /// reasonable: the permit is a queue, not a verdict.
    #[error("the handle's operation permit is held by another caller; nothing ran")]
    WouldBlock,
    /// The rewrite landed, and this platform could not say whether the old
    /// file is still reachable under another name.
    ///
    /// APPENDED, and it has to be: the Dart side maps these positionally, so
    /// inserting a variant anywhere above silently renames every one after it.
    ///
    /// Not the same as "no other names" — that is what a hard-coded count of
    /// one claimed on every non-Unix platform, and NTFS hard links exist, so a
    /// rotation could leave one behind and still report success (report17
    /// HV17-M3).
    ///
    /// **Not a failure to retry.** The rewrite is in place at the path that
    /// was named; what is unknown is how far the revocation reached, and
    /// rewriting the same name again does not find out.
    #[error(
        "rewrite is visible but this platform cannot say whether other names for the old file remain"
    )]
    RenameVisibleAliasesUnknown,
}

impl From<hidden_volume::Error> for HvError {
    fn from(e: hidden_volume::Error) -> Self {
        use hidden_volume::Error as E;
        match e {
            E::Io(io) => HvError::Io(io.to_string()),
            E::AuthFailed => HvError::AuthFailed,
            E::SpaceAlreadyExists => HvError::SpaceAlreadyExists,
            E::Busy => HvError::Busy,
            E::ReadOnly => HvError::ReadOnly,
            E::Malformed(s) => HvError::Malformed(s.into()),
            E::Kdf(s) => HvError::Kdf(s.into()),
            E::Internal(s) => HvError::Internal(s.into()),
            E::PayloadTooLarge => HvError::PayloadTooLarge,
            E::IndexFull => HvError::IndexFull,
            E::Compression(s) => HvError::Compression(s.into()),
            E::Cancelled => HvError::Cancelled,
            E::WrongNamespaceKind(s) => HvError::WrongNamespaceKind(s.into()),
            E::TooManyNamespaces { limit } => HvError::TooManyNamespaces {
                limit: limit as u64,
            },
            E::IntegrityFailure { detail, slot } => HvError::IntegrityFailure {
                detail: detail.into(),
                slot,
            },
            E::ContainerTooLarge { chunks, cap } => HvError::ContainerTooLarge { chunks, cap },
            E::UnreadableNewerState => HvError::UnreadableNewerState,
            E::RenameVisibleDurabilityUncertain(s) => {
                HvError::RenameVisibleDurabilityUncertain(s.into())
            },
            E::RenameVisibleContentUnverified(s) => {
                HvError::RenameVisibleContentUnverified(s.into())
            },
            E::WouldBlock => HvError::WouldBlock,
            E::SourceIsNotARegularFile(s) => HvError::SourceIsNotARegularFile(s.into()),
            E::RenameVisibleAliasesNotRevoked(others) => {
                HvError::RenameVisibleAliasesNotRevoked { others }
            },
            E::RenameVisibleAliasesUnknown => HvError::RenameVisibleAliasesUnknown,
            E::PublishUncertain(s) => HvError::PublishUncertain(s.into()),
            // `hidden_volume::Error` is `#[non_exhaustive]`, so this
            // catch-all is mandatory. It is a deniability-safe default
            // for any variant added upstream but not yet mapped here —
            // NOT a dumping ground for known variants. When a new core
            // variant is added, add an explicit arm above.
            //
            // `every_core_variant_maps_to_something_other_than_unknown`
            // is what holds that line: it names every variant the core
            // has and fails on any that lands here. It exists because
            // this comment used to promise `from_maps_*` tests that were
            // never written, and four variants sat in the catch-all
            // behind that promise (report7 P1).
            _ => HvError::Internal("unknown error variant".into()),
        }
    }
}

type HvResult<T> = Result<T, HvError>;

// ---------- Argon2 preset ----------

/// Cost preset for [`Argon2Params`]. Maps to the constants documented
/// in `DESIGN.md` §11.1. Host-apps usually pick LIGHT for low-end ARM,
/// DEFAULT for mainstream phones, HEAVY for desktop / server.
#[derive(uniffi::Enum, Debug, Clone, Copy)]
pub enum ArgonPreset {
    /// Test-only — minimum acceptable. Do NOT use in production.
    Min,
    /// Recommended for low-end ARM (Cortex-A53 class).
    Light,
    /// Recommended default for mid-range to high-end phones.
    Default,
    /// Recommended for desktop / unconstrained hardware.
    Heavy,
}

impl ArgonPreset {
    fn to_params(self) -> Argon2Params {
        match self {
            Self::Min => Argon2Params::MIN,
            Self::Light => Argon2Params::LIGHT,
            Self::Default => Argon2Params::DEFAULT,
            Self::Heavy => Argon2Params::HEAVY,
        }
    }
}

// ---------- Padding policy preset ----------

/// FFI-exposed post-commit padding policy. A flat preset enum
/// matching the persistable subset of [`PaddingPolicy`]. The four
/// variants below correspond exactly to indices 0..3 of the
/// in-header `padding_policy_index` byte (audit pass 8 S1 full),
/// and `Container::open` auto-restores the policy from the header on
/// every reopen — so most callers never need to call
/// [`SpaceHandle::set_padding_policy`] at all. Manual override is
/// only useful when the host wants to differ from the policy chosen
/// at create-time, or when a multi-snapshot adversary may have
/// tampered with the (unauthenticated by design — D1) cleartext byte
/// (see threat-model.md §F-PAD).
#[derive(uniffi::Enum, Debug, Clone, Copy)]
pub enum PaddingPreset {
    /// No post-commit padding. Privacy degrades against multi-snapshot
    /// adversaries — host-app should override with one of the bucket
    /// presets below.
    None,
    /// 256 KiB buckets — recommended for embedded / very weak phones.
    Bucket256Kib,
    /// 1 MiB buckets — recommended default for typical mobile.
    Bucket1Mib,
    /// 16 MiB buckets — desktop / unconstrained storage.
    Bucket16Mib,
}

impl PaddingPreset {
    fn to_policy(self) -> PaddingPolicy {
        match self {
            Self::None => PaddingPolicy::None,
            Self::Bucket256Kib => PaddingPolicy::BucketGrowth { bucket_chunks: 64 },
            Self::Bucket1Mib => PaddingPolicy::BucketGrowth { bucket_chunks: 256 },
            Self::Bucket16Mib => PaddingPolicy::BucketGrowth {
                bucket_chunks: 4096,
            },
        }
    }
}

// ---------- Header info (no password) ----------

/// Public header information about a container, readable without
/// a password (everything in [`HeaderInfo`] is plaintext on disk).
///
/// **v3 (2026-05-28).** The 32-byte `container_id` is no longer in
/// the cleartext header — it is derived per-space inside
/// `SpaceKeys::from_master` from the versioned master key. To learn
/// a space's `container_id` requires opening that space (and thus
/// knowing its password), which preserves D2 deniability.
#[derive(uniffi::Record, Debug, Clone)]
pub struct HeaderInfo {
    /// 32-byte random salt, hex-encoded.
    pub salt_hex: String,
    /// Argon2id memory cost (KiB).
    pub argon_m_cost_kib: u32,
    /// Argon2id time cost (iterations).
    pub argon_t_cost: u32,
    /// Argon2id parallelism lanes.
    pub argon_p_cost: u32,
    /// File size in bytes.
    pub file_size_bytes: u64,
}

/// Read public header info from a container at `path`. Does not require
/// a password — everything in [`HeaderInfo`] is plaintext on disk.
/// Uses a shared (read-only) flock so it is safe to call concurrently
/// with a writer process.
#[uniffi::export]
pub fn header_info(path: String) -> HvResult<HeaderInfo> {
    let p = PathBuf::from(path);
    let c = Container::open_readonly(&p)?;
    let h = c.header();
    let p_meta = c.params();
    let bytes = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
    Ok(HeaderInfo {
        salt_hex: hex(&h.salt),
        argon_m_cost_kib: p_meta.m_cost_kib,
        argon_t_cost: p_meta.t_cost,
        argon_p_cost: p_meta.p_cost,
        file_size_bytes: bytes,
    })
}

// ---------- Path-level maintenance (audit pass 11 R-FFI-1) ----------
//
// These functions take a container path (NOT a handle) because the
// underlying core APIs `Container::compact_known` /
// `Container::change_passwords` rewrite the file in place via the
// pass-11 `atomic_rewrite_under_source_lock` primitive. They acquire
// `LOCK_EX` on `path` themselves; the caller MUST first close every
// `SpaceHandle` / `AsyncSpaceHandle` for the same container — a held
// handle's lock will collide and these calls return
// [`HvError::Busy`].

/// One mapping for [`change_passwords`]. `old == new` preserves the
/// space verbatim (no rotation); `old != new` rotates to the new
/// password. Spaces NOT mentioned in the rotations vector are
/// **dropped** by the rewrite — list every space you want to keep.
///
/// **Memory hygiene (foreign-side responsibility).** Like every other
/// FFI password parameter on this crate (`SpaceHandle::create`,
/// `SpaceHandle::open`, async mirrors, top-level [`compact_known`]),
/// the `old` and `new` byte buffers are owned by the foreign side
/// and **not** zeroized by the Rust runtime when the call returns.
/// Foreign integrators SHOULD zeroize each `Vec<u8>` after the call
/// resolves (e.g. Kotlin: `oldPw.fill(0); newPw.fill(0)`; Swift:
/// loop-write zeros into the `Data`'s mutable view). This is a
/// documented trade-off: see `docs/en/security/audits/plaintext.md`.
// Audit pass 17 F-2: deliberately NO `Clone` derive. uniffi only needs
// `Record` for marshaling; `Clone` would silently allow a future
// caller to spawn a `.clone()` of the inner `Vec<u8>` keys outside the
// pass-16 `Zeroizing` flow, leaving plaintext heap copies that never
// scrub. If a future site genuinely needs a copy, write an explicit
// `Zeroizing`-aware constructor instead of re-deriving `Clone`.
#[derive(uniffi::Record)]
pub struct PasswordRotation {
    /// Current password (used to decrypt the source space).
    pub old: Vec<u8>,
    /// New password (used to encrypt the dest space). Equal to
    /// `old` for a "preserve verbatim" entry.
    pub new: Vec<u8>,
}

// Audit pass 20: manual redacted `Debug`. The pass-17 F-2 rationale
// above (no `Clone`, keep secrets out of unscrubbed copies) applies
// equally to `Debug` — a derived `{:?}` would print both passwords
// byte-for-byte into logs / panic messages. Redact both fields.
impl std::fmt::Debug for PasswordRotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordRotation")
            .field("old", &"<redacted>")
            .field("new", &"<redacted>")
            .finish()
    }
}

/// In-place compact of the container at `path`, keeping only the
/// spaces unlocked by `passwords`. Anything not unlocked by one of
/// these passwords is permanently destroyed by the rewrite — this
/// includes hidden spaces whose passwords the caller does not list.
/// Use [`change_passwords`] (with `old == new` for each kept space)
/// when the caller wants to preserve hidden spaces without naming
/// them.
///
/// Audit pass 11 R-FFI-1.
///
/// **Concurrency.** `LOCK_EX` is held on `path` for the entire
/// rewrite (Phase 1 read + Phase 2 write + atomic rename). Returns
/// [`HvError::Busy`] if any other process / handle has the file
/// open.
///
/// **The container's security posture is preserved** — the compacted
/// file keeps the source's Argon2 cost and its persisted padding
/// policy. This surface has no way to ask for anything else, and the
/// default it passes used to mean `Argon2Params::DEFAULT` +
/// `PaddingPolicy::None`: a container created HEAVY was silently
/// rewritten at a quarter of the brute-force cost, by a call the host
/// app makes on its own size threshold (audit HV-09). Callers that
/// genuinely want to re-parameterise go through the Rust API's
/// `RepackOptions`.
#[uniffi::export]
pub fn compact_known(path: String, passwords: Vec<Vec<u8>>) -> HvResult<()> {
    let p = PathBuf::from(path);
    // Audit pass 16: scrub each Rust-side password copy on return.
    // We move every inner `Vec<u8>` into a Zeroizing wrapper; the
    // outer `Vec` then drops empty without allocation residue.
    let passwords: Vec<zeroize::Zeroizing<Vec<u8>>> =
        passwords.into_iter().map(zeroize::Zeroizing::new).collect();
    let pw_refs: Vec<&[u8]> = passwords.iter().map(|v| v.as_slice()).collect();
    Container::compact_known(
        &p,
        &pw_refs,
        hidden_volume::container::RepackOptions::default(),
    )?;
    Ok(())
}

/// In-place password rotation for the container at `path`. Each
/// entry in `rotations` is a `(old, new)` pair; `old == new` preserves
/// the space verbatim. Spaces NOT mentioned are **dropped** — to keep
/// a hidden space, include it as a no-op `(p, p)` rotation.
///
/// Audit pass 11 R-FFI-1. See [`compact_known`] for the locking
/// model, the threat-model rationale for the destructive-drop
/// semantics on unlisted spaces, and the preserved Argon2 / padding
/// posture (audit HV-09) — a password change must not also be a
/// downgrade of the KDF the new password is protected by.
#[uniffi::export]
pub fn change_passwords(path: String, rotations: Vec<PasswordRotation>) -> HvResult<()> {
    let p = PathBuf::from(path);
    // Audit pass 16: drain each `PasswordRotation` into a pair of
    // Zeroizing buffers so both old and new keys scrub on return.
    type ZBuf = zeroize::Zeroizing<Vec<u8>>;
    let zeroized: Vec<(ZBuf, ZBuf)> = rotations
        .into_iter()
        .map(|r| (ZBuf::new(r.old), ZBuf::new(r.new)))
        .collect();
    // Build the &[(&[u8], &[u8])] slice the core API expects.
    let mapping: Vec<(&[u8], &[u8])> = zeroized
        .iter()
        .map(|(o, n)| (o.as_slice(), n.as_slice()))
        .collect();
    Container::change_passwords(
        &p,
        &mapping,
        hidden_volume::container::RepackOptions::default(),
    )?;
    Ok(())
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        // `write!` to a String is infallible — the underlying
        // `fmt::Write` impl never fails. Avoids the per-byte
        // intermediate `String` allocation that `format!` does.
        let _ = write!(s, "{byte:02x}");
    }
    s
}

// ---------- Write op ----------

/// One pending change to commit via [`SpaceHandle::commit`]. Mirrors
/// the sync core's `Tx::put` / `Tx::delete` / `Tx::append_log` /
/// `Tx::delete_log` ops.
#[derive(uniffi::Enum, Clone)]
pub enum WriteOp {
    /// KV insert / replace.
    Put {
        /// Namespace tag (1 = SETTINGS, 2 = CONTACTS, 3 = MESSAGE_LOG, …).
        namespace: u8,
        /// Key bytes (≤ MAX_KEY_LEN).
        key: Vec<u8>,
        /// Value bytes (≤ MAX_VALUE_LEN).
        value: Vec<u8>,
    },
    /// KV deletion. No-op if key absent.
    ///
    /// **Kv namespaces only.** Against a namespace holding log entries
    /// the commit fails with `WrongNamespaceKind` — including when the
    /// key is the eight big-endian bytes a `log_id` encodes to. Use
    /// [`Self::DeleteLog`] for those. Until audit HV-04 this went
    /// through and unlinked the record.
    Delete {
        /// Namespace tag.
        namespace: u8,
        /// Key bytes.
        key: Vec<u8>,
    },
    /// Append a log entry into a DataBatch chunk.
    AppendLog {
        /// Namespace tag (typically `MESSAGE_LOG = 3`).
        namespace: u8,
        /// Logical id, unique within namespace. Often a monotonic counter
        /// or a timestamp-encoded `u64`.
        log_id: u64,
        /// Payload bytes (≤ MAX_LOG_PAYLOAD_LEN, default 8 KiB).
        payload: Vec<u8>,
    },
    /// Delete a log entry by logical id. No-op if absent. This removes the
    /// log-id index entry; replacing it with an empty payload does not.
    ///
    /// **Log namespaces only** (audit HV-04). Against a Kv namespace
    /// the commit fails with `WrongNamespaceKind`; it used to succeed,
    /// removing whatever KV entry happened to be keyed on those eight
    /// bytes, because a log delete is stored as a KV delete and so met
    /// neither side's kind check.
    DeleteLog {
        /// Namespace tag; must be a Log-kind namespace.
        namespace: u8,
        /// Logical id to remove.
        log_id: u64,
    },
}

impl core::fmt::Debug for WriteOp {
    /// REDACTED (audit HV-09). The derive printed KEYS, VALUES and log
    /// PAYLOADS — everything the host is storing — across an FFI boundary
    /// whose consumers routinely log the ops they submit. A `{:?}` on a batch
    /// of writes wrote the user's messages into a Kotlin or Swift logcat.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Put {
                namespace,
                key,
                value,
            } => f
                .debug_struct("Put")
                .field("namespace", namespace)
                .field("key_len", &key.len())
                .field("value_len", &value.len())
                .finish(),
            Self::Delete { namespace, key } => f
                .debug_struct("Delete")
                .field("namespace", namespace)
                .field("key_len", &key.len())
                .finish(),
            Self::AppendLog {
                namespace,
                log_id,
                payload,
            } => f
                .debug_struct("AppendLog")
                .field("namespace", namespace)
                .field("log_id", log_id)
                .field("payload_len", &payload.len())
                .finish(),
            Self::DeleteLog { namespace, log_id } => f
                .debug_struct("DeleteLog")
                .field("namespace", namespace)
                .field("log_id", log_id)
                .finish(),
        }
    }
}

// ---------- Log entry record ----------

/// One log entry returned by [`SpaceHandle::iter_log_range`].
#[derive(uniffi::Record, Clone)]
pub struct LogEntry {
    /// Logical id of the entry (the same `log_id` passed to `AppendLog`).
    pub log_id: u64,
    /// Decoded payload bytes.
    pub payload: Vec<u8>,
}

impl core::fmt::Debug for LogEntry {
    /// REDACTED (audit HV-09) — `payload` is a decoded message.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LogEntry")
            .field("log_id", &self.log_id)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

// ---------- Stats record ----------

/// Which post-commit hardening step failed. Mirrors
/// [`hidden_volume::space::HardeningStep`] across UniFFI.
///
/// The step is the whole point of reporting the failure at all: the three
/// protect different things and a host told only "hardening failed" cannot act
/// on any of them (report9 HV-06). Flattening it to a bool on the way across
/// the boundary would have re-created that finding one layer out.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningStepKind {
    /// Padding failed — this commit's SIZE is readable by an adversary who
    /// diffs two snapshots of the file (DESIGN §8).
    Padding,
    /// Churn failed — the slots this commit REUSED stand alone in that same
    /// diff, with no decoy moved beside them (DESIGN §9.1).
    Churn,
    /// The fsync failed — the padding and churn writes are not on the platter
    /// yet. The COMMIT is durable regardless; this is about the masking.
    Sync,
}

impl From<hidden_volume::space::HardeningStep> for HardeningStepKind {
    fn from(s: hidden_volume::space::HardeningStep) -> Self {
        use hidden_volume::space::HardeningStep as S;
        match s {
            S::Padding => Self::Padding,
            S::Churn => Self::Churn,
            S::Sync => Self::Sync,
        }
    }
}

/// A recorded post-commit hardening failure, as
/// [`StatsInfo::hardening_failure`] carries it.
#[derive(uniffi::Record, Debug, Clone)]
pub struct HardeningFailureInfo {
    /// Which of the three steps failed.
    pub step: HardeningStepKind,
    /// Why, rendered. Diagnostic text for a log or a bug report — the host's
    /// decision comes from [`Self::step`], not from parsing this.
    pub message: String,
}

/// Aggregated per-space stats. Parallels [`hidden_volume::space::SpaceStats`]
/// but flattened for FFI.
#[derive(uniffi::Record, Debug, Clone)]
pub struct StatsInfo {
    /// Current monotonic commit counter.
    pub commit_seq: u64,
    /// Number of distinct seqs in the recoverable history.
    pub commit_history_len: u64,
    /// Total chunks owned by this space.
    pub owned_chunk_count: u64,
    /// Total slot count of the underlying container file (excluding
    /// the cleartext header chunk). Together with `owned_chunk_count`
    /// drives the host-app's `compact_known` trigger — see
    /// [`Self::utilization_ratio`].
    pub total_slot_count: u64,
    /// Slots this space has retired and will reuse before it grows the file
    /// again — the decoy pool (DESIGN §9.1). Mirrors
    /// [`hidden_volume::space::SpaceStats::reusable_slot_count`].
    ///
    /// **Read it with [`Self::utilization_ratio`], never without.** The ratio
    /// alone answers the `compact_known` question wrongly in both directions:
    /// a low ratio with a large pool is a container recycling healthily and
    /// wanting no compaction, and compacting it anyway rewrites the whole file
    /// and rotates the `container_id` for nothing; a low ratio with a pool near
    /// zero is the shape that genuinely needs it. Until report10 HV-04 this
    /// number did not cross the boundary at all, so a host had only the half of
    /// the pair that cannot decide on its own.
    ///
    /// It is also the anonymity set a reused slot hides in — see the core
    /// field's docs.
    pub reusable_slot_count: u64,
    /// Sum of per-namespace entry counts.
    pub total_entries: u64,
    /// Per-namespace `(namespace_byte, entry_count)` pairs.
    pub namespace_counts: Vec<NamespaceCount>,
    /// A post-commit hardening failure this space has recorded and the host
    /// has not yet acknowledged, if there is one (report10 HV-04).
    ///
    /// **Sticky.** It is NOT "the last commit's outcome" — a commit that
    /// succeeds completely leaves it exactly as it was. It stays here, poll
    /// after poll, until [`SpaceHandle::acknowledge_hardening_error`] clears
    /// it. That is the only thing that clears it.
    ///
    /// Why it has to work that way: a host learns about this by polling stats,
    /// and the failure it needs to warn about is one commit among many. A field
    /// that reflected only the newest commit would be empty by the time anyone
    /// looked, which is the state this crate shipped in — the write whose
    /// masking was weaker than promised was reported to nobody.
    ///
    /// `Some(_)` does NOT mean the commit failed. The commit is durable; what
    /// is weaker than promised is the masking around it. See
    /// [`HardeningStepKind`] for what each step costs.
    ///
    /// In-memory: a reopened handle starts with `None`.
    pub hardening_failure: Option<HardeningFailureInfo>,
}

impl StatsInfo {
    /// Fraction of the container file's slot grid owned by this
    /// space, in `[0.0, 1.0]`. Mirrors
    /// [`hidden_volume::space::SpaceStats::utilization_ratio`].
    /// Use this value as a `compact_known` trigger — see
    /// `docs/en/guide/operations.md` §3 "Reclaiming disk space".
    /// Returns `0.0` for an empty container.
    ///
    /// **Rust-only.** uniffi exports a `Record`'s *fields*, not its
    /// `impl` methods, so Kotlin/Swift/Python/Ruby callers cannot
    /// invoke this; they compute `owned_chunk_count / total_slot_count`
    /// (guarding the zero case) from the two exported fields. The Dart
    /// binding already provides a `utilizationRatio()` helper that does
    /// exactly this.
    #[must_use]
    pub fn utilization_ratio(&self) -> f64 {
        if self.total_slot_count == 0 {
            0.0
        } else {
            self.owned_chunk_count as f64 / self.total_slot_count as f64
        }
    }
}

/// Flatten a borrowed core record for the boundary. One function, so the sync
/// and async `stats` cannot disagree about what a failure looks like.
fn hardening_failure_info(f: &hidden_volume::space::HardeningFailure) -> HardeningFailureInfo {
    HardeningFailureInfo {
        step: f.step.into(),
        message: f.error.to_string(),
    }
}

/// One row of [`StatsInfo::namespace_counts`].
#[derive(uniffi::Record, Debug, Clone)]
pub struct NamespaceCount {
    /// Namespace byte tag.
    pub namespace: u8,
    /// Number of entries in this namespace.
    pub count: u64,
}

/// What is known about one blocking operation whose future the foreign
/// caller dropped. Mirrors [`hidden_volume_rt::OpOutcome`] across UniFFI.
///
/// The three "it ran" states are deliberately coarse. The value an
/// abandoned operation produced went nowhere — nobody was awaiting it —
/// so what is left to report is the only thing a host app can act on:
/// whether the container may have changed.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationOutcome {
    /// Dispatched, but the closure has not begun. Can still become any
    /// state below.
    Queued,
    /// Executing. **The container may or may not have been modified, and
    /// the operation cannot be undone.** This is the honest answer to "did
    /// my timed-out write land?" while it is still in flight — not an
    /// error, and not a promise that anything was stopped.
    Running,
    /// Abandoned before the closure touched anything: dropped before
    /// dispatch, or the pool thread found the cancel token already fired.
    /// **Proof of no effect** — safe to retry a non-idempotent call.
    NeverStarted,
    /// Ran to completion and returned success.
    Succeeded,
    /// Ran to completion and returned an error. Whether it left partial
    /// state behind is that operation's own contract.
    Failed,
    /// The runtime discarded the task without running it (shutdown), or
    /// the closure panicked. Same uncertainty class as [`Self::Running`],
    /// frozen.
    Lost,
}

impl From<hidden_volume_rt::OpOutcome> for OperationOutcome {
    fn from(o: hidden_volume_rt::OpOutcome) -> Self {
        match o {
            hidden_volume_rt::OpOutcome::Queued => Self::Queued,
            hidden_volume_rt::OpOutcome::Running => Self::Running,
            hidden_volume_rt::OpOutcome::NeverStarted => Self::NeverStarted,
            hidden_volume_rt::OpOutcome::Succeeded => Self::Succeeded,
            hidden_volume_rt::OpOutcome::Failed => Self::Failed,
            hidden_volume_rt::OpOutcome::Lost => Self::Lost,
        }
    }
}

/// One filed abandonment: which operation, and what is known about it as
/// of the [`AsyncSpaceHandle::abandoned_operations`] call that returned it.
///
/// A record whose `outcome` is `Queued` or `Running` is not final — ask
/// again to watch it settle.
#[derive(uniffi::Record, Debug, Clone, Copy)]
pub struct AbandonedOperation {
    /// Identifier, unique within the handle that filed it.
    pub id: u64,
    /// What is known about it now.
    pub outcome: OperationOutcome,
    /// `false` only for [`OperationOutcome::NeverStarted`], which is
    /// backed by a proof. Every other state either did run or may still,
    /// so a host app must reconcile before retrying a non-idempotent call.
    pub may_have_mutated: bool,
    /// Whether `outcome` can still change.
    pub settled: bool,
}

impl From<hidden_volume_rt::AbandonedOp> for AbandonedOperation {
    fn from(op: hidden_volume_rt::AbandonedOp) -> Self {
        Self {
            id: op.id.0,
            outcome: op.outcome.into(),
            may_have_mutated: op.outcome.may_have_mutated(),
            settled: op.outcome.is_settled(),
        }
    }
}

/// Result of a [`SpaceHandle::verify_integrity`] walk.
#[derive(uniffi::Record, Debug, Clone, Copy)]
pub struct IntegrityResult {
    /// Number of namespaces whose Merkle subtree was verified.
    pub namespaces_verified: u64,
    /// Total IndexNode + Commit chunks read and hash-matched.
    pub chunks_verified: u64,
    /// Maximum tree depth observed across namespaces, in levels
    /// (1 = a namespace that fits in one leaf). Not capped by the
    /// format since audit HV-15; 13 at the largest container allowed
    /// (audit HV-16 recomputed the fanout the bound is derived from).
    pub max_depth: u32,
    /// `DataBatch` chunks AEAD-decrypted and `decode_batch`-validated
    /// (log namespaces only). Closes the M2 audit gap (2026-05-10).
    pub data_batches_verified: u64,
}

// ---------- SpaceHandle ----------

/// FFI handle to an opened space inside a container.
///
/// Each `SpaceHandle` owns its `Box<Container>` exclusively (the
/// underlying file flock is `LOCK_EX`). Drop the handle to release
/// the lock and let another process acquire it.
///
/// All methods take `&self` and serialize on an internal `Mutex`.
/// Concurrent calls from foreign threads execute one-at-a-time.
#[derive(uniffi::Object)]
pub struct SpaceHandle {
    inner: Mutex<OwnedSpace>,
}

/// Translate a poisoned mutex into [`HvError::Internal`] rather than
/// panicking. Audit D4: matches `hidden-volume-async`'s pattern; a
/// panic across the FFI boundary would abort the foreign side.
fn poisoned_mutex() -> HvError {
    HvError::Internal("space mutex poisoned by panicked task".into())
}

/// Audit pass 7 (C5): reject `namespace == 0` (`Namespace::RESERVED`)
/// in FFI read paths for symmetry with write paths, which already
/// reject it via `Tx::put`/`Tx::delete`/`Tx::append_log`. Previously
/// reads silently returned `Ok(0)` / `Ok(None)` because no namespace
/// 0 ever exists — confusing for foreign callers expecting a
/// uniform error.
fn check_namespace(byte: u8) -> Result<(), HvError> {
    if byte == 0 {
        return Err(HvError::Malformed("namespace 0 is reserved".into()));
    }
    Ok(())
}

/// Frame KV keys into one byte buffer for the handwritten Dart bindings:
/// `[count u32 LE] ( [len u32 LE][key bytes] )*`.
///
/// Takes keys, not entries. Key enumeration exists for host-app garbage
/// collection, which point-reads any value it actually needs — so the values
/// used to be read off disk, carried through the whole walk and then dropped
/// here (report5 HV-04). `Space::list_keys` never builds them now, and this
/// signature is what keeps a future caller from reintroducing the pair.
fn frame_kv_keys(keys: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = keys.iter().map(|k| 4 + k.len()).sum();
    let mut out = Vec::with_capacity(4 + total);
    out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for k in keys {
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(k);
    }
    out
}

/// Parse the 64-byte FFI encoding of [`SpaceKeys`] (`container_id` ‖
/// `aead_root`). Rejects any other length as [`HvError::Malformed`].
/// Decode a 64-byte `SpaceKeys` from the buffer a foreign caller handed us.
///
/// Takes the `Vec` BY VALUE and wraps it in `Zeroizing` (audit H-03). Every
/// neighbouring FFI entry point already treats incoming secret bytes that way;
/// this one took a borrow of a plain `Vec` that uniffi had allocated, so the
/// 64 bytes of key material stayed in the allocator after the call and could
/// surface in a core dump or a later allocation. Owning it here means there is
/// exactly one place responsible for erasing it, and no call site can forget.
fn decode_space_keys(bytes: Vec<u8>) -> Result<SpaceKeys, HvError> {
    let bytes = zeroize::Zeroizing::new(bytes);
    if bytes.len() != SPACE_KEYS_LEN {
        return Err(HvError::Malformed(
            "SpaceKeys must be exactly 64 bytes".into(),
        ));
    }
    let mut container_id = [0u8; 32];
    let mut aead_root = [0u8; 32];
    container_id.copy_from_slice(&bytes[..32]);
    aead_root.copy_from_slice(&bytes[32..]);
    Ok(SpaceKeys {
        container_id,
        aead_root,
    })
}

// Drop impl for the self-referential pattern lives on
// `hidden_volume_rt::OwnedSpace`.

#[uniffi::export]
impl SpaceHandle {
    /// Create a new container at `path` and bootstrap a fresh space
    /// inside it under `password`. Errors with [`HvError::Busy`] if
    /// another process holds the file flock; with
    /// [`HvError::SpaceAlreadyExists`] if `path` already has a space
    /// for this password (this can happen when re-running create on a
    /// container created earlier).
    ///
    /// `argon`, `initial_garbage_chunks`, and `superblock_replicas`
    /// pin the container's storage parameters at creation. They cannot
    /// be changed in-place later — a `repack` is required.
    #[uniffi::constructor]
    pub fn create(
        path: String,
        password: Vec<u8>,
        argon: ArgonPreset,
        initial_garbage_chunks: u64,
        superblock_replicas: u8,
    ) -> HvResult<std::sync::Arc<Self>> {
        // Audit pass 16: scrub the Rust-side password copy when this
        // function returns. The foreign-side buffer is still owned
        // by the caller and remains their hygiene responsibility
        // (documented at the crate level + on PasswordRotation), but
        // OUR copy now zeroizes deterministically on the normal-return
        // path rather than dropping into uninitialized heap reuse.
        // Under `panic = "abort"` (Cargo.toml [profile.release]) the
        // panic path is process abort — destructors do NOT run on
        // panic in release, so the OS process teardown is the scrub
        // there. Zeroizing still buys us deterministic zeroing before
        // the allocator could reuse the bytes for an unrelated
        // allocation on the success path.
        let password = zeroize::Zeroizing::new(password);
        let p = PathBuf::from(path);
        let opts = ContainerOptions {
            argon2: argon.to_params(),
            initial_garbage_chunks,
            padding_policy: PaddingPolicy::DEFAULT,
            superblock_replicas: superblock_replicas.max(1),
        };
        let container = Box::new(Container::create_with_options(&p, opts)?);
        let inner = OwnedSpace::wrap_create(container, &password)?;
        Ok(std::sync::Arc::new(Self {
            inner: Mutex::new(inner),
        }))
    }

    /// Add a **new parallel space** to an **existing** container at `path`,
    /// keyed by `password`. Unlike [`Self::create`] (which bootstraps a fresh
    /// container file and fails if one already exists), this opens the
    /// container already on disk and creates an additional, deniable space
    /// inside it — the primitive for "hide several identities in one file".
    ///
    /// Errors:
    /// - [`HvError::Io`] / [`HvError::Malformed`] — `path` is not an existing,
    ///   readable container (e.g. the file does not exist — use [`Self::create`]
    ///   for first-run, or it is not a hidden-volume file).
    /// - [`HvError::SpaceAlreadyExists`] — `password` already maps to a space in
    ///   this container (the caller should fall back to [`Self::open`]).
    /// - [`HvError::Busy`] — another process holds the file flock.
    ///
    /// The container's storage parameters (Argon2, padding, replicas) are fixed
    /// at its creation and inherited here; there are no `argon`/options args.
    #[uniffi::constructor]
    pub fn add_space(path: String, password: Vec<u8>) -> HvResult<std::sync::Arc<Self>> {
        // Audit pass 16: scrub our password copy on return — see
        // SpaceHandle::create for the full rationale.
        let password = zeroize::Zeroizing::new(password);
        let p = PathBuf::from(path);
        // Open the EXISTING container (never re-create — that would risk
        // clobbering the file / an existing space), then bootstrap a new space.
        let container = Box::new(Container::open(&p)?);
        let inner = OwnedSpace::wrap_create(container, &password)?;
        Ok(std::sync::Arc::new(Self {
            inner: Mutex::new(inner),
        }))
    }

    /// Open a space in an existing container at `path` using pre-derived
    /// [`SpaceKeys`] (64 opaque bytes from [`Self::space_keys`]) instead of a
    /// password — skips Argon2. This is the **master-space** path: a master
    /// holds its children's keys (inside its own encrypted space) and opens any
    /// child without a per-child password prompt.
    ///
    /// Errors:
    /// - [`HvError::Malformed`] — `keys` is not exactly 64 bytes.
    /// - [`HvError::AuthFailed`] — the keys match no space in this container
    ///   (same indistinguishable path as a wrong password).
    /// - [`HvError::Io`] / [`HvError::Busy`] — see [`Self::open`].
    ///
    /// `keys` is sensitive key material; the caller must keep it inside a
    /// deniable space and never persist or log it in the clear.
    #[uniffi::constructor]
    pub fn open_with_keys(path: String, keys: Vec<u8>) -> HvResult<std::sync::Arc<Self>> {
        // The Vec becomes ours the moment uniffi hands it over, so it is ours
        // to wipe. Without this the space's AEAD root - the value that opens
        // the space without its password - stays in a freed heap block for the
        // rest of the process's life. `decode_space_keys` takes it by value and
        // does the wiping for every caller (audit H-03), so the wrap that used
        // to be spelled out here is no longer needed — and the one path that
        // was MISSING it can no longer exist. The foreign-side copy is the
        // caller's to zero; see the note on `space_keys`.
        let keys = decode_space_keys(keys)?;
        let p = PathBuf::from(path);
        let container = Box::new(Container::open(&p)?);
        // Constant-time scan: the FFI is the deniability-app surface, so equalize
        // the open so unlock latency can't distinguish which space (or none)
        // matched — see OwnedSpace::wrap_open_with_keys_constant_time.
        let inner = OwnedSpace::wrap_open_with_keys_constant_time(container, keys)?;
        Ok(std::sync::Arc::new(Self {
            inner: Mutex::new(inner),
        }))
    }

    /// Export this open space's [`SpaceKeys`] as 64 opaque bytes
    /// (`container_id` ‖ `aead_root`) so a master space can store them and
    /// later reopen this space via [`Self::open_with_keys`] without its
    /// password. **Sensitive** — the per-space decryption root; the caller MUST
    /// keep the bytes inside a deniable space and never log or persist them in
    /// the clear (doing so bypasses Argon2's brute-force protection).
    ///
    /// The returned buffer crosses into the foreign runtime, which copies it
    /// and owns the copy. Rust cannot wipe that copy, so zeroing it is the
    /// caller's job — Kotlin/Swift should overwrite the array as soon as the
    /// keys are stored, and must not let it reach a garbage-collected `String`
    /// or a log line on the way. What this side can wipe, it does: see
    /// [`Self::open_with_keys`].
    pub fn space_keys(&self) -> HvResult<Vec<u8>> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        Ok(g.with_space_mut(|s| {
            let keys = s.space_keys();
            let mut out = Vec::with_capacity(SPACE_KEYS_LEN);
            out.extend_from_slice(&keys.container_id);
            out.extend_from_slice(&keys.aead_root);
            out
        }))
    }

    /// Open an existing container at `path` and unlock the space
    /// identified by `password`. Errors with [`HvError::AuthFailed`]
    /// if no space matches `password` (deniability: do NOT distinguish
    /// "wrong password" from "no such space").
    #[uniffi::constructor]
    pub fn open(path: String, password: Vec<u8>) -> HvResult<std::sync::Arc<Self>> {
        // Audit pass 16: see SpaceHandle::create for the rationale.
        let password = zeroize::Zeroizing::new(password);
        let p = PathBuf::from(path);
        let container = Box::new(Container::open(&p)?);
        // Constant-time scan (deniability) — see open_with_keys / wrap_open_constant_time.
        let inner = OwnedSpace::wrap_open_constant_time(container, &password)?;
        Ok(std::sync::Arc::new(Self {
            inner: Mutex::new(inner),
        }))
    }

    /// Current monotonic commit counter for this space. Increments
    /// once per successful [`Self::commit`]. Host-app uses this as a
    /// rollback-detection anchor (see `docs/en/guide/multi-device.md`).
    pub fn commit_seq(&self) -> HvResult<u64> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        Ok(g.with_space_mut(|s| s.commit_seq()))
    }

    /// Recoverable commit-anchor history — every Superblock seq still
    /// on disk that AEAD-decrypts under this space's key.
    ///
    /// A WINDOW, not the whole history: a writable open retires every era
    /// below `commit_seq() - hidden_volume::ANCHOR_HORIZON`. An anchor absent
    /// from this list is a fork only if it is inside that window; further back
    /// than it, its absence says nothing either way. `docs/en/guide/
    /// multi-device.md` gives the order the three tests must be made in — a
    /// host that checks membership without checking distance first will read
    /// every long-offline device as an adversary.
    pub fn commit_history(&self) -> HvResult<Vec<u64>> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        Ok(g.with_space_mut(|s| s.commit_history().to_vec()))
    }

    /// Override the post-commit padding policy on the open handle.
    /// Audit pass 8 (S1 full): the four [`PaddingPreset`] variants
    /// ARE persisted in the cleartext header at create time and
    /// auto-restored on every `open`, so this call is only needed
    /// when the host-app wants to **change** the policy mid-session
    /// or guard against `F-PAD` (multi-snapshot adversary tampering
    /// with the unauthenticated padding-policy byte; see
    /// `threat-model.md` §4.1). On RO handles
    /// (`Container::open_readonly`) returns
    /// [`hidden_volume::Error::ReadOnly`].
    pub fn set_padding_policy(&self, preset: PaddingPreset) -> HvResult<()> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        g.with_space_mut(|s| s.set_padding_policy(preset.to_policy()))?;
        Ok(())
    }

    /// List namespaces that currently hold at least one entry.
    /// Returns the namespace bytes in ascending order.
    pub fn list_namespaces(&self) -> HvResult<Vec<u8>> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let v = g.with_space_mut(|s| s.list_namespaces())?;
        Ok(v.into_iter().map(|n| n.as_u8()).collect())
    }

    /// Number of entries in `namespace`.
    pub fn count(&self, namespace: u8) -> HvResult<u64> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let n = g.with_space_mut(|s| s.count(Namespace(namespace)))?;
        Ok(n as u64)
    }

    /// Keys of every KV entry in `namespace`, framed into one byte buffer:
    /// `[count u32 LE] ( [len u32 LE][key bytes] )*`. A host app garbage-
    /// collecting stale bookkeeping keys needs enumeration: the KV index is
    /// otherwise write/point-read only, so orphaned keys must be findable to
    /// be deletable.
    ///
    /// **Cost, stated honestly.** This doc used to claim the "same O(N)
    /// index walk as `count`" with "values not decoded" — and it was wrong
    /// on both halves: the call went through `Space::list`, which
    /// materialises every `(key, value)` pair in the namespace before this
    /// function drops the values (report5 HV-04). It now goes through
    /// [`hidden_volume::space::Space::list_keys`], so the *walk* really does
    /// peak at one decoded node the way `count` does.
    ///
    /// What is still O(N) — and cannot not be, for a call whose answer is
    /// "every key" — is the returned buffer, plus the copy uniffi makes of
    /// it. A namespace with a million 32-byte keys is ~36 MB across the FFI
    /// boundary in one allocation. **Use [`Self::kv_keys_page`] on anything
    /// whose size you do not control**; it is the same enumeration with a
    /// bound.
    pub fn kv_keys(&self, namespace: u8) -> HvResult<Vec<u8>> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let keys = g.with_space_mut(|s| s.list_keys(Namespace(namespace)))?;
        Ok(frame_kv_keys(&keys))
    }

    /// One page of [`Self::kv_keys`]: up to `limit` keys strictly greater
    /// than `after`, ascending, in the same
    /// `[count u32 LE] ( [len u32 LE][key bytes] )*` frame.
    ///
    /// Pass `after = None` for the first page, then the last key of the
    /// previous page for each subsequent one; a short page (fewer than
    /// `limit` keys) is the end. `limit = 0` returns an empty frame.
    ///
    /// This is the bounded enumeration primitive — the KV counterpart of
    /// `iter_log_after`, and the one to reach for when the namespace can
    /// grow without bound. As with `iter_log_after`, `limit` bounds the
    /// RESULT and not the chunk reads: each page still walks past the
    /// leaves before its cursor, so this trades a memory ceiling for
    /// repeated I/O rather than making the whole enumeration cheaper.
    pub fn kv_keys_page(
        &self,
        namespace: u8,
        after: Option<Vec<u8>>,
        limit: u32,
    ) -> HvResult<Vec<u8>> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let keys = g.with_space_mut(|s| {
            s.list_keys_after(Namespace(namespace), after.as_deref(), limit as usize)
        })?;
        Ok(frame_kv_keys(&keys))
    }

    /// Read one KV value. Returns `None` if the key is absent.
    pub fn get(&self, namespace: u8, key: Vec<u8>) -> HvResult<Option<Vec<u8>>> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        Ok(g.with_space_mut(|s| s.get(Namespace(namespace), &key))?)
    }

    /// Read one log entry by `log_id`. Returns `None` if not found.
    pub fn read_log(&self, namespace: u8, log_id: u64) -> HvResult<Option<Vec<u8>>> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        Ok(g.with_space_mut(|s| s.read_log(Namespace(namespace), log_id))?)
    }

    /// Half-open range query over a log namespace.
    /// `start` is inclusive (None = unbounded below), `end` is exclusive
    /// (None = unbounded above), result capped at `limit`.
    pub fn iter_log_range(
        &self,
        namespace: u8,
        start: Option<u64>,
        end: Option<u64>,
        limit: u32,
    ) -> HvResult<Vec<LogEntry>> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let v = g.with_space_mut(|s| {
            s.iter_log_range(Namespace(namespace), start, end, limit as usize)
        })?;
        Ok(v.into_iter()
            .map(|(log_id, payload)| LogEntry { log_id, payload })
            .collect())
    }

    /// Apply a batch of write ops atomically as one Tx + commit.
    /// Returns the new `commit_seq`. Empty `ops` → no commit chunk
    /// emitted; returns the current `commit_seq` unchanged.
    pub fn commit(&self, ops: Vec<WriteOp>) -> HvResult<u64> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        g.with_space_mut(|s| -> HvResult<u64> {
            if ops.is_empty() {
                return Ok(s.commit_seq());
            }
            let mut tx = s.begin_tx();
            for op in ops {
                match op {
                    WriteOp::Put {
                        namespace,
                        key,
                        value,
                    } => {
                        tx.put(Namespace(namespace), &key, &value)?;
                    },
                    WriteOp::Delete { namespace, key } => {
                        tx.delete(Namespace(namespace), &key)?;
                    },
                    WriteOp::AppendLog {
                        namespace,
                        log_id,
                        payload,
                    } => {
                        tx.append_log(Namespace(namespace), log_id, &payload)?;
                    },
                    WriteOp::DeleteLog { namespace, log_id } => {
                        tx.delete_log(Namespace(namespace), log_id)?;
                    },
                }
            }
            Ok(tx.commit()?)
        })
    }

    /// Aggregated per-space stats — same shape as the `hv dump-stats`
    /// CLI subcommand and what a host-app's "About this profile" UI
    /// would render.
    pub fn stats(&self) -> HvResult<StatsInfo> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let (s, hardening) = g.with_space_mut(|sp| {
            let s = sp.stats()?;
            // Read INSIDE the same lock hold as the stats walk, so the pair a
            // host acts on describes one moment. Read AFTER it, so a commit
            // that raced us is either wholly in both or wholly in neither.
            let h = sp.last_hardening_error().map(hardening_failure_info);
            Ok::<_, hidden_volume::Error>((s, h))
        })?;
        let total: usize = s.namespace_counts.iter().map(|(_, n)| *n).sum();
        Ok(StatsInfo {
            commit_seq: s.commit_seq,
            commit_history_len: s.commit_history_len as u64,
            owned_chunk_count: s.owned_chunk_count as u64,
            total_slot_count: s.total_slot_count,
            reusable_slot_count: s.reusable_slot_count,
            total_entries: total as u64,
            namespace_counts: s
                .namespace_counts
                .into_iter()
                .map(|(ns, c)| NamespaceCount {
                    namespace: ns.as_u8(),
                    count: c as u64,
                })
                .collect(),
            hardening_failure: hardening,
        })
    }

    /// Acknowledge the sticky [`StatsInfo::hardening_failure`] — "I have shown
    /// this to the person". Clears it; nothing else does (report10 HV-04).
    ///
    /// Idempotent, and safe to call when there is nothing recorded. Call it
    /// after the warning has actually been surfaced, not on the way past: the
    /// record survives commits precisely so it cannot be lost between two
    /// polls, and acknowledging it unread throws away the same warning by hand.
    pub fn acknowledge_hardening_error(&self) -> HvResult<()> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        g.with_space_mut(|sp| {
            sp.acknowledge_hardening_error();
            Ok::<(), hidden_volume::Error>(())
        })?;
        Ok(())
    }

    /// Walk the Merkle tree and verify every link end-to-end.
    /// Errors with [`HvError::IntegrityFailure`] on hash mismatch.
    pub fn verify_integrity(&self) -> HvResult<IntegrityResult> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let r = g.with_space_mut(|s| s.verify_integrity())?;
        Ok(IntegrityResult {
            namespaces_verified: r.namespaces_verified as u64,
            chunks_verified: r.chunks_verified as u64,
            max_depth: r.max_depth as u32,
            data_batches_verified: r.data_batches_verified as u64,
        })
    }

    /// Forward-secrecy maintenance for log namespaces. Scrubs every
    /// owned `DataBatch` chunk that is no longer referenced by a live
    /// KV entry — eliminates the on-disk plaintext of "deleted" log
    /// entries that ordinary `vacuum_orphans` (auto-run on `open`)
    /// leaves untouched. Returns the number of chunks scrubbed.
    ///
    /// Errors with [`HvError::ReadOnly`] on a handle opened via
    /// `open` of a read-only container path. Audit pass 11 R-FFI-1
    /// — previously this maintenance API was Rust-only; mobile
    /// clients had no way to reclaim deleted log entries' bytes.
    ///
    /// **When to call.** After [`SpaceHandle::commit`]s that include
    /// `Delete` ops on a log namespace, OR after any commit that
    /// returned an error (a mid-Phase-0 failure can leave orphan
    /// `DataBatch` chunks). Periodic per-launch is also a fine
    /// policy for "always-on" forward-secrecy of edited messages.
    pub fn vacuum_data_batches(&self) -> HvResult<u64> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let n = g.with_space_mut(|s| s.vacuum_data_batches())?;
        Ok(n as u64)
    }

    /// Run the post-open forward-secrecy scrub that this handle's open
    /// deliberately did not (audit HV-01). Returns the number of orphan
    /// `IndexNode` chunks scrubbed; `0` on a read-only container.
    ///
    /// [`Self::open`] and [`Self::open_with_keys`] take the constant-time
    /// path, because this surface is the deniability app's. That path
    /// equalizes the scan so unlock latency cannot say whether a password
    /// matched — and it used to vacuum inline right afterwards, which
    /// spent milliseconds and disk writes proportional to the space's
    /// history, on the success path only, and handed the answer straight
    /// back to whoever was watching the process while the password was
    /// being typed.
    ///
    /// **Call it away from the unlock.** Not in the line after `open`:
    /// the same work a moment later is still the unlock's work. A
    /// randomised delay, the screen going off, or the first user-initiated
    /// write are all moments the unlock did not cause. Until something
    /// calls this, previous versions of deleted or overwritten values stay
    /// recoverable by anyone who later gets the password and an old
    /// snapshot of the file — the scrub is deferred, not cancelled.
    pub fn vacuum_after_open(&self) -> HvResult<u64> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let n = g.with_space_mut(|s| s.vacuum_after_open())?;
        Ok(n as u64)
    }

    /// Erase every entry in `namespace` via a single Tx of
    /// `Delete { key }` ops. Returns the number of entries erased.
    /// Idempotent: erasing an already-empty namespace is a no-op
    /// returning `0` and produces no commit.
    ///
    /// Audit pass 11 R-FFI-1.
    ///
    /// **Forward-secrecy.** For KV namespaces, the on-disk
    /// plaintext of erased entries lives only in
    /// now-unreachable `IndexNode` chunks; the next auto-vacuum on
    /// `open` (or an explicit Rust-side `vacuum_orphans`) scrubs
    /// them. **For log namespaces, call
    /// [`Self::vacuum_data_batches`] after `erase_namespace`** —
    /// otherwise the original `DataBatch` chunks (still owned, no
    /// longer referenced) keep the plaintext recoverable by anyone
    /// with the password.
    pub fn erase_namespace(&self, namespace: u8) -> HvResult<u64> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let n = g.with_space_mut(|s| s.erase_namespace(Namespace(namespace)))?;
        Ok(n as u64)
    }
}

// =====================================================================
// AsyncSpaceHandle — async sibling of SpaceHandle.
// =====================================================================

use std::sync::Arc;

/// Async FFI handle to an opened space inside a container.
///
/// Functionally identical to [`SpaceHandle`], but every method is
/// `async` and offloads the underlying sync work to
/// [`tokio::task::spawn_blocking`]. This keeps the host-app's async
/// runtime responsive while CPU-heavy operations (Argon2 unlock, AEAD
/// across many chunks, zstd batch compression) run in parallel on
/// pool threads.
///
/// **When to use which.**
///
/// | Use [`SpaceHandle`] when | Use [`AsyncSpaceHandle`] when |
/// |---|---|
/// | Host-app already wraps storage calls in its own scheduler (`Dispatchers.IO`, `DispatchQueue.global`) | Host-app uses Kotlin coroutines or Swift `async/await` natively |
/// | Server-side single-threaded use case | Server-side Tokio-based runtime |
/// | Smallest dep tree (no Tokio) | Concurrent FFI calls from many tasks; async overlap helps |
///
/// **Threading.** uniffi exports each handle as `Arc<Self>`. Internal
/// state (the same [`hidden_volume_rt::OwnedSpace`] used by
/// `SpaceHandle`) is wrapped in `std::sync::Mutex`; concurrent calls
/// serialize on the lock —
/// matching the sync core's "one Tx per Space at a time" invariant.
/// The lock is held only for the duration of the offloaded sync work,
/// then released; other async tasks can proceed between calls.
///
/// **Concurrency model (audit pass 10 L8).** The internal
/// `std::sync::Mutex` is **non-reentrant**, but the FFI surface
/// exposes only closed-form typed methods (no caller-supplied
/// closures), so reentry-deadlock through callback paths is not
/// reachable. Concurrent FFI calls from multiple foreign tasks on
/// the same handle (or its clones) will **serialize** on the lock —
/// each call is a single `spawn_blocking` that acquires, runs the
/// sync op, and releases. That is the intended async-safe behaviour;
/// foreign callers may freely fan out from different coroutines /
/// tasks. Within a single task, sequential `await`s on this handle
/// are also fine — the previous lock is released before `await`
/// returns.
///
/// **Runtime requirement.** The host process must be running a Tokio
/// multi-thread runtime when these methods are awaited. Kotlin /
/// Swift integrators get this automatically via uniffi's tokio
/// bridge (started inside the Rust dylib). Pure-Rust callers must
/// `#[tokio::main]` or wrap in their own runtime.
///
/// # Abandoned calls (audit HV-02)
///
/// `spawn_blocking` cannot interrupt a closure that has started. A
/// foreign caller that times out a `commit` and walks away therefore has
/// no way to know, from the call itself, whether the transaction landed —
/// and retrying a non-idempotent `append_log` on a guess is data
/// corruption.
///
/// Every method here runs through this handle's own
/// [`hidden_volume_rt::OpLedger`], which files each abandoned call and
/// keeps the record after the call is gone.
/// [`Self::abandoned_operations`] is how the host asks. The ledger also
/// admits one blocking operation at a time, so a fan-out of abandoned
/// calls queues as cheap async tasks instead of occupying `spawn_blocking`
/// threads that all end up waiting on one mutex.
///
/// The mechanism shipped with HV-11 and was wired into
/// `hidden-volume-async`; this crate kept calling the plain
/// [`hidden_volume_rt::run_blocking`], which builds a **fresh, unbounded**
/// ledger per call and destroys it on return. Every verdict was filed into
/// an object that then ceased to exist.
#[derive(uniffi::Object)]
pub struct AsyncSpaceHandle {
    // Inner `Arc` is required so each `spawn_blocking` closure can
    // hold its own refcount of the locked space — `&self`-taking
    // async methods cannot move out of the uniffi-provided outer
    // `Arc<Self>`. The sync sibling `SpaceHandle` stores
    // `Mutex<OwnedSpace>` directly (no inner Arc) because its
    // methods do not spawn off-thread.
    inner: Arc<Mutex<OwnedSpace>>,
    /// Admission gate and abandonment ledger, shared by every call on
    /// this handle and by every foreign clone of it (uniffi hands out
    /// `Arc<Self>`). One permit: the handle serialises on `inner` anyway,
    /// and anything above one only moves the queue from tokio's scheduler
    /// onto parked pool threads.
    ops: Arc<OpLedger>,
}

impl AsyncSpaceHandle {
    fn new(inner: OwnedSpace) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(Mutex::new(inner)),
            ops: Arc::new(OpLedger::default()),
        })
    }

    /// Run `f` against the locked space through this handle's ledger.
    ///
    /// `f` receives the cancel token this call was dispatched under.
    /// [`OpLedger::run_cancellable`] fires it when the returned future is
    /// dropped, which is what lets an operation that has not begun refuse
    /// to begin — the plain [`hidden_volume_rt::run_blocking`] this crate
    /// used before creates that token internally, where no closure can
    /// see it.
    ///
    /// **What the token stops, precisely.** Dropped before the permit is
    /// granted: never dispatched. Dropped while queued on the pool: the
    /// ledger's own pre-start check short-circuits it. Dropped after the
    /// closure began: nothing stops it — the closure checks the token once
    /// more before it touches the space, and past that point the sync core
    /// has no cancellation checkpoints of its own, so the operation runs
    /// to completion and is reported rather than pretended away.
    async fn run_op<F, R>(&self, f: F) -> HvResult<R>
    where
        F: FnOnce(&mut Space<'_>, &CancelToken) -> HvResult<R> + Send + 'static,
        R: Send + 'static,
    {
        let inner = self.inner.clone();
        let token = CancelToken::new();
        let closure_token = token.clone();
        self.ops
            .run_cancellable(
                token,
                move || {
                    let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
                    if closure_token.is_cancelled() {
                        // The caller walked away while we waited for the
                        // lock. Nothing in this space has been touched, so
                        // this is a real cancellation, not a report.
                        return Err(HvError::Cancelled);
                    }
                    g.with_space_mut(|s| f(s, &closure_token))
                },
                map_blocking_failure,
            )
            .await
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AsyncSpaceHandle {
    /// Async equivalent of [`SpaceHandle::create`]. Argon2id KDF and
    /// initial container/space writes run on the blocking pool.
    #[uniffi::constructor]
    pub async fn create(
        path: String,
        password: Vec<u8>,
        argon: ArgonPreset,
        initial_garbage_chunks: u64,
        superblock_replicas: u8,
    ) -> HvResult<Arc<Self>> {
        // Audit pass 16: see `SpaceHandle::create` for the rationale.
        // Zeroizing wrapper is moved into the blocking closure and
        // dropped on closure exit, scrubbing the heap buffer
        // deterministically on the normal-return path. (Under
        // `panic = "abort"` the panic path is process abort —
        // destructors do not run on panic; see SpaceHandle::create.)
        let password = zeroize::Zeroizing::new(password);
        let p = PathBuf::from(path);
        let opts = ContainerOptions {
            argon2: argon.to_params(),
            initial_garbage_chunks,
            padding_policy: PaddingPolicy::DEFAULT,
            superblock_replicas: superblock_replicas.max(1),
        };
        let inner = run_blocking(move || -> HvResult<OwnedSpace> {
            let container = Box::new(Container::create_with_options(&p, opts)?);
            Ok(OwnedSpace::wrap_create(container, &password)?)
        })
        .await?;
        Ok(Self::new(inner))
    }

    /// Async equivalent of [`SpaceHandle::open`]. Argon2id KDF and the
    /// O(N) discovery scan run on the blocking pool — does not block
    /// the calling async task.
    #[uniffi::constructor]
    pub async fn open(path: String, password: Vec<u8>) -> HvResult<Arc<Self>> {
        // Audit pass 16: see `SpaceHandle::create` for the rationale.
        let password = zeroize::Zeroizing::new(password);
        let p = PathBuf::from(path);
        let inner = run_blocking(move || -> HvResult<OwnedSpace> {
            let container = Box::new(Container::open(&p)?);
            // Constant-time scan (deniability) — see the sync SpaceHandle::open.
            Ok(OwnedSpace::wrap_open_constant_time(container, &password)?)
        })
        .await?;
        Ok(Self::new(inner))
    }

    /// Async equivalent of [`SpaceHandle::add_space`]. Adds a new parallel,
    /// deniable space to an existing container. Argon2id + the space bootstrap
    /// run on the blocking pool.
    #[uniffi::constructor]
    pub async fn add_space(path: String, password: Vec<u8>) -> HvResult<Arc<Self>> {
        // Audit pass 16: see `SpaceHandle::create` for the rationale.
        let password = zeroize::Zeroizing::new(password);
        let p = PathBuf::from(path);
        let inner = run_blocking(move || -> HvResult<OwnedSpace> {
            let container = Box::new(Container::open(&p)?);
            Ok(OwnedSpace::wrap_create(container, &password)?)
        })
        .await?;
        Ok(Self::new(inner))
    }

    /// Async equivalent of [`SpaceHandle::open_with_keys`]. Opens a space from
    /// pre-derived [`SpaceKeys`] (64 opaque bytes) — the master-space path. The
    /// O(N) discovery scan runs on the blocking pool; no Argon2 (keys are
    /// already derived).
    #[uniffi::constructor]
    pub async fn open_with_keys(path: String, keys: Vec<u8>) -> HvResult<Arc<Self>> {
        // Wiped by `decode_space_keys` — see the sync open_with_keys.
        let keys = decode_space_keys(keys)?;
        let p = PathBuf::from(path);
        let inner = run_blocking(move || -> HvResult<OwnedSpace> {
            let container = Box::new(Container::open(&p)?);
            // Constant-time scan (deniability) — see the sync open_with_keys.
            Ok(OwnedSpace::wrap_open_with_keys_constant_time(
                container, keys,
            )?)
        })
        .await?;
        Ok(Self::new(inner))
    }

    /// Async equivalent of [`SpaceHandle::space_keys`]. Exports this space's
    /// `SpaceKeys` as 64 opaque bytes for a master roster. **Sensitive** — keep
    /// only inside a deniable space, never log.
    pub async fn space_keys(&self) -> HvResult<Vec<u8>> {
        self.run_op(move |s, _cancel| -> HvResult<Vec<u8>> {
            let keys = s.space_keys();
            let mut out = Vec::with_capacity(SPACE_KEYS_LEN);
            out.extend_from_slice(&keys.container_id);
            out.extend_from_slice(&keys.aead_root);
            Ok(out)
        })
        .await
    }

    /// Current monotonic commit counter.
    pub async fn commit_seq(&self) -> HvResult<u64> {
        self.run_op(move |s, _cancel| -> HvResult<u64> { Ok(s.commit_seq()) })
            .await
    }

    /// Recoverable commit-anchor history.
    pub async fn commit_history(&self) -> HvResult<Vec<u64>> {
        self.run_op(move |s, _cancel| -> HvResult<Vec<u64>> { Ok(s.commit_history().to_vec()) })
            .await
    }

    /// Set the post-commit padding policy — see
    /// [`SpaceHandle::set_padding_policy`] for the rationale (audit
    /// pass 7 S1).
    pub async fn set_padding_policy(&self, preset: PaddingPreset) -> HvResult<()> {
        self.run_op(move |s, _cancel| -> HvResult<()> {
            s.set_padding_policy(preset.to_policy())?;
            Ok(())
        })
        .await
    }

    /// List namespaces with at least one entry.
    pub async fn list_namespaces(&self) -> HvResult<Vec<u8>> {
        self.run_op(move |s, _cancel| -> HvResult<Vec<u8>> {
            let v = s.list_namespaces()?;
            Ok(v.into_iter().map(|n| n.as_u8()).collect())
        })
        .await
    }

    /// Number of entries in `namespace`.
    pub async fn count(&self, namespace: u8) -> HvResult<u64> {
        check_namespace(namespace)?;
        self.run_op(move |s, _cancel| -> HvResult<u64> {
            let n = s.count(Namespace(namespace))?;
            Ok(n as u64)
        })
        .await
    }

    /// Keys of every KV entry in `namespace`, framed as in
    /// [`SpaceHandle::kv_keys`]: `[count u32 LE] ( [len u32 LE][key bytes] )*`.
    ///
    /// The async surface claimed one-for-one parity with the sync one and was
    /// missing exactly these two methods, so a caller on this side had no way
    /// to enumerate a namespace at all — and the claim said otherwise
    /// (report14 HV14-L4). The returned buffer is O(total key bytes): use
    /// [`Self::kv_keys_page`] on anything that might be large.
    pub async fn kv_keys(&self, namespace: u8) -> HvResult<Vec<u8>> {
        check_namespace(namespace)?;
        self.run_op(move |s, _cancel| -> HvResult<Vec<u8>> {
            let keys = s.list_keys(Namespace(namespace))?;
            Ok(frame_kv_keys(&keys))
        })
        .await
    }

    /// One page of [`Self::kv_keys`]: up to `limit` keys strictly greater than
    /// `after`, ascending. Same cursor contract as
    /// [`SpaceHandle::kv_keys_page`].
    pub async fn kv_keys_page(
        &self,
        namespace: u8,
        after: Option<Vec<u8>>,
        limit: u32,
    ) -> HvResult<Vec<u8>> {
        check_namespace(namespace)?;
        self.run_op(move |s, _cancel| -> HvResult<Vec<u8>> {
            let keys = s.list_keys_after(Namespace(namespace), after.as_deref(), limit as usize)?;
            Ok(frame_kv_keys(&keys))
        })
        .await
    }

    /// Read one KV value.
    pub async fn get(&self, namespace: u8, key: Vec<u8>) -> HvResult<Option<Vec<u8>>> {
        check_namespace(namespace)?;
        self.run_op(move |s, _cancel| -> HvResult<Option<Vec<u8>>> {
            Ok(s.get(Namespace(namespace), &key)?)
        })
        .await
    }

    /// Read one log entry.
    pub async fn read_log(&self, namespace: u8, log_id: u64) -> HvResult<Option<Vec<u8>>> {
        check_namespace(namespace)?;
        self.run_op(move |s, _cancel| -> HvResult<Option<Vec<u8>>> {
            Ok(s.read_log(Namespace(namespace), log_id)?)
        })
        .await
    }

    /// Half-open range query over a log namespace.
    pub async fn iter_log_range(
        &self,
        namespace: u8,
        start: Option<u64>,
        end: Option<u64>,
        limit: u32,
    ) -> HvResult<Vec<LogEntry>> {
        check_namespace(namespace)?;
        self.run_op(move |s, _cancel| -> HvResult<Vec<LogEntry>> {
            let v = s.iter_log_range(Namespace(namespace), start, end, limit as usize)?;
            Ok(v.into_iter()
                .map(|(log_id, payload)| LogEntry { log_id, payload })
                .collect())
        })
        .await
    }

    /// Apply a batch of write ops as one Tx + commit. Returns the new
    /// `commit_seq`. Empty `ops` → no commit chunk emitted.
    pub async fn commit(&self, ops: Vec<WriteOp>) -> HvResult<u64> {
        self.run_op(move |s, cancel| -> HvResult<u64> {
            if ops.is_empty() {
                return Ok(s.commit_seq());
            }
            let mut tx = s.begin_tx();
            for op in ops {
                // The Tx is pure in-memory accumulation until `commit`,
                // so a caller who walked away mid-assembly can still be
                // honoured here with a provable no-effect abort — the one
                // point in this method where that is true (audit HV-02).
                //
                // Defence in depth, and honestly labelled as such: its
                // trigger window is "the future was dropped after the pool
                // thread entered this loop and before it left", which no
                // deterministic test can force from outside — removing this
                // line leaves the whole suite green. Everything a test *can*
                // pin about abandonment is pinned in
                // `tests/abandoned_operations.rs`.
                cancel.check().map_err(HvError::from)?;
                match op {
                    WriteOp::Put {
                        namespace,
                        key,
                        value,
                    } => {
                        tx.put(Namespace(namespace), &key, &value)?;
                    },
                    WriteOp::Delete { namespace, key } => {
                        tx.delete(Namespace(namespace), &key)?;
                    },
                    WriteOp::AppendLog {
                        namespace,
                        log_id,
                        payload,
                    } => {
                        tx.append_log(Namespace(namespace), log_id, &payload)?;
                    },
                    WriteOp::DeleteLog { namespace, log_id } => {
                        tx.delete_log(Namespace(namespace), log_id)?;
                    },
                }
            }
            Ok(tx.commit()?)
        })
        .await
    }

    /// Aggregated per-space stats.
    pub async fn stats(&self) -> HvResult<StatsInfo> {
        self.run_op(move |s, _cancel| -> HvResult<StatsInfo> {
            let stats = s.stats()?;
            let hardening = s.last_hardening_error().map(hardening_failure_info);
            let total: usize = stats.namespace_counts.iter().map(|(_, n)| *n).sum();
            Ok(StatsInfo {
                commit_seq: stats.commit_seq,
                commit_history_len: stats.commit_history_len as u64,
                owned_chunk_count: stats.owned_chunk_count as u64,
                total_slot_count: stats.total_slot_count,
                reusable_slot_count: stats.reusable_slot_count,
                total_entries: total as u64,
                namespace_counts: stats
                    .namespace_counts
                    .into_iter()
                    .map(|(ns, c)| NamespaceCount {
                        namespace: ns.as_u8(),
                        count: c as u64,
                    })
                    .collect(),
                hardening_failure: hardening,
            })
        })
        .await
    }

    /// Async equivalent of [`SpaceHandle::acknowledge_hardening_error`].
    pub async fn acknowledge_hardening_error(&self) -> HvResult<()> {
        self.run_op(move |s, _cancel| -> HvResult<()> {
            s.acknowledge_hardening_error();
            Ok(())
        })
        .await
    }

    /// Walk the Merkle tree. Errors on hash mismatch.
    pub async fn verify_integrity(&self) -> HvResult<IntegrityResult> {
        self.run_op(move |s, _cancel| -> HvResult<IntegrityResult> {
            let r = s.verify_integrity()?;
            Ok(IntegrityResult {
                namespaces_verified: r.namespaces_verified as u64,
                chunks_verified: r.chunks_verified as u64,
                max_depth: r.max_depth as u32,
                data_batches_verified: r.data_batches_verified as u64,
            })
        })
        .await
    }

    /// Async equivalent of [`SpaceHandle::vacuum_data_batches`].
    /// Audit pass 11 R-FFI-1.
    pub async fn vacuum_data_batches(&self) -> HvResult<u64> {
        self.run_op(move |s, _cancel| -> HvResult<u64> {
            let n = s.vacuum_data_batches()?;
            Ok(n as u64)
        })
        .await
    }

    /// Async equivalent of [`SpaceHandle::vacuum_after_open`] — the
    /// post-open scrub the constant-time open leaves undone (audit
    /// HV-01). Read that method for when to call it, which is the whole
    /// point of it existing separately: **not** on the heels of the
    /// `open` it belongs to.
    pub async fn vacuum_after_open(&self) -> HvResult<u64> {
        self.run_op(move |s, _cancel| -> HvResult<u64> {
            let n = s.vacuum_after_open()?;
            Ok(n as u64)
        })
        .await
    }

    /// Async equivalent of [`SpaceHandle::erase_namespace`].
    /// Audit pass 11 R-FFI-1.
    pub async fn erase_namespace(&self, namespace: u8) -> HvResult<u64> {
        check_namespace(namespace)?;
        self.run_op(move |s, _cancel| -> HvResult<u64> {
            let n = s.erase_namespace(Namespace(namespace))?;
            Ok(n as u64)
        })
        .await
    }
}

/// Reconciliation surface for abandoned calls (audit HV-02).
///
/// Separate `impl` block because these are **not** `async`: they read a
/// lock-free record the ledger already holds and must be answerable from a
/// `finally` / `catch` / `defer` path, which is exactly where a host app
/// discovers it abandoned something.
#[uniffi::export]
impl AsyncSpaceHandle {
    /// Every call on this handle whose future was dropped before it
    /// reported back, oldest first, each with what is known about it **as
    /// of this call**.
    ///
    /// This is the answer to "I timed out a `commit`; did it land?".
    /// Records with [`OperationOutcome::Running`] or `Queued` are not
    /// final — ask again to watch them settle. A record with
    /// `may_have_mutated == false` is a proof of no effect and the only
    /// state under which a non-idempotent call may be retried blind.
    ///
    /// The ledger keeps at most 128 records and drops the oldest beyond
    /// that; see [`Self::forgotten_abandonments`].
    pub fn abandoned_operations(&self) -> Vec<AbandonedOperation> {
        self.ops
            .abandoned_operations()
            .into_iter()
            .map(AbandonedOperation::from)
            .collect()
    }

    /// Drop the records that have reached a final state. Unsettled ones
    /// are kept — they are exactly the ones still worth watching.
    pub fn clear_settled_operations(&self) {
        self.ops.clear_settled_operations();
    }

    /// How many records were evicted because the ledger hit its cap.
    /// Non-zero means this app abandons faster than it reconciles, and
    /// that some uncertain outcomes are no longer reportable.
    pub fn forgotten_abandonments(&self) -> u64 {
        self.ops.forgotten_abandonments()
    }
}

/// Internal helper: spawn `f` on Tokio's blocking pool and translate
/// join errors to [`HvError::Internal`].
///
/// Audit pass 9 (D1): delegates to
/// [`hidden_volume_rt::run_blocking`]. The previous local copy
/// (carried over from pass-8 E6 minimal annotation) is now gone —
/// both `hidden-volume-async` and this crate route through the
/// canonical implementation in `hidden-volume-rt`.
async fn run_blocking<F, R>(f: F) -> HvResult<R>
where
    F: FnOnce() -> HvResult<R> + Send + 'static,
    R: Send + 'static,
{
    hidden_volume_rt::run_blocking(f, map_blocking_failure).await
}

/// The one place a [`hidden_volume_rt::BlockingFailure`] becomes an
/// [`HvError`]. Shared by the plain `run_blocking` above (constructors) and
/// by [`AsyncSpaceHandle::run_op`] (everything else), so the two cannot
/// drift into disagreeing about what a dropped task means.
fn map_blocking_failure(fail: hidden_volume_rt::BlockingFailure) -> HvError {
    match fail {
        hidden_volume_rt::BlockingFailure::Panicked => {
            HvError::Internal("AsyncSpaceHandle blocking task panicked".into())
        },
        hidden_volume_rt::BlockingFailure::Cancelled => {
            // The blocking task was dropped before completing — e.g.
            // the host tore down its Tokio runtime mid-call. This is
            // a cancellation, not a crate bug, so surface the typed
            // `Cancelled` variant rather than `Internal` (audit pass
            // 20).
            HvError::Cancelled
        },
        hidden_volume_rt::BlockingFailure::NotStarted => {
            // Stronger than the above: the closure short-circuited
            // before touching the container, so the foreign caller
            // can retry without first reconciling on-disk state
            // (audit HV-11).
            HvError::Cancelled
        },
    }
}

// ---------- MultiSpaceHandle ----------

/// FFI handle hosting SEVERAL spaces of one container open at once, under the
/// file's single exclusive lock (wraps [`hidden_volume::MultiSpace`]). The
/// storage foundation for a host that runs several identities simultaneously
/// (one network node per identity) over a single deniable container.
///
/// Spaces are addressed by a small `space_id` (`u32`) returned from
/// [`Self::open_space`]. Every method serializes on an internal `Mutex`, so
/// writes to different spaces never overlap — exactly what the single-writer
/// lock requires. Drop the handle to release the lock.
#[derive(uniffi::Object)]
pub struct MultiSpaceHandle {
    inner: Mutex<MultiSpace>,
}

#[uniffi::export]
impl MultiSpaceHandle {
    /// Open an existing container at `path` for multi-space hosting (takes the
    /// file's exclusive lock). Add spaces with [`Self::open_space`].
    #[uniffi::constructor]
    pub fn open(path: String) -> HvResult<std::sync::Arc<Self>> {
        let p = PathBuf::from(path);
        let container = Container::open(&p)?;
        Ok(std::sync::Arc::new(Self {
            inner: Mutex::new(MultiSpace::new(container)),
        }))
    }

    /// Host an existing space by its 64-byte `SpaceKeys` (from
    /// [`SpaceHandle::space_keys`]); returns its `space_id`. `AuthFailed` if no
    /// space matches; `Malformed` if `keys` is not 64 bytes.
    pub fn open_space(&self, keys: Vec<u8>) -> HvResult<u32> {
        let keys = decode_space_keys(keys)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        // Constant-time scan (deniability) — equalizes the discovery scan so
        // hosting a space doesn't leak which one (or none) matched.
        Ok(g.open_space_constant_time(keys)? as u32)
    }

    /// Run the post-open scrub for a hosted space.
    ///
    /// [`Self::open_space`] deliberately does NOT do this inline: the scrub's
    /// duration depends on the space's history, so running it as part of the
    /// constant-time unlock made a successful open measurably longer than a
    /// failed one and undid the equalized scan (audit HV-02).
    ///
    /// The host calls this once unlock is complete — the work still has to
    /// happen, or values a previous session deleted stay decryptable to anyone
    /// who later obtains the password and an old snapshot. Safe to call more
    /// than once; a read-only container answers Ok with nothing done.
    pub fn vacuum_space(&self, id: u32) -> HvResult<()> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        Ok(g.vacuum_hosted(id as usize)?)
    }

    /// Aggregated stats for hosted space `id` — the same shape
    /// [`SpaceHandle::stats`] returns, including the sticky
    /// [`StatsInfo::hardening_failure`].
    ///
    /// This surface had no stats at all, and a host running several identities
    /// over one container is exactly the configuration that gets no other
    /// answer. Its storage layer answered `null` for both the utilization and
    /// the hardening record — and `null` is indistinguishable from "nothing is
    /// wrong". So a masking, churn or sync step that failed after a commit was
    /// never shown to anybody, on the container where it was least visible
    /// (report16 XV-08).
    pub fn stats(&self, id: u32) -> HvResult<StatsInfo> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let (s, hardening) = g.with_space(id as usize, |sp| {
            let s = sp.stats()?;
            // Read inside the same lock hold as the stats walk and AFTER it,
            // for the reason spelled out on `SpaceHandle::stats`: the pair a
            // host acts on has to describe one moment.
            let h = sp.last_hardening_error().map(hardening_failure_info);
            Ok::<_, hidden_volume::Error>((s, h))
        })??;
        let total: usize = s.namespace_counts.iter().map(|(_, n)| *n).sum();
        Ok(StatsInfo {
            commit_seq: s.commit_seq,
            commit_history_len: s.commit_history_len as u64,
            owned_chunk_count: s.owned_chunk_count as u64,
            total_slot_count: s.total_slot_count,
            reusable_slot_count: s.reusable_slot_count,
            total_entries: total as u64,
            namespace_counts: s
                .namespace_counts
                .into_iter()
                .map(|(ns, c)| NamespaceCount {
                    namespace: ns.as_u8(),
                    count: c as u64,
                })
                .collect(),
            hardening_failure: hardening,
        })
    }

    /// Acknowledge the sticky hardening record of hosted space `id` — "I have
    /// shown this to the person". See
    /// [`SpaceHandle::acknowledge_hardening_error`].
    ///
    /// Without it the host had nothing to call, and its storage layer either
    /// did nothing and reported success — clearing its own copy of a warning
    /// with nothing agreeing — or refused every acknowledgement on a
    /// multi-space container (report16 XV-08).
    pub fn acknowledge_hardening_error(&self, id: u32) -> HvResult<()> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        g.with_space(id as usize, |sp| {
            sp.acknowledge_hardening_error();
        })?;
        Ok(())
    }

    /// Number of hosted spaces.
    pub fn space_count(&self) -> HvResult<u32> {
        let g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        Ok(g.len() as u32)
    }

    /// Override the shared container's post-commit padding policy. Applies to
    /// future commits from any hosted space; see [`SpaceHandle::set_padding_policy`].
    pub fn set_padding_policy(&self, preset: PaddingPreset) -> HvResult<()> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        Ok(g.set_padding_policy(preset.to_policy())?)
    }

    /// Export hosted space `id`'s 64-byte `SpaceKeys`. **Sensitive** — keep only
    /// inside a deniable space, never log.
    pub fn space_keys(&self, id: u32) -> HvResult<Vec<u8>> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let keys = g.with_space(id as usize, |s| s.space_keys())?;
        let mut out = Vec::with_capacity(SPACE_KEYS_LEN);
        out.extend_from_slice(&keys.container_id);
        out.extend_from_slice(&keys.aead_root);
        Ok(out)
    }

    /// Apply a batch of write ops atomically to space `id`; returns its new
    /// `commit_seq`. Empty `ops` returns the current seq unchanged.
    pub fn commit(&self, id: u32, ops: Vec<WriteOp>) -> HvResult<u64> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        g.with_space(id as usize, |s| -> HvResult<u64> {
            if ops.is_empty() {
                return Ok(s.commit_seq());
            }
            let mut tx = s.begin_tx();
            for op in ops {
                match op {
                    WriteOp::Put {
                        namespace,
                        key,
                        value,
                    } => tx.put(Namespace(namespace), &key, &value)?,
                    WriteOp::Delete { namespace, key } => tx.delete(Namespace(namespace), &key)?,
                    WriteOp::AppendLog {
                        namespace,
                        log_id,
                        payload,
                    } => tx.append_log(Namespace(namespace), log_id, &payload)?,
                    WriteOp::DeleteLog { namespace, log_id } => {
                        tx.delete_log(Namespace(namespace), log_id)?
                    },
                }
            }
            Ok(tx.commit()?)
        })?
    }

    /// Read a KV value from space `id`, or `None` if absent.
    pub fn get(&self, id: u32, namespace: u8, key: Vec<u8>) -> HvResult<Option<Vec<u8>>> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        Ok(g.with_space(id as usize, |s| s.get(Namespace(namespace), &key))??)
    }

    /// Read one log entry from space `id` by `log_id`; `None` if not found.
    pub fn read_log(&self, id: u32, namespace: u8, log_id: u64) -> HvResult<Option<Vec<u8>>> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        Ok(g.with_space(id as usize, |s| s.read_log(Namespace(namespace), log_id))??)
    }

    /// Half-open `[start, end)` range query over a log namespace of space `id`,
    /// capped at `limit`.
    pub fn iter_log_range(
        &self,
        id: u32,
        namespace: u8,
        start: Option<u64>,
        end: Option<u64>,
        limit: u32,
    ) -> HvResult<Vec<LogEntry>> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let v = g.with_space(id as usize, |s| {
            s.iter_log_range(Namespace(namespace), start, end, limit as usize)
        })??;
        Ok(v.into_iter()
            .map(|(log_id, payload)| LogEntry { log_id, payload })
            .collect())
    }

    /// Number of KV entries in `namespace` of space `id` (O(N) index walk).
    pub fn count(&self, id: u32, namespace: u8) -> HvResult<u64> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let n = g.with_space(id as usize, |s| s.count(Namespace(namespace)))??;
        Ok(n as u64)
    }

    /// Keys of every KV entry in `namespace` of space `id`, framed as in
    /// [`SpaceHandle::kv_keys`]: `[count u32 LE] ( [len u32 LE][key bytes] )*`.
    /// The returned buffer is O(total key bytes) — see
    /// [`SpaceHandle::kv_keys`] for what that means and
    /// [`Self::kv_keys_page`] for the bounded form.
    pub fn kv_keys(&self, id: u32, namespace: u8) -> HvResult<Vec<u8>> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let keys = g.with_space(id as usize, |s| s.list_keys(Namespace(namespace)))??;
        Ok(frame_kv_keys(&keys))
    }

    /// One page of [`Self::kv_keys`] for space `id`: up to `limit` keys
    /// strictly greater than `after`, ascending. Same cursor contract as
    /// [`SpaceHandle::kv_keys_page`].
    pub fn kv_keys_page(
        &self,
        id: u32,
        namespace: u8,
        after: Option<Vec<u8>>,
        limit: u32,
    ) -> HvResult<Vec<u8>> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let keys = g.with_space(id as usize, |s| {
            s.list_keys_after(Namespace(namespace), after.as_deref(), limit as usize)
        })??;
        Ok(frame_kv_keys(&keys))
    }

    /// Current commit sequence of space `id`.
    pub fn commit_seq(&self, id: u32) -> HvResult<u64> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        Ok(g.with_space(id as usize, |s| s.commit_seq())?)
    }

    /// Reclaim DataBatch slots orphaned by replaced/tombstoned records in space
    /// `id` (the deniable edit/delete scrub). Returns slots scrubbed.
    pub fn vacuum_data_batches(&self, id: u32) -> HvResult<u64> {
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let n = g.with_space(id as usize, |s| s.vacuum_data_batches())??;
        Ok(n as u64)
    }
}

#[cfg(test)]
mod tests {

    /// The async surface says it mirrors the sync one. This is what makes that
    /// a fact rather than a sentence.
    ///
    /// It was not one: `kv_keys` and `kv_keys_page` existed on `SpaceHandle`
    /// and on `MultiSpaceHandle` and nowhere else, so an async caller had no
    /// way to enumerate a namespace at all while the doc promised parity
    /// (report14 HV14-L4).
    ///
    /// Read from the source rather than from a hand-kept list: a list is a
    /// third place to forget.
    #[test]
    fn the_async_handle_mirrors_the_sync_one() {
        fn methods(src: &str, impl_header: &str, is_async: bool) -> Vec<String> {
            let mut out = Vec::new();
            let mut rest = src;
            let needle = if is_async { "pub async fn " } else { "pub fn " };
            while let Some(at) = rest.find(impl_header) {
                rest = &rest[at + impl_header.len()..];
                // Up to the next top-level `impl`, which is where this block
                // ends for our purposes.
                let end = rest.find("\nimpl ").unwrap_or(rest.len());
                for line in rest[..end].lines() {
                    let line = line.trim_start();
                    if let Some(tail) = line.strip_prefix(needle) {
                        let name: String = tail
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect();
                        if !name.is_empty() {
                            out.push(name);
                        }
                    }
                }
                rest = &rest[end..];
            }
            out.sort();
            out.dedup();
            out
        }

        let src = include_str!("lib.rs");
        let sync = methods(src, "impl SpaceHandle {", false);
        let asyncs = methods(src, "impl AsyncSpaceHandle {", true);
        assert!(
            sync.len() > 10,
            "the reader found almost nothing — it is broken, not the parity"
        );

        // Constructors differ by design (`create` takes different arguments on
        // the two sides), so what is compared is everything else.
        let missing: Vec<&String> = sync.iter().filter(|name| !asyncs.contains(name)).collect();
        assert!(
            missing.is_empty(),
            "the async handle is missing {missing:?}, and the docs claim parity"
        );
    }
    use super::*;

    fn scratch_path() -> PathBuf {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let p = tmp.path().to_owned();
        drop(tmp);
        p
    }

    /// Each hardening step crosses as itself (report10 HV-04).
    ///
    /// The step is the whole reason the record is a struct and not a flag: a
    /// size leak, a broken deniability and a missing fsync are three different
    /// pieces of news, and a host told the wrong one acts on the wrong thing —
    /// worse than being told nothing. A `From` impl is exactly where that gets
    /// transposed silently, because every arm typechecks against every variant.
    ///
    /// Driven off an exhaustive `match` so a fourth step added upstream fails
    /// to compile here rather than arriving mapped to whatever this list
    /// happened to end at.
    #[test]
    fn every_hardening_step_maps_to_its_own_kind() {
        use hidden_volume::space::HardeningStep as S;
        for step in [S::Padding, S::Churn, S::Sync] {
            let expected = match step {
                S::Padding => HardeningStepKind::Padding,
                S::Churn => HardeningStepKind::Churn,
                S::Sync => HardeningStepKind::Sync,
            };
            let info = hardening_failure_info(&hidden_volume::space::HardeningFailure {
                step,
                error: hidden_volume::Error::ReadOnly,
            });
            assert_eq!(
                info.step, expected,
                "a {step:?} failure crossed the boundary as {:?}",
                info.step
            );
            // The cause travels too, rendered. A host logging "hardening
            // failed" with no reason cannot get a bug report out of it.
            assert!(
                !info.message.is_empty(),
                "the failure crossed with no diagnostic at all"
            );
        }
    }

    #[test]
    fn kv_keys_frames_all_keys_sorted() {
        let path = scratch_path();
        let h = SpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            0,
            1,
        )
        .unwrap();
        h.commit(vec![
            WriteOp::Put {
                namespace: 1,
                key: b"beta".to_vec(),
                value: b"2".to_vec(),
            },
            WriteOp::Put {
                namespace: 1,
                key: b"alpha".to_vec(),
                value: b"1".to_vec(),
            },
        ])
        .unwrap();

        let framed = h.kv_keys(1).unwrap();
        // [count u32 LE] ( [len u32 LE][key] )*
        assert_eq!(&framed[..4], &2u32.to_le_bytes());
        let mut off = 4usize;
        let mut keys = Vec::new();
        for _ in 0..2 {
            let len = u32::from_le_bytes(framed[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            keys.push(framed[off..off + len].to_vec());
            off += len;
        }
        assert_eq!(off, framed.len(), "no trailing bytes");
        assert_eq!(keys, vec![b"alpha".to_vec(), b"beta".to_vec()]);

        // Empty namespace → zero-count frame, not an error.
        let empty = h.kv_keys(2).unwrap();
        assert_eq!(&empty[..], &0u32.to_le_bytes());
    }

    /// Decode the `[count u32 LE] ( [len u32 LE][key] )*` frame both
    /// `kv_keys` and `kv_keys_page` return.
    fn unframe(framed: &[u8]) -> Vec<Vec<u8>> {
        let count = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
        let mut off = 4usize;
        let mut keys = Vec::with_capacity(count);
        for _ in 0..count {
            let len = u32::from_le_bytes(framed[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            keys.push(framed[off..off + len].to_vec());
            off += len;
        }
        assert_eq!(off, framed.len(), "no trailing bytes");
        keys
    }

    #[test]
    fn kv_keys_page_walks_the_namespace_in_bounded_pages() {
        let path = scratch_path();
        let h = SpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            0,
            1,
        )
        .unwrap();
        let expected: Vec<Vec<u8>> = (0..25u8)
            .map(|i| vec![b'k', b'0' + i / 10, b'0' + i % 10])
            .collect();
        h.commit(
            expected
                .iter()
                .map(|k| WriteOp::Put {
                    namespace: 1,
                    key: k.clone(),
                    value: b"v".to_vec(),
                })
                .collect(),
        )
        .unwrap();

        // Follow the cursor the way a host app would; the concatenated
        // pages must reproduce `kv_keys` exactly.
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut cursor: Option<Vec<u8>> = None;
        loop {
            let page = unframe(&h.kv_keys_page(1, cursor.clone(), 4).unwrap());
            if page.is_empty() {
                break;
            }
            assert!(page.len() <= 4, "page exceeded its limit: {}", page.len());
            cursor = Some(page.last().unwrap().clone());
            seen.extend(page);
            assert!(seen.len() <= expected.len(), "cursor is not advancing");
        }
        assert_eq!(seen, expected);
        assert_eq!(seen, unframe(&h.kv_keys(1).unwrap()));

        // `after` is strictly-greater, and `limit = 0` is an empty frame
        // rather than "everything".
        let after_first = unframe(&h.kv_keys_page(1, Some(expected[0].clone()), 2).unwrap());
        assert_eq!(after_first, expected[1..3].to_vec());
        assert!(unframe(&h.kv_keys_page(1, None, 0).unwrap()).is_empty());

        // Reserved namespace is rejected on the paged path too.
        assert!(h.kv_keys_page(0, None, 4).is_err());
    }

    #[test]
    fn create_open_round_trip() {
        let path = scratch_path();

        let h = SpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            0,
            1,
        )
        .unwrap();
        assert_eq!(h.commit_seq().unwrap(), 1);

        h.commit(vec![
            WriteOp::Put {
                namespace: 1,
                key: b"username".to_vec(),
                value: b"alice".to_vec(),
            },
            WriteOp::AppendLog {
                namespace: 3,
                log_id: 1,
                payload: b"hi".to_vec(),
            },
        ])
        .unwrap();

        // commit_seq advanced.
        assert_eq!(h.commit_seq().unwrap(), 2);

        // Read-back through the same handle.
        let v = h.get(1, b"username".to_vec()).unwrap();
        assert_eq!(v.as_deref(), Some(&b"alice"[..]));
        let log = h.read_log(3, 1).unwrap();
        assert_eq!(log.as_deref(), Some(&b"hi"[..]));

        // Drop, reopen, verify durability.
        drop(h);
        let h2 = SpaceHandle::open(path.to_string_lossy().into_owned(), b"pw".to_vec()).unwrap();
        assert_eq!(h2.commit_seq().unwrap(), 2);
        assert_eq!(
            h2.get(1, b"username".to_vec()).unwrap().as_deref(),
            Some(&b"alice"[..])
        );
        // Release the LOCK_EX before re-opening with a different password.
        drop(h2);

        // Wrong password → AuthFailed.
        let bad = SpaceHandle::open(path.to_string_lossy().into_owned(), b"wrong".to_vec());
        match &bad {
            Err(HvError::AuthFailed) => {},
            Err(other) => panic!("expected AuthFailed, got {other:?}"),
            Ok(_) => panic!("expected AuthFailed, got Ok"),
        }
        drop(bad);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn delete_log_through_ffi_removes_record() {
        let path = scratch_path();
        let h = SpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            0,
            1,
        )
        .unwrap();
        h.commit(vec![WriteOp::AppendLog {
            namespace: 3,
            log_id: 41,
            payload: b"payload".to_vec(),
        }])
        .unwrap();
        assert_eq!(h.count(3).unwrap(), 1);

        h.commit(vec![WriteOp::DeleteLog {
            namespace: 3,
            log_id: 41,
        }])
        .unwrap();
        assert_eq!(h.count(3).unwrap(), 0);
        assert!(h.read_log(3, 41).unwrap().is_none());

        drop(h);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn add_space_creates_independent_parallel_space() {
        let path = scratch_path();
        let pstr = || path.to_string_lossy().into_owned();

        // First identity.
        let a = SpaceHandle::create(pstr(), b"p1".to_vec(), ArgonPreset::Min, 0, 1).unwrap();
        a.commit(vec![WriteOp::Put {
            namespace: 1,
            key: b"who".to_vec(),
            value: b"alice".to_vec(),
        }])
        .unwrap();
        drop(a); // release the exclusive flock

        // Second identity in the SAME file via add_space (the multi-identity
        // primitive). A fresh, independent space — its own commit history.
        let b = SpaceHandle::add_space(pstr(), b"p2".to_vec()).unwrap();
        assert_eq!(b.commit_seq().unwrap(), 1, "new space starts fresh");
        b.commit(vec![WriteOp::Put {
            namespace: 1,
            key: b"who".to_vec(),
            value: b"bob".to_vec(),
        }])
        .unwrap();
        drop(b);

        // Each password opens its own space with its own data — the two are
        // deniable parallel spaces, not a shared store.
        let ra = SpaceHandle::open(pstr(), b"p1".to_vec()).unwrap();
        assert_eq!(
            ra.get(1, b"who".to_vec()).unwrap().as_deref(),
            Some(&b"alice"[..])
        );
        drop(ra);
        let rb = SpaceHandle::open(pstr(), b"p2".to_vec()).unwrap();
        assert_eq!(
            rb.get(1, b"who".to_vec()).unwrap().as_deref(),
            Some(&b"bob"[..])
        );
        drop(rb);

        // add_space with an existing space's password → SpaceAlreadyExists, so
        // the host can fall back to `open` (adopt) on collision.
        let dup = SpaceHandle::add_space(pstr(), b"p1".to_vec());
        match &dup {
            Err(HvError::SpaceAlreadyExists) => {},
            Err(other) => panic!("expected SpaceAlreadyExists, got {other:?}"),
            Ok(_) => panic!("expected SpaceAlreadyExists, got Ok"),
        }
        drop(dup);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn multi_space_handle_hosts_two_spaces_at_once() {
        let path = scratch_path();
        let pstr = || path.to_string_lossy().into_owned();

        // Two spaces in one container; capture each space's keys.
        let a = SpaceHandle::create(pstr(), b"pa".to_vec(), ArgonPreset::Min, 0, 1).unwrap();
        let ka = a.space_keys().unwrap();
        drop(a);
        let b = SpaceHandle::add_space(pstr(), b"pb".to_vec()).unwrap();
        let kb = b.space_keys().unwrap();
        drop(b); // release the exclusive lock

        // Host BOTH open at once under one handle / one lock.
        let ms = MultiSpaceHandle::open(pstr()).unwrap();
        let ida = ms.open_space(ka).unwrap();
        let idb = ms.open_space(kb).unwrap();
        assert_eq!(ms.space_count().unwrap(), 2);

        // Interleaved writes to both spaces.
        ms.commit(
            ida,
            vec![WriteOp::Put {
                namespace: 1,
                key: b"who".to_vec(),
                value: b"alice".to_vec(),
            }],
        )
        .unwrap();
        ms.commit(
            idb,
            vec![WriteOp::Put {
                namespace: 1,
                key: b"who".to_vec(),
                value: b"bob".to_vec(),
            }],
        )
        .unwrap();

        // Each space reads back only its own data — isolation under one lock.
        assert_eq!(
            ms.get(ida, 1, b"who".to_vec()).unwrap().as_deref(),
            Some(&b"alice"[..])
        );
        assert_eq!(
            ms.get(idb, 1, b"who".to_vec()).unwrap().as_deref(),
            Some(&b"bob"[..])
        );

        // Error paths.
        match ms.open_space(vec![7u8; SPACE_KEYS_LEN]) {
            Err(HvError::AuthFailed) => {},
            other => panic!("expected AuthFailed, got {other:?}"),
        }
        match ms.open_space(vec![0u8; 10]) {
            Err(HvError::Malformed(_)) => {},
            other => panic!("expected Malformed, got {other:?}"),
        }
        match ms.get(99, 1, b"who".to_vec()) {
            Err(HvError::Malformed(_)) => {},
            other => panic!("expected Malformed for unknown id, got {other:?}"),
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn space_keys_round_trip_opens_without_password() {
        let path = scratch_path();
        let pstr = || path.to_string_lossy().into_owned();

        // Create a space (the "child identity"), write data, export its keys.
        let child =
            SpaceHandle::create(pstr(), b"childpw".to_vec(), ArgonPreset::Min, 0, 1).unwrap();
        child
            .commit(vec![WriteOp::Put {
                namespace: 1,
                key: b"who".to_vec(),
                value: b"carol".to_vec(),
            }])
            .unwrap();
        let keys = child.space_keys().unwrap();
        assert_eq!(keys.len(), SPACE_KEYS_LEN, "exported keys are 64 bytes");
        drop(child); // release the exclusive flock

        // The "master" reopens the child via its keys alone — no password.
        let reopened = SpaceHandle::open_with_keys(pstr(), keys.clone()).unwrap();
        assert_eq!(
            reopened.get(1, b"who".to_vec()).unwrap().as_deref(),
            Some(&b"carol"[..]),
            "keys-only open reads the same space"
        );
        // Keys exported here match (deterministic per space).
        assert_eq!(reopened.space_keys().unwrap(), keys);
        drop(reopened);

        // Wrong length → Malformed (not AuthFailed).
        match SpaceHandle::open_with_keys(pstr(), vec![0u8; 10]) {
            Err(HvError::Malformed(_)) => {},
            Err(other) => panic!("expected Malformed, got {other:?}"),
            Ok(_) => panic!("expected Malformed, got Ok"),
        }

        // Well-formed but bogus keys → AuthFailed (indistinguishable from a
        // wrong password — no leak about how many spaces exist).
        match SpaceHandle::open_with_keys(pstr(), vec![7u8; SPACE_KEYS_LEN]) {
            Err(HvError::AuthFailed) => {},
            Err(other) => panic!("expected AuthFailed, got {other:?}"),
            Ok(_) => panic!("expected AuthFailed, got Ok"),
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn header_info_works_no_password() {
        let path = scratch_path();
        let _h = SpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            10,
            1,
        )
        .unwrap();
        drop(_h);

        let info = header_info(path.to_string_lossy().into_owned()).unwrap();
        assert_eq!(info.salt_hex.len(), 64);
        // v3: container_id is no longer in the cleartext header.
        assert!(info.argon_m_cost_kib > 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn iter_log_range_through_ffi() {
        let path = scratch_path();
        let h = SpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            0,
            1,
        )
        .unwrap();

        let ops: Vec<WriteOp> = (1..=20u64)
            .map(|i| WriteOp::AppendLog {
                namespace: 3,
                log_id: i,
                payload: format!("msg{i}").into_bytes(),
            })
            .collect();
        h.commit(ops).unwrap();

        let r = h.iter_log_range(3, Some(5), Some(10), 100).unwrap();
        let ids: Vec<u64> = r.iter().map(|e| e.log_id).collect();
        assert_eq!(ids, vec![5, 6, 7, 8, 9]);
        for entry in &r {
            let want = format!("msg{}", entry.log_id);
            assert_eq!(entry.payload, want.into_bytes());
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn verify_integrity_through_ffi() {
        let path = scratch_path();
        let h = SpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            0,
            1,
        )
        .unwrap();
        h.commit(vec![
            WriteOp::Put {
                namespace: 1,
                key: b"k1".to_vec(),
                value: b"v1".to_vec(),
            },
            WriteOp::Put {
                namespace: 2,
                key: b"k2".to_vec(),
                value: b"v2".to_vec(),
            },
        ])
        .unwrap();

        let r = h.verify_integrity().unwrap();
        assert_eq!(r.namespaces_verified, 2);
        assert!(r.chunks_verified >= 2);

        let stats = h.stats().unwrap();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.commit_seq, 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_commit_is_noop() {
        let path = scratch_path();
        let h = SpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            0,
            1,
        )
        .unwrap();
        let before = h.commit_seq().unwrap();
        let after = h.commit(vec![]).unwrap();
        assert_eq!(before, after);
        let _ = std::fs::remove_file(&path);
    }

    // ---------- Maintenance API smoke (audit pass 11 R-FFI-1) ----------

    /// `erase_namespace` zeros entry count; subsequent `count` is 0.
    /// `vacuum_data_batches` returns the number of scrubbed batch
    /// chunks (≥ 1 here because we erased a log namespace whose
    /// DataBatch is now unreferenced).
    #[test]
    fn erase_namespace_then_vacuum_data_batches() {
        let path = scratch_path();
        let h = SpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            0,
            1,
        )
        .unwrap();
        // Write 5 log entries.
        let ops: Vec<WriteOp> = (1..=5u64)
            .map(|i| WriteOp::AppendLog {
                namespace: 3,
                log_id: i,
                payload: format!("msg{i}").into_bytes(),
            })
            .collect();
        h.commit(ops).unwrap();
        assert_eq!(h.count(3).unwrap(), 5);

        // Erase the entire log namespace.
        let erased = h.erase_namespace(3).unwrap();
        assert_eq!(erased, 5);
        assert_eq!(h.count(3).unwrap(), 0);

        // Vacuum forward-secrecy: the DataBatch chunk is now
        // unreferenced and should be scrubbed.
        let scrubbed = h.vacuum_data_batches().unwrap();
        assert!(scrubbed >= 1, "expected ≥ 1 scrubbed batch, got {scrubbed}");

        // Erase-already-empty is a no-op.
        let again = h.erase_namespace(3).unwrap();
        assert_eq!(again, 0);

        // Idempotent: vacuum again is a no-op.
        let none = h.vacuum_data_batches().unwrap();
        assert_eq!(none, 0);

        drop(h);
        let _ = std::fs::remove_file(&path);
    }

    /// `compact_known` rewrites the file in place dropping spaces
    /// whose passwords aren't supplied. Verifies the FFI front-door
    /// for the same atomic-rewrite-under-source-lock flow added in
    /// pass 11 M1.
    #[test]
    fn compact_known_through_ffi() {
        let path = scratch_path();
        // Two spaces, A + B.
        {
            let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
            let _a = c.create_space(b"a-pw").unwrap();
        }
        {
            let mut c = Container::open(&path).unwrap();
            let _b = c.create_space(b"b-pw").unwrap();
        }

        // Compact, naming only A. B should be destroyed.
        super::compact_known(path.to_string_lossy().into_owned(), vec![b"a-pw".to_vec()]).unwrap();

        // A still openable.
        let h = SpaceHandle::open(path.to_string_lossy().into_owned(), b"a-pw".to_vec()).unwrap();
        drop(h);

        // B no longer openable — AuthFailed (not crash).
        let bad = SpaceHandle::open(path.to_string_lossy().into_owned(), b"b-pw".to_vec());
        match &bad {
            Err(HvError::AuthFailed) => {},
            Err(other) => panic!("expected AuthFailed for dropped space, got {other:?}"),
            Ok(_) => panic!("expected AuthFailed for dropped space, got Ok"),
        }
        drop(bad);

        let _ = std::fs::remove_file(&path);
    }

    /// `change_passwords` rotates one space's password while
    /// preserving another. Smoke for the FFI binding to the core
    /// `Container::change_passwords`.
    #[test]
    fn change_passwords_through_ffi() {
        let path = scratch_path();
        {
            let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
            let _a = c.create_space(b"old-pw").unwrap();
        }
        {
            let mut c = Container::open(&path).unwrap();
            let _other = c.create_space(b"keep-pw").unwrap();
        }

        super::change_passwords(
            path.to_string_lossy().into_owned(),
            vec![
                super::PasswordRotation {
                    old: b"old-pw".to_vec(),
                    new: b"new-pw".to_vec(),
                },
                super::PasswordRotation {
                    old: b"keep-pw".to_vec(),
                    new: b"keep-pw".to_vec(),
                },
            ],
        )
        .unwrap();

        // Old password no longer works.
        let bad = SpaceHandle::open(path.to_string_lossy().into_owned(), b"old-pw".to_vec());
        match &bad {
            Err(HvError::AuthFailed) => {},
            Err(other) => panic!("expected AuthFailed for rotated-away pw, got {other:?}"),
            Ok(_) => panic!("expected AuthFailed for rotated-away pw, got Ok"),
        }
        drop(bad);
        // New password works.
        let h = SpaceHandle::open(path.to_string_lossy().into_owned(), b"new-pw".to_vec()).unwrap();
        drop(h);
        // Untouched password still works.
        let h2 =
            SpaceHandle::open(path.to_string_lossy().into_owned(), b"keep-pw".to_vec()).unwrap();
        drop(h2);

        let _ = std::fs::remove_file(&path);
    }

    /// Concurrent-handle protection: while a `SpaceHandle` is open,
    /// `compact_known` must fail with `Busy` rather than corrupt the
    /// in-progress state. Audit pass 11 M1 surface check via FFI.
    #[test]
    fn compact_known_with_open_handle_returns_busy() {
        let path = scratch_path();
        let h = SpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            0,
            1,
        )
        .unwrap();

        // Handle still open → compact must reject.
        let res = super::compact_known(path.to_string_lossy().into_owned(), vec![b"pw".to_vec()]);
        match res {
            Err(HvError::Busy) => {},
            Err(other) => panic!("expected Busy with open handle, got {other:?}"),
            Ok(()) => panic!("expected Busy with open handle, got Ok"),
        }

        drop(h);
        // Now compact succeeds.
        super::compact_known(path.to_string_lossy().into_owned(), vec![b"pw".to_vec()]).unwrap();

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn container_too_large_maps_to_typed_variant() {
        // Audit pass 20: a caller-actionable core variant must NOT
        // collapse into the `Internal("unknown error variant")`
        // catch-all — FFI hosts need the typed kind + the chunks/cap
        // diagnostic fields.
        let core = hidden_volume::Error::ContainerTooLarge {
            chunks: 16_000_005,
            cap: 16_000_000,
        };
        match HvError::from(core) {
            HvError::ContainerTooLarge { chunks, cap } => {
                assert_eq!(chunks, 16_000_005);
                assert_eq!(cap, 16_000_000);
            },
            other => panic!("expected typed ContainerTooLarge, got {other:?}"),
        }
    }

    // ---- report7 P1: the four variants the boundary used to erase ----
    //
    // Each of these asserts on `HvError`, the type a foreign caller
    // actually receives, and each fails if its variant slides back into
    // the catch-all. They are written one-per-variant on purpose: a
    // single table-driven test would report only the first regression,
    // and these four were lost one at a time, over three separate
    // commits, precisely because nothing named them individually.

    #[test]
    fn unreadable_newer_state_reaches_the_host_as_itself() {
        // Reachable on the main path: orphan cleanup raises it, and the
        // Dart plugin arms deferred cleanup on every open. As
        // `Internal` the host was told its library had a bug on every
        // single open of a container a newer build had touched, and the
        // real answer — upgrade, or open it with the version that wrote
        // it — never arrived.
        match HvError::from(hidden_volume::Error::UnreadableNewerState) {
            HvError::UnreadableNewerState => {},
            HvError::Internal(m) => {
                panic!("erased at the FFI boundary into Internal({m:?}) — the 'library bug' error")
            },
            other => panic!("expected UnreadableNewerState, got {other:?}"),
        }
    }

    #[test]
    fn publish_uncertain_reaches_the_host_as_itself() {
        // Same reachability as above, and the remedy it carries is the
        // one the host cannot guess: REOPEN the container. Reported as
        // `Internal`, a container that lost a publish produced "library
        // bug" on every open, forever.
        match HvError::from(hidden_volume::Error::PublishUncertain("vacuum")) {
            HvError::PublishUncertain(detail) => assert_eq!(detail, "vacuum"),
            HvError::Internal(m) => {
                panic!("erased at the FFI boundary into Internal({m:?}) — the 'library bug' error")
            },
            other => panic!("expected PublishUncertain, got {other:?}"),
        }
    }

    #[test]
    fn rename_durability_uncertain_reaches_the_host_as_itself() {
        // Raised by the rewrite-under-source-lock path, which the
        // EXPORTED compaction and password-change entry points both
        // reach. The distinction it carries is the whole point: the
        // rename APPLIED. After a password change the new passwords are
        // in effect and the old ones are dead. `Internal` says "a bug,
        // and by implication nothing happened" — the opposite, and the
        // caller who believes it retries with a password that no longer
        // opens the container.
        match HvError::from(hidden_volume::Error::RenameVisibleDurabilityUncertain(
            "dir fsync",
        )) {
            HvError::RenameVisibleDurabilityUncertain(detail) => assert_eq!(detail, "dir fsync"),
            HvError::Internal(m) => {
                panic!("erased at the FFI boundary into Internal({m:?}) — the 'library bug' error")
            },
            other => panic!("expected RenameVisibleDurabilityUncertain, got {other:?}"),
        }
    }

    #[test]
    fn rename_content_unverified_reaches_the_host_as_itself() {
        // Added to the core in df50507, which touched the core and not
        // this boundary — so the variant was born already erased. Like
        // its sibling it means the rewrite applied and the OLD container
        // is gone; unlike it, what sits at the path is attacker-chosen,
        // and the remedy is to restore from backup.
        match HvError::from(hidden_volume::Error::RenameVisibleContentUnverified(
            "inode moved",
        )) {
            HvError::RenameVisibleContentUnverified(detail) => assert_eq!(detail, "inode moved"),
            HvError::Internal(m) => {
                panic!("erased at the FFI boundary into Internal({m:?}) — the 'library bug' error")
            },
            other => panic!("expected RenameVisibleContentUnverified, got {other:?}"),
        }
    }

    #[test]
    fn every_core_variant_maps_to_something_other_than_unknown() {
        // The catch-all above used to cite `from_maps_*` unit tests as
        // the thing that kept known variants out of it. No such test
        // existed — there was one, on `ContainerTooLarge`, under another
        // name — and four variants had quietly collected in the
        // catch-all behind that claim.
        //
        // This is that test. `hidden_volume::Error` is `#[non_exhaustive]`
        // so it cannot be enumerated by the compiler; the list is written
        // out instead, and adding a core variant without an arm in
        // `From` fails here with the variant named. Weaker than an
        // exhaustive match and stronger than a comment.
        let core: Vec<hidden_volume::Error> = vec![
            hidden_volume::Error::Io(std::io::Error::other("x")),
            hidden_volume::Error::AuthFailed,
            hidden_volume::Error::UnreadableNewerState,
            hidden_volume::Error::SpaceAlreadyExists,
            hidden_volume::Error::Busy,
            hidden_volume::Error::ReadOnly,
            hidden_volume::Error::RenameVisibleDurabilityUncertain("d"),
            hidden_volume::Error::RenameVisibleContentUnverified("c"),
            hidden_volume::Error::SourceIsNotARegularFile("s"),
            hidden_volume::Error::RenameVisibleAliasesNotRevoked(1),
            hidden_volume::Error::RenameVisibleAliasesUnknown,
            hidden_volume::Error::WouldBlock,
            hidden_volume::Error::PublishUncertain("p"),
            hidden_volume::Error::Malformed("m"),
            hidden_volume::Error::Kdf("k"),
            hidden_volume::Error::Internal("i"),
            hidden_volume::Error::PayloadTooLarge,
            hidden_volume::Error::IndexFull,
            hidden_volume::Error::Compression("z"),
            hidden_volume::Error::Cancelled,
            hidden_volume::Error::WrongNamespaceKind("w"),
            hidden_volume::Error::TooManyNamespaces { limit: 16 },
            hidden_volume::Error::ContainerTooLarge { chunks: 2, cap: 1 },
            hidden_volume::Error::IntegrityFailure {
                detail: "d",
                slot: 7,
            },
        ];

        // `Error::Internal` legitimately maps to `HvError::Internal`, so
        // the catch-all is identified by its message, not by its kind.
        for e in core {
            let described = e.to_string();
            if let HvError::Internal(msg) = HvError::from(e) {
                assert_ne!(
                    msg, "unknown error variant",
                    "core error {described:?} is erased at the FFI boundary"
                );
            }
        }
    }

    #[test]
    fn password_rotation_debug_is_redacted() {
        // Audit pass 20 (mirrors pass-17 F-2 no-Clone rationale): a
        // `{:?}` of a rotation must not print either password.
        let r = PasswordRotation {
            old: b"super-secret-old".to_vec(),
            new: b"super-secret-new".to_vec(),
        };
        let dbg = format!("{r:?}");
        assert!(
            !dbg.contains("super-secret-old"),
            "old password leaked: {dbg}"
        );
        assert!(
            !dbg.contains("super-secret-new"),
            "new password leaked: {dbg}"
        );
        assert!(dbg.contains("redacted"), "expected redaction marker: {dbg}");
    }

    // ---------- Async FFI surface tests ----------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn async_create_open_round_trip() {
        let path = scratch_path();

        let h = AsyncSpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            0,
            1,
        )
        .await
        .unwrap();
        assert_eq!(h.commit_seq().await.unwrap(), 1);

        h.commit(vec![
            WriteOp::Put {
                namespace: 1,
                key: b"username".to_vec(),
                value: b"alice".to_vec(),
            },
            WriteOp::AppendLog {
                namespace: 3,
                log_id: 1,
                payload: b"hi".to_vec(),
            },
        ])
        .await
        .unwrap();
        assert_eq!(h.commit_seq().await.unwrap(), 2);

        let v = h.get(1, b"username".to_vec()).await.unwrap();
        assert_eq!(v.as_deref(), Some(&b"alice"[..]));

        let log = h.read_log(3, 1).await.unwrap();
        assert_eq!(log.as_deref(), Some(&b"hi"[..]));

        // Drop, reopen async, verify durability.
        drop(h);
        let h2 = AsyncSpaceHandle::open(path.to_string_lossy().into_owned(), b"pw".to_vec())
            .await
            .unwrap();
        assert_eq!(h2.commit_seq().await.unwrap(), 2);
        drop(h2);

        // Wrong password → AuthFailed.
        let bad =
            AsyncSpaceHandle::open(path.to_string_lossy().into_owned(), b"wrong".to_vec()).await;
        match &bad {
            Err(HvError::AuthFailed) => {},
            Err(other) => panic!("expected AuthFailed, got {other:?}"),
            Ok(_) => panic!("expected AuthFailed, got Ok"),
        }
        drop(bad);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn async_iter_log_range_through_ffi() {
        let path = scratch_path();
        let h = AsyncSpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            0,
            1,
        )
        .await
        .unwrap();

        let ops: Vec<WriteOp> = (1..=20u64)
            .map(|i| WriteOp::AppendLog {
                namespace: 3,
                log_id: i,
                payload: format!("msg{i}").into_bytes(),
            })
            .collect();
        h.commit(ops).await.unwrap();

        let r = h.iter_log_range(3, Some(5), Some(10), 100).await.unwrap();
        let ids: Vec<u64> = r.iter().map(|e| e.log_id).collect();
        assert_eq!(ids, vec![5, 6, 7, 8, 9]);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn async_verify_integrity_and_stats() {
        let path = scratch_path();
        let h = AsyncSpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            0,
            1,
        )
        .await
        .unwrap();
        h.commit(vec![
            WriteOp::Put {
                namespace: 1,
                key: b"k1".to_vec(),
                value: b"v1".to_vec(),
            },
            WriteOp::Put {
                namespace: 2,
                key: b"k2".to_vec(),
                value: b"v2".to_vec(),
            },
        ])
        .await
        .unwrap();

        let r = h.verify_integrity().await.unwrap();
        assert_eq!(r.namespaces_verified, 2);
        assert!(r.chunks_verified >= 2);

        let s = h.stats().await.unwrap();
        assert_eq!(s.total_entries, 2);
        assert_eq!(s.commit_seq, 2);

        let _ = std::fs::remove_file(&path);
    }

    /// Concurrent FFI calls from many tasks must serialize on the
    /// internal mutex but each finish correctly. This is the headline
    /// reason to ship the async surface.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn async_concurrent_calls_serialize_correctly() {
        let path = scratch_path();
        let h = AsyncSpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            0,
            1,
        )
        .await
        .unwrap();

        // Pre-populate with 50 KV entries.
        let put_ops: Vec<WriteOp> = (0..50u64)
            .map(|i| WriteOp::Put {
                namespace: 1,
                key: format!("k{i:02}").into_bytes(),
                value: format!("v{i:02}").into_bytes(),
            })
            .collect();
        h.commit(put_ops).await.unwrap();

        // Spawn 20 concurrent get tasks against the same handle.
        // The mutex serializes the underlying space access; all reads
        // should succeed and return the right values.
        let mut handles = Vec::new();
        for i in 0..20u64 {
            let h_clone = h.clone();
            handles.push(tokio::spawn(async move {
                let key = format!("k{i:02}");
                let want = format!("v{i:02}");
                let got = h_clone.get(1, key.into_bytes()).await.unwrap();
                assert_eq!(got.as_deref(), Some(want.as_bytes()), "i={i}");
            }));
        }
        for j in handles {
            j.await.unwrap();
        }

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn async_empty_commit_is_noop() {
        let path = scratch_path();
        let h = AsyncSpaceHandle::create(
            path.to_string_lossy().into_owned(),
            b"pw".to_vec(),
            ArgonPreset::Min,
            0,
            1,
        )
        .await
        .unwrap();
        let before = h.commit_seq().await.unwrap();
        let after = h.commit(vec![]).await.unwrap();
        assert_eq!(before, after);
        let _ = std::fs::remove_file(&path);
    }
}
