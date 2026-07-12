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
use hidden_volume::container::ContainerOptions;
use hidden_volume::crypto::SpaceKeys;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use hidden_volume_rt::OwnedSpace;

/// Length of a serialized [`SpaceKeys`] across the FFI: `container_id` (32) ‖
/// `aead_root` (32). These bytes are the per-space decryption root — opaque,
/// sensitive, **never logged**; they live only inside a master space.
const SPACE_KEYS_LEN: usize = 64;

uniffi::setup_scaffolding!();

// ---------- Error mapping ----------

/// FFI-friendly error. One variant per [`hidden_volume::Error`] case.
/// `flat_error` makes uniffi treat this as a flat tagged-union — every
/// variant becomes its own typed exception on the foreign side.
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
    /// Namespace's index has overflowed the 2-level B+ tree.
    #[error("index full")]
    IndexFull,
    /// zstd compression / decompression failure.
    #[error("compression: {0}")]
    Compression(String),
    /// Cooperative cancellation fired (only if a `CancelToken` was passed —
    /// the FFI surface does not currently expose tokens; this can fire
    /// only via internal use).
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
    /// A write would push the container past the open-scan budget
    /// (`MAX_OPEN_SCAN_CHUNKS`). Caller-actionable: shrink
    /// `initial_garbage_chunks`, pick a lighter [`PaddingPreset`], or
    /// partition the container. NOT a crate bug — distinct from
    /// [`HvError::Internal`].
    #[error("container would exceed open-scan budget (slot_count + {extra} > {cap})")]
    ContainerTooLarge {
        /// Slots the failing write would have added.
        extra: u64,
        /// Hard cap (`MAX_OPEN_SCAN_CHUNKS`).
        cap: u64,
    },
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
            E::ContainerTooLarge { extra, cap } => HvError::ContainerTooLarge { extra, cap },
            // `hidden_volume::Error` is `#[non_exhaustive]`, so this
            // catch-all is mandatory. It is a deniability-safe default
            // for any variant added upstream but not yet mapped here —
            // NOT a dumping ground for known variants. When a new core
            // variant is added, add an explicit arm above; the
            // `from_maps_*` unit tests guard the actionable ones.
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
/// model and the threat-model rationale for the destructive-drop
/// semantics on unlisted spaces.
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
#[derive(uniffi::Enum, Debug, Clone)]
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
    DeleteLog {
        /// Namespace tag (typically a Log-kind namespace).
        namespace: u8,
        /// Logical id to remove.
        log_id: u64,
    },
}

// ---------- Log entry record ----------

/// One log entry returned by [`SpaceHandle::iter_log_range`].
#[derive(uniffi::Record, Debug, Clone)]
pub struct LogEntry {
    /// Logical id of the entry (the same `log_id` passed to `AppendLog`).
    pub log_id: u64,
    /// Decoded payload bytes.
    pub payload: Vec<u8>,
}

// ---------- Stats record ----------

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
    /// Sum of per-namespace entry counts.
    pub total_entries: u64,
    /// Per-namespace `(namespace_byte, entry_count)` pairs.
    pub namespace_counts: Vec<NamespaceCount>,
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

/// One row of [`StatsInfo::namespace_counts`].
#[derive(uniffi::Record, Debug, Clone)]
pub struct NamespaceCount {
    /// Namespace byte tag.
    pub namespace: u8,
    /// Number of entries in this namespace.
    pub count: u64,
}

/// Result of a [`SpaceHandle::verify_integrity`] walk.
#[derive(uniffi::Record, Debug, Clone, Copy)]
pub struct IntegrityResult {
    /// Number of namespaces whose Merkle subtree was verified.
    pub namespaces_verified: u64,
    /// Total IndexNode + Commit chunks read and hash-matched.
    pub chunks_verified: u64,
    /// Maximum tree depth observed across namespaces.
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
/// `[count u32 LE] ( [len u32 LE][key bytes] )*`. Values are dropped — key
/// enumeration exists for host-app garbage collection, which point-reads any
/// value it actually needs.
fn frame_kv_keys(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let total: usize = entries.iter().map(|(k, _)| 4 + k.len()).sum();
    let mut out = Vec::with_capacity(4 + total);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (k, _) in entries {
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(k);
    }
    out
}

/// Parse the 64-byte FFI encoding of [`SpaceKeys`] (`container_id` ‖
/// `aead_root`). Rejects any other length as [`HvError::Malformed`].
fn decode_space_keys(bytes: &[u8]) -> Result<SpaceKeys, HvError> {
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
        let keys = decode_space_keys(&keys)?;
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
    /// otherwise write/point-read only, and a namespace's 2-level B+ tree has
    /// a hard entry budget ([`Error::IndexFull`]), so orphaned keys must be
    /// findable to be deletable. Same O(N) index walk as [`Self::count`];
    /// values are not decoded into the buffer.
    pub fn kv_keys(&self, namespace: u8) -> HvResult<Vec<u8>> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let entries = g.with_space_mut(|s| s.list(Namespace(namespace)))?;
        Ok(frame_kv_keys(&entries))
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
        let s = g.with_space_mut(|sp| sp.stats())?;
        let total: usize = s.namespace_counts.iter().map(|(_, n)| *n).sum();
        Ok(StatsInfo {
            commit_seq: s.commit_seq,
            commit_history_len: s.commit_history_len as u64,
            owned_chunk_count: s.owned_chunk_count as u64,
            total_slot_count: s.total_slot_count,
            total_entries: total as u64,
            namespace_counts: s
                .namespace_counts
                .into_iter()
                .map(|(ns, c)| NamespaceCount {
                    namespace: ns.as_u8(),
                    count: c as u64,
                })
                .collect(),
        })
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
#[derive(uniffi::Object)]
pub struct AsyncSpaceHandle {
    // Inner `Arc` is required so each `spawn_blocking` closure can
    // hold its own refcount of the locked space — `&self`-taking
    // async methods cannot move out of the uniffi-provided outer
    // `Arc<Self>`. The sync sibling `SpaceHandle` stores
    // `Mutex<OwnedSpace>` directly (no inner Arc) because its
    // methods do not spawn off-thread.
    inner: Arc<Mutex<OwnedSpace>>,
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
        Ok(Arc::new(Self {
            inner: Arc::new(Mutex::new(inner)),
        }))
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
        Ok(Arc::new(Self {
            inner: Arc::new(Mutex::new(inner)),
        }))
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
        Ok(Arc::new(Self {
            inner: Arc::new(Mutex::new(inner)),
        }))
    }

    /// Async equivalent of [`SpaceHandle::open_with_keys`]. Opens a space from
    /// pre-derived [`SpaceKeys`] (64 opaque bytes) — the master-space path. The
    /// O(N) discovery scan runs on the blocking pool; no Argon2 (keys are
    /// already derived).
    #[uniffi::constructor]
    pub async fn open_with_keys(path: String, keys: Vec<u8>) -> HvResult<Arc<Self>> {
        let keys = decode_space_keys(&keys)?;
        let p = PathBuf::from(path);
        let inner = run_blocking(move || -> HvResult<OwnedSpace> {
            let container = Box::new(Container::open(&p)?);
            // Constant-time scan (deniability) — see the sync open_with_keys.
            Ok(OwnedSpace::wrap_open_with_keys_constant_time(
                container, keys,
            )?)
        })
        .await?;
        Ok(Arc::new(Self {
            inner: Arc::new(Mutex::new(inner)),
        }))
    }

    /// Async equivalent of [`SpaceHandle::space_keys`]. Exports this space's
    /// `SpaceKeys` as 64 opaque bytes for a master roster. **Sensitive** — keep
    /// only inside a deniable space, never log.
    pub async fn space_keys(&self) -> HvResult<Vec<u8>> {
        let inner = self.inner.clone();
        run_blocking(move || -> HvResult<Vec<u8>> {
            let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
            Ok(g.with_space_mut(|s| {
                let keys = s.space_keys();
                let mut out = Vec::with_capacity(SPACE_KEYS_LEN);
                out.extend_from_slice(&keys.container_id);
                out.extend_from_slice(&keys.aead_root);
                out
            }))
        })
        .await
    }

    /// Current monotonic commit counter.
    pub async fn commit_seq(&self) -> HvResult<u64> {
        let inner = self.inner.clone();
        run_blocking(move || -> HvResult<u64> {
            let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
            Ok(g.with_space_mut(|s| s.commit_seq()))
        })
        .await
    }

    /// Recoverable commit-anchor history.
    pub async fn commit_history(&self) -> HvResult<Vec<u64>> {
        let inner = self.inner.clone();
        run_blocking(move || -> HvResult<Vec<u64>> {
            let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
            Ok(g.with_space_mut(|s| s.commit_history().to_vec()))
        })
        .await
    }

    /// Set the post-commit padding policy — see
    /// [`SpaceHandle::set_padding_policy`] for the rationale (audit
    /// pass 7 S1).
    pub async fn set_padding_policy(&self, preset: PaddingPreset) -> HvResult<()> {
        let inner = self.inner.clone();
        run_blocking(move || -> HvResult<()> {
            let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
            g.with_space_mut(|s| s.set_padding_policy(preset.to_policy()))?;
            Ok(())
        })
        .await
    }

    /// List namespaces with at least one entry.
    pub async fn list_namespaces(&self) -> HvResult<Vec<u8>> {
        let inner = self.inner.clone();
        run_blocking(move || -> HvResult<Vec<u8>> {
            let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
            let v = g.with_space_mut(|s| s.list_namespaces())?;
            Ok(v.into_iter().map(|n| n.as_u8()).collect())
        })
        .await
    }

    /// Number of entries in `namespace`.
    pub async fn count(&self, namespace: u8) -> HvResult<u64> {
        check_namespace(namespace)?;
        let inner = self.inner.clone();
        run_blocking(move || -> HvResult<u64> {
            let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
            let n = g.with_space_mut(|s| s.count(Namespace(namespace)))?;
            Ok(n as u64)
        })
        .await
    }

    /// Read one KV value.
    pub async fn get(&self, namespace: u8, key: Vec<u8>) -> HvResult<Option<Vec<u8>>> {
        check_namespace(namespace)?;
        let inner = self.inner.clone();
        run_blocking(move || -> HvResult<Option<Vec<u8>>> {
            let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
            Ok(g.with_space_mut(|s| s.get(Namespace(namespace), &key))?)
        })
        .await
    }

    /// Read one log entry.
    pub async fn read_log(&self, namespace: u8, log_id: u64) -> HvResult<Option<Vec<u8>>> {
        check_namespace(namespace)?;
        let inner = self.inner.clone();
        run_blocking(move || -> HvResult<Option<Vec<u8>>> {
            let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
            Ok(g.with_space_mut(|s| s.read_log(Namespace(namespace), log_id))?)
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
        let inner = self.inner.clone();
        run_blocking(move || -> HvResult<Vec<LogEntry>> {
            let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
            let v = g.with_space_mut(|s| {
                s.iter_log_range(Namespace(namespace), start, end, limit as usize)
            })?;
            Ok(v.into_iter()
                .map(|(log_id, payload)| LogEntry { log_id, payload })
                .collect())
        })
        .await
    }

    /// Apply a batch of write ops as one Tx + commit. Returns the new
    /// `commit_seq`. Empty `ops` → no commit chunk emitted.
    pub async fn commit(&self, ops: Vec<WriteOp>) -> HvResult<u64> {
        let inner = self.inner.clone();
        run_blocking(move || -> HvResult<u64> {
            let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
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
        })
        .await
    }

    /// Aggregated per-space stats.
    pub async fn stats(&self) -> HvResult<StatsInfo> {
        let inner = self.inner.clone();
        run_blocking(move || -> HvResult<StatsInfo> {
            let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
            let s = g.with_space_mut(|sp| sp.stats())?;
            let total: usize = s.namespace_counts.iter().map(|(_, n)| *n).sum();
            Ok(StatsInfo {
                commit_seq: s.commit_seq,
                commit_history_len: s.commit_history_len as u64,
                owned_chunk_count: s.owned_chunk_count as u64,
                total_slot_count: s.total_slot_count,
                total_entries: total as u64,
                namespace_counts: s
                    .namespace_counts
                    .into_iter()
                    .map(|(ns, c)| NamespaceCount {
                        namespace: ns.as_u8(),
                        count: c as u64,
                    })
                    .collect(),
            })
        })
        .await
    }

    /// Walk the Merkle tree. Errors on hash mismatch.
    pub async fn verify_integrity(&self) -> HvResult<IntegrityResult> {
        let inner = self.inner.clone();
        run_blocking(move || -> HvResult<IntegrityResult> {
            let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
            let r = g.with_space_mut(|s| s.verify_integrity())?;
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
        let inner = self.inner.clone();
        run_blocking(move || -> HvResult<u64> {
            let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
            let n = g.with_space_mut(|s| s.vacuum_data_batches())?;
            Ok(n as u64)
        })
        .await
    }

    /// Async equivalent of [`SpaceHandle::erase_namespace`].
    /// Audit pass 11 R-FFI-1.
    pub async fn erase_namespace(&self, namespace: u8) -> HvResult<u64> {
        check_namespace(namespace)?;
        let inner = self.inner.clone();
        run_blocking(move || -> HvResult<u64> {
            let mut g = inner.lock().map_err(|_| poisoned_mutex())?;
            let n = g.with_space_mut(|s| s.erase_namespace(Namespace(namespace)))?;
            Ok(n as u64)
        })
        .await
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
    hidden_volume_rt::run_blocking(f, |fail| match fail {
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
    })
    .await
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
        let keys = decode_space_keys(&keys)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        // Constant-time scan (deniability) — equalizes the discovery scan so
        // hosting a space doesn't leak which one (or none) matched.
        Ok(g.open_space_constant_time(keys)? as u32)
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
    pub fn kv_keys(&self, id: u32, namespace: u8) -> HvResult<Vec<u8>> {
        check_namespace(namespace)?;
        let mut g = self.inner.lock().map_err(|_| poisoned_mutex())?;
        let entries = g.with_space(id as usize, |s| s.list(Namespace(namespace)))??;
        Ok(frame_kv_keys(&entries))
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
    use super::*;

    fn scratch_path() -> PathBuf {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let p = tmp.path().to_owned();
        drop(tmp);
        p
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
        // catch-all — FFI hosts need the typed kind + the extra/cap
        // diagnostic fields.
        let core = hidden_volume::Error::ContainerTooLarge {
            extra: 5,
            cap: 16_000_000,
        };
        match HvError::from(core) {
            HvError::ContainerTooLarge { extra, cap } => {
                assert_eq!(extra, 5);
                assert_eq!(cap, 16_000_000);
            },
            other => panic!("expected typed ContainerTooLarge, got {other:?}"),
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
