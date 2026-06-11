//! Crate-wide error type.
//!
//! IMPORTANT: error variants must NOT leak information that distinguishes
//! "wrong password" from "no such space" — both surface as
//! [`Error::AuthFailed`]. See DESIGN §1 D2.

use thiserror::Error;

/// Convenient `Result` alias defaulting to [`enum@Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Crate-wide error type. Marked `#[non_exhaustive]` so adding new
/// variants in a future minor release is non-breaking — downstream
/// matches MUST include a `_ =>` catch-all arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying I/O error from the filesystem layer.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Generic authentication failure. Used for both "wrong password" and
    /// "this chunk doesn't belong to the space we're opening". Callers MUST
    /// NOT branch differently on these cases (deniability invariant).
    #[error("authentication failed")]
    AuthFailed,

    /// `Container::create_space` was called with a password that already
    /// has a space in this container. Internal-only — never written to
    /// disk, never observable by an adversary holding the file. Distinct
    /// from [`Self::AuthFailed`] only because the user calling
    /// `create_space` already proves they hold the password and so is
    /// not a deniability concern between user and their own app.
    #[error("space already exists for this password")]
    SpaceAlreadyExists,

    /// The container file is already open (locked) by another process
    /// or open file description. Returned by `Container::open` and
    /// `Container::create` when `flock(LOCK_EX | LOCK_NB)` would block.
    /// Retry after the holder closes their handle.
    #[error("container file is locked by another holder")]
    Busy,

    /// Operation requires a writable container, but this handle was
    /// opened via [`crate::Container::open_readonly`]. Reopen with
    /// `Container::open` (which acquires an exclusive lock) to perform
    /// writes. Useful for P2P sync agents that read concurrently with
    /// the writer process.
    #[error("operation requires a writable container handle")]
    ReadOnly,

    /// File too small / truncated / not aligned to chunk boundary.
    #[error("malformed container: {0}")]
    Malformed(&'static str),

    /// KDF failure (parameter validation, OOM, etc.).
    #[error("kdf: {0}")]
    Kdf(&'static str),

    /// Internal invariant violated. Indicates a bug in the crate; should
    /// never trigger for any input from disk.
    #[error("internal invariant: {0}")]
    Internal(&'static str),

    /// Payload exceeds the per-chunk plaintext capacity
    /// ([`crate::chunk::format::PAYLOAD_CAP`], ≈4040 bytes). For
    /// large append-log payloads use `DataBatch` chunking via
    /// `Tx::append_log`, which packs and chunks transparently.
    #[error("payload exceeds chunk capacity")]
    PayloadTooLarge,

    /// A namespace's KV index has grown beyond what the current
    /// 2-level B+ tree can hold (~5000–10000 entries depending on
    /// key/value sizes). For the message log specifically,
    /// `DataBatch` (`append_log`) is the right tool.
    #[error("index full: namespace exceeds 2-level B+ tree capacity")]
    IndexFull,

    /// zstd compression/decompression failure on a DataBatch payload.
    /// Indicates either a malformed batch chunk or a zstd internal error.
    #[error("compression: {0}")]
    Compression(&'static str),

    /// Cooperative cancellation fired during a long-running operation
    /// (open-scan, repack, verify_integrity). Returned only when the
    /// caller passed a [`crate::cancel::CancelToken`] and called
    /// `token.cancel()` from another thread before the operation
    /// completed. Mid-scan state (partial work) is dropped — no
    /// observable side effects on the file.
    #[error("operation cancelled")]
    Cancelled,

    /// A namespace's stored shape is not what the called API
    /// expects. Currently raised by `iter_log_*` / `read_log` when the
    /// namespace is a regular KV namespace (entries don't match the
    /// `(8-byte log_id_key, 8-byte batch_slot_pointer → DataBatch)`
    /// shape that `append_log` produces). Distinct from
    /// [`Error::Malformed`]: this means "wrong API for this
    /// namespace", **not** corruption. `repack` uses this to
    /// auto-classify namespaces — see audit pass 7 (L1).
    #[error("wrong namespace kind: {0}")]
    WrongNamespaceKind(&'static str),

    /// Too many distinct namespaces touched in a single transaction
    /// (cap is `MAX_NAMESPACES_PER_TX` = 16). User-facing — caller
    /// should commit + start a new `Tx`. Distinct from
    /// [`Error::Internal`]: this is an input-driven failure, not a
    /// crate-bug indicator.
    #[error("transaction touches more than {limit} distinct namespaces")]
    TooManyNamespaces {
        /// The cap.
        limit: usize,
    },

    /// A write would push the container past the open-scan budget
    /// ([`crate::MAX_OPEN_SCAN_CHUNKS`]), making the resulting
    /// file un-openable by `Container::open` (which would reject it
    /// with `Error::Malformed` to bound DoS). Audit pass 17 B closed
    /// the symmetry gap: previously the read-side cap could be
    /// tripped by a write-side that happily blew past it.
    ///
    /// Caller-actionable: shrink `initial_garbage_chunks`, pick a less
    /// aggressive [`crate::padding::PaddingPolicy`], or partition the
    /// container.
    #[error("container would exceed open-scan budget (slot_count + {extra} > {cap})")]
    ContainerTooLarge {
        /// Slots that the failing write would have added.
        extra: u64,
        /// Hard cap (`MAX_OPEN_SCAN_CHUNKS`).
        cap: u64,
    },

    /// Hash-chain mismatch during [`crate::Space::verify_integrity`].
    /// AEAD already protects each chunk individually; this variant fires
    /// when a chunk that AEAD-decrypts under our key contains bytes whose
    /// BLAKE3 hash does NOT match the value its parent (Superblock,
    /// CommitPayload, or InternalNode) recorded for it.
    ///
    /// Diagnostic only — no information leak via this error: callers who
    /// reach this code path already hold the password (so deniability
    /// against an outsider with the file is moot).
    #[error("integrity: {detail} at slot {slot}")]
    IntegrityFailure {
        /// Human-readable description of which Merkle link mismatched.
        detail: &'static str,
        /// Slot index where the offending chunk lives.
        slot: u64,
    },
}
