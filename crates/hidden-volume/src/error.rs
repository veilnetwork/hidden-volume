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

    /// A superblock that decrypted under this space's key, carried a HIGHER
    /// `seq` than the era we opened, and could not be parsed by this build.
    ///
    /// The space is READABLE — the open falls back to the newest superblock it
    /// understands, and a corrupt or forged one must not be able to brick a
    /// container. What is refused is anything that would act on that stale
    /// view: `vacuum_orphans` (which deletes what the newer writer wrote) and
    /// `commit_tx` (which forks the space by descending from a superseded
    /// root).
    ///
    /// In practice this means the container was written by a NEWER library.
    /// Upgrade, or open it with the version that wrote it.
    ///
    /// Not a deniability leak: reaching this requires the space key, so the
    /// caller already knows the space exists.
    #[error("this container holds state written by a newer format this build cannot read")]
    UnreadableNewerState,

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

    /// The atomic rewrite's `rename` SUCCEEDED and is visible, but the
    /// parent-directory `fsync` that makes the directory entry survive a crash
    /// did not.
    ///
    /// **The operation applied.** After
    /// [`crate::Container::change_passwords`] this means the new passwords ARE
    /// in effect and the old ones no longer open the container — do not retry
    /// with the old password, and do not treat this as "the rotation failed".
    /// What is unconfirmed is only whether the directory entry survives a power
    /// loss; on ext4/xfs a crash in that window can restore the OLD inode, and
    /// with it the old password or spaces the rewrite removed.
    ///
    /// Rotation is exactly where that matters: someone who rotates because a
    /// password leaked is entitled to know the old one is dead, and silently
    /// returning `Ok` told them so without grounds (audit HV-03).
    ///
    /// The caller's remedy is to fsync the containing directory by whatever
    /// means the platform offers, or to accept the window knowingly.
    #[error("rename is visible but its durability is unconfirmed: {0}")]
    RenameVisibleDurabilityUncertain(&'static str),

    /// The atomic rewrite's `rename` SUCCEEDED, and the file now at that
    /// path is **not the one we wrote**.
    ///
    /// The rewrite pins the temp file's inode before renaming it into
    /// place and re-reads the path's inode after. A mismatch means
    /// something renamed over `path` in the window between the two, so
    /// what a reader will find there is content this library did not
    /// produce — attacker-chosen, in the threat model this check exists
    /// for.
    ///
    /// **The old container is gone either way.** This is not a failed
    /// operation to retry: the rename happened, the previous inode is
    /// unlinked, and the caller's remedy is to restore from backup and
    /// to treat the directory as writable by someone else. Reporting it
    /// as [`Error::Internal`] said the opposite — a crate bug, and by
    /// implication nothing done — which is why it has its own variant
    /// now (report6 P2, sibling of the durability case above).
    #[error("rename is visible but the file at that path is not the one written: {0}")]
    RenameVisibleContentUnverified(&'static str),

    /// The path names something other than a plain file this library can
    /// rewrite in place — a symlink, a FIFO, a device node.
    ///
    /// **Refused BEFORE anything is touched.** A rewrite writes a sibling temp
    /// and renames it over the path, and a rename replaces the LEXICAL name:
    /// given a symlink it replaces the LINK with a new regular file and leaves
    /// the container the link pointed at exactly as it was. So a password
    /// rotation through an alias returned `Ok` while the real container — and
    /// the password someone rotated because it leaked — stayed reachable at the
    /// target path (report16 HV16-H2).
    ///
    /// Resolving the link instead would revoke the right object, but it would
    /// also write into a directory the caller never named and reopen the race
    /// the link itself is. Refusing says what happened; the caller can pass the
    /// resolved path if that is what they meant.
    #[error("path is not a regular file this library can rewrite in place: {0}")]
    SourceIsNotARegularFile(&'static str),

    /// The rewrite landed, and the previous inode is still reachable under
    /// another name.
    ///
    /// A hard link is a second NAME for the same file, not a copy. The rewrite
    /// replaces the name it was given; every other name goes on resolving to
    /// the OLD inode, which still opens with the OLD password and still holds
    /// the spaces this rewrite removed.
    ///
    /// **Not a failure to retry** — the same shape as
    /// [`Self::RenameVisibleDurabilityUncertain`]: the operation is visible at
    /// the path that was named, and what is qualified is how far the revocation
    /// reached. Retrying rewrites the same name again and changes nothing.
    ///
    /// The caller's remedy is to find and remove the other names, or to accept
    /// knowingly that a copy of the pre-rotation container exists. Whoever can
    /// create a link can usually also copy the file, so this is the boundary of
    /// what a path-local rewrite can promise rather than a hole in it — but
    /// promising revocation and delivering it for one name only is what this
    /// variant exists to stop (report16 HV16-M3).
    #[error("rewrite is visible but the old file is still reachable under {0} other name(s)")]
    RenameVisibleAliasesNotRevoked(u64),

    /// A publish got at least one Superblock replica onto the disk and then
    /// failed, so this handle's view of the tree may be one era behind what a
    /// reopen would select.
    ///
    /// **Raised by the publish itself** (report8 H-09). `commit_tx` and the
    /// checkpoint self-heal burn the seq one instruction before the first
    /// replica can reach the disk and adopt the new superblock only after the
    /// final `fsync`; any failure in between used to surface as the raw
    /// [`Self::Io`] of whichever syscall broke. That named the syscall and
    /// misnamed the situation — an I/O error reads as "the write did not
    /// happen", and a caller who believes that retries the same Tx or vacuums
    /// on a root the file has already moved past. The cause is not discarded:
    /// it is parked on [`crate::Space::last_publish_error`].
    ///
    /// Also refused for the DESTRUCTIVE operations. A vacuum walks the tree
    /// this handle believes in and erases everything else — including the
    /// chunks of the era it does not know was published. A later reopen picks
    /// the newer Superblock by seq, and it now points at erased chunks: the
    /// vacuum destroyed a commit that was already visible on disk
    /// (audit HV-01).
    ///
    /// The remedy is to reopen the container. The open scan resolves which era
    /// actually landed, and the reopened handle can vacuum safely.
    ///
    /// Committing is NOT blocked: `commit_tx` already derives the next seq from
    /// `attempted_seq` rather than the published one, so it skips the burnt
    /// number instead of writing a second payload under it.
    #[error("a previous publish may have reached the disk; reopen before {0}")]
    PublishUncertain(&'static str),

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

    /// A namespace's KV index could not be built.
    ///
    /// **This is no longer a capacity limit** (audit HV-15). The index
    /// grows a tree level whenever the level below outgrows one chunk,
    /// so how much a namespace holds is bounded by the container, not
    /// by the index — a full container raises
    /// [`Self::ContainerTooLarge`] instead. What remains here is the
    /// structural guard: a level that would not be narrower than the
    /// one below it, which needs a single child pointer large enough to
    /// fill a chunk on its own and is unreachable through
    /// [`crate::space::index::MAX_KEY_LEN`] (298 bytes at most against
    /// a ≈4040-byte payload).
    ///
    /// Before HV-15 this fired at ~4 000 entries with 64-byte values
    /// and at 79 with 2 KiB values.
    #[error("index full: an index level would not narrow")]
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

    /// A `run` closure asked for another `run` on a handle that shares its
    /// permit, from inside itself.
    ///
    /// The async wrappers admit one operation at a time across a handle and
    /// every clone of it, and the permit is taken before the closure starts.
    /// A nested call therefore waits for a permit its own caller is holding:
    /// a genuine hang that no timeout unwinds, reachable from entirely safe
    /// code. Refusing says so instead.
    ///
    /// There is nothing a nested call could reach that the outer one cannot —
    /// the closure already holds the handle it would ask through — so the fix
    /// on the caller's side is to do the whole job in one closure.
    #[error("reentrant run: this closure already holds the handle's operation permit")]
    ReentrantRun,

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

    /// The container is past the open-scan budget
    /// ([`crate::MAX_OPEN_SCAN_CHUNKS`]) — raised by BOTH sides of the
    /// gate: a write that would push the file over it, and an open of a
    /// file already over it.
    ///
    /// Audit pass 17 B closed the symmetry gap in the CHECK (the write
    /// side could blow past a cap the read side enforced). Audit HV-13
    /// closed it in the ANSWER: the read side used to report
    /// `Error::Malformed` — the corruption error — for a file that is not
    /// corrupt at all. A host meeting one could not tell "this container
    /// is damaged" from "this container is 64 GiB", and those call for
    /// opposite responses: the second one's data is intact and recoverable
    /// by splitting it or by a build with a larger budget, the first one's
    /// is not.
    ///
    /// Caller-actionable. On the write side: shrink
    /// `initial_garbage_chunks`, pick a less aggressive
    /// [`crate::padding::PaddingPolicy`], or partition the container. On
    /// the read side the file needs to be shrunk before this build can
    /// open it — see the operations guide.
    ///
    /// Nothing about this outcome depends on a password: the check runs on
    /// the slot count alone, before any key material is touched, and the
    /// slot count is a property of the file that anyone who can `stat` it
    /// already knows. It is not a deniability signal.
    #[error("container exceeds open-scan budget ({chunks} chunks > cap {cap})")]
    ContainerTooLarge {
        /// The chunk count that tripped the budget: the file's slot count
        /// on the read side, the count the refused write would have
        /// produced on the write side.
        chunks: u64,
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
