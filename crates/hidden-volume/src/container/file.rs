//! Append-only chunk-grid file (DESIGN §2, §6).
//!
//! Invariants enforced here:
//! - Inv-W1: writes go to a fresh slot via `append_slot`. Existing
//!   slots are never rewritten in place; forward-secrecy / orphan
//!   chunks are handled by `scrub_slot` (uniform-random overwrite).
//! - File size is always `(1 + N) * CHUNK_SIZE` (1 for header chunk + N data slots).

use std::fs::{File, OpenOptions};
// `TryLockError` is only consumed on the non-Android branch of
// `try_lock_exclusive` / `try_lock_shared` (audit pass 19 round 6 +
// v1.x Android-flock hardening). On Android we dispatch to
// `android_flock` via libc directly and never construct the std
// error variant — the import would surface as `unused_imports`
// under `-D warnings` (CI `android-cross-check` job caught this
// after the v1.0.0 release push).
#[cfg(not(target_os = "android"))]
use std::fs::TryLockError;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::header::Header;

/// Removes a just-created file unless the creator reaches its success path.
///
/// `ContainerFile::create` opens with `create_new`, so a stub left behind by a
/// mid-create failure does not just waste a few KiB — it makes the path
/// permanently unusable to the caller, whose retry gets `AlreadyExists` on a
/// file they never knowingly made (audit HV-07).
struct UnlinkOnDrop<'a> {
    path: Option<&'a Path>,
}

impl<'a> UnlinkOnDrop<'a> {
    fn arm(path: &'a Path) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for UnlinkOnDrop<'_> {
    fn drop(&mut self) {
        if let Some(path) = self.path {
            // Best-effort: we are already unwinding a failure the caller will
            // see, and a removal error is strictly less informative than it.
            let _ = std::fs::remove_file(path);
        }
    }
}
use crate::crypto::kdf::Argon2Params;
use crate::padding::PaddingPolicy;
use crate::{CHUNK_SIZE, Error, FIRST_SLOT_OFFSET, Result};

/// Acquire exclusive lock on a freshly opened file handle. Maps "would
/// block" (another holder) to [`Error::Busy`]. Uses std's `File::try_lock`
/// (stable since Rust 1.89) — backed by `flock(2)` on Unix and
/// `LockFileEx` on Windows.
///
/// **Android (v1.0 hardening, 2026-05-28).** Stable Rust 1.89's
/// `File::try_lock` returns `Unsupported "try_lock() not supported"`
/// on `target_os = "android"` — pre-v1.0 the workaround was a
/// documented no-op safe only on app-private storage (audit pass 18
/// M4). v1.0 calls `flock(2)` directly via libc instead so cross-
/// process races on `android:process=":subname"` configurations are
/// correctly serialized. The system call is `LOCK_EX | LOCK_NB`,
/// mirroring std's behaviour on other Unix targets; `EWOULDBLOCK`
/// maps to [`Error::Busy`] and other errno values to [`Error::Io`].
///
/// **Filesystems that don't honour `flock(2)`** (some FUSE backends,
/// network filesystems, vfat-on-emulated-storage) still degrade to
/// no-op behaviour the same way they would on a desktop Unix. The
/// host-app's storage choice is the load-bearing contract — see
/// [`docs/en/security/threat-model.md`](../../../../docs/en/security/threat-model.md)
/// §4.2 for the documented set of safe paths (app-private
/// `Context.getFilesDir()` / `getCacheDir()` is recommended; shared
/// / external / MediaStore paths remain out-of-scope).
///
/// **This is the crate's only exclusive-lock dispatcher (audit HV-09).**
/// The third lock site — the tmp-file pin `atomic_rewrite` holds through
/// the rename — used to inline `File::try_lock` behind a
/// `#[cfg(not(target_os = "android"))]`, which is precisely the shape this
/// function exists to stop anyone writing again: on Android that `cfg`
/// meant *no pin at all*, and the comment beside it recorded the gap as a
/// follow-up rather than closing it.
pub(crate) fn try_lock_exclusive(file: &File) -> Result<()> {
    #[cfg(not(target_os = "android"))]
    {
        match file.try_lock() {
            Ok(()) => Ok(()),
            Err(TryLockError::WouldBlock) => Err(Error::Busy),
            Err(TryLockError::Error(io)) => Err(Error::Io(io)),
        }
    }
    #[cfg(target_os = "android")]
    {
        android_flock(file, libc::LOCK_EX | libc::LOCK_NB)
    }
}

/// Acquire shared lock on a freshly opened file handle. Maps "would
/// block" (a writer is active) to [`Error::Busy`]. Same Android
/// contract as [`try_lock_exclusive`] — on Android the lock is now a
/// real `flock(LOCK_SH | LOCK_NB)` via libc (v1.0 hardening).
fn try_lock_shared(file: &File) -> Result<()> {
    #[cfg(not(target_os = "android"))]
    {
        match file.try_lock_shared() {
            Ok(()) => Ok(()),
            Err(TryLockError::WouldBlock) => Err(Error::Busy),
            Err(TryLockError::Error(io)) => Err(Error::Io(io)),
        }
    }
    #[cfg(target_os = "android")]
    {
        android_flock(file, libc::LOCK_SH | libc::LOCK_NB)
    }
}

/// Android-only direct `flock(2)` call. Returns [`Error::Busy`] on
/// `EWOULDBLOCK` (another holder), [`Error::Io`] on any other errno.
/// Released automatically when the [`File`] drops (close-on-fd
/// releases the lock per `flock(2)` semantics).
///
/// **Why direct libc instead of std?** Rust std's `File::try_lock`
/// is `Err(Unsupported)` for `target_os = "android"` — see
/// <https://github.com/rust-lang/rust/blob/master/library/std/src/sys/pal/unix/fs.rs>
/// (the Android branch deliberately surfaces unsupported instead of
/// dispatching to `flock(2)`). The Android kernel does implement
/// BSD-style flock; we just need to bypass std's missing dispatch.
#[cfg(target_os = "android")]
fn android_flock(file: &File, operation: i32) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: `file.as_raw_fd()` returns a valid fd for the lifetime
    // of `file`. `flock(2)` is a thread-safe system call that takes
    // an fd and an operation flag; it returns 0 on success or -1
    // with errno set on failure. We do not retain the fd past this
    // call. The lock is released by the kernel when the fd closes
    // (i.e. when `file` is dropped) — no manual unlock needed.
    let rc = unsafe { libc::flock(file.as_raw_fd(), operation) };
    if rc == 0 {
        return Ok(());
    }
    let errno = std::io::Error::last_os_error();
    if errno.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Err(Error::Busy);
    }
    Err(Error::Io(errno))
}

/// Default number of Superblock replicas written per commit.
/// Resilience: a single torn write or bit flip of the SB chunk is
/// recoverable from any other replica. Cost: 2 extra chunks per commit
/// at the default. Override via
/// [`crate::Container::set_superblock_replicas`].
pub const DEFAULT_SUPERBLOCK_REPLICAS: u8 = 3;

/// File-lock mode held on the underlying [`File`], and with it whether
/// this handle is allowed to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// `flock(LOCK_EX | LOCK_NB)` — exactly one writer; blocks readers
    /// and other writers. Acquired by [`ContainerFile::create`] and
    /// [`ContainerFile::open`]. The only mode that permits writes.
    Exclusive,
    /// `flock(LOCK_EX | LOCK_NB)` like [`LockMode::Exclusive`], but every
    /// write path returns [`Error::ReadOnly`] — including the maintenance
    /// the open paths run on their own initiative (`vacuum_orphans`, the
    /// self-heal checkpoint). Acquired by
    /// [`ContainerFile::open_exclusive_readonly`].
    ///
    /// The combination exists for one job: reading a container that is
    /// about to be REPLACED, where the exclusive lock must be held
    /// unbroken from the first read through the rename, and the source
    /// bytes must survive an abandoned rewrite untouched. See
    /// `atomic_rewrite_under_source_lock` (audit HV-06).
    ExclusiveReadOnly,
    /// `flock(LOCK_SH | LOCK_NB)` — multiple readers may coexist;
    /// blocks any writer. Acquired by [`ContainerFile::open_readonly`].
    /// All `*_slot` and `*_garbage_chunks` write paths return
    /// [`Error::ReadOnly`] in this mode.
    Shared,
}

impl LockMode {
    /// Whether a handle in this mode may modify the file.
    ///
    /// Every write gate in the crate asks THIS rather than comparing
    /// against a specific variant. The comparisons it replaced were all
    /// `== Shared`, which silently reads as "writable" for any mode added
    /// later — and the mode added later is precisely the one whose whole
    /// purpose is that it must not write.
    #[must_use]
    pub fn allows_writes(self) -> bool {
        matches!(self, LockMode::Exclusive)
    }
}

/// Low-level file-handle wrapper holding the cleartext header and slot
/// grid bookkeeping. Public for use by [`super::Container`] and the
/// scan / parse paths in `crate::open`; host-apps should not touch
/// this directly.
#[derive(Debug)]
pub struct ContainerFile {
    file: File,
    /// Parsed cleartext header (v3 layout: salt + Argon2 params).
    /// `pub(crate)` (audit pass 7 S2): the header is part of the
    /// crypto identity; mutating it post-create would silently
    /// invalidate every chunk. v3 #10 removed the `container_id`
    /// field from the cleartext header — it is now per-space
    /// derived from the versioned master key inside
    /// [`crate::crypto::derive::SpaceKeys::from_master`]. External
    /// read access goes through [`crate::Container::header`].
    pub(crate) header: Header,
    /// Total number of data slots currently in the file (does not include
    /// the header chunk).
    slot_count: u64,
    /// Runtime mirror of the post-commit padding policy. **Audit pass
    /// 8 (S1 full)**: preset values (`None`, `BucketGrowth { 64 }`,
    /// `BucketGrowth { 256 }`, `BucketGrowth { 4096 }`) ARE persisted
    /// in the cleartext header (`Argon2Params.version` bits 16..24)
    /// and `Container::open` auto-restores them into this field.
    /// Custom values (`FixedRatio`, non-preset bucket sizes) are
    /// runtime-only — callers must call
    /// [`crate::Container::set_padding_policy`] after every open.
    /// Default is [`PaddingPolicy::None`].
    /// `pub(crate)` — set via [`crate::Container::set_padding_policy`].
    pub(crate) padding_policy: PaddingPolicy,
    /// Runtime-only number of Superblock chunks to write per commit
    /// (≥ 1). Higher values increase resilience to single-chunk
    /// corruption at the cost of write amplification.
    /// `pub(crate)` — set via [`crate::Container::set_superblock_replicas`].
    pub(crate) superblock_replicas: u8,
    /// Which flock kind we hold. Determines whether writes are allowed.
    /// `pub(crate)` — read via [`crate::Container::is_readonly`].
    pub(crate) lock_mode: LockMode,
}

/// fsync the directory holding `path`, surfacing failures.
///
/// The best-effort variant in `container/mod.rs` is right for the rename path;
/// this one is for `create`, where an undurable directory entry means the file
/// may simply not be there after a power loss (audit HV-16).
#[cfg(unix)]
fn fsync_parent_dir_strict(path: &std::path::Path) -> Result<()> {
    #[cfg(test)]
    if create_fsync_should_fail() {
        return Err(Error::Io(std::io::Error::other(
            "test hook: forced parent-dir fsync failure",
        )));
    }
    // `super::parent_dir_for`, not `path.parent()`: a bare file name has an
    // EMPTY parent, not an absent one, and opening "" is ENOENT. Getting this
    // wrong here did not merely skip the fsync — it failed `create` outright
    // and the `UnlinkOnDrop` guard above then removed the container that had
    // already been written (report5 HV-P0).
    let dir = std::fs::File::open(super::parent_dir_for(path))?;
    dir.sync_all()?;
    Ok(())
}

/// Windows has no parent-directory fsync; `CreateFile` durability is handled by
/// the filesystem, so this is a no-op rather than a pretence.
#[cfg(not(unix))]
fn fsync_parent_dir_strict(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

// `unix` as well as `test`: the only thing that reads this switch is the
// `cfg(unix)` half of `fsync_parent_dir_strict`. Windows takes the no-op half,
// where there is no durability step to fail and therefore nothing to arm.
#[cfg(all(test, unix))]
thread_local! {
    /// Test-only switch that makes `create`'s final durability step fail.
    ///
    /// It is the last `?` before the success path, so it stands in for every
    /// failure in the window where the file already exists — the flock, the
    /// CSPRNG, the header write, either fsync. None of those can be provoked
    /// from outside on a file `create_new` just made.
    ///
    /// **Thread-local, not a process-global.** As a `static AtomicBool` it
    /// armed the hook for the WHOLE test binary, and `cargo test` runs the
    /// binary's tests on parallel threads: every unrelated
    /// `Container::create` that happened to land inside the arming test's
    /// window failed with the injected error. That made the suite fail on
    /// roughly three runs in five, on a defect-free tree — a red gate nobody
    /// can read, and a green one nobody should trust. A thread-local reaches
    /// exactly the `create` the arming test calls, and reaches nothing else.
    static CREATE_FSYNC_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(all(test, unix))]
fn create_fsync_should_fail() -> bool {
    CREATE_FSYNC_FAILS.with(std::cell::Cell::get)
}

#[cfg(test)]
thread_local! {
    /// Test-only switch that fails post-commit garbage padding.
    ///
    /// Padding fails for reasons no test can stage on a real filesystem: a
    /// full disk, a quota, the write budget 64 GiB up. Which one does not
    /// matter to what this is armed for — it is the only way to reach the
    /// state where the commit is already durable and the padding step did not
    /// finish, and what happens to the OTHER post-commit obligation in that
    /// state is a security property, not a cleanup detail.
    ///
    /// Thread-local for the reason `CREATE_FSYNC_FAILS` above records at
    /// length: a process-global fires inside whatever unrelated commit a
    /// parallel test thread happens to be running.
    static GARBAGE_APPEND_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arm [`GARBAGE_APPEND_FAILS`] on this thread; restores on drop so a
/// panicking test cannot leak the fault into whatever runs next.
#[cfg(test)]
pub(crate) struct ForcedGarbageAppendFailure;

#[cfg(test)]
impl ForcedGarbageAppendFailure {
    pub(crate) fn arm() -> Self {
        GARBAGE_APPEND_FAILS.with(|c| c.set(true));
        Self
    }
}

#[cfg(test)]
impl Drop for ForcedGarbageAppendFailure {
    fn drop(&mut self) {
        GARBAGE_APPEND_FAILS.with(|c| c.set(false));
    }
}

impl ContainerFile {
    /// Create a new container at `path` with the given Argon2 params.
    /// Errors if the file already exists or `params` are below
    /// [`Argon2Params::MIN`].
    ///
    /// `params` are persisted in the cleartext header (DESIGN §11.1):
    /// the host-app can pick the parameter set appropriate for its
    /// device class (use [`Argon2Params::LIGHT`] on constrained
    /// hardware, [`Argon2Params::HEAVY`] on desktop, or
    /// [`Argon2Params::DEFAULT`] for the mobile baseline).
    pub fn create<P: AsRef<Path>>(path: P, params: Argon2Params) -> Result<Self> {
        params.validate()?;
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create_new(true);
        // Owner-only from the moment it exists. The contents are encrypted, so
        // this is not what protects them — but a deniable container whose
        // EXISTENCE and size any other local user can stat is advertising the
        // one fact the design is built to avoid, and a world-readable file can
        // be copied wholesale for an offline attack at the attacker's leisure.
        // Set through the open flags rather than a chmod afterwards: a mode
        // applied later leaves a window in which the file is already there at
        // 0644 & !umask.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let path = path.as_ref();
        let mut file = opts.open(path)?;
        // From here the file EXISTS, and every step below can fail: the flock,
        // the CSPRNG behind the header, the header write, either fsync. The
        // caller's cleanup only starts once `create` has RETURNED, so a failure
        // in this window left a stub behind with nothing to remove it — and
        // `create_new` means the retry the caller obviously makes next gets
        // AlreadyExists on a path they never knowingly wrote (audit HV-07).
        //
        // Armed now, disarmed only on the success path.
        let mut guard = UnlinkOnDrop::arm(path);
        // Exclusive flock for the file's lifetime — auto-released when
        // `file` (and thus this struct) drops. Prevents concurrent
        // holders from corrupting the append-only chunk grid.
        try_lock_exclusive(&file)?;
        let header = Header::new_random(params)?;
        let first = header.encode_first_chunk()?;
        file.write_all(&first)?;
        file.sync_all()?;
        // fsync the PARENT too (audit HV-16). `sync_all` makes the file's
        // CONTENTS durable; it says nothing about the directory entry that
        // names it. On ext4/xfs/btrfs a power loss right after create could
        // therefore lose the whole container while `Container::create` had
        // already returned Ok — the caller believing it holds a store that no
        // longer exists, having possibly already told the user their identity
        // was created.
        //
        // Propagated, not swallowed: unlike the rename path — where a
        // successful rename is the thing that matters and failing a whole
        // compaction over a directory handle would be worse — a create that
        // cannot be made durable has produced nothing worth keeping, and the
        // caller's error path removes the partial file.
        fsync_parent_dir_strict(path)?;
        guard.disarm();
        Ok(Self {
            file,
            header,
            slot_count: 0,
            padding_policy: PaddingPolicy::None,
            superblock_replicas: DEFAULT_SUPERBLOCK_REPLICAS,
            lock_mode: LockMode::Exclusive,
        })
    }

    /// Open an existing container. Errors with [`Error::Busy`] if the
    /// file is already open in another process or open file description.
    ///
    /// **Trailing partial chunk handling.** If the file size is not
    /// a multiple of `CHUNK_SIZE`, the trailing partial bytes are
    /// silently ignored — they cannot represent a complete AEAD-
    /// protected chunk regardless of content. This makes
    /// `Container::open` robust against crash scenarios where the
    /// filesystem commits a partial block before fsync (`tests/
    /// fault_injection.rs::unaligned_truncation_*`). The file is
    /// not modified by `open`; the partial bytes simply aren't
    /// addressable as a slot. A subsequent `append_slot` will write
    /// past them, and the file size correction happens implicitly on
    /// the first write that crosses a chunk boundary.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        try_lock_exclusive(&file)?;
        let len = file.metadata()?.len();
        if len < CHUNK_SIZE as u64 {
            return Err(Error::Malformed("file shorter than one chunk"));
        }
        let mut first = [0u8; CHUNK_SIZE];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut first)?;
        let header = Header::decode(&first)?;
        // Round down to chunk boundary — trailing partial bytes are
        // not addressable as a slot. See struct doc above.
        let slot_count = (len / CHUNK_SIZE as u64) - 1;
        Ok(Self {
            file,
            header,
            slot_count,
            padding_policy: PaddingPolicy::None,
            superblock_replicas: DEFAULT_SUPERBLOCK_REPLICAS,
            lock_mode: LockMode::Exclusive,
        })
    }

    /// Open an existing container in read-only mode (shared flock).
    /// Multiple readers may coexist; blocks if any writer holds the
    /// exclusive lock. All `*_slot` and `*_garbage_chunks` write paths
    /// return [`Error::ReadOnly`] in this mode.
    ///
    /// **Trailing partial chunk handling.** Same as [`Self::open`]:
    /// trailing partial bytes are silently ignored.
    pub fn open_readonly<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = OpenOptions::new().read(true).open(path)?;
        try_lock_shared(&file)?;
        let len = file.metadata()?.len();
        if len < CHUNK_SIZE as u64 {
            return Err(Error::Malformed("file shorter than one chunk"));
        }
        let mut first = [0u8; CHUNK_SIZE];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut first)?;
        let header = Header::decode(&first)?;
        let slot_count = (len / CHUNK_SIZE as u64) - 1;
        Ok(Self {
            file,
            header,
            slot_count,
            padding_policy: PaddingPolicy::None,
            superblock_replicas: DEFAULT_SUPERBLOCK_REPLICAS,
            lock_mode: LockMode::Shared,
        })
    }

    /// Open an existing container under an EXCLUSIVE flock that refuses
    /// every write — see [`LockMode::ExclusiveReadOnly`] for why both
    /// halves are wanted at once (audit HV-06).
    ///
    /// Same `Error::Busy` semantics as [`Self::open`]: the lock excludes
    /// every other holder, shared or exclusive.
    ///
    /// **Trailing partial chunk handling.** Same as [`Self::open`].
    pub fn open_exclusive_readonly<P: AsRef<Path>>(path: P) -> Result<Self> {
        // `write(true)` is deliberately NOT requested: the descriptor
        // itself cannot write, so a missed gate anywhere above this layer
        // fails with EBADF instead of quietly editing the source.
        let mut file = OpenOptions::new().read(true).open(path)?;
        try_lock_exclusive(&file)?;
        let len = file.metadata()?.len();
        if len < CHUNK_SIZE as u64 {
            return Err(Error::Malformed("file shorter than one chunk"));
        }
        let mut first = [0u8; CHUNK_SIZE];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut first)?;
        let header = Header::decode(&first)?;
        let slot_count = (len / CHUNK_SIZE as u64) - 1;
        Ok(Self {
            file,
            header,
            slot_count,
            padding_policy: PaddingPolicy::None,
            superblock_replicas: DEFAULT_SUPERBLOCK_REPLICAS,
            lock_mode: LockMode::ExclusiveReadOnly,
        })
    }

    fn check_writable(&self) -> Result<()> {
        if self.lock_mode.allows_writes() {
            Ok(())
        } else {
            Err(Error::ReadOnly)
        }
    }

    /// Append `n` chunks of uniform random bytes. Used by post-commit
    /// padding (DESIGN §8) and by `Container::create_with_options`
    /// for initial decoy size.
    ///
    /// **Batched I/O (audit pass 14 perf finding).** A naive
    /// implementation does one `write_all(CHUNK_SIZE)` syscall per
    /// chunk. For a typical decoy (`initial_garbage_chunks: 100`,
    /// 400 KiB) that's 100 syscalls; for a multi-MiB decoy it
    /// adds up. We coalesce writes into batches of up to
    /// `BATCH_CHUNKS = 64` chunks per syscall (256 KiB at
    /// `CHUNK_SIZE = 4096`), so a 1024-chunk decoy collapses to 16
    /// syscalls. Memory cost is one 256 KiB heap buffer for the
    /// duration of the call. The `Zeroizing` wrapper scrubs the
    /// buffer when the function returns — important because the
    /// random bytes ARE the garbage chunks' on-disk content (no
    /// AEAD; reading them with any space's key returns
    /// AuthFailed), so leaking them via uninitialized heap reuse
    /// wouldn't compromise security, but the wrapper costs
    /// nothing and keeps the discipline consistent.
    pub fn append_garbage_chunks(&mut self, n: u64) -> Result<()> {
        self.check_writable()?;
        if n == 0 {
            return Ok(());
        }
        #[cfg(test)]
        if GARBAGE_APPEND_FAILS.with(std::cell::Cell::get) {
            return Err(Error::Internal("forced padding failure (test)"));
        }
        // Audit pass 17 B: refuse if the write would push past the
        // open-scan budget. Previously the create / post-commit-padding
        // / repack paths could grow the file past `MAX_OPEN_SCAN_CHUNKS`,
        // and the next `Container::open` would reject it with
        // `Malformed`. Symmetric write-side gate avoids the
        // create-then-can't-reopen footgun.
        check_write_budget(self.slot_count, n)?;
        const BATCH_CHUNKS: u64 = 64;
        let new_slot_base = self.slot_count;
        let offset = FIRST_SLOT_OFFSET + new_slot_base * CHUNK_SIZE as u64;
        self.file.seek(SeekFrom::Start(offset))?;

        let mut buf: zeroize::Zeroizing<Vec<u8>> =
            zeroize::Zeroizing::new(vec![0u8; (BATCH_CHUNKS as usize) * CHUNK_SIZE]);
        // ADVANCE PER BATCH (audit HV-13). `slot_count` used to move only after
        // the whole run succeeded, so a failure part-way — a full disk, an I/O
        // error — left the file physically longer than the cursor claimed.
        // Every later append then wrote OVER the padding already on disk, and
        // the container's own length disagreed with its slot count until the
        // next reopen recomputed it. Advancing per batch keeps the cursor true
        // to what is actually written at every point the loop can fail.
        let mut remaining = n;
        while remaining > 0 {
            let this_batch = remaining.min(BATCH_CHUNKS) as usize;
            let bytes = this_batch * CHUNK_SIZE;
            crate::crypto::rng::fill(&mut buf[..bytes])?;
            self.file.write_all(&buf[..bytes])?;
            self.slot_count += this_batch as u64;
            remaining -= this_batch as u64;
        }
        Ok(())
    }

    /// Number of data slots currently in the file (excluding header).
    #[must_use]
    pub fn slot_count(&self) -> u64 {
        self.slot_count
    }

    /// Read the chunk at slot `i`.
    ///
    /// An out-of-range `i` is reported as [`Error::Malformed`], not
    /// [`Error::Internal`]: this method is reached with slot pointers
    /// that were decrypted out of a chunk payload (commit roots,
    /// child pointers, log batch pointers), so a forged or corrupt
    /// pointer is input-driven, not a crate bug (audit pass 20).
    pub fn read_slot(&mut self, i: u64) -> Result<[u8; CHUNK_SIZE]> {
        if i >= self.slot_count {
            return Err(Error::Malformed("slot pointer out of range"));
        }
        let offset = FIRST_SLOT_OFFSET + i * CHUNK_SIZE as u64;
        let mut buf = [0u8; CHUNK_SIZE];
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Concurrent-safe positional read (`pread`) — does NOT mutate the
    /// file's seek position and takes only `&self`, so multiple threads
    /// can call this on the same `ContainerFile` without locking.
    /// Used by the `parallel-scan` feature's `scan_and_recover_parallel`.
    ///
    /// Unix-only: relies on `std::os::unix::fs::FileExt::read_exact_at`,
    /// which maps to `pread(2)`. On Windows the equivalent is
    /// `seek_read`, which is NOT thread-safe relative to other reads;
    /// hence we gate this method on `cfg(unix)`. Sequential `read_slot`
    /// remains the cross-platform path.
    #[cfg(unix)]
    pub fn read_slot_concurrent(&self, i: u64) -> Result<[u8; CHUNK_SIZE]> {
        use std::os::unix::fs::FileExt;
        if i >= self.slot_count {
            return Err(Error::Malformed("slot pointer out of range"));
        }
        let offset = FIRST_SLOT_OFFSET + i * CHUNK_SIZE as u64;
        let mut buf = [0u8; CHUNK_SIZE];
        self.file.read_exact_at(&mut buf, offset)?;
        Ok(buf)
    }

    /// Borrow the underlying [`File`] handle. Used by the `mmap`
    /// feature's `scan_and_recover_mmap` to construct a
    /// [`memmap2::Mmap`]. The flock acquired at open time
    /// (`LOCK_EX` in writer mode, `LOCK_SH` in readonly mode)
    /// excludes concurrent writers — this is what makes the unsafe
    /// `Mmap::map(&File)` call safe in our use.
    #[cfg(all(feature = "mmap", unix))]
    #[must_use]
    pub fn raw_file(&self) -> &File {
        &self.file
    }

    /// Append `chunk` as a new slot at the end. Returns the slot index.
    /// Caller is responsible for `fsync` discipline (DESIGN Inv-W2).
    ///
    /// Refuses with [`Error::ContainerTooLarge`] when adding this slot
    /// would push the file past [`crate::MAX_OPEN_SCAN_CHUNKS`]
    /// (audit pass 17 B: write-side / open-side budget symmetry).
    pub fn append_slot(&mut self, chunk: &[u8; CHUNK_SIZE]) -> Result<u64> {
        self.check_writable()?;
        check_write_budget(self.slot_count, 1)?;
        let new_slot = self.slot_count;
        let offset = FIRST_SLOT_OFFSET + new_slot * CHUNK_SIZE as u64;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(chunk)?;
        self.slot_count += 1;
        Ok(new_slot)
    }

    /// Overwrite an EXISTING slot with `chunk`, leaving the file length
    /// unchanged. Returns [`Error::Internal`] for `slot >= slot_count`.
    ///
    /// **This is the one in-place writer in the crate**, and every caller
    /// owes the same proof before calling it: the slot must be one this
    /// space wrote and has since retired — a scrubbed orphan or a garbage
    /// chunk this space itself appended. Rewriting a slot belonging to a
    /// foreign hidden space destroys that space, and a writer cannot tell
    /// a foreign chunk from garbage by looking (DESIGN §9). The proof is
    /// therefore never "it looked like garbage"; it is always
    /// bookkeeping — the in-crate decoy pool (`crate::space::pool`) is
    /// the only thing that supplies it.
    ///
    /// Until the churn/reuse work (DESIGN §9.1) this method existed only
    /// as `scrub_slot`, and Inv-W1 said existing slots are never
    /// rewritten *except* to scrub. Both halves are now the same
    /// primitive because they must produce the same observable: a scrub
    /// that an adversary can tell apart from a reuse is a scrub that
    /// marks its offset as "this held real data".
    pub fn rewrite_slot(&mut self, slot: u64, chunk: &[u8; CHUNK_SIZE]) -> Result<()> {
        self.check_writable()?;
        if slot >= self.slot_count {
            return Err(Error::Internal("rewrite_slot beyond slot_count"));
        }
        let offset = FIRST_SLOT_OFFSET + slot * CHUNK_SIZE as u64;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(chunk)?;
        Ok(())
    }

    /// Overwrite a slot with `CHUNK_SIZE` bytes of uniform random.
    /// Externally indistinguishable from a fresh garbage chunk; reading
    /// later with any space's key will return AuthFailed.
    ///
    /// Used by `Space::vacuum_orphans` to scrub old IndexNode chunks
    /// after they're replaced (prevents forensics with the space's
    /// password from recovering "deleted" KV entries from orphan
    /// chunks), and by the decoy churn to re-randomize a retired slot.
    ///
    /// SAFETY (deniability): caller MUST own the slot. Scrubbing
    /// another space's chunk would corrupt that space.
    pub fn scrub_slot(&mut self, slot: u64) -> Result<()> {
        let mut buf = [0u8; CHUNK_SIZE];
        crate::crypto::rng::fill(&mut buf)?;
        self.rewrite_slot(slot, &buf)
    }

    /// Force durability of all pending writes.
    pub fn fsync(&mut self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }
}

/// Refuse to grow the slot grid past
/// [`crate::MAX_OPEN_SCAN_CHUNKS`] (audit pass 17 B).
///
/// Symmetric counterpart to `crate::open::check_scan_budget` on the
/// read side. Both sides share the same constant — a write that
/// passes this check is guaranteed to produce a file the open path
/// can read — and, since audit HV-13, the same error variant, so a
/// caller does not have to learn two vocabularies for one condition.
fn check_write_budget(current: u64, extra: u64) -> Result<()> {
    let cap = crate::open::MAX_OPEN_SCAN_CHUNKS;
    let total = current.checked_add(extra).ok_or(Error::ContainerTooLarge {
        chunks: u64::MAX,
        cap,
    })?;
    if total > cap {
        return Err(Error::ContainerTooLarge { chunks: total, cap });
    }
    Ok(())
}

/// The write side's refusal, for the cross-module symmetry test in
/// `crate::open`. Test-only: the gate itself has no business being
/// callable outside the append paths that own it.
#[cfg(test)]
pub(crate) fn write_budget_error_for_test(current: u64, extra: u64) -> Error {
    check_write_budget(current, extra).expect_err("caller must pass an over-budget pair")
}

// `unix` too, and not to silence a warning: the failure this module exercises
// can only be provoked through the parent-directory fsync, which exists on
// unix alone. Compiled for Windows, the test armed a switch nothing reads and
// would have asserted that a create which actually SUCCEEDED had failed.
#[cfg(all(test, unix))]
mod hv07_tests {
    use super::*;
    use crate::crypto::kdf::Argon2Params;

    /// Restores the switch even on panic, so a failure here cannot leak into
    /// whatever runs next in the same process.
    struct ForcedCreateFailure;

    impl ForcedCreateFailure {
        fn arm() -> Self {
            CREATE_FSYNC_FAILS.with(|c| c.set(true));
            Self
        }
    }

    impl Drop for ForcedCreateFailure {
        fn drop(&mut self) {
            CREATE_FSYNC_FAILS.with(|c| c.set(false));
        }
    }

    /// A create that fails after the file exists must leave nothing behind.
    ///
    /// `create` opens with `create_new`, and the caller's cleanup only starts
    /// once `create` has RETURNED. A failure in between therefore left a stub
    /// that nothing removed — and the retry the caller obviously makes next got
    /// `AlreadyExists` on a path they never knowingly wrote, with no way to
    /// proceed short of deleting a file they do not recognise (audit HV-07).
    #[test]
    fn a_failed_create_leaves_no_file_to_block_the_retry() {
        let dir = std::env::temp_dir().join(format!("hv07-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.bin");
        let _cleanup = Cleanup(dir.clone());

        {
            let _armed = ForcedCreateFailure::arm();
            assert!(
                ContainerFile::create(&path, Argon2Params::MIN).is_err(),
                "precondition: the hook must make create fail"
            );
        }
        assert!(
            !path.exists(),
            "a stub left here makes the path permanently unusable: create_new \
             turns every retry into AlreadyExists"
        );

        // The retry must now succeed, which is the whole point of removing it.
        ContainerFile::create(&path, Argon2Params::MIN)
            .expect("the retry after a failed create must work");
    }

    struct Cleanup(std::path::PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
