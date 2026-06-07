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
fn try_lock_exclusive(file: &File) -> Result<()> {
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

/// File-lock mode held on the underlying [`File`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// `flock(LOCK_EX | LOCK_NB)` — exactly one writer; blocks readers
    /// and other writers. Acquired by [`ContainerFile::create`] and
    /// [`ContainerFile::open`].
    Exclusive,
    /// `flock(LOCK_SH | LOCK_NB)` — multiple readers may coexist;
    /// blocks any writer. Acquired by [`ContainerFile::open_readonly`].
    /// All `*_slot` and `*_garbage_chunks` write paths return
    /// [`Error::ReadOnly`] in this mode.
    Shared,
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
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        // Exclusive flock for the file's lifetime — auto-released when
        // `file` (and thus this struct) drops. Prevents concurrent
        // holders from corrupting the append-only chunk grid.
        try_lock_exclusive(&file)?;
        let header = Header::new_random(params)?;
        let first = header.encode_first_chunk()?;
        file.write_all(&first)?;
        file.sync_all()?;
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

    fn check_writable(&self) -> Result<()> {
        if self.lock_mode == LockMode::Shared {
            Err(Error::ReadOnly)
        } else {
            Ok(())
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
        let mut remaining = n;
        while remaining > 0 {
            let this_batch = remaining.min(BATCH_CHUNKS) as usize;
            let bytes = this_batch * CHUNK_SIZE;
            crate::crypto::rng::fill(&mut buf[..bytes])?;
            self.file.write_all(&buf[..bytes])?;
            remaining -= this_batch as u64;
        }
        self.slot_count += n;
        Ok(())
    }

    /// Number of data slots currently in the file (excluding header).
    #[must_use]
    pub fn slot_count(&self) -> u64 {
        self.slot_count
    }

    /// Read the chunk at slot `i`.
    pub fn read_slot(&mut self, i: u64) -> Result<[u8; CHUNK_SIZE]> {
        if i >= self.slot_count {
            return Err(Error::Internal("slot index out of range"));
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
            return Err(Error::Internal("slot index out of range"));
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

    /// Overwrite a slot with `CHUNK_SIZE` bytes of uniform random.
    /// Externally indistinguishable from a fresh garbage chunk; reading
    /// later with any space's key will return AuthFailed.
    ///
    /// Used by `Space::commit_tx` to scrub old IndexNode chunks after
    /// they're replaced (prevents forensics with the space's password
    /// from recovering "deleted" KV entries from orphan chunks).
    ///
    /// SAFETY (deniability): caller MUST own the slot. Scrubbing
    /// another space's chunk would corrupt that space.
    pub fn scrub_slot(&mut self, slot: u64) -> Result<()> {
        self.check_writable()?;
        if slot >= self.slot_count {
            return Err(Error::Internal("scrub_slot beyond slot_count"));
        }
        let mut buf = [0u8; CHUNK_SIZE];
        crate::crypto::rng::fill(&mut buf)?;
        let offset = FIRST_SLOT_OFFSET + slot * CHUNK_SIZE as u64;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&buf)?;
        Ok(())
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
/// can read.
fn check_write_budget(current: u64, extra: u64) -> Result<()> {
    let cap = crate::open::MAX_OPEN_SCAN_CHUNKS;
    let total = current
        .checked_add(extra)
        .ok_or(Error::ContainerTooLarge { extra, cap })?;
    if total > cap {
        return Err(Error::ContainerTooLarge { extra, cap });
    }
    Ok(())
}
