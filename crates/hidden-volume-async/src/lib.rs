//! Tokio-based async wrapper around the [`hidden_volume`] sync core.
//!
//! ## Architecture
//!
//! The sync core (`hidden-volume` crate) never blocks unbounded —
//! only on syscalls (file I/O, fsync) and Argon2id KDF. Async work
//! is delegated to [`tokio::task::spawn_blocking`], which puts the
//! call on Tokio's dedicated blocking-thread pool. This keeps the
//! async runtime responsive while CPU-heavy operations (Argon2
//! unlock, AEAD seal/open across many chunks, zstd batch compression)
//! run in parallel on pool threads.
//!
//! ## API surface
//!
//! Rather than translating every sync method to an async wrapper one-
//! by-one (high API maintenance burden), we expose a minimal surface:
//!
//! - [`AsyncContainer::create`] / [`AsyncContainer::open`] for the
//!   lifecycle entry points.
//! - [`AsyncContainer::run`] — generic offload of any closure that
//!   takes a `&mut Container` and returns a `Result<R>`.
//!
//! Host-apps batch their work inside `run()`. This matches the natural
//! transactional structure (a Tx already groups multiple ops); the
//! per-call async overhead is one blocking-pool dispatch + the
//! container mutex acquisition, both negligible compared to the
//! 3-fsync floor (~5 ms at minimum).
//!
//! ## Example
//!
//! ```no_run
//! # async fn run() -> hidden_volume::Result<()> {
//! use hidden_volume_async::AsyncContainer;
//! use hidden_volume::crypto::kdf::Argon2Params;
//! use hidden_volume::space::index::Namespace;
//!
//! let container = AsyncContainer::create(
//!     "/path/to/store",
//!     Argon2Params::DEFAULT,
//! ).await?;
//!
//! container.run(|c| {
//!     let mut space = c.create_space(b"password")?;
//!     let mut tx = space.begin_tx();
//!     tx.put(Namespace::SETTINGS, b"username", b"alice")?;
//!     tx.commit()?;
//!     Ok(())
//! }).await?;
//! # Ok(()) }
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
#![deny(missing_docs)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use hidden_volume::container::{Container, ContainerOptions};
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::{Error, Result};

/// Async wrapper around [`Container`]. All methods offload to Tokio's
/// blocking-thread pool via [`tokio::task::spawn_blocking`].
///
/// Cloneable — clones share the same underlying [`Container`] via an
/// [`Arc<Mutex<_>>`]. Only one `run` body executes against the
/// container at a time; concurrent calls serialize on the mutex.
#[derive(Clone)]
pub struct AsyncContainer {
    inner: Arc<Mutex<Container>>,
}

impl std::fmt::Debug for AsyncContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncContainer").finish_non_exhaustive()
    }
}

impl AsyncContainer {
    /// Create a new container at `path` with the given Argon2 params.
    /// Async wrapper around [`Container::create`].
    pub async fn create(path: impl AsRef<Path>, params: Argon2Params) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let container = run_blocking(move || Container::create(path, params)).await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(container)),
        })
    }

    /// Create with full options (initial garbage, padding policy, etc.).
    /// Async wrapper around [`Container::create_with_options`].
    pub async fn create_with_options(
        path: impl AsRef<Path>,
        options: ContainerOptions,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let container = run_blocking(move || Container::create_with_options(path, options)).await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(container)),
        })
    }

    /// Open an existing container.
    /// Async wrapper around [`Container::open`].
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let container = run_blocking(move || Container::open(path)).await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(container)),
        })
    }

    /// Run a closure with mutable access to the underlying [`Container`].
    /// The closure runs on Tokio's blocking-thread pool — long-running
    /// or fsync-heavy operations are safe here without starving the
    /// async runtime.
    ///
    /// Holds the internal mutex for the duration of the closure.
    /// Concurrent calls from cloned [`AsyncContainer`] handles serialize.
    pub async fn run<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Container) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let inner = self.inner.clone();
        run_blocking(move || {
            let mut guard = inner.lock().map_err(|_| {
                Error::Internal("AsyncContainer mutex poisoned by prior panicked task")
            })?;
            f(&mut guard)
        })
        .await
    }

    /// Set the post-commit padding policy. Affects future commits only.
    /// Errors with [`hidden_volume::Error::ReadOnly`] if the container
    /// was opened via [`Container::open_readonly`].
    pub async fn set_padding_policy(&self, policy: PaddingPolicy) -> Result<()> {
        self.run(move |c| c.set_padding_policy(policy)).await
    }

    /// Set the number of Superblock replicas to write per commit.
    /// Errors with [`hidden_volume::Error::ReadOnly`] on a read-only
    /// container.
    pub async fn set_superblock_replicas(&self, replicas: u8) -> Result<()> {
        self.run(move |c| c.set_superblock_replicas(replicas)).await
    }

    /// Run a closure with a [`hidden_volume::cancel::CancelToken`]
    /// threaded through. The token is the SAME instance the caller
    /// passed in; firing `token.cancel()` from any thread (including
    /// the async task that holds this future) makes the closure
    /// short-circuit at the next cooperative checkpoint with
    /// [`hidden_volume::Error::Cancelled`].
    ///
    /// This is the bridge between async-side cancellation and the sync
    /// core: `tokio::task::spawn_blocking` does NOT abort a running
    /// closure on its own (well-known tokio limitation), so we use a
    /// shared `Arc<AtomicBool>` flag instead. Long sync ops (open-scan,
    /// repack) call `token.check()?` at periodic checkpoints.
    ///
    /// ## Pattern
    ///
    /// ```no_run
    /// # async fn run() -> hidden_volume::Result<()> {
    /// use hidden_volume_async::AsyncContainer;
    /// use hidden_volume::cancel::CancelToken;
    ///
    /// # let container: AsyncContainer = todo!();
    /// let token = CancelToken::new();
    ///
    /// // Fire cancel from another thread on a deadline:
    /// let cancel = token.clone();
    /// std::thread::spawn(move || {
    ///     std::thread::sleep(std::time::Duration::from_secs(5));
    ///     cancel.cancel();
    /// });
    ///
    /// let result = container.run_cancellable(token, |c, t| {
    ///     // Use the threaded token in any cancellable sync call:
    ///     let _space = c.open_space_cancellable(b"password", t)?;
    ///     Ok(())
    /// }).await;
    /// # Ok(()) }
    /// ```
    pub async fn run_cancellable<F, R>(
        &self,
        token: hidden_volume::cancel::CancelToken,
        f: F,
    ) -> Result<R>
    where
        F: FnOnce(&mut Container, &hidden_volume::cancel::CancelToken) -> Result<R>
            + Send
            + 'static,
        R: Send + 'static,
    {
        let inner = self.inner.clone();
        run_blocking(move || {
            let mut guard = inner.lock().map_err(|_| {
                Error::Internal("AsyncContainer mutex poisoned by prior panicked task")
            })?;
            f(&mut guard, &token)
        })
        .await
    }
}

/// Internal helper: spawn `f` on the blocking pool and translate join
/// errors to [`hidden_volume::Error::Internal`]. Delegates to
/// [`hidden_volume_rt::run_blocking`] (the canonical implementation
/// shared with `hidden-volume-ffi`).
async fn run_blocking<F, R>(f: F) -> Result<R>
where
    F: FnOnce() -> Result<R> + Send + 'static,
    R: Send + 'static,
{
    hidden_volume_rt::run_blocking(f, |fail| match fail {
        hidden_volume_rt::BlockingFailure::Panicked => {
            Error::Internal("AsyncContainer blocking task panicked")
        },
        hidden_volume_rt::BlockingFailure::Cancelled => {
            Error::Internal("AsyncContainer blocking task cancelled")
        },
    })
    .await
}

// =====================================================================
// AsyncSpace — handle that keeps a Space alive across async calls.
// =====================================================================

use hidden_volume::space::Space;
use hidden_volume::space::index::Namespace;
use hidden_volume_rt::OwnedSpace;

/// Async wrapper around an opened [`Space`]. Holds the underlying
/// [`Container`] alive alongside the [`Space`] so subsequent async
/// calls reuse the already-decrypted state — the open-time scan
/// (Argon2id + O(N) trial-decrypts, dominated cost) runs **once** at
/// `open` / `create`, not per call.
///
/// ## Why a separate type from [`AsyncContainer`]
///
/// `AsyncContainer::run(closure)` is the right primitive for one-shot
/// transactions: the closure receives `&mut Container`, opens a Space
/// inside, does work, and returns. But a [`futures_core::Stream`] over
/// log pages must hold open state across many `poll_next` calls — each
/// page fetch is its own `spawn_blocking` task. Re-opening the Space on
/// every poll would pay the O(N) scan repeatedly (hundreds of ms per
/// poll on a 50K-slot container — see `docs/en/contributing/benchmarks.md`). Instead `AsyncSpace`
/// keeps both [`Container`] and [`Space`] alive in a self-referential
/// `Mutex`.
///
/// ## Threading
///
/// Cloneable (clones share the same underlying `Space` via
/// [`Arc<Mutex<_>>`]). Concurrent calls serialize on the mutex — only
/// one Tx may be active per Space at a time, which the mutex enforces
/// at the async boundary.
///
/// ## Reentrancy / deadlock (audit pass 10 L8)
///
/// The internal `Mutex` is `std::sync::Mutex` — **non-reentrant**.
/// Closures passed to [`Self::run`] (and the page closures inside the
/// `stream_log_pages_*` methods) MUST NOT re-call any `&self` method
/// on the same `AsyncSpace` (or any of its clones — they share the
/// lock) from inside the closure. Doing so would re-enter the mutex
/// on the same blocking thread and **deadlock the entire blocking
/// task**. The closure receives `&mut Space<'_>` directly; perform
/// all space operations through that borrow, not via fresh handle
/// calls.
///
/// The closure's signature taking `&mut Space<'_>` (not `&AsyncSpace`)
/// makes the safe path the obvious one, but the trap remains reachable
/// if a caller captures a handle clone via the closure's environment.
#[derive(Clone)]
pub struct AsyncSpace {
    inner: Arc<Mutex<OwnedSpace>>,
}

impl std::fmt::Debug for AsyncSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncSpace").finish_non_exhaustive()
    }
}

impl AsyncSpace {
    /// Create a new container at `path` and bootstrap a fresh space
    /// inside it under `password`. Equivalent to chaining
    /// [`Container::create`] + [`Container::create_space`] on the sync
    /// side, all inside one `spawn_blocking`.
    pub async fn create(
        path: impl AsRef<Path>,
        password: Vec<u8>,
        params: Argon2Params,
    ) -> Result<Self> {
        // Audit pass 17 E: scrub the Rust-side password copy on
        // normal return — symmetric to the FFI crate's pass-16
        // wrappers. The wrapper is moved into the blocking closure
        // so the scrub runs in the closure's drop on the success
        // path. Under `panic = "abort"` ([profile.release] in the
        // workspace Cargo.toml) destructors do not run on panic;
        // the OS process teardown is the scrub there.
        let password = zeroize::Zeroizing::new(password);
        let path = path.as_ref().to_path_buf();
        let inner = run_blocking(move || {
            let container = Box::new(Container::create(&path, params)?);
            OwnedSpace::wrap_create(container, &password)
        })
        .await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Open an existing container at `path` and unlock the space
    /// identified by `password`. The full open-time scan runs once
    /// inside the spawned blocking task; subsequent async calls on
    /// this `AsyncSpace` reuse the recovered state.
    pub async fn open(path: impl AsRef<Path>, password: Vec<u8>) -> Result<Self> {
        // Audit pass 17 E: see `Self::create` for the rationale.
        let password = zeroize::Zeroizing::new(password);
        let path = path.as_ref().to_path_buf();
        let inner = run_blocking(move || {
            let container = Box::new(Container::open(&path)?);
            OwnedSpace::wrap_open(container, &password)
        })
        .await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Run a closure with mutable access to the underlying [`Space`].
    /// The closure executes on Tokio's blocking-thread pool; the
    /// internal mutex is held for the closure's duration.
    ///
    /// # ⚠ Reentrant-call deadlock — read this before capturing a handle clone
    ///
    /// The internal `Mutex` is non-reentrant (`std::sync::Mutex`).
    /// **DO NOT** capture a clone of this `AsyncSpace` inside the
    /// closure and drive an async method on the clone via
    /// `Handle::current().block_on(...)`. Concrete deadlock sketch:
    ///
    /// ```ignore
    /// // BAD — deadlocks the entire blocking task:
    /// let clone = space.clone();
    /// space.run(move |s| {
    ///     s.put(...)?;
    ///     tokio::runtime::Handle::current().block_on(async {
    ///         let _ = clone.get(...).await;  // blocks waiting for *our own lock*
    ///     });
    ///     Ok(())
    /// }).await
    /// ```
    ///
    /// The fix is structural, not runtime — use the typed `&self`
    /// methods (`space.get(...)`, `space.put(...)`, `space.commit(...)`)
    /// which serialize on their own outside the closure. They take
    /// separate locks one-at-a-time and never nest. `run` is a
    /// low-level escape hatch for "I need direct `&mut Space` access
    /// for a multi-step op"; the closure body is meant to be straight
    /// sync code, not a sub-async-runtime entry point.
    ///
    /// **Why not a runtime guard?** Audit pass 19 round 6 considered
    /// switching to `try_lock` so the reentrant case surfaces as a
    /// typed `Error::Internal` instead of deadlocking. The change
    /// would regress
    /// `tests/async_basic.rs::concurrent_runs_serialize_via_mutex`
    /// — 10 concurrent legit `run` calls from independent tasks
    /// would fail-fast instead of serializing on the mutex. A
    /// per-task reentrancy detector needs task-local tracking that
    /// std doesn't surface (parking_lot's reentrant mutex would
    /// make `&mut Space` reachable twice on the same task —
    /// unsound). Decision: document the footgun loudly and steer
    /// callers toward the typed-methods path.
    pub async fn run<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Space<'_>) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let inner = self.inner.clone();
        run_blocking(move || {
            let mut guard = inner
                .lock()
                .map_err(|_| Error::Internal("AsyncSpace mutex poisoned by prior panicked task"))?;
            // `with_space_mut` re-narrows the stored `Space<'static>`
            // to a borrow handed to `f`; the `MutexGuard` keeps the
            // `OwnedSpace` alive for the closure's duration. The
            // higher-ranked bound on `f` (and on `with_space_mut`)
            // makes the `&mut Space` un-nameable by the caller, so it
            // cannot escape or be swapped between spaces.
            guard.with_space_mut(f)
        })
        .await
    }

    /// Stream forward over a log namespace, yielding pages of up to
    /// `page_size` entries each. Stops when the underlying log is
    /// exhausted. Each page is fetched on its own `spawn_blocking`
    /// task; the mutex is held only during the page fetch, so other
    /// async tasks can interleave between pages.
    ///
    /// Cursor semantics: `start_after` is the **exclusive** lower
    /// bound (matches [`hidden_volume::space::Space::iter_log_after`]).
    /// Pass `None` to start from the very first entry.
    ///
    /// This is the messenger primitive for "load all messages from
    /// oldest to newest" with bounded memory: each page is dropped as
    /// soon as the consumer moves on.
    pub fn stream_log_pages_after(
        &self,
        namespace: u8,
        start_after: Option<u64>,
        page_size: usize,
    ) -> impl futures_core::Stream<Item = Result<Vec<(u64, Vec<u8>)>>> + Send + 'static {
        let inner = self.inner.clone();
        let mut cursor = start_after;
        async_stream::try_stream! {
            loop {
                let inner = inner.clone();
                let page = run_blocking(move || {
                    let mut guard = inner
                        .lock()
                        .map_err(|_| Error::Internal("AsyncSpace mutex poisoned by prior panicked task"))?;
                    guard.with_space_mut(|s| s.iter_log_after(Namespace(namespace), cursor, page_size))
                }).await?;
                let Some(last) = page.last() else { break };
                cursor = Some(last.0);
                yield page;
            }
        }
    }

    /// Stream reverse over a log namespace (newest first), yielding
    /// pages of up to `page_size` entries each. Cursor is exclusive
    /// upper bound. Pass `None` to start from the latest entry.
    ///
    /// This is the canonical "scroll up to load older messages"
    /// primitive in chat UIs.
    pub fn stream_log_pages_before(
        &self,
        namespace: u8,
        start_before: Option<u64>,
        page_size: usize,
    ) -> impl futures_core::Stream<Item = Result<Vec<(u64, Vec<u8>)>>> + Send + 'static {
        let inner = self.inner.clone();
        let mut cursor = start_before;
        async_stream::try_stream! {
            loop {
                let inner = inner.clone();
                let page = run_blocking(move || {
                    let mut guard = inner
                        .lock()
                        .map_err(|_| Error::Internal("AsyncSpace mutex poisoned by prior panicked task"))?;
                    guard.with_space_mut(|s| s.iter_log_before(Namespace(namespace), cursor, page_size))
                }).await?;
                let Some(last) = page.last() else { break };
                cursor = Some(last.0);
                yield page;
            }
        }
    }

    /// Stream pages over `[start, end)` half-open range, ascending.
    /// Stops when either the range is exhausted or the upper bound is
    /// reached. Each page is at most `page_size` entries.
    ///
    /// Combine with timestamp-encoded `log_id`s (e.g. unix-ms in the
    /// high bits) for cheap async date-range queries:
    /// "stream all messages from yesterday".
    pub fn stream_log_pages_range(
        &self,
        namespace: u8,
        start: Option<u64>,
        end: Option<u64>,
        page_size: usize,
    ) -> impl futures_core::Stream<Item = Result<Vec<(u64, Vec<u8>)>>> + Send + 'static {
        let inner = self.inner.clone();
        // Use after-cursor walking, post-filtering for the upper bound.
        // `iter_log_range` already short-circuits on the upper bound
        // inside the walker, so this is efficient.
        let mut lower: Option<u64> = match start {
            // `iter_log_range`'s `start` is inclusive; we translate to
            // an exclusive lower bound via `start_minus_one`. For
            // `start = 0` we use None (unbounded below).
            Some(s) if s > 0 => Some(s - 1),
            _ => None,
        };
        let upper = end;
        async_stream::try_stream! {
            // Degenerate range: lower >= upper after translation.
            // `checked_add(1)` guards against the (theoretical) cursor
            // at u64::MAX overflowing to 0 and producing infinite
            // bytes; in practice log_id values from real callers are
            // far below u64::MAX.
            if let (Some(l), Some(u)) = (lower, upper)
                && l.checked_add(1).map(|next| next >= u).unwrap_or(true)
            {
                return;
            }
            loop {
                let inner = inner.clone();
                let cursor_lower = lower;
                let cursor_upper = upper;
                // Audit pass 11 (M4): if our exclusive lower bound is
                // already u64::MAX, there is nothing strictly above
                // it — translating (lower + 1) to inclusive start
                // would saturate to None, which would walk from the
                // namespace beginning and yield the same data again
                // forever. Compute the inclusive start outside the
                // blocking task and break early on saturation.
                let inclusive_start = match cursor_lower {
                    None => None,
                    Some(x) => match x.checked_add(1) {
                        Some(s) => Some(s),
                        // Hit u64::MAX cursor — no further entries
                        // can satisfy `id > u64::MAX`. Stream is
                        // exhausted.
                        None => break,
                    },
                };
                let page = run_blocking(move || {
                    let mut guard = inner
                        .lock()
                        .map_err(|_| Error::Internal("AsyncSpace mutex poisoned by prior panicked task"))?;
                    guard.with_space_mut(|s| {
                        s.iter_log_range(Namespace(namespace), inclusive_start, cursor_upper, page_size)
                    })
                }).await?;
                let Some(last) = page.last() else { break };
                // Advance the exclusive lower-bound cursor past the
                // last id seen this page.
                lower = Some(last.0);
                yield page;
            }
        }
    }
}
