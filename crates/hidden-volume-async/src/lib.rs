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
use hidden_volume_rt::OpLedger;

pub use hidden_volume_rt::{AbandonedOp, OpId, OpOutcome};

/// Async wrapper around [`Container`]. All methods offload to Tokio's
/// blocking-thread pool via [`tokio::task::spawn_blocking`].
///
/// Cloneable — clones share the same underlying [`Container`] via an
/// [`Arc<Mutex<_>>`]. Only one `run` body executes against the
/// container at a time; concurrent calls serialize on the mutex.
///
/// ## Abandoned calls (audit HV-11)
///
/// Dropping the future of any method here — `timeout`, `select!`, an
/// aborted task — does not necessarily stop the work. See
/// [`Self::abandoned_operations`] for what is knowable and how to ask.
#[derive(Clone)]
pub struct AsyncContainer {
    inner: Arc<Mutex<Container>>,
    ops: Arc<OpLedger>,
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
            ops: Arc::new(OpLedger::default()),
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
            ops: Arc::new(OpLedger::default()),
        })
    }

    /// Open an existing container.
    /// Async wrapper around [`Container::open`].
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let container = run_blocking(move || Container::open(path)).await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(container)),
            ops: Arc::new(OpLedger::default()),
        })
    }

    /// Every operation on this handle whose future was dropped before
    /// it reported back, with what is known about each **right now**.
    ///
    /// Dropping a future cannot interrupt a `spawn_blocking` closure
    /// that has already started — nothing in Rust can. Instead of
    /// pretending the work was cancelled, the abandoned operation is
    /// filed here under an [`OpId`] and its live outcome stays
    /// readable through this handle and every clone of it:
    ///
    /// - [`OpOutcome::NeverStarted`] — proven not to have run. Safe to
    ///   treat as "did not happen" and retry.
    /// - [`OpOutcome::Running`] — still executing; the container may
    ///   change under you at any moment. Not final.
    /// - [`OpOutcome::Succeeded`] / [`OpOutcome::Failed`] /
    ///   [`OpOutcome::Lost`] — final. `Succeeded` means the abandoned
    ///   write **did** land.
    ///
    /// The intended use after a timeout is to poll this until the
    /// entry settles, then reconcile against
    /// [`hidden_volume::space::Space::commit_seq`] rather than
    /// re-issuing the write blind.
    ///
    /// Records are capped (oldest evicted first); see
    /// [`Self::forgotten_abandonments`].
    #[must_use]
    pub fn abandoned_operations(&self) -> Vec<AbandonedOp> {
        self.ops.abandoned_operations()
    }

    /// Drop the abandonment records that have reached a final state.
    /// Unsettled ones are kept.
    pub fn clear_settled_operations(&self) {
        self.ops.clear_settled_operations();
    }

    /// How many abandonment records were evicted unread because the
    /// ledger filled up. Non-zero means some uncertain outcomes were
    /// lost — the host app is abandoning faster than it reconciles.
    #[must_use]
    pub fn forgotten_abandonments(&self) -> u64 {
        self.ops.forgotten_abandonments()
    }

    /// Run a closure with mutable access to the underlying [`Container`].
    /// The closure runs on Tokio's blocking-thread pool — long-running
    /// or fsync-heavy operations are safe here without starving the
    /// async runtime.
    ///
    /// Holds the internal mutex for the duration of the closure.
    /// Concurrent calls from cloned [`AsyncContainer`] handles serialize.
    ///
    /// # Do not re-enter
    ///
    /// `f` runs while this handle's mutex is held, and the mutex is NOT
    /// reentrant. A closure that blocks waiting on another operation of the
    /// *same* container — `handle.run(...)` on this or any clone, driven to
    /// completion from inside `f` — deadlocks against itself: the inner call
    /// waits for a lock the outer call will not release until the inner one
    /// returns. It is a genuine hang, not a slow path, and no timeout unwinds
    /// it (audit H-05).
    ///
    /// This is only reachable by blocking inside `f`. Ordinary concurrent
    /// calls from separate tasks serialize correctly — that is the whole point
    /// of the mutex — and `f` returning normally always releases it. Do the
    /// work in one closure rather than nesting: `f` already has `&mut
    /// Container`, so there is nothing a nested call could reach that the
    /// outer one cannot.
    ///
    /// # Dropping this future
    ///
    /// If `f` has not started yet, dropping the future prevents it from
    /// ever running — the call fails closed and nothing is written. If
    /// `f` is already running, dropping the future does **not** stop
    /// it; the operation is filed in
    /// [`Self::abandoned_operations`] instead. Use
    /// [`Self::run_cancellable`] for work that can honour a cancel
    /// token mid-flight.
    pub async fn run<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Container) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let inner = self.inner.clone();
        self.ops
            .run(
                move || {
                    let mut guard = inner.lock().map_err(|_| {
                        Error::Internal("AsyncContainer mutex poisoned by prior panicked task")
                    })?;
                    f(&mut guard)
                },
                container_failure(),
            )
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
    ///
    /// ## Dropping this future fires the token
    ///
    /// Abandoning the future (`timeout`, `select!`, task abort) calls
    /// `token.cancel()` on the way out, so a closure that polls the
    /// token — directly or through a `*_cancellable` sync entry point
    /// — stops at its next checkpoint instead of running to completion
    /// for nobody. A closure that never polls it is unaffected: this
    /// is cooperative cancellation, not preemption. Either way the
    /// operation lands in [`Self::abandoned_operations`].
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
        let closure_token = token.clone();
        self.ops
            .run_cancellable(
                token,
                move || {
                    let mut guard = inner.lock().map_err(|_| {
                        Error::Internal("AsyncContainer mutex poisoned by prior panicked task")
                    })?;
                    f(&mut guard, &closure_token)
                },
                container_failure(),
            )
            .await
    }
}

/// Map a blocking-dispatch failure onto the sync core's error type.
///
/// [`hidden_volume_rt::BlockingFailure::NotStarted`] maps to
/// [`Error::Cancelled`] and **not** to `Internal`: it is not a defect,
/// it is the one case where an abandoned or cancelled operation is
/// provably known to have left the container untouched.
fn map_blocking_failure(
    panicked: &'static str,
    cancelled: &'static str,
) -> impl FnOnce(hidden_volume_rt::BlockingFailure) -> Error + Send + 'static {
    move |fail| match fail {
        hidden_volume_rt::BlockingFailure::Panicked => Error::Internal(panicked),
        hidden_volume_rt::BlockingFailure::Cancelled => Error::Internal(cancelled),
        hidden_volume_rt::BlockingFailure::NotStarted => Error::Cancelled,
    }
}

/// Failure mapping for [`AsyncContainer`] dispatches.
fn container_failure() -> impl FnOnce(hidden_volume_rt::BlockingFailure) -> Error + Send + 'static {
    map_blocking_failure(
        "AsyncContainer blocking task panicked",
        "AsyncContainer blocking task cancelled",
    )
}

/// Failure mapping for [`AsyncSpace`] dispatches.
fn space_failure() -> impl FnOnce(hidden_volume_rt::BlockingFailure) -> Error + Send + 'static {
    map_blocking_failure(
        "AsyncSpace blocking task panicked",
        "AsyncSpace blocking task cancelled",
    )
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
    hidden_volume_rt::run_blocking(f, container_failure()).await
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
///
/// ## Abandoned calls (audit HV-11)
///
/// Dropping the future of any method here does not necessarily stop
/// the work; see [`Self::abandoned_operations`].
#[derive(Clone)]
pub struct AsyncSpace {
    inner: Arc<Mutex<OwnedSpace>>,
    ops: Arc<OpLedger>,
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
            ops: Arc::new(OpLedger::default()),
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
            ops: Arc::new(OpLedger::default()),
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
    ///
    /// # Dropping this future
    ///
    /// Same contract as [`AsyncContainer::run`]: not started yet ⇒ it
    /// never runs; already started ⇒ it runs to completion and is
    /// filed in [`Self::abandoned_operations`].
    pub async fn run<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Space<'_>) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let inner = self.inner.clone();
        self.ops
            .run(
                move || {
                    let mut guard = inner.lock().map_err(|_| {
                        Error::Internal("AsyncSpace mutex poisoned by prior panicked task")
                    })?;
                    // `with_space_mut` re-narrows the stored `Space<'static>`
                    // to a borrow handed to `f`; the `MutexGuard` keeps the
                    // `OwnedSpace` alive for the closure's duration. The
                    // higher-ranked bound on `f` (and on `with_space_mut`)
                    // makes the `&mut Space` un-nameable by the caller, so it
                    // cannot escape or be swapped between spaces.
                    guard.with_space_mut(f)
                },
                space_failure(),
            )
            .await
    }

    /// Every operation on this handle whose future was dropped before
    /// it reported back. See [`AsyncContainer::abandoned_operations`]
    /// — identical contract and identical reconciliation advice.
    #[must_use]
    pub fn abandoned_operations(&self) -> Vec<AbandonedOp> {
        self.ops.abandoned_operations()
    }

    /// Drop the abandonment records that have reached a final state.
    pub fn clear_settled_operations(&self) {
        self.ops.clear_settled_operations();
    }

    /// How many abandonment records were evicted unread.
    #[must_use]
    pub fn forgotten_abandonments(&self) -> u64 {
        self.ops.forgotten_abandonments()
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
        let ops = self.ops.clone();
        let mut cursor = start_after;
        async_stream::try_stream! {
            loop {
                let inner = inner.clone();
                let page = ops.run(move || {
                    let mut guard = inner
                        .lock()
                        .map_err(|_| Error::Internal("AsyncSpace mutex poisoned by prior panicked task"))?;
                    guard.with_space_mut(|s| s.iter_log_after(Namespace(namespace), cursor, page_size))
                }, space_failure()).await?;
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
        let ops = self.ops.clone();
        let mut cursor = start_before;
        async_stream::try_stream! {
            loop {
                let inner = inner.clone();
                let page = ops.run(move || {
                    let mut guard = inner
                        .lock()
                        .map_err(|_| Error::Internal("AsyncSpace mutex poisoned by prior panicked task"))?;
                    guard.with_space_mut(|s| s.iter_log_before(Namespace(namespace), cursor, page_size))
                }, space_failure()).await?;
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
        let ops = self.ops.clone();
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
                let page = ops.run(move || {
                    let mut guard = inner
                        .lock()
                        .map_err(|_| Error::Internal("AsyncSpace mutex poisoned by prior panicked task"))?;
                    guard.with_space_mut(|s| {
                        s.iter_log_range(Namespace(namespace), inclusive_start, cursor_upper, page_size)
                    })
                }, space_failure()).await?;
                let Some(last) = page.last() else { break };
                // Advance the exclusive lower-bound cursor past the
                // last id seen this page.
                lower = Some(last.0);
                yield page;
            }
        }
    }
}
