//! `hidden-volume-rt` — internal runtime helpers shared between the
//! `hidden-volume-async` (Tokio wrapper) and `hidden-volume-ffi`
//! (uniffi bindings) crates. Audit pass 8 (E5+E6 full extraction):
//! both downstream wrappers used to carry near-identical copies of
//! the self-referential `SpaceInner` pattern + a
//! `tokio::task::spawn_blocking` adapter; they now both depend on
//! this crate instead.
//!
//! **Not for end-user consumption.** Anything in here is wrapped
//! with a stable typed surface in the consuming crate; the names
//! here are subject to change without notice.
//!
//! ## What's in this crate
//!
//! - [`OwnedSpace`] — boxed `Container` plus a `Space<'static>`
//!   borrowing from it. Generic over the `tokio` `Mutex`/`std::sync::Mutex`
//!   distinction is **not** needed: the consumers wrap it
//!   themselves. This crate provides only the unsafe self-referential
//!   guts — the canonical place to review the lifetime-extension
//!   `transmute` and the `Drop` order.
//! - [`run_blocking`] — tokio's `spawn_blocking` adapter that
//!   translates join errors (panic / cancellation) into a typed
//!   `Result<T, E>`. Generic over `E` so the consuming crate can
//!   plug in its own error type (`hidden_volume::Error` for the
//!   async crate, `HvError` for the FFI crate).
//! - [`OpLedger`] — admission gate + outcome ledger for blocking
//!   operations whose future may be dropped. See "Abandoned futures"
//!   below.
//!
//! ## Abandoned futures (audit HV-11)
//!
//! `tokio::task::spawn_blocking` cannot be interrupted from the
//! outside. Dropping the `JoinHandle` **detaches** the task; the
//! closure keeps running on a pool thread and its mutation of the
//! container lands anyway. So `timeout(d, space.run(..)).await`
//! used to leave the caller with `Elapsed` and no way to learn
//! whether the write happened, while the pool filled up with work
//! nobody was waiting for.
//!
//! What is actually achievable is spelled out here rather than
//! papered over:
//!
//! - **Before the closure starts, cancellation is real.** Every
//!   spawned closure re-checks its cancel token as its first act.
//!   An operation abandoned while still queued short-circuits
//!   without touching the container, and reports
//!   [`OpOutcome::NeverStarted`] — a *proof* of no effect, not a
//!   hope.
//! - **After it starts, cancellation is cooperative at best.** The
//!   drop fires the token, and the sync core's long loops
//!   (open-scan, repack, integrity walk) honour it at their
//!   checkpoints. A commit already past its superblock fsync does
//!   not unwind, and this crate does not pretend otherwise: the
//!   operation is reported as [`OpOutcome::Running`] until it
//!   settles, then as [`OpOutcome::Succeeded`] /
//!   [`OpOutcome::Failed`].
//! - **The outcome is not thrown away.** The abandoning caller is
//!   gone, but the handle it abandoned is not. [`OpLedger`] files
//!   every abandoned operation under an [`OpId`] and keeps its
//!   live outcome readable via [`OpLedger::abandoned_operations`],
//!   so the host app can reconcile instead of guessing.
//!
//! ## Why a separate crate
//!
//! `hidden-volume` (the sync core) deliberately has zero tokio
//! dependency — it must build for embedded ARM / single-core mobile
//! without pulling in the runtime. So the shared helpers can't live
//! there. A separate internal crate keeps the dependency graph
//! clean: `hidden-volume` → `hidden-volume-rt` → `hidden-volume-{async,ffi}`.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]

use std::collections::VecDeque;
use std::mem::ManuallyDrop;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use hidden_volume::cancel::CancelToken;
use hidden_volume::container::Container;
use hidden_volume::crypto::SpaceKeys;
use hidden_volume::space::Space;

/// Self-referential pair of `Box<Container>` + `Space<'static>`
/// where the `Space` borrows from the `Box`'s heap pointee. The
/// `'static` lifetime on the `Space` is a lie; the actual borrow is
/// erased and re-established by `Drop` order.
///
/// ## Safety argument
///
/// 1. `container: Box<Container>` — heap-allocated. The `Box`'s
///    pointee has a stable address regardless of where `OwnedSpace`
///    itself lives or moves. Auditors note: `Pin<Box>` is **not
///    needed** because the borrowed-from data is in a separate heap
///    allocation, not in the same struct as the borrow (audit pass
///    6 D3 confirmed; `self_cell`/`ouroboros` would be no-op
///    semantic equivalents).
/// 2. `space: ManuallyDrop<Space<'static>>` — the `'static`
///    lifetime is faked via `unsafe { transmute }` at construction
///    time. The actual lifetime is bounded by `container`'s lifetime,
///    which is bounded by `OwnedSpace`'s lifetime via field-drop
///    order (next point).
/// 3. The [`Drop`] impl below explicitly drops `space` first (it
///    borrows from `container`), then `container` drops
///    automatically. Without `ManuallyDrop`, Rust's automatic
///    field-drop order would drop `container` first — UB.
///
/// ## Cross-thread safety
///
/// `OwnedSpace` is itself `Send` (`Space<'static>` and `Box<Container>`
/// are both `Send`). It is **NOT** `Sync` and is **NOT** safe to
/// share across threads without external serialization — the
/// consuming crate (async or ffi) wraps `OwnedSpace` in a `Mutex`
/// to serialize concurrent access from foreign threads / async
/// tasks.
///
/// ## Construction
///
/// Use [`OwnedSpace::wrap_open`] or [`OwnedSpace::wrap_create`] —
/// these are the only safe entry points. Both consume an
/// already-`Box`-ed `Container`; the consumer crate
/// (`hidden-volume-async` or `hidden-volume-ffi`) decides how to
/// open / create the container. Constructing `OwnedSpace` by value
/// directly is impossible (fields are private), which is what
/// prevents accidental misuse.
pub struct OwnedSpace {
    /// Heap-allocated container. Stable address; never moved after
    /// construction. Read only indirectly through `space`'s borrow.
    #[allow(dead_code, reason = "load-bearing for self-referential safety")]
    container: Box<Container>,
    /// `Space` borrowing from `container` with extended `'static`
    /// lifetime.
    space: ManuallyDrop<Space<'static>>,
}

impl OwnedSpace {
    /// Wrap an already-open Container by opening one of its spaces.
    pub fn wrap_open(
        mut container: Box<Container>,
        password: &[u8],
    ) -> hidden_volume::Result<Self> {
        // SAFETY: The transmute extends `Space<'_>`'s lifetime to
        // `'static`. This is sound only because:
        //  - `container` is heap-allocated; its pointee never moves.
        //  - `space` is dropped before `container` in `Drop`.
        //  - `OwnedSpace` is not `Sync`; concurrent mutation is
        //    serialized by the wrapping `Mutex` in the consumer
        //    crate.
        let space: Space<'_> = container.open_space(password)?;
        let space: Space<'static> = unsafe { std::mem::transmute(space) };
        Ok(Self {
            container,
            space: ManuallyDrop::new(space),
        })
    }

    /// Wrap an already-open Container by creating a new space.
    pub fn wrap_create(
        mut container: Box<Container>,
        password: &[u8],
    ) -> hidden_volume::Result<Self> {
        // SAFETY: same argument as `wrap_open`.
        let space: Space<'_> = container.create_space(password)?;
        let space: Space<'static> = unsafe { std::mem::transmute(space) };
        Ok(Self {
            container,
            space: ManuallyDrop::new(space),
        })
    }

    /// Wrap an already-open Container by opening one of its spaces with
    /// pre-derived [`SpaceKeys`] instead of a password — skips Argon2. This is
    /// the master-space path: a master holds its children's `SpaceKeys` and
    /// opens them without a per-child password prompt.
    pub fn wrap_open_with_keys(
        mut container: Box<Container>,
        keys: SpaceKeys,
    ) -> hidden_volume::Result<Self> {
        // SAFETY: same argument as `wrap_open`.
        let space: Space<'_> = container.open_space_with_keys(keys)?;
        let space: Space<'static> = unsafe { std::mem::transmute(space) };
        Ok(Self {
            container,
            space: ManuallyDrop::new(space),
        })
    }

    /// Constant-time-scan variant of [`Self::wrap_open`]. Equalizes the
    /// space-scan so the unlock time does not leak which slot matched — or
    /// whether any did — closing the F-TM1 timing side-channel that lets an
    /// observer who can measure unlock latency distinguish a real space, a
    /// decoy, or a wrong password. Used by the FFI open path, whose consumers
    /// are deniability apps that unlock in a coercion-prone setting.
    pub fn wrap_open_constant_time(
        mut container: Box<Container>,
        password: &[u8],
    ) -> hidden_volume::Result<Self> {
        // SAFETY: same argument as `wrap_open`.
        let space: Space<'_> = container.open_space_constant_time(password)?;
        let space: Space<'static> = unsafe { std::mem::transmute(space) };
        Ok(Self {
            container,
            space: ManuallyDrop::new(space),
        })
    }

    /// Constant-time-scan variant of [`Self::wrap_open_with_keys`] (the
    /// master-space path). Same F-TM1 mitigation as [`Self::wrap_open_constant_time`].
    pub fn wrap_open_with_keys_constant_time(
        mut container: Box<Container>,
        keys: SpaceKeys,
    ) -> hidden_volume::Result<Self> {
        // SAFETY: same argument as `wrap_open`.
        let space: Space<'_> = container.open_space_with_keys_constant_time(keys)?;
        let space: Space<'static> = unsafe { std::mem::transmute(space) };
        Ok(Self {
            container,
            space: ManuallyDrop::new(space),
        })
    }

    /// Borrow the inner `Space` for a callback-style operation. The
    /// stored `Space<'static>` is re-narrowed to a fresh, caller-un-
    /// nameable lifetime and handed to `f`; the result is returned.
    ///
    /// **Reborrow safety (audit pass 10 L3 + pass 20 soundness fix).**
    /// The earlier signature `&'a mut self -> &'a mut Space<'a>` was
    /// **unsound**: region inference could unify the inner `'a` across
    /// two independent `OwnedSpace` values to one common lifetime,
    /// yielding two `&mut Space<'0>` of *identical* type. `mem::swap`
    /// could then exchange the two `Space`s between containers — in
    /// 100% safe code — and dropping one `OwnedSpace` would free the
    /// `Box<Container>` the other now borrows (use-after-free).
    /// Invariance does NOT prevent this: a swap needs no lifetime
    /// *extension*, only two borrows of the *same* `Space<'0>` type.
    ///
    /// The higher-ranked bound `for<'a> FnOnce(&mut Space<'a>) -> R`
    /// closes the hole: `'a` is universally quantified per call, so
    /// the `&mut Space<'a>` cannot be named by the caller, cannot
    /// escape the closure, and cannot be unified with the `Space`
    /// lifetime of a second `with_space_mut` invocation. This is the
    /// same shape `ouroboros`/`self_cell` expose as `with_dependent_mut`.
    pub fn with_space_mut<R>(&mut self, f: impl for<'a> FnOnce(&mut Space<'a>) -> R) -> R {
        // SAFETY: the stored `Space<'static>` is only actually valid
        // while `self.container` is alive at its current heap address.
        // We re-narrow the faked `'static` to the bound lifetime `'a`
        // the closure is invoked with; `'a` cannot outlive the `&mut
        // self` borrow, so the reference is never used past the
        // container's lifetime.
        let space: &mut Space<'_> =
            unsafe { std::mem::transmute::<&mut Space<'static>, &mut Space<'_>>(&mut *self.space) };
        f(space)
    }
}

impl Drop for OwnedSpace {
    /// Drop order: `space` first, then `container`.
    ///
    /// ## `mem::forget` is sound (audit pass 10 L2)
    ///
    /// If a caller `mem::forget`s an `OwnedSpace`, neither `Drop`
    /// runs: both the `Box<Container>`'s heap allocation and the
    /// `Space`'s held resources (e.g. the file `flock`) leak. This
    /// is **sound** — Rust's `mem::forget` is safe by design. The
    /// `ManuallyDrop` wrapper guarantees that *automatic* drop order
    /// (which would be wrong: `container` first, then a
    /// `Space<'static>` that now references freed memory) cannot
    /// happen even via `mem::forget` paths, because we never let the
    /// compiler emit a `Space` drop on its own. Leaking is strictly
    /// preferable to use-after-free.
    ///
    /// ## No-panic requirement on `Space::drop`
    ///
    /// If `Space::drop` panicked (it currently can't —
    /// `Zeroize::zeroize` is infallible and `Drop`s downstream are
    /// noexcept-equivalent), `ManuallyDrop::drop` would propagate
    /// the panic and `container` would never run its own `Drop`,
    /// leaking the file flock. Future changes to `Space`'s `Drop`
    /// path must preserve no-panic to keep this invariant.
    fn drop(&mut self) {
        // SAFETY: drop `space` first (it borrows from `container`),
        // then `container` drops automatically. Without
        // `ManuallyDrop`, Rust's automatic field-drop order would
        // drop `container` first — UB while `space` still references
        // it.
        unsafe {
            ManuallyDrop::drop(&mut self.space);
        }
    }
}

impl std::fmt::Debug for OwnedSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedSpace").finish_non_exhaustive()
    }
}

// `OwnedSpace` is `Send` by auto-derivation, not by assertion.
//
// It used to carry `unsafe impl Send for OwnedSpace {}`, reasoning that
// `Box<Container>` is `Send` and so is `ManuallyDrop<Space<'static>>`.
// Both are true — and both are exactly what the compiler works out on
// its own, since every field is `Send`. The `unsafe impl` asserted a
// property nobody had to be told, and an `unsafe impl` that is not
// load-bearing is worse than none: it would go on holding if a future
// field stopped being `Send`, silently turning a compile error into a
// data race (report7 P3).
//
// The static assertion below keeps the guarantee without the assertion.
// It fails to COMPILE if any field ever loses `Send`, which is the
// outcome the `unsafe impl` was suppressing.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<OwnedSpace>();
};

/// Reason a [`run_blocking`] call did not produce a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockingFailure {
    /// The closure panicked. Typed as a separate variant so consumers
    /// can map it to "internal error" in their own error type.
    Panicked,
    /// The blocking task was cancelled (typically because the runtime
    /// shut down).
    Cancelled,
    /// The closure never ran: its cancel token was already fired when
    /// the pool thread picked the task up, so it short-circuited
    /// before touching any state. Distinct from [`Self::Cancelled`]
    /// because it carries a *proof* that nothing was mutated — map it
    /// to the consumer's "cancelled" error, never to "internal".
    NotStarted,
}

/// Spawn `f` on Tokio's blocking pool and translate join errors into
/// the consumer's error type via `map_err`. Generic over the consumer's
/// `Result<T, E>` to keep the pattern in one canonical place.
///
/// This is the canonical implementation; both
/// `hidden-volume-async` and `hidden-volume-ffi` route through it.
/// Previously each crate carried its own copy with subtle drift risk
/// — audit pass 8 (E6 full extraction) deduplicates.
///
/// ## Error mapping
///
/// `map_err` is invoked once with a [`BlockingFailure`] indicating
/// whether the failure was a panic or cancellation. Consumers
/// typically map both to `Error::Internal(...)` with a contextual
/// message:
///
/// ```ignore
/// run_blocking(closure, |fail| match fail {
///     BlockingFailure::Panicked => Error::Internal("task panicked"),
///     BlockingFailure::Cancelled => Error::Internal("task cancelled"),
///     BlockingFailure::NotStarted => Error::Cancelled,
/// }).await
/// ```
///
/// ## Abandonment
///
/// Dropping the returned future arms the same short-circuit
/// [`OpLedger`] uses: if the pool has not yet given the closure a
/// thread, it will not run at all. Once it has, this helper cannot
/// stop it and cannot tell anyone what it did — that is what
/// [`OpLedger`] is for. Use this plain form only where there is no
/// handle to report an abandoned outcome to (constructors, one-shot
/// opens).
pub async fn run_blocking<F, T, E>(
    f: F,
    map_err: impl FnOnce(BlockingFailure) -> E + Send + 'static,
) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    let ledger = OpLedger::unbounded();
    ledger.run(f, map_err).await
}

// =====================================================================
// Operation ledger — HV-11.
// =====================================================================

/// Identifier of one blocking operation, unique within its
/// [`OpLedger`]. Assigned at dispatch, before the task reaches the
/// pool, so an operation that is abandoned while still queued still
/// has a name to be reported under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpId(pub u64);

/// What is known about a blocking operation right now.
///
/// The three terminal "it ran" states are deliberately coarse: the
/// value `T` an abandoned operation produced went nowhere (nobody was
/// awaiting it), and `E` is not required to be `Clone`. What a host
/// app needs after abandoning a write is whether the container may
/// have changed — that is exactly what these variants say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpOutcome {
    /// Dispatched, but the closure has not begun. Nothing has been
    /// touched *yet*; this can still become any of the states below.
    Queued,
    /// The closure is executing. **The container may or may not have
    /// been modified, and the operation cannot be undone.** This is
    /// the honest answer to "did my abandoned write land?" while the
    /// write is still in flight — not an error, and not a promise
    /// that it was stopped.
    Running,
    /// Abandoned before the closure touched anything: either the
    /// future was dropped before the task was ever dispatched, or the
    /// pool thread found the cancel token already fired and
    /// short-circuited. **Proof of no effect.**
    NeverStarted,
    /// The closure ran to completion and returned `Ok`.
    Succeeded,
    /// The closure ran to completion and returned `Err`. Whether it
    /// left partial state behind is the operation's own contract
    /// (e.g. `commit_tx` documents its post-failure state).
    Failed,
    /// The runtime discarded the task without running it (runtime
    /// shutdown), or the closure panicked. Same uncertainty class as
    /// [`Self::Running`], frozen.
    Lost,
}

impl OpOutcome {
    /// Has this operation reached a state it can no longer leave?
    #[must_use]
    pub fn is_settled(self) -> bool {
        !matches!(self, Self::Queued | Self::Running)
    }

    /// Could this operation have modified the container? `false` only
    /// for [`Self::NeverStarted`], which is backed by a proof; every
    /// other state either did run or may still.
    #[must_use]
    pub fn may_have_mutated(self) -> bool {
        !matches!(self, Self::NeverStarted)
    }
}

/// One filed abandonment: the operation's id plus its outcome at the
/// moment [`OpLedger::abandoned_operations`] was called. Re-read the
/// ledger to observe a [`OpOutcome::Running`] entry settle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbandonedOp {
    /// Which operation.
    pub id: OpId,
    /// What is known about it now.
    pub outcome: OpOutcome,
}

const OUT_PENDING: u8 = 0;
const OUT_NEVER_STARTED: u8 = 1;
const OUT_SUCCEEDED: u8 = 2;
const OUT_FAILED: u8 = 3;
const OUT_LOST: u8 = 4;

/// How many abandonment records a ledger keeps before it starts
/// forgetting the oldest ones. Bounded on purpose: a host app that
/// abandons operations in a loop and never reads the ledger must not
/// be able to grow it without limit.
const MAX_ABANDONED_RECORDS: usize = 128;

/// Shared state of one operation. Lives in an `Arc` held by three
/// parties: the dispatching future, the spawned closure, and (once
/// abandoned) the ledger. Any of them may outlive the others.
#[derive(Debug)]
struct OpState {
    id: u64,
    token: CancelToken,
    started: AtomicBool,
    outcome: AtomicU8,
}

impl OpState {
    /// First writer wins. The closure settles the true outcome; the
    /// drop guards only fill in a state nobody else claimed.
    fn settle(&self, value: u8) {
        let _ =
            self.outcome
                .compare_exchange(OUT_PENDING, value, Ordering::AcqRel, Ordering::Acquire);
    }

    fn outcome_now(&self) -> OpOutcome {
        match self.outcome.load(Ordering::Acquire) {
            OUT_NEVER_STARTED => OpOutcome::NeverStarted,
            OUT_SUCCEEDED => OpOutcome::Succeeded,
            OUT_FAILED => OpOutcome::Failed,
            OUT_LOST => OpOutcome::Lost,
            _ if self.started.load(Ordering::Acquire) => OpOutcome::Running,
            _ => OpOutcome::Queued,
        }
    }
}

/// Fires when the spawned closure's captured environment is dropped
/// without the body having settled an outcome — i.e. the runtime threw
/// the task away, or the body panicked out.
struct LostGuard(Arc<OpState>);

impl Drop for LostGuard {
    fn drop(&mut self) {
        self.0.settle(OUT_LOST);
    }
}

/// Admission gate and abandonment ledger for one handle's blocking
/// operations.
///
/// A ledger does two things a bare `spawn_blocking` cannot:
///
/// 1. **Bounds how much of the blocking pool one handle can hold.**
///    Callers wait for a permit as ordinary async tasks (cheap, and
///    cancellable for free) instead of as parked pool threads. The
///    permit is released only when the closure truly finishes, so an
///    abandoned-but-still-running operation keeps applying
///    backpressure — which is correct: the container is still busy.
/// 2. **Remembers operations whose future was dropped.** The caller
///    that walked away cannot be told anything, but the handle it
///    walked away from can be asked. See [`Self::abandoned_operations`].
///
/// Cheap to construct; one per handle (`AsyncSpace`, `AsyncContainer`),
/// shared by all clones of that handle.
#[derive(Debug)]
pub struct OpLedger {
    next_id: AtomicU64,
    permits: Arc<tokio::sync::Semaphore>,
    abandoned: Mutex<VecDeque<Arc<OpState>>>,
    forgotten: AtomicU64,
}

impl OpLedger {
    /// Ledger admitting at most `max_concurrent` blocking operations
    /// at a time. Handles that serialize internally on a mutex want
    /// `1`: anything above that only moves the queue from tokio's
    /// async scheduler onto parked pool threads.
    ///
    /// # Panics
    ///
    /// If `max_concurrent` is zero — a ledger that admits nothing
    /// would hang every caller forever.
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        assert!(max_concurrent > 0, "OpLedger needs at least one permit");
        Self {
            next_id: AtomicU64::new(0),
            permits: Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
            abandoned: Mutex::new(VecDeque::new()),
            forgotten: AtomicU64::new(0),
        }
    }

    /// Ledger with no admission limit, used by the plain
    /// [`run_blocking`] helper — it has no handle to bound and no
    /// reader for its records.
    fn unbounded() -> Self {
        Self::new(tokio::sync::Semaphore::MAX_PERMITS)
    }

    /// Every abandonment this ledger still remembers, oldest first,
    /// each with its outcome **as of this call**. Entries whose
    /// outcome is [`OpOutcome::Running`] or [`OpOutcome::Queued`] are
    /// not final — call again later to see them settle.
    ///
    /// This is the answer to "I timed out a write; did it land?".
    #[must_use]
    pub fn abandoned_operations(&self) -> Vec<AbandonedOp> {
        let queue = self
            .abandoned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        queue
            .iter()
            .map(|state| AbandonedOp {
                id: OpId(state.id),
                outcome: state.outcome_now(),
            })
            .collect()
    }

    /// Forget the abandonment records that have reached a final
    /// state. Unsettled ones are kept — they are exactly the records
    /// still worth watching.
    pub fn clear_settled_operations(&self) {
        let mut queue = self
            .abandoned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        queue.retain(|state| !state.outcome_now().is_settled());
    }

    /// How many abandonment records were evicted because the ledger
    /// hit its record cap. Non-zero means the host app is abandoning
    /// faster than it reconciles, and that some uncertain outcomes are
    /// no longer reported.
    #[must_use]
    pub fn forgotten_abandonments(&self) -> u64 {
        self.forgotten.load(Ordering::Relaxed)
    }

    /// Dispatch `f` to the blocking pool under a fresh, private
    /// cancel token. See [`Self::run_cancellable`] — this is that
    /// method with a token the closure has no way to observe, so the
    /// only cancellation it can benefit from is the pre-start
    /// short-circuit.
    pub async fn run<F, T, E>(
        &self,
        f: F,
        map_err: impl FnOnce(BlockingFailure) -> E + Send + 'static,
    ) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E> + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
    {
        self.run_cancellable(CancelToken::new(), f, map_err).await
    }

    /// Dispatch `f` to the blocking pool, wired to `token`.
    ///
    /// `token` is the caller's own token — clone it into `f` and the
    /// sync core's cancellable entry points to get cooperative
    /// cancellation. This ledger fires the same token when the
    /// returned future is dropped, which is what turns "the caller
    /// walked away" into a signal the sync core's checkpoints can act
    /// on.
    ///
    /// ## What dropping the future actually does
    ///
    /// | State when dropped | Effect |
    /// |---|---|
    /// | Waiting for a permit | Never dispatched. [`OpOutcome::NeverStarted`]. |
    /// | Queued on the pool | Short-circuits on the token. [`OpOutcome::NeverStarted`]. |
    /// | Closure running | **Not interrupted.** Token fired; the closure stops at its next checkpoint if it has any, and runs to completion if it does not. [`OpOutcome::Running`] until it settles. |
    ///
    /// In every case the operation is filed in the ledger under a
    /// fresh [`OpId`].
    pub async fn run_cancellable<F, T, E>(
        &self,
        token: CancelToken,
        f: F,
        map_err: impl FnOnce(BlockingFailure) -> E + Send + 'static,
    ) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E> + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
    {
        let state = Arc::new(OpState {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            token,
            started: AtomicBool::new(false),
            outcome: AtomicU8::new(OUT_PENDING),
        });

        // Armed for the whole body. Every `return` below happens after
        // `disarm`, so the guard fires only when this future is
        // dropped mid-flight — the HV-11 case.
        let mut guard = AbandonGuard {
            ledger: self,
            state: Some(Arc::clone(&state)),
            dispatched: false,
        };

        let permit = match Arc::clone(&self.permits).acquire_owned().await {
            Ok(permit) => permit,
            // Unreachable: this ledger owns its semaphore and never
            // closes it. Report it as "did not run", which is true.
            Err(_) => {
                guard.disarm();
                state.settle(OUT_NEVER_STARTED);
                return Err(map_err(BlockingFailure::NotStarted));
            },
        };

        // From here on the task exists independently of this future.
        guard.dispatched = true;
        let task_state = Arc::clone(&state);
        // Captured by the closure, NOT created inside it: if tokio
        // drops the task without ever calling the body, dropping the
        // environment is the only signal we get.
        let lost = LostGuard(Arc::clone(&state));
        let join = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _lost = lost;
            // The linearization point of the whole design: past this
            // check the closure is unstoppable, before it the
            // operation provably did nothing.
            if task_state.token.is_cancelled() {
                task_state.settle(OUT_NEVER_STARTED);
                return None;
            }
            task_state.started.store(true, Ordering::Release);
            let result = f();
            task_state.settle(if result.is_ok() {
                OUT_SUCCEEDED
            } else {
                OUT_FAILED
            });
            Some(result)
        });

        let joined = join.await;
        guard.disarm();
        match joined {
            Ok(Some(result)) => result,
            Ok(None) => Err(map_err(BlockingFailure::NotStarted)),
            Err(e) if e.is_panic() => Err(map_err(BlockingFailure::Panicked)),
            Err(_) => Err(map_err(BlockingFailure::Cancelled)),
        }
    }

    fn file_abandoned(&self, state: Arc<OpState>) {
        let mut queue = self
            .abandoned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while queue.len() >= MAX_ABANDONED_RECORDS {
            queue.pop_front();
            self.forgotten.fetch_add(1, Ordering::Relaxed);
        }
        queue.push_back(state);
    }
}

impl Default for OpLedger {
    /// One permit — the shape every handle in this workspace wants,
    /// since each serializes on an internal mutex anyway.
    fn default() -> Self {
        Self::new(1)
    }
}

/// Fires the cancel token and files the operation when the dispatching
/// future is dropped before its blocking task reported back.
struct AbandonGuard<'l> {
    ledger: &'l OpLedger,
    state: Option<Arc<OpState>>,
    /// Whether `spawn_blocking` was already called. If not, nothing
    /// can possibly run and the outcome is settled on the spot.
    dispatched: bool,
}

impl AbandonGuard<'_> {
    fn disarm(&mut self) {
        self.state = None;
    }
}

impl Drop for AbandonGuard<'_> {
    fn drop(&mut self) {
        let Some(state) = self.state.take() else {
            return;
        };
        // Cooperative half: the sync core polls this at its
        // checkpoints. It stops loops; it does not unwind commits.
        state.token.cancel();
        if !self.dispatched {
            // Abandoned while waiting for a permit — no task was ever
            // created, so "nothing happened" is a fact, not a guess.
            state.settle(OUT_NEVER_STARTED);
        }
        self.ledger.file_abandoned(state);
    }
}
