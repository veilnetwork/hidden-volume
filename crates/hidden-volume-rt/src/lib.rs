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

use std::mem::ManuallyDrop;

use hidden_volume::container::Container;
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

// SAFETY: `Container` and `Space<'_>` are both `Send`; `Box<Container>`
// is `Send`; `ManuallyDrop<Space<'static>>` is `Send`. The fake `'static`
// lifetime doesn't escape this struct — `with_space_mut()` re-narrows it.
unsafe impl Send for OwnedSpace {}

/// Reason a [`run_blocking`] call did not produce a result.
#[derive(Debug, Clone, Copy)]
pub enum BlockingFailure {
    /// The closure panicked. Typed as a separate variant so consumers
    /// can map it to "internal error" in their own error type.
    Panicked,
    /// The blocking task was cancelled (typically because the runtime
    /// shut down).
    Cancelled,
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
/// }).await
/// ```
pub async fn run_blocking<F, T, E>(
    f: F,
    map_err: impl FnOnce(BlockingFailure) -> E + Send + 'static,
) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(res) => res,
        Err(e) if e.is_panic() => Err(map_err(BlockingFailure::Panicked)),
        Err(_) => Err(map_err(BlockingFailure::Cancelled)),
    }
}
