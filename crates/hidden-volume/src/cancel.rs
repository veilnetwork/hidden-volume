//! Cooperative cancellation primitive.
//!
//! `tokio::task::spawn_blocking` does not interrupt a running closure —
//! once the sync core enters a long loop (open-scan, repack, integrity
//! walk), there is no way for the runtime to abort it. To support
//! "user closed the app" / "user pressed cancel" scenarios on mobile
//! the sync core checks a [`CancelToken`] at coarse-grained
//! checkpoints and short-circuits with [`crate::Error::Cancelled`]
//! when the flag is set.
//!
//! ## Design
//!
//! - **Lightweight.** A single `Arc<AtomicBool>`. Clone is cheap; safe
//!   to pass between threads. No allocation per check.
//! - **Cooperative.** Long loops poll the token at periodic boundaries
//!   (every ~64 slots in the scan loop). The cost is one `Acquire`
//!   load per N iterations.
//! - **No false positives.** A token only flips one way (false → true);
//!   once cancelled, every subsequent check returns `Err(Cancelled)`.
//!   Drop a token and instantiate a fresh one to start a new
//!   cancellable operation.
//!
//! ## Usage
//!
//! ```no_run
//! use hidden_volume::cancel::CancelToken;
//! use hidden_volume::Container;
//!
//! # fn run() -> hidden_volume::Result<()> {
//! let token = CancelToken::new();
//! let token_for_cancel = token.clone();
//!
//! // Spawn a thread that fires cancel after a timeout.
//! std::thread::spawn(move || {
//!     std::thread::sleep(std::time::Duration::from_secs(5));
//!     token_for_cancel.cancel();
//! });
//!
//! let mut container = Container::open("/path/to/store")?;
//! match container.open_space_cancellable(b"password", &token) {
//!     Ok(_space) => { /* scan completed in time */ }
//!     Err(hidden_volume::Error::Cancelled) => { /* user-initiated abort */ }
//!     Err(other) => return Err(other),
//! }
//! # Ok(()) }
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{Error, Result};

/// Cooperative cancellation flag. Cheap to clone (one `Arc::clone`).
///
/// Each instance is a handle to the same underlying boolean — calling
/// [`cancel`](Self::cancel) on any clone fires the flag for all of them.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// Construct a fresh, not-yet-cancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fire the cancel flag. After this returns, every existing or
    /// future clone of this token reports `is_cancelled() == true`.
    /// Idempotent.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Has this token been cancelled? Cheap (one `Acquire` load).
    /// Most production callers should prefer [`Self::check`] which
    /// returns `Result` and integrates with `?` propagation; this is
    /// kept public for tests and ad-hoc inspection.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    /// Returns `Err(Error::Cancelled)` if cancelled, else `Ok(())`.
    /// Designed for `?` propagation inside long loops.
    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
}
