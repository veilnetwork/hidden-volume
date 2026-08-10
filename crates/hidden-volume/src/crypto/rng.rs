//! Unified RNG. We always go through `getrandom` — never custom or seeded
//! RNGs in production paths. Test-only deterministic RNGs live in tests.

use crate::{Error, Result};

/// Fill `buf` with cryptographically secure random bytes. Used for nonces,
/// salts, container_id, and garbage chunks.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    #[cfg(test)]
    if forced_fill_failure() {
        return Err(Error::Internal("test hook: forced CSPRNG failure"));
    }
    getrandom::getrandom(buf).map_err(|_| Error::Internal("getrandom failed"))
}

#[cfg(test)]
thread_local! {
    /// Test-only countdown: fail the `n`-th [`fill`] from the moment it was
    /// armed.
    ///
    /// The CSPRNG does not fail on any machine a test runs on, so a caller
    /// that draws in a LOOP cannot otherwise be made to unwind halfway
    /// through — and halfway through is the only interesting place, because
    /// that is where a caller can be holding state it has not put back yet.
    ///
    /// Thread-local for the reason `CREATE_FSYNC_FAILS` in `container/file.rs`
    /// records at length: a process-global fires inside whatever unrelated
    /// draw a parallel test thread happens to be making.
    static FILL_FAILS_AT: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// Arm [`FILL_FAILS_AT`] on this thread; restores on drop so a panicking test
/// cannot leak the fault into whatever runs next in the same thread.
#[cfg(test)]
pub(crate) struct ForcedRngFailure;

#[cfg(test)]
impl ForcedRngFailure {
    /// Fail the `nth` (1-based) fill from now.
    pub(crate) fn arm(nth: u32) -> Self {
        assert!(nth >= 1, "nth is 1-based");
        FILL_FAILS_AT.with(|c| c.set(Some(nth)));
        Self
    }
}

#[cfg(test)]
impl Drop for ForcedRngFailure {
    fn drop(&mut self) {
        FILL_FAILS_AT.with(|c| c.set(None));
    }
}

#[cfg(test)]
fn forced_fill_failure() -> bool {
    FILL_FAILS_AT.with(|c| match c.get() {
        Some(1) => {
            c.set(None);
            true
        },
        Some(n) => {
            c.set(Some(n - 1));
            false
        },
        None => false,
    })
}

/// Convenience: allocate `N` random bytes.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut a = [0u8; N];
    fill(&mut a)?;
    Ok(a)
}
