//! Unified RNG. We always go through `getrandom` — never custom or seeded
//! RNGs in production paths. Test-only deterministic RNGs live in tests.

use crate::{Error, Result};

/// Fill `buf` with cryptographically secure random bytes. Used for nonces,
/// salts, container_id, and garbage chunks.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::Internal("getrandom failed"))
}

/// Convenience: allocate `N` random bytes.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut a = [0u8; N];
    fill(&mut a)?;
    Ok(a)
}
