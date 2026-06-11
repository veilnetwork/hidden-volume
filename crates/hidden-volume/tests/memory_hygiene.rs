//! Type-level regression tests for the memory hygiene contract
//! documented in `docs/en/security/audits/memory.md`.
//!
//! These don't observe runtime zeroing (impossible to verify in safe
//! Rust without unsafe pointer reads after drop). What they do is
//! lock in the SIGNATURES of key-deriving functions so a future change
//! that drops `Zeroizing<>` from a return type would fail to compile.
//!
//! Runtime zeroize correctness lives in the `zeroize` crate itself
//! (carefully written volatile-write loops marked `#[inline(never)]`).

use hidden_volume::crypto::derive::{SpaceKeys, derive_chunk_key};
use hidden_volume::crypto::kdf::{Argon2Params, derive_master_key};
use zeroize::Zeroizing;

#[test]
fn derive_master_key_returns_zeroizing() {
    let salt = [0u8; 32];
    let result: Zeroizing<[u8; 32]> = derive_master_key(b"pw", &salt, Argon2Params::MIN).unwrap();
    // If the signature regresses to plain [u8; 32] this won't compile.
    let _ref: &[u8; 32] = &result;
}

#[test]
fn derive_chunk_key_returns_zeroizing() {
    let aead_root = [0u8; 32];
    let container_id = [0u8; 32];
    let result: Zeroizing<[u8; 32]> = derive_chunk_key(&aead_root, &container_id, 0);
    let _ref: &[u8; 32] = &result;
}

// Audit B6 (2026-05-02): `derive_subkey` is `pub(crate)` (no external
// callers, fixed-context BLAKE3 schedule). The corresponding type-
// regression test moved into `crypto/derive.rs` as a `#[cfg(test)]`
// unit test.

#[test]
fn space_keys_zeroize_on_drop() {
    // SpaceKeys derives ZeroizeOnDrop, which is a marker trait.
    // We can't directly test the zero on drop without unsafe, but
    // we can confirm the trait is implemented (compile-time check).
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<SpaceKeys>();
}

#[test]
fn space_keys_does_not_leak_via_debug() {
    // Debug must not print key bytes — uses finish_non_exhaustive.
    let salt = [0u8; 32];
    let master = derive_master_key(b"pw", &salt, Argon2Params::MIN).unwrap();
    let keys = SpaceKeys::from_master(&master);
    let dbg = format!("{:?}", keys);
    // Debug output should be opaque; specifically, it must not contain
    // the master, aead_root, or kdf bytes in any form.
    assert!(dbg.contains("SpaceKeys"));
    // No hex-like content (BLAKE3 outputs commonly contain printable
    // sequences). Reasonable proxy: the debug string is short.
    assert!(
        dbg.len() < 100,
        "SpaceKeys Debug output too verbose; likely leaks key bytes: {dbg}"
    );
}

#[test]
fn argon2_params_default_above_min() {
    // Defense-in-depth: confirm the runtime-default params are NOT
    // the minimum (otherwise a casual user gets weak KDF).
    let default = Argon2Params::DEFAULT;
    let min = Argon2Params::MIN;
    assert!(default.m_cost_kib >= min.m_cost_kib);
    assert!(default.t_cost >= min.t_cost);
    // Default should be strictly stronger on at least one axis.
    assert!(
        default.m_cost_kib > min.m_cost_kib || default.t_cost > min.t_cost,
        "Argon2Params::DEFAULT should be strictly stronger than MIN"
    );
}

#[test]
fn space_keys_clone_does_not_share_storage() {
    // SpaceKeys derives Clone — cloning produces a separate buffer
    // (each gets its own Drop scrub). If Clone were a shallow copy,
    // dropping one would zero the other's bytes early.
    let salt = [0u8; 32];
    let master = derive_master_key(b"pw", &salt, Argon2Params::MIN).unwrap();
    let k1 = SpaceKeys::from_master(&master);
    let k2 = k1.clone();
    // Both alive simultaneously — both have their own data.
    // Audit B1+B2: SpaceKeys now only holds `aead_root` (master/kdf
    // were dead fields, removed).
    assert_eq!(k1.aead_root, k2.aead_root);
    drop(k1);
    // k2 still readable after k1's drop scrubs k1's storage.
    assert_ne!(k2.aead_root, [0u8; 32]);
}
