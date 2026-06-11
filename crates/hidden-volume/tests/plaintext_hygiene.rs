//! Type-level regression tests for the plaintext-leak contract
//! documented in `docs/en/security/audits/plaintext.md`.
//!
//! Locks in the **signatures** that wrap transient plaintext buffers in
//! `Zeroizing`. A future refactor that drops the wrapper from a return
//! type or local binding will fail to compile here.
//!
//! Like `tests/memory_hygiene.rs`, these don't observe runtime zeroing
//! (not possible in safe Rust without UB-adjacent pointer reads). They
//! enforce the type-level guard the audit relies on.

use hidden_volume::crypto::aead::{ChunkAead, make_aad};
use zeroize::Zeroizing;

#[test]
fn aead_open_returns_zeroizing_vec() {
    // Build a real AEAD round-trip and confirm `open` hands back a
    // Zeroizing wrapper. If the signature regresses to plain Vec<u8>
    // the explicit type annotation below will fail to compile.
    let key = [0u8; 32];
    let aead = ChunkAead::new(&key);
    let container_id = [0u8; 32];
    let slot: u64 = 42;
    let aad = make_aad(&container_id, slot);

    let plaintext = b"hello plaintext audit";
    let (nonce, ct) = aead.seal(plaintext, aad).unwrap();

    let opened: Zeroizing<Vec<u8>> = aead.open(&nonce, &ct, aad).unwrap();
    assert_eq!(&opened[..], plaintext);
}

#[test]
fn aead_open_auth_failed_propagates() {
    // Sanity: changing AAD makes open fail; signature still matches.
    let key = [0u8; 32];
    let aead = ChunkAead::new(&key);
    let container_id = [0u8; 32];
    let aad_a = make_aad(&container_id, 1);
    let aad_b = make_aad(&container_id, 2);

    let (nonce, ct) = aead.seal(b"x", aad_a).unwrap();
    let result: hidden_volume::Result<Zeroizing<Vec<u8>>> = aead.open(&nonce, &ct, aad_b);
    assert!(matches!(result, Err(hidden_volume::Error::AuthFailed)));
}

#[test]
fn zeroizing_vec_derefs_to_slice() {
    // Confirms callers can pass `&zeroizing_vec` where `&[u8]` is expected
    // (the auto-deref chain `Zeroizing<Vec<u8>> → Vec<u8> → [u8]`). If
    // this stops working we'd have a forced API churn.
    fn takes_slice(_: &[u8]) {}
    let z: Zeroizing<Vec<u8>> = Zeroizing::new(vec![1u8, 2, 3]);
    takes_slice(&z);
}

#[test]
fn zeroizing_array_derefs_to_array_slice() {
    // Same for stack-array wraps used in `space::append_chunk`.
    fn takes_slice(_: &[u8]) {}
    let z: Zeroizing<[u8; 16]> = Zeroizing::new([0u8; 16]);
    takes_slice(&z[..]);
}
