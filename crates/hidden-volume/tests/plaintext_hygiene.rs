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
    // Same for stack-array wraps used in `space::place_chunk`.
    fn takes_slice(_: &[u8]) {}
    let z: Zeroizing<[u8; 16]> = Zeroizing::new([0u8; 16]);
    takes_slice(&z[..]);
}

/// report17 HV17-M5 — a decoded log record is plaintext, and it outlives the
/// buffer it was copied out of.
///
/// The decompressed batch has been `Zeroizing` since it was written, but every
/// payload was copied out of it into an ordinary `Vec<u8>`. Those copies go on
/// living: in the caller's result, in the iterator's cache holding up to 8 MiB
/// of them, and in the partial result a batch that fails to decode leaves
/// behind — and each one is a user's log record in the clear. Every way one
/// left was a plain drop.
///
/// Type-level, like the rest of this file: safe Rust cannot watch a freed
/// allocation without going somewhere it should not. What it CAN do is hold
/// the signature still.
#[test]
fn decoded_log_payloads_are_zeroizing() {
    use hidden_volume::space::log::{LogPayload, decode_batch, encode_batch};

    let records: Vec<(u64, Vec<u8>)> = vec![
        (1, b"the first log record".to_vec()),
        (2, b"the second".to_vec()),
    ];
    let bytes = encode_batch(&records).expect("a small batch encodes");

    // The annotation is the test: if `decode_batch` regresses to plain
    // `Vec<u8>` payloads this stops compiling.
    let decoded: Vec<(u64, LogPayload)> = decode_batch(&bytes).expect("it decodes");
    assert_eq!(decoded.len(), 2, "the fixture did not round-trip");
    assert_eq!(&decoded[0].1[..], b"the first log record");

    // And the alias really is the self-scrubbing wrapper, rather than a name
    // for `Vec<u8>` that would make the annotation above prove nothing.
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<LogPayload>();

    // The lookup hands back the same wrapper, so a caller cannot pick a
    // payload out of a batch and hold it in the clear by accident.
    let found: &LogPayload =
        hidden_volume::space::log::find_in_batch(&decoded, 2).expect("id 2 is in the batch");
    assert_eq!(&found[..], b"the second");
}
