//! v3 key-schedule regression invariants (audit pass 19
//! follow-through, 2026-05-28).
//!
//! Locks down the three v3 cryptographic hardenings shipped in
//! commit `feat(crypto): v3 format-bump`:
//!
//! - **#8 kind-tag bytes** — `derive_subkey` / `derive_chunk_key`
//!   inputs are domain-separated by explicit kind tags (0x01 /
//!   0x02), not by length convention. Locked down by the existing
//!   unit tests inside `crypto/derive.rs`; not re-tested here
//!   (the surface is `pub(crate)`).
//! - **#9 cryptographic version-binding** — `derive_master_key`
//!   folds `params.version` into the master key via a post-Argon2
//!   BLAKE3 step. A flipped `params.version` byte (e.g. a tampered
//!   `padding_policy_index`) MUST produce a different master key
//!   for the same password + salt.
//! - **#10 per-space derived `container_id`** — `SpaceKeys::from_master`
//!   derives `container_id` from the versioned master key rather
//!   than reading it from the cleartext header. Two containers
//!   with the same password but different salts MUST have
//!   different `container_id`s; two `SpaceKeys` derived from the
//!   same `versioned_master` are deterministic (no RNG path).
//!
//! These invariants are functional regression gates: a future
//! refactor that accidentally reverts to "read container_id from
//! header" or "skip the version-bind step" will fail one of these
//! tests, not just the doc.

use hidden_volume::crypto::derive::SpaceKeys;
use hidden_volume::crypto::{Argon2Params, derive_master_key};
use zeroize::Zeroizing;

/// v3 #9 regression: tampering `padding_policy_index` (bits 16..24
/// of `params.version`) produces a different master key for the
/// same password + salt.
///
/// In v2 this would NOT have changed the master key — the policy
/// byte was unauthenticated and only affected post-commit padding.
/// In v3 the byte flows through the BLAKE3 version-bind step.
/// F-PAD therefore graduates from privacy-degradation to DoS-class.
#[test]
fn v3_padding_policy_index_changes_master_key() {
    let password = b"correct-horse-battery-staple";
    let salt = [0x42u8; 32];

    let p0 = Argon2Params::MIN; // padding_policy_index = 0
    let p1 = Argon2Params::MIN.with_padding_policy_index(1);
    let p2 = Argon2Params::MIN.with_padding_policy_index(2);

    let m0 = derive_master_key(password, &salt, p0).unwrap();
    let m1 = derive_master_key(password, &salt, p1).unwrap();
    let m2 = derive_master_key(password, &salt, p2).unwrap();

    // All three differ: the padding-policy byte is folded into
    // master_key via the v3 BLAKE3 version-bind step.
    assert_ne!(
        m0.as_slice(),
        m1.as_slice(),
        "policy 0 vs 1 master keys collide"
    );
    assert_ne!(
        m0.as_slice(),
        m2.as_slice(),
        "policy 0 vs 2 master keys collide"
    );
    assert_ne!(
        m1.as_slice(),
        m2.as_slice(),
        "policy 1 vs 2 master keys collide"
    );
}

/// v3 #10 regression: two containers with the same password but
/// different `container_salt`s produce different per-space
/// `container_id`s — the cross-container-relocation defense is
/// preserved even though the cleartext header no longer carries a
/// per-space identifier.
#[test]
fn v3_container_id_differs_across_salts() {
    let password = b"shared-password";
    let salt_a = [0x01u8; 32];
    let salt_b = [0x02u8; 32];
    let params = Argon2Params::MIN;

    let m_a = derive_master_key(password, &salt_a, params).unwrap();
    let m_b = derive_master_key(password, &salt_b, params).unwrap();

    let keys_a = SpaceKeys::from_master(&m_a);
    let keys_b = SpaceKeys::from_master(&m_b);

    assert_ne!(
        keys_a.container_id, keys_b.container_id,
        "different salts must yield different per-space container_ids"
    );
    assert_ne!(
        keys_a.aead_root, keys_b.aead_root,
        "different salts must yield different aead_roots"
    );
}

/// v3 #10 regression: `SpaceKeys::from_master` is deterministic —
/// no RNG path. The same `versioned_master` produces the same
/// `container_id` and `aead_root` on every call.
///
/// Negative-image of "we accidentally re-introduced rand::random()
/// somewhere in the per-space init path".
#[test]
fn v3_space_keys_from_master_is_deterministic() {
    let vm = Zeroizing::new([0xAAu8; 32]);
    let k1 = SpaceKeys::from_master(&vm);
    let k2 = SpaceKeys::from_master(&vm);
    assert_eq!(k1.container_id, k2.container_id);
    assert_eq!(k1.aead_root, k2.aead_root);
}

/// v3 #9 regression: tampering `format_version` (bits 0..16 of
/// `params.version`) ALSO produces a different master key. This is
/// the v2 lock-down question that #9 closes — cross-version key
/// reuse is now closed cryptographically, not only by `validate()`
/// policy.
///
/// We bypass `validate()` here by constructing the params manually
/// (validate() would reject `format_version != PARAMS_VERSION`).
#[test]
fn v3_format_version_changes_master_key() {
    let password = b"another-test-password";
    let salt = [0x7Fu8; 32];

    let mut p_v3 = Argon2Params::MIN;
    // Synthesize a hypothetical v4 params word: same Argon2 cost,
    // different format_version in the low 16 bits.
    let mut p_v4 = p_v3;
    p_v4.version = (p_v3.version & !0xFFFF) | 4;
    // And a fake v2 to test backward direction.
    let mut p_v2 = p_v3;
    p_v2.version = (p_v3.version & !0xFFFF) | 2;

    // Make all three params identical EXCEPT the version word.
    // (MIN.with_padding_policy_index(0) keeps padding_policy_index = 0.)
    p_v3 = p_v3.with_padding_policy_index(0);

    let m_v3 = derive_master_key(password, &salt, p_v3).unwrap();
    let m_v4 = derive_master_key(password, &salt, p_v4).unwrap();
    let m_v2 = derive_master_key(password, &salt, p_v2).unwrap();

    // Each version derives a different master key. A hypothetical
    // v4 reader that loosened validate() would still get a
    // different key than the v3 writer that sealed the file.
    assert_ne!(m_v3.as_slice(), m_v4.as_slice());
    assert_ne!(m_v3.as_slice(), m_v2.as_slice());
    assert_ne!(m_v4.as_slice(), m_v2.as_slice());
}
