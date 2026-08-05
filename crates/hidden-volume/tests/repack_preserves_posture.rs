//! Maintenance must not re-parameterise the container (audit HV-09).
//!
//! `compact_known` and `change_passwords` rewrite the file through
//! `repack`, and `RepackOptions::default()` used to mean
//! `Argon2Params::DEFAULT` + `PaddingPolicy::None` for the destination.
//! All three production callers passed exactly that: the FFI's two
//! path-level maintenance functions and the `hv repack` CLI. So a
//! container created at 256 MiB / t4 / p4 came back at 64 MiB / t3 / p1
//! — four times cheaper to brute-force offline, baked into the header,
//! with nothing said to anyone. The host app calls compaction itself on a
//! size threshold, so the KDF half needed no user action at all.
//!
//! The two halves are asserted separately on purpose. Preserving only
//! `Argon2Params` is not a fix: `Container::create_with_options`
//! re-derives the header's padding bits (16..24 of the version word) from
//! its `padding_policy`, so carrying the cost across while letting the
//! policy default writes a header whose padding index is zeroed.

use hidden_volume::Container;
use hidden_volume::container::{ContainerOptions, RepackOptions};
use hidden_volume::crypto::kdf::{Argon2Params, PARAMS_VERSION};
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;

mod common;
use common::scratch_path;

/// Distinguishable from [`Argon2Params::DEFAULT`] (t3 / 64 MiB / p1) in
/// two of its three cost fields, and cheap enough to run in a test.
///
/// The real finding is HEAVY → DEFAULT; what the assertion needs is only
/// that the source is not already the value the defect would write.
fn distinctive_params() -> Argon2Params {
    Argon2Params {
        t_cost: 3,
        m_cost_kib: 8 * 1024,
        p_cost: 2,
        version: PARAMS_VERSION as u32,
    }
}

/// 256 KiB buckets — persisted index 1, so it is neither
/// [`PaddingPolicy::None`] (index 0, what the defect wrote) nor
/// [`PaddingPolicy::DEFAULT`] (index 2).
const DISTINCTIVE_POLICY: PaddingPolicy = PaddingPolicy::BucketGrowth { bucket_chunks: 64 };

/// A container whose posture is worth preserving, holding one entry per
/// password so the rewrite has something to carry.
fn build(path: &std::path::Path, passwords: &[&[u8]]) {
    let mut c = Container::create_with_options(
        path,
        ContainerOptions {
            argon2: distinctive_params(),
            initial_garbage_chunks: 0,
            padding_policy: DISTINCTIVE_POLICY,
            superblock_replicas: 1,
        },
    )
    .unwrap();
    for pw in passwords {
        let mut s = c.create_space(pw).unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", pw).unwrap();
        tx.commit().unwrap();
    }
}

/// The posture actually on disk at `path`, as `(cost, padding index,
/// decoded policy)`.
fn posture(path: &std::path::Path) -> ((u32, u32, u32), u8, PaddingPolicy) {
    let c = Container::open_readonly(path).unwrap();
    let p = c.params();
    (
        (p.t_cost, p.m_cost_kib, p.p_cost),
        p.padding_policy_index(),
        c.padding_policy(),
    )
}

/// Assert both halves separately, so a fix that carries one of them and
/// drops the other fails on the one it dropped.
fn assert_posture_kept(path: &std::path::Path, what: &str) {
    let (cost, idx, policy) = posture(path);
    let want = distinctive_params();
    assert_eq!(
        cost,
        (want.t_cost, want.m_cost_kib, want.p_cost),
        "{what} rewrote the Argon2 cost: the container was created at \
         t{}/{}KiB/p{} and now derives its master key at t{}/{}KiB/p{}, \
         which is a silent change to how expensive an offline guess is",
        want.t_cost,
        want.m_cost_kib,
        want.p_cost,
        cost.0,
        cost.1,
        cost.2
    );
    assert_eq!(
        idx,
        DISTINCTIVE_POLICY.to_persisted_index().unwrap(),
        "{what} rewrote the persisted padding-policy index"
    );
    assert_eq!(
        policy, DISTINCTIVE_POLICY,
        "{what} left a header that decodes to a different padding policy, \
         so the next open stops masking per-commit growth"
    );
}

#[test]
fn compact_known_keeps_the_kdf_cost_and_the_padding_policy() {
    let path = scratch_path();
    build(&path, &[b"pw"]);

    Container::compact_known(&path, &[b"pw"], RepackOptions::default()).unwrap();

    assert_posture_kept(&path, "compact_known");
    // Not vacuous: the rewrite really happened and the data survived it.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(
        s.get(Namespace::SETTINGS, b"k").unwrap().as_deref(),
        Some(&b"pw"[..])
    );
    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn change_passwords_keeps_the_kdf_cost_and_the_padding_policy() {
    let path = scratch_path();
    build(&path, &[b"old"]);

    Container::change_passwords(&path, &[(b"old", b"new")], RepackOptions::default()).unwrap();

    assert_posture_kept(&path, "change_passwords");
    // The rotation itself worked — otherwise "posture preserved" would be
    // preserved on a file nothing had rewritten.
    let mut c = Container::open(&path).unwrap();
    assert!(
        c.open_space(b"old").is_err(),
        "the old password still opens"
    );
    let mut s = c.open_space(b"new").unwrap();
    assert_eq!(
        s.get(Namespace::SETTINGS, b"k").unwrap().as_deref(),
        Some(&b"old"[..])
    );
    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn out_of_place_repack_keeps_them_too() {
    let src = scratch_path();
    let dst = scratch_path();
    build(&src, &[b"pw"]);

    Container::repack(&src, &dst, &[b"pw"], RepackOptions::default()).unwrap();

    assert_posture_kept(&dst, "repack");
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

/// The other side of the contract: preserving by default must not remove
/// the ability to re-parameterise deliberately. Without this, "preserve
/// everything unconditionally" would also pass every assertion above.
#[test]
fn an_explicit_option_still_rotates_each_field() {
    let path = scratch_path();
    build(&path, &[b"pw"]);

    let rotated = Argon2Params::LIGHT;
    assert_ne!(
        rotated,
        distinctive_params(),
        "fixture must actually differ"
    );
    Container::compact_known(
        &path,
        &[b"pw"],
        RepackOptions {
            argon2: Some(rotated),
            padding_policy: Some(PaddingPolicy::None),
            ..Default::default()
        },
    )
    .unwrap();

    let (cost, idx, policy) = posture(&path);
    assert_eq!(
        cost,
        (rotated.t_cost, rotated.m_cost_kib, rotated.p_cost),
        "an explicit argon2 must still reach the destination header"
    );
    assert_eq!(idx, 0, "an explicit padding policy must still be persisted");
    assert_eq!(policy, PaddingPolicy::None);
    let _ = std::fs::remove_file(&path);
}

/// A policy with no persisted form. Neither a preset bucket size
/// (64 / 256 / 4096) nor `None`, so `to_persisted_index()` answers
/// `None` and the header has nothing it can record.
const CUSTOM_POLICY: PaddingPolicy = PaddingPolicy::BucketGrowth { bucket_chunks: 100 };

/// Asking a rewrite for a CUSTOM policy must not leave the source's
/// preset index in the destination's header (report7 P2).
///
/// `create_with_options` derives the header's padding bits from the
/// requested policy — except for a custom one, where it used to pass the
/// caller's `Argon2Params` through untouched. That word carries the
/// index in bits 16..24, so "untouched" means "keep whatever index the
/// caller's params already held", and the caller here is `repack`, which
/// builds the destination's params out of the SOURCE header. The source
/// header carries the source's index.
///
/// So the new container claimed a preset nothing at runtime was
/// applying, and the next open read that index back and applied a policy
/// its owner had explicitly asked to replace. The comment at the site
/// said the custom case is "runtime-only", which was true of the policy
/// and false of the header.
#[test]
fn a_custom_policy_does_not_inherit_the_sources_padding_index() {
    let source = scratch_path();
    let dest = scratch_path();
    // The source persists index 1, so "inherited" and "zeroed" are
    // distinguishable — and so is "fell back to the DEFAULT preset".
    build(&source, &[b"pw"]);
    assert_eq!(
        posture(&source).1,
        DISTINCTIVE_POLICY.to_persisted_index().unwrap(),
        "the source must carry a non-zero index or this test proves nothing"
    );

    Container::repack(
        &source,
        &dest,
        &[b"pw"],
        RepackOptions {
            padding_policy: Some(CUSTOM_POLICY),
            ..Default::default()
        },
    )
    .unwrap();

    let (_, idx, decoded) = posture(&dest);
    assert_eq!(
        idx, 0,
        "the destination's header persists padding index {idx}, inherited \
         from the source — but the repack was asked for a custom policy, \
         which has no persisted form. The next open of this container will \
         apply preset {idx} instead of the policy that was requested"
    );
    assert_eq!(
        decoded,
        PaddingPolicy::None,
        "the destination header decodes to {decoded:?}; a container whose \
         policy is runtime-only must read back as None, so a host that \
         forgets `set_padding_policy` gets no padding rather than the \
         wrong padding"
    );

    // Not vacuous: the repack really happened and the data survived it.
    let mut c = Container::open(&dest).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(
        s.get(Namespace::SETTINGS, b"k").unwrap().as_deref(),
        Some(&b"pw"[..])
    );
    drop(s);
    drop(c);

    let _ = std::fs::remove_file(&source);
    let _ = std::fs::remove_file(&dest);
}
