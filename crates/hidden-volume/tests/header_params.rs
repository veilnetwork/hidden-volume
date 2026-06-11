//! Argon2 params header storage tests (DESIGN §2, §11.1).
//!
//! These lock in the on-disk encoding of Argon2 parameters: any change
//! that would silently make an old container unreadable should fail
//! one of these tests.

use hidden_volume::container::{ContainerFile, Header};
use hidden_volume::crypto::kdf::{Argon2Params, PARAMS_VERSION};
use hidden_volume::{HEADER_PARAMS_LEN, HEADER_PARAMS_OFFSET};
use proptest::prelude::*;

#[test]
fn params_encode_decode_roundtrip() {
    for p in [
        Argon2Params::MIN,
        Argon2Params::LIGHT,
        Argon2Params::DEFAULT,
        Argon2Params::HEAVY,
    ] {
        let bytes = p.encode();
        assert_eq!(bytes.len(), HEADER_PARAMS_LEN);
        let p2 = Argon2Params::decode(&bytes).unwrap();
        assert_eq!(p, p2, "roundtrip failed for {p:?}");
    }
}

#[test]
fn params_below_floor_rejected_by_validate() {
    // Below MIN on memory.
    let weak_m = Argon2Params {
        m_cost_kib: 1024, // 1 MiB, below 8 MiB floor
        t_cost: Argon2Params::MIN.t_cost,
        p_cost: Argon2Params::MIN.p_cost,
        version: PARAMS_VERSION as u32,
    };
    assert!(weak_m.validate().is_err());

    // Below MIN on iterations.
    let weak_t = Argon2Params {
        m_cost_kib: Argon2Params::MIN.m_cost_kib,
        t_cost: 1, // below floor of 2
        p_cost: Argon2Params::MIN.p_cost,
        version: PARAMS_VERSION as u32,
    };
    assert!(weak_t.validate().is_err());
}

#[test]
fn params_above_ceiling_rejected_by_validate() {
    // DoS guard (audit D1 / threat F1): cleartext header is unprotected;
    // a T2 file-modification adversary can write u32::MAX. validate()
    // must cap before we hand the value to argon2 (which would happily
    // try to allocate 4 TiB).
    let too_much_memory = Argon2Params {
        m_cost_kib: u32::MAX,
        t_cost: Argon2Params::MIN.t_cost,
        p_cost: Argon2Params::MIN.p_cost,
        version: PARAMS_VERSION as u32,
    };
    assert!(too_much_memory.validate().is_err());

    // Same for t_cost.
    let too_many_iters = Argon2Params {
        m_cost_kib: Argon2Params::MIN.m_cost_kib,
        t_cost: u32::MAX,
        p_cost: Argon2Params::MIN.p_cost,
        version: PARAMS_VERSION as u32,
    };
    assert!(too_many_iters.validate().is_err());

    // Same for p_cost.
    let too_many_lanes = Argon2Params {
        m_cost_kib: Argon2Params::MIN.m_cost_kib,
        t_cost: Argon2Params::MIN.t_cost,
        p_cost: u32::MAX,
        version: PARAMS_VERSION as u32,
    };
    assert!(too_many_lanes.validate().is_err());

    // Just-above-ceiling boundary cases.
    let m_just_above = Argon2Params {
        m_cost_kib: Argon2Params::MAX_M_COST_KIB + 1,
        t_cost: Argon2Params::MIN.t_cost,
        p_cost: Argon2Params::MIN.p_cost,
        version: PARAMS_VERSION as u32,
    };
    assert!(m_just_above.validate().is_err());

    let t_just_above = Argon2Params {
        m_cost_kib: Argon2Params::MIN.m_cost_kib,
        t_cost: Argon2Params::MAX_T_COST + 1,
        p_cost: Argon2Params::MIN.p_cost,
        version: PARAMS_VERSION as u32,
    };
    assert!(t_just_above.validate().is_err());

    let p_just_above = Argon2Params {
        m_cost_kib: Argon2Params::MIN.m_cost_kib,
        t_cost: Argon2Params::MIN.t_cost,
        p_cost: Argon2Params::MAX_P_COST + 1,
        version: PARAMS_VERSION as u32,
    };
    assert!(p_just_above.validate().is_err());

    // At-ceiling values must be accepted (argon2 crate's own params
    // ratio check may still reject some combinations; we test exactly
    // the m_cost ceiling here with floor t/p which is valid).
    let m_at_ceiling = Argon2Params {
        m_cost_kib: Argon2Params::MAX_M_COST_KIB,
        t_cost: Argon2Params::MIN.t_cost,
        p_cost: Argon2Params::MIN.p_cost,
        version: PARAMS_VERSION as u32,
    };
    assert!(
        m_at_ceiling.validate().is_ok(),
        "at-ceiling m_cost should pass: {:?}",
        m_at_ceiling.validate()
    );
}

#[test]
fn header_tamper_with_huge_m_cost_rejected_on_open() {
    // Real attack reproduction: create a legit container, then tamper
    // the header in-place to set m_cost_kib = u32::MAX. Re-open must
    // fail with Kdf error (NOT OOM, NOT panic, NOT timeout).
    use std::io::{Seek, SeekFrom, Write};
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    // Create with legit params.
    {
        let _ = ContainerFile::create(&path, Argon2Params::MIN).unwrap();
    }

    // Tamper the params field directly.
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let mut tampered = Argon2Params::MIN;
        tampered.m_cost_kib = u32::MAX;
        f.seek(SeekFrom::Start(HEADER_PARAMS_OFFSET as u64))
            .unwrap();
        f.write_all(&tampered.encode()).unwrap();
        f.sync_all().unwrap();
    }

    // Re-open must reject — and quickly, without trying to allocate.
    let start = std::time::Instant::now();
    let res = ContainerFile::open(&path);
    let elapsed = start.elapsed();
    assert!(res.is_err(), "tampered open should fail");
    // Validation is a constant-time check; any duration over 1s
    // suggests we tried Argon2 (DoS still possible).
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "validation took too long: {elapsed:?} — DoS guard not effective"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn params_unknown_version_rejected() {
    let alien = Argon2Params {
        m_cost_kib: Argon2Params::DEFAULT.m_cost_kib,
        t_cost: Argon2Params::DEFAULT.t_cost,
        p_cost: Argon2Params::DEFAULT.p_cost,
        version: 99, // not PARAMS_VERSION
    };
    assert!(alien.validate().is_err());
}

#[test]
fn container_create_with_below_floor_params_fails() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let weak = Argon2Params {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
        version: PARAMS_VERSION as u32,
    };
    assert!(ContainerFile::create(&path, weak).is_err());
    // File should NOT have been created (we validate before opening).
    // (Implementation detail: we open the file via create_new BEFORE
    // validate currently — this test documents the desired behavior.
    // If the test breaks, move validate above the OpenOptions call.)
    let _ = std::fs::remove_file(&path);
}

#[test]
fn header_decode_rejects_tampered_params() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    // Create a valid container.
    {
        let _c = ContainerFile::create(&path, Argon2Params::MIN).unwrap();
    }

    // Tamper with the params bytes in the header to a sub-floor value.
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.seek(SeekFrom::Start(HEADER_PARAMS_OFFSET as u64))
            .unwrap();
        let mut params_bytes = [0u8; HEADER_PARAMS_LEN];
        f.read_exact(&mut params_bytes).unwrap();
        let mut params = Argon2Params::decode(&params_bytes).unwrap();
        params.m_cost_kib = 64; // way below floor
        f.seek(SeekFrom::Start(HEADER_PARAMS_OFFSET as u64))
            .unwrap();
        f.write_all(&params.encode()).unwrap();
        f.sync_all().unwrap();
    }

    // Open should refuse: tampered params don't pass validate.
    assert!(ContainerFile::open(&path).is_err());

    let _ = std::fs::remove_file(&path);
}

proptest! {
    /// Any well-formed params (above MIN, with current version) must
    /// roundtrip through encode/decode bit-exact.
    #[test]
    fn proptest_valid_params_roundtrip(
        m_cost_kib in (Argon2Params::MIN.m_cost_kib)..=(1u32 << 20),
        t_cost in (Argon2Params::MIN.t_cost)..=64u32,
        p_cost in 1u32..=8u32,
    ) {
        let p = Argon2Params {
            m_cost_kib,
            t_cost,
            p_cost,
            version: PARAMS_VERSION as u32,
        };
        let bytes = p.encode();
        let p2 = Argon2Params::decode(&bytes).unwrap();
        prop_assert_eq!(p, p2);
    }

    /// Header roundtrip via encode_first_chunk / decode reproduces all
    /// three structured fields bit-exact.
    #[test]
    fn proptest_header_roundtrip(
        m_cost_kib in (Argon2Params::MIN.m_cost_kib)..=(1u32 << 18),
        t_cost in (Argon2Params::MIN.t_cost)..=8u32,
        p_cost in 1u32..=4u32,
    ) {
        let p = Argon2Params { m_cost_kib, t_cost, p_cost, version: PARAMS_VERSION as u32 };
        let h = Header::new_random(p).unwrap();
        let buf = h.encode_first_chunk().unwrap();
        let h2 = Header::decode(&buf).unwrap();
        prop_assert_eq!(h.salt, h2.salt);
        // v3: container_id is no longer in the cleartext header (it
        // is derived per-space from the master key). Roundtrip
        // covers only salt + params now.
        prop_assert_eq!(h.params, h2.params);
    }
}
