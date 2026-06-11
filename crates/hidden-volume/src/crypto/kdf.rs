//! Password-based KDF. Argon2id only. See DESIGN §4 and §11.1.
//!
//! Params are stored per-container in the cleartext header (DESIGN §2,
//! `HEADER_PARAMS_OFFSET`). This lets each host-app pick a workload
//! appropriate for its target hardware class — a low-end Android phone
//! and a desktop both ship the same library, but their containers carry
//! different parameter sets. On open the library reads the stored params
//! and runs Argon2id once with them.
//!
//! ## Floor
//!
//! [`Argon2Params::MIN`] is the floor below which the library refuses to
//! open or create a container, regardless of what the header says. This
//! prevents a malicious host-app (or a tampered container) from forcing
//! a victim's library into a trivially brute-forceable parameter set.

use argon2::{Algorithm, Argon2, Version};
use byteorder::{ByteOrder, LittleEndian};
use zeroize::Zeroizing;

use crate::{Error, HEADER_PARAMS_LEN, Result};

/// Argon2id parameter set, stored per-container.
///
/// ## `version` bit layout (audit pass 8, S1 full)
///
/// The `version` field is a packed `u32`:
///
/// | bits  | field                        | semantics |
/// |-------|------------------------------|-----------|
/// | 0..16 | `format_version`             | Currently `3` (v3 cluster, 2026-05-28: #8 kind-tag bytes + #9 cryptographic version-binding + #10 per-space derived `container_id`). Library refuses unknown values on open. v1/v2 containers are rejected. |
/// | 16..24 | `padding_policy_index`      | Encoding of the post-commit padding policy persisted at create time. `0` = `PaddingPolicy::None`; presets 1..=3 = bucket sizes (256 KiB / 1 MiB / 16 MiB). See [`crate::padding::PaddingPolicy::from_persisted_index`]. |
/// | 24..32 | reserved                    | Must be `0`. Future format-version planning may consume these bits. |
///
/// Pre-pass-8 containers had the whole `u32` set to `1`, which under
/// the pass-8 packed layout decoded as
/// `format_version=1, padding_policy_index=0` → `PaddingPolicy::None`.
/// That backward-compat held within the v1 line; v2 (post-R-NSKIND,
/// pass-13) rejects v1 containers via `validate()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Memory cost (KiB).
    pub m_cost_kib: u32,
    /// Parallelism lanes.
    pub p_cost: u32,
    /// Packed version word — see struct-level rustdoc for the bit
    /// layout. Use [`Self::format_version`] /
    /// [`Self::padding_policy_index`] / [`Self::with_padding_policy_index`]
    /// rather than touching this field directly.
    pub version: u32,
}

/// Current format version (the low 16 bits of
/// [`Argon2Params::version`]). Bump only with format-version planning.
///
/// **v3 (P-LOW2 + #9 + #10, 2026-05-28)** — three cryptographic
/// hardenings, format-breaking pre-1.0:
///
/// - **#8 kind-tag bytes** in `crypto::derive::derive_subkey` /
///   [`crate::crypto::derive::derive_chunk_key`] inputs (0x01 / 0x02)
///   replace the audit-pass-7-D3 length-distinguishes convention.
/// - **#9 cryptographic version-binding**: [`derive_master_key`] now
///   folds `params.version` through a post-Argon2 BLAKE3 step so
///   cross-version key reuse is closed cryptographically, not only by
///   `validate()` policy.
/// - **#10 per-space derived `container_id`**: the cleartext header
///   no longer stores `container_id` (it is derived per-space inside
///   `SpaceKeys::from_master`). Closes the specific D1-A2 fingerprint
///   that exposed «this is a hidden-volume container with one or more
///   space identifiers at offset 32..64».
///
/// **v2 (R-NSKIND)** — `CommitPayload` per-root layout adds a `kind`
/// byte to distinguish KV from Log namespaces (closes the audit pass
/// 12 HIGH "mixed-namespace data loss" finding).
///
/// v2 containers cannot be opened by a v3 reader (`validate()`
/// rejects unknown `format_version`); pre-1.0 — breaking is
/// acceptable. No migration tool is provided; users must re-create
/// containers under v3.
pub const PARAMS_VERSION: u16 = 3;

impl Argon2Params {
    /// OWASP "secret-management" baseline. ~100ms on mid-range ARM.
    /// Suitable default for messengers on phones from the last 5 years.
    pub const DEFAULT: Self = Self {
        t_cost: 3,
        m_cost_kib: 64 * 1024,
        p_cost: 1,
        version: PARAMS_VERSION as u32,
    };

    /// Minimum acceptable parameters. Anything below this is rejected by
    /// [`Self::validate`].
    ///
    /// **The floor is intentionally below the OWASP 2024 low-end
    /// recommendation** (`m = 12 MiB, t = 3, p = 1`) — 8 MiB exists so
    /// the library can run on very-low-end embedded targets that
    /// genuinely cannot afford 12+ MiB per Argon2id call. On such
    /// devices the resulting key derivation runs in ~10ms (vs ~700ms
    /// for [`Self::DEFAULT`]), which speeds up an attacker's offline
    /// brute-force by ~70×.
    ///
    /// **Mobile and desktop host-apps should use [`Self::DEFAULT`]
    /// (64 MiB)**, which is 3.4× the OWASP mainline recommendation
    /// (19 MiB). Reach for [`Self::MIN`] only when targeting an
    /// embedded device with a documented memory budget that cannot
    /// hold the DEFAULT working set.
    ///
    /// Header-tamper attacks that downgrade the on-disk params to
    /// [`Self::MIN`] do NOT speed up offline brute-force on the
    /// already-captured file: legitimate-open re-derives the master
    /// key under the tampered params, which differs from the seal-
    /// time key, hits [`crate::Error::AuthFailed`] — see
    /// [`docs/en/security/audits/adversarial-stance.md` D1-A5](../../../docs/en/security/audits/adversarial-stance.md).
    pub const MIN: Self = Self {
        t_cost: 2,
        m_cost_kib: 8 * 1024,
        p_cost: 1,
        version: PARAMS_VERSION as u32,
    };

    /// Lightweight preset for low-end devices (~30ms on Cortex-A53). Use
    /// when the device class is known constrained. Stays at the floor on
    /// memory and adds one extra iteration.
    pub const LIGHT: Self = Self {
        t_cost: 3,
        m_cost_kib: 16 * 1024,
        p_cost: 1,
        version: PARAMS_VERSION as u32,
    };

    /// Heavy preset for desktop hardware (~250ms on x86 server-class).
    /// Use when the host-app knows it's on capable hardware and wants a
    /// stronger margin against offline bruteforce.
    pub const HEAVY: Self = Self {
        t_cost: 4,
        m_cost_kib: 256 * 1024,
        p_cost: 4,
        version: PARAMS_VERSION as u32,
    };

    /// Extract the format-version field (low 16 bits of `version`).
    /// Audit pass 8 (S1 full): the upper bits are now used for
    /// padding-policy persistence; only the low 16 bits gate the
    /// `format_version == PARAMS_VERSION` check on open.
    #[must_use]
    pub fn format_version(&self) -> u16 {
        (self.version & 0xFFFF) as u16
    }

    /// Extract the padding-policy index (bits 16..24 of `version`).
    /// 0 → no padding. Bits 24..32 are reserved (must be 0).
    /// See [`crate::padding::PaddingPolicy::from_persisted_index`].
    #[must_use]
    pub fn padding_policy_index(&self) -> u8 {
        ((self.version >> 16) & 0xFF) as u8
    }

    /// Return a copy with the padding-policy index updated to `idx`.
    /// Used by `Container::create_with_options` to persist the policy
    /// at create time. Bits 24..32 are explicitly zeroed (audit pass
    /// 9 B1 — symmetry with `format_version` / `padding_policy_index`
    /// extractors, which both mask their own bit ranges; previously
    /// this method preserved bits 24..32 if they were non-zero,
    /// relying on `validate()` rejecting that case at open. Explicit
    /// is safer for future-refactor footgun-avoidance).
    #[must_use]
    pub fn with_padding_policy_index(self, idx: u8) -> Self {
        let lo = self.version & 0xFFFF;
        Self {
            // Mask: keep low 16 bits + the new policy byte at 16..24;
            // force reserved bits 24..32 to 0.
            version: lo | ((idx as u32) << 16),
            ..self
        }
    }

    /// Hard ceiling on `m_cost_kib` accepted from a stored header.
    /// 1 GiB = 4× HEAVY's 256 MiB; sufficient headroom for any realistic
    /// stronger preset, while bounding the worst-case allocation at open
    /// time. **Closes a DoS vector**: the cleartext header is not AEAD-
    /// protected, so a T2 file-modification adversary could otherwise
    /// write `m_cost_kib = u32::MAX` (≈4 TiB) and force every subsequent
    /// `Container::open` to OOM during Argon2id derivation. See
    /// `docs/en/security/threat-model.md` §F1 and `tests/header_params.rs`.
    pub const MAX_M_COST_KIB: u32 = 1024 * 1024;
    /// Hard ceiling on `t_cost`. Same DoS rationale as
    /// [`Self::MAX_M_COST_KIB`]. 100 iterations is ~250× the HEAVY
    /// preset's 4 iterations — strictly an upper bound, not a target.
    pub const MAX_T_COST: u32 = 100;
    /// Hard ceiling on `p_cost` (parallelism lanes). 64 lanes is well
    /// above any realistic deployment; the underlying `argon2` crate
    /// also imposes its own per-thread memory minimum which prevents
    /// pathological lane×memory combinations.
    pub const MAX_P_COST: u32 = 64;

    /// Reject params we won't honor: unknown version, below MIN, above
    /// MAX (DoS guards), or outside the underlying argon2 crate's
    /// bounds.
    pub fn validate(&self) -> Result<()> {
        // S1-full layout (audit pass 8): low 16 bits = format version;
        // bits 16..24 = padding policy index (any 0..=255 acceptable —
        // unknown indices are mapped to PaddingPolicy::None on read,
        // not rejected, so older readers see degraded-but-correct
        // behaviour rather than refuse-to-open); bits 24..32 reserved.
        if self.format_version() != PARAMS_VERSION {
            return Err(Error::Kdf("unknown argon2 params version"));
        }
        if (self.version >> 24) != 0 {
            return Err(Error::Kdf(
                "argon2 params version reserved bits (24..32) must be zero",
            ));
        }
        if self.t_cost < Self::MIN.t_cost
            || self.m_cost_kib < Self::MIN.m_cost_kib
            || self.p_cost < Self::MIN.p_cost
        {
            return Err(Error::Kdf("argon2 params below floor"));
        }
        // Upper bounds — closes the cleartext-header DoS where an
        // adversary writes `m_cost_kib = u32::MAX`. See `MAX_M_COST_KIB`
        // doc + `docs/en/security/threat-model.md` §F1.
        if self.m_cost_kib > Self::MAX_M_COST_KIB {
            return Err(Error::Kdf("argon2 m_cost above ceiling"));
        }
        if self.t_cost > Self::MAX_T_COST {
            return Err(Error::Kdf("argon2 t_cost above ceiling"));
        }
        if self.p_cost > Self::MAX_P_COST {
            return Err(Error::Kdf("argon2 p_cost above ceiling"));
        }
        // Verify the argon2 crate also accepts these values (its own
        // upper bounds, lane/memory ratios, etc.).
        argon2::Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(32))
            .map_err(|_| Error::Kdf("argon2 crate rejected params"))?;
        Ok(())
    }

    /// Encode into 16 bytes for storage in the cleartext header.
    /// Layout: [m_cost_kib u32 LE | t_cost u32 LE | p_cost u32 LE | version u32 LE].
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_PARAMS_LEN] {
        let mut buf = [0u8; HEADER_PARAMS_LEN];
        LittleEndian::write_u32(&mut buf[0..4], self.m_cost_kib);
        LittleEndian::write_u32(&mut buf[4..8], self.t_cost);
        LittleEndian::write_u32(&mut buf[8..12], self.p_cost);
        LittleEndian::write_u32(&mut buf[12..16], self.version);
        buf
    }

    /// Decode from 16 bytes. Does NOT call `validate` — caller decides
    /// whether to enforce the floor (e.g. `Container::open` does, but
    /// header introspection tools may skip).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_PARAMS_LEN {
            return Err(Error::Malformed("argon2 params slice too short"));
        }
        Ok(Self {
            m_cost_kib: LittleEndian::read_u32(&bytes[0..4]),
            t_cost: LittleEndian::read_u32(&bytes[4..8]),
            p_cost: LittleEndian::read_u32(&bytes[8..12]),
            version: LittleEndian::read_u32(&bytes[12..16]),
        })
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Derive a 32-byte **versioned master key** from a password, the
/// container salt, and the Argon2 parameter set.
///
/// `salt` MUST be the container_salt at file offset 0..32 (DESIGN §2).
/// `params` MUST have already passed [`Argon2Params::validate`] (caller's
/// responsibility — `Container::open`/`create` enforces this).
///
/// **v3 #9 cryptographic version-binding (2026-05-28).** The
/// `params.version` u32 is folded into the master via a post-Argon2id
/// BLAKE3-keyed step:
///
/// ```text
///   argon_out      = Argon2id(password, salt, m_cost_kib, t_cost, p_cost)
///   versioned_key  = BLAKE3-keyed(argon_out, b"hv/v3/master" ‖ version_le_u32)
/// ```
///
/// Before this step, `version` was only enforced by
/// [`Argon2Params::validate`] (policy-only). After: a hypothetical v4
/// reader that loosens `validate` would still derive a *different*
/// master_key for the same password+salt, because the version is
/// cryptographically bound. Closes the F-PAD-adjacent
/// cross-version key-reuse surface flagged in the `make_aad` rustdoc.
pub fn derive_master_key(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>> {
    if salt.len() != crate::HEADER_SALT_LEN {
        return Err(Error::Internal("salt must be HEADER_SALT_LEN bytes"));
    }
    let a2_params = argon2::Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| Error::Kdf("invalid argon2 params"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, a2_params);

    let mut argon_out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, argon_out.as_mut_slice())
        .map_err(|_| Error::Kdf("argon2 hash failed"))?;

    // v3 #9: BLAKE3-keyed step binding `version` into the master key.
    // The keyed input is `b"hv/v3/master"` (12 bytes) ‖ `version_le_u32`
    // (4 bytes) = 16 bytes total. The context label is fixed; the
    // version bytes are the differentiator. A v3 reader on a v3 file
    // with `params.version` reflecting format_version=3 always
    // computes the same versioned_key; a future v4 reader that
    // accepted format_version=3 input would compute a *different*
    // versioned_key (because its context label would be
    // `b"hv/v4/master"`), so cross-version key reuse is closed.
    let mut input = [0u8; 12 + 4];
    input[..12].copy_from_slice(b"hv/v3/master");
    input[12..].copy_from_slice(&params.version.to_le_bytes());
    let h = blake3::keyed_hash(
        argon_out.as_slice().try_into().expect("argon_out is 32 B"),
        &input,
    );
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(h.as_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    //! Audit pass 10 (I1 + B1 lock-down): unit tests for the
    //! `Argon2Params::version` packed-u32 layout. The accessors
    //! (`format_version`, `padding_policy_index`, `with_padding_policy_index`)
    //! are pure bit-twiddling and don't need a container fixture.

    use super::*;

    fn base() -> Argon2Params {
        Argon2Params::DEFAULT
    }

    /// Round-trip `with_padding_policy_index(idx)` →
    /// `padding_policy_index() == idx` for every persistable preset.
    /// Audit pass 10 I1.
    #[test]
    fn padding_policy_index_round_trip() {
        for idx in [0u8, 1, 2, 3] {
            let p = base().with_padding_policy_index(idx);
            assert_eq!(p.padding_policy_index(), idx, "idx {idx} round-trip");
            assert_eq!(
                p.format_version(),
                PARAMS_VERSION,
                "format_version preserved across with_padding_policy_index({idx})"
            );
        }
    }

    /// `with_padding_policy_index` must zero reserved bits 24..32 even
    /// when the source `version` had them set. Audit pass 9 B1
    /// regression: the `& 0xFFFF` mask in the implementation drops
    /// everything above bit 16 before `(idx << 16)` adds bits 16..24.
    #[test]
    fn with_padding_policy_index_zeroes_reserved_bits() {
        let mut p = base();
        // Manually set reserved bits 24..32 to a non-zero pattern.
        p.version |= 0xAB << 24;
        let cleaned = p.with_padding_policy_index(2);
        assert_eq!(cleaned.padding_policy_index(), 2);
        assert_eq!(
            cleaned.version >> 24,
            0,
            "reserved bits 24..32 must be zeroed by with_padding_policy_index"
        );
        // And the resulting params must validate cleanly.
        cleaned.validate().expect("cleaned params validate");
    }

    /// `format_version()` must extract only the low 16 bits regardless
    /// of what is in bits 16..32. Audit pass 10 I1.
    #[test]
    fn format_version_extracts_low_16_bits_with_noisy_upper() {
        let mut p = base();
        // Cram non-zero bits into 16..32 (policy index + reserved).
        p.version = (PARAMS_VERSION as u32) | (0x03 << 16) | (0xCD << 24);
        assert_eq!(p.format_version(), PARAMS_VERSION);
        assert_eq!(p.padding_policy_index(), 0x03);
    }

    /// `validate()` must reject params with reserved bits 24..32 set.
    /// Audit pass 10 I1: locks down the reserved-bits invariant —
    /// future format-version planning will use these bits, and stale
    /// containers must not pre-emptively claim them.
    #[test]
    fn validate_rejects_non_zero_reserved_bits() {
        let mut p = base();
        // Pack: format_version=1, padding_policy_index=0, reserved=0x01.
        p.version = (PARAMS_VERSION as u32) | (0x01 << 24);
        match p.validate() {
            Err(Error::Kdf(msg)) => {
                assert!(
                    msg.contains("reserved"),
                    "expected reserved-bits error, got {msg:?}"
                );
            },
            other => panic!("expected Err(Kdf reserved...), got {other:?}"),
        }
    }

    /// `validate()` accepts every persistable padding-policy index
    /// (0..=3) when reserved bits are clear. Audit pass 10 I1.
    #[test]
    fn validate_accepts_all_persistable_indices() {
        for idx in [0u8, 1, 2, 3] {
            let p = base().with_padding_policy_index(idx);
            p.validate()
                .unwrap_or_else(|e| panic!("validate() rejected legitimate idx {idx}: {e:?}"));
        }
    }
}
