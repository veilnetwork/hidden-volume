//! BLAKE3-keyed subkey derivation. See DESIGN §4.
//!
//! ## Format v3 key schedule (2026-05-28)
//!
//! Three changes from v2:
//!
//! 1. **#9 cryptographic version-binding.** The `format_version` is
//!    folded into the master key via a post-Argon2 BLAKE3 step (see
//!    `kdf::derive_master_key`). Cross-version key reuse is closed
//!    cryptographically, not only by `validate()` policy.
//!
//! 2. **#8 kind-tag bytes for domain separation.** Every BLAKE3 input
//!    in the key chain now starts with an explicit kind-tag byte
//!    (`0x01` for `derive_subkey`, `0x02` for `derive_chunk_key`).
//!    Replaces the fragile «input-length distinguishes purpose»
//!    convention that audit pass 7 D3 documented but did not enforce.
//!
//! 3. **#10 per-space derived `container_id`.** The 32-byte
//!    `container_id` is no longer stored in the cleartext header — it
//!    is derived per-space alongside `aead_root` from the versioned
//!    master key. Closes the specific D1-A2 fingerprint signature for
//!    multi-space containers: nothing in the cleartext header carries
//!    a per-space identifier any more.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Kind-tag byte for `derive_subkey` inputs (audit pass 2 P-LOW2,
/// closed in v3). Makes domain separation explicit by content rather
/// than implicit-by-input-length.
const SUBKEY_KIND_TAG: u8 = 0x01;

/// Kind-tag byte for [`derive_chunk_key`] inputs.
const CHUNK_KEY_KIND_TAG: u8 = 0x02;

/// Per-space derived keys. Held only in memory while a space is open.
///
/// Drop-time zeroing is enforced via [`ZeroizeOnDrop`]. Do NOT log, format,
/// or serialize these.
///
/// **v3 update.** `container_id` is now derived per-space from the
/// versioned master key, rather than read from the cleartext header.
/// Cross-container relocation defense is preserved (different salts ⇒
/// different master_keys ⇒ different container_ids), and the cleartext
/// header no longer carries a per-space identifier (closes the D1-A2
/// fingerprint that exposed «this is a hidden-volume container with
/// space N»).
#[derive(Clone, ZeroizeOnDrop)]
pub struct SpaceKeys {
    /// 32-byte per-space binding identifier used as the first half of
    /// AAD and as part of the per-slot AEAD-key derivation input. In
    /// v3 this is derived from the versioned master key; in v2 it was
    /// read from `Header.container_id`.
    pub container_id: [u8; 32],
    /// Sub-derivation key for chunk-AEAD keys (per slot).
    /// Consumed by [`derive_chunk_key`].
    pub aead_root: [u8; 32],
}

impl core::fmt::Debug for SpaceKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpaceKeys").finish_non_exhaustive()
    }
}

impl SpaceKeys {
    /// Build the per-space subkey schedule from the **versioned**
    /// master key (post-Argon2id, post-BLAKE3-version-bind — see
    /// [`crate::crypto::kdf::derive_master_key`]). Derives both
    /// `container_id` and `aead_root` via `derive_subkey` with
    /// distinct context labels.
    /// ## Copies of the derived bytes
    ///
    /// The two subkeys arrive in `Zeroizing` temporaries, whose drop wipes
    /// them, and go straight into the returned struct — which is
    /// `ZeroizeOnDrop`. There are no named intermediate arrays: they existed
    /// here, were not wiped, and are the copies report17 HV17-L4 asks about.
    ///
    /// What was MEASURED rather than reasoned (arm64, release profile): the
    /// optimiser had already elided those arrays, both temporaries were
    /// copied directly into the caller's output, and all 64 bytes of them
    /// were zeroized by the volatile writes `Zeroizing` performs. Writing the
    /// source this way stops that resting on the optimiser.
    ///
    /// What is still not guaranteed, and cannot be from within Rust: the
    /// returned value is moved to the caller, and the language promises
    /// nothing about the slot it was moved out of.
    #[must_use]
    pub fn from_master(versioned_master: &Zeroizing<[u8; 32]>) -> Self {
        Self {
            container_id: *derive_subkey(versioned_master.as_slice(), b"hv/v3/container_id"),
            aead_root: *derive_subkey(versioned_master.as_slice(), b"hv/v3/aead_root"),
        }
    }
}

/// Derive a 32-byte subkey via BLAKE3 keyed-hash.
///
/// **v3 input layout.** `BLAKE3-keyed(parent, [SUBKEY_KIND_TAG] ‖
/// context)`. The leading kind-tag byte `0x01` makes domain
/// separation from [`derive_chunk_key`] (kind tag `0x02`) explicit
/// — replaces the audit-pass-7-D3 length-based convention.
///
/// `parent` must be 32 bytes (zero-pads if shorter — caller's
/// responsibility to pass the right thing).
///
/// Returns a [`Zeroizing`] wrapper so the derived bytes are scrubbed
/// on drop even if the caller stores them in a temporary stack
/// variable.
///
/// **Zero-allocation since audit pass 19 follow-through (2026-05-28).**
/// The kind-tag byte is fed into `blake3::Hasher` via a separate
/// `.update(&[SUBKEY_KIND_TAG])` call rather than concatenating into
/// an owned `Vec<u8>`. BLAKE3 is incremental (each `.update(...)`
/// appends to the same internal state), so the streamed form is
/// bit-identical to the concatenated form. This keeps `derive_subkey`
/// on the "no heap allocation on the hot crypto path" discipline
/// that [`derive_chunk_key`] already follows with its stack
/// `[u8; 41]` input.
#[must_use]
pub(crate) fn derive_subkey(parent: &[u8], context: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key32 = Zeroizing::new([0u8; 32]);
    let n = parent.len().min(32);
    key32[..n].copy_from_slice(&parent[..n]);
    // v3 #8: kind-tag byte 0x01 prefixed before the context label,
    // ensures domain separation from `derive_chunk_key` inputs. Fed
    // through BLAKE3's incremental `update` API to avoid a heap
    // allocation that would otherwise hold the kind-tag ‖ context
    // bytes briefly on every per-space init.
    let mut hasher = blake3::Hasher::new_keyed(&key32);
    hasher.update(&[SUBKEY_KIND_TAG]);
    hasher.update(context);
    // Both the hasher's state and the finalized hash are key-equivalent here:
    // the hash IS the subkey. Neither was wiped (report9 HV-15).
    let mut h = hasher.finalize();
    hasher.zeroize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(h.as_bytes());
    h.zeroize();
    out
}

/// Derive the AEAD key for a specific slot index. See DESIGN §4.
///
/// **v3 input layout.** `BLAKE3-keyed(aead_root, [CHUNK_KEY_KIND_TAG] ‖
/// container_id (32) ‖ slot_le_u64 (8))` = 1 + 40 = 41 bytes. The
/// kind-tag byte `0x02` makes the input self-describing relative to
/// `derive_subkey` (`0x01`); replaces the D3 length-convention
/// (audit pass 7) with type-system-equivalent content distinction.
///
/// Returns a [`Zeroizing`] wrapper so per-slot derived keys are
/// scrubbed on drop. The AEAD cipher state internally zeroizes its
/// key copy (via `chacha20`'s `ZeroizeOnDrop` impl), so once the
/// caller has constructed the cipher, dropping the [`Zeroizing`]
/// handle is the last thing that holds the raw bytes.
#[must_use]
pub fn derive_chunk_key(
    aead_root: &[u8; 32],
    container_id: &[u8; 32],
    slot: u64,
) -> Zeroizing<[u8; 32]> {
    let mut input = [0u8; 1 + 32 + 8];
    input[0] = CHUNK_KEY_KIND_TAG;
    input[1..33].copy_from_slice(container_id);
    input[33..].copy_from_slice(&slot.to_le_bytes());
    // The hash IS the chunk key, and this runs once per chunk read or
    // written — the highest-traffic key site in the crate (report9 HV-15).
    let mut h = blake3::keyed_hash(aead_root, &input);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(h.as_bytes());
    h.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Type-level regression test: `derive_subkey` must return
    /// `Zeroizing<[u8; 32]>`. If a future change drops the `Zeroizing`
    /// wrapper from the return type this won't compile.
    /// See `docs/en/security/audits/memory.md`. Moved here from
    /// `tests/memory_hygiene.rs` after audit B6 made the function
    /// `pub(crate)`.
    #[test]
    fn derive_subkey_returns_zeroizing() {
        let parent = [0u8; 32];
        let result: Zeroizing<[u8; 32]> = derive_subkey(&parent, b"context");
        let _ref: &[u8; 32] = &result;
    }
}

#[cfg(test)]
mod hv15_wipe_reach_tests {
    /// The key-equivalent transients must stay wiped, and the crate features
    /// that make wiping possible must stay on.
    ///
    /// A source and manifest check, because the effect is invisible from
    /// inside the process: proving a freed buffer was scrubbed means reading
    /// memory after it is released, which is undefined behaviour, not a test.
    /// What can rot is the wiring — a dependency feature dropped in a
    /// dependency bump, or a `.zeroize()` lost in a refactor — and both are
    /// facts about files (report9 HV-15).
    /// The subkeys go straight into the struct, with nothing named on the way.
    ///
    /// report17 HV17-L4 asked whether `from_master` leaves plaintext key
    /// material on the stack. It does not — measured on the disassembly, and
    /// the source was tidied so the two derived keys are moved into the
    /// fields at the point they are produced, with no intermediate binding
    /// that outlives its `Zeroizing` wrapper.
    ///
    /// That conclusion has been the ONLY finding in the report resting on a
    /// measurement nobody re-runs. A disassembly test would pin a particular
    /// compiler; what can actually rot is the shape of the function, so the
    /// shape is what is held. Cut at this module for the same reason the
    /// check below is: an assertion that contains its own needle counts
    /// itself.
    #[test]
    fn from_master_names_no_intermediate_key() {
        // Read with line endings normalised: a Windows checkout hands
        // `include_str!` CRLF, and a needle written with "\n" then
        // matches nothing. The three tests that read source this way
        // failed only there.
        let source = include_str!("derive.rs").replace("\r\n", "\n");
        let production = &source[..source
            .find("mod hv15_wipe_reach_tests")
            .expect("this module moved — the guard is reading the wrong region")];

        let at = production
            .find("pub fn from_master(")
            .expect("from_master moved or was renamed");
        let body = &production[at..];
        let body = &body[..body.find("\n    }\n").expect("no end of from_master")];

        assert_eq!(
            body.matches("derive_subkey(").count(),
            2,
            "from_master no longer derives both subkeys, so the check below              is about nothing"
        );
        assert!(
            !body.contains("let "),
            "from_master binds a name on the way to the struct:\n{body}\n\
             a local holding the dereferenced key outlives the Zeroizing that              was supposed to wipe it"
        );
    }

    #[test]
    fn the_key_equivalent_transients_are_still_wiped() {
        let manifest = include_str!("../../Cargo.toml");
        for (dep, why) in [
            (
                "argon2",
                "Argon2's working memory is the password's expansion, tens of \
                 mebibytes of it, and without this feature it is freed as-is",
            ),
            (
                "blake3",
                "a keyed Hasher's state and a Hash are the derived key itself, \
                 and neither implements Zeroize without this feature",
            ),
        ] {
            let line = manifest
                .lines()
                .find(|l| l.starts_with(dep))
                .unwrap_or_else(|| panic!("{dep} is no longer a direct dependency"));
            assert!(
                line.contains("\"zeroize\""),
                "{dep} lost its zeroize feature: {why}"
            );
        }

        // Cut at this module: the assertions below contain the very literals
        // they look for, and counting them made the check count itself.
        let derive = include_str!("derive.rs");
        let derive = &derive[..derive
            .find("mod hv15_wipe_reach_tests")
            .expect("this module moved — the guard is reading the wrong region")];
        let kdf = include_str!("kdf.rs");
        assert_eq!(
            derive.matches("h.zeroize();").count(),
            2,
            "derive_subkey and derive_chunk_key each wipe the hash they copy \
             the key out of — one of them stopped"
        );
        assert!(
            derive.contains("hasher.zeroize();"),
            "the keyed hasher in derive_subkey holds key-equivalent state and \
             is no longer wiped"
        );
        assert!(
            kdf.contains("h.zeroize();"),
            "the master key's hash is no longer wiped"
        );
    }
}
