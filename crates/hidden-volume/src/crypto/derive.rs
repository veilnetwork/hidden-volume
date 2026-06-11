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

use zeroize::{ZeroizeOnDrop, Zeroizing};

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
    #[must_use]
    pub fn from_master(versioned_master: &Zeroizing<[u8; 32]>) -> Self {
        let container_id_z = derive_subkey(versioned_master.as_slice(), b"hv/v3/container_id");
        let aead_root_z = derive_subkey(versioned_master.as_slice(), b"hv/v3/aead_root");
        let mut container_id = [0u8; 32];
        container_id.copy_from_slice(container_id_z.as_slice());
        let mut aead_root = [0u8; 32];
        aead_root.copy_from_slice(aead_root_z.as_slice());
        Self {
            container_id,
            aead_root,
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
    let h = hasher.finalize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(h.as_bytes());
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
    let h = blake3::keyed_hash(aead_root, &input);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(h.as_bytes());
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
