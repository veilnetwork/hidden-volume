//! Per-chunk AEAD seal/open. See DESIGN §3.
//!
//! XChaCha20-Poly1305: 192-bit random nonce per chunk (DESIGN §10).
//! AAD = `container_id || u64_le(slot_index)` to bind ciphertext to slot.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::{Error, NONCE_LEN, PLAINTEXT_LEN, Result, TAG_LEN};

/// AAD layout: 32B container_id || 8B slot index.
///
/// Crate-internal (audit B12, 2026-05-03): used by [`ChunkAead::seal`]
/// / [`ChunkAead::open`] array signatures and [`make_aad`] return
/// type. External callers obtain the AAD bytes via [`make_aad`] —
/// no need to reference the constant directly.
pub(crate) const AAD_LEN: usize = 32 + 8;

/// Wrapper around `XChaCha20Poly1305` keyed for one specific chunk.
pub struct ChunkAead {
    cipher: XChaCha20Poly1305,
}

impl core::fmt::Debug for ChunkAead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChunkAead").finish_non_exhaustive()
    }
}

impl ChunkAead {
    /// Construct a [`ChunkAead`] keyed for one specific slot. The key
    /// is moved into the underlying cipher state and zeroized on drop
    /// via RustCrypto's `ZeroizeOnDrop` impl.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(Key::from_slice(key)),
        }
    }

    /// Encrypt `plaintext` (≤ [`PLAINTEXT_LEN`]) under random nonce.
    /// Returns `(nonce, ciphertext_with_tag)`. Caller writes them at the
    /// chunk slot in [nonce | ct | tag] order; the underlying crate appends
    /// the tag to the ciphertext.
    pub fn seal(&self, plaintext: &[u8], aad: [u8; AAD_LEN]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
        if plaintext.len() > PLAINTEXT_LEN {
            return Err(Error::Internal("plaintext exceeds chunk capacity"));
        }
        let nonce = crate::crypto::rng::random_array::<NONCE_LEN>()?;
        let ct = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Internal("aead seal failed"))?;
        debug_assert_eq!(ct.len(), plaintext.len() + TAG_LEN);
        Ok((nonce, ct))
    }

    /// Try to decrypt a chunk. Returns the plaintext on success, or
    /// [`Error::AuthFailed`] on any tag mismatch / wrong key.
    ///
    /// The plaintext is wrapped in [`Zeroizing`] so that when the caller
    /// drops the buffer, the bytes are scrubbed before the heap region
    /// is returned to the allocator. This is the single ingress point
    /// for AEAD-decrypted bytes in the crate; downstream callers
    /// (`Plaintext::decode` and friends) borrow immutably from the
    /// returned wrapper.
    ///
    /// IMPORTANT: callers in the discovery scan path (DESIGN §5) MUST treat
    /// `AuthFailed` as "not our chunk" and continue silently. Do not log
    /// per-chunk failures — that creates an oracle.
    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
        aad: [u8; AAD_LEN],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| Error::AuthFailed)
    }
}

/// Timing equalizer for the **TM1 constant-time scan path** (F-TM1
/// mitigation, audit pass 3 carried-forward #7).
///
/// The default open-scan calls [`ChunkAead::open`], which fails fast
/// on MAC mismatch — the body decrypt is skipped. That short-circuit
/// is the per-chunk timing distinguisher that the TM1 oracle
/// exploits (~40-75 µs/chunk, see threat-model F-TM1 §4.4).
///
/// This function consumes CPU time approximately equal to what a
/// successful body decrypt would take, by running XChaCha20 over a
/// dummy buffer of the same length. The output is discarded. Used by
/// `open/mod.rs::try_decrypt` when the constant-time-scan opt-in is
/// active: after the real AEAD-decrypt returns Err (MAC fail), the
/// equalizer runs, so the total per-chunk wall-clock is approximately
/// the same regardless of ownership.
///
/// **Why this works.** XChaCha20 is constant-time at the primitive
/// level (ADD/XOR/ROTATE on u32 lanes); the time depends only on the
/// input *length*, not on the key, nonce, or input content. So a
/// dummy stream over `body_len` bytes consumes the same CPU time as
/// the real ChaCha20 body decrypt would, for the same length.
///
/// **What this does NOT close.** The branch `if MAC fails then run
/// equalizer` is itself a tiny branch (~ns), which is negligible
/// vs the µs-scale body work. The constant key/nonce avoids setup-
/// time variability.
///
/// **The scratch buffer is thread-local and reused** (audit HV-12).
/// It used to be a fresh `vec![0u8; body_len]` per call, and the only
/// call site passes the compile-time constant [`PLAINTEXT_LEN`] — so
/// every rejected chunk allocated and freed the same ~4 KiB. On a
/// container near the format's 16 M-chunk ceiling that is tens of GB
/// of allocator traffic for one unlock, on the path the FFI takes by
/// default.
///
/// The audit filed this as a side channel; it is not, because a
/// constant size costs a constant amount and so says nothing about the
/// chunk, the key or the tag. If anything the reuse helps the property
/// this function exists for: what it removes is the allocator, whose
/// timing depends on the state of the heap — the one part of the cost
/// nobody controls. What it leaves is the ChaCha20 pass, which is
/// constant-time by construction and one to two orders of magnitude
/// larger than the allocation it replaces.
///
/// Thread-local rather than a shared buffer because the parallel scan
/// runs this on every rayon worker; a lock here would serialise the
/// scan and add contention timing, which really would be a signal.
pub(crate) fn equalize_timing_via_chacha20(body_len: usize) {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    // Constant key + nonce: operations are bit-identical regardless
    // of value, so this introduces no side-channel of its own.
    const EQ_KEY: [u8; 32] = [0u8; 32];
    const EQ_NONCE: [u8; 24] = [0u8; 24];

    thread_local! {
        /// Grown to the largest `body_len` this thread has been asked
        /// for and kept. Contents carry no secret — the input is
        /// whatever keystream the previous call left, and XChaCha20's
        /// timing does not depend on the bytes it is XOR-ing.
        static EQ_SCRATCH: core::cell::RefCell<Vec<u8>> =
            const { core::cell::RefCell::new(Vec::new()) };
    }

    EQ_SCRATCH.with(|scratch| {
        let mut scratch = scratch.borrow_mut();
        if scratch.len() < body_len {
            scratch.resize(body_len, 0);
        }
        let dummy = &mut scratch[..body_len];
        let mut cipher = chacha20::XChaCha20::new(&EQ_KEY.into(), &EQ_NONCE.into());
        cipher.apply_keystream(dummy);
        // Don't optimize the stream away. There is no key material in
        // here to scrub — the buffer never sees plaintext — but the
        // work has to survive the optimizer.
        std::hint::black_box(&dummy);
    });
}

/// Build AAD = container_id || slot_le_u64.
///
/// **What AAD covers.** Slot-shuffle (the `slot` u64 byte) and
/// cross-container chunk move (the 32-byte per-space derived
/// `container_id` — v3 #10).
///
/// **What AAD does NOT cover.** Format version directly. The AAD
/// stays focused on slot + space identity; cross-version protection
/// is bound elsewhere in the key chain:
///
/// 1. **v3 #9 cryptographic version-binding (shipped 2026-05-28)**:
///    [`crate::crypto::kdf::derive_master_key`] folds the entire
///    `Argon2Params.version` u32 into the master key through a
///    post-Argon2id BLAKE3 step (`b"hv/v3/master" || version_le_u32`).
///    Two containers with identical password, salt, container_id,
///    slot, and Argon2 cost params but different `format_version`
///    derive **different** master keys (and therefore different
///    per-slot AEAD keys). Cross-version key reuse is closed
///    cryptographically, not only by policy.
/// 2. **Policy enforcement at open time** —
///    [`crate::crypto::kdf::Argon2Params::validate`] rejects unknown
///    `format_version` values, so a v3 reader cannot open a v1/v2
///    container at all (and vice versa). The currently shipped
///    format is `format_version = 3` (cluster: #8 kind-tag bytes +
///    #9 cryptographic version-binding + #10 per-space derived
///    `container_id`, 2026-05-28); v1/v2 containers are rejected on
///    open.
///
/// Together (1) + (2) close cross-version chunk replay both
/// cryptographically and by policy. A hypothetical future v4 reader
/// that loosened `validate` would still derive a *different* master
/// key for the same password+salt because the BLAKE3 label is
/// `b"hv/v3/master"` — closing the surface that was historically
/// flagged here as "lock-down for any future format bump".
#[must_use]
pub fn make_aad(container_id: &[u8; 32], slot: u64) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[..32].copy_from_slice(container_id);
    aad[32..].copy_from_slice(&slot.to_le_bytes());
    aad
}
