//! Chunk plaintext encoding. See DESIGN §3.
//!
//! Plaintext layout (inside the AEAD-protected region; never visible
//! without the key):
//!
//! ```text
//!   offset  0  : magic   [u8; 4]   = b"HVC1"
//!   offset  4  : kind    u8
//!   offset  5  : flags   u8
//!   offset  6  : seq     u64 LE
//!   offset 14  : payload_len u16 LE  (≤ PAYLOAD_CAP)
//!   offset 16  : payload  [u8; payload_len]
//!   offset 16+payload_len : random padding to PLAINTEXT_LEN
//! ```

use byteorder::{ByteOrder, LittleEndian};

use super::kind::ChunkKind;
use crate::{Error, PLAINTEXT_LEN, Result};

/// Plaintext-frame magic bytes (`b"HVC1"`). Inside AEAD only — never
/// visible without the key. Acts as a defence-in-depth sanity check
/// after a successful decrypt.
pub const MAGIC: [u8; 4] = *b"HVC1";

/// Plaintext header bytes before the payload area.
pub const PLAINTEXT_HEADER_LEN: usize = 4 + 1 + 1 + 8 + 2;

/// Maximum payload bytes per chunk.
pub const PAYLOAD_CAP: usize = PLAINTEXT_LEN - PLAINTEXT_HEADER_LEN;

// Byte 5 (offset 5 within the plaintext header) is reserved for
// forward-compat flags. v1 requires this byte == 0; non-zero values
// are rejected as `Error::Malformed("non-zero reserved flags")`.
// Future format generations may use individual bits for compression,
// continuation, etc. — strict validation here ensures a v2 reader
// can detect a forward-format chunk and a v1 reader explicitly fails
// rather than silently accepting unknown semantics.

/// Decrypted chunk frame (`MAGIC` + `kind` + reserved-flags-byte +
/// `seq` + `payload_len` + `payload` + random pad). See
/// `docs/en/reference/format.md` §2.2 for the byte layout.
///
/// The reserved flags byte at offset 5 is not exposed in this struct —
/// it is hard-coded to 0 on encode and strictly validated on decode.
#[derive(Clone)]
pub struct Plaintext {
    /// Discriminator for the payload encoding (Superblock / IndexNode
    /// / Commit / DataBatch / …).
    pub kind: ChunkKind,
    /// Per-space monotonic sequence (DESIGN §3, §6).
    pub seq: u64,
    /// Kind-specific encoded payload bytes (≤ [`PAYLOAD_CAP`]).
    pub payload: Vec<u8>,
}

impl core::fmt::Debug for Plaintext {
    /// REDACTED (audit HV-09). The derive printed `payload` — the decrypted
    /// bytes of a message, an index node or a key/value pair — so any
    /// `{:?}`, any `assert_eq!` failure and any panic backtrace that happened
    /// to carry one wrote user plaintext into a log or a crash dump. A
    /// deniable store cannot have a type whose default formatting undoes it.
    ///
    /// Lengths and discriminators are kept: they are what a diagnostic
    /// actually needs, and they are already inferable from the file's shape.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Plaintext")
            .field("kind", &self.kind)
            .field("seq", &self.seq)
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl Plaintext {
    /// Serialize into a caller-owned [`PLAINTEXT_LEN`] buffer, padding the
    /// tail with random data. Random padding ensures pre-encryption plaintext
    /// is not trivially structured (defense-in-depth; AEAD already encrypts).
    ///
    /// The buffer is the caller's so it can be wrapped in `Zeroizing` BEFORE
    /// the first fallible step. Filling one here and returning it by value put
    /// two unscrubbed copies of the payload on the stack — the local, which a
    /// CSPRNG failure in the padding left behind fully populated, and the move
    /// out of it — and only the caller's third copy was ever wiped (report13
    /// HV13-L5). `payload` is borrowed for the same reason: the caller had to
    /// own one to build a `Plaintext`, and that copy was wiped by nothing.
    pub fn encode_into(
        kind: ChunkKind,
        seq: u64,
        payload: &[u8],
        buf: &mut [u8; PLAINTEXT_LEN],
    ) -> Result<()> {
        if payload.len() > PAYLOAD_CAP {
            return Err(Error::Internal("payload exceeds chunk capacity"));
        }
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4] = kind as u8;
        // Byte 5 is the reserved flags byte (see file header doc) and must be
        // zero. Written rather than assumed: the buffer is the caller's now,
        // and a reused one carries whatever was there before.
        buf[5] = 0;
        LittleEndian::write_u64(&mut buf[6..14], seq);
        LittleEndian::write_u16(&mut buf[14..16], payload.len() as u16);
        buf[PLAINTEXT_HEADER_LEN..PLAINTEXT_HEADER_LEN + payload.len()].copy_from_slice(payload);
        // Random pad the rest. AEAD will encrypt it; this is just to avoid
        // any chance of leaking via plaintext length oracle if a future
        // bug removes the AEAD layer.
        let pad_start = PLAINTEXT_HEADER_LEN + payload.len();
        crate::crypto::rng::fill(&mut buf[pad_start..])?;
        Ok(())
    }

    /// [`Self::encode_into`] into a fresh buffer, returned by value.
    ///
    /// For tests and fuzz targets, which want the bytes rather than a place to
    /// put them. The write path takes `encode_into` so the frame never exists
    /// outside a `Zeroizing`.
    pub fn encode(&self) -> Result<[u8; PLAINTEXT_LEN]> {
        let mut buf = [0u8; PLAINTEXT_LEN];
        Self::encode_into(self.kind, self.seq, &self.payload, &mut buf)?;
        Ok(buf)
    }

    /// Parse a decrypted plaintext buffer.
    ///
    /// Returns [`Error::Malformed`] only after AEAD has already verified the
    /// chunk belongs to this space — meaning a malformed plaintext at this
    /// stage is an internal-format bug, not a deniability issue.
    ///
    /// Strict-mode forward-compat: byte 5 (reserved flags) MUST be 0
    /// in v1. Non-zero values are rejected. This ensures a v1 reader
    /// won't silently accept a v2-format chunk under unknown semantics.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() != PLAINTEXT_LEN {
            return Err(Error::Internal("plaintext buffer wrong length"));
        }
        if buf[0..4] != MAGIC {
            return Err(Error::Malformed("plaintext magic mismatch"));
        }
        let kind = ChunkKind::from_u8(buf[4])?;
        if buf[5] != 0 {
            return Err(Error::Malformed("non-zero reserved flags"));
        }
        let seq = LittleEndian::read_u64(&buf[6..14]);
        let payload_len = LittleEndian::read_u16(&buf[14..16]) as usize;
        if payload_len > PAYLOAD_CAP {
            return Err(Error::Malformed("payload_len exceeds capacity"));
        }
        let payload = buf[PLAINTEXT_HEADER_LEN..PLAINTEXT_HEADER_LEN + payload_len].to_vec();
        Ok(Self { kind, seq, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The frame must define every byte it owns, because the buffer is the
    /// caller's now and a caller reuses buffers.
    ///
    /// `encode` used to start from a fresh zeroed array, so the reserved flags
    /// byte at offset 5 was correct by accident of initialization. Filling a
    /// caller-supplied buffer, that accident is gone: a non-zero byte 5 left
    /// over from a previous frame is rejected by `decode` as
    /// "non-zero reserved flags".
    #[test]
    fn encoding_into_a_dirty_buffer_leaves_nothing_of_what_was_there() {
        let mut fresh = [0u8; PLAINTEXT_LEN];
        Plaintext::encode_into(ChunkKind::IndexNode, 7, b"abc", &mut fresh).unwrap();
        let mut dirty = [0xAAu8; PLAINTEXT_LEN];
        Plaintext::encode_into(ChunkKind::IndexNode, 7, b"abc", &mut dirty).unwrap();

        // The random pad differs by design; the defined prefix must not.
        let defined = PLAINTEXT_HEADER_LEN + 3;
        assert_eq!(fresh[..defined], dirty[..defined]);
        let decoded = Plaintext::decode(&dirty).unwrap();
        assert_eq!(decoded.payload, b"abc");
        assert_eq!(decoded.seq, 7);
    }

    /// An over-long payload is refused before the buffer is touched, so the
    /// caller's `Zeroizing` never holds a partial frame it did not ask for.
    #[test]
    fn an_oversized_payload_is_refused_without_writing() {
        let mut buf = [0u8; PLAINTEXT_LEN];
        let payload = vec![1u8; PAYLOAD_CAP + 1];
        assert!(Plaintext::encode_into(ChunkKind::IndexNode, 1, &payload, &mut buf).is_err());
        assert!(buf.iter().all(|&b| b == 0), "a refused encode wrote anyway");
    }
}
