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
#[derive(Debug, Clone)]
pub struct Plaintext {
    /// Discriminator for the payload encoding (Superblock / IndexNode
    /// / Commit / DataBatch / …).
    pub kind: ChunkKind,
    /// Per-space monotonic sequence (DESIGN §3, §6).
    pub seq: u64,
    /// Kind-specific encoded payload bytes (≤ [`PAYLOAD_CAP`]).
    pub payload: Vec<u8>,
}

impl Plaintext {
    /// Serialize into exactly [`PLAINTEXT_LEN`] bytes, padding the tail with
    /// random data. Random padding ensures pre-encryption plaintext is not
    /// trivially structured (defense-in-depth; AEAD already encrypts).
    pub fn encode(&self) -> Result<[u8; PLAINTEXT_LEN]> {
        if self.payload.len() > PAYLOAD_CAP {
            return Err(Error::Internal("payload exceeds chunk capacity"));
        }
        let mut buf = [0u8; PLAINTEXT_LEN];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4] = self.kind as u8;
        // buf[5] = 0 (reserved flags byte; see file header doc).
        // Already zero from array init — no explicit write.
        LittleEndian::write_u64(&mut buf[6..14], self.seq);
        LittleEndian::write_u16(&mut buf[14..16], self.payload.len() as u16);
        buf[PLAINTEXT_HEADER_LEN..PLAINTEXT_HEADER_LEN + self.payload.len()]
            .copy_from_slice(&self.payload);
        // Random pad the rest. AEAD will encrypt it; this is just to avoid
        // any chance of leaking via plaintext length oracle if a future
        // bug removes the AEAD layer.
        let pad_start = PLAINTEXT_HEADER_LEN + self.payload.len();
        crate::crypto::rng::fill(&mut buf[pad_start..])?;
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
