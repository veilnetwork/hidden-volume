//! Cleartext container header (DESIGN §2).
//!
//! **v3 layout (2026-05-28).** 48 bytes of structured header:
//! salt (32) + Argon2 params (16). The 32-byte container_id field
//! from v2 is **removed** — `container_id` is now derived per-space
//! inside [`crate::crypto::derive::SpaceKeys::from_master`] from the
//! versioned master key. The rest of the first chunk (bytes 48
//! through `CHUNK_SIZE`) is uniform random padding.
//!
//! Closes the D1-A2 per-space-identifier fingerprint at file
//! offset 32..64. Argon2Params at offset 32..48 is retained — it
//! enables F-PAD-class persistent padding-policy (`Argon2Params.version`
//! bits 16..24, audit pass 8 S1 full) without regression, and is
//! itself a small (16-byte) and acknowledged fingerprint with a
//! documented out-of-scope decision in threat-model §3.D1.
//!
//! Cross-container relocation defense is preserved: different files
//! have different salts → different master_keys (even with the same
//! password) → different per-space `container_id`s → AAD differs.

use crate::crypto::kdf::Argon2Params;
use crate::{
    CHUNK_SIZE, Error, HEADER_LEN, HEADER_PARAMS_LEN, HEADER_PARAMS_OFFSET, HEADER_SALT_LEN,
    HEADER_SALT_OFFSET, Result,
};

/// Parsed cleartext container header — the first 48 bytes of a
/// container file (salt + Argon2 params). See
/// `docs/en/reference/format.md` §1.1 for the v3 byte layout.
#[derive(Debug, Clone)]
pub struct Header {
    /// 32 random bytes used as the Argon2id salt
    /// (`HEADER_SALT_OFFSET`).
    pub salt: [u8; HEADER_SALT_LEN],
    /// Encoded Argon2id parameters (`HEADER_PARAMS_OFFSET`, 16 bytes).
    pub params: Argon2Params,
}

impl Header {
    /// Generate a fresh random header for a new container with the
    /// given validated Argon2 params. Caller MUST have already called
    /// `params.validate()`. The salt is `getrandom`-fresh;
    /// `container_id` is no longer stored in v3 (it is derived per-
    /// space at open / create time inside `SpaceKeys::from_master`).
    pub fn new_random(params: Argon2Params) -> Result<Self> {
        Ok(Self {
            salt: crate::crypto::rng::random_array()?,
            params,
        })
    }

    /// Parse from the first `HEADER_LEN` bytes of the file. Performs
    /// `validate()` on params and returns an error if they're below
    /// the floor or use an unknown version.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Malformed("file shorter than header"));
        }
        let mut salt = [0u8; HEADER_SALT_LEN];
        salt.copy_from_slice(&bytes[HEADER_SALT_OFFSET..HEADER_SALT_OFFSET + HEADER_SALT_LEN]);
        let params = Argon2Params::decode(
            &bytes[HEADER_PARAMS_OFFSET..HEADER_PARAMS_OFFSET + HEADER_PARAMS_LEN],
        )?;
        params.validate()?;
        Ok(Self { salt, params })
    }

    /// Encode the entire first-chunk region: structured header +
    /// random padding to `CHUNK_SIZE`. The padding ensures the first
    /// chunk is indistinguishable in size from any other chunk.
    ///
    /// v3 layout: salt (0..32) and Argon2 params (32..48) are the
    /// structured prefix; bytes 48..`CHUNK_SIZE` are uniform random
    /// padding. (The v2 `container_id` field at offset 32..64 is gone
    /// — params now occupy its former start, and everything past the
    /// 48-byte header is padding.)
    pub fn encode_first_chunk(&self) -> Result<[u8; CHUNK_SIZE]> {
        let mut buf = [0u8; CHUNK_SIZE];
        buf[HEADER_SALT_OFFSET..HEADER_SALT_OFFSET + HEADER_SALT_LEN].copy_from_slice(&self.salt);
        buf[HEADER_PARAMS_OFFSET..HEADER_PARAMS_OFFSET + HEADER_PARAMS_LEN]
            .copy_from_slice(&self.params.encode());
        // Random-pad everything past the 48-byte structured header.
        // (v3 has no gap between salt and params — `HEADER_SALT_LEN ==
        // HEADER_PARAMS_OFFSET == 32` — so the only padding region is
        // `HEADER_LEN..CHUNK_SIZE`. Audit pass 20 removed a vestigial
        // `fill(&mut buf[32..32])` no-op left over from the v2 layout
        // where container_id sat between salt and params.)
        crate::crypto::rng::fill(&mut buf[HEADER_LEN..])?;
        Ok(buf)
    }
}
