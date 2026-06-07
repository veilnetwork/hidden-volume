//! Fuzz target: every public `decode` function in the format-parser
//! family.
//!
//! On real opens, AEAD ensures these decoders only ever see bytes we
//! wrote — but the format constants and the writer can have bugs that
//! produce malformed output, AND format-spec changes have to keep the
//! decoders safe on legacy bytes. This target hits each decoder with
//! arbitrary bytes to verify panic-freedom independent of AEAD.
//!
//! Decoders covered (all from `hidden_volume::*`):
//!   - `chunk::format::Plaintext::decode`
//!   - `space::superblock::Superblock::decode`
//!   - `tx::commit::CommitPayload::decode`
//!   - `space::index::IndexNode::decode` (Leaf + Internal variants)
//!   - `space::log::decode_batch` (zstd-framed)
//!   - `crypto::kdf::Argon2Params::decode`
//!
//! The fuzzer feeds the same input to every decoder. Any panic /
//! abort is a bug.
//!
//! Run with:
//!   cargo +nightly fuzz run decoder_family
//!   cargo +nightly fuzz run decoder_family -- -max_len=8192

#![no_main]

use libfuzzer_sys::fuzz_target;

use hidden_volume::chunk::format::Plaintext;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::IndexNode;
use hidden_volume::space::log::decode_batch;
use hidden_volume::space::superblock::Superblock;
use hidden_volume::tx::commit::CommitPayload;

fuzz_target!(|data: &[u8]| {
    let _ = Plaintext::decode(data);
    let _ = Superblock::decode(data);
    let _ = CommitPayload::decode(data);
    let _ = IndexNode::decode(data);
    let _ = decode_batch(data);
    // Argon2Params::decode handles arbitrary-length input internally
    // (returns Err on too-short).
    let _ = Argon2Params::decode(data);
});
