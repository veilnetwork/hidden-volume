//! Fuzz target: `Plaintext::decode` on arbitrary bytes.
//!
//! `Plaintext::decode` is the entry point for every chunk's
//! post-AEAD-decrypt parsing. AEAD only succeeds on bytes WE wrote,
//! but a bug in our writer or a torn-write could produce a
//! "valid-looking" plaintext frame the decoder mishandles.
//!
//! Goal: assert that for any input bytes, `decode` either returns
//! `Ok(Plaintext)` or `Err(Error::Malformed)` — **never panics, never
//! aborts, never reads out of bounds**.
//!
//! Run with:
//!   cargo +nightly fuzz run plaintext_decode
//!
//! Stop with Ctrl-C. Crashes are written to `fuzz/artifacts/plaintext_decode/`
//! and replayable via `cargo +nightly fuzz run plaintext_decode <path>`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use hidden_volume::chunk::format::Plaintext;

fuzz_target!(|data: &[u8]| {
    // Decoder must be panic-free on every input.
    let _ = Plaintext::decode(data);
});
