//! Fuzz target: `Container::open` on a random byte file.
//!
//! Writes the input bytes to a temporary file and calls
//! `Container::open` on it. Most inputs will fail at the magic check
//! or the header parser; the fuzzer's job is to find inputs that
//! crash the parser, trigger out-of-bounds reads, or cause infinite
//! loops in the discovery scan.
//!
//! Note: this target does NOT exercise post-AEAD-decrypt code paths
//! (every fuzzer-generated chunk fails AEAD against any real key).
//! The complementary `decoder_family` target hits the post-AEAD
//! parsers directly. Both are needed for full coverage.
//!
//! Run with:
//!   cargo +nightly fuzz run container_open
//!
//! Use a small `-max_len` to keep iterations fast — most interesting
//! cases are in the first few KB:
//!   cargo +nightly fuzz run container_open -- -max_len=8192

#![no_main]

use libfuzzer_sys::fuzz_target;
use hidden_volume::Container;

fuzz_target!(|data: &[u8]| {
    let tmp = match tempfile::NamedTempFile::new() {
        Ok(t) => t,
        Err(_) => return,
    };
    if std::fs::write(tmp.path(), data).is_err() {
        return;
    }
    // Open must never panic regardless of file content. AuthFailed,
    // Malformed, Io are all valid — only panics / OOB reads / infinite
    // loops are bugs.
    let _ = Container::open_readonly(tmp.path());
});
