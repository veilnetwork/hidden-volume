//! In-tree `uniffi-bindgen` driver.
//!
//! Generates foreign-language bindings (Kotlin, Swift, Python, Ruby)
//! against the compiled `hidden-volume-ffi` cdylib.
//!
//! ## Usage
//!
//! Build the cdylib first, then invoke this bin to generate bindings:
//!
//! ```sh
//! # Build the FFI library (cdylib).
//! cargo build -p hidden-volume-ffi --release
//!
//! # Generate Kotlin bindings.
//! cargo run --bin uniffi-bindgen --features bindgen-cli -- \
//!     generate \
//!     --library target/release/libhidden_volume_ffi.so \
//!     --language kotlin \
//!     --out-dir bindings/kotlin
//!
//! # Same for Swift / Python / Ruby:
//! cargo run --bin uniffi-bindgen --features bindgen-cli -- \
//!     generate \
//!     --library target/release/libhidden_volume_ffi.so \
//!     --language python \
//!     --out-dir bindings/python
//! ```
//!
//! Output is plain source files (`hidden_volume_ffi.kt`,
//! `hidden_volume_ffi.swift`, `hidden_volume_ffi.py`,
//! `hidden_volume_ffi.rb`) that integrators drop into their app's
//! source tree alongside the compiled native library.
//!
//! ## Why an in-tree bin instead of `cargo install uniffi-bindgen-cli`?
//!
//! uniffi-bindgen versions are tightly coupled to the runtime crate
//! version. Pinning the bin to the same `uniffi = "0.31"` we use for
//! exports prevents version-skew bugs. Recommended by uniffi upstream
//! since 0.25.

fn main() {
    uniffi::uniffi_bindgen_main()
}
