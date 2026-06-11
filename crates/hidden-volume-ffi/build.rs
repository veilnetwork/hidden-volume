//! Build script for `hidden-volume-ffi`.
//!
//! No `.udl` to compile (we use proc-macro mode), but uniffi still wants
//! its `setup_scaffolding!` macro to find a build-script marker so it
//! emits the right link directives. This empty `build.rs` is enough.

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=build.rs");
}
