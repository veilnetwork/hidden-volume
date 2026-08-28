//! A binary whose only job is to make `SpaceKeys::from_master` observable in
//! compiled form (report17 HV17-L4).
//!
//! The question that finding asks — whether deriving the space subkeys leaves
//! unwiped copies on the stack — cannot be answered by reading Rust. The
//! optimiser decides how many copies exist and where, and `Zeroizing`'s
//! volatile writes decide which of them are erased. So it is answered by
//! looking:
//!
//! ```sh
//! cargo build --release -p hidden-volume --example derive_stack_probe
//! otool -tV target/release/examples/derive_stack_probe   # or objdump -d
//! ```
//!
//! Read the body of `..SpaceKeys11from_master` and count two things: the
//! 32-byte moves (`ldp`/`stp` of `q` registers on arm64), and the bytes the
//! function zeroes before returning.
//!
//! Measured 2026-08-27 on arm64, release profile: two moves — each temporary
//! straight into the caller's output, no intermediate arrays — and 64 of 64
//! temporary bytes zeroed. A first reading of this said eight bytes were left
//! behind; that came from a disassembly window that cut the function short,
//! not from the code.
//!
//! What no measurement here can settle: the returned value is moved to the
//! caller, and Rust promises nothing about the slot it was moved out of.

fn main() {
    let master = zeroize::Zeroizing::new([7u8; 32]);
    let keys = hidden_volume::crypto::derive::SpaceKeys::from_master(&master);
    std::hint::black_box(&keys);
}
