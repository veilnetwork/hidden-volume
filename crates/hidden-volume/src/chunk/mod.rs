//! On-disk chunk format. See DESIGN §3.

pub mod format;
pub mod kind;

// Audit B13 (2026-05-03): only `Plaintext` and `ChunkKind` are
// consumed via the `chunk::` short path by external callers (tests,
// rustdoc cross-links). `MAGIC` and `PLAINTEXT_HEADER_LEN` had no
// external usage; access them via `chunk::format::MAGIC` /
// `chunk::format::PLAINTEXT_HEADER_LEN` if ever needed.
pub use format::Plaintext;
pub use kind::ChunkKind;
