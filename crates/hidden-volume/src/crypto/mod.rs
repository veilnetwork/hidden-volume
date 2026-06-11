//! Cryptographic primitives. See DESIGN §3 (chunk format) and §4 (key schedule).

pub mod aead;
pub mod derive;
pub mod kdf;
pub mod rng;

pub use aead::ChunkAead;
pub use derive::{SpaceKeys, derive_chunk_key};
pub use kdf::{Argon2Params, derive_master_key};
