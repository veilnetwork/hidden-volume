//! `hidden-volume` — deniable multi-space encrypted append-only container.
//!
//! A storage primitive for messengers and other apps that need
//! plausible-deniability against compelled-key disclosure: a single file
//! can hold an arbitrary number of independent encrypted spaces, and an
//! adversary with the file plus one password cannot prove that other
//! spaces exist.
//!
//! ## Where to start
//!
//! - **Building a host-app?** Read `docs/en/guide/integration.md` — narrative
//!   tour of every API a messenger needs (quickstart, pagination,
//!   cancellation, multi-device, integrity, key caching, anti-patterns).
//! - **Building P2P sync?** Read `docs/en/guide/multi-device.md` for the
//!   sync / anchor / rollback-detection contract.
//! - **Auditing crypto choices?** Read `DESIGN.md` (formal spec) and
//!   the `docs/*_AUDIT.md` family (`CT_AUDIT`, `MEMORY_AUDIT`,
//!   `PLAINTEXT_AUDIT`, `FSYNC_AUDIT`).
//!
//! `DESIGN.md` at the crate root is the formal specification — threat
//! model, on-disk format, invariants. This documentation is the
//! integrator-facing summary; for any conflict, `DESIGN.md` wins.
//!
//! # What this protects
//!
//! - **Confidentiality** of every space against any party without its
//!   password (XChaCha20-Poly1305 per chunk, Argon2id KDF).
//! - **Cross-space isolation**: opening space A neither reveals nor can
//!   accidentally corrupt space B (per-space keys + append-only file).
//! - **Single-snapshot deniability** (D1): the file is statistically
//!   indistinguishable from a uniform-random blob with one 48-byte
//!   cleartext header (salt + Argon2 params; v3 #10 removed the
//!   per-space `container_id` field — it is now per-space derived
//!   from the versioned master key).
//! - **Compelled-key deniability** (D2): predicating a password yields
//!   one space; the holder of *that* password cannot prove the
//!   existence of others.
//! - **Per-chunk integrity**: byte modification produces an AEAD
//!   failure on the affected chunk.
//!
//! # What this does NOT protect against
//!
//! Read this list carefully — a hidden-volume file is only as deniable
//! as the host application's behavior around it.
//!
//! - **Side-channel leaks at the application layer** — recently-opened
//!   files, IME caches, screenshot thumbnails, swap, system logs. The
//!   library can't see those; the host-app must.
//! - **Multi-snapshot byte-diff analysis** (T2'): in-place rewrite or
//!   tombstone of an existing slot leaves a "this byte changed" signal
//!   that distinguishes active slots from genuine garbage. See
//!   `DESIGN.md` §1 for the full out-of-scope list.
//! - **Rollback attacks**: if the adversary captures the file at time
//!   T₁ and restores it after the user has committed at T₂, the user
//!   loses recent state and the library can't detect it. Use
//!   [`Space::commit_seq`] from a host-app rollback anchor.
//! - **The fact that the file is encrypted** — high-entropy files are
//!   visible to any forensic scan. Deniability is about *which* and
//!   *how many* secrets are inside, not about hiding that the file is
//!   a ciphertext.
//!
//! # Hardware tuning (weak vs strong devices)
//!
//! The Argon2 cost is per-container, set at creation time, and stored
//! in the cleartext header. Pick a preset that matches the target
//! device class:
//!
//! | Preset | m | t | p | Use case |
//! |---|---|---|---|---|
//! | [`Argon2Params::LIGHT`]   | 16 MiB |  3 | 1 | Low-end ARM (Cortex-A53, embedded) |
//! | [`Argon2Params::DEFAULT`] | 64 MiB |  3 | 1 | Mid-range mobile (last 5y phones) |
//! | [`Argon2Params::HEAVY`]   | 256 MiB | 4 | 4 | Desktop / server-class hardware |
//!
//! [`Argon2Params::MIN`] is the floor below which the library refuses
//! to open or create a container — protection against malicious-host
//! attacks that would force a victim into a trivially brute-forceable
//! parameter set.
//!
//! # Quick start
//!
//! ```no_run
//! use hidden_volume::{Container, crypto::kdf::Argon2Params};
//! use hidden_volume::space::index::Namespace;
//!
//! # fn main() -> hidden_volume::Result<()> {
//! // Create a container (host-app picks Argon2 cost based on device class).
//! let mut container = Container::create("/path/to/messenger.store",
//!                                       Argon2Params::DEFAULT)?;
//!
//! // First space — typically the user's main profile.
//! {
//!     let mut space = container.create_space(b"main-password")?;
//!     let mut tx = space.begin_tx();
//!     tx.put(Namespace::SETTINGS, b"username", b"alice")?;
//!     tx.put(Namespace::CONTACTS, b"bob", b"bob@example.com")?;
//!     tx.commit()?;
//! } // drop releases borrow on container
//!
//! // Hidden second space, completely independent.
//! {
//!     let mut hidden = container.create_space(b"hidden-password")?;
//!     let mut tx = hidden.begin_tx();
//!     tx.put(Namespace::SETTINGS, b"username", b"actual-identity")?;
//!     tx.commit()?;
//! }
//!
//! // Reopen and read back.
//! let mut container = Container::open("/path/to/messenger.store")?;
//! let mut main = container.open_space(b"main-password")?;
//! assert_eq!(
//!     main.get(Namespace::SETTINGS, b"username")?.as_deref(),
//!     Some(&b"alice"[..])
//! );
//! # Ok(())
//! # }
//! ```
//!
//! # Layering
//!
//! - [`crypto`]    — primitives: KDF, AEAD, key derivation, RNG.
//! - [`chunk`]     — fixed-size on-disk chunk format (DESIGN §3).
//! - [`container`] — file-level append-only operations and header (DESIGN §2).
//! - [`space`]     — per-space keys, superblock, B+ tree index, DataBatch log, vacuum / scrub, integrity walk (DESIGN §4–§7). The v0.1 `journal` chunk was superseded by vacuum + scrub-old-on-success (TASKS.md v0.2 SKIPPED).
//! - [`tx`]        — transactional KV writes within a space.
//! - [`padding`]   — garbage/dummy-write policies (DESIGN §8).
//!
//! Discovery scan and recovery (DESIGN §5, §7) live in the
//! crate-private `open` module; not part of the public API.
//!
//! # Status
//!
//! Pre-1.0 freeze. v0.1 through v0.7 closed (foundation, KV +
//! transactions, repack/integrity, locking + multi-device, hardening +
//! audits, performance, async wrapper). v0.8 FFI scaffold (sync +
//! async sibling surfaces) shipped; iOS xcframework / Android
//! `.aar` / Flutter sample app remain platform-toolchain-bound.
//! Remaining v1.0 work is release engineering + external crypto
//! review. The async wrapper lives in the sibling
//! `hidden-volume-async` crate; FFI bindings in `hidden-volume-ffi`.
//! See `TASKS.md` for the live backlog and `CHANGELOG.md` for the
//! per-pass cleanup history.
//!
//! [`Argon2Params::LIGHT`]: crate::crypto::kdf::Argon2Params::LIGHT
//! [`Argon2Params::DEFAULT`]: crate::crypto::kdf::Argon2Params::DEFAULT
//! [`Argon2Params::HEAVY`]: crate::crypto::kdf::Argon2Params::HEAVY
//! [`Argon2Params::MIN`]: crate::crypto::kdf::Argon2Params::MIN

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
#![deny(missing_docs)]

pub mod cancel;
pub mod chunk;
pub mod container;
pub mod crypto;
pub mod error;
// `open` is the discovery-scan implementation — every fn inside is
// `pub(crate)`. Module visibility was `pub` historically as a no-op;
// audit B8 (2026-05-02) tightened it to crate-private to match
// reachability.
pub mod multi;
pub(crate) mod open;
pub mod padding;
pub mod space;
pub mod tx;

pub use container::Container;
pub use error::{Error, Result};
pub use multi::MultiSpace;
pub use open::MAX_OPEN_SCAN_CHUNKS;
pub use space::Space;

/// Size of a single chunk on disk, in bytes. Fixed by the format
/// (DESIGN §10). Never change without a format-version bump.
pub const CHUNK_SIZE: usize = 4096;

// Wire-format header constants. Audit B11 (2026-05-03): only
// **v3 layout (2026-05-28).** 48 bytes of structured header: salt
// at 0..32 + Argon2Params at 32..48. The v2 `container_id` field at
// offset 32..64 is **removed** — `container_id` is derived per-space
// inside `SpaceKeys::from_master`. Bytes 32..48 (v3 params) and
// 48..CHUNK_SIZE (random padding) replace the v2 layout. See
// `docs/en/reference/format.md` §1.1.

/// Size of the structured part of the cleartext container header
/// (salt + Argon2Params). The remainder of the first `CHUNK_SIZE`
/// bytes is uniform random padding.
pub(crate) const HEADER_LEN: usize = 48;

/// Bytes 0..32 of the file: KDF salt for all spaces in this container.
pub(crate) const HEADER_SALT_OFFSET: usize = 0;
/// Length of the KDF salt at [`HEADER_SALT_OFFSET`] (32 bytes).
pub(crate) const HEADER_SALT_LEN: usize = 32;

/// Bytes 32..48 of the file: encoded [`crypto::Argon2Params`].
/// See DESIGN §11.1 — params live per-container so host-app can tune
/// for the device class without touching format spec. The v3 layout
/// drops the v2-era container_id field that previously occupied
/// offset 32..64, shifting params to 32..48 (the rest of the v2
/// container_id slot becomes random padding).
pub const HEADER_PARAMS_OFFSET: usize = 32;
/// Length of the encoded `Argon2Params` block at
/// [`HEADER_PARAMS_OFFSET`] (16 bytes).
pub const HEADER_PARAMS_LEN: usize = 16;

/// First slot starts at this absolute file offset.
pub(crate) const FIRST_SLOT_OFFSET: u64 = CHUNK_SIZE as u64;

/// AEAD nonce length (XChaCha20-Poly1305).
pub const NONCE_LEN: usize = 24;

/// AEAD authentication tag length.
pub const TAG_LEN: usize = 16;

/// Bytes available for plaintext inside one chunk after nonce + tag.
pub const PLAINTEXT_LEN: usize = CHUNK_SIZE - NONCE_LEN - TAG_LEN;

const _: () = assert!(CHUNK_SIZE > NONCE_LEN + TAG_LEN);
const _: () = assert!(HEADER_LEN <= CHUNK_SIZE);
const _: () = assert!(HEADER_SALT_OFFSET + HEADER_SALT_LEN == HEADER_PARAMS_OFFSET);
const _: () = assert!(HEADER_PARAMS_OFFSET + HEADER_PARAMS_LEN == HEADER_LEN);
