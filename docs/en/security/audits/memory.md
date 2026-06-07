# Memory hygiene audit

🇬🇧 **English** · [🇷🇺 Русский](../../../ru/security/audits/memory.md)

**Status:** v0.5 audit pass complete. Findings + decisions below.

This document tracks every place in the crate that holds key material
or user-secret bytes in memory, the hygiene applied, and any deferred
decisions. Update on every change to crypto / space / tx modules.

## Methodology

- Grep for fixed-size arrays of key length (`[u8; 32]`, `[u8; 24]`,
  `[u8; 16]`).
- Grep for `Vec<u8>` carrying user data (KV values, log payloads,
  decoded plaintexts).
- Trace lifetime: where allocated, what scope, when dropped, whether
  bytes are scrubbed before the heap region is freed.
- Distinguish: **secret material** (zeroize required) vs **public
  material** (no obligation; e.g., container_id, salt, BLAKE3 hashes).

## Findings (current state)

### A. Key material — zeroized ✓

| Item | Location | Mechanism |
|---|---|---|
| Argon2-derived master key | `derive_master_key` return | `Zeroizing<[u8; 32]>` |
| `SpaceKeys.aead_root` | `crypto/derive.rs` | `#[derive(ZeroizeOnDrop)]` on the struct (2026-05-02: `master` and `kdf` fields were unused — removed as dead code) |
| `SpaceState.keys` | `space/mod.rs` | propagated `SpaceKeys` |
| Per-slot AEAD key | `derive_chunk_key` return | `Zeroizing<[u8; 32]>` (fixed in this audit) |
| BLAKE3 keyed-hash subkey | `derive_subkey` return | `Zeroizing<[u8; 32]>` (fixed in this audit) |
| `XChaCha20Poly1305` cipher state | inside `ChunkAead` | `Zeroize` impl on RustCrypto cipher state — automatic via the `cipher` crate's `ZeroizeOnDrop` (no explicit feature gate needed for this crate version) |
| Internal `key32` buffer in `derive_subkey` | `crypto/derive.rs:42` | `Zeroizing<[u8; 32]>` (was `.zeroize()` call; cleaner now) |

### B. Public material — no obligation ✓

| Item | Why not secret |
|---|---|
| `container_id` (`[u8; 32]`) | Stored cleartext in header; serves as AAD prefix |
| Container salt (`[u8; 32]`) | Stored cleartext in header |
| Argon2 params (`u32 × 4`) | Stored cleartext in header |
| Per-record `payload_hash` (BLAKE3) | Hash of already-encrypted ciphertext; reveals nothing |
| `Superblock.root_hash` | Same |
| `IndexRoot.payload_hash` | Same |
| `ChildPointer.child_hash` | Same |
| AEAD nonces (`[u8; 24]`) | Random per-write; OK to retain |
| AEAD AAD (`[u8; 40]`) | `container_id || slot` — both public |

### C. User-secret data — NOT zeroized (deferred)

**See also `docs/en/security/audits/plaintext.md`** for the dedicated audit pass on
plaintext temp buffers (bytes that briefly exist between AEAD seal/open
and the next handoff). That audit complements §C below: the *transient*
pre/post-encryption plaintext buffers ARE wrapped in `Zeroizing` (e.g.
`aead.open` return, `log::encode_batch`/`decode_batch` raw, encoded leaf
bytes before seal); the *user-owned* Vecs listed below remain deferred.

| Item | Risk | Decision |
|---|---|---|
| `Tx.pending_kv: BTreeMap<u8, Vec<KvOp>>` value bytes | KV values held in memory until commit | **Deferred:** wrapping every `Vec<u8>` in `Zeroizing<Vec<u8>>` is invasive across the entire stack. The bytes get encrypted into a chunk plaintext and the original `Vec<u8>` is dropped without scrubbing. |
| `Tx.pending_log` payloads | Same | Same |
| `Plaintext.payload: Vec<u8>` | Decoded chunk plaintext on read; lives until function-scope drop | **Deferred:** same. |
| Compressed batch `raw` in `log::encode_batch` | Pre-zstd plaintext | ✅ **Fixed:** wrapped in `Zeroizing<Vec<u8>>` (`space/log.rs:106`). |
| Decompressed batch `raw` in `log::decode_batch` | Decoded log records | ✅ **Fixed (audit pass 11 M5):** streaming `zstd::Decoder` + `Read::take(MAX_DECODED_BATCH_LEN)` + `Zeroizing<Vec<u8>>` (`space/log.rs:205-219`). |
| Encoded `IndexNode` payload before encryption | `Vec<u8>` | ✅ **Fixed:** wrapped in `Zeroizing<Vec<u8>>` at all 3 call sites (`space/commit.rs:265, 282, 296`). |
| `IndexNodePayload.entries` `Vec<(Vec<u8>, Vec<u8>)>` | Decoded KV entries | **Deferred.** Same rationale as `Tx.pending_kv` values: invasive across many call sites; entries flow into the rendering path of the host-app where the same exposure exists. |

**Rationale for deferring user-data zeroize.** Adding `Zeroizing<Vec<u8>>`
or a `SecretVec` newtype across all KV/log paths touches ~40 call
sites. The threat it addresses (memory-disclosure attacker who reads
freed heap pages) is real but secondary — the same attacker could
read plaintext while the Tx is still alive in memory, or read it from
the rendering path in the host-app. Mitigation has high invasiveness
and modest benefit; tracked as v0.5.x candidate.

For host-apps that NEED memory-disclosure resistance, the recommended
approach is OS-level mlock + private memory mapping for the entire
app process, which protects everything including UI state.

## Verification

The library has automated regression tests for the type-level
guarantees (see `tests/memory_hygiene.rs`):

- `derive_chunk_key` returns `Zeroizing<[u8; 32]>` (compile-time check)
- `derive_subkey` returns `Zeroizing<[u8; 32]>`
- `derive_master_key` returns `Result<Zeroizing<[u8; 32]>>`
- `SpaceKeys` implements `ZeroizeOnDrop`
- The above signatures cannot regress without breaking these tests.

Runtime zeroing of stack memory is not directly observable in safe
Rust; we rely on the `zeroize` crate's careful inline-asm-based
implementation, which the compiler does not optimize away (`#[inline(never)]`
+ `volatile` writes).

## Out-of-scope for this audit

- **Heap leaks via allocator reuse.** Once `Vec<u8>` is dropped, the
  freed pages may be re-allocated for unrelated data. A subsequent
  process reading these pages (via /dev/mem on Linux, or post-mortem
  swap analysis) may find old plaintext. Mitigation requires
  OS-level privileged isolation, not library-level work.
- **CPU side channels.** Spectre-class attacks reading kernel/cipher
  state from speculative execution. Defended only at the OS / CPU
  microcode layer.
- **Forensic RAM dumps.** Cold-boot attacks. Defended only by full-
  disk encryption + secure boot; not a library concern.

## Audit log

| Date | Change | Reviewer |
|---|---|---|
| Initial v0.5 | First pass. Fixed `derive_chunk_key` and `derive_subkey` to return `Zeroizing<[u8; 32]>`. Documented deferred user-data zeroize. | Self-audit |
