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
  material** (no obligation; e.g., salt, BLAKE3 hashes).

## Findings (current state)

### A. Key material — zeroized ✓

| Item | Location | Mechanism |
|---|---|---|
| Argon2-derived master key | `derive_master_key` return | `Zeroizing<[u8; 32]>` |
| `SpaceKeys.aead_root` | `crypto/derive.rs` | `#[derive(ZeroizeOnDrop)]` on the struct (2026-05-02: `master` and `kdf` fields were unused — removed as dead code) |
| `SpaceState.keys` | `space/mod.rs` | propagated `SpaceKeys` |
| `container_id` (`[u8; 32]`) | inside `SpaceKeys` | Zeroized with the rest of `SpaceKeys`. **Corrected 2026-08-02 (audit H-06):** this row used to sit under §B "public material" saying "stored cleartext in header". That was true in v2; v3 #10 derives `container_id` from the versioned master key and removed it from the cleartext header, so it became secret-derived while the doc still called it public — and `SpaceState` still kept a second plain `[u8; 32]` copy that nothing erased. The duplicate is gone; read `state.keys.container_id`. |
| Per-slot AEAD key | `derive_chunk_key` return | `Zeroizing<[u8; 32]>` (fixed in this audit) |
| BLAKE3 keyed-hash subkey | `derive_subkey` return | `Zeroizing<[u8; 32]>` (fixed in this audit) |
| `XChaCha20Poly1305` cipher state | inside `ChunkAead` | `Zeroize` impl on RustCrypto cipher state — automatic via the `cipher` crate's `ZeroizeOnDrop` (no explicit feature gate needed for this crate version) |
| Internal `key32` buffer in `derive_subkey` | `crypto/derive.rs:42` | `Zeroizing<[u8; 32]>` (was `.zeroize()` call; cleaner now) |
| Argon2 working memory | the matrix passed to `hash_password_into_with_memory`, `crypto/kdf.rs` | `Zeroizing<Vec<argon2::Block>>`. **Added 2026-08-10 (report9 HV-15):** this table accounted for the derived KEY and not for the buffer it was derived in — m_cost KiB, 64 MiB at the defaults and up to 512 MiB, holding the password's expansion and freed as-is. **Corrected 2026-09-03 (report22 HV-KDF-WIPE):** this row used to credit the `argon2` crate's `zeroize` feature, and that feature does not wipe anything. It gives `Block` an inherent `zeroize()` and NO `Drop`, and `hash_password_into_with_memory` never touches the caller's buffer — so for a year the row claimed a wipe that no code performed, and the guarding test only checked that the feature appeared in `Cargo.toml`. The feature makes the wipe expressible; the `Zeroizing` around the matrix is what runs it, on the success path, the error path and an unwind alike. |
| Transient `blake3::Hash` / `Hasher` | `derive_master_key`, `derive_subkey`, `derive_chunk_key` | `blake3` crate's `zeroize` feature plus an explicit `.zeroize()`. **Added 2026-08-10 (report9 HV-15):** each `Zeroizing` return above was copied OUT of a `Hash` that is the key itself, and that copy was dropped without a wipe. The keyed `Hasher` in `derive_subkey` holds key-equivalent state for the same reason. |

### B. Public material — no obligation ✓

| Item | Why not secret |
|---|---|
| Container salt (`[u8; 32]`) | Stored cleartext in header |
| Argon2 params (`u32 × 4`) | Stored cleartext in header |
| Per-record `payload_hash` (BLAKE3) | Hash of already-encrypted ciphertext; reveals nothing |
| `Superblock.root_hash` | Same |
| `IndexRoot.payload_hash` | Same |
| `ChildPointer.child_hash` | Same |
| AEAD nonces (`[u8; 24]`) | Random per-write; OK to retain |
| AEAD AAD (`[u8; 40]`) | `container_id \|\| slot`. NOT public since v3 — see §A. The AAD is written to disk beside every chunk regardless, so it is not a retention question; it is listed here only so the table accounts for it. |

### C. User-secret data — who owns it, and what clears it

**See also `docs/en/security/audits/plaintext.md`** for the dedicated audit pass
on plaintext temp buffers (bytes that briefly exist between AEAD seal/open and
the next handoff). That audit is about the transient buffers; this section is
the inventory of the OWNERS.

This section used to be titled "NOT zeroized (deferred)" and listed the four
owners below as open decisions. They were closed one at a time, and the table
was not updated with them — so the document told a reader the library leaves
user plaintext in the heap when it had not done so for some time
(report24 HV24-D1). What is written here now is the current contract; the
history of how it got here is in the audit table at the end of this file.

| Owner | What it holds | How it is cleared |
|---|---|---|
| `Tx::pending_kv` | KV keys and values, until commit | `Redacted<PendingKv>` (`tx/mod.rs`), whose `scrub_secret` zeroizes every key and value before clearing the map |
| `Tx::pending_log` | Log payloads, until commit | `Redacted<PendingLog>` (`tx/mod.rs`), same rule; `commit_tx` re-wraps what it drains so the drained copy is scrubbed too |
| `Plaintext::payload` | A decoded chunk on read — a message, an index node, a key/value pair | `Drop` zeroizes it (`chunk/format.rs`), so the bytes do not outlive the struct that decoded them |
| `LeafNode::entries` | The decoded `(key, value)` pairs of a leaf — the densest concentration of user plaintext in the format | `Redacted<Vec<(Vec<u8>, Vec<u8>)>>` (`space/index.rs`) |
| Compressed batch `raw` in `log::encode_batch` | Pre-zstd plaintext | Returned as `Zeroizing<Vec<u8>>` (`space/log.rs`) |
| Decompressed batch `raw` in `log::decode_batch` | Decoded log records | `Zeroizing<Vec<u8>>` **before the first read into it**, so the two error exits between hand back a scrubbed buffer as well (`space/log.rs`) |
| Encoded index node before encryption | `Vec<u8>` | `Zeroizing<Vec<u8>>` at both build sites (`space/tree.rs`) |

**What this does NOT claim.** Clearing an owner is about the heap AFTER it is
done with — a crash dump, a swap file or a core taken later. It says nothing
about plaintext that is still live: an attacker who can read this process's
memory while a `Tx` is open, or read the host-app's rendering path, sees the
same bytes either way. A host that needs resistance to that wants OS-level
mlock and a private mapping for the whole process, which covers UI state too.

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
| 2026-09-09 | §C rewritten as an inventory of owners. The four deferrals it listed had each been closed — `Redacted` on the transaction's pending maps and on a leaf's entries, `Drop` on `Plaintext` — and the table was never updated with them, so the document claimed an exposure the library did not have (report24 HV24-D1). | Self-audit |
