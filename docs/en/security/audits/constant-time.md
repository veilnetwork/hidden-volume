# Constant-time audit

🇬🇧 **English** · [🇷🇺 Русский](../../../ru/security/audits/constant-time.md)

**Status:** v0.5 first pass complete. **No constant-time issues found.**

This document records the methodology and findings of the
constant-time (CT) audit on `hidden-volume`. Update on every change to
the `crypto/` module or any code that handles password/key material.

## Methodology

A timing side channel exists when a comparison or branch's wall-clock
duration depends on a secret value. We grep'd for every `==` / `!=`
operator in `src/`, classified each by what it compares, and asked:

  > Could an attacker who is **not in the process** observe this
  > timing AND learn something useful from it?

If yes → use `subtle::ConstantTimeEq`. If no → vanilla `==` is fine.

## Scope (where CT actually matters)

Three concrete attack vectors that CT compares defend against:

1. **Password verification.** Comparing a stored password hash with a
   user-supplied attempt. `hidden-volume` does NOT store password
   hashes — passwords go through Argon2id, the result is a key, the
   key is used to drive AEAD-decrypt, and the AEAD tag check is the
   pass/fail signal. **No password hash compare exists in our code.**

2. **AEAD authentication tag verification.** A non-CT compare of the
   tag would let an attacker forge ciphertexts byte-by-byte using
   timing. `hidden-volume` does NOT compare tags directly — it
   delegates to `chacha20poly1305::XChaCha20Poly1305::decrypt` which
   uses a CT compare internally (Poly1305 by construction).

3. **Hash-of-secret comparisons.** Comparing `H(secret)` byte-by-byte
   with an expected value can leak prefix matches. `hidden-volume`
   uses BLAKE3 hashes as integrity tags on **already-encrypted**
   chunks; the hashed bytes are public ciphertext + AAD. **No hash
   of plaintext-secret is compared.**

In short: every secret-relevant compare in this crate happens inside
RustCrypto's `chacha20poly1305` and `argon2` crates, both of which are
constant-time by design. **There is no CT compare in our own code that
would close a timing channel.**

## Comparison-by-comparison audit

Every `==` and `!=` operator in `src/` (as of audit time):

| Comparison | Operands | Sensitivity | Verdict |
|---|---|---|---|
| `params.version != PARAMS_VERSION` | u32 vs u32 | public params | OK |
| `salt.len() != HEADER_SALT_LEN` | usize vs usize | length | OK |
| `pt.kind == ChunkKind::Superblock` | enum vs enum | discriminant (public type tag) | OK |
| `pt.kind != ChunkKind::DataBatch` | same | same | OK |
| `pt.kind != ChunkKind::Commit` | same | same | OK |
| `pt.kind != ChunkKind::IndexNode` | same | same | OK |
| `key.len() != 8` | length check | public | OK |
| `r.namespace == ns` | u8 newtype | namespace tag (public) | OK |
| `root_slot == NO_RECORD` | u64 vs sentinel | slot index (public) | OK |
| `len % CHUNK_SIZE as u64 != 0` | u64 modulo | file size (public) | OK |
| `bytes[0] != NODE_TYPE_LEAF / INTERNAL` | u8 byte | type tag (public) | OK |
| `klen == 0`, `klen > MAX_KEY_LEN` | u16 | length bounds | OK |
| `buf[0..4] != MAGIC` | bytes vs constant | magic bytes are public | OK |
| `namespace == Namespace::RESERVED` | u8 vs sentinel | public | OK |
| `*id == log_id` (in `find_in_batch`) | u64 vs u64 | log_id is caller-supplied (the caller already knows it) | OK |
| `value.len() != 8` | length | OK |
| `source == dest` | path | filesystem identity, public | OK |

No comparison is on:
- raw key material (`SpaceKeys.aead_root` — `master` and `kdf`
  fields removed in 2026-05-02 cleanup as dead code; only
  `aead_root` is consumed by `derive_chunk_key`)
- per-chunk derived keys
- AEAD tags
- password bytes
- hash outputs over plaintext-secret data

## Defense-in-depth: where CT is safe to add

If we ever want defense-in-depth (in case a future change introduces
a sensitive compare), the [`crate::crypto::ct`] module exposes
helpers backed by [`subtle::ConstantTimeEq`]:

```rust
use hidden_volume::crypto::ct;
let same = ct::eq_32(&hash_a, &hash_b);
let same_slice = ct::eq_slice(&buf_a, &buf_b);
```

These compile to the same code as `==` would, except via `subtle`'s
volatile-write tricks the comparison cannot be short-circuited by the
compiler.

## What this audit does NOT cover

- **Argon2id timing.** The KDF itself is timing-stable in the RustCrypto
  implementation; we trust their audit. A faster password derives the
  same way as a slower one.
- **AEAD decrypt timing on full chunks.** ~5 µs per 4 KiB chunk; doesn't
  vary based on key correctness within a few bits — chacha20poly1305
  always processes the full block, and the tag check at the end is CT.
- **BLAKE3 keyed-hash timing.** Output time depends only on input length,
  not key content. RustCrypto blake3 is CT.
- **CPU-level side channels** (Spectre, MDS, BHB). Defended at OS / CPU
  microcode level, not by library-level CT compares.
- **Cache timing on memory access patterns** (e.g., B+ tree walks may
  reveal which key was looked up via cache hit/miss patterns). Not
  applicable to local-storage messenger workloads — attacker has no way
  to time these from outside the process. For network-facing code the
  story is different and out of scope here.

## Audit log

| Date | Change | Reviewer |
|---|---|---|
| Initial v0.5 | First pass. Audited 17 distinct comparisons across `src/`; none operate on secret data. Codebase is CT-safe by virtue of delegating all secret-touching ops to RustCrypto crates. Added `crypto::ct` placeholder module for forward-compatible CT helpers. | Self-audit |
