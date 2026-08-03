# Plaintext-leak audit

🇬🇧 **English** · [🇷🇺 Русский](../../../ru/security/audits/plaintext.md)

**Status:** v0.5 first pass complete. All transient pre/post-encryption
buffers wrapped in `Zeroizing`; long-lived user-data buffers explicitly
deferred (cross-referenced in [`memory.md`](memory.md)).

This document complements [`memory.md`](memory.md). The memory-hygiene audit
focuses on **key material** lifetimes; this audit focuses on **plaintext
data** — bytes that have just been (or are about to be) AEAD-decrypted /
AEAD-sealed and that briefly live in heap or stack memory.

The threat addressed: a memory-disclosure adversary (allocator reuse,
swap pages, /dev/mem on a compromised host) that reads freed regions
shortly after the library finishes a chunk read or write. Per-chunk
keys are already zeroized (memory audit §A); plaintext is the next
layer.

## Methodology

1. Enumerate every code path where plaintext bytes exist between AEAD
   open/seal and the function boundary.
2. Classify by lifetime:
   - **Transient** — buffer lives only inside the encrypt or decrypt
     wrapper function; once it returns, the bytes are no longer
     reachable through any owned reference.
   - **User-owned** — buffer is created from / handed off to user
     code; lifetime is dictated by the caller, not the library.
3. For transient buffers, wrap in `zeroize::Zeroizing` so the heap
   region is scrubbed at drop time.
4. For user-owned buffers, document the deferral and cross-reference
   [`memory.md`](memory.md) §C.

## Transient plaintext sites — wrapped ✓

| Site | Buffer | Type | Lifetime |
|---|---|---|---|
| `crypto::aead::ChunkAead::open` (return value) | full decrypted chunk plaintext | `Zeroizing<Vec<u8>>` | one chunk read; drops at end of caller's read fn |
| `space::Space::append_chunk` (`pt_bytes`) | encoded `Plaintext` (`[u8; PLAINTEXT_LEN]`) prior to seal | `Zeroizing<[u8; PLAINTEXT_LEN]>` | one chunk write; drops at end of fn |
| `space::log::encode_batch` (`raw`) | concatenated record bytes prior to zstd | `Zeroizing<Vec<u8>>` | feeds zstd, then drops |
| `space::log::decode_batch` (`raw`) | zstd-decompressed record bytes | `Zeroizing<Vec<u8>>` | walked once to slice out per-record `payload`, then drops |
| `space::Space::write_tree_for_namespace` (single-leaf `bytes`) | `LeafNode::encode()` output prior to AEAD seal | `Zeroizing<Vec<u8>>` | feeds `append_chunk`, then drops |
| `space::Space::write_tree_for_namespace` (per-leaf `bytes` in split) | `LeafNode::encode()` output | `Zeroizing<Vec<u8>>` | feeds `append_chunk`, then drops |
| `space::Space::write_tree_for_namespace` (`internal` `bytes`) | `InternalNode::encode()` output (carries user `first_key` bytes) | `Zeroizing<Vec<u8>>` | feeds `append_chunk`, then drops |

Indirect (already covered by upstream RustCrypto):

| Site | Buffer | Mechanism |
|---|---|---|
| `chacha20poly1305::XChaCha20Poly1305` internal scratch | per-call cipher state | `chacha20` and `aead` crates impl `ZeroizeOnDrop` for cipher state |
| Per-slot AEAD key passed to `ChunkAead::new` | `[u8; 32]` | `derive_chunk_key` returns `Zeroizing<[u8; 32]>` — wiped after `ChunkAead` is constructed |

## User-owned plaintext sites — deferred (host-app controls)

These are buffers that the library produces or accepts as part of its
public API. Wrapping them in `Zeroizing` would change public
signatures and force every host-app to adopt the wrapper or fight type
errors. The cost-benefit is unfavorable for v0.5; the threat is real
but secondary (the same memory-disclosure adversary has access to the
host-app's UI buffers, IME caches, etc., where user data also lives).

| Site | Buffer | Reason for deferral |
|---|---|---|
| `Plaintext.payload: Vec<u8>` | decoded chunk payload | Fields used pervasively across `space/`, `tx/`, `chunk/`; would force `Zeroizing<Vec<u8>>` through `Plaintext::decode` and break test assertions on equality with raw `Vec<u8>`. The full pre-decode buffer (the `aead.open` return) IS wrapped, so the broader plaintext is already scrubbed; only this `to_vec()`-copied subrange escapes. |
| `Space::get(...) -> Vec<u8>` return | KV value handed to caller | Library can't dictate the host-app's storage lifetime. |
| `Space::list / iter_log / read_log` returns | KV / log records handed to caller | Same. |
| `log::decode_batch` returned `Vec<(u64, Vec<u8>)>` per-record `payload` | per-record plaintext copied out of the wrapped `raw` buffer | Same as `Plaintext.payload` — copied subrange escapes. |

## Internal copies — closed by `Redacted<T>` (audit HV-01 / HV-07)

The three deferrals above (`Tx::pending_kv`, `Tx::pending_log`,
`IndexNode::Leaf.entries`) are closed. The `SecretVec` newtype this
document called a v0.5.x candidate now exists as
[`redact::Redacted<T>`](../../../../crates/hidden-volume/src/redact.rs): it
`Deref`s to `T`, so read and mutate call sites are unchanged, and it does
two things on top.

| Field | Now | Scrubbed when |
|---|---|---|
| `Tx::pending_kv` | `Redacted<PendingKv>` | `commit_tx` returns — success **and** error paths, since the wrapper is moved into it |
| `Tx::pending_log` | `Redacted<PendingLog>` | same, plus per-namespace re-wrapping inside the Phase-0 drain |
| `LeafNode::entries` | `Redacted<Vec<(Vec<u8>, Vec<u8>)>>` | the decoded node drops |
| `ChildPointer::first_key` | `Redacted<Vec<u8>>` | same |
| `SpaceState::roots_payload_cache` | `Option<(u64, Redacted<Vec<u8>>)>` | the commit era ends (was `Zeroizing`, which scrubs but does not redact) |

**What this promises, exactly.** The crate's *internal* copies of a
decrypted key, value or payload do not outlive the operation that built
them. It is **not** a claim that a plaintext is gone from the process: a
`Vec` that grew during construction left an earlier allocation behind, the
value the API *returns* is owned by the caller, and across UniFFI it is
copied into a foreign heap this crate never sees. Those are still the
host-app's, and the `mlock` + hardened-allocator recommendation below is
still the answer for them.

## Formatting is a second leak class (audit HV-01)

`Zeroizing` scrubs on drop and says nothing about `{:?}` — the upstream
crate *derives* `Debug` on it, so a `Zeroizing<Vec<u8>>` prints its bytes
verbatim. Redaction is therefore a separate mechanism, not a side effect of
zeroizing, and it is enforced by two rules:

1. A plaintext-bearing field is typed `Redacted<T>`, whose `Debug` prints
   `{ items, bytes }` and never content. Safe under `#[derive(Debug)]`,
   safe printed on its own, safe if a later author pulls it into a
   `debug_struct`.
2. Its carrier's `Debug` is written by the `redacted_debug!` allow-list
   macro and ends in `finish_non_exhaustive()`, so a field added later is
   not printed at all until someone names it.

The first rule alone is what the previous pass tried and missed with: it
redacted `KvOp`, `WriteOp`, `LogEntry` and `Plaintext`, and left `Tx`,
`LeafNode`, `ChildPointer`, `SpaceState` and `Space` deriving `Debug` over
them. The second rule is what makes a *newly added* field safe without
anyone remembering to act. `tests/debug_redaction.rs` is the sentinel.

**Recommendation for host-apps that need stronger guarantees.** Run
the entire process under `mlock` + private memory mapping + a
hardened allocator (e.g. `secret-allocator`). That defends UI state,
swap, and library state uniformly without per-API plumbing.

## Why we wrap transient buffers but not user-owned ones

Wrapping a transient buffer is **invisible to the public API**: callers
of `aead.open` see auto-deref of `Zeroizing<Vec<u8>>` to `Vec<u8>` to
`&[u8]`; nothing breaks. Wrapping a user-owned buffer is a **breaking
public API change** that propagates to every caller and gets cargo-cult
copied through host-apps regardless of whether they actually need the
guarantee.

The asymmetry: transient wraps are pure win (one-line change, scrub on
drop, no API surface impact). User-owned wraps are a tradeoff and
should follow demand from concrete host-apps with concrete threat
models. Defer until v0.5.x has at least one host-app driving the
requirement.

## Stack vs. heap

- **Heap** (`Vec<u8>`): freed pages can be re-allocated for unrelated
  data. `Zeroizing<Vec<u8>>` overwrites the contents in the
  destructor before the allocation is returned. ✓
- **Stack** (`[u8; PLAINTEXT_LEN]` in `append_chunk`): the stack frame
  is reused on the next function call without being scrubbed by
  default. `Zeroizing<[u8; N]>` runs `Zeroize for [T; N]` (since
  `zeroize` 1.6) on drop, scrubbing the stack region. ✓

The compiler is allowed to optimize away dead writes — the `zeroize`
crate guards against this with `#[inline(never)]` + volatile writes
in the impl. We rely on that guarantee; it has held up in the crate's
audit history.

## Out-of-scope for this audit

- **Compiler-optimized stack scratch** in cryptographic primitives
  (e.g. ChaCha20 round state). RustCrypto handles this; we don't
  reach into `chacha20poly1305`'s internals.
- **CPU register spills** of plaintext bytes during AEAD operations.
  Defended only at the CPU microcode / OS-context-switch level.
- **Compiler reordering of zeroize writes**. `zeroize` uses
  `core::ptr::write_volatile` to prevent this; we trust the crate.

## Audit log

| Date | Change | Reviewer |
|---|---|---|
| audit HV-01 / HV-07 | Closed the `Tx::pending_kv` / `Tx::pending_log` / `LeafNode::entries` deferrals with `redact::Redacted<T>`, extended it to `ChildPointer::first_key` and `SpaceState::roots_payload_cache`, and separated redaction from zeroizing (`Zeroizing` derives `Debug`). Added `tests/debug_redaction.rs`. | Self-audit |
| Initial v0.5 | First pass. Wrapped 7 transient plaintext sites (1 in `aead`, 1 in `space::append_chunk`, 2 in `space::log`, 3 in `space::write_tree_for_namespace`). Documented 7 user-owned sites as deferred with cross-ref to [`memory.md`](memory.md) §C. Added `tests/plaintext_hygiene.rs` for type-level regression checks. | Self-audit |

## Cross-references

- `docs/en/security/threat-model.md` §3 (M1 invariant) — formal statement this audit pass supports
- `docs/en/security/audits/memory.md` §C — overlapping deferrals for user-data Vecs
- `docs/en/security/audits/constant-time.md` — constant-time pass (companion audit)
- `docs/en/security/audits/fsync.md` — fsync ordering pass (companion audit)
- `tests/memory_hygiene.rs` — type-level regression for derived keys
- `tests/plaintext_hygiene.rs` — type-level regression for plaintext wraps
- `tests/debug_redaction.rs` — sentinel for the `Debug`-redaction contract
