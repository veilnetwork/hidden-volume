# Format-fuzzing analysis

**Date.** 2026-05-28. **Pass.** 4 of 5 in the deeper-review series.
**Reviewer.** LLM-assisted. **Scope.** Formal boundary enumeration
of every `decode` entry point + inventory of the existing fuzzing
infrastructure that covers each boundary.

## Methodology

Every byte that crosses into the library can hit a `decode`
function. The threat model treats those decoders as "untrusted
input" surface — AEAD-protected on the on-disk path (so the
attacker shouldn't be able to reach the decoders without the key),
but a writer-side regression or a torn write could still feed a
decoder malformed bytes that *did* AEAD-decrypt.

This pass:

1. Enumerates every `pub` `decode` (and `from_u8`) entry point.
2. For each, lists the boundary classes (truncation, oversized
   length, bad discriminator, sortedness, etc.).
3. Maps each boundary to its **defending code** and to the
   **existing fuzz/proptest test** that exercises it.
4. Flags any boundary that is not covered, with a
   recommendation.

Severity legend unchanged from prior passes.

## Headline

**0 CRITICAL / 0 HIGH / 0 MEDIUM, 0 LOW, 1 INFO.** Fuzz coverage
is *comprehensive*: 3 cargo-fuzz targets (nightly), 9 proptest
"decode-doesn't-panic" properties + 6 encode/decode roundtrip
properties (stable, on every CI run). Every boundary I could
enumerate maps to a specific test. The single INFO observation:

- **FZ-INFO1.** The proptest layer is integration-level (cargo
  test --test parser_fuzz) and runs 512 cases per property per
  CI run. The cargo-fuzz layer runs nightly with continue-on-
  error in `.github/workflows/ci.yml`. There is no
  CI-failure-on-fuzz-finding gate; fuzz findings would surface
  as `fuzz-crashes` artifacts rather than blocking the release.
  Trade-off documented in [`docs/en/security/audits/fsync.md`](fsync.md)
  + [TASKS.md F-3 v1.x](../../../TASKS.md). Not a current bug;
  noted for completeness.

## Inventory: existing fuzz / proptest coverage

### cargo-fuzz targets ([`crates/hidden-volume/fuzz/fuzz_targets/`](../../../crates/hidden-volume/fuzz/fuzz_targets/))

| Target | What it fuzzes | Reaches post-AEAD code? |
|---|---|---|
| `container_open.rs` | Full `Container::open` on a random-bytes file | No (most chunks fail AEAD; tests pre-AEAD parsers) |
| `decoder_family.rs` | Every public `decode` function with arbitrary bytes | Yes — bypasses AEAD entirely |
| `plaintext_decode.rs` | `Plaintext::decode` only, deep coverage | Yes |

Trigger: nightly `fuzz-smoke` job in `.github/workflows/ci.yml`
(continue-on-error). Local run: `cargo +nightly fuzz run <target>`.

### proptest properties ([`crates/hidden-volume/tests/parser_fuzz.rs`](../../../crates/hidden-volume/tests/parser_fuzz.rs))

| Property | Decoder | Phase | Cases per CI run |
|---|---|---|---|
| `plaintext_decode_doesnt_panic` | `Plaintext::decode` | 1 (don't panic) | 512 |
| `argon2_params_decode_doesnt_panic` | `Argon2Params::decode` | 1 | 512 |
| `header_decode_doesnt_panic` | `Header::decode` | 1 | 512 |
| `superblock_decode_doesnt_panic` | `Superblock::decode` | 1 | 512 |
| `commit_payload_decode_doesnt_panic` | `CommitPayload::decode` | 1 | 512 |
| `leaf_node_decode_doesnt_panic` | `LeafNode::decode` | 1 | 512 |
| `internal_node_decode_doesnt_panic` | `InternalNode::decode` | 1 | 512 |
| `index_node_decode_doesnt_panic` | `IndexNode::decode` (dispatcher) | 1 | 512 |
| `batch_decode_doesnt_panic` | `decode_batch` (zstd) | 1 | 512 |
| `argon2_params_roundtrip` | encode→decode | 2 | 128 |
| `superblock_roundtrip` | encode→decode | 2 | 128 |
| `leaf_node_roundtrip` | encode→decode | 2 | 128 |
| `internal_node_roundtrip` | encode→decode | 2 | 128 |
| `commit_payload_roundtrip` | encode→decode | 2 (incl. R-NSKIND kind alternation) | 128 |
| `batch_roundtrip` | encode→decode | 2 | 128 |

Trigger: every `cargo test` run (workspace test gate).

### Additional crash / property tests

- [`tests/crash_recovery.rs`](../../../crates/hidden-volume/tests/crash_recovery.rs) —
  deterministic crash-injection tests for the 3-fsync protocol.
- [`tests/crash_proptest.rs`](../../../crates/hidden-volume/tests/crash_proptest.rs) —
  proptest with crash-injection at arbitrary byte boundaries.
- [`tests/property_full.rs`](../../../crates/hidden-volume/tests/property_full.rs) —
  end-to-end property test on KV + log namespaces.

## Per-decoder boundary enumeration

For each decoder, the boundary classes I could enumerate, where in
the code they are rejected, and which test exercises each.

### `Plaintext::decode` ([chunk/format.rs:91](../../../crates/hidden-volume/src/chunk/format.rs))

Decodes the 4040-byte post-AEAD plaintext frame.

| Boundary | Defending code | Test |
|---|---|---|
| `bytes.len() != PLAINTEXT_LEN` (exact-length check) | line 92-94: `if buf.len() != PLAINTEXT_LEN` | `plaintext_decode_doesnt_panic` (random bytes of arbitrary length) |
| Bad magic | line 95-97: `&buf[..4] != MAGIC` | covered by fuzz; magic is 4-byte constant `b"HVC1"` |
| Bad kind discriminator | line 99: `ChunkKind::from_u8` returns `Err` | covered |
| Non-zero flags byte (forward-compat) | line 102-104: `buf[5] != 0` rejected | covered; tested by `tests/header_params.rs::p1_non_zero_reserved_flags_byte_rejected` |
| Reserved bytes 6-7 != 0 (we don't actively check; they're random-padded on encode) | n/a — no constraint | not a boundary |
| `payload_len > PAYLOAD_CAP` | line 109-111: rejected before slice | covered |
| `seq` is any u64 | no constraint by design (seq is from writer) | n/a |

**Verdict.** Fully bounded; every byte position has a defined valid
range; every out-of-range case maps to `Err(Malformed)` not panic.

### `Argon2Params::decode` ([crypto/kdf.rs:237](../../../crates/hidden-volume/src/crypto/kdf.rs))

Decodes the 16-byte Argon2 params block from the cleartext header.

| Boundary | Defending code | Test |
|---|---|---|
| `bytes.len() != HEADER_PARAMS_LEN` (16) | exact-length check | `argon2_params_decode_doesnt_panic` |
| All four u32 fields parsed by `u32::from_le_bytes` (infallible) | n/a — never panics on 4-byte slice | n/a |
| Subsequent `validate()` enforces semantic ranges | line 164-201 (separate fn) | `tests/header_params.rs` (D1-class regressions) |

**Verdict.** Decoder is unconditionally panic-free; semantic
validation in `validate()` covered separately.

### `Header::decode` ([container/header.rs:49](../../../crates/hidden-volume/src/container/header.rs))

Decodes the 48-byte container header (`salt ‖ Argon2Params`). v3
dropped the 32-byte `container_id` field that v2 placed between
salt and params; `container_id` is now per-space derived inside
`SpaceKeys::from_master` rather than parsed from the cleartext.

| Boundary | Defending code | Test |
|---|---|---|
| `bytes.len() < HEADER_LEN` (48) | length check + early return | `header_decode_doesnt_panic` |
| `Argon2Params::decode` failure on the 16-byte slice | propagates `Err` | covered |
| Salt is unconditionally accepted (32 bytes, no semantic constraint) | n/a | n/a |

**Verdict.** Fully bounded.

### `Superblock::decode` ([space/superblock.rs:52](../../../crates/hidden-volume/src/space/superblock.rs))

Decodes the 48-byte superblock payload.

| Boundary | Defending code | Test |
|---|---|---|
| `bytes.len() != SUPERBLOCK_LEN` (48) | exact-length check | `superblock_decode_doesnt_panic` |
| `seq`, `root_slot`, `root_hash` all parsed by infallible u64 / fixed-array reads | n/a | n/a |

**Verdict.** Fully bounded.

### `IndexNode::decode` ([space/index.rs:156](../../../crates/hidden-volume/src/space/index.rs))

Dispatcher: reads the leading discriminator byte and routes to
`LeafNode::decode` or `InternalNode::decode`.

| Boundary | Defending code | Test |
|---|---|---|
| `bytes.len() < HEADER_LEN` (4) | line 157-159: rejected | `index_node_decode_doesnt_panic` |
| Bad discriminator | line 163: `Err(Malformed("unknown index node type"))` | covered |

**Verdict.** Fully bounded.

### `LeafNode::decode` ([space/index.rs:234](../../../crates/hidden-volume/src/space/index.rs))

Decodes a Leaf with `num_entries × (klen, key, vlen, value)`.

| Boundary | Defending code | Test |
|---|---|---|
| Header length / discriminator | line 235-237 | covered |
| **G2 pre-allocation bound** (`num × MIN_LEAF_ENTRY_BYTES > body`) | line 240-251 | covered; closes the audit-pass-5 G2 finding |
| Truncated at `key_len` field | line 255-257 | covered |
| `klen == 0` or `klen > MAX_KEY_LEN` (256) | line 260-262 | covered |
| Truncated at key / value-length / value | line 263-275 | covered |
| `vlen > MAX_VALUE_LEN` (2048) | line 270-272 | covered |
| **Sortedness violation** | line 280-296: `windows(2)` pattern rejects unsorted entries; typed `Error::Internal` for the impossible `let [a,b]=w else` branch (audit pass 17) | covered |
| Encode-decode bijectivity | `leaf_node_roundtrip` proptest | Phase 2 |

**Verdict.** Fully bounded with explicit pre-allocation budget
check (G2). No panic site.

### `InternalNode::decode` ([space/index.rs:384](../../../crates/hidden-volume/src/space/index.rs))

Decodes an Internal node with `num_children × (klen, first_key,
child_slot, child_hash)`.

| Boundary | Defending code | Test |
|---|---|---|
| Header length / discriminator | line 385-387 | covered |
| **L1 zero-children rejection** | line 396-398 | covered; closes audit-pass-11 L1 |
| **G3 pre-allocation bound** | line 399-406 | covered |
| Truncated at `first_key_len` / `first_key` / `child_slot` / `child_hash` | line 410-433 | covered |
| `klen == 0` or `klen > MAX_KEY_LEN` | line 415-417 | covered |
| **Sortedness violation** | line 434-444: same `windows(2)` pattern as Leaf | covered |
| Encode-decode bijectivity | `internal_node_roundtrip` proptest | Phase 2 |

**Verdict.** Fully bounded; L1 + G3 closures verified.

### `CommitPayload::decode` ([tx/commit.rs:142](../../../crates/hidden-volume/src/tx/commit.rs))

Decodes `num_roots × (namespace, kind, index_slot, payload_hash) ‖
tx_root_hash`.

| Boundary | Defending code | Test |
|---|---|---|
| `bytes.len() < 2 + 32` (header floor) | line 143-145 | covered |
| `num > MAX_NAMESPACES_PER_TX` | line 147-149 | covered |
| `bytes.len() < expected` (truncation post-num) | line 150-153 | covered |
| `kind` discriminator (`NamespaceKind::from_u8`) | line 159 | covered (R-NSKIND v2 closure) |
| **Sortedness violation** on `namespace` | line 174-178 | covered |
| Final 32-byte `tx_root_hash` read in-bounds | guaranteed by the `expected` length check at line 150 | covered |

**Verdict.** Fully bounded. R-NSKIND v2 layout (added `kind` byte
per IndexRoot) is correctly handled.

### `decode_batch` ([space/log.rs:196](../../../crates/hidden-volume/src/space/log.rs))

Decompresses + decodes a zstd-compressed DataBatch payload.

| Boundary | Defending code | Test |
|---|---|---|
| zstd decode failure | line 207-208: maps to `Error::Compression` | covered |
| **M5 streaming cap** (`MAX_DECODED_BATCH_LEN ≈ 8.4 MiB`) | line 212-218: `Read::take(cap + 1)` enforces byte-level cap | covered; closes audit-pass-11 M5 (zstd bomb) |
| `raw.len() < 4` (num_records header) | line 221-223 | covered |
| `num > MAX_RECORDS_PER_BATCH` (1024) | line 224-227 | covered |
| Truncated at record header / payload | line 230-243 | covered |
| `plen > MAX_LOG_PAYLOAD_LEN` (8 KiB) | line 238-240 | covered |

**Verdict.** Fully bounded with the M5 compression-bomb cap as
the load-bearing defense.

### `ChunkKind::from_u8` ([chunk/kind.rs:37](../../../crates/hidden-volume/src/chunk/kind.rs))

Single-byte discriminator.

| Boundary | Defending code | Test |
|---|---|---|
| Unknown discriminator | line 37-45: `Err(Malformed("unknown chunk kind"))` (rejects reserved 0x03 / 0x04) | reached via every higher-level decoder's coverage |

**Verdict.** Trivial.

### `NamespaceKind::from_u8` ([tx/commit.rs:74](../../../crates/hidden-volume/src/tx/commit.rs))

Single-byte R-NSKIND discriminator (0 = Kv, 1 = Log).

| Boundary | Defending code | Test |
|---|---|---|
| Unknown discriminator | line 74-80: `Err(Malformed("unknown namespace kind discriminant"))` | covered via `CommitPayload::decode` proptest |

**Verdict.** Trivial.

## Boundary classes (summary)

| Class | Decoders affected | Defense pattern | Coverage |
|---|---|---|---|
| Truncation (too few bytes) | every decoder | length check + early return | proptest Phase 1 |
| Exact-length mismatch | Plaintext, Header, Argon2Params, Superblock | exact `==` check | covered |
| Bad discriminator | Plaintext (kind), CommitPayload (kind), IndexNode (node_type), ChunkKind, NamespaceKind | match arm + Err | covered |
| Pre-allocation amplifier (G2, G3) | LeafNode, InternalNode, CommitPayload, decode_batch | `num × MIN_ENTRY ≤ body` upfront | covered (G2 / G3 closures) |
| Per-entry length OOB | LeafNode, InternalNode, decode_batch | per-step length check | covered |
| Per-entry value-length cap | LeafNode (MAX_VALUE_LEN), decode_batch (MAX_LOG_PAYLOAD_LEN) | constant check | covered |
| Sortedness violation | LeafNode, InternalNode, CommitPayload | `windows(2)` post-decode loop | covered |
| Zero-count structural-invalid | InternalNode (`num_children == 0`) | L1 reject | covered |
| Compression bomb | decode_batch | M5 streaming cap | covered |
| Non-zero reserved bits / flags | Plaintext (flags), Argon2Params (reserved bits 24..32) | byte check + Argon2Params::validate | covered |

**0 boundary classes uncovered.**

## What about post-AEAD-success malformed plaintext?

A theoretical concern: AEAD-decrypt succeeds on bytes WE wrote
(via a writer-side regression) or on a torn-write that
coincidentally MAC-verifies (2⁻¹⁰⁰ — astronomical). In that case,
the decoder receives malformed-but-AEAD-blessed bytes. The
`decoder_family.rs` cargo-fuzz target and the `parser_fuzz.rs`
proptest deliberately bypass AEAD and feed the decoders arbitrary
bytes — so any post-AEAD malformed plaintext that could reach the
decoder is in the input distribution the fuzzers explore.

This is the *right* fuzzing strategy: AEAD is provably hard to
fuzz directly (the attacker needs the key), so the layer below
AEAD is fuzzed with arbitrary inputs as a proxy for "any
bit-pattern a buggy writer or astronomical-MAC-collision could
produce".

## Coverage of error-message non-leakage

Every error variant returned by the decoders is checked in
[`audits/side-channel-surface.md` L-2](side-channel-surface.md)
to confirm no variant interpolates key material or content. Just
static labels and numeric fields.

## What this pass did NOT cover

- **Differential / state-machine fuzzing.** I did not enumerate
  state transitions in the commit-recovery protocol; the
  `crash_recovery.rs` + `crash_proptest.rs` tests cover that
  separately.
- **Fuzz harness performance / corpus quality.** Whether the
  fuzz corpus drives all decoder branches with reasonable
  coverage is a question for the fuzz framework, not a
  static-analysis audit.
- **External crate fuzz.** RustCrypto / blake3 / zstd-safe /
  proptest are trusted dependencies; we do not fuzz THEIR
  decoders.
- **End-to-end attack narrative** — that's the [pass-5
  threat-model challenge](./threat-model-challenge.md) (next
  and final).

## Recommended actions (v1.x roadmap)

Nothing required. One INFO observation tracked above (FZ-INFO1
re: CI-failure-on-fuzz-finding gate).

The existing `decoder_family.rs` cargo-fuzz target is the right
shape; running it for a longer wallclock budget (e.g., a
periodic 30-minute fuzz farm rather than a 5-minute smoke run)
would deepen confidence further. Not a current bug.
