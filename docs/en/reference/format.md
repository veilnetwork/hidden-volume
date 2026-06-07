# hidden-volume on-disk format v3

🇬🇧 **English** · [🇷🇺 Русский](../../ru/reference/format.md)

**Status.** Pre-freeze. The shape will not change between now and
v1.0; specific reservation bytes / version markers may still flex.
After v1.0 release this document is **frozen**: any later change to
the layout requires a v4 generation and a migration tool (see
`docs/en/guide/migration.md`).

This document is the canonical, byte-level reference for the on-disk
format. `DESIGN.md` covers rationale and design choices; this file is
"what's actually on disk", structured for reviewers and external
implementors.

If anything here conflicts with `DESIGN.md`, this document wins for
**format facts**; `DESIGN.md` wins for **invariants and threat model**.

## 1. Top-level layout

A container file is a contiguous sequence of fixed-size **chunks**:

```
offset                 length            content
---------------------------------------------------------------
0                      32                container_salt
32                     16                argon2_params
48                     CHUNK_SIZE - 48   header padding (uniform random)
CHUNK_SIZE             CHUNK_SIZE        chunk[0]
2 * CHUNK_SIZE         CHUNK_SIZE        chunk[1]
...                    ...               ...
(1 + N) * CHUNK_SIZE   ─                 EOF
```

Where:

- `CHUNK_SIZE = 4096` bytes (constant, not encoded — implicit by
  format version).
- `N` = number of chunks ≥ 0. The file size is exactly
  `(1 + N) * CHUNK_SIZE` bytes.
- The first chunk (offset 0..4096) is the **header**.
- Each subsequent chunk is at slot index `i ∈ [0, N)`.

### 1.1 Header (first 4 KiB)

```
offset 0..32   container_salt    32 random bytes (KDF salt; cleartext)
offset 32..48  argon2_params     16 bytes, structured (§1.2)
offset 48..4096 padding          uniform random (visually identical
                                  to slot ciphertext)
```

**v3 change (closes D1-A2).** The 32-byte `container_id` field that
used to occupy offset 32..64 in v2 is **gone from the cleartext
header**. It is now derived **per-space** from the versioned master
key inside [`crate::crypto::derive::SpaceKeys::from_master`] —
nothing in the cleartext header carries a per-space identifier.
This closes the D1-A2 fingerprint signature flagged in
`docs/en/security/threat-model.md` (single-snapshot distinguisher
"this file has shape `salt ‖ container_id ‖ argon2_params`").

**Invariants.**

- The file MUST be at least `CHUNK_SIZE` bytes (i.e. the header is
  always present).
- The file size MUST be a multiple of `CHUNK_SIZE`. A file with a
  non-aligned tail is rejected (`Error::Malformed`) — the library
  refuses to open ambiguous truncated files.
- All bytes outside the cleartext header (offset 0..48) MUST be
  statistically indistinguishable from uniform random for an
  observer without any password.
- There are no other cleartext fields. **No magic bytes, no format
  version marker, no chunk counts in the clear.** Format version is
  implicit (this document) and bound by the consuming library's
  reading rules. The Argon2 `params_version` u32 carries
  `format_version` in its low 16 bits (§1.2), but it is not a magic
  marker on its own.

### 1.2 Argon2 parameter encoding (16 bytes at offset 32..48)

```
offset 32..36  m_cost_kib     u32 LE   (memory in KiB)
offset 36..40  t_cost         u32 LE   (iterations)
offset 40..44  p_cost         u32 LE   (parallelism lanes)
offset 44..48  params_version u32 LE   (packed; see bit layout below)
```

The `params_version` u32 is **packed** (audit pass 8 S1 full):

| bits   | field                      | semantics                                                                                                                                                                                                                                                                |
|--------|----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0..16  | `format_version`           | Currently `3` (v3 cluster: #8 kind-tag bytes + #9 cryptographic version-binding + #10 per-space derived `container_id`). Library refuses to open if any other value. v1/v2 containers cannot be opened by a v3 reader; pre-1.0 — breaking is acceptable.                  |
| 16..24 | `padding_policy_index`     | Persistent post-commit padding policy. `0` = `None` (default); `1` = 256 KiB buckets; `2` = 1 MiB buckets (DEFAULT preset); `3` = 16 MiB buckets. Unknown values (4..=255) silently degrade to `None` for forward-compat.                                                  |
| 24..32 | reserved                   | MUST be `0`. The library rejects open if any of these bits are set. Future format-version planning may consume them.                                                                                                                                                     |

- `format_version = 3` means: Argon2id v0x13 (RFC 9106) + the BLAKE3
  derive chain in §3 (including the v3 post-Argon2 version-bind step
  and the per-space `container_id` derive) + the CommitPayload
  layout in §4.3 (per-root `kind` byte, unchanged from v2).
- `m_cost_kib`, `t_cost`, `p_cost` MUST be ≥ `Argon2Params::MIN`
  (m=8 MiB, t=2, p=1). The library refuses to open or create a
  container with weaker parameters. Symmetric ceilings — 1 GiB / 100 /
  64 — close the cleartext-header DoS where a tampered field would
  force the next opener into a multi-TiB Argon2id allocation.
- Older v1 (pre-pass-13) and v2 (post-pass-13) containers are
  REJECTED by v3 readers because `format_version != 3`. The reject
  is now **doubly bound**: by `Argon2Params::validate` policy AND by
  the v3 cryptographic version-bind step in §3 — a hypothetical v4
  reader that loosened `validate` would still derive a different
  master key for the same password+salt because `params.version` is
  folded into the master key.
- The persistent padding-policy byte was previously
  unauthenticated; in v3 it is **bound into `master_key` derivation**
  (because `params.version` flows through the post-Argon2 BLAKE3
  step, and `padding_policy_index` lives in bits 16..24 of that u32).
  A T2 file-modify adversary who flips `padding_policy_index`
  therefore now causes `Error::AuthFailed` on the next open — F-PAD
  graduates from "silent privacy degradation" to "DoS-class
  visible failure". See `docs/en/security/threat-model.md` §4.1.

## 2. Chunk format

Every chunk is exactly `CHUNK_SIZE = 4096` bytes. On disk, the bytes
are uninterpretable without the right per-slot key — there are no
cleartext fields per chunk.

### 2.1 Wire layout (4096 bytes)

```
offset 0..24      nonce       24 bytes, uniform random (XChaCha20 nonce)
offset 24..4080   ciphertext  4056 bytes (XChaCha20-Poly1305 output sans tag)
offset 4080..4096 tag         16 bytes (Poly1305 authentication tag)
```

- The XChaCha20-Poly1305 input plaintext is exactly
  `PLAINTEXT_LEN = CHUNK_SIZE - NONCE_LEN - TAG_LEN = 4056` bytes
  (§2.2).
- AAD = `container_id || u64_le(slot_index)`, total 40 bytes (§2.3).
  The `container_id` is now the **per-space derived** value (§3),
  not a field read from the cleartext header.

### 2.2 Plaintext layout (4056 bytes, never visible without key)

```
offset 0..4    magic        b"HVC1" (4 bytes)
offset 4       kind         u8 (ChunkKind, §2.4)
offset 5       flags        u8 (reserved, MUST be 0 in v3)
offset 6..14   seq          u64 LE (per-space monotonic counter)
offset 14..16  payload_len  u16 LE (≤ PAYLOAD_CAP = 4040)
offset 16..16+payload_len   payload    (kind-specific encoding, §4)
offset 16+payload_len..4056 plaintext padding (uniform random)
```

`PAYLOAD_CAP = PLAINTEXT_LEN - 16 = 4040` bytes.

The `magic` field is a sanity check after AEAD-decrypt only — never
visible without the key. If AEAD passes but `magic ≠ b"HVC1"`, the
chunk is rejected as `Error::Malformed`. With astronomically low
collision probability, this is essentially a defence-in-depth check.

### 2.3 AAD construction

```
AAD = container_id (32 bytes) || slot_index (u64 LE, 8 bytes)
    = 40 bytes
```

This binds each chunk's ciphertext to the specific (space, slot)
pair. Moving a ciphertext to a different slot or a different
container makes AEAD-decrypt fail. **v3 strengthening.** Because
`container_id` is now per-space derived (different spaces in the
same container have different `container_id`s) and the master key
itself is version-bound, cross-container chunk relocation is closed
by two independent gates: different `container_salt` ⇒ different
`master_key` ⇒ different `container_id` ⇒ AAD mismatch ⇒
AEAD-decrypt fail.

### 2.4 ChunkKind values (u8, offset 4 of plaintext)

| Value | Name | Payload encoding | Section |
|---|---|---|---|
| `0x01` | `Superblock` | per-space root, latest commit pointer | §4.1 |
| `0x02` | `IndexNode` | KV-index B+ tree node (Leaf or Internal) | §4.2 |
| `0x03` | `Data` | reserved (legacy v0.1 single-record API) | — |
| `0x04` | `Journal` | reserved (intent-log; not emitted in v3) | — |
| `0x05` | `Commit` | per-Tx root commit | §4.3 |
| `0x06` | `DataBatch` | zstd-compressed log batch | §4.4 |

Other values: rejected as `Error::Malformed`.

### 2.5 Garbage chunks

A chunk that doesn't AEAD-decrypt under any space's key is a
**garbage chunk**. Bytes are uniform random; no plaintext exists.
Garbage chunks are written by:

- Initial garbage (`ContainerOptions::initial_garbage_chunks` at
  create time).
- Post-commit padding (`PaddingPolicy::{BucketGrowth, FixedRatio}`
  per `Space::commit_tx`).
- Tombstone scrub (`scrub_slot` on a previously-owned slot).

Garbage chunks contribute to D1 (single-snapshot indistinguishability)
by making the file size and per-chunk content non-informative.

## 3. Key schedule (v3)

```text
// Stage 1: Argon2id over (password, container_salt, argon2_params).
argon_out      = Argon2id(password, container_salt, argon2_params)
                                                 -> 32 bytes (Zeroizing)

// Stage 2 (v3 #9): cryptographic format-version binding.
versioned_master = BLAKE3-keyed(
    argon_out,
    b"hv/v3/master" || u32_le(params.version)
)                                                -> 32 bytes (Zeroizing)
            // 12-byte ASCII label || 4-byte LE version = 16-byte input

// Stage 3 (v3 #8 + #10): per-space subkey derivation. Each subkey
// is derived with a kind-tag byte 0x01 (SUBKEY_KIND_TAG) prefixed
// to the context label, replacing the pre-v3 length-distinguishes
// convention.
container_id   = BLAKE3-keyed(
    versioned_master,
    [0x01] || b"hv/v3/container_id"
)                                                -> 32 bytes (in SpaceKeys)

aead_root      = BLAKE3-keyed(
    versioned_master,
    [0x01] || b"hv/v3/aead_root"
)                                                -> 32 bytes (Zeroizing)

// Stage 4: per-slot AEAD key. v3 #8 kind tag 0x02 distinguishes
// this input from the subkey inputs above.
chunk_key(slot) = BLAKE3-keyed(
    aead_root,
    [0x02] || container_id || u64_le(slot)
)                                                -> 32 bytes (Zeroizing)
                  // 1 + 32 + 8 = 41-byte stack input
```

- `argon_out` and `versioned_master` are dropped immediately after
  use; only `container_id` and `aead_root` are retained inside the
  per-space `SpaceKeys` struct (which is `ZeroizeOnDrop`).
- BLAKE3-keyed: `blake3::Hasher::new_keyed(&key).update(input).finalize()`
  truncated to 32 bytes.
- All derived keys are `Zeroizing<[u8; 32]>` at the call site.
  `SpaceKeys` derives `ZeroizeOnDrop`.
- Argon2id parameters come from the cleartext header (§1.2).
- The context labels (`b"hv/v3/master"`, `b"hv/v3/container_id"`,
  `b"hv/v3/aead_root"`) are **stable domain-separation tags**.
  Changing any of them would render every existing v3 container
  unreadable. The "v3" segment is also the format-version marker:
  any v4 generation will use `b"hv/v4/master"` etc., so cross-
  version key reuse is closed cryptographically (a v3 password
  derives a *different* `master_key` than a v4 password against the
  same `container_salt`).

**Why the kind-tag bytes.** Pre-v3, domain separation between
`derive_subkey` and `derive_chunk_key` relied on the input length
being different (audit pass 7 D3 documented this convention but did
not enforce it). v3 #8 makes the kind explicit: `0x01` for any
subkey derivation, `0x02` for any per-slot AEAD-key derivation.
Future BLAKE3-keyed inputs in the same key chain MUST take new
kind-tag bytes from the same byte-namespace.

## 4. Per-kind payload encodings

### 4.1 Superblock (`kind = 0x01`)

```
offset 0..8    seq        u64 LE
offset 8..16   root_slot  u64 LE   (slot of the latest Commit chunk,
                                    or u64::MAX for empty space)
offset 16..48  root_hash  32 bytes (Merkle root over Commit's roots)
```

Total: 48 bytes. Multiple Superblock replicas at the same `seq` are
written per Tx (default `superblock_replicas = 3`); recovery picks
any AEAD-decryptable replica with the highest `seq`.

`root_hash` is BLAKE3 over the concatenation of
`IndexRoot.payload_hash` for every namespace in the latest Commit
(§4.3) — this is the Merkle root of the current state.

`root_slot = u64::MAX` (constant `NO_RECORD`) means "no commit yet";
this is the state of a freshly-created space before any Tx commits.

### 4.2 IndexNode (`kind = 0x02`)

A B+ tree node. Two variants:

#### 4.2.1 Leaf

```
offset 0       node_kind   u8 (0x01 = Leaf)
offset 1       namespace   u8
offset 2..4    entry_count u16 LE
for i in 0..entry_count:
    key_len   u16 LE
    key       key_len bytes
    value_len u32 LE
    value     value_len bytes
```

Constraints:

- `key_len` ∈ [1, 256].
- `value_len` ∈ [0, 2048].
- Entries MUST be sorted ascending by `key` and pairwise unique.
- Total encoded size ≤ `PAYLOAD_CAP` (4040).

#### 4.2.2 Internal

```
offset 0       node_kind   u8 (0x02 = Internal)
offset 1       namespace   u8
offset 2..4    child_count u16 LE
for i in 0..child_count:
    first_key_len u16 LE
    first_key     first_key_len bytes
    child_slot    u64 LE
    child_hash    32 bytes (BLAKE3 of child IndexNode's plaintext payload)
```

Constraints:

- `child_count` ≥ 2.
- `first_key`s MUST be strictly ascending.
- Total encoded size ≤ `PAYLOAD_CAP`.

The Internal-vs-Leaf discriminator is the first byte (`0x01` /
`0x02`); other values: `Error::Malformed`.

### 4.3 CommitPayload (`kind = 0x05`) — v3 layout

The wire shape is identical to v2 (R-NSKIND, audit pass 13). v3 did
not touch this encoding — only the key schedule above and the
cleartext header layout. The per-root `kind` byte is unchanged.

```
offset 0..2    root_count   u16 LE
for i in 0..root_count:
    namespace     u8
    kind          u8                (0 = Kv, 1 = Log; 2..=255 reserved)
    index_slot    u64 LE
    payload_hash  32 bytes (BLAKE3 of root IndexNode's plaintext payload)
offset (2 + 42 * root_count)..(2 + 42 * root_count + 32):
    tx_root_hash  32 bytes (= BLAKE3(concat(payload_hash[i])))
```

Constraints:

- Roots MUST be sorted ascending by `namespace` and pairwise unique
  (one root per namespace).
- `kind` MUST be `0` (Kv) or `1` (Log). Discriminants `2..=255` are
  reserved; decoders MUST fail with `Error::Malformed` on read of
  any unknown discriminant. The kind is enforced cross-Tx by
  `Space::commit_tx`: a namespace established as `Kv` cannot be
  appended to as `Log` in a later Tx (and vice versa); this closes
  the audit pass 12 HIGH "mixed-namespace data loss" finding.
- `tx_root_hash` MUST equal `BLAKE3(concat(roots[i].payload_hash))`
  recomputed at read time. Mismatch ⇒ `Error::IntegrityFailure`
  during `verify_integrity`.
- Total encoded size: `2 + 42 * root_count + 32`. With
  `PAYLOAD_CAP = 4040`, ≤ 95 namespaces per Commit (well above any
  realistic use).
- v1/v2 (pre-v3) containers are not readable by v3 implementations
  because `Argon2Params::validate` rejects `format_version != 3` at
  open AND because the v3 cryptographic version-bind step in §3
  derives a different master key.

### 4.4 DataBatch (`kind = 0x06`)

zstd-level-3 compression of the following raw layout:

```
raw layout (input to zstd):
    offset 0..4   num_records u32 LE
    for i in 0..num_records:
        log_id      u64 LE
        payload_len u32 LE
        payload     payload_len bytes
```

Constraints (raw, before compression):

- `num_records` ∈ [1, `MAX_RECORDS_PER_BATCH = 1024`].
- `payload_len` ∈ [0, `MAX_LOG_PAYLOAD_LEN = 8192`].
- The compressed result MUST fit in `PAYLOAD_CAP = 4040` bytes after
  zstd; oversize → `Error::PayloadTooLarge`.

Each DataBatch is referenced from the namespace's KV index by an
8-byte LE slot pointer:

```
KV value for log entry: u64 LE = batch_slot
KV key for log entry:   u64 BE = log_id (big-endian for natural sort order)
```

## 5. Tx commit protocol (write path)

A successful Tx commit MUST execute the following sequence (DESIGN
§6 + `src/space/mod.rs::commit_tx`):

1. **Phase 0** (log namespaces): for each non-empty log namespace's
   pending batch — encode + zstd-compress, append a `DataBatch`
   chunk, and route a KV `put` of `log_id_key → batch_slot_value`
   into the namespace's pending KV ops. (DataBatch chunks land
   first so KV pointers can reference them.)
2. **Phase 1** (KV indexes): for each touched namespace, rebuild the
   B+ tree from prior + pending ops, append every IndexNode chunk
   (Leaf and Internal), record `(namespace, root_slot, payload_hash)`.
3. **fsync barrier 1.** All data + index chunks durable.
4. **Phase 2**: encode `CommitPayload` from the new
   `IndexRoot[]`, append a `Commit` chunk.
5. **fsync barrier 2.** Commit pointer durable.
6. **Phase 3**: build the new `Superblock { seq, root_slot, root_hash }`,
   append `superblock_replicas` copies of it (default 3, atomically
   in one fsync).
7. **fsync barrier 3.** New superblock(s) durable; the new state is
   live from this point.
8. **Phase 4** (optional): post-commit padding chunks per
   `PaddingPolicy`, single fsync if any.

The crash recovery contract (§7 of DESIGN, summarized):

- Crash before barrier 1: nothing changed; reopen sees prior state.
- Crash between barrier 1 and barrier 2: tail orphan IndexNode +
  partial DataBatch chunks remain on disk but are not reachable
  from any Superblock; reopen rolls back to prior state.
- Crash between barrier 2 and barrier 3: orphan Commit chunk
  exists but the new Superblock isn't durable; reopen rolls back.
- Crash after barrier 3: new state is durable; reopen sees it.

Three-fsync floor: a commit takes at least ~5 ms on modern SSDs
because of the three barriers. Batch writes within a single Tx
amortize over this floor.

## 6. Discovery scan (open path)

Given `(container_salt, argon2_params)` from the cleartext header
(v3 — `container_id` is no longer in the header, see §1.1) and a
candidate `password`:

1. `argon_out = Argon2id(password, container_salt, argon2_params)`.
2. Compute `versioned_master = BLAKE3-keyed(argon_out, b"hv/v3/master" || u32_le(params.version))`.
3. Derive `container_id` and `aead_root` per §3 (each via
   `derive_subkey(versioned_master, ...)`).
4. For `slot = 0..N` (where `N = (file_size / CHUNK_SIZE) - 1`):

    a. Read chunk at offset `(1 + slot) * CHUNK_SIZE`.

    b. Compute `chunk_key(slot)` per §3.

    c. Try AEAD-decrypt with key + AAD = `container_id || u64_le(slot)`.

    d. On success: parse plaintext (§2.2), record `(slot, kind, seq)`. Discard the plaintext bytes.

5. Among AEAD-successful Superblock chunks, pick the one with the
   highest `seq`. The file's recovered state for this space is its
   `(seq, root_slot, root_hash)`. If no Superblock is found ⇒
   `Error::AuthFailed`.
6. Optionally: build `commit_history = sort_dedup(all SB seqs)`
   and `owned_slots = sort(all AEAD-successful slots)` for
   downstream APIs.

**Deniability invariant.** Step 4 executes exactly `N` AEAD attempts
regardless of the per-space outcome. Successful and unsuccessful
decrypts are indistinguishable to an outside observer (constant-time
tag check inside RustCrypto's AEAD; no logging branches; same return
path on `Error::AuthFailed`). This is what makes the format support
T2/T3 deniability — see `docs/en/security/threat-model.md` §3 D1/D2.

**TM1 timing-equalization (v1.0, shipped 2026-05-28).** Per-chunk
work-amount divergence between MAC-pass and MAC-fail paths is the
F-TM1 residual. All three scan modes ship constant-time
companions: `Container::open_space_constant_time` (sequential),
`Container::open_space_parallel_constant_time` (parallel-scan),
`Container::open_space_mmap_constant_time` (mmap). Each runs a
ChaCha20 stream over `body_len` bytes on every chunk to equalize
the dominant cost component. They do NOT equalize allocation /
parsing overhead — host-apps that need a stronger guarantee
should request the same Argon2 parameters on every open and pad
the post-open processing externally.

## 7. Cross-version policy

| Reader \ File | v1 | v2 | v3 | future v4 |
|---|---|---|---|---|
| v1            | OK (legacy)   | reject | reject | reject |
| v2            | reject | OK     | reject | reject |
| **v3** (current) | reject | reject | **OK** | reject |
| v4            | reject | reject | reject | OK |

Cross-version reject is **doubly bound** in v3:

1. **Policy.** `Argon2Params::validate` rejects any
   `format_version != PARAMS_VERSION` at open. Encoded in
   [`crates/hidden-volume/src/crypto/kdf.rs`](../../../crates/hidden-volume/src/crypto/kdf.rs).
2. **Cryptography.** The post-Argon2 BLAKE3 step (§3 Stage 2) folds
   `params.version` into `master_key`. A hypothetical reader that
   loosened the policy gate would still derive a *different*
   `master_key` than the writer that sealed the file, hitting
   `Error::AuthFailed` on the first AEAD attempt.

No in-place migration is provided. To move data from a vN container
to a vM container (with M ≠ N), the host-app must:

- Open the source with a vN-capable build of the library.
- Export every namespace via `Space::list` (KV) and
  `Space::iter_log` (Log).
- Create a fresh vM container.
- Re-import each namespace.

See `docs/en/guide/migration.md` for the procedure.

## 8. Format-level constants

| Constant | Value | Purpose |
|---|---|---|
| `CHUNK_SIZE` | 4096 | Chunk size in bytes. Implicit; not in header. |
| `HEADER_LEN` | 48 | Cleartext header bytes (salt 32 + params 16). v2 was 80; v3 dropped the cleartext `container_id` field (now per-space derived). |
| `NONCE_LEN` | 24 | XChaCha20 nonce length. |
| `TAG_LEN` | 16 | Poly1305 tag length. |
| `PLAINTEXT_LEN` | 4056 | `CHUNK_SIZE - NONCE_LEN - TAG_LEN`. |
| `PLAINTEXT_HEADER_LEN` | 16 | Per-chunk plaintext frame header. |
| `PAYLOAD_CAP` | 4040 | `PLAINTEXT_LEN - PLAINTEXT_HEADER_LEN`. |
| `MAX_KEY_LEN` | 256 | Per-KV-entry key cap. |
| `MAX_VALUE_LEN` | 2048 | Per-KV-entry value cap. |
| `MAX_LOG_PAYLOAD_LEN` | 8192 | Per-log-entry payload cap (pre-compression). |
| `MAX_RECORDS_PER_BATCH` | 1024 | DataBatch entry-count cap. |
| `MAX_RAW_BATCH_LEN` | 1 048 576 | DataBatch raw size soft cap (1 MiB). |
| `MAX_RECORDS_PER_TX` | 100 | Records (plus IndexNodes) per single CommitPayload. |
| `DEFAULT_SUPERBLOCK_REPLICAS` | 3 | SB replicas per commit. |
| `params_version.format_version` | 3 | On-disk format generation; encoded as low 16 bits of the 4-byte `params.version` (§1.2). v3 readers refuse v1/v2 files, and v3 readers are refused by hypothetical v4 readers. |
| `argon2_floor` (`Argon2Params::MIN`) | m=8 MiB, t=2, p=1 | Refuse-to-open threshold. |
| `Argon2Params::MAX_M_COST_KIB` / `MAX_T_COST` / `MAX_P_COST` | 1 GiB / 100 / 64 | Refuse-to-open ceilings (audit pass 1 D1, header-tamper Argon2 OOM mitigation). |
| `MAX_OPEN_SCAN_CHUNKS` | 16 × 1024 × 1024 (= 64 GiB at `CHUNK_SIZE`) | Hard cap on slot grid size. Open-side rejects files exceeding this with `Error::Malformed("container exceeds open-scan budget")` (audit pass 16 TM1 mitigation); write-side refuses with `Error::ContainerTooLarge { extra, cap }` (audit pass 17 B). Re-exported as `pub use hidden_volume::MAX_OPEN_SCAN_CHUNKS`. |
| `MAX_TREE_DEPTH` | 3 | Hard cap on B+ tree depth used by every walker (Space::get, list, log_iter, integrity, vacuum). Pathological cyclic Internal→Internal chain trips `Error::Malformed("tree depth exceeded MAX_TREE_DEPTH")` after at most this many descents. Writer-side invariant guarantees depth ≤ 2 in well-formed containers. |

## 9. Reservation bytes (forward-compat)

The format reserves the following bytes for **non-breaking** extensions
within v3 (i.e., a v3.x library MUST refuse to read a container that
sets reserved bytes, but a future v3.y > v3.x MAY define new meaning
and existing v3.x libraries MUST then refuse to open):

- **Plaintext frame `flags` byte** (offset 5 of plaintext, §2.2).
  Currently MUST be 0. Any future use is a v3-internal optional
  feature with a fall-back kind / version path.
- **Argon2 `params_version` reserved bits 24..32** (§1.2).
  Currently MUST be 0. Future format-version planning may consume
  them; until then any non-zero value is rejected.

A breaking change beyond these reservations forces a v4 generation;
see `docs/en/guide/migration.md` (cross-version policy in §7 above).

## 10. What's NOT in the format

To rule out ambiguity for parser-differential reviewers:

- **No magic bytes.** The cleartext header has none. The plaintext
  frame's `b"HVC1"` is post-AEAD only; it does not aid file-type
  identification by an outsider.
- **No format version in the cleartext (as a separate marker).**
  `params_version` is the closest thing, but it is packed inside
  the Argon2 params word; v3 also binds it cryptographically into
  `master_key` so a bit-flip degrades to `Error::AuthFailed`.
- **No per-space identifier in the cleartext (v3 #10).** v2 stored
  `container_id` at offset 32..64; v3 removed it. Different spaces
  inside the same container have different `container_id`s, derived
  in-memory at open time. A T1 single-snapshot observer no longer
  sees a per-space fingerprint.
- **No file size in the header.** Inferred from `metadata().len()`.
- **No global chunk count.** Inferred as `(file_size / CHUNK_SIZE) - 1`.
- **No global table of contents.** Discovery is by trial-decrypt.
- **No timestamps.** Anywhere. (Timestamps would leak activity
  patterns to T2 adversaries.)
- **No host-app metadata.** Custom namespaces (1+) are
  application-defined; reserved namespaces (0..=4) are listed in
  `src/space/index.rs`.

## 11. Audit checklist for reviewers

A format-focused review can confirm or deny:

1. § 1: header layout (48 bytes), salt randomness, params parsing;
   confirm the absence of `container_id` from the cleartext header.
2. § 2: chunk wire layout, AEAD inputs, AAD construction (with
   per-space derived `container_id`), magic sanity check.
3. § 3: key derivation chain. Confirm:
    - Stage 2 `b"hv/v3/master" || u32_le(version)` BLAKE3 step
      exists in [`crypto/kdf.rs::derive_master_key`](../../../crates/hidden-volume/src/crypto/kdf.rs);
    - Stage 3 `[0x01] || context` kind-tag prefix exists in
      [`crypto/derive.rs::derive_subkey`](../../../crates/hidden-volume/src/crypto/derive.rs);
    - Stage 4 `[0x02] || container_id || u64_le(slot)` exists in
      [`crypto/derive.rs::derive_chunk_key`](../../../crates/hidden-volume/src/crypto/derive.rs);
    - test vectors in `tests/parser_fuzz.rs`.
4. § 4: per-kind payload encodings, especially CommitPayload's
   `tx_root_hash` invariant.
5. § 5: 3-fsync barrier ordering exists in code (cross-check
   `src/space/mod.rs::commit_tx` + `docs/en/security/audits/fsync.md`).
6. § 6: discovery scan is O(N) AEAD attempts, no
   `kind`-conditional branching that distinguishes wrong-password
   from no-such-space at the timing layer.
7. § 7: cross-version reject is **doubly bound** (policy + crypto).
8. § 8: format constants match `src/lib.rs` and
   `src/chunk/format.rs` source.
9. § 9: reservation bytes are checked / rejected as documented.
10. § 10: no leaked cleartext field beyond §1.

## 12. Cross-references

- `DESIGN.md` — rationale, threat model, design choices.
- `docs/en/security/threat-model.md` — formal invariants (D1 / D2 / I1-3 / R1 /
  M1 / C1) defended by this format.
- `docs/en/security/audits/constant-time.md`, `docs/en/security/audits/memory.md`,
  `docs/en/security/audits/plaintext.md`, `docs/en/security/audits/fsync.md` — implementation-
  level audit notes.
- `docs/en/guide/migration.md` — vN → vM transition procedure.
- Source: `src/chunk/format.rs`, `src/container/header.rs`,
  `src/crypto/kdf.rs`, `src/crypto/derive.rs`,
  `src/space/superblock.rs`, `src/space/index.rs`,
  `src/space/log.rs`, `src/tx/commit.rs`.
- Tests: `tests/parser_fuzz.rs` (proptest roundtrip + decode-doesn't-
  panic for every wire format), `tests/header_params.rs`,
  `tests/v3_key_schedule.rs` (v3 regression invariants).

## 13. Format change log

| Version | Date | Change | Document |
|---|---|---|---|
| v1.0 | (project start) | Initial layout. | this document (historical) |
| v2 | 2026 audit pass 13 (R-NSKIND) | `CommitPayload` per-root grew from 41 → 42 bytes (added `kind` byte distinguishing Kv from Log). | this document (historical) |
| **v3** | **2026-05-28** | **#8 kind-tag bytes** (`derive_subkey` 0x01 / `derive_chunk_key` 0x02), **#9 cryptographic version-binding** (post-Argon2 BLAKE3 over `params.version`), **#10 per-space derived `container_id`** (removed from cleartext header). `HEADER_LEN`: 80 → 48. | this document (current) |
| v4 (planned) | TBD | First post-1.0 generation. Requires an explicit format-freeze policy decision. | TBD |
