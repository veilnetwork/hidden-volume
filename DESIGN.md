# hidden-volume — design

🇬🇧 **English** · [🇷🇺 Русский](DESIGN.ru.md)

Formalization of the deniable multi-space container idea. This document is the
source of truth for implementation; code should reference invariants by number.

## 0. Scope and non-goals

**In scope:**
- A single container file on disk.
- Multiple independent spaces, each with its own password.
- Append-only writes, AEAD per-chunk, per-space encrypted superblock + index.
- Crash-safe commit, damage localization within the open space.

**Non-goals (worth fixing expectations explicitly):**
- We do not hide the fact that the file is encrypted. A file of pure entropy
  is distinguishable from an ordinary file; deniability is about "how many
  passwords and what data inside", not about "the file does not look like
  ciphertext".
- We do not protect against application-level leaks (recently-opened,
  thumbnails, IME, swap, system logs). That is the responsibility of the
  host application.
- We do not do network synchronization in this crate.
- We do not do `async`. The core is synchronous, std-only. The async wrapper
  is a separate crate.

## 1. Threat model

> The full formal version of the threat model lives in
> `docs/en/security/threat-model.md` (intended for external crypto review).
> Below is a concise summary for DESIGN readers; in case of disagreement
> between the two documents `THREAT_MODEL.md` is more detailed, but the
> invariants are the same.

**Adversary capabilities:**
1. A one-shot snapshot of the container file.
2. Multiple snapshots of the file over time (rollback / forensic timeline).
3. Coercion to disclose *one* password.

**Properties that must hold:**
- **D1 — Single-snapshot indistinguishability**: given only the file, the
  adversary cannot distinguish a container with N spaces from a container
  with M spaces (for any N, M ≥ 1) at a fixed file size.
- **D2 — Compelled-key plausible deniability**: having disclosed the
  password for space A, the user can plausibly claim that no other spaces
  exist. The adversary, given the file and password A, must not have
  cryptographic evidence of the existence of space B.
- **I1 — Per-chunk integrity**: any modification of chunk bytes is detected
  on attempt to decrypt it with the corresponding key.
- **I2 — Tail-corruption tolerance**: corruption of the file tail rolls the
  space back to the last valid checkpoint without losing it entirely.
- **I3 — Cross-space isolation**: the owner of space A can neither read nor
  intentionally damage space B. By accident — yes (see §6).

**Out-of-scope threats:**
- Multi-snapshot diffing with an active writer (T2): the adversary sees that
  the file grew — this discloses only the fact of writing, not the content
  and not which space. Masked by dummy writes, but that is policy, not a
  property.
- **Multi-snapshot per-byte diffing (T2'):** with in-place rewrite or
  tombstone (see §6), a specific slot i changes content between two file
  snapshots. From this the adversary concludes "slot i is not garbage, it
  belongs to an active space", narrowing the set of possible hidden-space
  slots. Full masking would require periodic rewriting of random garbage
  slots with fresh random, which is expensive and does not give perfect
  coverage. We accept this as a known limitation under T2.
- Application-side side-channel timing.
- RAM/swap forensics.

> Note: byte-level wire-format reference is `docs/en/reference/format.md`
> (canonical spec for v1.0 freeze + external crypto review).
> §2-§10 below remain the rationale + design-choice narrative
> pointing at the same byte layout.

## 2. Container layout

```
offset  0   : 32 bytes  container_salt          (cleartext, uniform random)
offset 32   : 16 bytes  argon2_params           (cleartext, structured)
offset 48   : padding to CHUNK_SIZE             (uniform random)
offset CHUNK_SIZE * (1 + i) : chunk[i]          (i = 0, 1, 2, ...)
```

**v3 change (closes D1-A2 fingerprint).** The 32-byte `container_id`
field that v2 stored at offset 32..64 has been removed from the
cleartext header. `container_id` is now derived **per-space** from
the versioned master key inside
[`crate::crypto::derive::SpaceKeys::from_master`] — nothing in the
cleartext header carries a per-space identifier. See
[`docs/en/reference/format.md`](docs/en/reference/format.md) §1.1.

**Invariants:**
- `CHUNK_SIZE = 4096` bytes (fixed at the format level). See §10 on the choice.
- File size is always a multiple of `CHUNK_SIZE` and ≥ `CHUNK_SIZE`.
- All bytes of the file except the first 48 (salt + params) must be
  statistically indistinguishable from uniform random for an observer
  without keys.
- No other cleartext fields. No magic, no format version marker, no counters.

**container_salt** — single KDF salt shared by all spaces. The fact that it
is single does not disclose spaces: a salt is a standard artifact of any
password-derived crypto and is not considered a deniability leak.

**argon2_params** — Argon2id parameters for this container (DESIGN §4,
§11.1). Layout (16 bytes):

```
offset 32..36  : m_cost_kib    u32 LE   (memory in KiB)
offset 36..40  : t_cost        u32 LE   (iterations)
offset 40..44  : p_cost        u32 LE   (parallelism lanes)
offset 44..48  : params_version u32 LE  (packed; low 16 bits = format_version,
                                          currently 3; bits 16..24 = padding
                                          policy index; bits 24..32 reserved)
```

Does not disclose the structure of spaces — only the cost of one brute-force
attempt, which is visible one way or another in any
encrypted-with-password artifact. Library refuses to open a container with
`format_version != 3` or `params < Argon2Params::MIN`. The reject is
**doubly bound** in v3: by `Argon2Params::validate()` policy AND by the
v3 cryptographic version-binding step in the key schedule (§4), so
even a tampered policy gate would still derive a different master key.
v1 (pre-pass-13) and v2 (post-pass-13) containers are rejected; pre-1.0
— breaking is acceptable.

## 3. Chunk format (on disk)

Each chunk is exactly `CHUNK_SIZE` bytes. On disk there are no fields in
the clear: it is one continuous block that looks like uniform random.

Logically a chunk consists of:

```
[ nonce : 24 ] [ ciphertext : CHUNK_SIZE - 24 - 16 ] [ tag : 16 ]
```

- **nonce** — 24 bytes, generated by a fresh cryptographic RNG for each
  write. Stored in the clear (as part of chunk bytes). Uniform random nonce
  ⇒ externally indistinguishable from noise.
- **ciphertext + tag** — XChaCha20-Poly1305(`chunk_key`, `nonce`, `aad`,
  plaintext). AAD = `container_id || u64_le(slot_index)`. The
  `container_id` here is the **per-space derived** value (§4), not a
  field read from the cleartext header. Slot binding defends against
  move-attack (relocating a chunk to another slot).

**Plaintext layout (`CHUNK_SIZE - 40` bytes = 4056):**

```
[ magic : 4 ]  = b"HVC1"  // only inside plaintext, never visible without key
[ kind  : 1 ]  // ChunkKind enum
[ flags : 1 ]  // compression, etc.
[ seq   : 8 ]  // per-space monotonic sequence number
[ payload_len : 2 ]  // ≤ payload area
[ payload : up to 4040 ]
[ pad : remainder ]   // random bytes (irrelevant — encrypted away)
```

`magic` is needed only as a cheap sanity check after decrypt: if the
AEAD-tag passed but magic does not match, we either broke our own format
or hit an astronomically unlikely collision. This is a plaintext-side
check; from the outside magic is invisible.

**ChunkKind:**
- `0x01` Superblock — root of a space.
- `0x02` IndexNode — B+ tree node (Leaf / Internal) of a namespace's KV index.
- `0x03` — reserved (was the v0.1 `Data` chunk; replaced by per-batch
  encoding inside `DataBatch`. Decoders MUST treat 0x03 as unknown.)
- `0x04` — reserved (was the v0.1 `Journal` chunk; never shipped — vacuum
  + scrub-old-on-success replaced the intent-log design. Decoders MUST
  treat 0x04 as unknown.)
- `0x05` Commit — Tx completion marker; payload is the Merkle root over
  per-namespace IndexRoots.
- `0x06` DataBatch — zstd-compressed batch of log entries (see §11.4 in
  the canonical spec at `docs/en/reference/format.md`).

**Garbage chunks**: `CHUNK_SIZE` bytes of pure RNG. They have no key and no
plaintext; they will never "decrypt successfully" under any space.

## 4. Key schedule (v3, since 2026-05-28)

```
// Stage 1: Argon2id over (password, container_salt, params).
argon_out        = Argon2id(password, container_salt, params)        // 32B

// Stage 2 (v3 #9): cryptographic format-version binding.
versioned_master = blake3_keyed(argon_out,
                                "hv/v3/master" || u32_le(params.version))

// Stage 3 (v3 #8 + #10): per-space subkeys with kind-tag bytes.
container_id     = blake3_keyed(versioned_master,
                                [0x01] || "hv/v3/container_id")     // 32B, per-space
aead_root        = blake3_keyed(versioned_master,
                                [0x01] || "hv/v3/aead_root")        // 32B

// Stage 4: per-chunk AEAD key for slot i.
chunk_key(i)     = blake3_keyed(aead_root,
                                [0x02] || container_id || u64_le(i))
```

`argon_out` and `versioned_master` are dropped immediately after use;
only `container_id` and `aead_root` are retained inside the per-space
`SpaceKeys` (which is `ZeroizeOnDrop`). Per-slot `chunk_key` is
re-derived on each access.

**Three v3 hardenings encoded in this schedule** (2026-05-28):

- **#8 kind-tag bytes.** Each BLAKE3-keyed input starts with an
  explicit kind tag: `0x01` (`SUBKEY_KIND_TAG`) for subkey
  derivations, `0x02` (`CHUNK_KEY_KIND_TAG`) for per-slot
  derivations. Replaces the pre-v3 length-distinguishes convention.
- **#9 cryptographic version-binding.** The whole `params.version`
  u32 (format_version + padding_policy_index + reserved) is folded
  into `versioned_master` through the Stage 2 BLAKE3 step. Cross-
  version key reuse is closed cryptographically, not only by
  `validate()` policy. As a side effect, F-PAD (audit pass 9)
  graduates from silent privacy-degradation to DoS-class visible
  failure: a tampered policy byte now causes
  `Error::AuthFailed`, not silent padding-policy downgrade.
- **#10 per-space derived `container_id`.** The cleartext header no
  longer carries `container_id` (closes D1-A2 fingerprint).

The v0.1 sketch derived two more sub-keys — `space_kdf_key` and
`space_chunk_key` — that no callsite ever consumed; audit pass 1
B1+B2 removed them, saving 64 B/space + 1 BLAKE3 derivation per
open.

- **Argon2id parameters**: `Argon2Params::DEFAULT` is `t=3, m=64 MiB, p=1`
  (mobile-friendly). Tunable per `Container::create_with_options`. The
  params are persisted in the cleartext header at offset `64..80`
  (audit pass 8 S1: bits 16..24 of the `version` u32 also encode the
  persistent padding-policy preset; see `docs/en/reference/format.md` §1.2).
  Library presets: `Argon2Params::LIGHT/DEFAULT/HEAVY`; floor:
  `Argon2Params::MIN` (m=8 MiB, t=2, p=1) — open/create rejects anything
  below it, which closes the malicious-host downgrade attack.
- **Per-chunk derivation** gives every slot a unique key; even if a single
  nonce accidentally repeats between slots (negligible probability at
  192-bit), security is not affected.
- All keys live in `Zeroizing<[u8; 32]>`.

## 5. Space discovery (open path)

Given a password:

1. Read `container_salt` and `params` from header (v3: `container_id`
   is no longer in the header — it is derived in step 3).
2. Argon2id over `(password, container_salt, params)` → `argon_out`.
   Expensive: once per unlock, ~100 ms on mobile.
3. BLAKE3-keyed version-bind → `versioned_master`; then derive
   `container_id` and `aead_root` from it (§4).
4. Scan slots `i = 0..N`:
   - compute `chunk_key(i)`,
   - attempt XChaCha20-Poly1305 decrypt with AAD,
   - on success — check magic, parse `kind`/`seq`,
   - put into in-memory map keyed by `(kind, seq)`.
5. Pick the highest-seq Superblock that **AEAD-decrypts** and
   `Superblock::decode`-parses (audit D2 fallback walks down by seq
   on decode failure). The chosen SB's `root_hash` is **trusted on
   adoption** — the chain of `IndexNode + Commit + DataBatch`
   reachable from it is verified **lazily** at the first read that
   touches it, or **eagerly** if the host-app calls
   [`crate::Container::open_space_verified`](crates/hidden-volume/src/container/mod.rs)
   instead of [`crate::Container::open_space`]. v0.x docs of this
   step suggested eager full-chain validation in `open_space`; the
   shipped behaviour has always been lazy — `open_space_verified`
   is the explicit opt-in for the eager-validation use case (e.g.
   integrity audit on container restore).
6. Load chunk map → now we know which slots of the space are "live".

**Cost**: N XChaCha20-Poly1305 decrypt traces. On a modern CPU ~5 GB/s ⇒ a
1 GB container is scanned in ~200 ms. On ARM mobile ~1 s. This is
unlock-time, not per-message; acceptable.

**Streaming memory** (v0.6): scan does not accumulate decrypted plaintexts.
Per iteration there is one ciphertext chunk (4 KiB stack) and one Plaintext
(≈4 KiB heap), both die before the next iteration. From persistent state
only `owned_slots: Vec<u64>` (8 B/owned chunk), `commit_history: Vec<u64>`
(8 B/Superblock after dedup), and the payload of the current max-seq
Superblock (~48 B) accumulate. Total — on the order of 16 B per owned chunk
regardless of container size. That is ~250× less than holding all
Plaintexts during the scan; critical for weak devices with large
(multi-GiB) containers.

**Why this is deniable**: exactly the same N decrypts are performed both
when no other spaces exist and when there are three. The unlock timing of
one space does not depend on the existence of others.

## 6. Append (write path)

Append-only. Writing to space A:

1. Prepare a set of chunks for the transaction:
   - 0..k DataBatch chunks (zstd-compressed log entries; one per log
     namespace touched in this Tx)
   - 0..m new IndexNode chunks (B+ tree leaves + internals for KV
     namespaces touched in this Tx)
   - 1 Commit chunk (Merkle root over per-namespace IndexRoots)
   - 1+ new Superblock chunks (replicas, configurable; default 3)
2. Get the current slot count `N` (from `file_size / CHUNK_SIZE - 1`).
3. For each new chunk allocate the next free slot `N, N+1, ...`, encrypt
   with `chunk_key(slot)`, write.
4. **fsync** (3-fsync barrier protocol — DataBatch+Index → Commit → SB).
5. Optionally — top up with garbage chunks (padding policy, see §8).

**Inv-W1 (final, v1.0)**: the writer **only appends**. New chunks land
at slot indices `≥` current `N`; existing slot bytes are NEVER
rewritten. Forward-secrecy — i.e. making "deleted" KV entries and
"replaced" log entries unrecoverable — is achieved by a separate
**vacuum + scrub-old-on-success** pass (see below), not by per-slot
rewrite. This invariant is load-bearing for crash safety: a torn
in-place write would corrupt a previously-committed chunk that the
recovery path needs.

(The v0.1 design sketch additionally proposed `Tx::update_slot` and
`Tx::tombstone_slot` slot-level operations. Both were
**SKIPPED** in v0.2 — see `TASKS.md` — because they fundamentally
conflict with append-only crash safety. The use cases they targeted
are covered by vacuum + scrub. The §12 API skeleton historical note
records this superseding.)

**Vacuum** (v0.2 implementation: `Space::vacuum_orphans`):
  - `commit_tx` stays append-only (no scrub — needed for crash recovery
    fallbacks).
  - On `Container::open_space`, after a successful `scan_and_recover`,
    `vacuum_orphans` is invoked automatically: walk the tree from the
    current Superblock, collect reachable IndexNode slots, scrub
    owned-but-not-reachable IndexNode chunks (overwrite with uniform random).
  - On `Container::open_space_verified` (audit pass 17 A) the auto-vacuum
    is **deferred** until after `verify_integrity` succeeds — a failed
    integrity walk leaves the file untouched, preserving the
    "no observable mutation on verify failure" guarantee for forensics
    and backup tooling. On success the post-verify vacuum restores
    the standard `open_space` forward-secrecy invariant.
  - Idempotent — a repeat call without commits in between does nothing.
  - **Does NOT scrub DataBatch chunks** (a single batch may contain
    still-live records, referenced by other log_ids — that is the domain
    of v0.3 compaction which knows how to repack batches).
  - **Does NOT scrub old Superblock/Commit chunks** — they are needed as
    fallbacks for crash recovery in case the current Superblock is
    corrupted. v0.3 compaction sweeps them.
  - Trade-off: between a commit and the next open, forensics with the
    password can read "deleted" KV entries. For a typical app-launch
    workflow the window is small; for paranoid forward secrecy the host-app
    can call `vacuum_orphans` explicitly after a privacy-sensitive Tx.

**Inv-W2**: the Commit chunk must be written and fsync'd AFTER all of its
data/index/journal chunks. Otherwise the reader will roll the transaction back.

**Inv-W3**: the new Superblock is written after Commit. The reader picks
the Superblock with the largest seq whose Commit chain is fully valid.

## 7. Recovery

After a crash:
1. Scan as on open (§5).
2. Among our Superblocks pick the one with the largest seq for which:
   - all referenced IndexNode chunks decrypt,
   - there is a valid Commit chunk with a matching root hash,
   - the hash chain back to the previous checkpoint is intact.
3. If none — take the previous one by seq, and so on.
4. Slots after the last valid Superblock are treated as "tail garbage" —
   they are simply ignored. We do not truncate the file (that would be
   visible from the outside as shrinkage — a leak about a failed write).

## 8. Padding policy

Policy is a separate runtime config, not part of the on-disk format.
Implementations (see `src/padding/mod.rs`):

- **`PaddingPolicy::None`** — only real chunks. Tests / debug. In
  production this exposes the real write tempo to a multi-snapshot adversary.
- **`PaddingPolicy::BucketGrowth { bucket_chunks }`** — after each
  successful Tx commit the file is padded with garbage up to the nearest
  multiple of `bucket_chunks`. The observer sees file size changing in
  discrete steps of size `bucket_chunks * CHUNK_SIZE`. Worst-case
  overhead: `bucket_chunks - 1` extra chunks per commit.
- **`PaddingPolicy::FixedRatio { garbage_per_real_x100 }`** — adds garbage
  proportional to real chunks: `garbage_per_real_x100 = 100` gives 1:1
  (file grows 2× actual data). Smoother growth, without bucket
  quantization.

**Initial garbage** (`ContainerOptions::initial_garbage_chunks`) — how many
garbage chunks to write at `Container::create_with_options` time. Creates
the appearance "this file has been ~N MiB all along". Forensics sees a
file of size `(1 + initial_garbage_chunks) * CHUNK_SIZE` byte-for-byte
uniform-random (except the 48-byte v3 header).

**Recommended defaults for a typical messenger deploy:**
- `initial_garbage_chunks = 2048` (8 MiB decoy size — looks like a small backup)
- `padding_policy = BucketGrowth { bucket_chunks: 256 }` (1 MiB quantization)

**Notes:**
- The padding policy **is not persisted in the file** — it is runtime-only
  config. The host-app must re-set it via `Container::set_padding_policy`
  after `open`. No on-disk field → no metadata leak about the chosen policy.
- Garbage chunks: `CHUNK_SIZE` bytes of uniform random. Visually identical
  to AEAD-encrypted chunks of any space. Indistinguishable from
  real-but-foreign-space data.
- Padding does not help against T2 per-byte diff (you can see which bytes
  changed), but it does help against T2 file-size diff. These are two
  different leak channels.

## 9. Compaction

The fundamental problem: the writer of space A does not see B/C/garbage
chunks and cannot tell them apart. Any operation that removes a "not ours"
chunk could destroy a foreign hidden space.

Under the hood there is exactly one primitive: `repack(passwords) →
new_file` — open each space with the corresponding password, copy its
live chunks (per chunk map) into a new container, treat everything else
(what none of the passed keys could decrypt) as deletable.

Audit pass 16 (R-STREAMING-REPACK) made `repack` memory-bounded: log
namespaces are walked one paginated page at a time via
`iter_log_after(ns, cursor, log_page_size)` with per-page `Tx::commit`
on the destination, so the working set is ≈ 4 MiB per page regardless
of total log volume. KV namespaces still collect once per namespace
(bounded structurally by the 2-level B+ tree cap of ≈ 5–10 K entries).
The previous implementation kept every live entry in memory across
both phases (Phase 1: read all, Phase 2: write all) — multi-GiB log
namespaces could OOM the host.

The API wraps the primitive in three explicit modes:

- `Container::append_garbage(n)` — only tops up garbage. Always safe. The
  file only grows; nothing is lost.

- `Container::compact_known(passwords)` — the user knowingly sacrifices
  non-disclosed spaces. Semantics: "keep only these, throw out everything
  else, I know what I'm doing". Used in case of loss/revocation of one of
  the space passwords.

`compact_known` is the only "compact" mode shipped. The original v0.1
sketch also proposed `compact_all` ("these are ALL passwords; everything
else is garbage"); audit pass 2 B7 removed it because its body was
bit-identical to `compact_known` — only the API wording differed, and
the wording asymmetry was a footgun (a user could call `compact_all` in
the wrong context and lose a hidden space). The host-app's UI is the
right place to express the "I asserted this is exhaustive" semantic, not
the library API.

**v3 note on `container_id` rotation.** Compaction produces a fresh
`container_salt`, which in v3 causes every space inside the new
container to derive a fresh `container_id` (per-space, from the
versioned master — see §4). The cross-container relocation defense
is therefore preserved by the same mechanism as v2; the only
observable change is that no per-space identifier sits in the
cleartext header any more.

There is no "compact in the background" and no
`compact_with_open_space_only` for the same reason.

### Slot-reuse prohibition (deniability constraint)

**Scrubbed slots are NOT reused** by subsequent writes. Every
successful Tx commit appends new chunks at the end of the slot
grid; `vacuum_orphans` and `vacuum_data_batches` overwrite orphan
slots with uniform-random bytes but **leave the file size
unchanged**. Reclaiming disk space requires `compact_known` (§9
above), which atomically rewrites the file with a fresh
`container_id`.

This is **not a missed optimization** — it is load-bearing for
the deniability invariant. A T2' multi-snapshot adversary
diffing snapshots `S1, S2, S3, …` would observe:

```
offset 4096 * slot_K, S1: bytes_X     ← legitimate write
offset 4096 * slot_K, S2: bytes_X'    ← scrub (overwrite #1)
offset 4096 * slot_K, S3: bytes_Y     ← if we reused this slot: overwrite #2
```

A second overwrite at the same offset is an unambiguous "this
slot has live state" signal that cannot be explained away as
decoy padding (decoy chunks are only ever appended, never
mutated). Therefore `Tx::commit` does NOT search for free slots
in the middle of the file; it always extends. The cost — file
size monotonically grows until the host-app schedules a
`compact_known` — is the price of T2' resistance.

The host-app trigger for compaction is documented at
[`docs/en/guide/operations.md`](docs/en/guide/operations.md) §5.4
(live-ratio threshold, size budget, idle-time defer, privacy
event). `SpaceStats::utilization_ratio()` returns the relevant
metric; `Container::compact_known` is the only mechanism that
turns scrubbed slots back into reclaimed disk bytes.

## 10. Format parameters

| Parameter | Value | Rationale |
|---|---|---|
| `CHUNK_SIZE` | 4096 | Multiple of page size; AEAD overhead 40B ⇒ 4056 payload; reasonable balance between fragmentation and slot-scanning |
| AEAD | XChaCha20-Poly1305 | 192-bit nonce → random nonces are safe without a counter. AES-GCM (96-bit) requires counter state, which composes badly with multi-space writers. AES-GCM-SIV is rejected due to the lower maturity of Rust implementations; AEGIS-256 — same. The per-slot KDF (see above) already provides misuse resistance, so XChaCha-Poly1305 is enough. |
| KDF | Argon2id, t=3 m=64MiB p=1 | OWASP recommendation for mobile |
| Hash | BLAKE3 | keyed mode, fast, used for derivation and Merkle |
| Header size | 48B + padding to `CHUNK_SIZE` | salt + argon2_params + slack. v2 was 80B (had cleartext `container_id`); v3 derives `container_id` per-space (§4). |
| `MAX_OPEN_SCAN_CHUNKS` | 16 × 1024 × 1024 (= 64 GiB at `CHUNK_SIZE`) | Hard cap on slot grid size. Both write-side (audit pass 17 B: `Container::create_with_options`, post-commit padding, `repack` destination) and read-side (audit pass 16 TM1: all three open-scan paths) refuse to grow past or scan past this cap. Bounds DoS-via-inflated-file (T2 adversary) and the create-then-can't-reopen footgun. |

## 11. Open questions

This section catalogues design decisions that were open at v0.1 plan
time. Items 1, 2, 4, 5 have shipped resolutions; item 3 is a soft cap
documented under threat-model "out of scope".

1. **Argon2 params storage.** ✅ Resolved. Parameters are stored in the
   cleartext header (v3: offset 32..48; in v2 it was 64..80, see §2).
   This is not a deniability
   leak — params describe the cost of a single brute-force attempt and say
   nothing about the number of spaces or content. The library exposes
   presets (`Argon2Params::LIGHT/DEFAULT/HEAVY`) and a floor
   (`Argon2Params::MIN`, below which open/create is rejected). Audit
   pass 1 D1 also added an upper ceiling
   (`MAX_M_COST_KIB` = 1 GiB, `MAX_T_COST` = 100, `MAX_P_COST` = 64) to
   close the OOM DoS where a tampered header would force the next opener
   into a 4 TiB Argon2 derivation.

2. **Replay/rollback protection.** ✅ Delegated to host-app. A snapshot
   adversary (T2) can roll the file back to an old version — the library
   alone does not detect this. The host-app contract is captured in
   `docs/en/guide/multi-device.md`: `Space::commit_seq()` — the current
   monotonic commit counter; `Space::commit_history()` — the list of all
   seqs whose Superblocks are still on disk and decrypt under our key (to
   distinguish rollback from a fork). Anchor ONLY for spaces whose
   existence is not deniability-sensitive.

3. **Maximum slot count.** With `u64` seq and 4 KiB chunks the file goes
   up to 64 EiB. The real limit is memory at scan time. Practical
   guidance lives in `docs/en/guide/operations.md` ("recommended container
   size"); the library does not enforce a hard cap.

4. **Compression boundary.** ✅ Resolved by the `DataBatch` chunk kind
   (0x06). The messenger's high-volume namespace (`MESSAGE_LOG`) writes
   per-Tx zstd-compressed batches via `Tx::append_log`; KV namespaces
   continue to use uncompressed `IndexNode` chunks because compressing
   tiny B+ tree nodes regresses size. See `crates/hidden-volume/src/space/log.rs`.

5. **Duress password as first-class.** ✅ Resolved by NOT declaring it
   in the API. A duress space is just another space the host-app
   designates as such — the library never sees the distinction. This
   keeps the format ignorant of duress, which is the right boundary for
   plausible deniability (no on-disk byte distinguishes a duress space
   from any other space).

6. **Format version cryptographic binding.** ✅ Closed in v3
   (2026-05-28). The v2 ship-with-policy-gate posture was upgraded to
   a doubly-bound reject in the v3 key schedule (§4): `params.version`
   is now folded into `versioned_master` through a post-Argon2 BLAKE3
   step. A hypothetical v4 reader that loosened
   `Argon2Params::validate()` would still derive a *different*
   `master_key` than the v3 writer that sealed the file, hitting
   `Error::AuthFailed` on the first AEAD attempt. The lockdown
   requirement that audit M5 (2026-05-10) raised for v3 has shipped
   via option (a) — fold version into the KDF chain. See
   [`crypto/kdf.rs::derive_master_key`](crates/hidden-volume/src/crypto/kdf.rs)
   and threat-model F-PAD §4.1 (now reclassified to DoS-only).

## 12. API skeleton (v0.1 sketch — kept for historical context)

> **Note.** This section reproduces the original v0.1 design sketch.
> The actual v1.0 API has evolved through 10 audit passes (lock modes,
> per-namespace KV, log streaming, async/FFI wrappers, cancellation,
> persistent padding, …). For the canonical current surface refer to
> `cargo doc --workspace --all-features --open`, the `bindings/`
> directory for FFI shape, and `docs/en/reference/format.md` for the
> on-disk format spec. The sketch below is preserved because the
> design rationale it captures (KV-as-foundation, namespace split,
> deniable compaction) is still load-bearing.

```rust
pub struct Container { /* file handle + cached header */ }

impl Container {
    pub fn create(path: &Path) -> Result<Self>;
    pub fn open(path: &Path) -> Result<Self>;
    pub fn append_garbage(&mut self, count: usize) -> Result<()>;
    /// "Keep only these spaces, drop everything else (intentional)."
    pub fn compact_known(&mut self, passwords: &[Password]) -> Result<()>;
}

pub struct Space<'c> { container: &'c mut Container, keys: SpaceKeys, state: SpaceState }

impl Container {
    pub fn create_space(&mut self, password: &Password, params: SpaceParams) -> Result<SpaceHandle>;
    pub fn open_space(&mut self, password: &Password) -> Result<Space<'_>>;
}

impl<'c> Space<'c> {
    pub fn begin_tx(&mut self) -> Tx<'_, 'c>;
}

pub struct Tx<'s, 'c> { /* ... */ }

impl<'s, 'c> Tx<'s, 'c> {
    pub fn put(&mut self, namespace: Namespace, key: &[u8], value: &[u8]) -> Result<()>;
    pub fn delete(&mut self, namespace: Namespace, key: &[u8]) -> Result<()>;
    pub fn append_log(&mut self, namespace: Namespace, log_id: u64, entry: &[u8]) -> Result<()>;
    pub fn delete_log(&mut self, namespace: Namespace, log_id: u64) -> Result<()>;
    pub fn commit(self) -> Result<u64>;
}
```

The lower layer is a per-namespace KV + append-only log store with
atomic multi-namespace transactions. The messenger is built on top:
message stream = `MESSAGE_LOG` namespace via `append_log` / `delete_log`; contacts =
`CONTACTS` KV namespace; media = `MEDIA` KV namespace with large values
(possibly chunked by the host-app). Slot-level `update_slot` /
`tombstone_slot` from the v0.1 sketch were superseded by `vacuum` +
`scrub-old-on-success`; that path is incompatible with the append-only
write invariant (Inv-W1) which is load-bearing for crash safety.

## 13. Module layout (canonical)

The actual v1.0 layout is a 4-crate workspace; the original v0.1 sketch
showed only `src/`. See `README.md` § Architecture for the full diagram.
Summary:

```
crates/hidden-volume/      — sync core: crypto/, chunk/, container/,
                              space/{mod,commit,vacuum,log_iter,integrity}.rs,
                              tx/, padding/, open/, cancel.rs, error.rs,
                              bin/hv.rs (feature `cli`)
crates/hidden-volume-rt/   — internal: OwnedSpace + run_blocking
                              (shared by async + ffi)
crates/hidden-volume-async/— Tokio wrapper: AsyncContainer / AsyncSpace
crates/hidden-volume-ffi/  — uniffi 0.31 bindings: SpaceHandle /
                              AsyncSpaceHandle (Kotlin / Swift / Python / Ruby)
```

The v0.1 sketch listed `space/journal.rs` and `space/keys.rs` —
neither shipped in v1.0. `journal.rs` was superseded by vacuum +
scrub (audit pass 1 A1); `keys.rs` is consolidated into
`crypto/derive.rs` as `SpaceKeys`.

## 14. What was built first (v0.1 milestone, historical)

The minimum for an end-to-end "create → open → put → reopen → get" test:

1. `crypto::*` — all primitives.
2. `chunk::format` — encode/decode plaintext, AEAD seal/open.
3. `container::header` + `container::file` — write/read fixed-size slots.
4. `crypto::derive::SpaceKeys` — Argon2 + derivation chain.
5. `space::superblock` — single chunk-pointer per space.
6. `open` — scan + pick latest superblock.
7. `Tx` — single-record commit (without a fully-fledged KV index).

v0.2 added the per-namespace B+ tree, multi-Tx atomicity, and the
`commit_history` chain. v0.3 added vacuum + integrity walks. v0.4 added
the lock modes. v0.5–v0.7 added padding, parallel/mmap scan, and the
async wrapper. v0.8 added the FFI crate. See `TASKS.md` for the
milestone log and `TASKS_ARCHIVE.md` for the closed work history.
