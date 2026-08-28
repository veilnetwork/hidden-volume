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
only `owned_slots` (a BITMAP — one bit per slot in the file, not eight bytes
per owned chunk; see `space::slots`), `commit_history: Vec<u64>` (8 B per
distinct commit seq, replicas collapsed as the scan goes), and the payload of
the current max-seq Superblock (~48 B) accumulate. Measured end to end by
`tests/open_peak_memory.rs`: **0.16 bytes of peak heap per owned slot**, which
is ~2.5 MiB at the 16M-slot scan cap. It was 27.5 B/slot — 440 MiB at the cap
— while `owned_slots` was a `Vec<u64>` (report9 HV-13). That is ~250× less than holding all
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
2. For each new chunk allocate a slot: a uniformly-drawn slot from the
   **decoy pool** if one is available, otherwise the next slot past the
   end (`N, N+1, ...` from `file_size / CHUNK_SIZE - 1`). Encrypt with
   `chunk_key(slot)`, write.
3. **fsync** (3-fsync barrier protocol — DataBatch+Index → Commit → SB).
4. Optionally — top up with garbage chunks (padding policy, see §8) and
   churn the decoys (see §9.1).

**Inv-W1 (revised 2026-08-06)**: the writer only ever writes to a slot
that is **not reachable from any superblock a reopen could select** —
by appending past the end of the grid, or by allocating a slot the
**decoy pool** vouches for. It is the unreachability that is
load-bearing for crash safety, not the appending: a torn in-place write
must not be able to corrupt a chunk the recovery path needs, and a slot
`vacuum_orphans` has retired is one no recoverable era references. See
§9.1 for the pool's accounting, the guards reuse inherits from vacuum,
and the one chunk kind (`Checkpoint`) that is still append-only.

Until 2026-08-06 this invariant read "the writer **only appends**", and
the stronger form bought exactly one thing the revised form does not:
it made the *forward* argument trivial. The revised form has to prove
unreachability instead, which it does by making reuse rest on vacuum's
existing proof rather than on a new one.

Forward-secrecy — making "deleted" KV entries and "replaced" log
entries unrecoverable — is still achieved by the separate **vacuum +
scrub-old-on-success** pass (see below).

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

`repack` is memory-bounded on both legs. Log namespaces are walked one
paginated page at a time via `iter_log_after(ns, cursor,
log_page_size)` (audit pass 16, R-STREAMING-REPACK) and KV namespaces
via `list_after(ns, cursor, kv_page_size)` (audit HV-02), each page
committed to the destination before the next is read — ≈ 4 MiB per log
page, ≈ 1 MiB per KV page, regardless of namespace size.

The KV leg collected a whole namespace until HV-02, and then handed
every pair to `Tx::put`, which copies it, so its peak was twice that
namespace's plaintext. It was written under the two-level B+ tree cap
of ≈ 5–10 K entries; audit HV-15 removed the cap (the index grows
levels on demand) and left the only remaining ceiling at the
container's own. Splitting one namespace's copy across several
destination transactions is sound here because the destination is a
file the call created — a failure between pages leaves a partial
`dest` that the caller discards. See
`docs/en/contributing/benchmarks.md`.
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

### 9.1 Slot reuse and decoy churn

Retired slots **are** reused. This section replaces the "slot-reuse
prohibition" that stood here until 2026-08-06, states the argument
that prohibition rested on, says what replaces it, and — the part
that matters most — says plainly what the replacement does not buy.

#### What the prohibition was protecting

A T2' multi-snapshot adversary diffing `S1, S2, S3, …` used to see
at most two distinct values at any one offset:

```
offset 4096 * slot_K, S1: bytes_X     ← legitimate write
offset 4096 * slot_K, S2: bytes_X'    ← scrub (overwrite #1)
```

Decoy chunks were written once and never touched again, so a
**third** value at one offset had no decoy explanation. "This
offset was rewritten twice" was therefore a reliable "live data
was here" oracle, and forbidding reuse was what kept the third
value from ever existing.

The prohibition worked and it cost the product its disk. Nothing
but `compact_known` ever returned a byte, so a messenger store that
deleted as much as it wrote grew without bound: on the reference
deployment a container reached **7.0 GB** and compacted to
**4.8 MB**.

#### What replaces it

The oracle is not "an offset was rewritten"; it is "an offset was
rewritten **and no decoy is ever rewritten**". Remove the second
half and the first says nothing. So decoy slots are re-randomized
too — **churn** — and reuse becomes safe.

The immediate objection is the right one: a churn on a timer moves
the distinguisher from *whether* an offset is rewritten to *how
often*. Real slots would change on every commit, decoys once an
hour, and a snapshot series would separate them trivially. The
churn is therefore **not on a timer**. It is defined by three rules,
each closing one way the two populations could be told apart:

1. **Same event.** Churn runs inside `commit_tx`, in the same
   post-publish block as the padding and under the same `fsync`.
   Reuse and churn land in one snapshot interval; there is no
   interval in which one happens and not the other.
2. **Same rate.** A commit that reuses `k` slots churns
   `k · CHURN_PER_REUSE` decoys, and `CHURN_PER_REUSE` is `1` today.
   The rate is a function of the workload, not of the clock, so it has
   no frequency of its own to leak.
3. **Same distribution.** Both draw uniformly at random from the
   **same pool**, without replacement within a commit. Allocation
   uses `DecoyPool::take`, churn uses `DecoyPool::sample_distinct`.
   A FIFO or lowest-index-first allocator would have given real
   writes an index-locality signature that a uniform churn does not
   share, and the adversary would separate them by *where* instead
   of by *how often*.

Rule 2 is a promise about the churn, so it has to be paid for out of
the pool **before** the reuse spends it. Both halves draw from the same
pool and reuse goes first: `take` removes a slot, and the churn then
samples what is left. A commit free to reuse the whole pool would leave
nothing to sample, and `sample_distinct` returns `n.min(len)` -- it
truncates in silence -- so the commit would keep rule 2 in name and
break it on disk.

An episode may therefore reuse at most

```
pool / (1 + CHURN_PER_REUSE)
```

slots, leaving the remainder to fund their churn (`reuse_floor_for`).
Past that it appends, which is a cost in growth and never in
deniability -- the direction this trade must always fail in. At
`CHURN_PER_REUSE = 1` that is an even split, the same split rule 2
describes on disk. A pool of one funds nothing and reuses nothing, and
a container right after its first `vacuum_orphans` is exactly where
that case lives.

The budget is spent where a slot leaves the pool, not decided once per
commit. `publish_superblock` reads the *era* half of the reuse
predicate once, before it burns the seq, and hands one answer to every
replica -- correct for a question about the era, wrong for a resource
the placements are consuming as they go.

Rule 1 has the matching consequence: `commit_tx` is the only place the
churn runs, so it is the only place reuse may happen.
`write_self_heal_checkpoint` publishes a superblock too, and it takes
its slots by appending rather than from the pool, because a reused slot
there is one no churn would ever cover.

#### The decoy pool, and why it is not "the garbage"

A writer of space A **cannot** tell a garbage chunk from space B's
live chunk — that is §9's whole premise, and it means "re-randomize
the garbage" is not an operation this format can express. Every slot
A did not write is a slot A must not touch.

What A can prove it owns and has retired is exactly two things, and
their union is the **decoy pool**:

- slots A scrubbed: orphan `IndexNode` / `DataBatch` chunks retired
  by `vacuum_orphans` / `vacuum_data_batches`, and superseded
  checkpoint chains;
- garbage A itself appended as post-commit padding (§8), whose slot
  range A watched itself write.

Cross-space disjointness is structural: a slot enters A's pool only
by A scrubbing a slot A owned, or by A appending past the end of the
file. Neither can name a slot another space ever wrote.

#### Durable accounting

The pool lives in the **checkpoint chain** (§5, `ChunkKind::Checkpoint`)
alongside the owned-slot set: one chain, one pointer from the
superblock, published atomically with an era, sealed under the same
per-space key. It is not a separate structure because it needs
nothing the owned set does not already have.

The checkpoint is refreshed lazily, so a recorded pool is routinely
**stale** — it may still name a slot a later commit already reused.
That is safe because the open path does not trust it:

```
pool_effective = pool_recorded \ owned_slots
```

A reused slot AEAD-decrypts under this space's key again, so the
scan reports it *owned*, so it leaves the pool whatever the
checkpoint said. The recorded pool may therefore under-report (the
cost is leaked disk, reclaimed by the next `compact_known`) and
cannot over-report for an honest writer. **Crash consistency needs
nothing else**: a pool entry lost to a crash is a leaked slot, never
a lost one.

Two consequences of putting it there:

- The fast-open scan must trial-decrypt the recorded pool slots as
  well as the recorded owned set. The completeness induction in
  `space/checkpoint.rs` used to rest on "no slot below the
  high-water becomes newly owned after the checkpoint", which held
  because writes only appended; reuse breaks that premise in exactly
  one place, and pool slots are that place. Visiting them restores
  the induction with `owned ∪ pool` as the covered region.
- Reuse is refreshed by a third trigger, `CHECKPOINT_MIN_POOL_DRIFT`.
  The existing trigger measures growth of the un-checkpointed tail —
  which is precisely what reuse suppresses, so without a pool-drift
  trigger the better reuse worked the less often the pool that
  enables it would be written down.

#### Crash safety

Reuse rests on **exactly** `vacuum_orphans`' proof and adds none of
its own: a pool slot is one vacuum already showed unreachable from
the era this handle names. It therefore inherits vacuum's
discipline, at the point of decision (`Space::reuse_permitted`):

- `attempted_seq > superblock.seq` — a publish got a replica onto
  the disk and then failed, so a reopen may select an era this
  handle has never seen, and "unreachable from the era I can see" is
  not a statement about that one. Reuse falls back to appending, the
  same way `vacuum_orphans` returns `Error::PublishUncertain`.
- `unreadable_newer_superblock` — a writer we do not understand
  published after us; same refusal, same reason.

The 3-fsync barrier is unchanged. A crash between the chunk writes
and the superblock publish leaves the previous era current, and that
era provably does not reference any slot the commit reused.

**Checkpoint chunks are the one kind that never comes from the
pool.** `write_self_heal_checkpoint` retires the chain it supersedes
into the pool and only then publishes the superblock naming the new
chain; in between, the on-disk superblock still points at the old
head. A `Checkpoint` chunk landing there would make a crash leave a
chain that reads as valid and is a *suffix* of the new one — a
silently incomplete owned set. Any other kind landing there decodes
as the wrong kind and the reader falls back to a full scan, which is
correct.

#### Keys

Reuse is sound for the cipher without any change to the key
schedule, and the reason is worth stating because the opposite would
be catastrophic. `derive_chunk_key(aead_root, container_id, slot)`
and the AAD are bound to the slot **index**, not to a write
generation, so a second chunk in slot K seals under the same key as
the first. What makes that safe is the nonce: `ChunkAead::seal`
draws a fresh random 192-bit XChaCha20 nonce per call, so two seals
into one slot share a key and share no keystream. This is exactly
the property §10 chose XChaCha20-Poly1305 for — a 96-bit nonce would
have needed counter state, and counter state is what reuse would
have broken.

#### What this buys, and what it does not

Stated honestly, because the prohibition it replaces was a real
protection and this is weaker in ways that matter.

**Preserved.** Within the pool, the number of times an offset has
been rewritten carries no information about whether it holds live
data. Reuse and churn are one write process — same event, same rate,
same distribution — so the per-offset rewrite counts have the same
law for decoys and for real chunks. This is strictly better than the
old design *inside* the pool, where a scrubbed slot was permanently
marked as an offset that had held real data and been retired.

**Lost — the anonymity set is the pool, not the file.** An offset
that has never changed is provably not in any pool. A T2' adversary
partitions the file into "never changed" and "changed", and learns
that this space's live data is somewhere in the second part. The
anonymity set for a real write is `SpaceStats::reusable_slot_count`,
not the container's size. A host-app that wants a large one must
keep the padding policy generous; with `PaddingPolicy::None` the
pool is only what vacuum retired.

**Lost — volume still leaks, and always did.** A commit that reuses
`k` slots dirties `k · (1 + CHURN_PER_REUSE)` offsets. The count is
proportional to real activity, so an adversary still estimates how
much happened between two snapshots. This is not a regression —
under append-only the same estimate came from the file's growth,
which is a cleaner signal — but the churn does not close it and
cannot. Hiding write *volume* requires writing at a constant rate
independent of activity, which is a battery and flash-wear cost this
project has not accepted.

**Reuse alone did not stop the growth; the horizon does.** Reuse
recycles `IndexNode` and `DataBatch` chunks, because those are what
`vacuum_orphans` retires. It used to leave superseded `Commit` and
`Superblock` chunks alone — the crash-recovery fallbacks and the
`commit_history` anchors — so growth stayed at `1 + superblock_replicas`
chunks per commit (4 at the default). Measured on the
`reuse_recycles_the_index_tree_and_nothing_else` fixture at one replica:
24 commits appended **48** slots where append-only appended **72**.

That paragraph used to end "retiring old eras would bound
`commit_history`, which is a published contract — a separate decision,
not this one". **The decision was taken.** `vacuum_orphans` now retires
the pair — the era's Superblock and the Commit chunk it points at —
for every era below `commit_seq() - ANCHOR_HORIZON` (1024). The two go
together: a fallback Superblock whose Commit chunk is gone is worse
than no fallback.

Measured on a fixture rewriting one key: the owned set PLATEAUS
(2003, 3604, 5204, 6115, 6116, 6115 across sessions of 400 commits)
and per-commit growth falls from ~17 KB to ~0.5 KB. What is left is
the padding policy doing its job — with `PaddingPolicy::None` the same
fixture grows by exactly zero — and the D2 fallback depth is unchanged,
because the scan caps candidates at 64 and the horizon is far above it.
The contract that changed is in `docs/{en,ru}/guide/multi-device.md`.

**Cost.** One extra chunk write per reused slot per commit, in the
`fsync` the padding already pays for. On a phone that is 4 KiB of
extra I/O per reused slot — for a typical messenger commit reusing
one or two slots, 4-8 KiB against the ~20 KiB the commit already
writes. Flash wear rises by the same proportion. `CHURN_PER_REUSE`
is the knob; raising it buys a larger anonymity ratio at a
proportional cost, and it is paid on every commit.

The host-app trigger for compaction is documented at
[`docs/en/guide/operations.md`](docs/en/guide/operations.md) §5.4
(live-ratio threshold, size budget, idle-time defer, privacy event).
`SpaceStats::utilization_ratio()` and
`SpaceStats::reusable_slot_count` are the metrics; a low ratio with
a healthy pool is a recycling container that wants no compaction,
and a low ratio with an empty pool is one that does.

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
time. All five have shipped resolutions.

This preamble used to say item 3 was "a soft cap documented under
threat-model out of scope" while item 3 itself, three paragraphs down,
records the hard cap enforced on both the write and the read side. The
same drift the item describes, one level up (report17 HV17-L2).

1. **Argon2 params storage.** ✅ Resolved. Parameters are stored in the
   cleartext header (v3: offset 32..48; in v2 it was 64..80, see §2).
   This is not a deniability
   leak — params describe the cost of a single brute-force attempt and say
   nothing about the number of spaces or content. The library exposes
   presets (`Argon2Params::LIGHT/DEFAULT/HEAVY`) and a floor
   (`Argon2Params::MIN`, below which open/create is rejected). Audit
   pass 1 D1 also added an upper ceiling
   (`MAX_M_COST_KIB` = 512 MiB, `MAX_T_COST` = 8, `MAX_P_COST` = 16) to
   close the OOM DoS where a tampered header would force the next opener
   into a 4 TiB Argon2 derivation. Each ceiling is a small multiple of
   the heaviest shipped preset (`HEAVY`: m=256 MiB, t=4, p=4), so the
   worst header an adversary can write is bounded in *time* as well as
   in memory.

2. **Replay/rollback protection.** ✅ Delegated to host-app. A snapshot
   adversary (T2) can roll the file back to an old version — the library
   alone does not detect this. The host-app contract is captured in
   `docs/en/guide/multi-device.md`: `Space::commit_seq()` — the current
   monotonic commit counter; `Space::commit_history()` — the seqs whose
   Superblocks are still on disk and decrypt under our key, which since
   `ANCHOR_HORIZON` is a WINDOW on recent history rather than all of it (to
   distinguish rollback from a fork, and see the guide for the order the
   three tests must be made in: an anchor older than the horizon is
   "unknown", not "fork"). Anchor ONLY for spaces whose
   existence is not deniability-sensitive.

3. **Maximum slot count.** ✅ Resolved. With `u64` seq and 4 KiB chunks the
   file goes up to 64 EiB, and the real limit was memory at scan time —
   so `MAX_OPEN_SCAN_CHUNKS` (§10) is enforced on BOTH sides: the write
   path refuses to grow past it and every open-scan path refuses to scan
   past it. This entry said the library did not enforce a hard cap while
   §10 of the same document described one, which is the kind of drift a
   reader resolves in whichever direction costs them more (report16
   HV16-L1). Practical guidance still lives in
   `docs/en/guide/operations.md` ("recommended container size").

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
`scrub-old-on-success`. Note that this is *not* because in-place writes
are impossible — §9.1 reuses retired slots — but because those two
operations let a caller rewrite a slot of its own choosing, with no
proof that the slot is unreachable from a recoverable era. That proof is
the whole content of Inv-W1, and the decoy pool exists to supply it.

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
