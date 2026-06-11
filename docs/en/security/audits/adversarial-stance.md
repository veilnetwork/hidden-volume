# Adversarial-stance audit pass

**Date.** 2026-05-28. **Reviewer.** LLM-assisted, instructed to *try
to break* the project's invariants rather than verify them
defensively. **Code reviewed against.** `master` plus the dossier
commit `e3382a6`.

## Methodology

The [self-audit dossier](self-audit.md) §4 lists what is claimed
about each security invariant and how the code is supposed to
defend it. The dossier was written in defensive stance: *"the claim
is X, the code enforces it via Y"*. This pass inverts the mindset:
*"how would I, as an attacker fitting one of the T1/T2/T2'/T3
adversary tiers, attempt to violate each claim?"*

For each attempted attack I record:

- **Attack name** and **adversary tier**.
- **Method** — concrete steps the adversary takes.
- **Code path that defends** (or fails to).
- **Outcome** — *defended*, *leaks acknowledged-and-bounded
  information*, or *real finding to fix*.

Out-of-scope items from the threat model ([§4 of threat-model.md](../threat-model.md))
are catalogued so we can confirm we have not accidentally drifted
*into* defending things the dossier says we don't, and so newcomers
can see the explicit T2' / OS-level / CPU-side-channel boundary.

Severity legend: **CRITICAL** (claim broken), **HIGH** (mitigation
bypass), **MEDIUM** (leak beyond what the threat model
acknowledges), **LOW** (doc inconsistency or defense-in-depth),
**INFO** (attack catalogued but already documented as defended /
out-of-scope).

## Headline

**No critical / high / medium findings.** Every attack I attempted
either:

- (a) the code defends correctly (most cases), or
- (b) the attack is documented out-of-scope (T2', OS-level, CPU-
  side-channel), or
- (c) the leak is documented and quantified (TM1 timing oracle,
  F-PAD downgrade, file-size visibility).

**One LOW finding:** my own `self-audit.md` §4 (the dossier
committed in `e3382a6`) describes the cleartext header as "64-byte"
in its D1 invariant statement. Every other document and the source
constants (`HEADER_LEN = 80`) say 80. Fix folded into this audit
pass commit.

## Attack catalogue

### Against **D1** (single-snapshot indistinguishability)

#### D1-A1. Garbage vs real-chunk distinguishability by byte distribution

- **Tier.** T1.
- **Method.** Collect byte-frequency / entropy / autocorrelation
  statistics over every 4096-byte chunk past the header. Look for a
  bimodal distribution that separates encrypted chunks from garbage.
- **Why it should fail.** Garbage chunks are `getrandom` output
  ([`ContainerFile::append_garbage_chunks`](../../../../crates/hidden-volume/src/container/file.rs)).
  Encrypted chunks are `nonce (24, getrandom) ‖
  XChaCha20-Poly1305(...)` — the keystream is computationally
  indistinguishable from random under the standard ChaCha20
  assumption, and the 16-byte Poly1305 tag is a high-entropy
  function of the (key, nonce, ad, plaintext) tuple.
- **Verdict.** **Defended.** Statistical tests on randomness give no
  signal under any standard CSPRNG assumption.
- **Severity.** INFO.

#### D1-A2. Cleartext-header fingerprint reveals "this is a `hidden-volume` file"

- **Tier.** T1.
- **Method.** Parse the first 48 bytes as `salt (32) ‖
  Argon2Params (16)` (v3 layout; v2 had an additional 32-byte
  cleartext `container_id` at offset 32..64 — closed by v3 #10).
  Check whether the 16-byte `Argon2Params` block contains values
  in the plausible range (`m_cost_kib ∈ [8192, 2²⁰]`,
  `t_cost ∈ [2, 100]`, `p_cost ∈ [1, 64]`, `format_version == 3`,
  padding-policy bits 16..24 ∈ {0, 1, 2, 3}, reserved bits
  24..32 == 0). If everything parses, with high probability this
  is a `hidden-volume` container.
- **Why it succeeds.** D1 only claims indistinguishability from
  uniform-random **past the cleartext header**. The header is, by
  design, cleartext and structured (the alternative is "trial
  decrypt" on open, see threat-model §4 hidden-header discussion).
  v3 #10 shrank the cleartext-header attack surface by removing
  the per-space `container_id` field — no per-space identifier
  sits in the open header any more, so the fingerprint is
  "this is a container" but not "this is *space N* of a container".
- **Verdict.** **Acknowledged out-of-scope.** D1 explicitly carves
  out the 48-byte structured header; "the file is a container" is
  detectable, but "*which spaces and what content* are inside" is
  not.
- **Severity.** INFO (documented limitation; tracked as candidate
  v2-format change in [migration.md](../../guide/migration.md)).

#### D1-A3. Slot count visibility via `stat`

- **Tier.** T1.
- **Method.** `stat` the file. Compute
  `slot_count = (file_size - CHUNK_SIZE) / CHUNK_SIZE` (the first
  chunk holds the header). This reveals how much storage the
  container uses.
- **Why it succeeds.** File size is unavoidably public.
- **Verdict.** **Acknowledged out-of-scope.** Any file's size is
  observable; this doesn't reveal *content*. Aggregate file size +
  the cleartext-header fingerprint (D1-A2) reveals "this user has
  ≈N chunks of hidden-volume storage", which is metadata, not
  D1-violating content disclosure.
- **Severity.** INFO.

#### D1-A4. Padding-policy byte tamper (F-PAD)

- **Tier.** T2.
- **Method.** Flip `Argon2Params.version` bits 16..24 from `3`
  (`Bucket16Mib`) to `0` (`None`). On next commit, the writer's
  padding policy degrades to `None` — subsequent commits ship
  exactly the data chunks they wrote, no garbage padding to mask
  size growth.
- **Why it partially succeeds.** The byte is unauthenticated; only
  the upper 8 bits (reserved) are zeroed and validated by
  `Argon2Params::validate`. The padding-policy byte is intentionally
  unauthenticated because binding it to AEAD would defeat F-PAD
  privacy (you would be able to *detect* that the writer changed
  policy, which is itself a privacy signal).
- **Why the impact is bounded.** Forces padding to `None` —
  privacy degradation only for **multi-snapshot adversaries**
  (T2'). Single-snapshot D1 holds: chunks remain uniform random.
- **Defense.** Host-app override: `set_padding_policy()` at runtime
  ignores the persisted byte. Documented in F-PAD escape hatch and
  the dossier §4 D1 caveat.
- **Verdict.** **Acknowledged limitation** (F-PAD §4.1).
- **Severity.** INFO.

#### D1-A5. Argon2-param header tamper to weaken brute-force

- **Tier.** T2.
- **Method.** Flip header bytes to set `m_cost_kib = MIN_M_COST_KIB
  = 8192`, `t_cost = MIN_T_COST = 2`, `p_cost = MIN_P_COST = 1`,
  then capture the file and brute-force offline.
- **Why it fails.** Argon2 params are an *input* to the KDF chain:
  the legitimate seal computed `derive_master(password, salt,
  ORIGINAL_PARAMS)`. After tamper, the next open computes
  `derive_master(password, salt, WEAK_PARAMS)`, deriving a
  *different* `master_key`, hence a different per-slot AEAD key,
  hence AEAD fails on every chunk — the legitimate user observes
  `AuthFailed`. The attacker captured the file *before* tampering;
  for offline brute-force the attacker must use whatever params
  were sealed under, so weakening the on-disk header doesn't speed
  up brute-force against the captured file.
- **Verdict.** **Defended.** Best the attack does is DoS on the
  legitimate user (and that DoS is recoverable by restoring the
  header from a backup or by trial-trying `Argon2Params::DEFAULT`
  + standard preset variants).
- **Severity.** INFO.

#### D1-A6. Header padding bytes reveal commit timing

- **Tier.** T1.
- **Method.** The first chunk is `HEADER_LEN (80) ‖ uniform random
  padding (4016 bytes)`. The padding bytes are random at create
  time. Could the *entropy* or *pattern* of those bytes reveal when
  the container was created?
- **Why it fails.** `getrandom` output. No timestamp embedded.
- **Verdict.** **Defended.**
- **Severity.** INFO.

#### D1-LOW1. Dossier doc inconsistency: "64-byte" cleartext header

- **Where.** [`self-audit.md`](self-audit.md) §4 D1 statement:
  *"... 64-byte cleartext header (`salt (32) ‖ container_id (32)
  ‖ Argon2Params (16) ‖ ...`)"*. The arithmetic inside the
  parens sums to 80, not 64. The source constant
  ([`lib.rs:183`](../../../../crates/hidden-volume/src/lib.rs):
  `pub(crate) const HEADER_LEN: usize = 80;`), `format.md`,
  `threat-model.md`, root `README.md`, and `guide/migration.md` all
  say 80.
- **Severity.** LOW (doc consistency in a file I authored in the
  same session as this audit).
- **Fix.** Folded into this audit's commit — change "64-byte" to
  "80-byte" in EN dossier line 122 and "64-байтового" to
  "80-байтового" in RU dossier line 122.

### Against **D2** (compelled-key plausible deniability)

#### D2-A1. TM1 open-time timing oracle (deeper view)

- **Tier.** T1 with side-channel access (passive observer of
  open-time CPU usage / wallclock).
- **Method.** Profile `Container::open_space` wallclock as a
  function of `frac_owned = owned_chunks / total_chunks`. Bench
  [`benches/timing_oracle.rs`](../../../../crates/hidden-volume/benches/timing_oracle.rs)
  established a ~75 µs-per-chunk swing tied to MAC-fail-then-skip
  vs MAC-pass-then-decrypt.
- **What it leaks.** Approximate `frac_owned` (±10-20%) for the
  observed space. Does **not** identify *which* slots are owned;
  does **not** distinguish "space B exists with low frac" from
  "no space B, those slots are garbage padding".
- **Why D2 still holds in the strict sense.** D2 claims that an
  adversary with `S_A`'s password cannot prove the existence of
  `S_B`. The frac-owned leak is observed during the *legitimate
  open of `S_A`*, by an observer of that open's runtime. From
  `S_A`'s key holder's perspective, *every non-owned chunk* is
  indistinguishable (AEAD fails the same way for "wrong space" and
  "garbage"). The frac-owned leak gives "this much of the file is
  *not* `S_A`'s" — which is also leaked by the file size (D1-A3),
  modulo padding. So TM1 sharpens an already-leaked signal; it
  doesn't create a new one *that distinguishes between* "other
  space" and "garbage padding".
- **Mitigation roadmap.** Replace MAC-fail-fast with a
  constant-time AEAD path that always runs ChaCha20 over the body.
  ~2× cost on garbage chunks but eliminates the timing leak.
  Tracked as TM1-v1.x in [threat-model F-TM1](../threat-model.md).
- **Verdict.** **Acknowledged, bounded, mitigation-tracked.**
- **Severity.** INFO (already documented at exactly this level).

#### D2-A2. Wrong-password vs not-our-chunk error discrimination

- **Tier.** T1 + access to the API caller's error stream.
- **Method.** Attacker invokes `Container::open_space(path,
  wrong_password)` and observes the returned error. Compare with
  `Container::open_space(path_with_only_garbage,
  any_password)`. If the errors differ (different error variant,
  different message, different latency), the attacker can
  distinguish "this file has SOME space" from "this file is
  garbage", which is D2-relevant.
- **Why it fails.** Both paths return `Error::AuthFailed` ([`error.rs`](../../../../crates/hidden-volume/src/error.rs)).
  Verified by grep of every `try_decrypt` call site: `.ok()?`
  pattern silently skips failures during discovery scan
  ([`open/mod.rs::try_decrypt`](../../../../crates/hidden-volume/src/open/mod.rs)).
  Final return is `Err(AuthFailed)` if no superblock decrypted —
  same variant whether the file is garbage or has unrelated
  spaces. Timing is the TM1 question (see D2-A1).
- **Verdict.** **Defended.** D2 closure for error-channel: confirmed.
- **Severity.** INFO.

#### D2-A3. Recovery-path observability via multiple opens

- **Tier.** T1 with repeated-observation capability (e.g., side-
  channel watcher of process activity over time).
- **Method.** Observe the wallclock of `n` successive opens of the
  same file with the same password. Are there variations across
  opens that correlate with file content (caches, recovery
  fallbacks)?
- **What's there.** OS page cache after the first open shortens
  subsequent opens. This is OS-level, content-independent in the
  D2 sense (caches don't know which slots are which space).
- **What's NOT there.** No per-open randomness in the scan
  algorithm — the slot order is deterministic.
- **Verdict.** **Defended** at the library boundary. OS caches are
  out-of-scope (the threat model puts kernel + filesystem inside
  the trusted base for `T0–T3`; `T2'` adversaries with kernel-
  level taps are explicitly out of scope).
- **Severity.** INFO.

#### D2-A4. Writer-active signal via file-size growth at commit

- **Tier.** T2'.
- **Method.** Attacker has snapshots at times `t1 < t2`. They diff
  the byte ranges. Size grew by `Δ` chunks ⇒ writer was active
  between `t1` and `t2`.
- **Why D2 doesn't break.** D2 is about *which space* the writer
  belongs to, not about *whether writing occurred*. The file size
  growth says "*some* writer touched this file"; it doesn't pin a
  specific space.
- **Bounded by padding.** With `Bucket16Mib` policy, growth is
  rounded up to bucket boundaries → much coarser size signal.
  F-PAD downgrade (D1-A4) flattens this back to per-commit
  granularity.
- **Verdict.** **Acknowledged out-of-scope (T2').** Documented in
  threat-model §2 + §4.
- **Severity.** INFO.

#### D2-A5. Commit-history exposure via `Space::commit_history`

- **Tier.** T1 + key for `S_A`.
- **Method.** Attacker holds `S_A`'s password. They open and call
  `commit_history()` — returns the list of seq values of `S_A`'s
  superblocks. Could this reveal *anything* about `S_B`?
- **Why it fails.** `commit_history` only iterates superblocks
  that decrypt under `S_A`'s key. `S_B`'s superblocks fail AEAD,
  skipped. The seq sequence is internally `S_A`'s history; it
  does not include `S_B`'s seqs (they're encrypted under a
  different key).
- **Possible cross-leak?** Both spaces share the *file*. If both
  spaces commit, both write superblocks at distinct slots. `S_A`'s
  commit_history reveals "this file has at least `len(history)`
  superblocks owned by `S_A`". Doesn't reveal `S_B`'s existence
  unless `S_A`'s key-holder can also read filesystem-level
  metadata (slot count) — which they can (D1-A3, file size). The
  ratio `len(commit_history) / slot_count` reveals "what fraction
  of slots are `S_A`'s superblocks", which is a much coarser
  signal than TM1 already gives.
- **Verdict.** **Defended.** D2 holds.
- **Severity.** INFO.

#### D2-A6. Cross-key chunk-relocation: forge an `S_B` chunk from `S_A` material

- **Tier.** T3 (compelled key for `S_A`).
- **Method.** Attacker has `S_A`'s key + ciphertext of a chunk
  (`nonce ‖ ct ‖ tag`). Can they relocate or repurpose it to
  decrypt under `S_B`'s key, or otherwise leak `S_B`?
- **Why it fails.**
  1. Per-slot AEAD key = `BLAKE3-keyed(aead_root, container_id,
     slot)`. `aead_root` derives from `master_key` →
     `Argon2id(password, salt, params)`. Different password →
     different `aead_root` → different per-slot keys for every
     slot.
  2. AAD binds `container_id ‖ slot`. Same container_id (both
     spaces in same file), but different slot ⇒ AAD differs.
  3. Forging a valid `(nonce, ct, tag)` for `S_B`'s key requires
     the key. AEAD security assumption.
- **Verdict.** **Defended.** Standard AEAD + per-slot binding.
- **Severity.** INFO.

### Against **I1** (per-chunk integrity)

#### I1-A1. Bit-flip attack on chunk ciphertext

- **Tier.** T2.
- **Method.** Flip one bit anywhere in `nonce ‖ ct ‖ tag` of a
  chunk.
- **Outcome.** Poly1305 MAC verification fails (probability of
  false-positive: 2⁻¹⁰⁰). `AuthFailed` from
  [`ChunkAead::open`](../../../../crates/hidden-volume/src/crypto/aead.rs).
- **Verdict.** **Defended.** Standard AEAD.
- **Severity.** INFO.

#### I1-A2. Slot reorder (swap two slots' ciphertexts)

- **Tier.** T2.
- **Method.** Swap the contents of slot `A` and slot `B` (same
  container, same space).
- **Outcome.** The chunk's AAD binds `container_id ‖ slot`. After
  swap, the chunk originally sealed for slot `A` is read at slot
  `B` — AEAD-decrypt uses AAD `(container_id ‖ B)` but the seal
  used `(container_id ‖ A)`. MAC fails.
- **Verdict.** **Defended** by AAD slot binding.
- **Severity.** INFO.

#### I1-A3. Cross-container chunk relocation

- **Tier.** T2.
- **Method.** Copy a chunk from container `X` (slot `S`) to
  container `Y` (slot `S`).
- **Outcome.** Two-layer defense: AAD includes the AD's
  `container_id`, so AAD differs (X.id vs Y.id) ⇒ MAC fails. AND
  per-slot key derives from `container_id`, so even if AAD matched,
  the key differs.
- **Verdict.** **Defended.** Double-bound.
- **Severity.** INFO.

#### I1-A4. Hash-collision on Merkle chain

- **Tier.** T-key-holder.
- **Method.** Attacker holds the password (insider). Constructs two
  IndexNode payloads with the same BLAKE3-256 hash.
- **Outcome.** BLAKE3 collision resistance ≥ 128-bit, practical
  collisions are infeasible (≥ 2¹²⁸ work to find one).
- **Verdict.** **Defended.** Standard cryptographic hash.
- **Severity.** INFO.

### Against **I2** (tail-corruption tolerance)

#### I2-A1. Truncate-tail attack

- **Tier.** T2.
- **Method.** Truncate the file at any byte boundary mid-chunk.
- **Outcome.**
  [`ContainerFile::read_slot`](../../../../crates/hidden-volume/src/container/file.rs)
  computes `slot_count` from file length divided by `CHUNK_SIZE`;
  a trailing partial chunk is excluded
  (`(len - HEADER_OFFSET) / CHUNK_SIZE - 0`). The last complete
  superblock that AEAD-decrypts under our key is the recovered
  state.
- **Verdict.** **Defended.** Recovery picks the highest-seq
  *complete-and-decryptable* superblock; truncation past the last
  superblock is a no-op semantically.
- **Severity.** INFO.

#### I2-A2. Tamper one superblock replica

- **Tier.** T2.
- **Method.** Overwrite one replica's bytes with garbage. Other
  replicas of the same seq are untouched.
- **Outcome.**
  [`open/mod.rs::scan_and_recover`](../../../../crates/hidden-volume/src/open/mod.rs)
  iterates superblock candidates by descending seq; same-seq
  replicas are asserted bit-identical via `debug_assert` (pass-14
  D4 hardening). One tampered replica fails AEAD; the next
  same-seq replica (or the next-highest-seq if all replicas at
  this seq tampered) wins.
- **Verdict.** **Defended.** Replica redundancy works.
- **Severity.** INFO.

#### I2-A3. Forge a high-seq superblock

- **Tier.** T2 (no key).
- **Method.** Write random bytes at any slot position, hoping the
  scan picks them as a "high-seq superblock".
- **Outcome.** Without the key, the attacker cannot produce valid
  AEAD ciphertext that decrypts to a `Superblock` plaintext with a
  high `seq` field. Scan-and-recover's `try_decrypt` returns
  `None` on garbage; only AEAD-valid candidates enter the
  superblock-seq sort.
- **Verdict.** **Defended.** Standard AEAD.
- **Severity.** INFO.

### Against **I3** (cross-space isolation)

#### I3-A1. Cross-space chunk relocation within same container

- **Tier.** T3 (compelled key for `S_A`, wants to leak `S_B`).
- **Method.** Read `S_B`'s ciphertext at slot `B`, write it at a
  slot pretend-owned-by-`S_A`, hope it decrypts under `S_A`.
- **Outcome.** Per-slot AEAD key = `BLAKE3(aead_root, container_id,
  slot)`. `S_A`'s `aead_root` differs from `S_B`'s (different
  master_key). Even if AAD `(container_id, slot)` were forced to
  match, the key still differs ⇒ AEAD fails.
- **Verdict.** **Defended.** Per-key isolation.
- **Severity.** INFO.

### Against **R1** (rollback / fork-detection, host-app cooperative)

#### R1-A1. File-level rollback

- **Tier.** T2.
- **Method.** Attacker replaces the current file with an earlier
  snapshot.
- **Library-level outcome.** Library opens the file fine; current
  `commit_seq` is the older seq.
- **What the library doesn't do.** Self-contained rollback
  detection. R1 says: host-app stores `commit_seq` externally
  (anchor) and re-checks on next open. If host-app does this,
  rollback is detectable.
- **Verdict.** **Defended at the documented boundary.** R1 is
  *cooperative* — library exposes `commit_seq()` + `commit_history()`;
  host-app must use them. Documented in
  [`guide/multi-device.md`](../../guide/multi-device.md).
- **Severity.** INFO.

#### R1-A2. Fork attack — present a different-history file

- **Tier.** T2'.
- **Method.** Attacker presents a file that *also* decrypts under
  the user's key but with a different commit history (e.g., they
  forked at some seq and made different commits).
- **Library outcome.** Library opens it; commit_history shows the
  forked history. The user's external anchor seq might be *higher*
  than file's commit_seq (file rollback) or *absent from
  commit_history* (genuine fork — divergent timeline).
- **Verdict.** **Detectable via R1 host-app cooperative check.**
  Bounded by the host-app's diligence.
- **Severity.** INFO.

### Against **M1** (memory hygiene)

#### M1-A1. Heap-residual password after panic

- **Tier.** T-process-memory (memory dump after panic).
- **Method.** Trigger a panic in the FFI surface (e.g., via a
  malformed input that hits an unwrap... if any).
- **Outcome.**
  - In release: `panic = "abort"` (workspace Cargo.toml). On panic,
    process is aborted; OS reclaims the address space. No
    destructor runs, but no observer can read scrubbed memory
    either.
  - In dev/test: `panic = "unwind"`. Destructors run. `Zeroizing<Vec<u8>>`
    on each FFI password entry scrubs the heap copy.
  - The actual panic surface: every FFI lock-acquire maps `PoisonError`
    to `HvError::Internal` (pass-1 D4, verified by grep across
    [`ffi/lib.rs`](../../../../crates/hidden-volume-ffi/src/lib.rs)).
    No `.unwrap()` / `.expect()` on locks in production code.
- **Verdict.** **Defended.** Memory hygiene story validated in
  [`audits/memory.md`](memory.md) +
  [`audits/plaintext.md`](plaintext.md). Panic + abort = scrub via
  OS teardown; panic + unwind = scrub via Drop.
- **Severity.** INFO.

#### M1-A2. Cold-boot attack — DRAM remanence

- **Tier.** Physical access with cold-boot capability.
- **Method.** Power-cycle the host machine quickly, dump DRAM,
  search for key material.
- **Outcome.** Out of scope. Documented in
  [threat-model §2](../threat-model.md) (RAM-dump attacks defended
  by full-disk encryption + secure-boot at the host level).
- **Verdict.** **Acknowledged out-of-scope.**
- **Severity.** INFO.

### Against **C1** (cancellation safety)

#### C1-A1. Cancel mid-commit between data write and superblock fsync

- **Tier.** T-cooperative-cancel (e.g., async task cancellation).
- **Method.** Issue an `await` cancel between Phase 1 (data write)
  and Phase 3 (superblock fsync).
- **Outcome.** Some data chunks land on disk but are unreachable
  from any superblock. On reopen, `vacuum_orphans` scrubs them
  (IndexNode orphans) and `vacuum_data_batches` handles DataBatch
  orphans (with explicit call documented for the post-commit-error
  case). Superblock state pre-cancel is preserved.
- **Verdict.** **Defended** per the 3-fsync protocol.
- **Severity.** INFO.

#### C1-A2. Cancel after superblock fsync but before padding step

- **Tier.** T-cooperative-cancel.
- **Method.** Cancel during the post-commit garbage-padding step.
- **Outcome.** Pass-18 M1 hardening: padding failures stash to
  `last_padding_error` and `Ok(new_seq)` is returned. Durability
  is not downgraded. Privacy-padding loss is bounded to that one
  commit, observable to multi-snapshot adversaries (T2'); same as
  F-PAD-tamper outcome for that commit.
- **Verdict.** **Defended** at the durability layer; bounded
  privacy degradation acknowledged.
- **Severity.** INFO.

### Format / parsing surface (decode safety)

#### F-A1. Argon2 OOM via header tamper (closed pre-pass)

- **Tier.** T2.
- **Method.** Tamper Argon2Params to extreme values (`m_cost_kib =
  u32::MAX`).
- **Outcome.** `Argon2Params::validate` rejects with explicit caps
  (`m_cost_kib ≤ 1 GiB`, `t_cost ≤ 100`, `p_cost ≤ 64`,
  `format_version == 2`, reserved bits 24..32 == 0). Closed in
  audit pass 1 (D1).
- **Verdict.** **Defended.**
- **Severity.** INFO.

#### F-A2. zstd compression bomb in DataBatch

- **Tier.** T-key-holder OR T-malformed-AEAD-valid (if the writer
  was buggy and produced a valid-AEAD bomb).
- **Method.** Construct a `DataBatch` chunk whose 4040-byte
  ciphertext (compressed) decompresses to gigabytes of zeros.
- **Outcome.** Pass-11 M5: `decode_batch` uses streaming
  `Read::take(MAX_DECODED_BATCH_LEN + 1) ≈ 8.4 MiB`. Bomb hits
  cap → `Error::Malformed("batch decompressed size exceeds cap")`.
- **Verdict.** **Defended.**
- **Severity.** INFO.

#### F-A3. B+ tree node-count allocation amplifier

- **Tier.** Same as F-A2.
- **Method.** Construct an IndexNode payload claiming `num =
  u16::MAX` entries with under-capacity body.
- **Outcome.** Pass-5 G2/G3: pre-allocation bound check
  `num.saturating_mul(MIN_*_BYTES) ≤ bytes.len() - HEADER_LEN`
  in both `LeafNode::decode` and `InternalNode::decode`. Rejects
  before the `Vec::with_capacity(num)` allocation.
- **Verdict.** **Defended.**
- **Severity.** INFO.

#### F-A4. Open-scan budget bypass

- **Tier.** T2.
- **Method.** Inflate file to 100 GiB to force a 100-GB AEAD-scan
  loop on open.
- **Outcome.** Pass-16 TM1-budget: `MAX_OPEN_SCAN_CHUNKS = 16 ×
  1024 × 1024 ≈ 16M` (= 64 GiB at 4 KiB chunks). All three scan
  entry points (sequential, parallel, mmap) gate via
  `check_scan_budget(total)` before the loop. Symmetric
  `check_write_budget` on the write side
  ([`container/file.rs`](../../../../crates/hidden-volume/src/container/file.rs)
  `append_slot` + `append_garbage_chunks`).
- **Verdict.** **Defended.**
- **Severity.** INFO.

#### F-A5. Cycle in B+ tree (key-holder self-DoS)

- **Tier.** T-key-holder OR writer-bug regression.
- **Method.** Key-holder crafts an InternalNode at slot A pointing
  at an InternalNode at slot B that points back at A. Reading the
  tree → infinite recursion → stack overflow.
- **Outcome.** Writer-side invariant guarantees depth ≤ 2 because
  `write_tree_for_namespace`
  ([`space/commit.rs`](../../../../crates/hidden-volume/src/space/commit.rs))
  emits only Leaf or one-level-of-Internal-over-Leaves. The
  recursive walkers (`collect_leaves`, `count_leaves`,
  `iter_log_*`, `vacuum_orphans::collect_tree_chunks_into_set`)
  have no visited-set or depth-cap.
- **`verify_integrity`** *is* cycle-resistant — the Merkle hash
  chain requires `H(B) = recorded_child_hash_in_A` and `H(A) =
  recorded_child_hash_in_B`, which forces a BLAKE3 preimage
  attack to construct. So an attacker without preimage capability
  cannot make a cycle that passes `verify_integrity`.
- **Threat-model status.** Key-holder is *not* a defended-against
  adversary in this library (it's the legitimate owner of the
  data; nothing in scope says we defend the maintainer from
  themselves). Writer-bug regression would be a self-foot-gun.
- **Defense-in-depth idea (deferred).** Add a depth cap (e.g.,
  `MAX_TREE_DEPTH = 3`) check in the recursive walkers. Cheap and
  catches both an adversarial key-holder and any future writer
  regression. Tracked as a v1.x defense-in-depth in
  [self-audit.md §5](self-audit.md).
- **Verdict.** **Acknowledged, out-of-strict-threat-model, defense-
  in-depth opportunity.**
- **Severity.** INFO.

### Build / supply-chain

#### S-A1. Forge a signed release without the workflow's OIDC identity

- **Tier.** Supply-chain.
- **Method.** Adversary tries to produce a `SHA256SUMS.cosign.bundle`
  that verifies under
  `https://github.com/veilnetwork/hidden-volume/.github/workflows/release.yml@refs/tags/v.*`
  identity regex without having actually run the workflow.
- **Outcome.** Cosign keyless ties signatures to the OIDC token of
  the *actual* workflow run, with the signature recorded in the
  public Rekor transparency log. Forging requires either:
  (a) compromising the OIDC issuer (`token.actions.githubusercontent.com`),
  (b) compromising Sigstore Fulcio's signing CA, or
  (c) compromising Rekor's append-only log.
  Each is a substantial public infrastructure attack with a
  transparency-log signal.
- **Verdict.** **Defended at the Sigstore transparency level.**
- **Severity.** INFO.

#### S-A2. Workflow file tamper to sign attacker code

- **Tier.** Repository write access.
- **Method.** PR that edits `.github/workflows/release.yml` to
  build attacker code, run cosign-sign, attach to release.
- **Outcome.** Sigstore certificate includes the *workflow file
  path + git ref*. A tampered workflow on a tag still signs as
  `release.yml@refs/tags/vX.Y.Z`. The defense is:
  - Repo write-access control (maintainer/GitHub).
  - Public diff of `release.yml` — any change is visible in commit
    history.
  - The transparency log records *what* was signed; downstream
    verifiers can re-derive the SHA256 of the workflow file at
    the tag commit and confirm it matches the expected content.
- **Verdict.** **Bounded by repo access control + transparency.**
  A downstream verifier paranoid about workflow tamper should
  compare `release.yml` at the tag's commit SHA against a trusted
  reference (e.g., the version they last reviewed).
- **Severity.** INFO.

## Summary table

| ID | Attack | Tier | Verdict | Severity |
|---|---|---|---|---|
| D1-A1 | Byte-distribution distinguisher | T1 | Defended | INFO |
| D1-A2 | Header fingerprint | T1 | Acknowledged out-of-scope | INFO |
| D1-A3 | Slot count via `stat` | T1 | Acknowledged out-of-scope | INFO |
| D1-A4 | Padding-policy downgrade (F-PAD) | T2 | Acknowledged out-of-scope | INFO |
| D1-A5 | Argon2-param weaken-then-brute | T2 | Defended | INFO |
| D1-A6 | Header-padding-bytes timing reveal | T1 | Defended | INFO |
| **D1-LOW1** | **`self-audit.md` "64-byte" doc inconsistency** | — | **Fix in this commit** | **LOW** |
| D2-A1 | TM1 timing oracle | T1 + side-channel | Acknowledged + mitigation-tracked | INFO |
| D2-A2 | Wrong-pwd vs not-our-chunk | T1 | Defended | INFO |
| D2-A3 | Repeated-open variance | T1 + side-channel | Defended | INFO |
| D2-A4 | Writer-active signal | T2' | Acknowledged out-of-scope | INFO |
| D2-A5 | `commit_history` exposure | T1 + key | Defended | INFO |
| D2-A6 | Cross-key chunk forgery | T3 | Defended | INFO |
| I1-A1 | Bit-flip | T2 | Defended | INFO |
| I1-A2 | Slot reorder | T2 | Defended | INFO |
| I1-A3 | Cross-container relocation | T2 | Defended | INFO |
| I1-A4 | Merkle hash collision | T-key-holder | Defended | INFO |
| I2-A1 | Tail truncate | T2 | Defended | INFO |
| I2-A2 | One replica tamper | T2 | Defended | INFO |
| I2-A3 | Forge high-seq superblock | T2 | Defended | INFO |
| I3-A1 | Cross-space chunk relocation | T3 | Defended | INFO |
| R1-A1 | File rollback | T2 | Defended at host-app boundary | INFO |
| R1-A2 | Fork (divergent timeline) | T2' | Defended at host-app boundary | INFO |
| M1-A1 | Heap-residual password after panic | T-process-memory | Defended | INFO |
| M1-A2 | Cold-boot RAM dump | Physical | Acknowledged out-of-scope | INFO |
| C1-A1 | Cancel mid-commit | T-cancel | Defended | INFO |
| C1-A2 | Cancel mid-padding | T-cancel | Defended (durability) | INFO |
| F-A1 | Argon2 OOM via header tamper | T2 | Defended (pass 1 D1) | INFO |
| F-A2 | zstd compression bomb | T-key-holder | Defended (pass 11 M5) | INFO |
| F-A3 | B+ tree alloc amplifier | T-key-holder | Defended (pass 5 G2/G3) | INFO |
| F-A4 | Open-scan budget bypass | T2 | Defended (pass 16) | INFO |
| F-A5 | B+ tree cycle | T-key-holder | Out-of-strict-model; defense-in-depth opportunity | INFO |
| S-A1 | Forge signed release | Supply-chain | Defended (Sigstore transparency) | INFO |
| S-A2 | Workflow tamper | Repo-access | Bounded by repo access control + transparency | INFO |

**Counts:** 0 CRITICAL, 0 HIGH, 0 MEDIUM, 1 LOW (folded into this
commit), rest INFO.

## What this pass did NOT cover

Deliberately deferred to later specialised passes (already
scheduled — see the user's plan + [self-audit.md §9](self-audit.md)):

- **Primitive-level review**: Argon2id parameter choice vs 2026
  literature, ChaCha20 key-schedule edge cases, BLAKE3-keyed
  domain-separation analysis. (Adversarial pass took primitives
  as black boxes; primitive-level pass will challenge the
  primitives themselves.)
- **Side-channel surface map (beyond TM1)**: cache-timing in the
  AEAD path, branch prediction in `decode_*` functions, allocator
  behaviour on failed paths.
- **Format fuzzing analysis**: formal boundary enumeration of every
  `decode` function with adversarial inputs at each boundary.
- **Threat-model challenge**: full T2/T2'/T3 step-by-step attack
  construction with attacker-stance narrative.
