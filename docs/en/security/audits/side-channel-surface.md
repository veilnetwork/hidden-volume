# Side-channel surface map

**Date.** 2026-05-28. **Pass.** 3 of 5 in the deeper-review series.
**Reviewer.** LLM-assisted, instructed to enumerate every channel
through which a side-channel observer (timing, memory layout,
filesystem syscalls, logs) could learn something the threat model
claims is hidden.

## Methodology

The pre-existing [`audits/constant-time.md`](constant-time.md) audited
every `==` / `!=` comparison site. The known timing leak TM1 is
documented in [threat-model F-TM1](../threat-model.md). This pass
catalogues *every other* side-channel vector — confirms the
defended ones, flags any defense-in-depth opportunities, and is
explicit about what is out-of-scope.

Surface categories:

1. **Timing.** Wall-clock or CPU-cycle observable by an adversary
   on the same machine (e.g., spying via `getrusage()`, process
   monitoring, syscall-tracing) or via remote-network response
   times.
2. **Memory layout.** Allocation patterns, page faults, TLB
   pressure observable to an in-process or kernel-level adversary.
3. **Filesystem.** Syscall traces, mtime/atime/ctime, file size
   evolution observable to a kernel-level adversary.
4. **Logging.** Library-emitted log messages or error strings that
   could carry content.
5. **Microarchitectural.** Cache-timing, branch prediction,
   Spectre / MDS — out-of-scope but enumerated for completeness.

For each channel: code refs, what leaks, what the threat-model
position is, action (if any).

## Headline

**0 CRITICAL / 0 HIGH / 0 MEDIUM, 0 LOW.** Every side-channel
vector I found is either already defended (constant-time
primitives, explicit `subtle::ct_eq` on key/tag material, no
production logging), documented out-of-scope (TM1 timing oracle,
T2' multi-snapshot temporal patterns, kernel-level syscall taps,
CPU microarchitecture), or unreachable to a non-key-holder
adversary (decode-path timing inside AEAD-protected plaintext).

Two **INFO observations** worth flagging for v1.x roadmap:

- **SC-INFO1.** The decode paths (`Plaintext::decode`,
  `LeafNode::decode`, `InternalNode::decode`, `decode_batch`)
  short-circuit on the first malformed byte and therefore take
  variable time. Not reachable by non-key-holders (AEAD-decrypt
  must succeed first), so not a real channel today. A constant-
  time decode pass would be defense-in-depth against an
  adversarial-key-holder scenario, but key-holder is explicitly
  out of the threat model.
- **SC-INFO2.** `parallel-scan` and `mmap` features change the
  observable syscall/page-fault pattern at open time. Any
  side-channel analysis of TM1 should treat these as separate
  variants — the bench `timing_oracle.rs` runs only the
  sequential path, so the parallel/mmap paths are not
  independently characterised.

## Per-channel analysis

### 1. Timing channels

#### T-1. Argon2id derivation time

- **Where.** [`crypto/kdf.rs::derive_master_key`](../../../../crates/hidden-volume/src/crypto/kdf.rs).
- **What's observable.** Total `Container::open_space` time
  includes the Argon2 KDF run. With `Argon2Params::DEFAULT`
  (`m=64 MiB, t=3, p=1`) this is ~700ms on mid-range mobile,
  dominating every other source of timing variance.
- **Content-dependence.** Argon2id is data-dependent by design
  (the `d` half of `id` uses password-dependent memory access
  patterns; this is what makes Argon2d resist TMTO attacks). The
  `i` half is data-independent (resists cache-timing). The `id`
  combined variant has SOME cache-side-channel resistance but
  not full constant-time wrt password content. This is an
  inherent property of the Argon2 family and is documented in
  RFC 9106 §6.
- **Threat-model position.** Acknowledged out-of-scope in
  [threat-model §4](../threat-model.md) ("CPU-level side
  channels — defended by OS/microcode"). Argon2id's cache
  resistance is sufficient for the threat model (attacker
  cannot get cache-resolution timing on a mobile/desktop
  victim without local code execution).
- **Verdict.** **Acknowledged out-of-scope.**

#### T-2. ChaCha20 keystream / Poly1305 MAC

- **Where.**
  [`crypto/aead.rs::ChunkAead`](../../../../crates/hidden-volume/src/crypto/aead.rs).
- **What's observable.** AEAD seal / open time per chunk (~µs).
- **Content-dependence.** ChaCha20 is implemented as
  ADD / XOR / ROTATE operations on `u32` lanes; constant-time on
  every supported architecture. Poly1305 field multiplication
  mod 2¹³⁰ − 5 is implemented constant-time in RustCrypto.
- **AEAD tag check.** RustCrypto's `Aead::decrypt` uses
  `subtle::ct_eq` for the final Poly1305 tag comparison
  ([`audits/constant-time.md`](constant-time.md)).
- **Verdict.** **Defended.** Constant-time at the primitive level.

#### T-3. BLAKE3 hash

- **Where.** Subkey derivation, per-slot key derivation, Merkle
  payload hashes.
- **What's observable.** Per-hash time (~ns).
- **Content-dependence.** ADD / XOR / ROTATE on `u32` lanes;
  constant-time on every supported architecture (BLAKE3
  specification §6.4).
- **Verdict.** **Defended.**

#### T-4. AEAD MAC-fail-then-skip vs MAC-pass-then-decrypt (TM1)

- **Where.** [`open/mod.rs::try_decrypt`](../../../../crates/hidden-volume/src/open/mod.rs)
  + benches [`benches/timing_oracle.rs`](../../../../crates/hidden-volume/benches/timing_oracle.rs).
- **What's observable.** ~75 µs/chunk swing in scan time tied
  to ownership; aggregate leaks `frac_owned` (±10-20%) for the
  observed space. Per-chunk identification of "owned vs not"
  requires per-chunk timing resolution, which a process-level
  observer typically does not have.
- **Threat-model position.** TM1 — quantified, documented in
  [threat-model F-TM1](../threat-model.md). Mitigation
  (constant-time AEAD path that always runs ChaCha20 over the
  body) tracked for v1.x.
- **Verdict.** **Acknowledged + mitigation-tracked.**

#### T-5. Decode-path early-return variance (SC-INFO1)

- **Where.**
  [`chunk/format.rs::Plaintext::decode`](../../../../crates/hidden-volume/src/chunk/format.rs),
  [`space/index.rs::{LeafNode,InternalNode}::decode`](../../../../crates/hidden-volume/src/space/index.rs),
  [`tx/commit.rs::CommitPayload::decode`](../../../../crates/hidden-volume/src/tx/commit.rs),
  [`space/log.rs::decode_batch`](../../../../crates/hidden-volume/src/space/log.rs).
- **What's observable.** Each decode function returns
  `Err(Malformed(...))` on the first invalid byte. Different
  malformed inputs take different time to reject.
- **Reachability.** None for non-key-holders: every decode runs
  on AEAD-decrypted plaintext, which the attacker cannot produce
  without the key. A key-holder *could* construct malformed
  plaintexts and time the parser, but key-holder is explicitly
  not a defended-against adversary in this library (a key-holder
  has full access to their own data; nothing about the
  threat-model says we defend the maintainer from themselves).
- **Defense-in-depth.** A constant-time decode pass would walk
  the entire payload regardless of validity, producing an
  early-rejection result at the end. ~4 KiB overhead per chunk
  per decode call. Negligible cost; minimal benefit (only
  closes the key-holder-self-DoS scenario).
- **Verdict.** **INFO** (defense-in-depth opportunity tracked
  for v1.x; not a real channel today).

#### T-6. zstd decompression time variance

- **Where.** [`space/log.rs::decode_batch`](../../../../crates/hidden-volume/src/space/log.rs).
- **What's observable.** Per-batch decompression time depends
  on compressed size and entropy of the input.
- **Reachability.** Decompression runs on AEAD-decrypted batches
  — non-key-holder cannot probe.
- **Verdict.** **Defended at the AEAD layer.**

#### T-7. Argon2 parameters parsing

- **Where.** [`Argon2Params::validate`](../../../../crates/hidden-volume/src/crypto/kdf.rs).
- **What's observable.** Open-time spent parsing the cleartext
  header (cheap, ~ns).
- **Content-dependence.** `validate()` does branching on
  `m_cost_kib` / `t_cost` / `p_cost` / `format_version` /
  reserved-bits checks — variable time.
- **Reachability.** Cleartext header is public, so an attacker
  with file-read access already knows the params. Timing of the
  validate call leaks nothing new.
- **Verdict.** **Defended (cleartext-equivalent).**

#### T-8. Superblock candidate sort

- **Where.** [`open/mod.rs::scan_and_recover`](../../../../crates/hidden-volume/src/open/mod.rs).
- **What's observable.** Time to collect distinct-seq
  superblocks into a `BTreeMap` and iterate descending. Depends
  on superblock count.
- **Content-dependence.** Superblock count is a function of
  commit history × replicas — a metadata-level signal (D2-A5
  in adversarial-stance).
- **Verdict.** **Defended at the metadata layer** (commit-history
  exposure already analysed).

#### T-9. Cache-line patterns in scan loops

- **Where.** Sequential, parallel-scan, mmap variants of
  `scan_and_recover`.
- **What's observable.** Memory-access patterns inside a single
  open call.
- **Reachability.** Requires CPU-level cache-timing (Spectre /
  Flush+Reload). Out-of-scope CPU side-channel.
- **Verdict.** **Acknowledged out-of-scope.**

### 2. Memory channels

#### M-1. Heap allocation sizes

- **Where.** Every `Vec::with_capacity(n)` where `n` derives
  from chunk content: B+ tree node decode, batch decode,
  CommitPayload decode.
- **What's observable.** With an in-process or allocator-stats
  observer (`mallinfo()`, jemalloc dumps), allocation sizes per
  decode reveal *something* about the underlying chunk.
- **Reachability.** In-process observer requires running on the
  same process (e.g., a malicious sibling thread). The library
  doesn't expose hooks for allocator introspection.
- **Verdict.** **Out-of-scope** (sibling-thread / allocator-tap
  attacks are at the OS-process-isolation boundary, not the
  library's).

#### M-2. Stack frame sizes

- **Where.** All Rust functions.
- **What's observable.** Stack growth depth.
- **Content-dependence.** Rust stack frames are content-
  independent for normal functions (no `alloca`-style stack
  growth without `unsafe`). Recursion in B+ tree walkers is
  bounded by depth ≤ 2 (writer invariant).
- **Verdict.** **Defended.**

#### M-3. Page-fault patterns in mmap mode

- **Where.** [`open/mod.rs::scan_and_recover_mmap`](../../../../crates/hidden-volume/src/open/mod.rs)
  (feature `mmap`).
- **What's observable.** Page faults reveal which slot the scan
  is currently accessing to a kernel-level observer.
- **Threat-model position.** Kernel-level taps are out-of-scope
  ([threat-model §1.3](../threat-model.md) trusts kernel +
  filesystem for tiers T0–T3; T2' adversaries with kernel taps
  are explicitly out of scope).
- **Verdict.** **Acknowledged out-of-scope.**

#### M-4. Heap-residual key material after drop

- **Where.** Every `Zeroizing<...>` wrapper.
- **What's observable.** Heap state post-Drop.
- **Defense.** `Zeroizing<...>` (volatile + compiler_fence) on
  every secret-bearing buffer. Documented in
  [`audits/memory.md`](memory.md) +
  [`audits/plaintext.md`](plaintext.md).
- **Caveat.** Under `panic = "abort"` in release: no Drop on
  panic; OS process teardown is the scrub. Acknowledged in
  pass-1 commit `f67281f` and in the dossier §4 M1.
- **Verdict.** **Defended.**

### 3. Filesystem channels

#### F-1. File size visibility

- **Where.** `stat()` syscall on the container file.
- **What leaks.** Slot count = `(file_size - CHUNK_SIZE) / CHUNK_SIZE`.
- **Threat-model position.** Documented out-of-scope (file size
  is metadata, threat-model T1 doesn't claim it's hidden).
- **Verdict.** **Acknowledged out-of-scope.**

#### F-2. mtime / atime / ctime evolution

- **Where.** Filesystem metadata, updated on every write
  (mtime), every read (atime, unless mounted noatime).
- **What leaks.** Approximate write / read times to a T2'
  observer.
- **Verdict.** **Acknowledged out-of-scope (T2').**

#### F-3. Syscall trace at open

- **Where.** Linux: visible via `strace`. macOS: `dtrace`.
  Windows: ETW.
- **What leaks.** Sequence of `pread(fd, buf, 4096, offset)`
  calls reveals slot access order during scan.
- **Threat-model position.** Syscall-level taps are kernel-
  level — out-of-scope ([threat-model §1.3](../threat-model.md)).
- **Verdict.** **Acknowledged out-of-scope.**

#### F-4. flock acquisition pattern

- **Where.** [`container/file.rs`](../../../../crates/hidden-volume/src/container/file.rs)
  `try_lock_exclusive` / `try_lock_shared`.
- **What's observable.** flock attempts visible via `lsof` or
  similar. Concurrent-process attempts return WouldBlock fast.
- **Verdict.** **Acknowledged out-of-scope** (lock visibility
  is filesystem-level metadata; the *content* protected by the
  lock is the encrypted file).

### 4. Logging channels

#### L-1. Production library logging

- **Where.** Verified by grep across all `crates/*/src/`:
  - `log::*` macros: **0 production sites**.
  - `tracing::*` macros: **0 production sites**.
  - `println!` / `eprintln!`: **0 production sites** (only in
    `bin/hv.rs` CLI's stderr-progress + `examples/`).
  - `dbg!()`: **0 sites** anywhere.
- **What this proves.** The library does not emit log messages
  during normal operation. A logging subsystem that captures
  the host process's logs sees nothing from the library.
- **Verdict.** **Defended by absence.** No log channel exists.

#### L-2. Error message content

- **Where.** [`error.rs`](../../../../crates/hidden-volume/src/error.rs).
- **What's observable.** `Error::Display` strings returned to
  the API caller.
- **Content-dependence.** All variants use static `&'static str`
  payloads or `{slot: u64}` / `{limit: usize}` numeric fields.
  No variant interpolates key material, password content, or
  plaintext bytes (verified by grep for `format!` patterns
  including "password"/"key" — only test files match).
- **Verdict.** **Defended.** Error messages are deniability-safe
  (D2 — wrong-password and not-our-chunk unify in `AuthFailed`).

#### L-3. Panic message content

- **Where.** Production-reachable `panic!` / `unreachable!` /
  `unwrap` / `expect` sites: 0 in production code
  ([adversarial-stance M1-A1](adversarial-stance.md), verified
  pass-1).
- **Verdict.** **Defended.** No panic path can leak content
  because no panic path is reachable from production inputs.

### 5. Microarchitectural channels (out-of-scope, enumerated)

#### MA-1. Spectre / MDS / Foreshadow

- **Threat-model position.** Out-of-scope ([§4](../threat-model.md)).
  Mitigation is OS-level (microcode updates + kernel KPTI /
  speculative-execution mitigations).
- **Verdict.** **Out-of-scope.**

#### MA-2. Cache-timing on AES instructions

- **Reachability.** N/A — the project uses ChaCha20, not AES.
  AES-NI cache-timing is irrelevant.
- **Verdict.** **N/A.**

#### MA-3. Branch-prediction probes

- **Where.** Any branch in production code.
- **Threat-model position.** CPU-level. Out-of-scope.
- **Verdict.** **Out-of-scope.**

#### MA-4. Power / EM / acoustic emanations

- **Threat-model position.** Out-of-scope for a software
  library (these are physical-side-channels requiring lab
  equipment).
- **Verdict.** **Out-of-scope.**

### 6. Feature-variant differences (SC-INFO2)

The library exposes three open-scan variants:

| Variant | Where | Channel signature |
|---|---|---|
| Sequential | default | per-slot read, in slot order |
| Parallel | `parallel-scan` feature (Linux/macOS) | rayon work-stealing; access order non-deterministic across runs |
| mmap | `mmap` feature (Linux/macOS) | one `mmap()` syscall + page faults per accessed slot |

TM1's bench ([`benches/timing_oracle.rs`](../../../../crates/hidden-volume/benches/timing_oracle.rs))
exercises the *sequential* path. The parallel and mmap paths
have not been independently timing-characterised.

- **Expected outcome.** Parallel: per-thread variance washes
  out the per-chunk MAC-fail-vs-pass signal at the aggregate
  open-time level, *but* an observer with thread-level
  visibility could re-aggregate. Mmap: page-fault pattern
  reveals access order to a kernel-level observer (M-3).
- **Verdict.** **INFO** for v1.x: extend `timing_oracle.rs`
  to cover both feature variants and document the per-variant
  TM1 leak shape. Not a new channel; refinement of TM1
  characterisation.

## Summary table

| ID | Channel | Observable | Verdict | Severity |
|---|---|---|---|---|
| T-1 | Argon2 timing | derivation time | Acknowledged out-of-scope (CPU-level) | INFO |
| T-2 | ChaCha20 / Poly1305 | per-AEAD-op time | Defended (primitives constant-time) | INFO |
| T-3 | BLAKE3 timing | hash time | Defended (constant-time) | INFO |
| T-4 | TM1 open-scan oracle | frac_owned ±10-20% | Acknowledged + mitigation-tracked v1.x | INFO |
| **T-5** | **Decode-path early-return** | malformed-input rejection time | **Not reachable today; defense-in-depth opp** | **INFO (SC-INFO1)** |
| T-6 | zstd decompression timing | batch decompress time | Defended at AEAD layer | INFO |
| T-7 | Argon2-params validate timing | header-parse time | Defended (cleartext) | INFO |
| T-8 | Superblock-candidate sort | sort time | Defended at metadata layer | INFO |
| T-9 | Cache-line patterns in scan | scan-thread cache misses | Acknowledged out-of-scope (CPU-level) | INFO |
| M-1 | Heap allocation sizes | alloc dumps | Out-of-scope (sibling-thread / allocator taps) | INFO |
| M-2 | Stack frame sizes | content-independent in Rust | Defended | INFO |
| M-3 | mmap page-fault patterns | kernel-level | Acknowledged out-of-scope | INFO |
| M-4 | Heap-residual key material | post-Drop heap | Defended (`Zeroizing`); panic=abort caveat | INFO |
| F-1 | File size | `stat()` | Acknowledged out-of-scope | INFO |
| F-2 | mtime/atime/ctime | filesystem metadata | Acknowledged out-of-scope (T2') | INFO |
| F-3 | Syscall trace | strace / dtrace / ETW | Acknowledged out-of-scope (kernel-level) | INFO |
| F-4 | flock pattern | `lsof` visibility | Acknowledged out-of-scope | INFO |
| L-1 | Production logging | log / tracing / println | **Defended by absence** (0 production sites) | INFO |
| L-2 | Error message content | API caller observable | Defended (no secret content) | INFO |
| L-3 | Panic message content | unwrap / expect / panic! | Defended (0 production sites) | INFO |
| MA-1 | Spectre / MDS / Foreshadow | CPU microarchitecture | Out-of-scope | INFO |
| MA-2 | AES cache-timing | N/A (not used) | N/A | INFO |
| MA-3 | Branch-prediction probes | CPU-level | Out-of-scope | INFO |
| MA-4 | Power / EM / acoustic | physical | Out-of-scope | INFO |
| **SC-INFO2** | **TM1 across feature variants** | parallel / mmap not bench'd | **Extend bench in v1.x** | **INFO** |

**Counts:** 0 CRITICAL, 0 HIGH, 0 MEDIUM, 0 LOW. 2 INFO
observations (SC-INFO1 decode-path constant-time defense-in-depth,
SC-INFO2 TM1 multi-variant characterisation).

## What this pass did NOT cover

- **Quantitative timing experiments beyond the existing
  `timing_oracle.rs` bench.** Running the bench across hardware
  variants (x86, ARM, NEON-on/off) is out of scope for a
  static-analysis pass.
- **Concrete fuzzing of decode paths.** That's the [pass-4 format
  fuzzing analysis](./format-fuzzing.md) (next).
- **End-to-end attack narrative.** That's the [pass-5 threat-model
  challenge](./threat-model-challenge.md) (final).
- **External-tool runs** (Valgrind cachegrind, Callgrind, ptrace
  bench harnesses). These would be a separate dependent-tooling
  audit.

## Recommended actions (v1.x roadmap)

Neither is a current bug; both are defense-in-depth options to
consider during a v1.x security-hardening pass:

1. **SC-INFO1 (constant-time decode pass).** Add a constant-time
   variant of `Plaintext::decode` / `LeafNode::decode` /
   `InternalNode::decode` / `decode_batch` that walks the full
   payload regardless of validity. Wraps the existing decode in
   a fixed-time shell. Cost: ~4 KiB extra work per chunk per
   decode; negligible against the per-chunk AEAD-decrypt cost.
   Benefit: closes the key-holder-self-DoS scenario; matters
   only if writer-side regression produces malformed plaintexts.
2. **SC-INFO2 (TM1 multi-variant bench).** Extend
   `benches/timing_oracle.rs` to include parallel-scan and mmap
   variants. Document the per-variant TM1 leak shape in the
   threat-model F-TM1 section. No code change needed; just
   bench + doc.
