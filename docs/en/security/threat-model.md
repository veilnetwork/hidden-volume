# Threat model

🇬🇧 **English** · [🇷🇺 Русский](../../ru/security/threat-model.md)

**Status.** Pre-release working document. The shape will not change
between now and v1.0 — only specific findings will be filled in. No
external paid review (Trail of Bits / Cure53 / NCC class) is planned
for this project; the rationale (anonymity + no-budget) and the
substitute process (in-tree audit passes, this threat model, the
per-area audits, reproducible signed builds, community bug-bounty)
are documented in
[`audits/self-audit.md`](audits/self-audit.md). Engagement of a
community researcher whose public technical write-up follows the
SECURITY.md disclosure timeline is the canonical path by which
external review *can* still happen for this project.

This document is the formal counterpart to `DESIGN.md` §1 (which
states the model concisely) and to the existing per-area audit notes
([`audits/constant-time.md`](audits/constant-time.md),
[`audits/memory.md`](audits/memory.md),
[`audits/plaintext.md`](audits/plaintext.md),
[`audits/fsync.md`](audits/fsync.md)). It is structured as a
checklist for any reviewer
— internal, community, or eventual external — taking the project's
claims seriously: each invariant is named, defined, mapped to
concrete code, and cross-referenced to its supporting audit pass.

If anything here conflicts with `DESIGN.md`, **`DESIGN.md` wins**.

## 1. System model

### 1.1 What `hidden-volume` is

A single-file, append-only, encrypted, multi-space storage primitive.
The core is sync, std-only Rust. An optional tokio wrapper
(`hidden-volume-async`, currently feature-gated) and a `parallel-scan`
feature exist but are not part of the security boundary — they call
the same sync core.

A container file holds:

- A 48-byte cleartext header (salt 32 + Argon2id params 16; the rest
  of the first chunk is uniform-random padding). v3 removed the
  32-byte `container_id` field that v2 stored in the cleartext
  header — `container_id` is now derived per-space from the
  versioned master key (closes D1-A2 fingerprint signature).
- A grid of fixed 4 KiB chunks, each AEAD-sealed
  (XChaCha20-Poly1305) under a per-slot key derived from the per-
  space master via BLAKE3 keyed-hash.
- One or more **spaces** within that grid, mutually indistinguishable
  from random bytes without the per-space password.

The library exposes per-space KV (`Tx::put` / `delete` / `get` /
`list`) and append-log (`Tx::append_log` / `iter_log_after` /
`iter_log_before` / `read_log`) APIs, plus management primitives
(`Container::compact_known`, `Container::change_passwords`,
`Space::erase_namespace`, `Space::vacuum_data_batches`,
`Space::verify_integrity`).

### 1.2 What `hidden-volume` is NOT

- **Not a network protocol.** P2P sync, transit encryption, identity
  exchange, contact discovery — all out of scope. See
  `docs/en/guide/multi-device.md` for the contract host-app sync layers
  follow.
- **Not a host-app.** UI state, recently-opened-files lists, IME
  caches, screenshot thumbnails, swap-file leakage — all the host-
  app's responsibility. The library can't see them.
- **Not a key-management service.** Argon2id derives keys from
  passwords on demand; the optional pre-derived `SpaceKeys` cache
  delegates to the OS keyring. No KMS integration.
- **Not an authentication layer.** "Has the password" ≡ "is the
  user". Multi-factor / hardware-token gating is host-app concern.

### 1.3 Trusted components

`hidden-volume`'s correctness rests on the following dependencies
running correctly:

- The Rust toolchain (rustc + std).
- RustCrypto crates: `chacha20poly1305`, `argon2`, `blake3`,
  `zeroize`, `subtle`. These are constant-time / zeroizing by
  construction.
- The OS filesystem (POSIX `flock`, `pread`, `fsync` / `sync_all`
  semantics).
- `getrandom` for non-determinism in salts, nonces, padding.

A compromise of any of the above is **out of scope** for this
threat model.

## 2. Adversary model

We enumerate three adversary capability tiers. The library defends
the listed invariants against each.

### T1 — Single-snapshot passive

**Capability.** Adversary obtains the container file at one
point in time. They have unlimited offline compute and full
knowledge of the format. They do NOT have any password.

**Examples.** Cloud-storage subpoena returning a backup snapshot;
forensic seizure of an offline disk; airport border inspection of
a powered-off device.

### T2 — Multi-snapshot passive

**Capability.** Adversary obtains the container file at multiple
points in time and can compare snapshots byte-for-byte. They
otherwise behave as T1.

**Examples.** Recurring cloud backups; periodic forensic imaging.

We split T2 into:

- **T2 (append-diff).** Sees that the file grew between snapshots.
- **T2' (in-place-diff).** Sees that specific bytes inside the
  file region present in both snapshots changed (rewrite-in-place
  or tombstone-scrub at a specific slot).

T2' is strictly stronger than T2.

### T3 — Compelled-key

**Capability.** Adversary has T2 plus has compelled the user to
supply *one* password (e.g., border officer demands a password
under threat). They have unlimited offline compute and full
knowledge of the format.

**Examples.** Border interrogation; rubber-hose cryptanalysis.

T3 is the *primary* adversary `hidden-volume` is designed against —
deniability of additional spaces beyond the one whose password was
disclosed.

### Out-of-scope adversaries

Listed for completeness; **no defence is claimed**:

- **T-active.** Adversary modifies the file between snapshots and
  observes the user's reaction. Detection is host-app responsibility
  (see §4 R1).
- **T-side-channel-OS.** Adversary has read access to swap, /proc,
  /dev/mem, kernel page cache, etc. on a running host. The library
  cannot defend against an OS-compromised attacker.
- **T-side-channel-CPU.** Spectre / Meltdown / cache-timing on
  shared hardware. Defended only at the CPU microcode and
  hypervisor layers.
- **T-cold-boot.** Memory remains readable for seconds-to-minutes
  after power loss. Defended only by full-disk encryption + secure
  boot.
- **T-supply-chain.** Compromised RustCrypto / `rustc` /
  dependency. The cargo audit workflow and the `Cargo.lock` policy
  bound this risk but do not eliminate it.

## 3. Security invariants

The library makes the following invariant claims. Each is named
(short tag + descriptive title), defined precisely, and mapped to
the code path that establishes it plus the audit document that
verifies it.

### D1 — Single-snapshot indistinguishability

**Statement.** Against T1, the file is computationally
indistinguishable from a uniform-random blob with the 48-byte
cleartext header. Specifically: an adversary holding the file but
no password cannot determine the number of spaces (≥ 0) inside,
nor the kind / count / size of any chunk's contents, nor any
per-space identifier (v3 closed the D1-A2 fingerprint).

**Provided by.**
- Per-chunk XChaCha20-Poly1305 with random 192-bit nonce and AAD
  binding to slot index + per-space derived `container_id`.
  Ciphertext indistinguishable from random (IND-CPA + ciphertext
  integrity).
- Garbage chunks are uniform-random fill (`crypto::rng::fill`),
  visually identical to AEAD ciphertext.
- File size obfuscation via `ContainerOptions::initial_garbage_chunks`
  (decoy initial size) and `PaddingPolicy::{BucketGrowth, FixedRatio}`
  (per-commit growth obfuscation).
- Header is always 48 bytes regardless of space count; the only
  populated cleartext field beyond the 16-byte Argon2 params word is
  the 32-byte random `container_salt` (random per fresh container).
  v3 removed the cleartext `container_id` (now per-space derived).

**Code paths.** `crypto/aead.rs::ChunkAead::seal`,
`container/file.rs::append_garbage_chunks`,
`padding/`, `space/mod.rs::commit_tx` post-commit padding hook.

**Audit.** Implicit — covered by AEAD upstream proofs. No
hidden-volume-specific audit document; no findings expected.

### D2 — Compelled-key plausible deniability

**Statement.** Against T3, an adversary holding the file plus one
disclosed password for space A obtains a cryptographic statement
about A but no statement (cryptographic or otherwise) about whether
other spaces exist.

**Provided by.**
- Per-space master key `Argon2id(password, container_salt)` is
  domain-separated and indistinguishable across spaces — same salt,
  different passwords produce uncorrelated keys.
- Discovery scan (open path) is `O(N)` trial-decrypts every slot
  with the candidate space's per-slot key. Slots that AEAD-fail are
  silently skipped without any side-channel signal — `try_decrypt`
  branches identically on success/failure (constant-time AEAD tag
  check inside RustCrypto).
- `Error::AuthFailed` unifies "wrong password" and "no such space" —
  same return code, same timing, same recovery path.
- Public APIs DO NOT expose chunk count, owned-slot indices, or any
  per-space metadata to anyone without the password.

**Code paths.** `crypto/kdf.rs::derive_master_key`,
`open/mod.rs::scan_and_recover` (and `scan_and_recover_parallel`),
`crypto/aead.rs::ChunkAead::open`, `error.rs::Error::AuthFailed`.

**Audit.** `docs/en/security/audits/constant-time.md` (constant-time pass) — passed; no
secret-touching compares in our own code, all CT-sensitive ops
delegate to RustCrypto.

### I1 — Per-chunk integrity

**Statement.** Any single-byte modification to any chunk is detected
on the next attempt to AEAD-open it. The library never returns
unauthenticated bytes.

**Provided by.** Poly1305 tag in each chunk (XChaCha20-Poly1305).
Tag check is constant-time in RustCrypto.

**Code paths.** `crypto/aead.rs::ChunkAead::open`.

**Audit.** Implicit (RustCrypto proven). Tested in
`tests/sb_replicas.rs` (single-byte flip → AuthFailed),
`tests/integrity.rs` (corruption localization through verify_integrity).

### I2 — Tail-corruption tolerance

**Statement.** Truncation or torn writes at the file tail roll the
container back to the last successfully-fsynced state. No partial
state is exposed; no panic; no UB.

**Provided by.**
- Three-fsync commit protocol: Data → fsync → Commit → fsync →
  Superblock(s) → fsync. Crash before the third fsync leaves the
  prior Superblock as max-seq.
- Multiple Superblock replicas per commit (`superblock_replicas`,
  default 3). Single-chunk corruption survives via remaining
  replicas.
- Open path picks max-seq Superblock that AEAD-decrypts and ignores
  the rest.

**Code paths.** `space/mod.rs::commit_tx` (3-fsync barriers),
`container/mod.rs::ContainerOptions::superblock_replicas`,
`open/mod.rs::scan_and_recover` (max-seq pick).

**Audit.** `docs/en/security/audits/fsync.md` (fsync ordering pass) — passed;
all 7 fsync sites traced. Tested by `tests/crash_recovery.rs` (8
hand-written), `tests/crash_proptest.rs` (24 random workload ×
random truncation), `tests/sb_replicas.rs` (corruption survival).

### I3 — Cross-space isolation

**Statement.** A bug or malicious caller in code holding space A's
keys CANNOT corrupt space B's data structures. Specifically: A's
write paths only touch slots A owns (Tx-tracked); B's chunks are
opaque garbage to A.

**Provided by.**
- Per-space keys (Argon2id per password). Keys derived from password
  X cannot AEAD-open chunks sealed under password Y.
- Append-only file format: writes go to fresh slots, never overwrite
  arbitrary positions. Scrub / overwrite primitives
  (`scrub_slot`, `write_slot`) require a slot the caller owns; the
  module documents this and tests verify ownership tracking.
- DataBatch chunks are written exclusively by the Tx that committed
  them; pointer slots are stored in that namespace's KV index, not
  reachable from another namespace.

**Code paths.** `crypto/derive.rs::SpaceKeys`,
`container/file.rs::ContainerFile::{scrub_slot, write_slot}`,
`space/mod.rs::Space::owned_slots`.

**Audit.** `docs/en/security/audits/memory.md` + `docs/en/security/audits/plaintext.md`. Tested
by `tests/multi_device.rs::cross_space_history_isolation`,
`tests/scrub.rs::vacuum_does_not_touch_other_spaces`,
`tests/erase_namespace.rs::multi_space_isolation_under_erase`,
`tests/integrity.rs::multi_space_isolation_in_verify`.

### R1 — Rollback / fork-detection contract (host-app cooperative)

**Statement.** The library does NOT detect rollback attacks on its
own (T-active). It DOES expose primitives sufficient for a host-app
to detect rollback / fork against an external anchor (TPM, server
counter, signed log).

**Provided by.**
- `Space::commit_seq()` — monotonic per-space counter.
- `Space::commit_history()` — sorted-asc, deduplicated list of every
  Superblock seq still on disk that AEAD-decrypts under our key.
- Triage algorithm in `docs/en/guide/multi-device.md` §"Rollback / fork-
  detection".

**Code paths.** `space/mod.rs::Space::{commit_seq, commit_history}`,
`open/mod.rs::scan_and_recover` (commit_history population).

**Audit.** `docs/en/guide/multi-device.md` documents the contract. Tested by
`tests/multi_device.rs` (8 scenarios incl. host-app triage).

### M1 — Memory hygiene of key material

**Statement.** Secret key material (Argon2-derived master, per-space
keys, per-slot keys, per-call cipher state) is zeroized when its
owning value drops; in particular before allocator pages are
returned to the OS.

**Provided by.**
- `SpaceKeys` derives `ZeroizeOnDrop`; its fields are
  `Zeroizing<[u8; 32]>` in transit.
- `derive_master_key` returns `Zeroizing<[u8; 32]>`.
- `derive_chunk_key` / `derive_subkey` return `Zeroizing<[u8; 32]>`.
- `ChunkAead`'s cipher state zeroes via RustCrypto's
  `ZeroizeOnDrop` impl on `chacha20`+`aead` cipher state.
- AEAD-decrypted plaintext bytes (`ChunkAead::open` return value)
  are wrapped in `Zeroizing<Vec<u8>>` so the heap region is scrubbed
  on drop. Pre-encrypt encoded bytes (`Plaintext::encode` output,
  `LeafNode`/`InternalNode`/`CommitPayload` encoded bytes,
  `log::encode_batch`/`decode_batch` raw concat / decompress
  buffers) are `Zeroizing`-wrapped at creation.

**Code paths.** `crypto/derive.rs`, `crypto/kdf.rs`,
`crypto/aead.rs::ChunkAead::open`, `space/mod.rs::append_chunk`,
`space/mod.rs::write_tree_for_namespace`, `space/log.rs`.

**Audit.** `docs/en/security/audits/memory.md` + `docs/en/security/audits/plaintext.md`.
Type-level regression tests in `tests/memory_hygiene.rs` and
`tests/plaintext_hygiene.rs` lock in the `Zeroizing<>` signatures.

**Known deferral.** User-owned `Vec<u8>`s (KV values held in
`Tx::pending_*`, `Space::get`/`list`/`iter_log` return values,
decoded `IndexNode` entries) are NOT wrapped in `Zeroizing`.
Wrapping would propagate through the public API and force every
host-app to adopt the wrapper. Mitigation route for hosts that
need it: process-scope `mlock` + private memory mapping +
secret-allocator. Documented in
[`docs/en/security/audits/memory.md`](audits/memory.md) §C and
[`docs/en/security/audits/plaintext.md`](audits/plaintext.md).

**FFI / async / CLI password buffers (audit pass 16 + 17).** Every
password entry point on every wrapper crate now wraps the incoming
`Vec<u8>` in `zeroize::Zeroizing` immediately on entry, so the
Rust-side heap copy scrubs deterministically on drop (including the
panic path):

- `hidden-volume-ffi`: `SpaceHandle::create`, `SpaceHandle::open`,
  `AsyncSpaceHandle::create`, `AsyncSpaceHandle::open`, top-level
  `compact_known(path, passwords)` (drains `Vec<Vec<u8>>` into
  `Vec<Zeroizing<Vec<u8>>>`), and `change_passwords(path, rotations)`
  (drains every `PasswordRotation` into a pair of `Zeroizing`
  buffers).
- `hidden-volume-async`: `AsyncSpace::create`, `AsyncSpace::open`.
- `hv` CLI: `read_password` returns `Zeroizing<Vec<u8>>`,
  `read_all_passwords` returns `Vec<Zeroizing<Vec<u8>>>`, and
  `cmd_put`'s `value_bytes` is `Zeroizing<Vec<u8>>`.

`PasswordRotation` deliberately does NOT derive `Clone` (audit pass
17 F-2) — a derived `Clone` would let an internal `.clone()` silently
spawn a non-`Zeroizing` copy outside the wrapper flow. Foreign-side
buffers (the Kotlin `ByteArray` / Swift `Data` / etc. that uniffi
unmarshals from) remain the host-app's hygiene responsibility — that
is the owner of the foreign-side memory, not the Rust runtime.

### C1 — Cancellation safety

**Statement.** Long sync operations (`open_space` discovery scan,
`Container::repack`, `compact_*`) accept a `CancelToken` and abort
at well-defined checkpoints without leaving partial state on disk
that's observable to other writers. Mid-cancel: completed Tx
remains durable; partial Tx is discarded (no `commit_tx` was
issued); temp files used by `compact_*` and `change_passwords` are
removed on cancel.

**Provided by.**
- `cancel.rs::CancelToken` (Arc<AtomicBool>).
- `Container::open_space_cancellable`, `repack_cancellable`,
  `compact_known_cancellable`,
  `change_passwords_cancellable`. Internal: per-slot poll every
  `CANCEL_POLL_PERIOD = 64` slots in `scan_and_recover_with_cancel`;
  per-namespace and per-Tx checkpoints in `repack_inner_mapped`;
  tmp-file cleanup in `compact_in_place_impl` and
  `change_passwords_impl`.

**Code paths.** `cancel.rs`, `open/mod.rs::scan_and_recover_with_cancel`,
`container/mod.rs::repack_inner_mapped`,
`container/mod.rs::compact_in_place_impl`,
`container/mod.rs::change_passwords_impl`.

**Audit.** Tested by `tests/cancellation.rs` (10 scenarios) and
`tests/repack_cancellation.rs` (7 scenarios) — incl. mid-flight
race + post-cancel file-integrity check.

## 4. Out-of-scope mitigations (known limitations)

The library does NOT defend against the following. Listed
explicitly so review can confirm they are not in scope:

| Threat | Why not | Where deferred |
|---|---|---|
| Rollback by snapshot adversary | Library has no notion of "now"; needs external anchor | R1 (host-app cooperative); `docs/en/guide/multi-device.md` |
| User-data Vec<u8> heap residue | Public-API churn cost > benefit; mitigated process-wide via mlock | [`audits/memory.md`](audits/memory.md) §C, [`audits/plaintext.md`](audits/plaintext.md) |
| Side-channel on host-app UI / IME / swap | Outside library scope | `DESIGN.md` §1 out-of-scope |
| Multi-snapshot byte-diff on in-place rewrite (T2') | Rewrite is intentional (vacuum, scrub); fully obscuring requires periodic random rewrite of all garbage, prohibitively expensive | `DESIGN.md` §1 out-of-scope |
| Encryption-at-rest is visible | Deniability is about *which* secrets, not *whether* secrets exist | `DESIGN.md` §1 out-of-scope |
| Network filesystems that ignore `flock` | Library can't detect; deployer responsibility | [`guide/multi-device.md`](../guide/multi-device.md) Pattern B caveat |
| **mmap on filesystems that allow concurrent mutation** (NFS, FUSE, SMB) | The `mmap` feature uses `memmap2::Mmap` which assumes the underlying file's bytes are stable for the mapping's lifetime. `flock(LOCK_EX)` enforces this on local filesystems (ext4/xfs/btrfs/APFS/NTFS); on NFS the lock advisory is best-effort and on some FUSE filesystems it's outright ignored. A concurrent mutation under an active mmap violates Rust's aliasing rules. | See §4.2 below; `mmap` is `cfg(unix)` AND opt-in via Cargo feature; mobile and FFI consumers should leave it off |
| **Argon2id is uninterruptible** (`HV-NEW1`) | RustCrypto's `argon2::Argon2::hash_password_into` does not check a cancellation flag. A user who triggers `Container::open_cancellable` with `HEAVY` params (~250ms on x86 server-class, multi-second on Cortex-A53) and then cancels will still see Argon2 run to completion before `Error::Cancelled` surfaces. | See §4.3 below; host-apps should run KDF in a `spawn_blocking` task with a hard timeout and treat the timeout as user-visible cancel |
| OS-level compromise (root, /proc, /dev/mem) | Threat exceeds library boundary | §2 out-of-scope |
| CPU side channels (Spectre, cache timing) | OS / microcode boundary | §2 out-of-scope |
| Cold-boot RAM recovery | Hardware boundary | §2 out-of-scope |
| Supply chain (RustCrypto / rustc / deps) | `cargo audit` + `Cargo.lock` policy bounds, doesn't eliminate | §2 out-of-scope |
| **F-PAD** — padding-policy tamper by header modification (audit pass 9; reclassified v3 #9) | v2 behaviour: T2 adversary flipped `padding_policy_index` (bits 16..24 of `Argon2Params.version`) silently degrading post-commit padding on future writes. **v3 reclassifies this from silent privacy-degradation to DoS-class visible failure**: the entire `params.version` u32 is now folded into `master_key` via the post-Argon2 BLAKE3 step (§3 / `derive_master_key`), so a flipped policy byte produces a *different* master_key on next open ⇒ `Error::AuthFailed`. The DoS surface remains (any cleartext-header tamper still can deny open), but the privacy-degradation surface is closed cryptographically. | See §4.1 below |

### 4.1 F-PAD — padding-policy tamper (v3 reclassification)

**v3 status (2026-05-28).** **F-PAD has graduated from a
privacy-degradation class to a DoS-class threat**, by the v3
cryptographic version-binding step (`derive_master_key`, §3 of
[`docs/en/reference/format.md`](../reference/format.md) and #9 of
[`crypto/kdf.rs`](../../../crates/hidden-volume/src/crypto/kdf.rs)).
The reason: in v3 the full `Argon2Params.version` u32 — *including
the `padding_policy_index` byte at bits 16..24* — flows into the
BLAKE3-keyed step that produces `master_key`. So a flipped policy
byte produces a different `master_key` on the next open ⇒
`Error::AuthFailed`. Silent degradation is no longer reachable.

This section describes the **historical v2 surface** (padding
silently degraded) and the **v3 new surface** (open denied), which
are different threat classes.

**v2 historical scope (closed in v3).** A T2 (file-modify) adversary
with write access to the container file but no password could flip
`Argon2Params.version` bits 16..24 from a non-zero preset (1=256 KiB
/ 2=1 MiB / 3=16 MiB) to `0` (`PaddingPolicy::None`). On the next
`Container::open`, `from_persisted_index(0)` returned
`PaddingPolicy::None` and runtime policy degraded silently. **Future
writes** then grew the file without post-commit padding, leaking
per-Tx growth deltas to the multi-snapshot adversary. Past chunks on
disk were unchanged; only future commits leaked.

**v3 current scope (DoS-class).** Any tamper of bits 0..32 of
`params.version` causes the next open to derive a different
`master_key` ⇒ `Error::AuthFailed`. The adversary cannot any longer
*silently* degrade the runtime padding policy; the only achievable
outcome is denial-of-service. F-PAD therefore graduates out of the
D1 / privacy surface and into the same DoS bucket as F1 (Argon2
m_cost OOM via header tamper) — both mitigated by the same
mechanism: validation + crypto-binding gate.

**Forward-compat fallback case (audit pass 10 L4, still relevant in
v3).** The silent-degrade-to-`None` path remains reachable in the
v3-reader-meets-future-v3.y-writer scenario, but ONLY across
non-version-bumping policy extensions. A future v3.y writer that
introduces a new preset (index 4..=255 for, say, a 64 MiB bucket
size) WITHOUT bumping `format_version` would produce containers a
v3.x reader decodes through [`PaddingPolicy::from_persisted_index`]
into the `_ => None` arm — same observable failure mode as a v2
tamper. Host-apps mixing library versions on the same container
should call [`Container::set_padding_policy`] explicitly after open.
Note: any future v3.y change to the policy-index encoding that
expects cross-version interop is a doc-policy decision; the v3
crypto binding prevents *malicious* downgrade but not *benign*
version-skew degrade.

**What is NOT affected (v3).**
- Confidentiality of stored data — AEAD-protected as before.
- Integrity of stored data — chunks on disk unchanged.
- Deniability of stored data — D1 / D2 / I1 / I2 / I3 still hold.
- D1 with respect to *future* writes — closed by the v3 binding;
  no longer a privacy concern.

**What IS affected (v3).**
- **Availability** of the container after a header-byte tamper
  (DoS). Mitigation: keep an out-of-band backup of the original
  header bytes; the file body remains decryptable if the original
  header is restored byte-for-byte.

**Practical reachability.** The adversary already has T2 (file
write) access — at that point DoS is largely conceded for any
cleartext-header field (F1 / F-PAD / future). The v3 cryptographic
version-binding step is what *prevents* this DoS surface from being
silently leveraged into a privacy surface.

**Mitigation (host-app cooperative, retained from v2).**
[`Container::set_padding_policy`] (FFI: `SpaceHandle::set_padding_policy`)
overrides the persisted policy unconditionally. In v3 this is no
longer security-critical (tamper denies open, not privacy), but it
remains useful for the legitimate v3.y forward-compat case
described above.

**Why we still rely on a cleartext-header byte for policy.**
Binding `padding_policy_index` into AEAD would re-introduce a
structured cleartext field, regressing D1. The v3 solution
(version-bind the entire `params.version` into KDF) keeps the byte
in the open-header but eliminates its silent-degrade attack
surface.

### 4.2 `mmap` and trusted filesystems (audit pass 14)

**Scope.** The `mmap` Cargo feature opens the container file and
maps its bytes via [`memmap2::Mmap`](https://docs.rs/memmap2). The
mapping is constructed with `unsafe` because `Mmap`'s safety
contract requires that **no other process or thread mutates the
mapped bytes for the lifetime of the mapping**. The library
acquires `flock(LOCK_EX)` (or `LOCK_SH` for `open_readonly`) before
constructing the mapping, which on POSIX local filesystems
satisfies the contract: another writer attempting to acquire
`LOCK_EX` blocks (or gets `Error::Busy`) until our mapping is
dropped.

**Where the contract may not hold.**

- **NFS v3** without `lockd` — advisory-only; depending on server
  configuration, a remote client can mutate the file regardless of
  our `flock`.
- **FUSE filesystems** that don't propagate `flock(2)` to the
  backend — `fuse-overlayfs`, some sshfs configurations, etc.
- **SMB/CIFS shares** mounted via `cifs-utils` — locking is
  implementation-dependent.
- **Containerised runtimes** (Docker, Kubernetes) where the volume
  driver substitutes a non-flock-honouring backend.

**Concretely what fails.** The mapping is read by `open` /
`open_readonly` to scan the chunk grid. If a concurrent writer
mutates the file under us, the AEAD-decrypt of a torn chunk fails
with `Error::AuthFailed`, which is a safe error path. **But** Rust
considers the underlying memory aliasing UB; in practice this
manifests as either a stale-cache read (benign-looking failure) or
a SIGBUS on Linux when the file shrinks under the mapping.

**Recommendation.** `mmap` is **opt-in** via a Cargo feature AND
`#[cfg(unix)]`. Mobile and FFI consumers SHOULD leave it disabled.
For server-side deployments on local ext4/xfs/btrfs/APFS, mmap is
safe and gives a measurable speedup on cold-cache scans of
multi-GiB containers. For any environment where the underlying
storage is questionable (network-mounted, FUSE-overlayed,
container-volume-passthrough), use the default streaming `pread`
path.

**Why we don't auto-detect.** The library cannot reliably
introspect mount options across all platforms; `statfs` returns
hints (`f_type == NFS_SUPER_MAGIC`, etc.) but not enough for a
universal "this FS is safe for mmap" predicate. The opt-in feature
flag is the contract.

### 4.3 Argon2id is uninterruptible (`HV-NEW1`)

**Scope.** Every cancellable open path
([`crate::Container::open_space_cancellable`],
[`crate::Container::repack_cancellable`], etc.) takes a
[`crate::cancel::CancelToken`] and polls
[`crate::cancel::CancelToken::check`] at coarse-grained
checkpoints inside the O(N) discovery scan. **Argon2id derivation
runs BEFORE the scan and is NOT cancellable.** RustCrypto's
[`argon2::Argon2::hash_password_into`] does not check any flag;
once it starts, it runs to completion (~30 ms on x86 with `MIN`
params, ~250 ms with `HEAVY` params, multi-second on Cortex-A53
with `HEAVY`).

**Concretely what fails.** A user invoking
`Container::open_space_cancellable(b"password", &token)` and then
firing `token.cancel()` from another thread will still see Argon2
complete; `Error::Cancelled` surfaces only at the first scan-loop
checkpoint AFTER Argon2 returns. For default params on modern
hardware this window is sub-100ms and rarely user-visible. For
`HEAVY` params on weak phones the window is multi-second and CAN
result in a UI freeze if the cancellation was triggered by an
"app going to background" event.

**Recommendation.** Host-apps that need hard timeouts on KDF
should run `Container::open*` inside a `tokio::task::spawn_blocking`
(or platform equivalent) with an outer timeout, and treat the
timeout as user-visible cancel. The
[`crate::cancel::CancelToken`] is sufficient for the post-KDF
scan phase; KDF needs the surrounding runtime's pre-emption.

**Won't fix in-tree** until RustCrypto's `argon2` crate adds a
cancellation hook (upstream issue, no ETA). The library's
documentation calls out the limitation; the test
`tests/cancellation::cancel_during_argon2_completes_then_aborts`
locks down the current behaviour.

### 4.4 F-TM1 — open-time scan timing oracle

**Scope.** A T1 adversary capable of measuring `Container::open_space`
wall-clock time (e.g., a process-monitoring observer on the same
host) can infer the *owned-fraction* of the container — the ratio
of chunks decryptable under the supplied password to total chunks.
The leak originates in the AEAD-decrypt path: a failed MAC
short-circuits before the body decrypt; a successful MAC runs
ChaCha20 over the full body. So the per-chunk wall-clock is a
function of "owned?" with a CPU-cycle granularity gap.

**What's leaked.** Approximate `frac_owned` (±10-20%) for the
observed open. Does **not** identify which slots are owned. Does
**not** distinguish "another space's chunks" from "garbage padding"
(both fail AEAD identically). The leak is *coarser* than file
size + cleartext-header fingerprint and *additive* to them.

**What's not leaked.** Per-slot ownership (would require per-chunk
timing resolution that a process-level observer typically does not
have); identity of "the other space"; commit count of any other
space.

#### Measurement (audit pass 5, 2026-05-28)

[`benches/timing_oracle.rs`](../../../crates/hidden-volume/benches/timing_oracle.rs)
characterises the leak across all three scan-mode variants
(sequential, parallel-scan, mmap). Run with:

```sh
cargo bench --bench timing_oracle --features parallel-scan,mmap -- --quick
```

Sample results from a 2026-05-28 run on an Apple M5 Pro (macOS 26.5,
APFS on NVMe, Argon2 `MIN`, 500-slot container; `total_500` row is
the same scenario as the fraction sweep):

| Scan mode | frac=0.10 | frac=0.50 | frac=0.90 | Δ (0.90 − 0.10) |
|---|---:|---:|---:|---:|
| Sequential | 17.2 ms | 28.3 ms | 37.3 ms | **≈20 ms** |
| Parallel-scan | 13.0 ms | 28.8 ms | 35.0 ms | **≈22 ms** |
| Mmap | 16.6 ms | 28.0 ms | 36.4 ms | **≈20 ms** |

Per-chunk swing (Δ / total_slots = 500): **≈40 µs/chunk** on this
hardware. The prior pass-15 characterisation on Windows/NVMe
measured ≈75 µs/chunk; the leak's magnitude is hardware-dependent
but the *shape* is uniform across both runs.

**Key finding (audit pass 5 SC-INFO2).** The hypothesis that
parallel-scan's work-stealing would wash out the per-chunk
MAC-fail-vs-pass signal at the aggregate open-time level is
**refuted**. Parallel and sequential leak with the same swing
magnitude (within criterion's noise floor). Mmap is similar. The
TM1 leak does **not** depend on scan-mode choice; opting in to
parallel-scan or mmap for performance does not mitigate the
oracle.

#### Mitigation (shipped 2026-05-28, opt-in — partial; FFI default since Unreleased)

The bounded mitigation is shipped as an opt-in API:
[`Container::open_space_constant_time`](../../../crates/hidden-volume/src/container/mod.rs)
(plus the keys-driven sibling `open_space_with_keys_constant_time`).
**For the FFI surface it is no longer opt-in:** `SpaceHandle::open` /
`open_with_keys` (sync and async) and `MultiSpaceHandle::open_space` route through
the constant-time scan unconditionally (see CHANGELOG `[Unreleased]`), so a host
app built on the FFI — the deniability client — gets the mitigation by default
rather than having to remember to opt in. The direct Rust `Container::open_space`
remains early-exit for callers that prioritise scan speed over the timing oracle.
For each slot the scan runs the real AEAD-decrypt, and on MAC-fail
runs a ChaCha20 stream-equalizer of length `PLAINTEXT_LEN` to
consume CPU time approximately equivalent to the body decrypt of a
successful MAC.

**Honest scope of this mitigation (audit pass 19 follow-through,
2026-05-28).** The equalizer closes the **ChaCha20-body component**
of the per-chunk swing — empirically a single ChaCha20 stream over
4040 bytes is ~1-3 µs on contemporary x86/ARM. The **full per-chunk
swing measured in the bench above is ~40 µs/chunk** on M5 Pro.
The remaining ~37 µs come from work that happens **only on
MAC-pass** and is not equalized: plaintext frame parsing
(`chunk/format.rs::decode_plaintext`), allocation/copy into the
returned `Vec<u8>`, and the `owned_slots.push(slot)` bookkeeping
inside the open loop. The constant-time path *reduces* the
per-chunk distinguisher to roughly the parsing+alloc component
(~order of magnitude smaller than the unmitigated swing), but does
**not** drive it to zero.

A complete closure would require also (a) running a dummy
`decode_plaintext` against a frozen scratch buffer on MAC-fail
and (b) padding `owned_slots.push` cost — neither of which is
shipped today. Tracked as v1.x carried-forward #7 follow-up.

**What this means for a host-app's threat model.**

| Threat model element | Sequential `open_space` | Sequential `open_space_constant_time` |
|---|---|---|
| Per-chunk wall-clock swing | ≈40 µs/chunk (M5 Pro) | ≈order-of-magnitude smaller (parsing+alloc residual only) |
| Aggregate `frac_owned` recovery | ±10-20% from full open-time | greatly diminished but not zero |
| What a process-level observer can still infer | precise `frac_owned` | rough activity envelope (open ran at all + total slot count) |

In short: the equalizer is a meaningful hardening (it closes the
dominant component) but it does NOT make the open-path "constant
time" in the strict crypto sense. Host-apps where the threat
includes a process-monitoring observer who can take many
measurements should additionally pad the post-open processing
externally (e.g., run open inside a fixed-duration `tokio::time::sleep`
window).

**Cost.** Approximately doubles the open-time on garbage-heavy
containers (the equalizer runs for every non-owned chunk). On
sparse, padding-heavy storage this is meaningful (hundreds of ms
on 100-MiB profiles); on dense containers (owned-fraction ≥ 0.9)
it's negligible. Default callers should stick with
`Container::open_space` unless their threat model includes a
process-level timing observer.

**Scope (v1.0, shipped 2026-05-28).** All three scan modes ship
constant-time companions:

- [`Container::open_space_constant_time`](../../../crates/hidden-volume/src/container/mod.rs)
  — sequential (the original mitigation entry).
- [`Container::open_space_parallel_constant_time`](../../../crates/hidden-volume/src/container/mod.rs)
  — parallel-scan + equalizer. Multi-core wall-clock benefits
  combine with the per-chunk timing fix.
- [`Container::open_space_mmap_constant_time`](../../../crates/hidden-volume/src/container/mod.rs)
  — mmap + equalizer. Zero-allocation read path keeps the cold-
  cache speedup; equalizer reuses the same `equalize_timing_via_chacha20`
  primitive on every MAC-fail.

Each companion has a `_with_keys_…` sibling for the cached-keys
path. The residual parsing+alloc swing applies uniformly across
all three (it is the part the equalizer does NOT cover — see the
honest-scope table above). The "constant-time scan" naming is
consistent across the three: callers picking any of them get the
same security property and the same caveats.

**Helper.** The equalizer itself is in
[`crypto::aead::equalize_timing_via_chacha20`](../../../crates/hidden-volume/src/crypto/aead.rs)
— a `pub(crate)` function that runs XChaCha20 over a dummy buffer
of the requested length using a constant key/nonce (operations
are bit-identical regardless of key, so this introduces no side
channel of its own).

**Reproduce locally.** Bench results are hardware-dependent (NVMe
vs SATA vs eMMC vs network FS); a tighter or looser swing is
expected on other platforms. If your threat model includes a
process-level timing observer, run the bench on your target
hardware before relying on the documented magnitude.

## 5. Mitigation summary by code area

A reviewer auditing `src/` should focus on:

| Module | Primary invariants | Audit pass |
|---|---|---|
| `src/crypto/kdf.rs` | D1 (salt randomness), D2 (Argon2 cost ≥ MIN), M1 | CT, MEMORY |
| `src/crypto/aead.rs` | D1, D2 (tag CT), I1, M1 | CT, MEMORY, PLAINTEXT |
| `src/crypto/derive.rs` | D2 (per-space domain separation), M1 | CT, MEMORY |
| `src/chunk/format.rs` | D1 (random padding inside plaintext), I1 | PLAINTEXT |
| `src/container/file.rs` | I2 (fsync), I3 (slot ownership) | FSYNC |
| `src/container/header.rs` | D1 (header layout) | — |
| `src/container/mod.rs` | I3 (cross-space write isolation), C1 | FSYNC |
| `src/space/mod.rs` (commit_tx) | I2 (3-fsync), R1 (commit_seq), C1 | FSYNC |
| `src/space/mod.rs` (vacuum_orphans / vacuum_data_batches) | T2' mitigation (forward-secrecy after delete / overwrite) | MEMORY |
| `src/space/superblock.rs` | I2 (max-seq pick) | — |
| `src/space/index.rs` | I3 (B+ tree per-namespace), R1 (Merkle hash chain) | — |
| `src/space/log.rs` | M1 (zstd raw buffer Zeroizing) | PLAINTEXT |
| `src/open/mod.rs` | D2 (silent skip on AEAD-fail), R1 (commit_history population) | CT |
| `src/cancel.rs` | C1 | — |
| `src/tx/mod.rs` | I3 (Tx slot tracking) | — |
| `src/padding/` | D1 (size obfuscation) | — |
| `src/error.rs` | D2 (AuthFailed unification) | CT |

## 6. Audit history

| Date | Pass | Outcome | Document |
|---|---|---|---|
| v0.5 first pass | Constant-time | No CT issues found in our code. Secret compares all delegate to RustCrypto. | `docs/en/security/audits/constant-time.md` |
| v0.5 first pass | Memory hygiene | Fixed `derive_chunk_key` / `derive_subkey` to return `Zeroizing<[u8; 32]>`. Documented user-data deferral. | `docs/en/security/audits/memory.md` |
| v0.5 first pass | fsync ordering | All 7 fsync sites traced, all barriers in place per `DESIGN.md` §6. macOS `F_FULLFSYNC` quirk documented as host-app concern. | `docs/en/security/audits/fsync.md` |
| v0.5 first pass | Plaintext leak | Wrapped 7 transient pre/post-encryption buffers in `Zeroizing`. Documented user-owned Vec deferral. | `docs/en/security/audits/plaintext.md` |
| 2026-05-09 | Pass 16 (R-STREAMING-REPACK + TM1 + R-FFI-PWD-Z) | `Container::repack` rewritten as streaming pipeline (≈ 4 MiB working set per page, was O(total plaintext)); `MAX_OPEN_SCAN_CHUNKS = 16M` ≈ 64 GiB cap on open-scan; FFI password buffers wrapped in `Zeroizing` on all entry points. | TASKS.md pass-16 section |
| 2026-05-09 | Pass 17 (security/quality follow-through) | New `Error::ContainerTooLarge` variant + symmetric write-side budget gate; `open_space_verified` defers auto-vacuum until verify succeeds; `PaddingPolicy::garbage_after_commit → Result<u64>`; `iter_log_after/before/range` strict on non-8-byte keys; async + CLI password Zeroizing; `PasswordRotation` no longer derives `Clone`; MSRV 1.85 → 1.89. **389 tests pass.** | TASKS.md pass-17 section |
| 2026-05-10 | Pass 18 (second-reviewer follow-through) | M1: `commit_tx` no longer Err after durable commit; M2: `verify_integrity` covers DataBatch chunks; M3: `atomic_rewrite_under_source_lock` race window narrowed via re-open + inode-preservation check; M4: Android lock-skip precondition documented; M5: v3 format-binding requirement specced. | CHANGELOG `[Unreleased]` (pass-18 section) |
| 2026-05-28 | 5-pass deep-review series (adversarial-stance / primitive-level / side-channel-surface / format-fuzzing / threat-model-challenge) | 0 critical / 0 high / 0 medium findings. SC-INFO2 closed by multi-variant TM1 bench (parallel-scan does NOT wash out the signal). F-A5 closed by `MAX_TREE_DEPTH = 3` cap in B+ tree walkers. F-TM1 partially mitigated by opt-in `Container::open_space_constant_time`. | `docs/en/security/audits/*.md` |
| 2026-05-28 | v3 format-bump (#8 + #9 + #10) | #8 kind-tag bytes (0x01 / 0x02) explicit in BLAKE3 inputs; #9 cryptographic version-binding via post-Argon2 BLAKE3; #10 per-space derived `container_id` (closes D1-A2 fingerprint, reclassifies F-PAD to DoS-only). `HEADER_LEN`: 80 → 48. | `docs/en/reference/format.md` §3 |
| 2026-05-28 | **v1.0.0 release** | Format freeze (`format_version = 3`); TM1 CT companions shipped for parallel-scan and mmap (closes the "Sequential-scan only" caveat from §4.4); Android lock hardened — pass-18 M4's documented no-op replaced by a real `flock(2)` via libc so `android:process=":subname"` multi-process races are correctly serialized; cargo-audit became release-blocking (branch CI gate). 401 tests pass. | CHANGELOG `[1.0.0]` |
| v1.0 (planned) | External community review (substitute) | Self-audit dossier published as substitute for paid review (anonymity + no-budget rationale); community researchers welcome via `SECURITY.md` disclosure timeline. | `docs/en/security/audits/self-audit.md` |

## 7. Review request — what we want external review to confirm

For each invariant in §3, the reviewer is asked to confirm or deny:

1. **D1.** Holds the file is indistinguishable from random against
   T1, given the 48-byte cleartext header (salt 32 + Argon2 params
   16; v3 removed cleartext `container_id`). Pay particular
   attention to padding randomness and to potential leaks via
   file-size / chunk-count side channels.
2. **D2.** Holds the password-A holder cannot prove existence /
   non-existence of password-B's space. Look for timing differences
   in `scan_and_recover` between "wrong password" and "no such
   space". Look for accidental information disclosure via error
   variants, panic messages, or debug formatting.
3. **I1, I2, I3.** Holds per-chunk integrity, tail-corruption
   tolerance, and cross-space isolation. Inspect the `commit_tx`
   3-fsync sequence, the ownership tracking in `Tx`, and
   `vacuum_orphans` / `vacuum_data_batches` for cross-namespace
   leakage.
4. **M1.** Holds that key material is zeroized as documented. Look
   for derived keys / cipher state that escape `Zeroizing` wrappers.
5. **R1, C1.** Documented contract is sufficient and correctly
   implemented (host-app rollback detection; cooperative cancel
   without partial-state hazards).

Additionally:

- Format spec in `DESIGN.md` §2-§10 for ambiguity / parser-
  differential bugs.
- Public API surface (`Container`, `Space`, `Tx`, `CancelToken`,
  `SpaceKeys`) for misuse-resistance / footguns.
- Cross-platform `flock` / `pread` semantics; `fsync` reordering
  on macOS.

## 8. Cross-references

- `DESIGN.md` — formal on-disk format and invariants.
- `docs/en/guide/integration.md` — host-app integration narrative.
- `docs/en/guide/multi-device.md` — host-app sync / anchor contract (R1).
- `docs/en/security/audits/constant-time.md` / `docs/en/security/audits/memory.md` /
  `docs/en/security/audits/plaintext.md` / `docs/en/security/audits/fsync.md` — per-pass
  audit notes.
- `docs/en/contributing/benchmarks.md` — performance baseline (not security but informs
  hardware-tuning recommendations in `DESIGN.md` §11.1).
- `tests/` — every invariant above has at least one test directory
  cited in §3.
