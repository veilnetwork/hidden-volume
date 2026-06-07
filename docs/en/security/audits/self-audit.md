# Self-audit dossier

**Last refreshed:** 2026-05-28. **Code reviewed against:** `master`
at commit [`848752a`](https://github.com/veilnetwork/hidden-volume/commit/848752a)
+ the three subsequent local commits (`f67281f`, `53b5720`,
`848752a`). **Reviewer identity:** the maintainer + LLM-assisted
audit passes; **no external paid review has been performed**.

This document is **not** a substitute for an external crypto review by
an established firm. It is a deliberate alternative for a project that
ships a deniable-storage primitive: paying an audit firm under the
maintainer's real-world identity would defeat the project's anonymity
posture, and downstream users of a deniable-storage library should
verify properties from code rather than from a third-party badge
anyway.

Read this document as: *here is what is verified, here is the
evidence, here is how you can independently re-verify it without
trusting the maintainer.*

---

## 1. Why this document exists

`hidden-volume` is the at-rest storage layer of a decentralized
messenger. Its security claims are non-trivial:

- A pre-1.0 cryptographic format whose validity rests on careful
  Argon2id parameter choices, XChaCha20-Poly1305 nonce discipline,
  AAD binding, and an append-only commit protocol.
- A *deniability* invariant — single-snapshot indistinguishability
  from random + compelled-key plausible deniability — that requires
  every code path to avoid leaking which slots belong to which
  password.
- A Rust workspace with one load-bearing `unsafe { transmute }` block
  in `hidden-volume-rt` for the self-referential `OwnedSpace`
  pattern.

A reader has a reasonable question: *"why should I trust that this
holds together?"*

Conventional answer: "an external firm audited it." That answer is
not available here for two reasons stated openly:

1. **No budget.** The maintainer is funding the project without a
   commercial backer; engagements with Trail of Bits / Cure53 / NCC
   start in the tens of thousands USD.
2. **Anonymity.** Paying an audit firm requires invoicing under a
   real-world identity, which deanonymizes the maintainer. For a
   project that ships a *deniability* primitive — where the threat
   model includes nation-state pressure on identifiable parties —
   that's not an acceptable trade.

This dossier is the **process substitute**: a public, code-anchored
record of what is verified, by whom, against what claim, and how a
reader can independently reproduce the verification. The substitute
is weaker than a third-party badge in *reputation*, but it is at
least as strong in *technical content* and *reproducibility*.

---

## 2. What has been done (process)

| Layer | Mechanism | Evidence |
|---|---|---|
| **In-tree audit history** | 18 numbered audit passes (audit pass 1 through pass 18, 2026-05-02 → 2026-05-10) — each with a `Refactoring backlog — pass N` section in [`TASKS.md`](../../../../TASKS.md) listing every finding, severity, and the commit that closed it. | TASKS.md, git log |
| **Topic-specific audits** | Four focused audits with full code refs and conclusions: [constant-time](constant-time.md), [fsync ordering](fsync.md), [memory hygiene](memory.md), [plaintext residency](plaintext.md). | Each file under this directory |
| **Property-level review** | This document — explicit statements of every cryptographic invariant claimed in the threat model, the code that enforces each, what would break it, and how to verify. | §4 of this document |
| **Read-only re-audit (2026-05-28)** | Independent pass against the same code, looking for missed/regressed findings. **0 critical/high/medium**, 7 LOW (all doc-accuracy); all 7 fixed in commits `f67281f` + `53b5720`. | Audit pass commits, [TASKS.md §Refactoring backlog](../../../../TASKS.md) |
| **Reproducible signed builds** | `cosign keyless` signatures on every SemVer-tagged release; no long-lived signing keys exist. | [`.github/workflows/release.yml`](../../../../.github/workflows/release.yml), [`docs/en/contributing/verifying-release.md`](../../contributing/verifying-release.md) |
| **Public threat model** | Explicit T1/T2/T2'/T3 adversary tiers, D1/D2/I1/I2/I3/R1/M1/C1 invariants, out-of-scope mitigations enumerated. | [`docs/en/security/threat-model.md`](../threat-model.md) |
| **Test suite** | 391 tests pass (unit + integration + proptest + crash-recovery + log-pagination + repack + property-full). | `cargo test --workspace` |
| **Fuzz targets** | `container_open` fuzz target plus parser fuzz integration test. | [`crates/hidden-volume/fuzz/`](../../../../crates/hidden-volume/fuzz/), `tests/parser_fuzz.rs` |
| **Pre-tag CI gate** | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo doc -D warnings`, `cargo test`, `cargo audit`, `cargo deny check`, `scripts/dump-public-api.sh --check`. Trigger: `push: tags: ['v*.*.*']` + `workflow_dispatch`. | [`.github/workflows/ci.yml`](../../../../.github/workflows/ci.yml) |
| **Bug bounty (community review)** | No-monetary, credit + coordinated-disclosure timeline. Pseudonymous reports welcomed via GitHub Private Vulnerability Reporting. | [`SECURITY.md`](../../../../SECURITY.md) |

What is **NOT** in this list, deliberately:

- Third-party paid audit
- Liability / insurance backing
- Formal-verification tool runs (KLEE, Tamarin, ProVerif, SAW)
- Side-channel testing on real hardware (power analysis, EM,
  acoustic) — out of scope for a software library

---

## 3. Cryptographic primitive choices

Each primitive picked and the reasoning. Verifiable by reading
[`crates/hidden-volume/src/crypto/`](../../../../crates/hidden-volume/src/crypto/).

| Primitive | Choice | Why | Risk if wrong |
|---|---|---|---|
| **Password-based KDF** | Argon2id, RustCrypto `argon2 = "0.5"` | RFC 9106 (IETF, 2021); Argon2 won the PHC competition; `id` variant resists both side-channel (Argon2i) and TMTO (Argon2d) attacks. | Slower brute-force ⇒ realistic password strength assumption. Default params (`m=64 MiB, t=3, p=1`) hit ~700 ms on mid-range mobile, validated in benches. |
| **Symmetric AEAD** | XChaCha20-Poly1305, RustCrypto `chacha20poly1305 = "0.10"` | 192-bit random nonce (vs ChaCha20-Poly1305's 96-bit) makes nonce collision negligible without per-message counter discipline; constant-time AEAD tag check in RustCrypto. | Nonce reuse = catastrophic key recovery. The 192-bit space makes random-nonce safe for ~10²⁰ chunks; we cap container at 16M chunks (~64 GiB) for unrelated DoS reasons. |
| **Version-bind step (v3 #9)** | `versioned_master = BLAKE3-keyed(argon_out, b"hv/v3/master" \|\| u32_le(params.version))` | Folds the full `params.version` u32 (format_version + padding_policy_index + reserved) into the master key. **Closes the v2 lock-down requirement** flagged in [`make_aad`](../../../../crates/hidden-volume/src/crypto/aead.rs) rustdoc — cross-version key reuse is now closed cryptographically, not only by policy. | Any future v4 reader that loosens `validate` would still derive a different `master_key` (different label `b"hv/v4/master"`), preserving cross-version reject. |
| **KDF→AEAD root + per-space container_id (v3 #8 + #10)** | `aead_root = BLAKE3-keyed(versioned_master, [0x01] \|\| b"hv/v3/aead_root")`; `container_id = BLAKE3-keyed(versioned_master, [0x01] \|\| b"hv/v3/container_id")` | BLAKE3-keyed is constant-time, parallelizable, modern (2020); keyed mode = strong domain separation. Kind-tag byte `0x01` (`SUBKEY_KIND_TAG`) prefixed to the context label is the v3 #8 explicit-domain-separation step — replaces the v2 length-distinguishes convention (audit pass 7 D3). v3 #10 derives `container_id` per-space rather than reading it from the cleartext header, closing the D1-A2 fingerprint signature. | Different label per subkey purpose → no cross-purpose key reuse. Convention codified in [`derive.rs`](../../../../crates/hidden-volume/src/crypto/derive.rs). |
| **Per-slot AEAD key (v3 #8 kind-tag 0x02)** | `chunk_key(slot) = BLAKE3-keyed(aead_root, [0x02] \|\| container_id \|\| u64_le(slot))` — see [`derive_chunk_key`](../../../../crates/hidden-volume/src/crypto/derive.rs) | Binds the slot index into the key, defeating slot-shuffle attacks on top of AAD binding. Kind-tag byte `0x02` (`CHUNK_KEY_KIND_TAG`) distinguishes this input from subkey inputs (kind-tag `0x01`). | If multiple slots shared a key, slot-shuffle would be a one-byte swap attack on ciphertext. |
| **AAD** | `container_id (32) ‖ slot (8 LE)` — see [`make_aad`](../../../../crates/hidden-volume/src/crypto/aead.rs). **v3 strengthening:** `container_id` is now per-space derived, so different spaces inside the same container have different AAD prefixes. | Binds chunks to *this space within this container* (defeats cross-container AND cross-space chunk relocation) and to *this* slot. | Missing AAD binding = chunks portable across containers/slots. |
| **RNG** | OS CSPRNG via `getrandom` crate | Standard for cryptographic randomness; same source for nonces, salts, padding, temp filenames. (v3 #10 removed `container_id` from the RNG-fed cleartext fields — it is now derived, not random per container.) | Any non-CSPRNG path = nonce predictability ⇒ catastrophic. No seeded/test RNG in production. Verified by grep — only one funnel in [`crypto/rng.rs`](../../../../crates/hidden-volume/src/crypto/rng.rs). |
| **Merkle tree hash** | BLAKE3 unkeyed for IndexNode payload hashes (cross-Tx integrity links). | Unkeyed is correct here — these hashes are *public commitments* readable from the encrypted chunk's plaintext under the key; their role is integrity, not secrecy. | A non-collision-resistant hash here would let a key-holder produce inconsistent index trees that pass `verify_integrity`. BLAKE3 = 256-bit collision resistance. |

**v2 lock-down question — closed in v3 (2026-05-28).** Pre-v3, the
format `version` was bound only by policy (`Argon2Params::validate`
rejecting unknown `format_version`) rather than by cryptography. v3
#9 closes this: `derive_master_key` now folds `params.version` into
the master via a BLAKE3-keyed step before any subkey is derived.
The lock-down comment that lived in [`make_aad`](../../../../crates/hidden-volume/src/crypto/aead.rs)
rustdoc is now historical — cross-version key reuse is closed
**doubly** (policy + crypto).

---

## 4. Security invariants — claims, enforcement, and how to verify

Each invariant is claimed in [threat-model.md](../threat-model.md). For
each, the *code* that enforces it, the *adversary* against which it
holds, and a *test* you can run yourself.

### D1 — Single-snapshot indistinguishability

**Claim:** A T1 adversary holding one snapshot of the container file
cannot distinguish it from uniform random of the same length, save for
the 48-byte structured cleartext header (`salt (32) ‖ Argon2Params (16)`);
the rest of the first chunk (bytes 48..4096) is uniform random padding
indistinguishable from data chunks. **v3 #10** removed the cleartext
`container_id` field (now per-space derived inside `SpaceKeys::from_master`).

**Enforcement:**
- File-level: every chunk is `nonce (24) ‖ AEAD ciphertext + tag`,
  with nonce drawn from `getrandom` per chunk ([`Space::append_chunk`](../../../../crates/hidden-volume/src/space/mod.rs)).
  XChaCha20 keystream is computationally indistinguishable from
  random under the standard ChaCha20 assumption.
- Header-level: `Argon2Params` (16 bytes) is the only structured byte
  range. Reserved bits zeroed and validated ([`Argon2Params::validate`](../../../../crates/hidden-volume/src/crypto/kdf.rs)).
  Padding-policy byte is acknowledged-cleartext (F-PAD §4.1, accepted
  scope).
- Garbage chunks: indistinguishable from real chunks. They are
  uniform random bytes written via the same `append_slot` path
  ([`ContainerFile::append_garbage_chunks`](../../../../crates/hidden-volume/src/container/file.rs)).

**Adversary against:** T1 (single-snapshot passive). Defends.

**Adversary AGAINST WHICH IT DOES NOT HOLD:** T2' (multi-snapshot
byte-diff over time). Documented out-of-scope in threat-model §4.

**Verify yourself:**
1. Read the threat-model §3.D1 statement.
2. Grep for every `append_*` and `write` call in
   [`crates/hidden-volume/src/container/`](../../../../crates/hidden-volume/src/container/).
   Confirm every non-header byte is one of: AEAD output, raw
   `getrandom` bytes (scrub or garbage), or the random nonce. No
   plaintext structure leaks.
3. Run `cargo test -p hidden-volume --test property_full` — includes a
   randomness statistical test on a fresh container.

### D2 — Compelled-key plausible deniability

**Claim:** A T3 adversary who extracts password `P` for space `S_A`
gets enough to decrypt `S_A`'s chunks but **cannot** prove (or even
detect) the existence of another space `S_B` whose chunks coexist in
the same file.

**Enforcement:**
- Per-slot AEAD-decrypt with `S_A`'s key on `S_B`'s chunks fails with
  `AuthFailed`. Failed decrypts are *unobservable to the caller* —
  the discovery scan skips silently (`.ok()?` pattern at
  [`open/mod.rs::try_decrypt`](../../../../crates/hidden-volume/src/open/mod.rs)).
- `Error::AuthFailed` is a single variant that maps both "wrong
  password / no such space" AND "this specific chunk is not ours" to
  the same external observation ([`error.rs`](../../../../crates/hidden-volume/src/error.rs)).
- AEAD tag check is constant-time (RustCrypto invariant).

**Adversary against:** T3 (compelled-key for one space). Defends.

**Adversary AGAINST WHICH IT DOES NOT HOLD:**
- T2' (multi-snapshot): writer-active signals (size growth at commit
  time) reveal that *something* changed. Defends *which space* the
  change belongs to, but not *that activity occurred*.
- TM1 (open-time timing oracle): a passive observer of one open
  measures roughly the owned-fraction of the container (±10-20%);
  doesn't reveal which slots, but reveals approximate sparsity. See
  [threat-model F-TM1](../threat-model.md).

**Verify yourself:**
1. Run `cargo test --test multi_device -- deny_test` (cross-space
   isolation tests).
2. Run `cargo bench --bench timing_oracle -- --quick` and observe
   the magnitude of the leak personally.
3. Construct two passwords for the same file, write differently with
   each, and confirm `Container::open_space` with `S_B`'s password
   on a `S_A`-written file returns the same error/timing as on a
   garbage file.

### I1 — Per-chunk integrity

**Claim:** Any single-bit flip in a chunk's ciphertext, nonce, or
AAD-bound metadata surfaces as `AuthFailed` (during discovery scan)
or `IntegrityFailure` (during explicit `verify_integrity`).

**Enforcement:**
- ChaCha20-Poly1305 with 16-byte tag — Poly1305 MAC over (AAD ‖
  ciphertext) makes any modification detectable with overwhelming
  probability (2⁻¹⁰⁰).
- AAD = `container_id ‖ slot_le` — slot-shuffle is detected because
  decrypt under a different slot's AAD fails.
- [`Space::verify_integrity`](../../../../crates/hidden-volume/src/space/integrity.rs)
  walks the Merkle hash chain (Superblock → CommitPayload →
  IndexNode tree → DataBatch leaves) and re-hashes every chunk's
  plaintext, comparing against the parent's recorded hash. Hash
  mismatch ⇒ `IntegrityFailure { detail, slot }`.

**Verify yourself:** `tests/integrity.rs` exercises mutation at every
layer; `cargo test --test integrity` confirms 0 failures.

### I2 — Tail-corruption tolerance

**Claim:** A partial write at the file tail (crash mid-fsync, truncation,
ENOSPC) does not roll back commits already made durable by an earlier
Superblock.

**Enforcement:**
- 3-fsync commit protocol: data → CommitPayload → Superblock. The
  Superblock is published last; recovery picks the highest-seq
  Superblock that decrypts under our key
  ([`open/mod.rs::scan_and_recover`](../../../../crates/hidden-volume/src/open/mod.rs)).
- Multi-replica Superblock (configurable, default 3): a partial write
  that wipes one replica still leaves the others.
- `Argon2Params::validate` defends against tampered headers that
  would force a bogus-but-AEAD-valid Superblock.

**Verify yourself:** `tests/crash_recovery.rs` and `tests/crash_proptest.rs`
exercise crash-injection at every byte boundary of the commit path.

### I3 — Cross-space isolation

**Claim:** A space's chunks cannot be moved into a different space (or
into a different container) and decrypt successfully under the target's
key.

**Enforcement:**
- AAD binds `container_id` (32 bytes; in v3 this is per-space
  *derived* from the versioned master key — different spaces in the
  same container have different `container_id`s, and different
  containers have different `container_salt`s ⇒ different
  `master_key`s ⇒ different `container_id`s).
- Per-slot key derives from `aead_root` AND `container_id` AND
  slot, so even a hypothetical key-graft attack fails: relocation
  to a different space or container produces a key the chunks
  were not sealed under.
- Verified by [`tests/tx_multi.rs`](../../../../crates/hidden-volume/tests/tx_multi.rs)
  and (v3) [`tests/v3_key_schedule.rs`](../../../../crates/hidden-volume/tests/v3_key_schedule.rs).

### R1 — Rollback / fork-detection (host-app cooperative)

**Claim:** A host-app that stores an external anchor (the latest
`commit_seq` it observed) can detect a file-level rollback by
re-checking `Space::commit_seq()` on next open.

**Enforcement:** [`Space::commit_seq`](../../../../crates/hidden-volume/src/space/mod.rs)
+ [`commit_history`](../../../../crates/hidden-volume/src/space/mod.rs) +
the per-Superblock-replica decryption pattern.

**This is NOT an adversary defense by the library alone.** It requires
host-app cooperation per [`docs/en/guide/multi-device.md`](../../guide/multi-device.md).
The library exposes the primitives; the host-app must store and check
the anchor.

### M1 — Memory hygiene of key material

**Claim:** Decrypted plaintext and key material is scrubbed from
heap/stack before the corresponding memory can be reused.

**Enforcement:** Audited end-to-end in [`audits/memory.md`](memory.md)
and [`audits/plaintext.md`](plaintext.md). Every AEAD output buffer,
plaintext encode buffer, decompressed batch, and password copy is
wrapped in `zeroize::Zeroizing`. Master/subkeys derive `ZeroizeOnDrop`.

**Caveat (acknowledged):** Under `panic = "abort"` (release profile),
destructors do not run on panic — the OS process teardown is the
scrub. Documented in
[`ffi/lib.rs` SpaceHandle::create](../../../../crates/hidden-volume-ffi/src/lib.rs)
and [`docs/en/reference/ffi.md` §Password buffer hygiene](../../reference/ffi.md).

### C1 — Cancellation safety

**Claim:** Cancellation tokens checked at the documented checkpoints
do not leave the container in an inconsistent on-disk state.

**Enforcement:** [`audits/fsync.md`](fsync.md) audits every cancel-
between-write-and-fsync window. The 3-fsync barrier ensures any
cancellation during commit either rolls forward (Superblock written)
or rolls back (Superblock not yet written, recovery picks prior
seq).

---

## 5. Open items + acknowledged gaps

These are **known** and **documented**; they are not bugs.

| Item | What | Why open | Where documented |
|---|---|---|---|
| **TM1** | Open-scan timing oracle leaks ~owned-fraction to a process-watching observer | **Partially mitigated 2026-05-28**: opt-in `Container::open_space_constant_time` runs ChaCha20-equalizer on MAC-fail, closing the ChaCha20-body component (~1-3 µs of the ~40 µs/chunk swing). Parsing/alloc residual remains; full closure tracked as v1.x #7 follow-up. | [threat-model F-TM1 §4.4](../threat-model.md) |
| **F-PAD** | (v2) Padding-policy byte in the cleartext header was unauthenticated, allowing silent privacy degradation by a T2 adversary | **Reclassified to DoS-class in v3** (2026-05-28). The v3 cryptographic version-binding step (#9) folds the full `params.version` u32 (including `padding_policy_index`) into `master_key`. Tamper now causes `AuthFailed`, not silent degradation. The DoS surface remains acceptable (any cleartext-header tamper can deny open). | [threat-model F-PAD §4.1](../threat-model.md) |
| **R-LOG-INDEX-3L** | 2-level B+ tree caps a Log namespace at ~10-20K unique log_ids | Caller-side partitioning is the current recommendation; 3-level tree would push to ~1.5M. Decision deferred to first integrator hitting the cap. | [`docs/en/guide/integration.md`](../../guide/integration.md) §13 |
| **Cycle detection in non-verify walkers** | `collect_leaves`, `count_leaves`, `iter_log_*`, `vacuum_orphans` recurse on writer-produced trees without visited-set | Writer-side invariant guarantees depth ≤ 2. Adversarial cycle requires key-holder threat (out-of-scope). `verify_integrity` is cycle-resistant by Merkle hash binding. | This dossier |
| **Format v1 final freeze** | Pre-1.0 status; format may break in v0.x → v0.y bumps | Gated on "ready to commit forever"; tied to external community review. | [`docs/en/reference/semver.md`](../../reference/semver.md) |

---

## 6. What's out of scope (be honest)

The library does **not** defend against:

- **Multi-snapshot byte-diff over time** (T2'). In-place rewrites and
  tombstones leave "this byte changed" signals. Documented accepted
  trade-off — see threat-model §2 + §4.
- **Rollback attacks without an external anchor.** Requires host-app
  cooperation per [`docs/en/guide/multi-device.md`](../../guide/multi-device.md).
- **Application-layer side channels.** Recently-opened files,
  thumbnails, IME caches, swap pages, system logs — all OS-level
  host-app responsibility.
- **CPU-level side channels.** Spectre, MDS, Foreshadow — defended by
  OS/microcode.
- **Forensic RAM dumps.** Defended by full-disk encryption + secure
  boot at the host level.
- **NFS / FUSE / network filesystems** that ignore or weaken `flock(2)`.
- **Android multi-process write** without explicit application-layer
  serialization (the per-app UID sandbox is the assumed isolation
  boundary; the in-process `Mutex` enforces within-process single-
  writer).
- **Container parent directory writable by an attacker UID.** The
  `atomic_rewrite_under_source_lock` primitive raises the cost of a
  TOCTOU substitution but cannot fully close it on a hostile parent.

---

## 7. How to verify the project's claims yourself

The project is designed for *reader verification*, not *reader trust*.
Concrete checks:

### 7.1 Cryptographic-property checks

```sh
# 1. Confirm the AEAD primitive choice and that nonces come from getrandom
grep -rn "ChaCha20Poly1305\|XChaCha20\|getrandom" crates/hidden-volume/src/crypto/

# 2. Confirm AAD binds container_id + slot
grep -rn "make_aad\|AAD_LEN" crates/hidden-volume/src/crypto/

# 3. Confirm KDF parameters validate
sed -n '/fn validate/,/^    }/p' crates/hidden-volume/src/crypto/kdf.rs

# 4. Run the full test suite — 391 tests cover the invariants above
cargo test --workspace --all-features --no-fail-fast
```

### 7.2 Build verification

```sh
# Reproduce the release-build matrix locally for your platform:
cargo build -p hidden-volume --release --features cli --target $(rustc -vV | awk '/host:/{print $2}')

# Compare your local SHA256 to the published SHA256SUMS:
sha256sum target/$(rustc -vV | awk '/host:/{print $2}')/release/hv
```

### 7.3 Signed-release verification

See [`docs/en/contributing/verifying-release.md`](../../contributing/verifying-release.md).
TL;DR — every SemVer tag publishes a `SHA256SUMS` signed by the
release workflow's GitHub Actions OIDC identity via cosign keyless;
the signature is in the Sigstore Rekor transparency log.

### 7.4 Independent audit replay

This document and the per-pass entries in [`TASKS.md`](../../../../TASKS.md)
list every finding with code references. Anyone can re-walk the same
diffs and confirm the closure.

### 7.5 Format-spec verification

[`docs/en/reference/format.md`](../../reference/format.md) is the
authoritative byte-layout. The Rust source must be consistent with it.
To check: implement a minimal independent parser in another language
against `format.md`, point it at a small test container, confirm
matching field interpretations.

---

## 8. Community review (bug bounty without money)

See [`SECURITY.md`](../../../../SECURITY.md) for the standing offer.
Brief:

- **In scope:** vulnerabilities that violate D1, D2, I1, I2, I3, R1,
  M1, or C1; any panic-via-input across the public API; any memory-
  safety issue in the `unsafe` blocks.
- **Reward:** credit (in CHANGELOG + SECURITY.md hall of fame) +
  early access to the fix. **No monetary reward** — budget reality.
  Reporters are welcome to remain pseudonymous.
- **Disclosure:** coordinated, 90-day default, fast-track for
  critical findings.
- **Channel:** GitHub Private Vulnerability Reporting (preferred) or
  the email listed in `SECURITY.md`.

---

## 9. Roadmap for additional review

In order of expected cost-effectiveness:

1. **Anonymous academic preprint** (free, pseudonymous) — submit
   threat-model + format spec to IACR ePrint (`cs.CR`). Forces a
   pass through real cryptographers' habits of mind via citations.
2. **Community-eyes posts** to `/r/crypto`, lobste.rs, modern-crypto
   mailing list, with explicit "please challenge X" framing.
3. **Cross-link with peer projects** (VeraCrypt, age, rage,
   tomb) — ask maintainers for review trades.
4. **Optional v1.x mitigations** — status after the 2026-05-28 work:
   - TM1 constant-time AEAD path — **shipped** as opt-in
     `Container::open_space_constant_time` (partial closure: ChaCha20-body
     component equalized; parsing/alloc residual remains, see threat-model
     F-TM1 §4.4 honest-scope table).
   - **v3 format with cryptographic version-binding — shipped**
     (`derive_master_key` BLAKE3 step folds `params.version` into master).
   - **Per-space derived `container_id` (#10) — shipped** (closes D1-A2).
   - **Kind-tag bytes in BLAKE3 inputs (#8) — shipped** (explicit
     `0x01`/`0x02` domain separation, no length-distinguishes convention).
   - 3-level B+ tree (R-LOG-INDEX-3L) when first integrator needs it.
5. **If a security researcher engages with the project** (via bug
   bounty or community), their public report becomes the external
   review by virtue of being public + technical + signed.

---

## 10. Document history

| Date | Change | Reviewer |
|---|---|---|
| 2026-05-28 | Initial dossier. Covers audit passes 1-18 + pass-19 read-only audit. | Maintainer + LLM-assisted |
| 2026-05-28 | v3 actualization — primitives table updated for #8/#9/#10; F-PAD reclassified to DoS-only; TM1 mitigation marked partial-shipped; D1 statement updated for 48-byte header; v1.x mitigation roadmap status updated. | Maintainer + LLM-assisted |
