# Primitive-level review

**Date.** 2026-05-28. **Pass.** 2 of 5 in the deeper-review series.
**Reviewer.** LLM-assisted, instructed to *challenge the primitives
themselves* rather than the construction built on them, against
state-of-the-art literature current as of 2026.

## Methodology

Where the [adversarial-stance pass](adversarial-stance.md) treated
Argon2id / XChaCha20-Poly1305 / BLAKE3 / `getrandom` as trustworthy
black boxes and challenged the *construction* above them, this pass
inverts: it accepts the construction as given and asks "are these
the *right primitives*, and are they parametrised the way 2026
cryptographic literature recommends?"

References consulted:

- **OWASP Password Storage Cheat Sheet** (2024-edition recommendations
  for Argon2id parameters)
- **IETF RFC 9106** — Argon2 specification (PHC winner, IRTF CFRG)
- **IETF RFC 8439** — ChaCha20-Poly1305 (the base AEAD)
- **IETF RFC 7539-bis** — XChaCha20 extended-nonce construction
  (Bernstein, status: widely deployed but pre-final-RFC; libsodium
  reference implementation since 1.0.12)
- **NIST SP 800-63B-rev4** (Authenticator and Verifier Requirements)
- **BLAKE3 specification** (Aumasson, O'Connor, Neves, Wilcox-O'Hearn,
  2020) and follow-up cryptanalysis through 2025
- **RustCrypto** crate set: published vulnerability advisories +
  open-issue tracker reviewed as of 2026-05-28
- **CFRG draft-irtf-cfrg-aegis-aead-12** — AEGIS-256 (an alternative
  AEAD that's CFRG-final as of late 2024; we compare to it)

For each primitive choice I record:

- **What is used** and **where**.
- **2026 state of the art** for that role.
- **Match / gap.**
- **If a gap exists**: severity, exploitability, recommended action.

Severity legend matches [adversarial-stance §"Headline"](adversarial-stance.md):
CRITICAL / HIGH / MEDIUM / LOW / INFO.

## Headline

**0 CRITICAL / 0 HIGH / 0 MEDIUM, 2 LOW, 3 INFO observations.** The
primitive choices are sound and conservative. Two findings worth
recording:

- **P-LOW1.** `Argon2Params::MIN` sets `m_cost_kib = 8 MiB`, which
  is **below the OWASP 2023 low-end recommendation of 12 MiB**.
  Intentional accessibility trade-off (low-end embedded / mobile)
  documented in the constant; should be flagged explicitly in
  `Argon2Params::MIN`'s rustdoc so a future maintainer can't
  raise the floor without realising the rationale.
- **P-LOW2.** `derive_subkey` domain-separation convention relies
  on the **label byte-length** differing from `derive_chunk_key`'s
  40-byte input. This is a fragile invariant (no type-system
  enforcement; relies on documented convention). A length-prefix
  or a leading kind-tag byte would make the separation explicit.
  Not a current bug — the only `derive_subkey` callers respect
  the convention — but a defense-in-depth opportunity (audit D3
  closure assumes the convention holds in future code too).

The 3 INFO observations are positions where the choice is sound but
worth noting for future maintainers / migration planners
(post-quantum, AEAD alternative landscape, label hardening).

## Per-primitive review

### 1. Password KDF — Argon2id (RustCrypto `argon2 = "0.5"`)

**Where.** [`crates/hidden-volume/src/crypto/kdf.rs`](../../../../crates/hidden-volume/src/crypto/kdf.rs)
`derive_master_key`.

**2026 state of the art.** Argon2id remains the IRTF / OWASP /
NIST recommendation for password-based KDFs:

- IRTF RFC 9106 (2021) — Argon2id is the recommended variant.
- OWASP Password Storage Cheat Sheet (2024):
  - Mainline: `m=19 MiB, t=2, p=1` minimum.
  - "Low-resource devices": `m=12 MiB, t=3, p=1` minimum.
  - No formal upper bound; `m=1 GiB` is the "no RAM constraint"
    recommendation.
- NIST SP 800-63B-rev4 §5.1.1.2: "memory-hard functions such as
  Argon2 SHOULD be used".

**Match.**

| Constant | Value | OWASP comparison | Verdict |
|---|---|---|---|
| `Argon2Params::DEFAULT.m_cost_kib` | 64 MiB | 3.4× OWASP mainline (19 MiB) | ✓ above recommendation |
| `Argon2Params::DEFAULT.t_cost` | 3 | = OWASP low-end | ✓ at recommendation |
| `Argon2Params::DEFAULT.p_cost` | 1 | = OWASP | ✓ at recommendation |
| `Argon2Params::MIN.m_cost_kib` | **8 MiB** | **below OWASP low-end (12 MiB)** | ⚠ **P-LOW1** |
| `Argon2Params::MIN.t_cost` | 2 | = OWASP mainline | ✓ |
| `Argon2Params::MIN.p_cost` | 1 | = OWASP | ✓ |
| `Argon2Params::MAX.m_cost_kib` | 1 GiB | = OWASP "no constraint" | ✓ |
| `Argon2Params::MAX.t_cost` | 100 | well above OWASP | ✓ |
| `Argon2Params::MAX.p_cost` | 64 | well above OWASP | ✓ |

**P-LOW1 — Argon2Params::MIN m_cost below OWASP low-end.**

The 8 MiB floor exists so the library can run on *very* memory-
constrained devices (low-end IoT, tiny embedded). The DEFAULT is
8× the floor (64 MiB) and is what host-apps actually use; the floor
is the validation gate that rejects tampered headers below this
value.

The attacker scenarios:

1. **Header-tamper to MIN to weaken brute-force.** Already analysed
   in [adversarial-stance D1-A5](adversarial-stance.md): doesn't
   work because the legitimate user's open then derives a *different*
   master_key, hits AuthFailed, never opens the file. The captured
   file's chunks are still sealed under the ORIGINAL params, so
   offline brute-force isn't speeded up.
2. **Legitimate host-app explicitly chooses MIN.** A user on a
   1 MiB-RAM embedded device might genuinely need this. The
   resulting key derivation runs in ~10ms (vs ~700ms for DEFAULT),
   which speeds up offline brute-force by ~70×. That's a real
   strength reduction, deliberately accepted by that host-app.

So the floor is not exploitable by attackers; it's a *user-chosen
weakness* for resource-constrained deployments.

**Recommendation (proposed for v1.x).** Add a `#![doc]` warning on
`Argon2Params::MIN` calling out that:

- It is below OWASP 2024's low-end recommendation (12 MiB).
- It exists for very-low-end embedded use; **mobile host-apps
  should use DEFAULT (64 MiB)**, not MIN.
- The reduction in brute-force resistance is ~70× compared to
  DEFAULT.

This is a doc change (not a constant change), since lifting the
floor would break low-end host-apps.

### 2. Symmetric AEAD — XChaCha20-Poly1305 (RustCrypto `chacha20poly1305 = "0.10"`)

**Where.** [`crates/hidden-volume/src/crypto/aead.rs`](../../../../crates/hidden-volume/src/crypto/aead.rs)
`ChunkAead::{new, seal, open}`.

**2026 state of the art.**

- **ChaCha20-Poly1305 (RFC 8439, 2018):** IETF-standardised, widely
  deployed (TLS 1.3, WireGuard, age, libsodium, Signal). 96-bit
  nonce, so random-nonce safe only for ~2³² messages per key.
- **XChaCha20-Poly1305 (Bernstein draft, libsodium 1.0.12+):** same
  cipher with HChaCha20 nonce-extension to 192-bit. Random-nonce
  safe for ~2⁹⁶ messages.
- **AEGIS-256 (CFRG, draft-irtf-cfrg-aegis-aead-12, final late
  2024):** AES-based, hardware-accelerated on platforms with AES
  instructions. ~2× faster than ChaCha20 on x86_64-with-AES-NI,
  but ~3× slower on ARM-without-crypto-extensions (mobile).
- **AES-GCM-SIV (RFC 8452):** misuse-resistant against nonce reuse
  (nonce reuse leaks at most equality of plaintexts, not the
  plaintexts themselves). 96-bit nonce. Performs well only with
  hardware AES.

**Match.** XChaCha20-Poly1305 is the **correct conservative choice**
for this project:

- Deniable storage runs on diverse hardware including ARMv7 mobile
  without AES extensions; ChaCha20 is software-uniform there.
- 192-bit random nonce eliminates the need for per-message counter
  discipline; collision risk is negligible at 16M chunks (the
  open-scan budget cap = 16 × 1024 × 1024 ≈ 2²⁴ messages, far
  below the 2⁹⁶ collision frontier).
- Constant-time tag check is a RustCrypto invariant; the AEAD
  primitive cannot leak the tag content via timing.

**Gap.** None functional. AEGIS-256 *might* offer better
performance on x86_64-with-AES, but the deniability-storage use
case is dominated by Argon2 (~700ms) rather than per-chunk AEAD
(~µs), so the savings would be invisible.

**Verdict.** ✓ Sound. INFO observation: as AEGIS-256 matures and
sees deployment, consider it for a v3-format-bump for x86-heavy
deployments — but XChaCha20 is the right pick for now.

### 3. Cryptographic hash — BLAKE3 (`blake3 = "1.x"`)

**Where.**
- `derive_subkey(parent, label)` — BLAKE3-keyed for key
  derivation chain ([`crypto/derive.rs`](../../../../crates/hidden-volume/src/crypto/derive.rs)).
- `derive_chunk_key(aead_root, container_id, slot)` — BLAKE3-
  keyed for per-slot AEAD key.
- IndexNode payload hashes / `tx_root_hash` in `CommitPayload` —
  BLAKE3 unkeyed for Merkle integrity links
  ([`tx/commit.rs::blake3_of`](../../../../crates/hidden-volume/src/tx/commit.rs)).

**2026 state of the art.**

- BLAKE3 (Aumasson, O'Connor, Neves, Wilcox-O'Hearn, 2020): 256-bit
  collision resistance, 256-bit preimage, constant-time,
  parallelizable, XOF mode. No cryptanalysis weakening it through
  2025.
- BLAKE2b (RFC 7693, 2015): predecessor, also sound, slightly
  slower.
- SHA-3 / Keccak (FIPS 202): NIST standard, sound, slower than
  BLAKE3.
- KangarooTwelve (Bertoni, Daemen, Peeters, Van Assche, 2018):
  Keccak-derived XOF with explicit parallelism. Faster than SHA-3,
  slower than BLAKE3 in benchmarks.

**Match.** BLAKE3 is **modern and sound**. The keyed mode
(`BLAKE3-keyed(key, msg) = BLAKE3 with key as the chaining input`)
is a proper PRF for fixed-length keys. The unkeyed mode for Merkle
hashes is correct (these are public commitments, not secrets).

**Verdict.** ✓ Sound.

### 4. Subkey derivation — BLAKE3-keyed of label

**Where.** `derive_subkey(parent: &[u8; 32], label: &[u8]) -> [u8; 32]`
in [`crypto/derive.rs`](../../../../crates/hidden-volume/src/crypto/derive.rs).

Implementation: `BLAKE3-keyed(parent, label) → 32 bytes`.

Functionally equivalent to HKDF-Expand(parent, info=label, L=32).
The HKDF-Extract step is unnecessary because `parent` is already
uniform (output of a prior BLAKE3 derivation in the chain).

**2026 state of the art.**

- HKDF (RFC 5869): the canonical KDF chain — `HKDF-Extract(salt,
  IKM) -> PRK; HKDF-Expand(PRK, info, L) -> OKM`.
- BLAKE3 keyed mode functions as Expand-only.

**Match.** Mathematically equivalent in security. Style choice.
Documented as such in `derive_subkey`'s rustdoc.

**P-LOW2 — domain-separation convention is label-length-based.**

The audit-pass-1 D3 closure documented that
`derive_chunk_key(aead_root, container_id, slot)`'s 40-byte input
is the **domain-separation discriminator** from
`derive_subkey(aead_root, "hv/v1/space/...")`'s 16-byte label.
That is, the *length* of the input distinguishes "chunk-key
derivation" from "subkey derivation".

This convention is **fragile**:

- Nothing in the type system enforces it.
- A future `derive_subkey(aead_root, b"hv/v2/some-40-byte-context-string-here!!!")`
  call could accidentally collide with a chunk-key derivation.
- The convention is documented but not enforced by code review
  tooling.

**Recommendation (proposed for v1.x).** One of:

(a) Prefix every `derive_subkey` label with a length-prefix byte:
    `BLAKE3-keyed(parent, len(label) ‖ label)` — makes the input
    self-describing and prevents length-collision with any
    chunk-key input.
(b) Add a leading kind-tag byte to both `derive_chunk_key` and
    `derive_subkey`:
    - `derive_chunk_key`: `0x01 ‖ container_id ‖ slot_le_u64` (41
      bytes).
    - `derive_subkey`: `0x02 ‖ label` (1 + label.len()).
    Makes the distinction explicit by content, not by length.

Either is a format-version-bump-class change (it changes key
derivation, so v1/v2 containers wouldn't reopen with the new
scheme without backward-compat handling). Tracked alongside the
v3 cryptographic-version-binding lock-down from the dossier §3.

**Update (2026-05-28, shipped in v3 commit `8722fa1`).** Option
(b) was selected and shipped, with the **kind tags swapped vs the
original proposal**: `derive_subkey` carries `SUBKEY_KIND_TAG = 0x01`
and `derive_chunk_key` carries `CHUNK_KEY_KIND_TAG = 0x02` (see
[`crates/hidden-volume/src/crypto/derive.rs`](../../../../crates/hidden-volume/src/crypto/derive.rs)).
The flip is harmless — both ordering choices give equivalent
domain separation. P-LOW2 now **closed**.

**Verdict.** ✓ Sound today, **✓ closed v3 (2026-05-28)** — the
fragile convention was replaced by explicit kind-tag bytes.

### 5. AAD — container_id ‖ slot_le_u64

**Where.** [`make_aad`](../../../../crates/hidden-volume/src/crypto/aead.rs)
returns the 40-byte AAD.

**2026 state of the art.** AAD should bind every contextual fact
that an adversary could attempt to vary without changing the
ciphertext bytes — exactly the "swap a chunk between contexts"
attacks I tested in [adversarial-stance I1-A2/I1-A3](adversarial-stance.md).

**Match.** The two facts that AAD must bind are present:

- `container_id` (32 bytes) — defeats cross-container chunk move.
- `slot` (8 bytes LE) — defeats slot-shuffle within container.

**What's NOT in AAD, deliberately:**

- **format_version**: closed by policy (`validate()` rejects
  unknown version). Acknowledged limitation; v3 lock-down
  required (documented in dossier §3).
- **commit_seq**: covered by superblock's own AEAD + Merkle
  chain. AAD-binding seq into every chunk would require
  re-encrypting on every commit (the chunk is shared between
  commits if no change). Correctly omitted.
- **kind / namespace**: covered by the encrypted plaintext header
  byte. AAD-binding kind would mean an adversary swapping a
  chunk's kind (e.g., relabel IndexNode as DataBatch) would fail
  AEAD — but the plaintext-side kind check after decrypt catches
  this anyway. Defense-in-depth would be marginal.

**Verdict.** ✓ Sound for the stated invariants (D1-A2, I1, I3).
v3 should add format_version per the lock-down requirement.

### 6. Random number generation — `getrandom` crate

**Where.** [`crypto/rng.rs`](../../../../crates/hidden-volume/src/crypto/rng.rs)
is the sole CSPRNG funnel. Used for:

- 32-byte salt at container create
- 32-byte container_id at container create
- 24-byte XChaCha20 nonce per AEAD seal
- 8-byte temp filename randomness for atomic_rewrite
- N-byte garbage padding chunks

**2026 state of the art.** `getrandom` calls the OS CSPRNG:
- Linux: `getrandom(2)` syscall (since 3.17) — pulls from `/dev/urandom`
  pool seeded by hardware/kernel entropy.
- macOS / iOS: `SecRandomCopyBytes` (Apple CryptoKit).
- Windows: `BCryptGenRandom` (CNG).
- Android: `getrandom(2)` (since API 23).

These are the maintained-CSPRNG paths. Vulnerabilities in them
(e.g., Linux 5.x `/dev/urandom` early-boot weakness, ECC-RNG
backdoors in older Windows) are tracked by OS vendors.

**Match.** ✓ Single funnel, no test/seeded RNG path in production
(verified via grep). Errors map to `Error::Internal` and propagate
(no silent fallback to weaker entropy).

**Verdict.** ✓ Sound. INFO observation: extremely early-boot
container creation could hit Linux's pre-seeded `/dev/urandom`
(historical CVE class). Practically irrelevant for messenger
storage which runs long after boot.

### 7. Zeroization — `zeroize` crate

**Where.** Every secret-bearing buffer:
- `Zeroizing<Vec<u8>>` wrapping password copies at FFI/async/CLI
  entry points
- `Zeroizing<[u8; PLAINTEXT_LEN]>` for plaintext encode buffers
- `Zeroizing<Vec<u8>>` for AEAD-decrypted bodies, decompressed
  batch buffers
- `#[derive(ZeroizeOnDrop)]` on `SpaceKeys` and `Argon2Params`
  derived material

**2026 state of the art.** `zeroize` crate (1.8): uses
`compiler_fence` + `volatile` writes to prevent the optimizer
from eliding the scrub.

**Match.** ✓ Industry standard.

**Caveat (documented).** Under `panic = "abort"` (workspace release
profile), destructors do not run on panic. OS process teardown is
the scrub there. Documented in the pass-1 commit `f67281f` and in
the dossier §4 M1.

**Verdict.** ✓ Sound.

### 8. Merkle hash chain — BLAKE3 unkeyed

**Where.** [`tx/commit.rs::blake3_of`](../../../../crates/hidden-volume/src/tx/commit.rs).

Used for:
- IndexNode payload hash (`IndexRoot.payload_hash`)
- ChildPointer's `child_hash` for Internal-to-Leaf links
- `CommitPayload.tx_root_hash` = BLAKE3(concat of payload_hashes)
- Superblock's `root_hash` = the same tx_root_hash, also stored
  in the Superblock for hop-by-hop verification

**2026 state of the art.** Merkle hash chains in append-only
storage (Git, IPFS, Sigstore Rekor) use cryptographic hashes;
BLAKE3 is one of the modern choices.

**Match.** ✓ Unkeyed BLAKE3 is correct here — these are *public
commitments* readable from each chunk's plaintext after AEAD
decrypt. The role is integrity (collision-resistance), not secrecy.

**INFO — post-quantum margin.** BLAKE3-256's collision resistance
is 128-bit classically. Grover's algorithm on a CRQC reduces it to
~85-bit (cube root). For very long-term protection (decades),
upgrading to a 512-bit hash would extend the PQ margin. For
deniable-storage use cases (typically short-to-medium-term
retention with vacuum + repack), 128-bit classical / 85-bit PQ
is comfortably enough. Not a finding; just noted for v3+
roadmap.

**Verdict.** ✓ Sound.

### 9. Constant-time comparisons / branch-free checks

**Where.** `audits/constant-time.md` already audited every `==` /
`!=` comparison site:
- Public values (length checks, slot indices, file offsets): OK
  to be data-dependent, by classification in that audit.
- Key / tag material: delegated to RustCrypto's `subtle::ct_eq`
  inside the AEAD crate.

**2026 state of the art.** `subtle::Choice` /
`subtle::ConstantTimeEq` is the de-facto Rust standard for
constant-time comparison (Reginald Aumasson endorsement, Diem,
zkcrypto).

**Match.** ✓ Sound (per prior audit).

**Verdict.** ✓ See `audits/constant-time.md`.

### 10. Algorithmic-agility / format-version bump mechanism

**Where.** [`Argon2Params::validate`](../../../../crates/hidden-volume/src/crypto/kdf.rs)
gates `format_version`. R-NSKIND closed v1 → v2 in audit pass 13
(added kind byte). Future v3 documented in `make_aad` rustdoc as
the path to bind format_version cryptographically.

**2026 state of the art.** Cryptographic agility is the ability to
swap algorithms without breaking deployed data. Patterns:

- Versioned key/AEAD selection (TLS, OpenSSH, age): each container
  records the algorithm IDs in its header, and readers maintain
  multi-version support.
- "Last writer wins" version bumps (this project's choice for
  pre-1.0): single-active-version, no parallel readers.

**Match.** The project's pre-1.0 stance is "breaking changes are
fine" (CLAUDE.md §3). Cryptographic agility is **deferred to v1.0
freeze**, after which any change is a major-version bump.

**INFO — algorithm rotation is not currently supported.** If a
weakness is later discovered in Argon2id or XChaCha20-Poly1305,
the rotation mechanism is: cut a new format version, write a
migration tool that reads-with-old-key + writes-with-new-key, and
have host-apps run the migration. This is the same pattern as
TLS / OpenSSH; not unusual.

**Verdict.** ✓ Sound as a pre-1.0 strategy; should be documented
in a v1.0-freeze checklist.

## Summary table

| ID | Primitive | Choice | Severity | Action |
|---|---|---|---|---|
| 1 | Password KDF | Argon2id (RFC 9106) | ✓ INFO | Default = 64 MiB above OWASP 2024 mainline |
| **P-LOW1** | **`Argon2Params::MIN.m_cost_kib = 8 MiB`** | **below OWASP low-end (12 MiB)** | **LOW** | **add rustdoc warning + recommend MIN only for very-low-end** |
| 2 | AEAD | XChaCha20-Poly1305 (libsodium / RustCrypto) | ✓ INFO | Conservative choice; AEGIS-256 candidate for x86-heavy v3 |
| 3 | Hash | BLAKE3 (Aumasson 2020) | ✓ INFO | Sound, modern |
| 4 | Subkey derivation | BLAKE3-keyed(parent, label) ≡ HKDF-Expand | ✓ INFO | Equivalent to HKDF-Expand |
| **P-LOW2** | **Domain separation via label-length convention** | **fragile, no type-system enforcement** | **LOW** | **length-prefix or kind-tag byte, tied to v3 format bump** |
| 5 | AAD | container_id ‖ slot_le | ✓ INFO | Binds the two relevant facts |
| 6 | RNG | `getrandom` (OS CSPRNG) | ✓ INFO | Single funnel, no test fallback |
| 7 | Zeroization | `zeroize` crate (volatile) | ✓ INFO | Industry standard; panic=abort caveat documented |
| 8 | Merkle hash | BLAKE3-256 unkeyed | ✓ INFO | Sound; PQ margin 85-bit (acceptable) |
| 9 | Constant-time compare | RustCrypto `subtle` | ✓ INFO | See `audits/constant-time.md` |
| 10 | Algorithm agility | format_version + breaking pre-1.0 | ✓ INFO | Document v1.0-freeze migration playbook |

**Counts:** 0 CRITICAL, 0 HIGH, 0 MEDIUM, 2 LOW (P-LOW1, P-LOW2),
8 INFO.

## What's NOT used, and why

A primitive-level review should be explicit about choices NOT made:

- **HKDF-SHA-256 / -SHA-512**: not used directly; BLAKE3-keyed
  subsumes Expand and is faster.
- **AES-GCM / AES-GCM-SIV**: not used; XChaCha20 is software-
  uniform across ARM/x86 without hardware AES.
- **Ed25519 / X25519**: no signatures or DH key exchange needed —
  password-based symmetric KDF is sufficient for the storage
  layer's threat model. Signature schemes would matter if there
  were a multi-party / multi-device key-exchange protocol, which
  is the host-app's domain (`docs/en/guide/multi-device.md`).
- **scrypt / bcrypt / PBKDF2**: superseded by Argon2id for new
  designs (RFC 9106 explicitly recommends Argon2id over scrypt).
- **SHA-256 / SHA-3**: BLAKE3 chosen; sound alternatives but
  slower.
- **Post-quantum primitives (ML-KEM / ML-DSA / SLH-DSA)**: not
  needed at the symmetric layer. Argon2id + ChaCha20 + Poly1305 +
  BLAKE3-256 give 128-bit classical / ~85-bit PQ security
  margins, comfortably enough for storage retention horizons.

## What this pass did NOT cover

- **Implementation-level analysis of the chosen crates.** This pass
  trusted RustCrypto and `blake3` crate as correctly-implemented;
  no audit of the Rust source of these dependencies. That's the
  scope of an external dependency audit, which we substitute with
  pinning advisory ignores in `deny.toml` and reproducible builds.
- **Side-channel surface beyond `subtle::ct_eq` correctness.** That's
  the [pass-3 side-channel audit](./side-channel-surface.md) (next).
- **Concrete fuzzing of decode paths.** That's the [pass-4 format
  fuzzing analysis](./format-fuzzing.md) (after).
- **End-to-end attack construction with attacker narrative.** That's
  the [pass-5 threat-model challenge](./threat-model-challenge.md)
  (final).
