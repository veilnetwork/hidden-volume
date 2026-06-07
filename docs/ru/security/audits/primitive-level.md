# Primitive-level review

**Дата.** 2026-05-28. **Pass.** 2 из 5 в серии deeper-review.
**Reviewer.** LLM-assisted, проинструктирован *challenge'ить сами
примитивы*, а не construction'ы поверх них, против state-of-the-art
литературы актуальной на 2026.

## Методология

Где [adversarial-stance pass](adversarial-stance.md) брал
Argon2id / XChaCha20-Poly1305 / BLAKE3 / `getrandom` как
trustworthy black boxes и challenge'ил *construction* над ними,
этот pass инвертирует: принимает construction как данное и
спрашивает «правильные ли это *примитивы*, и параметризованы ли
они так, как рекомендует криптографическая литература 2026?»

Использованные источники:

- **OWASP Password Storage Cheat Sheet** (2024-editon
  рекомендации для Argon2id-параметров)
- **IETF RFC 9106** — спецификация Argon2 (победитель PHC, IRTF
  CFRG)
- **IETF RFC 8439** — ChaCha20-Poly1305 (базовый AEAD)
- **IETF RFC 7539-bis** — XChaCha20 extended-nonce construction
  (Bernstein, статус: широко развёрнут, но pre-final-RFC;
  libsodium reference implementation с 1.0.12)
- **NIST SP 800-63B-rev4** (Authenticator and Verifier
  Requirements)
- **BLAKE3 specification** (Aumasson, O'Connor, Neves,
  Wilcox-O'Hearn, 2020) и follow-up cryptanalysis через 2025
- **RustCrypto** crate set: published vulnerability advisories +
  open-issue tracker reviewed на 2026-05-28
- **CFRG draft-irtf-cfrg-aegis-aead-12** — AEGIS-256 (alternative
  AEAD, CFRG-final в late 2024; сравниваем с ним)

Для каждого выбора примитива фиксируется:

- **Что используется** и **где**.
- **2026 state of the art** для этой роли.
- **Match / gap.**
- **Если есть gap**: severity, exploitability, recommended action.

Severity-legend совпадает с [adversarial-stance §"Headline"](adversarial-stance.md):
CRITICAL / HIGH / MEDIUM / LOW / INFO.

## Headline

**0 CRITICAL / 0 HIGH / 0 MEDIUM, 2 LOW, 3 INFO observations.**
Выборы примитивов sound и conservative. Два worth-recording
finding:

- **P-LOW1.** `Argon2Params::MIN` ставит `m_cost_kib = 8 MiB`,
  что **ниже OWASP 2023 low-end рекомендации в 12 MiB**.
  Намеренный accessibility trade-off (low-end embedded / mobile),
  документированный в константе; следует флагнуть явно в rustdoc
  `Argon2Params::MIN`, чтобы future maintainer не повысил floor
  не осознав rationale.
- **P-LOW2.** `derive_subkey` domain-separation convention
  полагается на **byte-length label**, отличающуюся от 40-байтного
  input'а `derive_chunk_key`. Это fragile-инвариант (нет type-
  system enforcement; полагается на документированный convention).
  Length-prefix или leading kind-tag byte сделали бы separation
  явной. Не current bug — единственные `derive_subkey` callers
  respect convention — но defense-in-depth opportunity (D3
  closure audit'а полагается, что convention держится в future
  коде тоже).

3 INFO observations — позиции, где выбор sound, но worth-noting
для future maintainer'ов / migration planner'ов (post-quantum,
AEAD-alternative landscape, label hardening).

## Per-primitive review

### 1. Password KDF — Argon2id (RustCrypto `argon2 = "0.5"`)

**Где.** [`crates/hidden-volume/src/crypto/kdf.rs`](../../../../crates/hidden-volume/src/crypto/kdf.rs)
`derive_master_key`.

**2026 state of the art.** Argon2id остаётся IRTF / OWASP /
NIST рекомендацией для password-based KDF'ов:

- IRTF RFC 9106 (2021) — Argon2id — recommended variant.
- OWASP Password Storage Cheat Sheet (2024):
  - Mainline: `m=19 MiB, t=2, p=1` minimum.
  - «Low-resource devices»: `m=12 MiB, t=3, p=1` minimum.
  - Нет формального upper bound'а; `m=1 GiB` — «no RAM
    constraint» рекомендация.
- NIST SP 800-63B-rev4 §5.1.1.2: «memory-hard functions such as
  Argon2 SHOULD be used».

**Match.**

| Константа | Значение | OWASP comparison | Verdict |
|---|---|---|---|
| `Argon2Params::DEFAULT.m_cost_kib` | 64 MiB | 3.4× OWASP mainline (19 MiB) | ✓ above recommendation |
| `Argon2Params::DEFAULT.t_cost` | 3 | = OWASP low-end | ✓ at recommendation |
| `Argon2Params::DEFAULT.p_cost` | 1 | = OWASP | ✓ at recommendation |
| `Argon2Params::MIN.m_cost_kib` | **8 MiB** | **ниже OWASP low-end (12 MiB)** | ⚠ **P-LOW1** |
| `Argon2Params::MIN.t_cost` | 2 | = OWASP mainline | ✓ |
| `Argon2Params::MIN.p_cost` | 1 | = OWASP | ✓ |
| `Argon2Params::MAX.m_cost_kib` | 1 GiB | = OWASP «no constraint» | ✓ |
| `Argon2Params::MAX.t_cost` | 100 | well above OWASP | ✓ |
| `Argon2Params::MAX.p_cost` | 64 | well above OWASP | ✓ |

**P-LOW1 — `Argon2Params::MIN` m_cost ниже OWASP low-end.**

Floor 8 MiB существует, чтобы библиотека могла работать на *очень*
memory-constrained устройствах (low-end IoT, tiny embedded).
DEFAULT — 8× floor (64 MiB) и это то, что host-apps реально
используют; floor — validation-gate, отвергающий tampered headers
ниже этого значения.

Сценарии атакующего:

1. **Header-tamper в MIN для ослабления brute-force.** Уже
   проанализировано в [adversarial-stance D1-A5](adversarial-stance.md):
   не работает, потому что legitimate user's open потом derive'ит
   *другой* master_key, hit'ит AuthFailed, никогда не открывает
   файл. Chunks captured файла всё ещё sealed под ORIGINAL params,
   так что offline brute-force не ускоряется.
2. **Legitimate host-app явно выбирает MIN.** Пользователь на
   1 MiB-RAM embedded устройстве может genuinely нуждаться в
   этом. Resulting key-derivation выполняется в ~10ms (vs ~700ms
   для DEFAULT), что ускоряет offline brute-force в ~70×. Это
   реальное снижение strength, deliberately accepted этим
   host-app.

Так что floor не exploit'able атакующими; это *user-chosen
weakness* для resource-constrained deployments.

**Recommendation (proposed for v1.x).** Добавить `#![doc]`
warning на `Argon2Params::MIN` calling out, что:

- Это ниже OWASP 2024 low-end рекомендации (12 MiB).
- Существует для very-low-end embedded use; **mobile host-apps
  должны использовать DEFAULT (64 MiB)**, не MIN.
- Снижение brute-force resistance — ~70× по сравнению с DEFAULT.

Это doc change (не const change), потому что подъём floor сломал
бы low-end host-apps.

### 2. Symmetric AEAD — XChaCha20-Poly1305 (RustCrypto `chacha20poly1305 = "0.10"`)

**Где.** [`crates/hidden-volume/src/crypto/aead.rs`](../../../../crates/hidden-volume/src/crypto/aead.rs)
`ChunkAead::{new, seal, open}`.

**2026 state of the art.**

- **ChaCha20-Poly1305 (RFC 8439, 2018):** IETF-стандартизирован,
  широко развёрнут (TLS 1.3, WireGuard, age, libsodium, Signal).
  96-bit nonce, так что random-nonce safe только для ~2³²
  messages per key.
- **XChaCha20-Poly1305 (Bernstein draft, libsodium 1.0.12+):**
  тот же cipher с HChaCha20 nonce-extension до 192-bit. Random-
  nonce safe для ~2⁹⁶ messages.
- **AEGIS-256 (CFRG, draft-irtf-cfrg-aegis-aead-12, final в
  late 2024):** AES-based, hardware-accelerated на платформах с
  AES-инструкциями. ~2× быстрее ChaCha20 на x86_64-с-AES-NI, но
  ~3× медленнее на ARM-без-crypto-extensions (mobile).
- **AES-GCM-SIV (RFC 8452):** misuse-resistant против nonce
  reuse (nonce reuse утекает максимум plaintexts equality, не
  plaintexts themselves). 96-bit nonce. Performs well только с
  hardware AES.

**Match.** XChaCha20-Poly1305 — **корректный conservative
выбор** для этого проекта:

- Deniable-storage работает на разнообразном железе включая
  ARMv7 mobile без AES-extensions; ChaCha20 software-uniform
  там.
- 192-bit random nonce устраняет необходимость per-message
  counter discipline; collision risk пренебрежимый при 16M
  chunks (open-scan budget cap = 16 × 1024 × 1024 ≈ 2²⁴
  messages, far ниже 2⁹⁶ collision frontier).
- Constant-time tag check — RustCrypto invariant; AEAD-примитив
  не может leak'ать tag content через timing.

**Gap.** Нет functional. AEGIS-256 *возможно* предлагает лучшую
performance на x86_64-с-AES, но deniability-storage use case
доминирован Argon2 (~700ms), а не per-chunk AEAD (~µs), так что
savings были бы invisible.

**Verdict.** ✓ Sound. INFO observation: по мере maturing
AEGIS-256 и видя deployment, рассмотреть его для v3-format-bump
для x86-heavy deployments — но XChaCha20 — правильный pick сейчас.

### 3. Cryptographic hash — BLAKE3 (`blake3 = "1.x"`)

**Где.**
- `derive_subkey(parent, label)` — BLAKE3-keyed для key
  derivation chain ([`crypto/derive.rs`](../../../../crates/hidden-volume/src/crypto/derive.rs)).
- `derive_chunk_key(aead_root, container_id, slot)` — BLAKE3-
  keyed для per-slot AEAD key.
- IndexNode payload hashes / `tx_root_hash` в `CommitPayload` —
  BLAKE3 unkeyed для Merkle integrity links
  ([`tx/commit.rs::blake3_of`](../../../../crates/hidden-volume/src/tx/commit.rs)).

**2026 state of the art.**

- BLAKE3 (Aumasson, O'Connor, Neves, Wilcox-O'Hearn, 2020):
  256-bit collision resistance, 256-bit preimage, constant-time,
  parallelizable, XOF mode. Нет cryptanalysis weakening через
  2025.
- BLAKE2b (RFC 7693, 2015): предшественник, тоже sound, slightly
  slower.
- SHA-3 / Keccak (FIPS 202): NIST стандарт, sound, slower BLAKE3.
- KangarooTwelve (Bertoni, Daemen, Peeters, Van Assche, 2018):
  Keccak-derived XOF с explicit parallelism. Быстрее SHA-3,
  медленнее BLAKE3 в benchmarks.

**Match.** BLAKE3 — **modern и sound**. Keyed mode
(`BLAKE3-keyed(key, msg) = BLAKE3 с key как chaining input`) —
правильный PRF для fixed-length keys. Unkeyed mode для Merkle
hashes корректен (это public commitments, не secrets).

**Verdict.** ✓ Sound.

### 4. Subkey derivation — BLAKE3-keyed of label

**Где.** `derive_subkey(parent: &[u8; 32], label: &[u8]) -> [u8; 32]`
в [`crypto/derive.rs`](../../../../crates/hidden-volume/src/crypto/derive.rs).

Implementation: `BLAKE3-keyed(parent, label) → 32 bytes`.

Функционально эквивалентно HKDF-Expand(parent, info=label, L=32).
HKDF-Extract step ненужен, потому что `parent` уже uniform
(output prior BLAKE3 derivation в chain).

**2026 state of the art.**

- HKDF (RFC 5869): canonical KDF chain — `HKDF-Extract(salt,
  IKM) -> PRK; HKDF-Expand(PRK, info, L) -> OKM`.
- BLAKE3 keyed mode функционирует как Expand-only.

**Match.** Mathematically эквивалентно по security. Style choice.
Документировано как такое в rustdoc `derive_subkey`.

**P-LOW2 — domain-separation convention label-length-based.**

Audit-pass-1 D3 closure документировал, что 40-байтный input
`derive_chunk_key(aead_root, container_id, slot)` — **domain-
separation discriminator** от 16-байтной label
`derive_subkey(aead_root, "hv/v1/space/...")`. То есть, *длина*
input distinguishes «chunk-key derivation» от «subkey derivation».

Этот convention **fragile**:

- Ничего в type system не enforce'ит его.
- Future `derive_subkey(aead_root, b"hv/v2/some-40-byte-context-string-here!!!")`
  call мог бы случайно collide с chunk-key derivation.
- Convention документирован, но не enforced code-review tooling.

**Recommendation (proposed for v1.x).** Один из:

(a) Префиксировать каждую label `derive_subkey` length-prefix
    байтом: `BLAKE3-keyed(parent, len(label) ‖ label)` — делает
    input self-describing и предотвращает length-collision с
    любым chunk-key input.
(b) Добавить leading kind-tag byte и в `derive_chunk_key`, и в
    `derive_subkey`:
    - `derive_chunk_key`: `0x01 ‖ container_id ‖ slot_le_u64` (41
      байт).
    - `derive_subkey`: `0x02 ‖ label` (1 + label.len()).
    Делает разделение explicit by content, не by length.

Любое — format-version-bump-class изменение (меняет key
derivation, так что v1/v2 контейнеры не reopen с новой схемой
без backward-compat handling). Tracked рядом с v3 cryptographic-
version-binding lock-down из dossier §3.

**Update (2026-05-28, отгружено в v3 коммит `8722fa1`).** Был
выбран option (b) с отгрузкой, причём **kind tag'и swap'нуты vs
оригинальный proposal**: `derive_subkey` несёт
`SUBKEY_KIND_TAG = 0x01`, `derive_chunk_key` —
`CHUNK_KEY_KIND_TAG = 0x02` (см.
[`crates/hidden-volume/src/crypto/derive.rs`](../../../../crates/hidden-volume/src/crypto/derive.rs)).
Swap безвреден — оба порядка дают эквивалентную domain
separation. P-LOW2 теперь **закрыт**.

**Verdict.** ✓ Sound today, **✓ закрыт в v3 (2026-05-28)** —
fragile convention заменена явными kind-tag байтами.

### 5. AAD — container_id ‖ slot_le_u64

**Где.** [`make_aad`](../../../../crates/hidden-volume/src/crypto/aead.rs)
возвращает 40-байтный AAD.

**2026 state of the art.** AAD должен привязывать каждый
contextual factor, который атакующий мог бы попытаться варьировать
без изменения ciphertext bytes — точно «swap chunk between
contexts» атаки, тестируемые в [adversarial-stance I1-A2/I1-A3](adversarial-stance.md).

**Match.** Два factor'а, которые AAD должен привязать, present:

- `container_id` (32 байта) — defeats cross-container chunk move.
- `slot` (8 байт LE) — defeats slot-shuffle внутри container'а.

**Что НЕ в AAD, deliberately:**

- **format_version**: closed by policy (`validate()` отвергает
  unknown version). Acknowledged limitation; v3 lock-down
  required (документировано в dossier §3).
- **commit_seq**: покрыто собственным AEAD superblock'а +
  Merkle chain. AAD-binding seq в каждый chunk потребовал бы
  re-encrypting на каждом commit (chunk shared между commits,
  если нет изменения). Корректно omitted.
- **kind / namespace**: покрыто encrypted plaintext header byte.
  AAD-binding kind означал бы, что атакующий, swap'ящий chunk's
  kind (например, relabel IndexNode как DataBatch), failed бы
  AEAD — но plaintext-side kind check после decrypt ловит это
  всё равно. Defense-in-depth был бы marginal.

**Verdict.** ✓ Sound для заявленных инвариантов (D1-A2, I1, I3).
v3 должен добавить format_version per lock-down requirement.

### 6. Random number generation — `getrandom` crate

**Где.** [`crypto/rng.rs`](../../../../crates/hidden-volume/src/crypto/rng.rs)
— единственный CSPRNG funnel. Используется для:

- 32-байтный salt на container create
- 32-байтный container_id на container create
- 24-байтный XChaCha20 nonce на AEAD seal
- 8-байтная temp-filename randomness для atomic_rewrite
- N-byte garbage padding chunks

**2026 state of the art.** `getrandom` зовёт OS CSPRNG:
- Linux: `getrandom(2)` syscall (с 3.17) — тянет из `/dev/urandom`
  pool, seeded hardware/kernel entropy.
- macOS / iOS: `SecRandomCopyBytes` (Apple CryptoKit).
- Windows: `BCryptGenRandom` (CNG).
- Android: `getrandom(2)` (с API 23).

Это maintained-CSPRNG paths. Vulnerabilities в них (например,
Linux 5.x `/dev/urandom` early-boot weakness, ECC-RNG backdoors
в старых Windows) tracked OS vendor'ами.

**Match.** ✓ Single funnel, нет test/seeded RNG path в
production (verified grep'ом). Errors мапят к `Error::Internal`
и propagate (нет silent fallback к weaker entropy).

**Verdict.** ✓ Sound. INFO observation: extreme early-boot
container creation мог бы hit'нуть Linux's pre-seeded
`/dev/urandom` (historical CVE class). Practically irrelevant
для messenger storage, который работает long после boot.

### 7. Zeroization — `zeroize` crate

**Где.** Каждый secret-bearing buffer:
- `Zeroizing<Vec<u8>>` оборачивающий password copies на FFI/
  async/CLI entry points
- `Zeroizing<[u8; PLAINTEXT_LEN]>` для plaintext encode buffers
- `Zeroizing<Vec<u8>>` для AEAD-decrypted bodies, decompressed
  batch buffers
- `#[derive(ZeroizeOnDrop)]` на `SpaceKeys` и `Argon2Params`
  derived material

**2026 state of the art.** `zeroize` crate (1.8): использует
`compiler_fence` + `volatile` writes для предотвращения
оптимизатора от eliding scrub'а.

**Match.** ✓ Industry standard.

**Caveat (documented).** Под `panic = "abort"` (workspace release
profile), destructors не запускаются на panic. OS process
teardown — scrub там. Документировано в pass-1 коммите
`f67281f` и в dossier §4 M1.

**Verdict.** ✓ Sound.

### 8. Merkle hash chain — BLAKE3 unkeyed

**Где.** [`tx/commit.rs::blake3_of`](../../../../crates/hidden-volume/src/tx/commit.rs).

Используется для:
- IndexNode payload hash (`IndexRoot.payload_hash`)
- ChildPointer's `child_hash` для Internal-to-Leaf links
- `CommitPayload.tx_root_hash` = BLAKE3(concat of payload_hashes)
- Superblock's `root_hash` = тот же tx_root_hash, также хранится
  в Superblock для hop-by-hop verification

**2026 state of the art.** Merkle hash chains в append-only
storage (Git, IPFS, Sigstore Rekor) используют криптографические
hashes; BLAKE3 — один из modern choices.

**Match.** ✓ Unkeyed BLAKE3 — корректно здесь — это *public
commitments*, readable из plaintext каждого chunk'а после AEAD
decrypt'а. Роль — integrity (collision-resistance), не secrecy.

**INFO — post-quantum margin.** BLAKE3-256 collision resistance
— 128-bit classical. Grover algorithm на CRQC снижает её к
~85-bit (cube root). Для very long-term protection (decades),
upgrade к 512-bit hash расширил бы PQ margin. Для deniable-
storage use cases (typically short-to-medium-term retention с
vacuum + repack), 128-bit classical / 85-bit PQ comfortably
enough. Не finding; просто noted для v3+ roadmap.

**Verdict.** ✓ Sound.

### 9. Constant-time comparisons / branch-free checks

**Где.** `audits/constant-time.md` уже audit'ил каждый `==` /
`!=` comparison site:
- Public values (length checks, slot indices, file offsets): OK
  to be data-dependent, by classification в том audit.
- Key / tag material: delegated к `subtle::ct_eq` RustCrypto
  внутри AEAD crate.

**2026 state of the art.** `subtle::Choice` /
`subtle::ConstantTimeEq` — de-facto Rust standard для
constant-time comparison (Reginald Aumasson endorsement, Diem,
zkcrypto).

**Match.** ✓ Sound (по prior audit'у).

**Verdict.** ✓ См. `audits/constant-time.md`.

### 10. Algorithmic-agility / format-version bump mechanism

**Где.** [`Argon2Params::validate`](../../../../crates/hidden-volume/src/crypto/kdf.rs)
gate'ит `format_version`. R-NSKIND закрыл v1 → v2 в audit pass
13 (добавил kind byte). Future v3 документирован в `make_aad`
rustdoc как path для bind'а format_version cryptographically.

**2026 state of the art.** Cryptographic agility — способность
swap алгоритмов без сломания deployed data. Patterns:

- Versioned key/AEAD selection (TLS, OpenSSH, age): каждый
  контейнер записывает algorithm IDs в header, readers
  поддерживают multi-version.
- «Last writer wins» version bumps (выбор этого проекта для
  pre-1.0): single-active-version, нет parallel readers.

**Match.** Pre-1.0 stance проекта — «breaking changes are fine»
(CLAUDE.md §3). Cryptographic agility **отложена до v1.0
freeze**, после чего любое изменение — major-version bump.

**INFO — algorithm rotation не currently supported.** Если
weakness позже будет discovered в Argon2id или
XChaCha20-Poly1305, rotation mechanism: cut новую format-
version, написать migration tool, читающий-старым-ключом +
пишущий-новым-ключом, и host-apps run migration. Это тот же
pattern что TLS / OpenSSH; не unusual.

**Verdict.** ✓ Sound как pre-1.0 strategy; следует документировать
в v1.0-freeze checklist.

## Summary table

| ID | Примитив | Choice | Severity | Action |
|---|---|---|---|---|
| 1 | Password KDF | Argon2id (RFC 9106) | ✓ INFO | Default = 64 MiB above OWASP 2024 mainline |
| **P-LOW1** | **`Argon2Params::MIN.m_cost_kib = 8 MiB`** | **ниже OWASP low-end (12 MiB)** | **LOW** | **add rustdoc warning + recommend MIN только для very-low-end** |
| 2 | AEAD | XChaCha20-Poly1305 (libsodium / RustCrypto) | ✓ INFO | Conservative choice; AEGIS-256 candidate для x86-heavy v3 |
| 3 | Hash | BLAKE3 (Aumasson 2020) | ✓ INFO | Sound, modern |
| 4 | Subkey derivation | BLAKE3-keyed(parent, label) ≡ HKDF-Expand | ✓ INFO | Эквивалентно HKDF-Expand |
| **P-LOW2** | **Domain separation через label-length convention** | **fragile, нет type-system enforcement** | **LOW** | **length-prefix или kind-tag byte, tied к v3 format bump** |
| 5 | AAD | container_id ‖ slot_le | ✓ INFO | Привязывает два relevant facts |
| 6 | RNG | `getrandom` (OS CSPRNG) | ✓ INFO | Single funnel, нет test fallback |
| 7 | Zeroization | `zeroize` crate (volatile) | ✓ INFO | Industry standard; panic=abort caveat документирован |
| 8 | Merkle hash | BLAKE3-256 unkeyed | ✓ INFO | Sound; PQ margin 85-bit (acceptable) |
| 9 | Constant-time compare | RustCrypto `subtle` | ✓ INFO | См. `audits/constant-time.md` |
| 10 | Algorithm agility | format_version + breaking pre-1.0 | ✓ INFO | Document v1.0-freeze migration playbook |

**Counts:** 0 CRITICAL, 0 HIGH, 0 MEDIUM, 2 LOW (P-LOW1, P-LOW2),
8 INFO.

## Что НЕ используется и почему

Primitive-level review должен быть explicit о выборах NOT made:

- **HKDF-SHA-256 / -SHA-512**: not used directly; BLAKE3-keyed
  subsumes Expand и быстрее.
- **AES-GCM / AES-GCM-SIV**: not used; XChaCha20 software-
  uniform по ARM/x86 без hardware AES.
- **Ed25519 / X25519**: signatures или DH key exchange не
  нужны — password-based symmetric KDF достаточно для threat
  model'а storage-layer'а. Signature schemes мattered бы, если
  бы был multi-party / multi-device key-exchange protocol, что
  domain host-app'а (`docs/ru/guide/multi-device.md`).
- **scrypt / bcrypt / PBKDF2**: superseded Argon2id'ом для new
  designs (RFC 9106 explicitly рекомендует Argon2id over
  scrypt).
- **SHA-256 / SHA-3**: BLAKE3 chosen; sound alternatives, но
  slower.
- **Post-quantum primitives (ML-KEM / ML-DSA / SLH-DSA)**: не
  нужны на symmetric layer'е. Argon2id + ChaCha20 + Poly1305 +
  BLAKE3-256 дают 128-bit classical / ~85-bit PQ security
  margins, comfortably enough для storage retention horizons.

## Что этот pass НЕ покрыл

- **Implementation-level analysis выбранных crates.** Этот pass
  trust'ит RustCrypto и `blake3` crate как correctly-implemented;
  никакого audit'а Rust source этих dependencies. Это scope
  external dependency audit'а, который мы substitute pin'ингом
  advisory ignores в `deny.toml` и reproducible builds.
- **Side-channel surface beyond `subtle::ct_eq` correctness.**
  Это [pass-3 side-channel audit](./side-channel-surface.md)
  (next).
- **Concrete fuzzing of decode paths.** Это [pass-4 format
  fuzzing analysis](./format-fuzzing.md) (после).
- **End-to-end attack construction с attacker narrative.** Это
  [pass-5 threat-model challenge](./threat-model-challenge.md)
  (final).
