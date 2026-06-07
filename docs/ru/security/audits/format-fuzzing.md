# Format-fuzzing analysis

**Дата.** 2026-05-28. **Pass.** 4 из 5 серии deeper-review.
**Reviewer.** LLM-assisted. **Scope.** Формальная boundary-
enumeration каждой `decode` entry-точки + инвентарь существующей
fuzzing-infrastructure, покрывающей каждую границу.

## Методология

Каждый байт, пересекающий в библиотеку, может попасть в
`decode`-функцию. Threat-model трактует эти decoder'ы как
«untrusted input» surface — AEAD-protected на on-disk пути (так
что атакующий не должен иметь возможности достичь decoder'ов без
ключа), но writer-side regression или torn write всё ещё могут
скормить decoder'у malformed-bytes, которые *успешно* AEAD-
decrypt'ились.

Этот pass:

1. Перечисляет каждую `pub` `decode` (и `from_u8`) entry-точку.
2. Для каждой перечисляет boundary-классы (truncation, oversized
   length, bad discriminator, sortedness, etc.).
3. Мапит каждую границу к её **defending code** и к
   **существующему fuzz/proptest тесту**, который её
   упражняет.
4. Флагает любую границу, не covered, с рекомендацией.

Severity-legend без изменений от prior pass'ей.

## Headline

**0 CRITICAL / 0 HIGH / 0 MEDIUM, 0 LOW, 1 INFO.** Fuzz-coverage
*comprehensive*: 3 cargo-fuzz targets (nightly), 9 proptest
«decode-doesn't-panic» properties + 6 encode/decode roundtrip
properties (stable, на каждом CI run). Каждая boundary, которую
я смог перечислить, мапится к конкретному тесту. Единственное
INFO observation:

- **FZ-INFO1.** Proptest layer — integration-level (cargo test
  --test parser_fuzz) и прогоняет 512 cases per property per
  CI run. Cargo-fuzz layer прогоняется nightly с continue-on-
  error в `.github/workflows/ci.yml`. Нет CI-failure-on-fuzz-
  finding gate'а; fuzz findings surfaced бы как
  `fuzz-crashes` artifacts, а не блокировали бы release.
  Trade-off документирован в [`docs/ru/security/audits/fsync.md`](fsync.md)
  + [TASKS.md F-3 v1.x](../../../TASKS.md). Не current bug;
  noted для полноты.

## Инвентарь: существующее fuzz / proptest coverage

### cargo-fuzz targets ([`crates/hidden-volume/fuzz/fuzz_targets/`](../../../crates/hidden-volume/fuzz/fuzz_targets/))

| Target | Что fuzz'ит | Достигает post-AEAD code? |
|---|---|---|
| `container_open.rs` | Полный `Container::open` на random-bytes файле | Нет (большинство chunks падают AEAD; тестирует pre-AEAD parsers) |
| `decoder_family.rs` | Каждая публичная `decode`-функция с arbitrary bytes | Да — bypass AEAD entirely |
| `plaintext_decode.rs` | `Plaintext::decode` only, deep coverage | Да |

Trigger: nightly `fuzz-smoke` job в `.github/workflows/ci.yml`
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

Trigger: каждый `cargo test` run (workspace test gate).

### Дополнительные crash / property тесты

- [`tests/crash_recovery.rs`](../../../crates/hidden-volume/tests/crash_recovery.rs) —
  detereministic crash-injection тесты для 3-fsync protocol'а.
- [`tests/crash_proptest.rs`](../../../crates/hidden-volume/tests/crash_proptest.rs) —
  proptest с crash-injection на arbitrary byte boundaries.
- [`tests/property_full.rs`](../../../crates/hidden-volume/tests/property_full.rs) —
  end-to-end property test на KV + log namespaces.

## Per-decoder boundary enumeration

Для каждого decoder'а — boundary-классы, которые я смог
перечислить, где в коде они отвергаются, и какой тест упражняет
каждую.

### `Plaintext::decode` ([chunk/format.rs:91](../../../crates/hidden-volume/src/chunk/format.rs))

Decode'ит 4040-байтный post-AEAD plaintext frame.

| Boundary | Defending code | Test |
|---|---|---|
| `bytes.len() != PLAINTEXT_LEN` (exact-length check) | line 92-94: `if buf.len() != PLAINTEXT_LEN` | `plaintext_decode_doesnt_panic` (random bytes arbitrary length) |
| Bad magic | line 95-97: `&buf[..4] != MAGIC` | covered fuzz'ом; magic — 4-байтная константа `b"HVC1"` |
| Bad kind discriminator | line 99: `ChunkKind::from_u8` returns `Err` | covered |
| Non-zero flags byte (forward-compat) | line 102-104: `buf[5] != 0` rejected | covered; tested `tests/header_params.rs::p1_non_zero_reserved_flags_byte_rejected` |
| Reserved bytes 6-7 != 0 (мы активно не проверяем; random-padded на encode) | n/a — нет constraint'а | not a boundary |
| `payload_len > PAYLOAD_CAP` | line 109-111: rejected до slice | covered |
| `seq` — любой u64 | нет constraint by design (seq от writer'а) | n/a |

**Verdict.** Fully bounded; каждая byte position имеет defined
valid-range; каждый out-of-range case мапит к `Err(Malformed)`,
не panic.

### `Argon2Params::decode` ([crypto/kdf.rs:237](../../../crates/hidden-volume/src/crypto/kdf.rs))

Decode'ит 16-байтный Argon2-params block из cleartext header'а.

| Boundary | Defending code | Test |
|---|---|---|
| `bytes.len() != HEADER_PARAMS_LEN` (16) | exact-length check | `argon2_params_decode_doesnt_panic` |
| Все четыре u32-поля парсятся `u32::from_le_bytes` (infallible) | n/a — никогда не panic'ит на 4-byte slice | n/a |
| Последующий `validate()` enforce'ит semantic ranges | line 164-201 (separate fn) | `tests/header_params.rs` (D1-class regressions) |

**Verdict.** Decoder unconditionally panic-free; semantic
validation в `validate()` покрыта отдельно.

### `Header::decode` ([container/header.rs:49](../../../crates/hidden-volume/src/container/header.rs))

Decode'ит 48-байтный container-header (`salt ‖ Argon2Params`). v3
убрал 32-байтное поле `container_id`, которое в v2 лежало между
salt и params; в v3 `container_id` деривится per-space внутри
`SpaceKeys::from_master`, а не парсится из cleartext.

| Boundary | Defending code | Test |
|---|---|---|
| `bytes.len() < HEADER_LEN` (48) | length check + early return | `header_decode_doesnt_panic` |
| `Argon2Params::decode` failure на 16-byte slice | propagates `Err` | covered |
| Salt unconditionally accepted (32 байта, нет semantic-constraint'ов) | n/a | n/a |

**Verdict.** Fully bounded.

### `Superblock::decode` ([space/superblock.rs:52](../../../crates/hidden-volume/src/space/superblock.rs))

Decode'ит 48-байтный superblock payload.

| Boundary | Defending code | Test |
|---|---|---|
| `bytes.len() != SUPERBLOCK_LEN` (48) | exact-length check | `superblock_decode_doesnt_panic` |
| `seq`, `root_slot`, `root_hash` все парсятся infallible u64 / fixed-array reads | n/a | n/a |

**Verdict.** Fully bounded.

### `IndexNode::decode` ([space/index.rs:156](../../../crates/hidden-volume/src/space/index.rs))

Dispatcher: читает leading discriminator byte и route'ит к
`LeafNode::decode` или `InternalNode::decode`.

| Boundary | Defending code | Test |
|---|---|---|
| `bytes.len() < HEADER_LEN` (4) | line 157-159: rejected | `index_node_decode_doesnt_panic` |
| Bad discriminator | line 163: `Err(Malformed("unknown index node type"))` | covered |

**Verdict.** Fully bounded.

### `LeafNode::decode` ([space/index.rs:234](../../../crates/hidden-volume/src/space/index.rs))

Decode'ит Leaf с `num_entries × (klen, key, vlen, value)`.

| Boundary | Defending code | Test |
|---|---|---|
| Header length / discriminator | line 235-237 | covered |
| **G2 pre-allocation bound** (`num × MIN_LEAF_ENTRY_BYTES > body`) | line 240-251 | covered; closes audit-pass-5 G2 finding |
| Truncated на `key_len` field | line 255-257 | covered |
| `klen == 0` или `klen > MAX_KEY_LEN` (256) | line 260-262 | covered |
| Truncated на key / value-length / value | line 263-275 | covered |
| `vlen > MAX_VALUE_LEN` (2048) | line 270-272 | covered |
| **Sortedness violation** | line 280-296: `windows(2)` pattern rejects unsorted entries; typed `Error::Internal` для impossible `let [a,b]=w else` branch'а (audit pass 17) | covered |
| Encode-decode bijectivity | `leaf_node_roundtrip` proptest | Phase 2 |

**Verdict.** Fully bounded с explicit pre-allocation budget check
(G2). Нет panic site.

### `InternalNode::decode` ([space/index.rs:384](../../../crates/hidden-volume/src/space/index.rs))

Decode'ит Internal-node с `num_children × (klen, first_key,
child_slot, child_hash)`.

| Boundary | Defending code | Test |
|---|---|---|
| Header length / discriminator | line 385-387 | covered |
| **L1 zero-children rejection** | line 396-398 | covered; closes audit-pass-11 L1 |
| **G3 pre-allocation bound** | line 399-406 | covered |
| Truncated на `first_key_len` / `first_key` / `child_slot` / `child_hash` | line 410-433 | covered |
| `klen == 0` или `klen > MAX_KEY_LEN` | line 415-417 | covered |
| **Sortedness violation** | line 434-444: тот же `windows(2)` pattern что Leaf | covered |
| Encode-decode bijectivity | `internal_node_roundtrip` proptest | Phase 2 |

**Verdict.** Fully bounded; L1 + G3 closures verified.

### `CommitPayload::decode` ([tx/commit.rs:142](../../../crates/hidden-volume/src/tx/commit.rs))

Decode'ит `num_roots × (namespace, kind, index_slot, payload_hash) ‖
tx_root_hash`.

| Boundary | Defending code | Test |
|---|---|---|
| `bytes.len() < 2 + 32` (header floor) | line 143-145 | covered |
| `num > MAX_NAMESPACES_PER_TX` | line 147-149 | covered |
| `bytes.len() < expected` (truncation post-num) | line 150-153 | covered |
| `kind` discriminator (`NamespaceKind::from_u8`) | line 159 | covered (R-NSKIND v2 closure) |
| **Sortedness violation** на `namespace` | line 174-178 | covered |
| Final 32-byte `tx_root_hash` read in-bounds | guaranteed `expected` length check на line 150 | covered |

**Verdict.** Fully bounded. R-NSKIND v2 layout (added `kind`
byte per IndexRoot) корректно handled.

### `decode_batch` ([space/log.rs:196](../../../crates/hidden-volume/src/space/log.rs))

Decompress'ит + decode'ит zstd-compressed DataBatch payload.

| Boundary | Defending code | Test |
|---|---|---|
| zstd decode failure | line 207-208: мапит к `Error::Compression` | covered |
| **M5 streaming cap** (`MAX_DECODED_BATCH_LEN ≈ 8.4 MiB`) | line 212-218: `Read::take(cap + 1)` enforce'ит byte-level cap | covered; closes audit-pass-11 M5 (zstd bomb) |
| `raw.len() < 4` (num_records header) | line 221-223 | covered |
| `num > MAX_RECORDS_PER_BATCH` (1024) | line 224-227 | covered |
| Truncated на record-header / payload | line 230-243 | covered |
| `plen > MAX_LOG_PAYLOAD_LEN` (8 KiB) | line 238-240 | covered |

**Verdict.** Fully bounded с M5 compression-bomb cap'ом как load-
bearing defense'ом.

### `ChunkKind::from_u8` ([chunk/kind.rs:37](../../../crates/hidden-volume/src/chunk/kind.rs))

Single-byte discriminator.

| Boundary | Defending code | Test |
|---|---|---|
| Unknown discriminator | line 37-45: `Err(Malformed("unknown chunk kind"))` (rejects reserved 0x03 / 0x04) | reached через каждое higher-level decoder coverage |

**Verdict.** Trivial.

### `NamespaceKind::from_u8` ([tx/commit.rs:74](../../../crates/hidden-volume/src/tx/commit.rs))

Single-byte R-NSKIND discriminator (0 = Kv, 1 = Log).

| Boundary | Defending code | Test |
|---|---|---|
| Unknown discriminator | line 74-80: `Err(Malformed("unknown namespace kind discriminant"))` | covered через `CommitPayload::decode` proptest |

**Verdict.** Trivial.

## Boundary classes (summary)

| Class | Decoders affected | Defense pattern | Coverage |
|---|---|---|---|
| Truncation (too few bytes) | каждый decoder | length check + early return | proptest Phase 1 |
| Exact-length mismatch | Plaintext, Header, Argon2Params, Superblock | exact `==` check | covered |
| Bad discriminator | Plaintext (kind), CommitPayload (kind), IndexNode (node_type), ChunkKind, NamespaceKind | match arm + Err | covered |
| Pre-allocation amplifier (G2, G3) | LeafNode, InternalNode, CommitPayload, decode_batch | `num × MIN_ENTRY ≤ body` upfront | covered (G2 / G3 closures) |
| Per-entry length OOB | LeafNode, InternalNode, decode_batch | per-step length check | covered |
| Per-entry value-length cap | LeafNode (MAX_VALUE_LEN), decode_batch (MAX_LOG_PAYLOAD_LEN) | const check | covered |
| Sortedness violation | LeafNode, InternalNode, CommitPayload | `windows(2)` post-decode loop | covered |
| Zero-count structural-invalid | InternalNode (`num_children == 0`) | L1 reject | covered |
| Compression bomb | decode_batch | M5 streaming cap | covered |
| Non-zero reserved bits / flags | Plaintext (flags), Argon2Params (reserved bits 24..32) | byte check + Argon2Params::validate | covered |

**0 boundary classes uncovered.**

## Что насчёт post-AEAD-success malformed plaintext?

Теоретическая concern'а: AEAD-decrypt succeeds на bytes WE wrote
(через writer-side regression) или на torn-write, который
случайно MAC-verifies (2⁻¹⁰⁰ — астрономическая). В этом случае
decoder получает malformed-but-AEAD-blessed bytes. Target
`decoder_family.rs` cargo-fuzz и `parser_fuzz.rs` proptest
намеренно bypass'ят AEAD и feed'ят decoder'ам arbitrary bytes —
так что любой post-AEAD malformed plaintext, который мог бы
достичь decoder'а, в input-distribution, которую fuzzer'ы
explore'ят.

Это *правильная* fuzzing strategy: AEAD provably hard для fuzz
directly (атакующий нуждается в ключе), так что layer ниже AEAD
fuzz'ится с arbitrary inputs как proxy для «любой bit-pattern,
который buggy writer или астрономическая-MAC-collision могла бы
произвести».

## Coverage error-message non-leakage

Каждый error-variant, возвращаемый decoder'ами, проверен в
[`audits/side-channel-surface.md` L-2](side-channel-surface.md)
для подтверждения, что никакой variant не интерполирует key
material или content. Только static-labels и numeric-fields.

## Что этот pass НЕ покрыл

- **Differential / state-machine fuzzing.** Я не перечислял state-
  transitions в commit-recovery protocol'е; тесты
  `crash_recovery.rs` + `crash_proptest.rs` covering это
  отдельно.
- **Fuzz harness performance / corpus quality.** Driver'ит ли
  fuzz-corpus все decoder branches с reasonable coverage —
  вопрос для fuzz-framework, не для static-analysis audit'а.
- **External crate fuzz.** RustCrypto / blake3 / zstd-safe /
  proptest — trusted dependencies; мы не fuzz'им ИХ decoder'ы.
- **End-to-end attack narrative** — это [pass-5 threat-model
  challenge](./threat-model-challenge.md) (next и final).

## Recommended actions (v1.x roadmap)

Ничего required. Одно INFO observation tracked выше (FZ-INFO1 re:
CI-failure-on-fuzz-finding gate).

Существующий `decoder_family.rs` cargo-fuzz target — правильная
shape; running его за longer wallclock budget (например,
periodic 30-minute fuzz farm вместо 5-minute smoke run) deepen'ил
бы confidence дальше. Не current bug.
