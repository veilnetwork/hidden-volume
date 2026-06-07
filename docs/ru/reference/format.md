# hidden-volume: формат хранения на диске v3

[🇬🇧 English](../../en/reference/format.md) · 🇷🇺 **Русский**

**Статус.** Pre-freeze. Структура не изменится между текущим моментом
и v1.0; конкретные резервные байты / маркеры версии ещё могут
поменяться. После релиза v1.0 этот документ **заморожен**: любое
дальнейшее изменение раскладки требует нового поколения v4 и
инструмента миграции (см. `docs/ru/guide/migration.md`).

Этот документ — каноническая, побайтовая спецификация формата на
диске. `DESIGN.md` описывает обоснование и проектные решения; этот
файл — «что реально лежит на диске», структурирован для рецензентов
и сторонних реализаторов.

Если что-то здесь противоречит `DESIGN.md`, этот документ имеет
приоритет в **фактах формата**; `DESIGN.md` имеет приоритет в
**инвариантах и модели угроз**.

## 1. Раскладка верхнего уровня

Файл container — это непрерывная последовательность chunk'ов
фиксированного размера:

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

Где:

- `CHUNK_SIZE = 4096` байт (константа, не закодирована — неявно
  определяется версией формата).
- `N` = количество chunk'ов ≥ 0. Размер файла строго равен
  `(1 + N) * CHUNK_SIZE` байт.
- Первый chunk (offset 0..4096) — это header.
- Каждый последующий chunk имеет slot-индекс `i ∈ [0, N)`.

### 1.1 Header (первые 4 KiB)

```
offset 0..32   container_salt    32 random bytes (KDF salt; cleartext)
offset 32..48  argon2_params     16 bytes, structured (§1.2)
offset 48..4096 padding          uniform random (visually identical
                                  to slot ciphertext)
```

**Изменение в v3 (закрывает D1-A2).** 32-байтовое поле
`container_id`, которое в v2 занимало offset 32..64, **удалено из
открытого header'а**. Теперь оно дeriviтся **per-space** из
versioned master key внутри
[`crate::crypto::derive::SpaceKeys::from_master`] — в открытом
header'е нет ни одного per-space идентификатора. Это закрывает
D1-A2 fingerprint signature, указанный в
`docs/ru/security/threat-model.md` (single-snapshot distinguisher
«у этого файла форма `salt ‖ container_id ‖ argon2_params`»).

**Инварианты.**

- Файл ОБЯЗАН быть размером не менее `CHUNK_SIZE` байт (то есть
  header всегда присутствует).
- Размер файла ОБЯЗАН быть кратным `CHUNK_SIZE`. Файл с
  невыровненным хвостом отклоняется (`Error::Malformed`).
- Все байты вне открытого header (offset 0..48) ОБЯЗАНЫ быть
  статистически неотличимы от равномерно случайных для наблюдателя
  без пароля.
- Других открытых полей нет. **Никаких magic bytes, никакого
  маркера версии формата, никакого счётчика chunk'ов в открытом
  виде.** Версия формата неявная (этот документ) и связана с
  правилами чтения потребляющей библиотеки. Argon2 `params_version`
  u32 несёт `format_version` в младших 16 битах (§1.2), но сам по
  себе не является magic-маркером.

### 1.2 Кодирование параметров Argon2 (16 байт по offset 32..48)

```
offset 32..36  m_cost_kib     u32 LE   (memory in KiB)
offset 36..40  t_cost         u32 LE   (iterations)
offset 40..44  p_cost         u32 LE   (parallelism lanes)
offset 44..48  params_version u32 LE   (упаковано; см. bit-layout ниже)
```

`params_version` u32 — **упакован** (audit pass 8 S1 full):

| биты   | поле                       | семантика                                                                                                                                                                                                                                                                  |
|--------|----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0..16  | `format_version`           | Сейчас `3` (v3 cluster: #8 kind-tag bytes + #9 cryptographic version-binding + #10 per-space derived `container_id`). Библиотека отказывается открывать при любом другом значении. v1/v2 контейнеры не читаются v3-readers; pre-1.0 — breaking приемлемо. |
| 16..24 | `padding_policy_index`     | Персистентный post-commit padding policy. `0` = `None` (default); `1` = 256 KiB buckets; `2` = 1 MiB buckets (DEFAULT preset); `3` = 16 MiB buckets. Неизвестные значения (4..=255) молча деградируют до `None` для forward-compat.                                          |
| 24..32 | reserved                   | ОБЯЗАНЫ быть `0`. Библиотека отбраковывает open, если любой из этих битов выставлен. Будущее планирование версии формата может их использовать.                                                                                                                              |

- `format_version = 3` означает: Argon2id v0x13 (RFC 9106) +
  цепочка деривации BLAKE3 из §3 (включая v3 post-Argon2
  version-bind step и per-space `container_id` derive) + раскладка
  CommitPayload из §4.3 (per-root байт `kind`, не изменился с v2).
- `m_cost_kib`, `t_cost`, `p_cost` ОБЯЗАНЫ быть ≥
  `Argon2Params::MIN` (m=8 MiB, t=2, p=1). Библиотека отказывается
  открывать или создавать container с более слабыми параметрами.
  Симметричные потолки — 1 GiB / 100 / 64 — закрывают DoS через
  cleartext-header, где tampered-поле заставляло бы следующего
  opener'а уйти в multi-TiB Argon2id-аллокацию.
- Более старые v1 (pre-pass-13) и v2 (post-pass-13) контейнеры
  ОТВЕРГАЮТСЯ v3-readers'ами потому что `format_version != 3`.
  Отказ теперь **двойной**: и `Argon2Params::validate`-политика, и
  v3 криптографическая привязка версии из §3 — гипотетический
  v4-reader, который ослабил бы `validate`, всё равно вычислил бы
  *другой* master_key для того же пароля+salt'а, потому что
  `params.version` свёрнут в master key.
- Байт persistent padding-policy раньше не аутентифицировался;
  в v3 он **связан в derivation `master_key`** (потому что
  `params.version` проходит через post-Argon2 BLAKE3 step, а
  `padding_policy_index` живёт в битах 16..24 этого u32). T2
  file-modify-adversary, который переворачивает
  `padding_policy_index`, теперь приводит к `Error::AuthFailed` на
  следующем open — F-PAD из «silent privacy degradation»
  превращается в «DoS-class видимый отказ». См.
  `docs/ru/security/threat-model.md` §4.1.

## 2. Формат chunk'а

Каждый chunk имеет ровно `CHUNK_SIZE = 4096` байт. На диске байты
не интерпретируются без правильного per-slot ключа — открытых
полей в каждом chunk нет.

### 2.1 Wire layout (4096 байт)

```
offset 0..24      nonce       24 bytes, uniform random (XChaCha20 nonce)
offset 24..4080   ciphertext  4056 bytes (XChaCha20-Poly1305 output sans tag)
offset 4080..4096 tag         16 bytes (Poly1305 authentication tag)
```

- Входной plaintext для XChaCha20-Poly1305 имеет ровно
  `PLAINTEXT_LEN = CHUNK_SIZE - NONCE_LEN - TAG_LEN = 4056` байт
  (§2.2).
- AAD = `container_id || u64_le(slot_index)`, всего 40 байт (§2.3).
  Теперь `container_id` — это **per-space derived** значение (§3),
  а не поле, читаемое из открытого header'а.

### 2.2 Раскладка plaintext (4056 байт, никогда не видна без ключа)

```
offset 0..4    magic        b"HVC1" (4 bytes)
offset 4       kind         u8 (ChunkKind, §2.4)
offset 5       flags        u8 (reserved, MUST be 0 in v3)
offset 6..14   seq          u64 LE (per-space monotonic counter)
offset 14..16  payload_len  u16 LE (≤ PAYLOAD_CAP = 4040)
offset 16..16+payload_len   payload    (kind-specific encoding, §4)
offset 16+payload_len..4056 plaintext padding (uniform random)
```

`PAYLOAD_CAP = PLAINTEXT_LEN - 16 = 4040` байт.

Поле `magic` — это sanity-проверка только после AEAD-decrypt, никогда
не видимая без ключа. Если AEAD проходит, но `magic ≠ b"HVC1"`,
chunk отклоняется как `Error::Malformed`.

### 2.3 Построение AAD

```
AAD = container_id (32 bytes) || slot_index (u64 LE, 8 bytes)
    = 40 bytes
```

Это связывает ciphertext каждого chunk с конкретной парой
(space, slot). Перенос ciphertext в другой slot или в другой
container ломает AEAD-decrypt. **Усиление в v3.** Так как
`container_id` теперь per-space derived (разные spaces в одном и
том же контейнере имеют разные `container_id`s), а сам master key
привязан к версии, cross-container chunk relocation закрыта двумя
независимыми барьерами: разные `container_salt` ⇒ разные
`master_key` ⇒ разные `container_id` ⇒ несовпадение AAD ⇒
AEAD-decrypt fail.

### 2.4 Значения ChunkKind (u8, offset 4 в plaintext)

| Value | Name | Payload encoding | Section |
|---|---|---|---|
| `0x01` | `Superblock` | per-space root, latest commit pointer | §4.1 |
| `0x02` | `IndexNode` | KV-index B+ tree node (Leaf or Internal) | §4.2 |
| `0x03` | `Data` | reserved (legacy v0.1 single-record API) | — |
| `0x04` | `Journal` | reserved (intent-log; not emitted in v3) | — |
| `0x05` | `Commit` | per-Tx root commit | §4.3 |
| `0x06` | `DataBatch` | zstd-compressed log batch | §4.4 |

Прочие значения: отклоняются как `Error::Malformed`.

### 2.5 Garbage chunks

Chunk, который не AEAD-decrypt'ится ни под одним ключом ни одного
space, является **garbage chunk**. Байты — равномерно случайные;
plaintext отсутствует. Garbage chunks записываются:

- Начальный мусор (`ContainerOptions::initial_garbage_chunks` при
  создании).
- Padding после commit (`PaddingPolicy::{BucketGrowth, FixedRatio}`
  в `Space::commit_tx`).
- Tombstone scrub (`scrub_slot` на ранее принадлежавшем slot).

Garbage chunks вносят вклад в D1 (single-snapshot
indistinguishability), делая размер файла и содержимое каждого
chunk неинформативными.

## 3. Расписание ключей (v3)

```text
// Stage 1: Argon2id над (password, container_salt, argon2_params).
argon_out      = Argon2id(password, container_salt, argon2_params)
                                                 -> 32 bytes (Zeroizing)

// Stage 2 (v3 #9): криптографическая привязка format-version.
versioned_master = BLAKE3-keyed(
    argon_out,
    b"hv/v3/master" || u32_le(params.version)
)                                                -> 32 bytes (Zeroizing)
            // 12-байтовый ASCII label || 4-байтовая LE-версия = 16-байтовый вход

// Stage 3 (v3 #8 + #10): per-space derivation подключей. Каждый
// subkey деривируется с kind-tag байтом 0x01 (SUBKEY_KIND_TAG),
// префиксуемым к context-label'у, заменяя pre-v3 length-
// distinguishes convention.
container_id   = BLAKE3-keyed(
    versioned_master,
    [0x01] || b"hv/v3/container_id"
)                                                -> 32 bytes (в SpaceKeys)

aead_root      = BLAKE3-keyed(
    versioned_master,
    [0x01] || b"hv/v3/aead_root"
)                                                -> 32 bytes (Zeroizing)

// Stage 4: per-slot AEAD key. v3 #8 kind-tag 0x02 отличает этот
// вход от subkey-входов выше.
chunk_key(slot) = BLAKE3-keyed(
    aead_root,
    [0x02] || container_id || u64_le(slot)
)                                                -> 32 bytes (Zeroizing)
                  // 1 + 32 + 8 = 41-байтовый stack-вход
```

- `argon_out` и `versioned_master` дропаются сразу после
  использования; в per-space структуре `SpaceKeys` (которая
  `ZeroizeOnDrop`) удерживаются только `container_id` и `aead_root`.
- BLAKE3-keyed: `blake3::Hasher::new_keyed(&key).update(input).finalize()`
  усечённый до 32 байт.
- Все производные ключи — `Zeroizing<[u8; 32]>` в месте вызова.
  `SpaceKeys` выводит `ZeroizeOnDrop`.
- Параметры Argon2id берутся из открытого header (§1.2).
- Context-labels (`b"hv/v3/master"`, `b"hv/v3/container_id"`,
  `b"hv/v3/aead_root"`) — это **стабильные domain-separation
  теги**. Изменение любого из них = все существующие v3-контейнеры
  нечитаемы. Сегмент «v3» одновременно является маркером версии
  формата: любое поколение v4 будет использовать
  `b"hv/v4/master"` и т.д., поэтому cross-version key reuse
  криптографически закрыт (v3-пароль вычислит *другой* master_key,
  чем v4-пароль над тем же `container_salt`).

**Зачем kind-tag-байты.** Pre-v3 domain separation между
`derive_subkey` и `derive_chunk_key` опиралась на то, что длина
входа разная (audit pass 7 D3 документировал эту конвенцию, но не
обеспечивал её). v3 #8 делает kind явным: `0x01` для любой
subkey-derivation, `0x02` для любой per-slot AEAD-key derivation.
Будущие BLAKE3-keyed входы в этой же key chain ОБЯЗАНЫ брать новые
kind-tag-байты из того же byte-namespace.

## 4. Кодирование payload по типам

### 4.1 Superblock (`kind = 0x01`)

```
offset 0..8    seq        u64 LE
offset 8..16   root_slot  u64 LE   (slot of the latest Commit chunk,
                                    or u64::MAX for empty space)
offset 16..48  root_hash  32 bytes (Merkle root over Commit's roots)
```

Всего: 48 байт. Несколько реплик Superblock с одним и тем же `seq`
пишутся за Tx (по умолчанию `superblock_replicas = 3`); recovery
выбирает любую AEAD-decryptable реплику с наибольшим `seq`.

`root_hash` — это BLAKE3 над конкатенацией
`IndexRoot.payload_hash` для каждого namespace в последнем Commit
(§4.3) — это Merkle root текущего состояния.

`root_slot = u64::MAX` (константа `NO_RECORD`) означает «commit'а
ещё нет»; это состояние свежесозданного space до любых Tx commit.

### 4.2 IndexNode (`kind = 0x02`)

Узел B+ tree. Два варианта:

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

Ограничения:

- `key_len` ∈ [1, 256].
- `value_len` ∈ [0, 2048].
- Записи ОБЯЗАНЫ быть отсортированы по возрастанию `key` и попарно
  уникальны.
- Полный закодированный размер ≤ `PAYLOAD_CAP` (4040).

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

Ограничения:

- `child_count` ≥ 2.
- `first_key`s ОБЯЗАНЫ строго возрастать.
- Полный закодированный размер ≤ `PAYLOAD_CAP`.

Дискриминатор Internal-vs-Leaf — это первый байт (`0x01` /
`0x02`); прочие значения: `Error::Malformed`.

### 4.3 CommitPayload (`kind = 0x05`) — v3 layout

Wire-форма идентична v2 (R-NSKIND, audit pass 13). v3 не трогал
эту кодировку — только key-schedule выше и раскладку открытого
header'а. Per-root байт `kind` не изменился.

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

Ограничения:

- Корни ОБЯЗАНЫ быть отсортированы по возрастанию `namespace` и
  попарно уникальны (один корень на namespace).
- `kind` ОБЯЗАН быть `0` (Kv) или `1` (Log). Дискриминанты `2..=255`
  зарезервированы; декодеры ОБЯЗАНЫ упасть с `Error::Malformed` при
  чтении любого неизвестного дискриминанта. Kind enforce'ится
  cross-Tx через `Space::commit_tx`: namespace, установленный как
  `Kv`, не может быть append'нут как `Log` в более поздней Tx (и
  наоборот); это закрывает audit pass 12 HIGH «mixed-namespace
  data loss» finding.
- `tx_root_hash` ОБЯЗАН равняться
  `BLAKE3(concat(roots[i].payload_hash))`, пересчитанному при
  чтении. Несовпадение ⇒ `Error::IntegrityFailure` во время
  `verify_integrity`.
- Полный закодированный размер: `2 + 42 * root_count + 32`. При
  `PAYLOAD_CAP = 4040` — ≤ 95 namespaces в одном Commit.
- v1/v2 (pre-v3) контейнеры нечитаемы v3-реализациями, потому что
  `Argon2Params::validate` отбраковывает `format_version != 3` на
  open'е И потому что v3 cryptographic version-bind step из §3
  дeriviт другой master key.

### 4.4 DataBatch (`kind = 0x06`)

zstd-level-3 сжатие следующей сырой раскладки:

```
raw layout (input to zstd):
    offset 0..4   num_records u32 LE
    for i in 0..num_records:
        log_id      u64 LE
        payload_len u32 LE
        payload     payload_len bytes
```

Ограничения (raw, до сжатия):

- `num_records` ∈ [1, `MAX_RECORDS_PER_BATCH = 1024`].
- `payload_len` ∈ [0, `MAX_LOG_PAYLOAD_LEN = 8192`].
- Сжатый результат ОБЯЗАН помещаться в `PAYLOAD_CAP = 4040` байт
  после zstd; превышение → `Error::PayloadTooLarge`.

На каждый DataBatch ссылается KV-index namespace через 8-байтовый
LE slot-указатель:

```
KV value for log entry: u64 LE = batch_slot
KV key for log entry:   u64 BE = log_id (big-endian for natural sort order)
```

## 5. Протокол commit Tx (write path)

Успешный commit Tx ОБЯЗАН выполнить следующую последовательность
(DESIGN §6 + `src/space/mod.rs::commit_tx`):

1. **Phase 0** (log namespaces): для pending batch каждого
   непустого log namespace — закодировать + zstd-compress, добавить
   chunk `DataBatch`, и направить KV `put` для
   `log_id_key → batch_slot_value` в pending KV ops этого
   namespace.
2. **Phase 1** (KV indexes): для каждого затронутого namespace
   перестроить B+ tree из prior + pending ops, добавить каждый
   chunk IndexNode (Leaf и Internal), записать
   `(namespace, root_slot, payload_hash)`.
3. **fsync barrier 1.** Все data + index chunks устойчивы.
4. **Phase 2**: закодировать `CommitPayload` из нового
   `IndexRoot[]`, добавить chunk `Commit`.
5. **fsync barrier 2.** Указатель commit устойчив.
6. **Phase 3**: построить новый
   `Superblock { seq, root_slot, root_hash }`, добавить
   `superblock_replicas` его копий (по умолчанию 3, атомарно одним
   fsync).
7. **fsync barrier 3.** Новый superblock(и) устойчив; новое
   состояние с этого момента — текущее.
8. **Phase 4** (опционально): post-commit padding chunks по
   `PaddingPolicy`, один fsync если они есть.

Контракт восстановления после сбоя (§7 DESIGN, кратко):

- Сбой до barrier 1: ничего не изменилось; повторное открытие
  видит предыдущее состояние.
- Сбой между barrier 1 и barrier 2: tail-orphan IndexNode +
  частичные chunks DataBatch остаются на диске, но недостижимы из
  любого Superblock; повторное открытие откатывается к предыдущему
  состоянию.
- Сбой между barrier 2 и barrier 3: orphan-chunk Commit
  существует, но новый Superblock не устойчив; повторное открытие
  откатывается.
- Сбой после barrier 3: новое состояние устойчиво; повторное
  открытие его видит.

Three-fsync floor: commit занимает не менее ~5 мс на современных
SSD из-за трёх barrier.

## 6. Discovery scan (open path)

Имея `(container_salt, argon2_params)` из открытого header (в v3
`container_id` больше нет в header, см. §1.1) и кандидат
`password`:

1. `argon_out = Argon2id(password, container_salt, argon2_params)`.
2. Вычислить `versioned_master = BLAKE3-keyed(argon_out, b"hv/v3/master" || u32_le(params.version))`.
3. Вывести `container_id` и `aead_root` по §3 (каждый через
   `derive_subkey(versioned_master, ...)`).
4. Для `slot = 0..N` (где `N = (file_size / CHUNK_SIZE) - 1`):

    a. Прочитать chunk по offset `(1 + slot) * CHUNK_SIZE`.

    b. Вычислить `chunk_key(slot)` по §3.

    c. Попробовать AEAD-decrypt с ключом + AAD = `container_id || u64_le(slot)`.

    d. При успехе: распарсить plaintext (§2.2), записать `(slot, kind, seq)`. Отбросить байты plaintext.

5. Среди AEAD-успешных chunks Superblock выбрать тот, у которого
   наибольший `seq`. Восстановленное состояние файла для этого
   space — это его `(seq, root_slot, root_hash)`. Если ни одного
   Superblock не найдено ⇒ `Error::AuthFailed`.
6. Опционально: построить `commit_history = sort_dedup(all SB seqs)`
   и `owned_slots = sort(all AEAD-successful slots)` для downstream
   API.

**Инвариант deniability.** Шаг 4 выполняет ровно `N` AEAD-попыток
независимо от per-space результата. Успешные и неуспешные decrypts
неотличимы для внешнего наблюдателя (constant-time проверка tag
внутри AEAD из RustCrypto; никакого ветвления в логировании;
одинаковый return-path по `Error::AuthFailed`). Именно это даёт
формату поддержку deniability T2/T3 — см.
`docs/ru/security/threat-model.md` §3 D1/D2.

**TM1 timing-equalization (v1.0, отгружено 2026-05-28).** Разница
work-amount между MAC-pass и MAC-fail путями на каждом chunk —
это F-TM1 residual. Все три scan-режима имеют constant-time
companion'ы: `Container::open_space_constant_time` (sequential),
`Container::open_space_parallel_constant_time` (parallel-scan),
`Container::open_space_mmap_constant_time` (mmap). Каждый
прогоняет ChaCha20 stream над `body_len` байтами на каждом chunk,
выравнивая доминирующую часть стоимости. Они НЕ выравнивают
allocation/parsing overhead — host-apps, которым нужна более
сильная гарантия, должны запрашивать одинаковые Argon2-параметры
на каждый open и padd'ить post-open обработку извне.

## 7. Cross-version policy

| Reader \ File | v1 | v2 | v3 | future v4 |
|---|---|---|---|---|
| v1            | OK (legacy)   | reject | reject | reject |
| v2            | reject | OK     | reject | reject |
| **v3** (текущий) | reject | reject | **OK** | reject |
| v4            | reject | reject | reject | OK |

Cross-version reject **двойной** в v3:

1. **Политика.** `Argon2Params::validate` отбраковывает любое
   `format_version != PARAMS_VERSION` на open'е. Закодировано в
   [`crates/hidden-volume/src/crypto/kdf.rs`](../../../crates/hidden-volume/src/crypto/kdf.rs).
2. **Криптография.** Post-Argon2 BLAKE3 step (§3 Stage 2) свёртывает
   `params.version` в `master_key`. Гипотетический reader, который
   ослабил бы политику-gate, всё равно вычислил бы *другой*
   `master_key`, чем writer, запечатавший файл, и упал с
   `Error::AuthFailed` на первой же AEAD-попытке.

In-place миграция не предоставляется. Чтобы перенести данные из
контейнера vN в контейнер vM (где M ≠ N), host-app должен:

- Открыть источник vN-совместимой сборкой библиотеки.
- Экспортировать каждый namespace через `Space::list` (KV) и
  `Space::iter_log` (Log).
- Создать свежий vM-контейнер.
- Импортировать обратно каждый namespace.

См. `docs/ru/guide/migration.md` для процедуры.

## 8. Format-level константы

| Constant | Value | Purpose |
|---|---|---|
| `CHUNK_SIZE` | 4096 | Chunk size in bytes. Implicit; not in header. |
| `HEADER_LEN` | 48 | Cleartext header bytes (salt 32 + params 16). v2 был 80; v3 убрал поле `container_id` из cleartext (теперь per-space derived). |
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
| `params_version.format_version` | 3 | Поколение on-disk формата; кодируется в младших 16 битах 4-байтного `params.version` (§1.2). v3-читатели отказываются открывать v1/v2-файлы, а v3-читатели отвергаются гипотетическими v4-читателями. |
| `argon2_floor` (`Argon2Params::MIN`) | m=8 MiB, t=2, p=1 | Refuse-to-open threshold. |
| `Argon2Params::MAX_M_COST_KIB` / `MAX_T_COST` / `MAX_P_COST` | 1 GiB / 100 / 64 | Refuse-to-open ceilings (audit pass 1 D1). |
| `MAX_OPEN_SCAN_CHUNKS` | 16 × 1024 × 1024 (= 64 GiB при `CHUNK_SIZE`) | Жёсткий cap на slot-grid (audit pass 16 TM1 / audit pass 17 B). |
| `MAX_TREE_DEPTH` | 3 | Жёсткий cap на глубину B+ tree, используемый всеми walker'ами (Space::get, list, log_iter, integrity, vacuum). Pathological cyclic Internal→Internal chain валится `Error::Malformed("tree depth exceeded MAX_TREE_DEPTH")` после максимум этого числа спусков. Writer-side инвариант гарантирует depth ≤ 2 в well-formed контейнерах. |

## 9. Резервные байты (forward-compat)

Формат резервирует следующие байты под **не ломающие** расширения
в рамках v3 (то есть библиотека v3.x ОБЯЗАНА отказывать в чтении
container, в котором установлены резервные байты, но будущая
v3.y > v3.x МОЖЕТ задать им новый смысл, и существующие библиотеки
v3.x в этом случае ОБЯЗАНЫ отказать в открытии):

- **Байт `flags` plaintext-frame** (offset 5 в plaintext, §2.2).
  Сейчас ОБЯЗАН быть 0. Любое будущее использование — это
  v3-внутренняя опциональная фича с fall-back путём по kind /
  версии.
- **Резервные биты 24..32 у Argon2 `params_version`** (§1.2).
  Сейчас ОБЯЗАНЫ быть 0. Будущее планирование версии формата
  может их использовать; до тех пор любое ненулевое значение
  отвергается.

Любое ломающее изменение за пределами этих резервов вынуждает
поколение v4; см. cross-version policy в §7 выше.

## 10. Чего НЕТ в формате

- **Никаких magic bytes.** В открытом header их нет. `b"HVC1"`
  plaintext-frame — это только post-AEAD; он не помогает внешнему
  наблюдателю определить тип файла.
- **Никакого маркера версии формата в открытом виде (как
  отдельного маркера).** `params_version` — ближе всего, но он
  упакован внутри Argon2-params-слова; v3 также связывает его
  криптографически в `master_key`, так что бит-флип деградирует
  до `Error::AuthFailed`.
- **Никакого per-space идентификатора в открытом виде (v3 #10).**
  v2 хранил `container_id` по offset 32..64; v3 его убрал. Разные
  spaces внутри одного контейнера имеют разные `container_id`s,
  деривированные в памяти на момент open'а. T1 single-snapshot
  наблюдатель больше не видит per-space fingerprint.
- **Никакого размера файла в header.** Выводится из
  `metadata().len()`.
- **Никакого глобального счётчика chunk'ов.** Выводится как
  `(file_size / CHUNK_SIZE) - 1`.
- **Никакого глобального оглавления.** Discovery — через
  trial-decrypt.
- **Никаких timestamps.** Нигде. (Timestamps утекали бы паттерны
  активности противникам T2.)
- **Никаких метаданных host-приложения.** Кастомные namespaces
  (1+) определяются приложением; зарезервированные namespaces
  (0..=4) перечислены в `src/space/index.rs`.

## 11. Audit-чеклист для рецензентов

1. § 1: раскладка header (48 байт), случайность salt, парсинг
   params; подтвердить отсутствие `container_id` в открытом header.
2. § 2: chunk wire layout, входы AEAD, построение AAD (с per-space
   derived `container_id`), sanity-проверка magic.
3. § 3: цепочка деривации ключей. Подтвердить:
    - Stage 2 `b"hv/v3/master" || u32_le(version)` BLAKE3 step
      есть в [`crypto/kdf.rs::derive_master_key`](../../../crates/hidden-volume/src/crypto/kdf.rs);
    - Stage 3 `[0x01] || context` kind-tag prefix есть в
      [`crypto/derive.rs::derive_subkey`](../../../crates/hidden-volume/src/crypto/derive.rs);
    - Stage 4 `[0x02] || container_id || u64_le(slot)` есть в
      [`crypto/derive.rs::derive_chunk_key`](../../../crates/hidden-volume/src/crypto/derive.rs);
    - тестовые векторы в `tests/parser_fuzz.rs`.
4. § 4: кодирование payload по типам, особенно инвариант
   `tx_root_hash` для CommitPayload.
5. § 5: упорядочивание из 3 fsync-barrier присутствует в коде
   (cross-check `src/space/mod.rs::commit_tx` +
   `docs/ru/security/audits/fsync.md`).
6. § 6: discovery scan — это O(N) AEAD-попыток, без
   `kind`-условного ветвления, которое отличало бы wrong-password
   от no-such-space на уровне таймингов.
7. § 7: cross-version reject **двойной** (политика + криптография).
8. § 8: format-константы соответствуют исходникам `src/lib.rs` и
   `src/chunk/format.rs`.
9. § 9: резервные байты проверяются / отвергаются как
   задокументировано.
10. § 10: нет утечки открытого поля сверх §1.

## 12. Перекрёстные ссылки

- `DESIGN.md` — обоснование, модель угроз, проектные решения.
- `docs/ru/security/threat-model.md` — формальные инварианты
  (D1 / D2 / I1-3 / R1 / M1 / C1), защищаемые этим форматом.
- `docs/ru/security/audits/constant-time.md`,
  `docs/ru/security/audits/memory.md`,
  `docs/ru/security/audits/plaintext.md`,
  `docs/ru/security/audits/fsync.md` — заметки аудита уровня
  реализации.
- `docs/ru/guide/migration.md` — процедура перехода vN → vM.
- Source: `src/chunk/format.rs`, `src/container/header.rs`,
  `src/crypto/kdf.rs`, `src/crypto/derive.rs`,
  `src/space/superblock.rs`, `src/space/index.rs`,
  `src/space/log.rs`, `src/tx/commit.rs`.
- Tests: `tests/parser_fuzz.rs`, `tests/header_params.rs`,
  `tests/v3_key_schedule.rs` (v3 регрессионные инварианты).

## 13. Журнал изменений формата

| Version | Date | Change | Document |
|---|---|---|---|
| v1.0 | (project start) | Initial layout. | this document (historical) |
| v2 | 2026 audit pass 13 (R-NSKIND) | `CommitPayload` per-root вырос с 41 → 42 байт (добавлен байт `kind`, различающий Kv от Log). | this document (historical) |
| **v3** | **2026-05-28** | **#8 kind-tag bytes** (`derive_subkey` 0x01 / `derive_chunk_key` 0x02), **#9 криптографическая привязка версии** (post-Argon2 BLAKE3 над `params.version`), **#10 per-space derived `container_id`** (убран из cleartext header). `HEADER_LEN`: 80 → 48. | this document (current) |
| v4 (planned) | TBD | Первое post-1.0 поколение. Требует явного решения о format-freeze policy. | TBD |
