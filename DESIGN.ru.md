# hidden-volume — design

[🇬🇧 English](DESIGN.md) · 🇷🇺 **Русский**

Формализация идеи deniable multi-space контейнера. Документ — источник правды
для реализации; код должен ссылаться на инварианты по номерам.

## 0. Scope и не-цели

**В scope:**
- Один файл-контейнер на диске.
- Несколько независимых пространств (spaces), каждое со своим паролем.
- Append-only запись, AEAD per-chunk, per-space encrypted superblock + index.
- Crash-safe commit, локализация повреждений в пределах открытого пространства.

**Не цели (важно зафиксировать ожидания):**
- Не скрываем сам факт того, что файл зашифрован. Файл из чистой энтропии
  отличим от обычного файла; deniability — про "сколько паролей и какие
  данные внутри", а не про "файл не выглядит шифром".
- Не защищаем от утечек на уровне приложения (recently-opened, thumbnails,
  IME, swap, system logs). Это ответственность хост-приложения.
- Не делаем сетевую синхронизацию в этом крейте.
- Не делаем `async`. Ядро — синхронное, std-only. Async-обёртка — отдельным крейтом.

## 1. Threat model

> Полная формальная версия threat model'а — `docs/en/security/threat-model.md`
> (для external crypto review). Ниже — concise summary для DESIGN
> readers; при расхождениях между двумя документами `THREAT_MODEL.md`
> детальнее, но invariants остаются те же.

**Adversary capabilities:**
1. Однократный snapshot файла-контейнера.
2. Множественные snapshots файла во времени (rollback / forensic timeline).
3. Принуждение к выдаче *одного* пароля.

**Свойства, которые должны держаться:**
- **D1 — Single-snapshot indistinguishability**: имея только файл, противник
  не может отличить контейнер с N пространствами от контейнера с M
  пространствами (для любых N, M ≥ 1) при фиксированном размере файла.
- **D2 — Compelled-key plausible deniability**: предъявив пароль для space A,
  пользователь может правдоподобно утверждать, что других пространств нет.
  Противник, имея файл и пароль A, не должен иметь криптографических
  доказательств существования space B.
- **I1 — Per-chunk integrity**: любая модификация байт chunk обнаруживается
  при попытке расшифровать его соответствующим ключом.
- **I2 — Tail-corruption tolerance**: повреждение хвоста файла откатывает
  пространство к последнему валидному checkpoint, не теряя его целиком.
- **I3 — Cross-space isolation**: владелец space A не может ни читать, ни
  целенаправленно повредить space B. Случайно — может (см. §6).

**Out of scope угрозы:**
- Multi-snapshot diffing с активным writer'ом (T2): противник видит, что
  файл вырос — это раскрывает только сам факт записи, не содержание и не
  пространство. Маскируется dummy-writes, но это политика, а не свойство.
- **Multi-snapshot per-byte diffing (T2'):** при in-place rewrite или
  tombstone (см. §6) конкретный slot i меняет содержимое между двумя
  снимками файла. Из этого противник заключает "slot i — не garbage,
  он принадлежит активному пространству", сужая множество возможных
  hidden-space слотов. Полная маскировка требует периодической
  перезаписи случайных garbage слотов свежим random'ом, что дорого и не
  даёт идеального покрытия. Принимаем как известное ограничение под T2.
- Side-channel timing на стороне приложения.
- Forensics RAM/swap.

> Note: byte-level wire-format reference is `docs/en/reference/format.md`
> (canonical spec for v1.0 freeze + external crypto review).
> §2-§10 below remain the rationale + design-choice narrative
> pointing at the same byte layout.

## 2. Container layout

```
offset  0   : 32 байта  container_salt          (cleartext, uniform random)
offset 32   : 16 байт   argon2_params           (cleartext, structured)
offset 48   : padding до CHUNK_SIZE             (uniform random)
offset CHUNK_SIZE * (1 + i) : chunk[i]          (i = 0, 1, 2, ...)
```

**v3 изменение (закрывает D1-A2 fingerprint).** 32-байтовое поле
`container_id`, которое v2 хранил по offset 32..64, удалено из
открытого header'а. `container_id` теперь дeriviтся **per-space**
из versioned master key внутри
[`crate::crypto::derive::SpaceKeys::from_master`] — в открытом
header'е нет ни одного per-space идентификатора. См.
[`docs/ru/reference/format.md`](docs/ru/reference/format.md) §1.1.

**Инварианты:**
- `CHUNK_SIZE = 4096` байт (фиксировано на уровне формата). См. §10 про выбор.
- Размер файла всегда кратен `CHUNK_SIZE` и ≥ `CHUNK_SIZE`.
- Все байты файла, кроме первых 48 (salt + params), должны быть
  статистически неотличимы от uniform random для наблюдателя без ключей.
- Никаких других cleartext полей. Ни magic, ни маркера версии формата,
  ни счётчиков.

**container_salt** — единый для всех пространств KDF salt. То, что он один,
не раскрывает пространств: salt — стандартный артефакт любого
password-derived crypto и не считается deniability-leak.

**argon2_params** — параметры Argon2id для этого контейнера (DESIGN §4,
§11.1). Layout (16 байт):

```
offset 32..36  : m_cost_kib    u32 LE   (memory in KiB)
offset 36..40  : t_cost        u32 LE   (iterations)
offset 40..44  : p_cost        u32 LE   (parallelism lanes)
offset 44..48  : params_version u32 LE  (упакован; низшие 16 бит = format_version,
                                          сейчас 3; биты 16..24 = padding-policy
                                          index; биты 24..32 reserved)
```

Не раскрывает структуру пространств — только стоимость одной попытки
brute-force, что у любого encrypted-with-password артефакта так или иначе
видно. Library refuses to open контейнер с `format_version != 3` или
`params < Argon2Params::MIN`. Reject **двойной** в v3: и
`Argon2Params::validate()`-политика, и v3-криптографическая
привязка версии в key schedule (§4) — даже tampered policy gate
дeriviл бы другой master_key. v1 (pre-pass-13) и v2 (post-pass-13)
контейнеры отвергаются; pre-1.0 — breaking приемлемо.

## 3. Chunk format (на диске)

Каждый chunk — ровно `CHUNK_SIZE` байт. На диске никаких полей в открытом
виде нет: всё — один непрерывный блок, который выглядит как uniform random.

Логически chunk состоит из:

```
[ nonce : 24 ] [ ciphertext : CHUNK_SIZE - 24 - 16 ] [ tag : 16 ]
```

- **nonce** — 24 байта, генерируется свежим криптостойким RNG для каждой
  записи. Хранится в открытом виде (в составе chunk-байт). nonce uniform
  random ⇒ внешне неотличим от шума.
- **ciphertext + tag** — XChaCha20-Poly1305(`chunk_key`, `nonce`, `aad`,
  plaintext). AAD = `container_id || u64_le(slot_index)`. `container_id`
  здесь — это **per-space derived** значение (§4), а не поле,
  читаемое из открытого header'а. Привязка к слоту защищает от
  move-attack (перемещение чанка в другой слот).

**Plaintext layout (`CHUNK_SIZE - 40` байт = 4056):**

```
[ magic : 4 ]  = b"HVC1"  // только внутри plaintext, никогда не видим без ключа
[ kind  : 1 ]  // ChunkKind enum
[ flags : 1 ]  // compression, etc.
[ seq   : 8 ]  // per-space monotonic sequence number
[ payload_len : 2 ]  // ≤ payload area
[ payload : up to 4040 ]
[ pad : remainder ]   // random bytes (irrelevant — encrypted away)
```

`magic` нужен только как дешёвая sanity-проверка после decrypt: если AEAD-tag
прошёл, но magic не совпадает, мы либо сломали свой собственный формат, либо
наткнулись на astronomically unlikely collision. Это plaintext-side check;
снаружи magic невидим.

**ChunkKind:**
- `0x01` Superblock — корень пространства.
- `0x02` IndexNode — узел B+ tree (Leaf / Internal) индекса namespace'а KV.
- `0x03` — зарезервирован (это был v0.1-чанк `Data`; заменён per-batch
  encoding'ом внутри `DataBatch`. Декодеры ОБЯЗАНЫ трактовать 0x03 как
  unknown.)
- `0x04` — зарезервирован (это был v0.1-чанк `Journal`; не отгружен —
  vacuum + scrub-old-on-success вытеснили intent-log. Декодеры ОБЯЗАНЫ
  трактовать 0x04 как unknown.)
- `0x05` Commit — маркер завершения Tx; payload — Merkle root над
  IndexRoot'ами per namespace.
- `0x06` DataBatch — zstd-сжатый batch log-записей (см. §11.4 в
  каноническом spec'е `docs/ru/reference/format.md`).

**Garbage chunks**: `CHUNK_SIZE` байт чистого RNG. У них нет ключа и нет
plaintext; они никогда не "расшифровываются успешно" ни одним пространством.

## 4. Key schedule (v3, с 2026-05-28)

```
// Stage 1: Argon2id над (password, container_salt, params).
argon_out        = Argon2id(password, container_salt, params)        // 32B

// Stage 2 (v3 #9): криптографическая привязка format-version.
versioned_master = blake3_keyed(argon_out,
                                "hv/v3/master" || u32_le(params.version))

// Stage 3 (v3 #8 + #10): per-space subkeys c kind-tag байтами.
container_id     = blake3_keyed(versioned_master,
                                [0x01] || "hv/v3/container_id")     // 32B, per-space
aead_root        = blake3_keyed(versioned_master,
                                [0x01] || "hv/v3/aead_root")        // 32B

// Stage 4: per-chunk AEAD key для slot i.
chunk_key(i)     = blake3_keyed(aead_root,
                                [0x02] || container_id || u64_le(i))
```

`argon_out` и `versioned_master` дропаются сразу после использования;
в per-space `SpaceKeys` (которая `ZeroizeOnDrop`) удерживаются только
`container_id` и `aead_root`. Per-slot `chunk_key` пере-вычисляется на
каждом доступе.

**Три v3-харднинга, закодированные в этом schedule** (2026-05-28):

- **#8 kind-tag bytes.** Каждый BLAKE3-keyed вход начинается с
  явного kind-байта: `0x01` (`SUBKEY_KIND_TAG`) для subkey-derivation,
  `0x02` (`CHUNK_KEY_KIND_TAG`) для per-slot-derivation. Заменяет
  pre-v3-конвенцию length-distinguishes.
- **#9 криптографическая привязка версии.** Весь u32 `params.version`
  (format_version + padding_policy_index + reserved) свёртывается в
  `versioned_master` через Stage 2 BLAKE3-step. Cross-version key
  reuse закрыт криптографически, не только `validate()`-политикой.
  Побочный эффект: F-PAD (audit pass 9) переходит из silent
  privacy-degradation в DoS-class видимый отказ — флипнутый
  policy-байт теперь приводит к `Error::AuthFailed`, а не
  безмолвной деградации padding-политики.
- **#10 per-space derived `container_id`.** Открытый header больше
  не несёт `container_id` (закрывает D1-A2 fingerprint).

V0.1-набросок выводил ещё два под-ключа — `space_kdf_key` и
`space_chunk_key` — которые ни один callsite не использовал;
audit pass 1 B1+B2 удалил их, экономя 64 B/space + 1 BLAKE3-
derivation на open.

- **Argon2id parameters**: `Argon2Params::DEFAULT` — `t=3, m=64 MiB, p=1`
  (mobile-friendly). Tunable через `Container::create_with_options`.
  Параметры персистируются в cleartext-header'е по offset'у `64..80`
  (audit pass 8 S1: биты 16..24 поля `version` u32 также кодируют
  персистентный preset padding-policy; см. `docs/ru/reference/format.md` §1.2).
  Library-пресеты: `Argon2Params::LIGHT/DEFAULT/HEAVY`; пол:
  `Argon2Params::MIN` (m=8 MiB, t=2, p=1) — open/create отбраковывают
  всё ниже, что закрывает malicious-host downgrade-атаку.
- **Per-chunk derivation** даёт каждому слоту уникальный ключ; даже если
  один nonce случайно повторится между слотами (вероятность пренебрежимо
  мала на 192-bit), безопасность не страдает.
- Все ключи в `Zeroizing<[u8; 32]>`.

## 5. Space discovery (open path)

Получив пароль:

1. Прочитать `container_salt` и `params` из header (в v3
   `container_id` больше нет в header — он дeriviтся на шаге 3).
2. Argon2id над `(password, container_salt, params)` → `argon_out`.
   Дорого: один раз на unlock, ~100 ms на mobile.
3. BLAKE3-keyed version-bind → `versioned_master`; затем deriviт
   `container_id` и `aead_root` из него (§4).
4. Сканировать слоты `i = 0..N`:
   - вычислить `chunk_key(i)`,
   - попытаться XChaCha20-Poly1305 decrypt с AAD,
   - при успехе — проверить magic, разобрать `kind`/`seq`,
   - сложить в in-memory map по `(kind, seq)`.
5. Выбрать Superblock с максимальным `seq`, который **AEAD-decrypt'ится
   и `Superblock::decode`-парсится** (audit D2 fallback — при decode
   failure walk вниз по seq). `root_hash` выбранного SB **принимается
   на adoption** — цепь `IndexNode + Commit + DataBatch`, достижимая
   из него, проверяется **лениво** при первом чтении, которое её
   затрагивает, или **eagerly**, если host-app вызывает
   [`crate::Container::open_space_verified`](crates/hidden-volume/src/container/mod.rs)
   вместо [`crate::Container::open_space`]. Старые v0.x-доки этого
   шага намекали на eager full-chain validation в `open_space`;
   shipped поведение всегда было ленивым — `open_space_verified`
   является явным opt-in для eager-validation use case
   (например, integrity audit при container restore).
6. Загрузить chunk-map → теперь знаем, какие слоты пространства "живые".

**Стоимость**: N трасс XChaCha20-Poly1305 decrypt. На современном CPU
~5 GB/s ⇒ 1 ГБ контейнер сканируется за ~200 мс. На ARM mobile ~1 с.
Это unlock-time, не per-message; приемлемо.

**Streaming memory** (v0.6): scan не аккумулирует расшифрованные plaintext'ы.
За iteration живёт один ciphertext-чанк (4 KiB stack) и один Plaintext
(≈4 KiB heap), оба умирают до следующей итерации. Из персистентного
state'а копится только `owned_slots: Vec<u64>` (8 B/owned chunk),
`commit_history: Vec<u64>` (8 B/Superblock после dedup), и payload
текущего max-seq Superblock'а (~48 B). Итого — порядка 16 B на каждый
owned chunk вне зависимости от размера контейнера. Это ~250× меньше,
чем хранить все Plaintext'ы во время сканирования; критично для слабых
устройств с большими (мульти-GiB) контейнерами.

**Почему это deniable**: ровно те же N decrypt'ов выполняются и когда других
пространств нет, и когда их три. Тайминг unlock'а одного пространства не
зависит от существования других.

## 6. Append (write path)

Append-only. Запись пространства A:

1. Подготовить набор chunk'ов для транзакции:
   - 0..k DataBatch chunks (zstd-сжатые log-записи; по одному на
     log-namespace, затронутый в этой Tx)
   - 0..m новых IndexNode chunks (B+ tree leaves + internals для KV
     namespaces, затронутых в этой Tx)
   - 1 Commit chunk (Merkle root над per-namespace IndexRoots)
   - 1+ новых Superblock chunks (реплики; по умолчанию 3)
2. Для каждого нового chunk выделить слот: равномерно случайный слот из
   **decoy pool**, если пул не пуст, иначе — следующий за концом файла
   (`N, N+1, ...` из `file_size / CHUNK_SIZE - 1`). Зашифровать с
   `chunk_key(slot)`, записать.
3. **fsync** (3-fsync barrier protocol — DataBatch+Index → Commit → SB).
4. Опционально — досыпать garbage chunks (политика padding, см. §8) и
   перерандомизировать приманки (churn, см. §9.1).

**Inv-W1 (пересмотрен 2026-08-06)**: writer пишет только в слот,
**недостижимый ни из одного суперблока, который может быть выбран при
открытии** — либо дописывая за конец сетки, либо выделяя слот, за
который ручается **decoy pool**. Load-bearing для crash-safety именно
недостижимость, а не append: торн-write не должен ломать chunk, нужный
на recovery-пути, а слот, списанный `vacuum_orphans`, не упомянут ни
одной восстановимой эрой. См. §9.1 — учёт пула, гарантии, которые
переиспользование наследует от vacuum, и единственный вид чанков
(`Checkpoint`), который остаётся append-only.

До 2026-08-06 инвариант читался «writer **только append'ит**», и более
сильная форма давала ровно одно, чего не даёт новая: прямое
доказательство становилось тривиальным. Новая форма обязана доказывать
недостижимость — и делает это, опираясь на уже существующее
доказательство vacuum, а не на новое.

Forward-secrecy — превращение «удалённых» KV-записей и «заменённых»
log-записей в нерекуверабельные — по-прежнему достигается отдельным
проходом **vacuum + scrub-old-on-success** (см. ниже).

(V0.1 design-набросок дополнительно предлагал slot-уровневые операции
`Tx::update_slot` и `Tx::tombstone_slot`. Обе **SKIPPED** в v0.2 —
см. `TASKS.md` — потому что фундаментально конфликтуют с append-only
crash-safety. Use-cases, которые они таргетировали, покрыты vacuum +
scrub. §12 API skeleton historical note фиксирует это вытеснение.)

**Vacuum** (реализация v0.2: `Space::vacuum_orphans`):
  - `commit_tx` остаётся append-only (без scrub'а — нужен для crash recovery fallback'ов).
  - На `Container::open_space` после успешного `scan_and_recover` автоматически вызывается
    `vacuum_orphans`: walk tree из текущего Superblock'а, собрать reachable IndexNode slots,
    scrub'нуть owned-but-not-reachable IndexNode chunks (overwrite uniform random).
  - На `Container::open_space_verified` (audit pass 17 A) auto-vacuum
    **отсрочен** до успешного `verify_integrity` — провалившийся
    integrity-walk оставляет файл нетронутым, сохраняя гарантию
    «no observable mutation on verify failure» для forensics и
    backup-инструментов. При успехе post-verify vacuum восстанавливает
    обычный `open_space` forward-secrecy инвариант.
  - Idempotent — повторный вызов без коммитов между ничего не делает.
  - **НЕ scrub'ит DataBatch chunks** (один batch может содержать ещё-живые записи,
    referenced by other log_ids — это домен v0.3 compaction который умеет batch repack).
  - **НЕ scrub'ит старые Superblock/Commit chunks** — они нужны как fallback'и для
    crash recovery в случае повреждения текущего Superblock'а. v0.3 compaction их сметает.
  - Trade-off: между commit'ом и следующим open'ом forensics с паролем может прочитать
    "удалённые" KV entries. Для типичного app-launch workflow окно невелико; для
    параноидального forward-secrecy host-app может вызвать `vacuum_orphans` явно после
    privacy-sensitive Tx.

**Inv-W2**: Commit chunk должен быть записан и fsync'нут ПОСЛЕ всех его
data/index/journal chunks. Иначе reader откатит транзакцию.

**Inv-W3**: новый Superblock пишется после Commit. Reader выбирает
Superblock с наибольшим seq, чья цепь Commit полностью валидна.

## 7. Recovery

После crash:
1. Сканируем как при open (§5).
2. Среди наших Superblock'ов берём с наибольшим seq, у которого:
   - все referenced IndexNode chunks decrypt'ятся,
   - есть валидный Commit chunk с матчащимся root hash,
   - hash chain до предыдущего checkpoint цел.
3. Если такого нет — берём предыдущий по seq и так далее.
4. Слоты после последнего валидного Superblock считаем "tail garbage" —
   они просто игнорируются. Файл не truncate'им (это бы видно было снаружи
   как сжатие — leak о неуспешной записи).

## 8. Padding policy

Политика — отдельный runtime-config, не часть on-disk формата. Реализации
(см. `src/padding/mod.rs`):

- **`PaddingPolicy::None`** — только реальные chunks. Тесты / debug.
  В production раскрывает реальный темп записи multi-snapshot adversary'у.
- **`PaddingPolicy::BucketGrowth { bucket_chunks }`** — после каждого
  successful Tx commit'а файл дополняется garbage'ом до ближайшего
  кратного `bucket_chunks`. Observer видит file size меняющийся
  дискретными шагами размера `bucket_chunks * CHUNK_SIZE`. Worst-case
  overhead: `bucket_chunks - 1` extra chunks per commit.
- **`PaddingPolicy::FixedRatio { garbage_per_real_x100 }`** — добавляет
  garbage proportional to real chunks: `garbage_per_real_x100 = 100`
  даёт 1:1 (file grows 2× actual data). Smoother growth, без bucket
  quantization.

**Initial garbage** (`ContainerOptions::initial_garbage_chunks`) — сколько
garbage chunks записать при `Container::create_with_options` сразу. Создаёт
видимость "этот файл был ~N MiB всегда". Forensics видит файл размера
`(1 + initial_garbage_chunks) * CHUNK_SIZE` byte-для-byte uniform-random
(кроме 80-байтного header).

**Recommended defaults для типичного messenger deploy:**
- `initial_garbage_chunks = 2048` (8 MiB decoy size — выглядит как small backup)
- `padding_policy = BucketGrowth { bucket_chunks: 256 }` (1 MiB quantization)

**Notes:**
- Padding policy **не персистится в файле** — это runtime-only config.
  Host-app должен re-set'ить через `Container::set_padding_policy` после `open`.
  Нет on-disk поля → нет metadata leak'а о выбранной политике.
- Garbage chunks: `CHUNK_SIZE` байт uniform random. Visually identical to
  AEAD-encrypted chunks of any space. Indistinguishable from real-but-foreign-space data.
- Padding не помогает против T2 per-byte diff (видно какие байты поменялись),
  но помогает против T2 file-size diff. Это два разных канала утечки.

## 9. Compaction

Фундаментальная проблема: writer пространства A не видит чанки B/C/garbage и
не может их различить. Любая операция, удаляющая чанк "не наш", может
уничтожить чужое скрытое пространство.

Под капотом есть ровно один примитив: `repack(passwords) → new_file`
— открыть каждое пространство по соответствующему паролю, скопировать его
живые чанки (по chunk-map) в новый контейнер, остальное (то, что ни один
из переданных ключей не расшифровал) считать удаляемым.

`repack` memory-bounded на обеих ногах. Log-namespaces проходятся
постранично через `iter_log_after(ns, cursor, log_page_size)` (audit
pass 16, R-STREAMING-REPACK), KV-namespaces — через
`list_after(ns, cursor, kv_page_size)` (аудит HV-02); каждая страница
коммитится в destination до чтения следующей. Working-set ≈ 4 MiB на
log-страницу и ≈ 1 MiB на KV-страницу, независимо от размера
namespace.

До HV-02 KV-нога собирала namespace целиком и затем отдавала каждую
пару в `Tx::put`, который её копирует, — пик был вдвое больше
открытого текста namespace. Написано это было под 2-уровневым B+ tree
cap'ом ≈ 5–10 K записей; аудит HV-15 cap снял (индекс растит уровни по
мере надобности), и единственным потолком остался потолок самого
контейнера. Дробить копирование одного namespace на несколько
транзакций назначения здесь безопасно именно потому, что назначение —
файл, созданный этим же вызовом: сбой между страницами оставляет
частичный `dest`, который вызывающий выбрасывает. См.
`docs/ru/contributing/benchmarks.md`. Прежняя реализация держала
все живые записи в памяти на обеих фазах (Phase 1: read all, Phase 2:
write all) — multi-GiB log-namespaces могли OOM'ить хост.

API оборачивает примитив в три явных режима:

- `Container::append_garbage(n)` — только досыпает мусор. Безопасно всегда.
  Файл только растёт; ничего не теряется.

- `Container::compact_known(passwords)` — пользователь сознательно
  жертвует невыданными пространствами. Семантика: "оставь только эти, всё
  остальное — выкинь, я знаю что делаю". Используется в случае
  утери/отзыва пароля одного из пространств.

`compact_known` — единственный отгруженный режим compact'а.
Изначальный v0.1-набросок предлагал ещё `compact_all` ("это ВСЕ пароли;
всё остальное — garbage"); audit pass 2 B7 удалил его, потому что тело
было бит-в-бит идентично `compact_known` — отличалась только формулировка
API, а сама асимметрия формулировок была footgun'ом (пользователь мог
вызвать `compact_all` в неправильном контексте и потерять hidden space).
UI host-app'а — правильное место для семантики "я гарантирую исчерпывающий
список", а не библиотечный API.

Никакого "compact в фоне" и никакого `compact_with_open_space_only` нет
по этой же причине.

### 9.1 Переиспользование слотов и churn приманок

Списанные слоты **переиспользуются**. Этот раздел заменяет
«slot-reuse prohibition», стоявший здесь до 2026-08-06, излагает
аргумент, на котором тот запрет держался, что пришло ему на смену — и,
что важнее всего, чего замена НЕ даёт.

#### Что защищал запрет

T2'-противник, диффующий снимки `S1, S2, S3, …`, видел по одному
смещению максимум два разных значения:

```
offset 4096 * slot_K, S1: bytes_X     ← легитимная запись
offset 4096 * slot_K, S2: bytes_X'    ← scrub (перезапись #1)
```

Приманки дописывались один раз и больше не трогались, поэтому
**третьему** значению по одному смещению не находилось объяснения через
приманки. «Это смещение переписано дважды» было надёжным оракулом «здесь
были живые данные», и запрет переиспользования не давал третьему
значению появиться.

Запрет работал и стоил продукту диска. Кроме `compact_known` байты не
возвращал никто, поэтому хранилище мессенджера, удаляющее столько же,
сколько пишет, росло неограниченно: на референсном стенде контейнер
дорос до **7,0 ГБ** и сжался до **4,8 МБ**.

#### Что пришло на смену

Оракул — это не «смещение переписали», а «смещение переписали, **и при
этом ни одну приманку никогда не переписывают**». Уберите вторую
половину, и первая перестанет что-либо значить. Поэтому слоты-приманки
тоже перерандомизируются (**churn**), и переиспользование становится
безопасным.

Первое возражение здесь правильное: churn по таймеру переносит
различитель с того, *переписано ли* смещение, на то, *как часто*.
Настоящие слоты менялись бы на каждом коммите, приманки — раз в час, и
серия снимков разделила бы их тривиально. Поэтому churn **не по
таймеру**. Он задан тремя правилами, каждое из которых закрывает свой
способ различить две популяции:

1. **То же событие.** Churn выполняется внутри `commit_tx`, в том же
   пост-публикационном блоке, что и padding, и под тем же `fsync`.
   Переиспользование и churn попадают в один интервал между снимками;
   интервала, где есть одно и нет другого, не существует.
2. **Та же частота.** Коммит, переиспользовавший `k` слотов,
   перерандомизирует `k · CHURN_PER_REUSE` приманок (сейчас `1`).
   Частота — функция нагрузки, а не часов, поэтому своей собственной
   частоты, которую можно было бы вычленить, у неё нет.
3. **То же распределение.** Оба берут равномерно случайный слот из
   **одного и того же пула**, без возвращения в пределах коммита:
   выделение через `DecoyPool::take`, churn через
   `DecoyPool::sample_distinct`. FIFO-аллокатор или «наименьший индекс
   первым» дал бы настоящим записям сигнатуру локальности по индексу,
   которой нет у равномерного churn, и противник разделил бы их по
   *где* вместо *как часто*.

#### Decoy pool — и почему это не «мусор»

Writer пространства A **не может** отличить garbage-чанк от живого
чанка пространства B — это и есть посылка §9, и она означает, что
«перерандомизировать мусор» — операция, которую этот формат выразить не
способен. Любой слот, который A не писал, — это слот, который A трогать
нельзя.

A может доказать, что владеет и списал, ровно две вещи; их объединение
и есть **decoy pool**:

- слоты, которые A затёр: orphan-чанки `IndexNode` / `DataBatch`,
  списанные `vacuum_orphans` / `vacuum_data_batches`, и вытесненные
  checkpoint-цепочки;
- garbage, который A дописал сам как post-commit padding (§8) и чей
  диапазон слотов A наблюдал в момент записи.

Непересекаемость между пространствами — структурная: слот попадает в
пул A либо когда A затирает слот, которым владел, либо когда A дописал
за конец файла. Ни то, ни другое не может назвать слот, который когда-
либо писало другое пространство.

#### Durable-учёт

Пул живёт в **checkpoint-цепочке** (§5, `ChunkKind::Checkpoint`) рядом с
множеством owned-слотов: одна цепочка, один указатель из суперблока,
публикация атомарна с эрой, запечатано тем же ключом пространства.
Отдельной структурой он не сделан потому, что ему не нужно ничего, чего
уже нет у owned-множества.

Checkpoint обновляется лениво, поэтому записанный пул регулярно
**устаревает** — он может по-прежнему называть слот, который более
поздний коммит уже переиспользовал. Это безопасно, потому что путь
открытия ему не доверяет:

```
pool_effective = pool_recorded \ owned_slots
```

Переиспользованный слот снова расшифровывается AEAD под ключом этого
пространства, поэтому скан сообщает, что он *owned*, поэтому он уходит
из пула — что бы ни говорил checkpoint. Записанный пул имеет право
недосчитывать (цена — утёкший диск, возвращаемый ближайшим
`compact_known`) и не может пересчитать при честном writer'е. **Для
крах-безопасности больше ничего не нужно**: запись пула, потерянная при
крахе, — это утёкший слот, но никогда не потерянный.

Два следствия того, что пул живёт именно там:

- Быстрое открытие обязано trial-decrypt'ить не только записанное
  owned-множество, но и слоты пула. Индукция полноты в
  `space/checkpoint.rs` опиралась на «ни один слот ниже high-water не
  становится owned после checkpoint'а», что было верно, пока записи
  только дописывались; переиспользование ломает эту посылку ровно в
  одном месте, и это место — слоты пула. Их посещение восстанавливает
  индукцию с `owned ∪ pool` в качестве покрытой области.
- Добавлен третий триггер обновления, `CHECKPOINT_MIN_POOL_DRIFT`.
  Существующий триггер меряет рост незачекпойнченного хвоста — а это
  ровно то, что переиспользование подавляет, так что без триггера по
  дрейфу пула чем лучше работало бы переиспользование, тем реже
  записывался бы пул, который его и обеспечивает.

#### Крах-безопасность

Переиспользование опирается **ровно** на доказательство
`vacuum_orphans` и не добавляет своего: слот из пула — это слот, про
который vacuum уже показал, что он недостижим из эры, которую называет
этот handle. Поэтому оно наследует дисциплину vacuum, в точке принятия
решения (`Space::reuse_permitted`):

- `attempted_seq > superblock.seq` — публикация положила реплику на
  диск и упала, поэтому переоткрытие может выбрать эру, которую этот
  handle никогда не видел, а «недостижим из эры, которую я вижу» —
  утверждение не про неё. Переиспользование откатывается к дописыванию,
  ровно как `vacuum_orphans` отвечает `Error::PublishUncertain`.
- `unreadable_newer_superblock` — писатель, которого мы не понимаем,
  опубликовал состояние после нас; тот же отказ по той же причине.

3-fsync-барьер не изменился. Крах между записью чанков и публикацией
суперблока оставляет текущей предыдущую эру, а она доказуемо не
ссылается ни на один слот, переиспользованный этим коммитом.

**Checkpoint-чанки — единственный вид, который никогда не берётся из
пула.** `write_self_heal_checkpoint` списывает вытесняемую цепочку в
пул и только потом публикует суперблок, называющий новую цепочку; в
промежутке суперблок на диске всё ещё указывает на старую голову. Чанк
`Checkpoint`, попавший туда, привёл бы к тому, что после краха
читается цепочка, выглядящая корректной и являющаяся *суффиксом* новой,
— молча неполное owned-множество. Чанк любого другого вида на том же
месте декодируется как «не тот kind», и читатель откатывается к полному
скану, что корректно.

#### Ключи

Переиспользование корректно для шифра без единого изменения в key
schedule, и это стоит проговорить, потому что обратное было бы
катастрофой. `derive_chunk_key(aead_root, container_id, slot)` и AAD
привязаны к **номеру** слота, а не к поколению записи, так что второй
чанк в слоте K запечатывается тем же ключом, что и первый. Безопасным
это делает нонс: `ChunkAead::seal` берёт свежий случайный 192-битный
нонс XChaCha20 на каждый вызов, поэтому две запечатки в один слот делят
ключ и не делят ни байта гаммы. Это ровно то свойство, ради которого §10
выбрала XChaCha20-Poly1305: 96-битному нонсу понадобился бы counter
state, а counter state переиспользование как раз бы и сломало.

#### Что это даёт и чего не даёт

Честно, потому что заменённый запрет был настоящей защитой, а это
слабее — и в тех местах, которые важны.

**Сохранено.** Внутри пула число перезаписей смещения не несёт
информации о том, живые ли там данные. Переиспользование и churn — один
процесс записи (то же событие, та же частота, то же распределение),
поэтому по-смещенческие счётчики перезаписей подчиняются одному закону и
для приманок, и для настоящих чанков. Это строго лучше старой схемы
*внутри пула*, где затёртый слот навсегда оставался помеченным как
смещение, которое держало настоящие данные и было списано.

**Потеряно — множество анонимности есть пул, а не файл.** Смещение,
которое никогда не менялось, доказуемо не входит ни в один пул.
Противник T2' делит файл на «никогда не менялось» и «менялось» и
узнаёт, что живые данные этого пространства — во второй части.
Множество анонимности для настоящей записи — это
`SpaceStats::reusable_slot_count`, а не размер контейнера. Host-app,
которому нужно большое множество, обязан держать padding policy
щедрой; при `PaddingPolicy::None` пул — это только то, что списал
vacuum.

**Потеряно — объём по-прежнему утекает, и утекал всегда.** Коммит,
переиспользовавший `k` слотов, пачкает `k · (1 + CHURN_PER_REUSE)`
смещений. Счёт пропорционален реальной активности, так что противник
по-прежнему оценивает, сколько всего произошло между двумя снимками.
Это не регресс — при append-only та же оценка бралась из роста файла,
что сигнал даже более чистый, — но churn эту дыру не закрывает и
закрыть не может. Спрятать *объём* записи можно только записывая с
постоянной скоростью независимо от активности, а такой цены по батарее
и износу флеша проект не принимал.

**Не изменилось — файл всё ещё растёт.** Переиспользование
перерабатывает `IndexNode` и `DataBatch`, потому что именно их списывает
`vacuum_orphans`. Оно **не** перерабатывает вытесненные `Commit` и
`Superblock`: это crash-recovery fallback'и и якоря `commit_history`, и
vacuum их не трогает намеренно. Поэтому в установившемся режиме рост —
`1 + superblock_replicas` чанков на коммит (4 по умолчанию) вместо этого
же плюс перестроенный путь индекса. Измерено на фикстуре
`reuse_recycles_the_index_tree_and_nothing_else` при одной реплике:
24 коммита дописали **48** слотов там, где append-only дописывал **72**.
Переиспользование уменьшает рост; останавливает его по-прежнему только
`compact_known`. Списание старых эр закрыло бы остаток и ограничило бы
`commit_history`, а это опубликованный контракт — отдельное решение, не
это.

**Цена.** Одна лишняя запись чанка на каждый переиспользованный слот на
коммит, в том `fsync`, который padding платит и так. На телефоне это
4 КиБ дополнительного ввода-вывода на переиспользованный слот — для
типичного коммита мессенджера, переиспользующего один-два слота, 4–8 КиБ
против ~20 КиБ, которые коммит пишет и без того. Износ флеша растёт в
той же пропорции. Ручка — `CHURN_PER_REUSE`; её увеличение покупает
большее отношение анонимности пропорциональной ценой, и платится оно на
каждом коммите.

Триггер host-app'а для компакции документирован в
[`docs/ru/guide/operations.md`](docs/ru/guide/operations.md) §5.4
(порог live-ratio, бюджет размера, idle-time defer, privacy event).
Метрики — `SpaceStats::utilization_ratio()` и
`SpaceStats::reusable_slot_count`: низкое отношение при здоровом пуле —
это перерабатывающий контейнер, которому компакция не нужна, а низкое
отношение при пустом пуле — тот случай, когда нужна.

## 10. Параметры формата

| Параметр | Значение | Обоснование |
|---|---|---|
| `CHUNK_SIZE` | 4096 | Кратен page size; AEAD overhead 40B ⇒ 4056 payload; разумный балланс между fragmentation и слот-сканированием |
| AEAD | XChaCha20-Poly1305 | 192-bit nonce → random nonces безопасны без счётчика. AES-GCM (96-bit) требует counter state, что плохо сочетается с multi-space writer'ами. AES-GCM-SIV отбрасывается из-за меньшей зрелости Rust-реализаций; AEGIS-256 — туда же. Per-slot KDF (см. выше) уже даёт misuse-resistance, поэтому XChaCha-Poly1305 достаточно. |
| KDF | Argon2id, t=3 m=64MiB p=1 | OWASP-рекомендация для mobile |
| Hash | BLAKE3 | keyed mode, fast, used for derivation и Merkle |
| Header size | 48B + padding до `CHUNK_SIZE` | salt + argon2_params + slack. v2 был 80B (с cleartext `container_id`); v3 деривит `container_id` per-space (§4). |
| `MAX_OPEN_SCAN_CHUNKS` | 16 × 1024 × 1024 (= 64 GiB при `CHUNK_SIZE`) | Жёсткий cap на slot-grid. Write-side (audit pass 17 B: `Container::create_with_options`, post-commit padding, `repack` destination) и read-side (audit pass 16 TM1: все три open-scan пути) отказываются расти или сканировать за этот cap. Закрывает DoS-via-inflated-file (T2-adversary) и create-then-can't-reopen footgun. |

## 11. Open questions

Раздел каталогизирует design-решения, которые были open на этапе плана
v0.1. Items 1, 2, 4, 5 имеют отгруженные resolution'ы; item 3 — soft
cap, документированный в threat-model'е как "out of scope".

1. **Argon2 params storage.** ✅ Решено. Параметры хранятся в cleartext
   header'е (v3: offset 32..48; в v2 было 64..80, см. §2). Это не
   deniability-leak — params
   описывают стоимость одной попытки brute-force, ничего не говорят о
   количестве пространств или содержимом. Library exposes presets
   (`Argon2Params::LIGHT/DEFAULT/HEAVY`) и floor (`Argon2Params::MIN`,
   ниже которого open/create отклоняется). Audit pass 1 D1 также добавил
   верхний потолок (`MAX_M_COST_KIB` = 512 MiB, `MAX_T_COST` = 8,
   `MAX_P_COST` = 16), чтобы закрыть OOM DoS, при котором tampered header
   заставлял бы следующего opener'а уйти в 4 TiB Argon2-derivation.
   Каждый потолок — небольшая кратность самого тяжёлого поставляемого
   preset'а (`HEAVY`: m=256 MiB, t=4, p=4), поэтому худший заголовок,
   который может написать противник, ограничен и по *времени*, а не
   только по памяти.

2. **Replay/rollback защита.** ✅ Вынесено в host-app. Snapshot adversary
   (T2) может откатить файл к старой версии — библиотека одна это не
   детектит. Контракт host-app'а оформлен в `docs/en/guide/multi-device.md`:
   `Space::commit_seq()` — текущий монотонный счётчик коммитов;
   `Space::commit_history()` — список всех seq, чьи Superblock'и ещё на
   диске и расшифровываются нашим ключом (для отличения rollback'а от
   forka). Привязывать якоря ТОЛЬКО для пространств, чьё существование
   не deniability-чувствительно.

3. **Maximum slot count.** При `u64` seq и 4 KiB chunks файл до 64 EiB.
   Реальный лимит — память при scan. Практическое руководство — в
   `docs/ru/guide/operations.md` ("рекомендованный размер контейнера");
   библиотека не enforce'ит жёсткий cap.

4. **Compression boundary.** ✅ Решено через chunk-kind `DataBatch`
   (0x06). Высокообъёмный namespace мессенджера (`MESSAGE_LOG`) пишет
   per-Tx zstd-сжатые batch'и через `Tx::append_log`; KV-namespace'ы
   продолжают использовать несжатые `IndexNode`-чанки, потому что сжатие
   крошечных B+-tree-узлов регрессирует размер. См.
   `crates/hidden-volume/src/space/log.rs`.

5. **Duress password как first-class.** ✅ Решено через ОТСУТСТВИЕ
   декларации в API. Duress-space — это просто ещё одно пространство,
   которое host-app назначает duress'ом; библиотека никогда не видит
   разницы. Это сохраняет формат ignorant к duress, что и есть правильная
   граница для plausible deniability (ни один on-disk байт не отличает
   duress-space от любого другого).

6. **Криптографическая привязка версии формата.** ✅ Закрыто в v3
   (2026-05-28). v2-постура «отгружаем-через-policy-gate» поднята
   до doubly-bound reject'а в v3-key-schedule (§4): `params.version`
   теперь свёртывается в `versioned_master` через post-Argon2
   BLAKE3-step. Гипотетический v4-reader, ослабивший
   `Argon2Params::validate()`, всё равно дeriviл бы *другой*
   `master_key`, чем v3-writer, запечатавший файл, и упал бы с
   `Error::AuthFailed` на первой же AEAD-попытке. Lockdown-
   требование, которое audit M5 (2026-05-10) поднял для v3,
   отгружено через option (a) — fold version into the KDF chain.
   См. [`crypto/kdf.rs::derive_master_key`](crates/hidden-volume/src/crypto/kdf.rs)
   и threat-model F-PAD §4.1 (теперь реклассифицирован в DoS-only).

## 12. API skeleton (v0.1-набросок — сохранён как исторический контекст)

> **Замечание.** Этот раздел воспроизводит изначальный v0.1 design-набросок.
> Реальный v1.0 API эволюционировал через 10 audit-проходов (lock-режимы,
> per-namespace KV, log streaming, async/FFI обёртки, cancellation,
> persistent padding, …). Канонический текущий surface — в
> `cargo doc --workspace --all-features --open`, директория `bindings/`
> для FFI-формы и `docs/ru/reference/format.md` для on-disk format spec.
> Набросок ниже сохранён, потому что заложенные в него design-rationale
> (KV-как-фундамент, namespace split, deniable compaction) до сих пор
> load-bearing.

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

Нижний слой — per-namespace KV + append-only log с атомарными
multi-namespace транзакциями. Мессенджер строится поверх: message stream
= namespace `MESSAGE_LOG` через `append_log` / `delete_log`; contacts = `CONTACTS`
KV-namespace; media = `MEDIA` KV-namespace с большими value'ами
(возможно — chunked самим host-app'ом). Slot-уровневые `update_slot` /
`tombstone_slot` из v0.1-наброска вытеснены `vacuum` +
`scrub-old-on-success`. И это *не* потому, что in-place-записи
невозможны — §9.1 переиспользует списанные слоты, — а потому, что эти
две операции позволяли вызывающему переписать слот по своему выбору, без
доказательства, что слот недостижим из восстановимой эры. Именно это
доказательство и составляет всё содержание Inv-W1, а decoy pool
существует, чтобы его поставлять.

## 13. Module layout (canonical)

Реальный v1.0 layout — 4-крейтовый workspace; изначальный v0.1-набросок
показывал только `src/`. Полная диаграмма — в `README.ru.md` § Архитектура.
Кратко:

```
crates/hidden-volume/      — sync-ядро: crypto/, chunk/, container/,
                              space/{mod,commit,vacuum,log_iter,integrity}.rs,
                              tx/, padding/, open/, cancel.rs, error.rs,
                              bin/hv.rs (фича `cli`)
crates/hidden-volume-rt/   — внутренний: OwnedSpace + run_blocking
                              (общий для async + ffi)
crates/hidden-volume-async/— Tokio-обёртка: AsyncContainer / AsyncSpace
crates/hidden-volume-ffi/  — uniffi 0.31 биндинги: SpaceHandle /
                              AsyncSpaceHandle (Kotlin / Swift / Python / Ruby)
```

V0.1-набросок включал `space/journal.rs` и `space/keys.rs` — ни тот,
ни другой не отгружен в v1.0. `journal.rs` вытеснен vacuum + scrub
(audit pass 1 A1); `keys.rs` консолидирован внутри `crypto/derive.rs`
как `SpaceKeys`.

## 14. Что строилось в первую очередь (v0.1 milestone, исторически)

Минимум для end-to-end теста "create → open → put → reopen → get":

1. `crypto::*` — все примитивы.
2. `chunk::format` — encode/decode plaintext, AEAD seal/open.
3. `container::header` + `container::file` — write/read fixed-size slots.
4. `crypto::derive::SpaceKeys` — Argon2 + derivation chain.
5. `space::superblock` — single chunk-pointer per space.
6. `open` — scan + pick latest superblock.
7. `Tx` — single-record commit (без полноценного KV index).

V0.2 добавил per-namespace B+ tree, multi-Tx atomicity и цепочку
`commit_history`. V0.3 — vacuum + integrity walks. V0.4 — lock-режимы.
V0.5–v0.7 — padding, parallel/mmap scan, async-обёртку. V0.8 —
FFI-крейт. См. `TASKS.md` для milestone-лога и `TASKS_ARCHIVE.md` для
истории закрытых работ.

Index/journal/checkpoints — v0.2. Compaction — v0.3.
