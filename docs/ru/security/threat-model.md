# Модель угроз

[🇬🇧 English](../../en/security/threat-model.md) · 🇷🇺 **Русский**

**Статус.** Рабочий документ предрелизной стадии. Структура не
изменится между текущим моментом и v1.0 — будут добавляться только
конкретные результаты. Внешний платный аудит (класса Trail of Bits /
Cure53 / NCC) для этого проекта **не планируется**; обоснование
(анонимность + no-budget) и замещающий процесс (in-tree audit
passes, эта модель угроз, per-area аудиты, reproducible signed
builds, community bug-bounty) задокументированы в
[`audits/self-audit.md`](audits/self-audit.md). Engagement community-
researcher'а, чей публичный technical write-up следует SECURITY.md
timeline'у — канонический путь, по которому external review для
этого проекта всё ещё *может* состояться.

Этот документ — формальный аналог `DESIGN.md` §1 (где модель изложена
кратко) и существующих аудит-заметок по отдельным областям
([`audits/constant-time.md`](audits/constant-time.md),
[`audits/memory.md`](audits/memory.md),
[`audits/plaintext.md`](audits/plaintext.md),
[`audits/fsync.md`](audits/fsync.md)). Документ построен как
чек-лист для любого
рецензента — internal, community или eventual external —
относящегося серьёзно к claim'ам проекта: каждый инвариант
именован, точно определён, сопоставлен с конкретным кодом и с
подкрепляющим его проходом аудита.

Если что-то здесь противоречит `DESIGN.md`, **`DESIGN.md` имеет
приоритет**.

## 1. Системная модель

### 1.1 Что такое `hidden-volume`

Однофайловый, append-only, зашифрованный, multi-space примитив
хранения. Ядро — синхронный, std-only Rust. Опциональная обёртка
над tokio (`hidden-volume-async`, сейчас за feature-flag) и feature
`parallel-scan` существуют, но не входят в security boundary — они
вызывают то же синхронное ядро.

Файл-контейнер содержит:

- 48-байтный cleartext-заголовок (salt 32 + параметры Argon2id 16;
  остаток первого чанка — равномерно случайный padding). v3 убрал
  32-байтное поле `container_id`, которое v2 хранил в открытом
  заголовке — `container_id` теперь дeriviтся per-space из
  versioned master key (закрывает D1-A2 fingerprint signature).
- Сетку фиксированных 4 KiB чанков, каждый AEAD-запечатан
  (XChaCha20-Poly1305) под per-slot ключом, выведенным из per-space
  master через keyed-hash BLAKE3.
- Один или несколько **spaces** внутри этой сетки, взаимно
  неотличимых от случайных байт без per-space пароля.

Библиотека предоставляет per-space KV (`Tx::put` / `delete` / `get` /
`list`) и append-log (`Tx::append_log` / `iter_log_after` /
`iter_log_before` / `read_log`) API, плюс примитивы управления
(`Container::compact_known`, `Container::change_passwords`,
`Space::erase_namespace`, `Space::vacuum_data_batches`,
`Space::verify_integrity`).

### 1.2 Чем `hidden-volume` НЕ является

- **Не сетевой протокол.** P2P-синхронизация, transit-шифрование,
  обмен идентичностями, contact discovery — всё out of scope. См.
  `docs/ru/guide/multi-device.md` для контракта, которому следуют
  слои синхронизации host-app.
- **Не host-app.** Состояние UI, списки недавно открытых файлов,
  кэши IME, миниатюры скриншотов, утечки в swap-файл — всё на
  ответственности host-app. Библиотека их не видит.
- **Не сервис управления ключами.** Argon2id выводит ключи из
  паролей по требованию; опциональный кэш пре-выведенных
  `SpaceKeys` делегирует OS keyring. Интеграции с KMS нет.
- **Не слой аутентификации.** «Имеет пароль» ≡ «является
  пользователем». Multi-factor / hardware-token gating — забота
  host-app.

### 1.3 Доверяемые компоненты

Корректность `hidden-volume` опирается на корректную работу
следующих зависимостей:

- Toolchain Rust (rustc + std).
- Крейты RustCrypto: `chacha20poly1305`, `argon2`, `blake3`,
  `zeroize`, `subtle`. Они constant-time / zeroizing по построению.
- ФС ОС (семантика POSIX `flock`, `pread`, `fsync` / `sync_all`).
- `getrandom` для недетерминизма в salts, nonces, padding.

Компрометация любого из вышеперечисленного — **out of scope** для
этой модели угроз.

## 2. Модель противника

Перечисляем три уровня возможностей противника. Библиотека защищает
указанные инварианты против каждого из них.

### T1 — Single-snapshot passive

**Возможность.** Противник получает файл контейнера в один
момент времени. У него неограниченные offline-вычисления и полное
знание формата. Пароля у него НЕТ.

**Примеры.** Subpoena у облачного хранилища, возвращающий backup-
snapshot; криминалистическое изъятие выключенного диска; досмотр
выключенного устройства на границе.

### T2 — Multi-snapshot passive

**Возможность.** Противник получает файл контейнера в разные
моменты времени и может побайтно сравнивать snapshot'ы. В остальном
ведёт себя как T1.

**Примеры.** Регулярные облачные backup'ы; периодическое
криминалистическое снятие образа.

T2 разделяется на:

- **T2 (append-diff).** Видит, что файл вырос между snapshot'ами.
- **T2' (in-place-diff).** Видит, что конкретные байты внутри
  области файла, присутствующей в обоих snapshot'ах, изменились
  (rewrite-in-place или tombstone-scrub в конкретном слоте).

T2' строго сильнее T2.

### T3 — Compelled-key

**Возможность.** Противник имеет T2 плюс принудительно получил от
пользователя *один* пароль (например, пограничник требует пароль
под угрозой). У него неограниченные offline-вычисления и полное
знание формата.

**Примеры.** Допрос на границе; rubber-hose cryptanalysis.

T3 — *основной* противник, против которого `hidden-volume`
проектируется — deniability дополнительных spaces сверх того,
чей пароль был раскрыт.

### Out-of-scope противники

Перечислены для полноты; **защита не заявляется**:

- **T-active.** Противник модифицирует файл между snapshot'ами и
  наблюдает реакцию пользователя. Detection — ответственность
  host-app (см. §4 R1).
- **T-side-channel-OS.** Противник имеет read-доступ к swap, /proc,
  /dev/mem, kernel page cache и т. п. на работающей машине.
  Библиотека не способна защититься от атакующего с
  скомпрометированной ОС.
- **T-side-channel-CPU.** Spectre / Meltdown / cache-timing на
  shared-железе. Защищается только на уровне CPU microcode и
  hypervisor.
- **T-cold-boot.** Память остаётся читаемой секунды-минуты после
  потери питания. Защищается только полным шифрованием диска +
  secure boot.
- **T-supply-chain.** Скомпрометированный RustCrypto / `rustc` /
  зависимость. Workflow `cargo audit` и политика `Cargo.lock`
  ограничивают этот риск, но не устраняют его.

## 3. Инварианты безопасности

Библиотека делает следующие заявления об инвариантах. Каждый
именован (короткий тег + описательный заголовок), точно определён
и сопоставлен с code path, который его устанавливает, плюс с
аудит-документом, который его верифицирует.

### D1 — Single-snapshot indistinguishability

**Утверждение.** Против T1 файл вычислительно неотличим от
равномерно случайного blob'а с 48-байтным cleartext-заголовком.
Конкретно: противник, держащий файл, но без пароля, не может
определить ни количество spaces (≥ 0) внутри, ни kind / count /
size содержимого любого чанка, ни какого-либо per-space
идентификатора (v3 закрыл D1-A2 fingerprint).

**Обеспечивается.**
- Per-chunk XChaCha20-Poly1305 со случайным 192-битным nonce и AAD,
  привязывающим к slot index + per-space-derived `container_id`.
  Ciphertext неотличим от случайного (IND-CPA + ciphertext
  integrity).
- Garbage-чанки — равномерно случайный fill (`crypto::rng::fill`),
  визуально идентичны AEAD ciphertext.
- Обфускация размера файла через
  `ContainerOptions::initial_garbage_chunks` (decoy-начальный
  размер) и `PaddingPolicy::{BucketGrowth, FixedRatio}`
  (per-commit обфускация роста).
- Заголовок всегда 48 байт независимо от количества spaces;
  единственное заполненное cleartext-поле кроме 16-байтового слова
  Argon2-параметров — это 32-байтный случайный `container_salt`
  (случаен на каждый свежий контейнер). v3 убрал cleartext
  `container_id` (теперь per-space derived).

**Code paths.** `crypto/aead.rs::ChunkAead::seal`,
`container/file.rs::append_garbage_chunks`,
`padding/`, `space/mod.rs::commit_tx` post-commit padding hook.

**Аудит.** Неявный — покрывается upstream-доказательствами AEAD.
Hidden-volume-специфичного аудит-документа нет; находок не
ожидается.

### D2 — Compelled-key plausible deniability

**Утверждение.** Против T3 противник, держащий файл плюс один
раскрытый пароль для space A, получает криптографическое
утверждение об A, но никакого утверждения (криптографического или
иного) о том, существуют ли другие spaces.

**Обеспечивается.**
- Per-space master-ключ `Argon2id(password, container_salt)`
  domain-separated и неотличим между spaces — одна и та же соль,
  разные пароли дают некоррелированные ключи.
- Discovery scan (open path) — `O(N)` trial-decrypt каждого слота
  per-slot ключом кандидата space. Слоты с AEAD-fail молча
  пропускаются без какого-либо side-channel сигнала —
  `try_decrypt` ветвится идентично на success/failure (constant-
  time проверка AEAD-тега внутри RustCrypto).
- `Error::AuthFailed` объединяет «неверный пароль» и «нет такого
  space» — одинаковый код возврата, одинаковый timing, одинаковый
  recovery path.
- Публичные API НЕ раскрывают chunk count, owned-slot indices или
  любые per-space метаданные тому, у кого нет пароля.

**Code paths.** `crypto/kdf.rs::derive_master_key`,
`open/mod.rs::scan_and_recover` (и `scan_and_recover_parallel`),
`crypto/aead.rs::ChunkAead::open`, `error.rs::Error::AuthFailed`.

**Аудит.** `docs/ru/security/audits/constant-time.md` (constant-time pass) — пройден; в
нашем коде нет secret-touching сравнений, все CT-чувствительные
операции делегируют RustCrypto.

### I1 — Per-chunk integrity

**Утверждение.** Любая модификация одного байта любого чанка
обнаруживается при следующей попытке его AEAD-open. Библиотека
никогда не возвращает неаутентифицированные байты.

**Обеспечивается.** Тег Poly1305 в каждом чанке (XChaCha20-
Poly1305). Проверка тега constant-time в RustCrypto.

**Code paths.** `crypto/aead.rs::ChunkAead::open`.

**Аудит.** Неявный (RustCrypto доказан). Тестируется в
`tests/sb_replicas.rs` (single-byte flip → AuthFailed),
`tests/integrity.rs` (локализация corruption через
verify_integrity).

### I2 — Tail-corruption tolerance

**Утверждение.** Truncation или torn writes в хвосте файла
откатывают контейнер к последнему успешно fsync'нутому состоянию.
Никакое частичное состояние не выставляется наружу; нет panic;
нет UB.

**Обеспечивается.**
- Three-fsync commit-протокол: Data → fsync → Commit → fsync →
  Superblock(s) → fsync. Crash до третьего fsync оставляет
  предыдущий Superblock как max-seq.
- Множественные реплики Superblock на коммит
  (`superblock_replicas`, по умолчанию 3). Single-chunk corruption
  переживается за счёт оставшихся реплик.
- Open path выбирает Superblock с max-seq, который AEAD-decrypts,
  и игнорирует остальные.

**Code paths.** `space/mod.rs::commit_tx` (3-fsync барьеры),
`container/mod.rs::ContainerOptions::superblock_replicas`,
`open/mod.rs::scan_and_recover` (max-seq pick).

**Аудит.** `docs/ru/security/audits/fsync.md` (fsync ordering pass) — пройден;
все 7 fsync-точек прослежены. Тестируется
`tests/crash_recovery.rs` (8 ручных), `tests/crash_proptest.rs`
(24 случайных workload × random truncation),
`tests/sb_replicas.rs` (выживание corruption).

### I3 — Cross-space isolation

**Утверждение.** Баг или вредоносный caller в коде, держащем ключи
space A, НЕ МОЖЕТ повредить структуры данных space B. Конкретно:
write paths A трогают только слоты, которыми владеет A
(Tx-tracked); чанки B для A — непрозрачный мусор.

**Обеспечивается.**
- Per-space ключи (Argon2id на пароль). Ключи, выведенные из
  пароля X, не могут AEAD-open чанки, запечатанные под паролем Y.
- Append-only формат файла: записи идут в свежие слоты, никогда
  не перезаписывают произвольные позиции. Примитивы scrub /
  overwrite (`scrub_slot`, `write_slot`) требуют слот, которым
  владеет caller; модуль это документирует, и тесты верифицируют
  ownership tracking.
- DataBatch-чанки пишутся исключительно тем Tx, который их
  закоммитил; pointer-слоты хранятся в KV-индексе того namespace,
  недостижимы из другого namespace.

**Code paths.** `crypto/derive.rs::SpaceKeys`,
`container/file.rs::ContainerFile::{scrub_slot, write_slot}`,
`space/mod.rs::Space::owned_slots`.

**Аудит.** `docs/ru/security/audits/memory.md` + `docs/ru/security/audits/plaintext.md`. Тестируется
`tests/multi_device.rs::cross_space_history_isolation`,
`tests/scrub.rs::vacuum_does_not_touch_other_spaces`,
`tests/erase_namespace.rs::multi_space_isolation_under_erase`,
`tests/integrity.rs::multi_space_isolation_in_verify`.

### R1 — Rollback / fork-detection contract (host-app cooperative)

**Утверждение.** Библиотека самостоятельно НЕ обнаруживает
rollback-атаки (T-active). Она ПРЕДОСТАВЛЯЕТ примитивы, достаточные
для того, чтобы host-app обнаружила rollback / fork против внешнего
anchor (TPM, server counter, signed log).

**Обеспечивается.**
- `Space::commit_seq()` — монотонный per-space счётчик.
- `Space::commit_history()` — отсортированный по возрастанию,
  дедуплицированный список каждого Superblock seq, ещё лежащего на
  диске и AEAD-decrypts под нашим ключом.
- Алгоритм triage в `docs/ru/guide/multi-device.md` §«Rollback /
  fork-detection».

**Code paths.** `space/mod.rs::Space::{commit_seq, commit_history}`,
`open/mod.rs::scan_and_recover` (заполнение commit_history).

**Аудит.** `docs/ru/guide/multi-device.md` документирует контракт.
Тестируется `tests/multi_device.rs` (8 сценариев, включая host-app
triage).

### M1 — Memory hygiene of key material

**Утверждение.** Секретный материал ключей (Argon2-выведенный
master, per-space ключи, per-slot ключи, per-call cipher state)
зануляется при drop'е владеющего значения; в частности, до того
как страницы аллокатора возвращаются ОС.

**Обеспечивается.**
- `SpaceKeys` derive `ZeroizeOnDrop`; его поля
  `Zeroizing<[u8; 32]>` в transit.
- `derive_master_key` возвращает `Zeroizing<[u8; 32]>`.
- `derive_chunk_key` / `derive_subkey` возвращают
  `Zeroizing<[u8; 32]>`.
- Cipher state у `ChunkAead` зануляется через `ZeroizeOnDrop` impl
  RustCrypto на cipher state `chacha20`+`aead`.
- AEAD-расшифрованные plaintext-байты (возвращаемое значение
  `ChunkAead::open`) обёрнуты в `Zeroizing<Vec<u8>>`, так что heap-
  область скрабится при drop. Pre-encrypt encoded-байты (выход
  `Plaintext::encode`, encoded-байты
  `LeafNode`/`InternalNode`/`CommitPayload`,
  raw concat / decompress буферы
  `log::encode_batch`/`decode_batch`) обёрнуты в `Zeroizing` при
  создании.

**Code paths.** `crypto/derive.rs`, `crypto/kdf.rs`,
`crypto/aead.rs::ChunkAead::open`, `space/mod.rs::append_chunk`,
`space/mod.rs::write_tree_for_namespace`, `space/log.rs`.

**Аудит.** `docs/ru/security/audits/memory.md` + `docs/ru/security/audits/plaintext.md`.
Type-level регрессионные тесты в `tests/memory_hygiene.rs` и
`tests/plaintext_hygiene.rs` фиксируют сигнатуры `Zeroizing<>`.

**Известная отсрочка.** User-owned `Vec<u8>`'ы (KV values в
`Tx::pending_*`, возвращаемые значения
`Space::get`/`list`/`iter_log`, декодированные записи `IndexNode`)
НЕ обёрнуты в `Zeroizing`. Wrapping распространился бы через
публичный API и заставил бы каждое host-app принять обёртку. Путь
митигации для хостов, которым это нужно: process-scope `mlock` +
private memory mapping + secret-allocator. Документировано в
[`docs/ru/security/audits/memory.md`](audits/memory.md) §C и
[`docs/ru/security/audits/plaintext.md`](audits/plaintext.md).

**FFI / async / CLI password-буферы (audit pass 16 + 17).** На каждой
точке входа с паролем во всех wrapper-крейтах входящий `Vec<u8>`
оборачивается в `zeroize::Zeroizing` сразу при вызове, чтобы
Rust-side heap-копия гарантированно затиралась на drop (включая
panic-путь):

- `hidden-volume-ffi`: `SpaceHandle::create`, `SpaceHandle::open`,
  `AsyncSpaceHandle::create`, `AsyncSpaceHandle::open`, top-level
  `compact_known(path, passwords)` (drain'ит `Vec<Vec<u8>>` в
  `Vec<Zeroizing<Vec<u8>>>`) и `change_passwords(path, rotations)`
  (drain'ит каждый `PasswordRotation` в пару `Zeroizing`-буферов).
- `hidden-volume-async`: `AsyncSpace::create`, `AsyncSpace::open`.
- CLI `hv`: `read_password` возвращает `Zeroizing<Vec<u8>>`,
  `read_all_passwords` возвращает `Vec<Zeroizing<Vec<u8>>>`,
  `cmd_put`'s `value_bytes` тоже `Zeroizing<Vec<u8>>`.

`PasswordRotation` намеренно НЕ деривит `Clone` (audit pass 17 F-2)
— derived `Clone` позволил бы внутреннему `.clone()` молча создать
non-`Zeroizing` копию вне wrapper-flow. Foreign-side буферы (Kotlin
`ByteArray` / Swift `Data` / и т.п., которые uniffi анмаршалит)
остаются hygiene-ответственностью host-app — это владелец
foreign-side памяти, а не Rust-runtime.

### C1 — Cancellation safety

**Утверждение.** Длительные синхронные операции (discovery scan
`open_space`, `Container::repack`, `compact_*`) принимают
`CancelToken` и прерываются на well-defined чекпоинтах, не оставляя
на диске частичного состояния, наблюдаемого другими writer'ами.
В середине отмены: завершённый Tx остаётся durable; частичный Tx
отбрасывается (не было выполнено `commit_tx`); временные файлы,
используемые `compact_*` и `change_passwords`, удаляются при cancel.

**Обеспечивается.**
- `cancel.rs::CancelToken` (Arc<AtomicBool>).
- `Container::open_space_cancellable`, `repack_cancellable`,
  `compact_known_cancellable`,
  `change_passwords_cancellable`. Внутри: per-slot polling каждые
  `CANCEL_POLL_PERIOD = 64` слотов в
  `scan_and_recover_with_cancel`; per-namespace и per-Tx чекпоинты
  в `repack_inner_mapped`; cleanup tmp-файлов в
  `compact_in_place_impl` и `change_passwords_impl`.

**Code paths.** `cancel.rs`, `open/mod.rs::scan_and_recover_with_cancel`,
`container/mod.rs::repack_inner_mapped`,
`container/mod.rs::compact_in_place_impl`,
`container/mod.rs::change_passwords_impl`.

**Аудит.** Тестируется `tests/cancellation.rs` (10 сценариев) и
`tests/repack_cancellation.rs` (7 сценариев) — включая mid-flight
race + post-cancel file-integrity check.

## 4. Out-of-scope митигации (известные ограничения)

Библиотека НЕ защищает от следующего. Перечислено явно, чтобы
рецензент мог подтвердить, что эти угрозы не в scope:

| Threat | Почему нет | Где отсрочено |
|---|---|---|
| Rollback от snapshot-противника | У библиотеки нет понятия «сейчас»; нужен внешний anchor | R1 (host-app cooperative); `docs/ru/guide/multi-device.md` |
| Heap-остатки user-data Vec<u8> | Стоимость churn'а публичного API > выгода; митигируется process-wide через mlock | [`audits/memory.md`](audits/memory.md) §C, [`audits/plaintext.md`](audits/plaintext.md) |
| Side-channel на host-app UI / IME / swap | За пределами scope библиотеки | `DESIGN.md` §1 out-of-scope |
| Multi-snapshot byte-diff на in-place rewrite (T2') | Rewrite намеренный (vacuum, scrub); полное сокрытие требует периодической случайной перезаписи всего garbage, запретительно дорого | `DESIGN.md` §1 out-of-scope |
| Encryption-at-rest виден | Deniability — про *какие* секреты, а не про *существуют ли* секреты | `DESIGN.md` §1 out-of-scope |
| Сетевые ФС, игнорирующие `flock` | Библиотека не может это обнаружить; ответственность развёртывающего | [`guide/multi-device.md`](../guide/multi-device.md) Pattern B caveat |
| **`mmap` на ФС, разрешающих concurrent mutation** (NFS, FUSE, SMB) | Cargo-фича `mmap` использует `memmap2::Mmap`, чей контракт безопасности требует, чтобы байты mapped-файла были стабильны в течение жизни маппинга. `flock(LOCK_EX)` обеспечивает это на локальных ФС (ext4/xfs/btrfs/APFS/NTFS); на NFS lock advisory best-effort, на некоторых FUSE-ФС вообще игнорируется. Concurrent mutation под активным mmap нарушает Rust aliasing rules. | См. §4.2 ниже; `mmap` — `cfg(unix)` И opt-in через Cargo feature; mobile / FFI consumers должны держать выключенным |
| **Argon2id неинтеррапбл** (`HV-NEW1`) | RustCrypto `argon2::Argon2::hash_password_into` не проверяет cancellation flag. Пользователь, вызвавший `Container::open_cancellable` с `HEAVY` params (~250ms на x86 server-class, multi-second на Cortex-A53) и затем cancel'нувший, всё равно увидит, как Argon2 доработает до конца, прежде чем `Error::Cancelled` всплывёт. | См. §4.3 ниже; host-app'ы должны запускать KDF в `spawn_blocking` task с hard timeout'ом и трактовать timeout как user-visible cancel |
| Компрометация уровня ОС (root, /proc, /dev/mem) | Угроза превышает границу библиотеки | §2 out-of-scope |
| CPU side channels (Spectre, cache timing) | Граница ОС / microcode | §2 out-of-scope |
| Cold-boot восстановление RAM | Граница железа | §2 out-of-scope |
| Supply chain (RustCrypto / rustc / deps) | Политика `cargo audit` + `Cargo.lock` ограничивает, не устраняет | §2 out-of-scope |
| **F-PAD** — tamper padding-policy через header modification (audit pass 9; reclassified v3 #9) | v2 поведение: T2-adversary флипал `padding_policy_index` (биты 16..24 у `Argon2Params.version`), молча деградируя post-commit padding на будущих записях. **v3 реклассифицирует это из silent privacy-degradation в DoS-class видимый отказ**: весь u32 `params.version` теперь свёртывается в `master_key` через post-Argon2 BLAKE3-step (§3 / `derive_master_key`), так что флипнутый policy-байт даёт *другой* master_key на следующем open ⇒ `Error::AuthFailed`. DoS-поверхность остаётся (любой tamper cleartext-header'а может denied open), но privacy-degradation поверхность закрыта криптографически. | См. §4.1 ниже |

### 4.1 F-PAD — tamper padding-policy (v3 реклассификация)

**Статус v3 (2026-05-28).** **F-PAD перешёл из класса
privacy-degradation в DoS-class угрозу** благодаря v3
криптографической привязке версии (`derive_master_key`, §3
[`docs/ru/reference/format.md`](../reference/format.md) и #9
[`crypto/kdf.rs`](../../../crates/hidden-volume/src/crypto/kdf.rs)).
Причина: в v3 весь u32 `Argon2Params.version` — *включая байт
`padding_policy_index` в битах 16..24* — попадает в BLAKE3-keyed
step, производящий `master_key`. Поэтому флипнутый policy-байт
даёт другой `master_key` на следующем open ⇒ `Error::AuthFailed`.
Silent degradation больше недостижим.

Этот раздел описывает **исторический v2 surface** (padding молча
деградировал) и **v3 новую поверхность** (open denied) — это
разные классы угроз.

**v2 исторический scope (закрыт в v3).** T2 (file-modify)
adversary с write-доступом, но без пароля, мог флипнуть биты 16..24
у `Argon2Params.version` с non-zero preset'а (1=256 KiB / 2=1 MiB /
3=16 MiB) на `0` (`PaddingPolicy::None`). На следующем
`Container::open` `from_persisted_index(0)` возвращал
`PaddingPolicy::None`, и runtime-политика тихо деградировала.
**Будущие записи** тогда росли без post-commit padding'а, утекая
per-Tx growth-deltas multi-snapshot adversary. Прошлые chunk'и на
диске не менялись; утекали только будущие commits.

**v3 текущий scope (DoS-class).** Любой tamper битов 0..32 в
`params.version` приводит к тому, что следующий open вычисляет
другой `master_key` ⇒ `Error::AuthFailed`. Adversary больше не
может *молча* деградировать runtime padding policy; единственный
достижимый исход — denial-of-service. F-PAD таким образом
переходит из D1 / privacy surface в тот же DoS-bucket, что и F1
(Argon2 m_cost OOM через header-tamper) — оба смягчаются одним
механизмом: validation + crypto-binding gate.

**Forward-compat fallback case (audit pass 10 L4, всё ещё
релевантен в v3).** Тропа silent-degrade-to-`None` остаётся
достижимой в сценарии v3-reader-meets-future-v3.y-writer, но
ТОЛЬКО через расширения policy без bump'а версии. Будущий v3.y
writer, который вводит новый preset (index 4..=255 для, скажем,
64 MiB-buckets) БЕЗ bump'а `format_version`, произведёт
контейнеры, которые v3.x reader декодирует через
[`PaddingPolicy::from_persisted_index`] в ветку `_ => None` — тот
же наблюдаемый failure mode, что и при v2-tamper'е. Host-app'ы,
миксующие версии библиотеки на одном контейнере, должны вызывать
[`Container::set_padding_policy`] явно после open'а. Замечание:
любое будущее v3.y изменение в кодировке policy-index'а,
ожидающее cross-version interop, — это doc-policy-решение; v3
crypto-binding предотвращает *malicious* downgrade, но не
*benign* version-skew degrade.

**На что это НЕ влияет (v3).**
- Конфиденциальность сохранённых данных — AEAD-protected как и
  раньше.
- Целостность сохранённых данных — chunk'и на диске не меняются.
- Deniability сохранённых данных — D1 / D2 / I1 / I2 / I3 — все
  по-прежнему держатся.
- D1 в отношении *будущих* записей — закрыто v3-привязкой;
  больше не privacy-concern.

**На что это ВЛИЯЕТ (v3).**
- **Доступность** контейнера после header-byte tamper'а (DoS).
  Смягчение: держать out-of-band бэкап исходных байт header'а;
  тело файла остаётся расшифровываемым, если оригинальный header
  восстановлен побайтно.

**Practical reachability.** У атакующего уже есть T2 (file write)
доступ — на этом этапе DoS в значительной мере уступлен для
любого cleartext-header поля (F1 / F-PAD / будущее). v3
криптографический version-bind — это то, что *предотвращает*
безмолвное leveraging этой DoS-поверхности в privacy-поверхность.

**Mitigation (host-app cooperative, сохранён из v2).**
[`Container::set_padding_policy`] (FFI:
`SpaceHandle::set_padding_policy`) безусловно override'ит
персистированную политику. В v3 это больше не критично для
безопасности (tamper денит open, не privacy), но остаётся
полезным для legitimate v3.y forward-compat case, описанного
выше.

**Почему мы всё ещё опираемся на cleartext-header байт для
policy.** Bind'инг `padding_policy_index` в AEAD ре-вводил бы
структурированное cleartext-поле, регрессируя D1. v3-решение
(version-bind весь `params.version` в KDF) сохраняет байт в
открытом header'е, но устраняет его silent-degrade attack
surface.

### 4.2 `mmap` и доверенные файловые системы (audit pass 14)

**Scope.** Cargo-feature `mmap` открывает контейнерный файл и
маппит его байты через [`memmap2::Mmap`](https://docs.rs/memmap2).
Маппинг конструируется через `unsafe` потому что safety-контракт
`Mmap` требует: **никакой другой процесс или поток не должен
мутировать mapped-байты в течение жизни маппинга.** Библиотека
берёт `flock(LOCK_EX)` (или `LOCK_SH` для `open_readonly`) перед
конструированием маппинга, что на POSIX-локальных ФС удовлетворяет
контракт: другой writer, пытающийся взять `LOCK_EX`, блокируется
(или получает `Error::Busy`) до тех пор, пока наш маппинг не
дропнется.

**Где контракт может не держаться.**

- **NFS v3** без `lockd` — advisory-only; в зависимости от
  конфигурации сервера, удалённый клиент может мутировать файл
  независимо от нашего `flock`.
- **FUSE-ФС**, не передающие `flock(2)` в backend —
  `fuse-overlayfs`, некоторые конфигурации sshfs, и т. д.
- **SMB/CIFS-шары**, монтированные через `cifs-utils` —
  locking implementation-dependent.
- **Контейнерные runtime'ы** (Docker, Kubernetes), где volume
  driver подменяет flock-несовместимый backend.

**Что конкретно ломается.** Маппинг читается `open` /
`open_readonly` для скана chunk-grid'а. Если concurrent writer
мутирует файл под нами, AEAD-decrypt of torn chunk fail'ится с
`Error::AuthFailed`, что — безопасный путь ошибки. **Но** Rust
считает underlying memory aliasing UB; на практике это проявляется
либо как stale-cache read (выглядит как benign failure), либо как
SIGBUS на Linux, когда файл сжимается под маппингом.

**Рекомендация.** `mmap` — **opt-in** через Cargo feature И
`#[cfg(unix)]`. Mobile и FFI consumers ДОЛЖНЫ держать его
выключенным. Для server-side развёртываний на локальном
ext4/xfs/btrfs/APFS, mmap безопасен и даёт измеримый speedup на
cold-cache scans of multi-GiB containers. Для любого окружения,
где underlying storage сомнительный (network-mounted,
FUSE-overlayed, container-volume-passthrough), используйте
default streaming `pread` path.

**Почему не auto-detect'им.** Библиотека не может надёжно
интроспектировать mount options через все платформы; `statfs`
возвращает hints (`f_type == NFS_SUPER_MAGIC`, и т. д.), но
недостаточно для универсального предиката "эта ФС безопасна для
mmap". Opt-in feature flag — это контракт.

### 4.3 Argon2id неинтеррапбл (`HV-NEW1`)

**Scope.** Каждый cancellable open-path
([`crate::Container::open_space_cancellable`],
[`crate::Container::repack_cancellable`], и т. д.) принимает
[`crate::cancel::CancelToken`] и polls
[`crate::cancel::CancelToken::check`] на coarse-grained
checkpoints внутри O(N) discovery scan. **Argon2id derivation
запускается ДО scan'а и НЕ cancellable.** RustCrypto
[`argon2::Argon2::hash_password_into`] не проверяет никакой
flag; раз начавшись, она доработает до конца (~30 ms на x86 с
`MIN` params, ~250 ms с `HEAVY`, multi-second на Cortex-A53 с
`HEAVY`).

**Что конкретно ломается.** Пользователь, вызвавший
`Container::open_space_cancellable(b"password", &token)` и затем
firing `token.cancel()` из другого потока, всё равно увидит, как
Argon2 завершится; `Error::Cancelled` всплывёт только на первом
scan-loop checkpoint ПОСЛЕ возврата Argon2. Для default params на
современном железе это окно sub-100ms и редко user-visible. Для
`HEAVY` params на слабых телефонах окно multi-second и МОЖЕТ
вылиться в UI-фриз, если cancel был triggered'нут "приложение
ушло в фон".

**Рекомендация.** Host-app'ы, нуждающиеся в hard-timeout'ах на
KDF, должны запускать `Container::open*` внутри
`tokio::task::spawn_blocking` (или платформенного эквивалента) с
outer timeout'ом и трактовать timeout как user-visible cancel.
[`crate::cancel::CancelToken`] достаточен для post-KDF scan
phase; KDF нуждается в pre-emption surrounding runtime'а.

**Не будет починено в-tree** до того, как RustCrypto crate
`argon2` добавит cancellation hook (upstream issue, ETA нет).
Доку библиотеки явно вызывает ограничение; тест
`tests/cancellation::cancel_during_argon2_completes_then_aborts`
locks down текущее поведение.

### 4.4 F-TM1 — open-time scan timing oracle

**Scope.** T1-противник, способный измерить wall-clock
`Container::open_space` (например, process-monitoring observer на
том же host'е), может infer *owned-fraction* контейнера —
отношение chunks, decryptable под supplied-паролем, к total
chunks. Утечка происходит в AEAD-decrypt path'е: failed MAC
short-circuit'ит до body-decrypt'а; successful MAC прогоняет
ChaCha20 над full body. Так per-chunk wall-clock — функция
«owned?» с CPU-cycle granularity gap'ом.

**Что утекает.** Approximate `frac_owned` (±10-20%) для
observed open. **Не** идентифицирует, какие slots owned. **Не**
различает «chunks другого space» от «garbage padding» (оба
fail AEAD identically). Утечка *coarser* file size +
cleartext-header fingerprint'а и *additive* к ним.

**Что НЕ утекает.** Per-slot ownership (требовало бы per-chunk
timing resolution, которую process-level observer обычно не
имеет); identity «другого space»; commit-count любого другого
space.

#### Измерение (audit pass 5, 2026-05-28)

[`benches/timing_oracle.rs`](../../../crates/hidden-volume/benches/timing_oracle.rs)
characterises утечку через все три scan-mode варианта
(sequential, parallel-scan, mmap). Запуск:

```sh
cargo bench --bench timing_oracle --features parallel-scan,mmap -- --quick
```

Sample results из 2026-05-28 run'а на Apple M5 Pro (macOS 26.5,
APFS на NVMe, Argon2 `MIN`, 500-slot контейнер; ряд `total_500`
— тот же сценарий что fraction sweep):

| Scan-mode | frac=0.10 | frac=0.50 | frac=0.90 | Δ (0.90 − 0.10) |
|---|---:|---:|---:|---:|
| Sequential | 17.2 ms | 28.3 ms | 37.3 ms | **≈20 ms** |
| Parallel-scan | 13.0 ms | 28.8 ms | 35.0 ms | **≈22 ms** |
| Mmap | 16.6 ms | 28.0 ms | 36.4 ms | **≈20 ms** |

Per-chunk swing (Δ / total_slots = 500): **≈40 µs/chunk** на
этом железе. Предыдущая pass-15 characterisation на Windows/NVMe
измеряла ≈75 µs/chunk; magnitude утечки hardware-dependent, но
*shape* uniform по обоим run'ам.

**Key finding (audit pass 5 SC-INFO2).** Гипотеза, что
parallel-scan work-stealing вымоет per-chunk MAC-fail-vs-pass
сигнал на aggregate-open-time уровне — **отвергнута**.
Parallel и sequential утекают с тем же swing-magnitude (в
пределах noise-floor criterion'а). Mmap аналогично. TM1-утечка
**не** зависит от выбора scan-mode'а; opting in to parallel-scan
или mmap для performance не mitigate'ит oracle.

#### Mitigation (shipped 2026-05-28, opt-in — частичная)

Bounded mitigation отгружен как opt-in API:
[`Container::open_space_constant_time`](../../../crates/hidden-volume/src/container/mod.rs)
(плюс keys-driven sibling
`open_space_with_keys_constant_time`). Для каждого slot'а scan
запускает real AEAD-decrypt, и на MAC-fail запускает ChaCha20
stream-equalizer длины `PLAINTEXT_LEN` для consumption CPU
time'а, приблизительно эквивалентного body-decrypt'у при
successful MAC.

**Честный scope этой митигации (audit pass 19 follow-through,
2026-05-28).** Equalizer закрывает **ChaCha20-body компоненту**
per-chunk swing'а — эмпирически один ChaCha20-stream над 4040
байтами — это ~1-3 µs на современных x86/ARM. **Полный per-chunk
swing, измеренный в bench'е выше — ~40 µs/chunk** на M5 Pro.
Оставшиеся ~37 µs приходят от работы, которая случается **только
на MAC-pass** и не выравнивается: парсинг plaintext-frame'а
(`chunk/format.rs::decode_plaintext`), аллокация/копирование в
возвращаемый `Vec<u8>`, и bookkeeping `owned_slots.push(slot)`
внутри open-цикла. Constant-time path *уменьшает* per-chunk
distinguisher примерно до parsing+alloc компоненты (~порядок
меньше unmitigated-swing'а), но **не** доводит её до нуля.

Полное закрытие потребовало бы дополнительно (a) запускать dummy
`decode_plaintext` над frozen scratch-buffer'ом на MAC-fail и (b)
padd'ить стоимость `owned_slots.push` — ничего из этого сегодня
не отгружено. Tracked как v1.x carried-forward #7 follow-up.

**Что это значит для host-app threat model.**

| Элемент threat model | Sequential `open_space` | Sequential `open_space_constant_time` |
|---|---|---|
| Per-chunk wall-clock swing | ≈40 µs/chunk (M5 Pro) | ≈на порядок меньше (только parsing+alloc residual) |
| Aggregate `frac_owned` recovery | ±10-20% от полного open-time | сильно уменьшен, но не до нуля |
| Что process-level observer всё ещё может вывести | точный `frac_owned` | грубый activity-envelope (open запустился + общее число slot'ов) |

Коротко: equalizer — это содержательное hardening (закрывает
доминирующую компоненту), но НЕ делает open-path "constant time"
в строгом крипто-смысле. Host-app'ы, где угроза включает
process-monitoring observer'а, способного снять много измерений,
должны дополнительно padd'ить post-open обработку извне
(например, запускать open внутри fixed-duration
`tokio::time::sleep`-окна).

**Cost.** Approximately удваивает open-time на garbage-heavy
контейнерах (equalizer runs для каждого non-owned chunk'а). На
sparse, padding-heavy storage'е это meaningful (сотни ms на
100-MiB profiles); на dense контейнерах (owned-fraction ≥ 0.9)
negligible. Default-caller'ы должны stick с
`Container::open_space`, если их threat model не включает
process-level timing observer.

**Scope (v1.0, отгружено 2026-05-28).** Все три scan-режима имеют
constant-time companion'ы:

- [`Container::open_space_constant_time`](../../../crates/hidden-volume/src/container/mod.rs)
  — sequential (изначальная mitigation entry).
- [`Container::open_space_parallel_constant_time`](../../../crates/hidden-volume/src/container/mod.rs)
  — parallel-scan + equalizer. Multi-core wall-clock-выигрыш
  комбинируется с per-chunk timing-fix'ом.
- [`Container::open_space_mmap_constant_time`](../../../crates/hidden-volume/src/container/mod.rs)
  — mmap + equalizer. Zero-allocation read-path сохраняет
  cold-cache-ускорение; equalizer переиспользует тот же
  `equalize_timing_via_chacha20`-примитив на каждом MAC-fail.

У каждого companion есть `_with_keys_…`-собрат для cached-keys-
пути. Parsing/alloc-residual swing применяется единообразно ко
всем трём (это та часть, которую equalizer НЕ покрывает — см.
honest-scope-таблицу выше). Naming «constant-time scan»
consistent across all three: caller'ы, выбирающие любой,
получают то же security-свойство и те же caveat'ы.

**Helper.** Equalizer сам в
[`crypto::aead::equalize_timing_via_chacha20`](../../../crates/hidden-volume/src/crypto/aead.rs)
— `pub(crate)`-функция, запускающая XChaCha20 над dummy-buffer
запрошенной длины с constant key/nonce (operations bit-
identical regardless of key, так это не вводит side channel
собственный).

**Воспроизвести локально.** Bench-результаты hardware-dependent
(NVMe vs SATA vs eMMC vs network FS); tighter или looser swing
expected на других платформах. Если ваша threat model включает
process-level timing observer, прогоните bench на вашем target-
железе до полагания на документированную magnitude.

## 5. Сводка митигаций по областям кода

Рецензент, аудирующий `src/`, должен сосредоточиться на:

| Модуль | Основные инварианты | Audit pass |
|---|---|---|
| `src/crypto/kdf.rs` | D1 (случайность salt), D2 (стоимость Argon2 ≥ MIN), M1 | CT, MEMORY |
| `src/crypto/aead.rs` | D1, D2 (CT для тега), I1, M1 | CT, MEMORY, PLAINTEXT |
| `src/crypto/derive.rs` | D2 (per-space domain separation), M1 | CT, MEMORY |
| `src/chunk/format.rs` | D1 (случайный padding внутри plaintext), I1 | PLAINTEXT |
| `src/container/file.rs` | I2 (fsync), I3 (slot ownership) | FSYNC |
| `src/container/header.rs` | D1 (header layout) | — |
| `src/container/mod.rs` | I3 (cross-space write isolation), C1 | FSYNC |
| `src/space/mod.rs` (commit_tx) | I2 (3-fsync), R1 (commit_seq), C1 | FSYNC |
| `src/space/mod.rs` (vacuum_orphans / vacuum_data_batches) | T2' митигация (forward-secrecy после delete / overwrite) | MEMORY |
| `src/space/superblock.rs` | I2 (max-seq pick) | — |
| `src/space/index.rs` | I3 (B+ tree per-namespace), R1 (Merkle hash chain) | — |
| `src/space/log.rs` | M1 (Zeroizing для raw zstd-буфера) | PLAINTEXT |
| `src/open/mod.rs` | D2 (silent skip при AEAD-fail), R1 (заполнение commit_history) | CT |
| `src/cancel.rs` | C1 | — |
| `src/tx/mod.rs` | I3 (Tx slot tracking) | — |
| `src/padding/` | D1 (обфускация размера) | — |
| `src/error.rs` | D2 (унификация AuthFailed) | CT |

## 6. История аудитов

| Дата | Pass | Результат | Документ |
|---|---|---|---|
| v0.5 первый проход | Constant-time | CT-проблем в нашем коде не найдено. Secret compares полностью делегированы RustCrypto. | `docs/ru/security/audits/constant-time.md` |
| v0.5 первый проход | Memory hygiene | Исправлены `derive_chunk_key` / `derive_subkey` — возвращают `Zeroizing<[u8; 32]>`. Документирована отсрочка по user-data. | `docs/ru/security/audits/memory.md` |
| v0.5 первый проход | fsync ordering | Все 7 fsync-точек прослежены, все барьеры на месте согласно `DESIGN.md` §6. Особенность macOS `F_FULLFSYNC` документирована как ответственность host-app. | `docs/ru/security/audits/fsync.md` |
| v0.5 первый проход | Plaintext leak | 7 транзитных pre/post-encryption буферов обёрнуты в `Zeroizing`. Документирована отсрочка по user-owned Vec. | `docs/ru/security/audits/plaintext.md` |
| 2026-05-09 | Pass 16 (R-STREAMING-REPACK + TM1 + R-FFI-PWD-Z) | `Container::repack` переписан как streaming-pipeline (≈ 4 MiB working set на страницу, было O(total plaintext)); `MAX_OPEN_SCAN_CHUNKS = 16M` ≈ 64 GiB cap на open-scan; FFI password-буферы обёрнуты в `Zeroizing` на всех точках входа. | TASKS.md pass-16 секция |
| 2026-05-09 | Pass 17 (security/quality follow-through) | Новый `Error::ContainerTooLarge` variant + симметричный write-side budget gate; `open_space_verified` отсрочил auto-vacuum до успеха verify; `PaddingPolicy::garbage_after_commit → Result<u64>`; `iter_log_after/before/range` строго отвергает не-8-байтовые ключи; async + CLI password Zeroizing; `PasswordRotation` больше не деривит `Clone`; MSRV 1.85 → 1.89. **389 тестов проходят.** | TASKS.md pass-17 секция |
| 2026-05-10 | Pass 18 (second-reviewer follow-through) | M1: `commit_tx` больше не Err после durable commit; M2: `verify_integrity` покрывает DataBatch chunks; M3: `atomic_rewrite_under_source_lock` race-window сужен через re-open + inode-preservation check; M4: Android lock-skip precondition задокументирован; M5: v3 format-binding requirement зафиксирован. | CHANGELOG `[Unreleased]` (pass-18 секция) |
| 2026-05-28 | **v1.0.0 release** | Format freeze (`format_version = 3`); TM1 CT companions отгружены для parallel-scan и mmap (закрывает caveat «Sequential-scan only» из §4.4); Android lock hardened — pass-18 M4 documented no-op заменён на реальный `flock(2)` через libc, так что `android:process=":subname"` multi-process races корректно сериализуются; cargo-audit release-blocking (branch CI gate). 401 тест проходит. | CHANGELOG `[1.0.0]` |
| 2026-05-28 | 5-pass deep-review series (adversarial-stance / primitive-level / side-channel-surface / format-fuzzing / threat-model-challenge) | 0 critical / 0 high / 0 medium findings. SC-INFO2 закрыт multi-variant TM1-bench'ем (parallel-scan НЕ вымывает сигнал). F-A5 закрыт `MAX_TREE_DEPTH = 3` cap'ом в B+ tree walker'ах. F-TM1 частично смягчён opt-in `Container::open_space_constant_time`. | `docs/ru/security/audits/*.md` |
| 2026-05-28 | v3 format-bump (#8 + #9 + #10) | #8 kind-tag bytes (0x01 / 0x02) явные в BLAKE3-входах; #9 криптографическая привязка версии через post-Argon2 BLAKE3; #10 per-space derived `container_id` (закрывает D1-A2 fingerprint, реклассифицирует F-PAD в DoS-only). `HEADER_LEN`: 80 → 48. | `docs/ru/reference/format.md` §3 |
| v1.0 (планируется) | Внешний community-review (substitute) | Self-audit dossier опубликован как substitute paid review'у (anonymity + no-budget rationale); community-researchers welcome через `SECURITY.md` disclosure timeline. | `docs/ru/security/audits/self-audit.md` |

## 7. Запрос на review — что мы хотим, чтобы внешний review подтвердил

Для каждого инварианта в §3 рецензента просят подтвердить или
опровергнуть:

1. **D1.** Файл неотличим от случайного против T1 при наличии 48-
   байтного cleartext-заголовка (salt 32 + Argon2-params 16; v3
   убрал cleartext `container_id`). Особое внимание уделить
   случайности padding и потенциальным утечкам через side channels
   размера файла / количества чанков.
2. **D2.** Держатель пароля A не может доказать существование /
   несуществование space'а пароля B. Искать timing-различия в
   `scan_and_recover` между «неверный пароль» и «нет такого space».
   Искать случайное раскрытие информации через варианты ошибок,
   panic-сообщения или debug-форматирование.
3. **I1, I2, I3.** Per-chunk integrity, tail-corruption tolerance
   и cross-space isolation. Инспектировать 3-fsync последовательность
   `commit_tx`, ownership tracking в `Tx`, и `vacuum_orphans` /
   `vacuum_data_batches` на cross-namespace утечки.
4. **M1.** Материал ключей зануляется как документировано. Искать
   выведенные ключи / cipher state, ускользающие от обёрток
   `Zeroizing`.
5. **R1, C1.** Документированный контракт достаточен и корректно
   реализован (rollback detection в host-app; cooperative cancel
   без рисков частичного состояния).

Дополнительно:

- Спецификация формата в `DESIGN.md` §2-§10 на ambiguity / parser-
  differential баги.
- Поверхность публичного API (`Container`, `Space`, `Tx`,
  `CancelToken`, `SpaceKeys`) на misuse-resistance / footguns.
- Кросс-платформенная семантика `flock` / `pread`; reordering
  `fsync` на macOS.

## 8. Перекрёстные ссылки

- `DESIGN.md` — формальный on-disk формат и инварианты.
- `docs/ru/guide/integration.md` — нарратив интеграции с host-app.
- `docs/ru/guide/multi-device.md` — host-app sync / anchor контракт (R1).
- `docs/ru/security/audits/constant-time.md` / `docs/ru/security/audits/memory.md` /
  `docs/ru/security/audits/plaintext.md` / `docs/ru/security/audits/fsync.md` — заметки
  по аудиту по проходам.
- `docs/ru/contributing/benchmarks.md` — performance baseline (не security, но
  информирует рекомендации по hardware-tuning в `DESIGN.md` §11.1).
- `tests/` — у каждого инварианта выше есть как минимум одна
  директория тестов, упомянутая в §3.
