# hidden-volume

[🇬🇧 English](README.md) · 🇷🇺 **Русский**

Отрицаемый мультипространственный шифрованный append-only контейнер —
примитив хранения для мессенджеров и других приложений, которым нужна
правдоподобная отрицаемость при принудительном раскрытии ключей.

Один файл хранит произвольное число независимых шифрованных пространств.
Противник, получивший файл и один пароль, не может доказать существование
других пространств. У каждого пространства свои per-chunk AEAD-ключи,
выведенные из его пароля; chunk'и разных пространств взаимно
неотличимы от случайных байт.

```text
messenger.store
└── 48-байтовый открытый заголовок (salt + параметры Argon2)
    └── сетка слотов из chunk'ов фиксированного размера 4096 байт
         ├── шифрованные IndexNode chunk'и пространства A
         ├── шифрованные IndexNode chunk'и пространства B (скрытое)
         ├── шифрованные DataBatch chunk'и пространства A
         ├── padding-chunk'и (мусор)
         └── ...
```

Версия формата 3 (с 2026-05-28). Per-space `container_id`
дeriviтся из versioned master key — никакого per-space
идентификатора в открытом header'е нет. Каноническая
побайтовая раскладка — в
[`docs/ru/reference/format.md`](docs/ru/reference/format.md).

## Статус

**v1.0.0 выпущен (2026-05-28).** On-disk формат и публичный API
теперь заморожены — любое последующее breaking change требует
major-bump v2.0 и полноценного migration tool'а. См.
[`TASKS.md`](TASKS.md) для milestone-roadmap,
[`DESIGN.ru.md`](DESIGN.ru.md) для design-rationale, а
[`docs/ru/reference/format.md`](docs/ru/reference/format.md) — для
канонической байтовой спецификации on-wire формата (заморожена на
v1.0). Гайд по интеграции в host-app:
[`docs/ru/guide/integration.md`](docs/ru/guide/integration.md). Формальная
модель угроз: [`docs/ru/security/threat-model.md`](docs/ru/security/threat-model.md).
Operations playbook (бэкап, восстановление, ротация ключей, recovery,
scrub): [`docs/ru/guide/operations.md`](docs/ru/guide/operations.md).
Политика semver: [`docs/ru/reference/semver.md`](docs/ru/reference/semver.md).

| Возможность | Статус |
|---|---|
| Multi-space deniability (инварианты D1, D2) | ✓ доступно |
| KV-индекс с namespaces (2-уровневое B+ дерево) | ✓ доступно |
| Append-log через DataBatch + zstd | ✓ доступно |
| **Пагинированный лог** (`iter_log_after` / `iter_log_before`) | ✓ доступно |
| Crash recovery (3-fsync протокол) | ✓ доступно + property-based crash proptest |
| Forward-secrecy (`vacuum_orphans` на open) | ✓ доступно |
| Compaction / repack с batch scrub | ✓ доступно |
| Multi-Superblock реплики (защита от corruption) | ✓ доступно |
| Padding policy + initial garbage | ✓ доступно |
| Exclusive / shared file lock (multi-process safety) | ✓ доступно |
| **Read-only режим** (`open_readonly`, `LOCK_SH`) | ✓ доступно |
| **Кооперативная отмена** (`CancelToken`) | ✓ доступно (open + repack) |
| **Multi-device anchors** (`commit_seq` + `commit_history`) | ✓ доступно, см. [`multi-device.md`](docs/ru/guide/multi-device.md) |
| **Merkle integrity walk** (`verify_integrity`) | ✓ доступно |
| **Streaming open** (O(M·16 B) памяти независимо от размера контейнера) | ✓ доступно |
| **Параллельный scan** (фича `parallel-scan`, Unix, 2.8× на 40 MiB → 7.4× на 400 MiB) | ✓ доступно |
| **mmap reader** (фича `mmap`, Unix, zero-copy путь scan'а) | ✓ доступно |
| Property-тесты + parser-fuzzing | ✓ доступно (proptest + 26 parser-fuzz кейсов) |
| Аудиты (CT / memory / fsync / plaintext-leak) | ✓ все четыре проведены |
| Performance benchmarks | ✓ доступно (см. [`docs/ru/contributing/benchmarks.md`](docs/ru/contributing/benchmarks.md)) |
| Tokio-async обёртка (крейт `hidden-volume-async`) | ✓ доступно |
| Кэш pre-derived ключей (skip Argon2id на relaunch) | ✓ доступно |
| `hv` CLI (фича `cli`) | ✓ доступно |
| FFI-биндинги (Kotlin / Swift / Python / Ruby через uniffi 0.31) | ✓ доступно (v0.8 scaffold + сгенерированные биндинги) |
| Внешнее security-ревью | планируется (gate v1.0) |

## Quick start

```rust
use hidden_volume::{Container, crypto::kdf::Argon2Params};
use hidden_volume::space::index::Namespace;

# fn run() -> hidden_volume::Result<()> {
// Создаём контейнер. Параметры Argon2 подбираются под целевое железо:
//   Argon2Params::LIGHT   — слабый ARM (Cortex-A53)
//   Argon2Params::DEFAULT — типичный смартфон (последние 5 лет)
//   Argon2Params::HEAVY   — desktop / server-class
let mut container = Container::create(
    "/path/to/messenger.store",
    Argon2Params::DEFAULT,
)?;

// Первое пространство — основной профиль пользователя.
{
    let mut space = container.create_space(b"main-password")?;
    let mut tx = space.begin_tx();
    tx.put(Namespace::SETTINGS, b"username", b"alice")?;
    tx.put(Namespace::CONTACTS, b"bob",      b"bob@example.com")?;
    tx.append_log(Namespace::MESSAGE_LOG, 1, b"first message")?;
    tx.commit()?;
}

// Скрытое второе пространство, полностью независимое.
{
    let mut hidden = container.create_space(b"hidden-password")?;
    let mut tx = hidden.begin_tx();
    tx.put(Namespace::SETTINGS, b"username", b"actual-identity")?;
    tx.commit()?;
}

// Переоткрываем и читаем обратно.
let mut container = Container::open("/path/to/messenger.store")?;
let mut main = container.open_space(b"main-password")?;
assert_eq!(
    main.get(Namespace::SETTINGS, b"username")?.as_deref(),
    Some(&b"alice"[..])
);
# Ok(()) }
```

Полностью runnable-пример лежит в
[`crates/hidden-volume/examples/messenger_lifecycle.rs`](crates/hidden-volume/examples/messenger_lifecycle.rs):

```sh
cargo run --example messenger_lifecycle
```

Полный гайд по каждому API, нужному мессенджеру (пагинация,
cancellation, multi-device anchors, key caching, integrity audits,
анти-паттерны) — [`docs/ru/guide/integration.md`](docs/ru/guide/integration.md).

### Пагинация message-history

Не материализуйте лог из 100K сообщений в память; используйте
курсорную пагинацию. `iter_log_before` — канонический primitive для
chat-UI («скролл вверх до старых сообщений»):

```rust,ignore
use hidden_volume::space::index::Namespace;

// Первая страница: 50 самых свежих сообщений.
let page1 = space.iter_log_before(Namespace::MESSAGE_LOG, None, 50)?;

// Следующие страницы: передаём самый старый log_id из предыдущей страницы.
let cursor = page1.last().map(|(id, _)| *id);
let page2 = space.iter_log_before(Namespace::MESSAGE_LOG, cursor, 50)?;
```

Память: O(limit) декодированных записей плюс несколько затронутых
DataBatch chunk'ов — независимо от общего размера namespace'а.
**В 5.6× быстрее**, чем legacy `iter_log` на логе из 1000 сообщений
(87 µs против 484 µs;
[`docs/ru/contributing/benchmarks.md`](docs/ru/contributing/benchmarks.md)).

### Cancellation (mobile UX)

Долгие операции (`open_space` scan, `repack`) принимают
[`CancelToken`](crates/hidden-volume/src/cancel.rs) для кооперативной
отмены. Это необходимо потому, что `tokio::task::spawn_blocking` не
умеет прервать выполняющуюся closure сам:

```rust,ignore
use hidden_volume::cancel::CancelToken;

let token = CancelToken::new();
let arm = token.clone();
std::thread::spawn(move || {
    std::thread::sleep(std::time::Duration::from_secs(5));
    arm.cancel();
});

match container.open_space_cancellable(b"password", &token) {
    Ok(_) => { /* успели разблокировать */ }
    Err(hidden_volume::Error::Cancelled) => { /* пользователь нажал cancel */ }
    Err(e) => return Err(e),
}
```

### Rollback / fork detection

После каждого commit'а сохраняйте `space.commit_seq()` в TPM /
Secure Enclave / серверный счётчик. На reopen проверяйте, что
состояние файла не подменили:

```rust,ignore
let cur = space.commit_seq();
let history = space.commit_history();
if cur < anchor_seq || !history.contains(&anchor_seq) {
    panic!("rollback или fork обнаружен — файл заменён старой версией");
}
```

Полный алгоритм + tradeoffs хранения якоря —
[`docs/ru/guide/multi-device.md`](docs/ru/guide/multi-device.md).

### Self-test целостности

Обходит весь Merkle hash chain за 125 µs (sub-millisecond на тестовом
железе) — рекомендуется после sync'а от пира или как периодический
defense-in-depth audit:

```rust,ignore
let report = space.verify_integrity()?;
println!(
    "verified {} chunks across {} namespaces, max depth {}",
    report.chunks_verified, report.namespaces_verified, report.max_depth,
);
```

### CLI-утилита (`hv`)

Фича `cli` собирает бинарь `hv` для отладки, скриптов и миграции:

```sh
cargo install --path . --features cli
```

Подкоманды:

```sh
hv info <path>                                   # инфо открытого заголовка, без пароля
hv create <path> [--params LIGHT|DEFAULT|HEAVY|MIN]
hv create-space <path>                           # пароль с первой строки stdin
hv inspect <path>                                # список namespaces со счётчиками
hv get <path> <namespace_id> <key>
hv put <path> <namespace_id> <key> <value>       # value через argv (виден в /proc/<pid>/cmdline)
hv put <path> <namespace_id> <key> --value-stdin # value как вторая строка stdin (приватно)
hv repack <source> <dest>                        # пароли из stdin, по одному на строку
```

Пароли всегда читаются из stdin — env-var fallback'а нет (env-vars
утекают через `/proc/<pid>/environ` и shell history). Для
неинтерактивного использования передавайте пароль по pipe:

```sh
printf 'secret\n' | hv create-space messenger.store
printf 'secret\n' | hv put messenger.store 1 username alice
printf 'secret\n' | hv get messenger.store 1 username
printf 'secret\n' | hv inspect messenger.store
# Чтобы избежать argv-утечки самого value:
printf 'secret\nbob@example.com\n' | hv put messenger.store 2 bob --value-stdin
```

ID namespace'ов соответствуют константам `Namespace`:
- `1` SETTINGS
- `2` CONTACTS
- `3` MESSAGE_LOG
- `4` MEDIA
- `5+` пользовательские namespaces host-app'а

### Async / Tokio-интеграция

Отдельный крейт **[`hidden-volume-async`](crates/hidden-volume-async)**
предоставляет `AsyncContainer`, который оффлоадит sync-операции в
blocking-thread пул Tokio через `spawn_blocking`. Sync-ядро остаётся
без зависимости от tokio — async-пользователи опт-инят tokio явно
зависимостью на wrapper-крейт; sync-only пользователи (mobile /
single-process desktop) платят нулевую dep-цену за tokio.

```toml
[dependencies]
hidden-volume = { version = "..." }
hidden-volume-async = { version = "..." }
tokio = { version = "1", features = ["rt-multi-thread"] }
```

```rust,ignore
use hidden_volume::space::index::Namespace;
use hidden_volume_async::AsyncContainer;

let container = AsyncContainer::open("/path/to/store").await?;
container.run(|c| {
    let mut s = c.open_space(b"password")?;
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"theme", b"dark")?;
    tx.commit()?;
    Ok(())
}).await?;
```

Метод `run()` принимает любую `FnOnce(&mut Container) -> Result<R>`,
так что транзакционные batch'и остаются вместе внутри одной
blocking-pool диспатчи. Для cancellable async-работы используйте
`run_cancellable(token, |c, t| …)` — он пробрасывает `CancelToken`
в closure (необходимо потому, что `spawn_blocking` не умеет
прервать выполняющуюся closure сам — токен решает это обходом).

### Параллельный scan (фича `parallel-scan`, только Unix)

Для multi-core хостов, открывающих контейнеры на много MiB,
`Container::open_space_parallel` параллелит discovery-scan через
work-stealing пул rayon (с потолком 4 потока, лениво кэшируется).
Скорость растёт с размером контейнера — на 12-нитевом x86
dev-хосте:

| Контейнер | Sequential | Parallel | Speedup |
|---|---:|---:|---:|
| 40 MiB / 10K слотов | 52 ms | 18 ms | 2.8× |
| 200 MiB / 50K слотов | 608 ms | 264 ms | 2.3× |
| 400 MiB / 100K слотов | 1499 ms | 204 ms | **7.4×** |

**TL;DR для разработчиков мессенджеров.** Включайте `parallel-scan`
для любого multi-core хоста с реалистичной для мессенджера историей
(≥ 40 MiB). На 400 MiB истории (heavy-пользователь) разблокировка
падает с 1.5 s до 200 ms — заметно в UX. Оставляйте OFF на
single-core mobile (он сложится в 1 поток, и вы заплатите
~6 MiB binary-size за rayon без speedup'а). Подробный анализ —
[`docs/ru/contributing/benchmarks.md`](docs/ru/contributing/benchmarks.md)
«Parallel-scan tuning» + «Scaling».

### mmap reader (фича `mmap`, только Unix)

Zero-copy альтернативный путь scan'а. Маппит весь файл контейнера
через `mmap(2)` и вырезает каждый chunk из mapping'а —
`Container::open_space_mmap` вместо streaming-`pread` пути.

Когда использовать: cold-cache открытия multi-GiB контейнеров,
где избежание per-chunk syscall overhead'а даёт измеримый
wall-clock выигрыш. На warm-cache повторных открытиях разница
небольшая; kernel page cache и так доминирует. Фича обменивает
зависимость `memmap2` (~80 KiB compiled) и `unsafe` Mmap-конструкцию
на этот выигрыш — `LOCK_EX` / `LOCK_SH` flock исключают
конкурирующих writer'ов, что и делает unsafe-вызов безопасным.

Гарантия поведения: идентичное `Space` state'у sequential и parallel
путей. `tests/mmap_scan.rs` (7 сценариев) делает cross-check против
обоих — см. «Архитектура» о том, какой crate хостит какой путь.

## От чего это защищает

- **Конфиденциальность** каждого пространства против любой стороны
  без его пароля (XChaCha20-Poly1305 на chunk, Argon2id KDF).
- **Cross-space изоляция** — открытие space A ни не раскрывает, ни
  случайно не портит space B (per-space ключи + append-only файл).
- **Single-snapshot deniability** (D1) — файл статистически
  неотличим от равномерно-случайного blob'а с одним 48-байтовым
  открытым заголовком (salt + параметры Argon2). v3 (2026-05-28)
  убрал per-space `container_id` из открытого header'а, закрыв
  D1-A2 fingerprint.
- **Compelled-key deniability** (D2) — раскрытие пароля даёт одно
  пространство; держатель этого пароля не может доказать
  существование других.
- **Per-chunk целостность** — модификация байт даёт сбой AEAD на
  затронутом chunk'е.
- **Forward-secrecy после reopen** — `Container::open_space`
  автоматически зачищает orphan-IndexNode chunk'и;
  `Container::compact` делает то же для DataBatch.
- **Crash safety** — three-fsync протокол коммита с
  multi-replica Superblock fallback'ом. Валидируется 8 ручными
  truncation-сценариями + property-based crash-recovery
  (random-ops × random-truncate, ассертит, что recovered seq —
  это ранее закоммиченный seq) + exhaustive
  truncate-at-every-slot sweep.
- **Multi-process safety** — exclusive `flock(LOCK_EX)` на open
  предотвращает двух writer'ов; `LOCK_SH` позволяет нескольким
  reader'ам сосуществовать с одним writer'ом (`open_readonly`).
  Полезно для sync-агентов или backup-инструментов рядом с
  приложением.
- **Tamper-evident целостность** — `verify_integrity()` обходит
  Merkle-цепь (Superblock → Commit → дерево IndexNode) и сообщает
  любой mismatch хэша как
  `Error::IntegrityFailure { detail, slot }`.
- **Кооперативная отмена** — долгие операции (open scan, repack)
  опрашивают `CancelToken` на периодических чекпоинтах. Mobile UX
  может прервать попытку разблокировки в полёте, не оставив файл
  в частичном состоянии.
- **Streaming-bounded память на open** — discovery-scan удерживает
  ~16 байт на owned chunk независимо от размера файла; контейнеры
  в multi-GiB открываются без OOM на слабом ARM.

## От чего это НЕ защищает

Прочитайте этот список внимательно — файл hidden-volume отрицаем
ровно настолько, насколько отрицаемо поведение host-приложения
вокруг него.

- **Side-channel утечки на уровне приложения** — недавно открытые
  файлы, IME-кэши, скриншот-thumbnail'ы, swap, system logs.
  Библиотека их не видит; host-app должен видеть.
- **Multi-snapshot byte-diff анализ** (T2') — in-place rewrite или
  tombstone существующего слота оставляет «этот байт менялся»
  сигнал, отличающий активные слоты от настоящего мусора. См.
  [`DESIGN.ru.md`](DESIGN.ru.md) §1.
- **Rollback-атаки (из коробки)** — если противник захватил файл в
  момент T₁ и восстановил после того, как пользователь сделал
  commit в T₂, пользователь теряет недавнее состояние, а
  библиотека сама по себе этого не детектит. Библиотека ДЕЙСТВИТЕЛЬНО
  выставляет `Space::commit_seq()` + `Space::commit_history()`,
  чтобы host-app мог реализовать rollback / fork detection против
  внешнего якоря (TPM, серверный счётчик, signed log) — см.
  [`docs/ru/guide/multi-device.md`](docs/ru/guide/multi-device.md).
- **Сам факт того, что файл шифрован** — high-entropy файлы
  видимы любому forensic-сканеру. Отрицаемость про *какие* и
  *сколько* секретов внутри, а не про сокрытие того, что файл —
  шифротекст.

## Tuning под железо

Стоимость Argon2id — per-container, задаётся при создании,
персистится в открытом заголовке. Выбирайте preset под целевое
устройство:

| Preset | m | t | p | Open time | Use case |
|---|---|---|---|---|---|
| `Argon2Params::LIGHT` | 16 MiB | 3 | 1 | ~30 ms | Слабый ARM (Cortex-A53) |
| `Argon2Params::DEFAULT` | 64 MiB | 3 | 1 | ~100 ms | Mid-range mobile |
| `Argon2Params::HEAVY` | 256 MiB | 4 | 4 | ~250 ms | Desktop / server |

`Argon2Params::MIN` (m=8 MiB, t=2, p=1) — пол; библиотека
отказывается открывать или создавать контейнер с параметрами
слабее (защита от malicious-host атаки).

## Архитектура

Cargo workspace с четырьмя крейтами:

```
crates/hidden-volume/        — sync-ядро (без зависимости от tokio)
└── src/
    ├── crypto/              — примитивы: Argon2id KDF, XChaCha20-Poly1305 AEAD,
    │                          BLAKE3 keyed derivation, getrandom RNG
    ├── chunk/               — формат chunk'а 4096 байт + enum ChunkKind
    │                          (Superblock=0x01, IndexNode=0x02, Commit=0x05,
    │                          DataBatch=0x06; 0x03/0x04 зарезервированы)
    ├── container/           — file-level append-only ops, header, PaddingPolicy,
    │                          ContainerOptions, RepackOptions, режимы блокировки
    │                          LOCK_EX / LOCK_SH, API repack + compact_known + change_passwords
    ├── space/               — per-space superblock + commit_history; mod.rs разбит
    │                          на submodule'ы commit / vacuum / log_iter / integrity
    │                          (pass-8 E7); B+ tree IndexNode (Leaf/Internal),
    │                          encoding DataBatch-лога (zstd), пагинация
    │                          iter_log_after / _before, vacuum_orphans +
    │                          vacuum_data_batches, verify_integrity Merkle walk,
    │                          erase_namespace, stats
    ├── tx/                  — Tx<'s, 'f> с put/delete/append_log/commit;
    │                          encoding CommitPayload (Merkle root над IndexRoots)
    ├── padding/             — политики None | BucketGrowth | FixedRatio; пресеты
    │                          0..=3 персистируются через Argon2Params.version биты 16..24
    ├── open/                — discovery-scan + recovery (sequential streaming;
    │                          опционально rayon-parallel через фичу `parallel-scan`,
    │                          опционально mmap через фичу `mmap`)
    ├── cancel.rs            — CancelToken (Arc<AtomicBool>) для кооперативной отмены
    ├── bin/hv.rs            — CLI `hv` (фича `cli`): info, create, inspect, …
    └── error.rs             — единый enum Error; AuthFailed объединяет wrong-password
                               и no-such-space (инвариант отрицаемости D2)

crates/hidden-volume-rt/     — внутренние runtime-хелперы (pass-8 E5/E6 extraction)
└── src/lib.rs               — OwnedSpace (self-referential Box<Container> +
                               Space<'static>) и адаптер run_blocking, общие
                               для async + ffi крейтов. Не для конечных пользователей.

crates/hidden-volume-async/  — Tokio-обёртка (зависит от hidden-volume + -rt)
└── src/lib.rs               — AsyncContainer (run / run_cancellable) и
                               AsyncSpace (run / stream_log_pages_*); offload
                               через spawn_blocking; mutex-сериализованный handle.

crates/hidden-volume-ffi/    — uniffi 0.31 FFI (зависит от hidden-volume + -rt)
└── src/lib.rs               — SpaceHandle (sync) + AsyncSpaceHandle (Tokio);
                               типизированная поверхность для Kotlin / Swift /
                               Python / Ruby через bindings/.
```

См. [`DESIGN.ru.md`](DESIGN.ru.md) для полной on-disk format
specification, threat-model и каталога инвариантов.

## Тестирование

```sh
cargo test --all-features
cargo test --doc                  # crate-level doctest
cargo bench                       # baseline'ы — docs/ru/contributing/benchmarks.md
cargo clippy --all-targets --all-features -- -D warnings
```

43 файла integration-тестов (39 в `hidden-volume`, 3 в
`hidden-volume-async`, 1 в `hidden-volume-ffi`) плюс unit-тесты;
**397 тестов** зелёные на dev-машине. Хайлайты:

- **Crash recovery**: 8 ручных truncate-сценариев + property-based
  crash proptest (24 случайных workload × 3 инварианта:
  monotonicity, no-panic, idempotence) + exhaustive
  truncate-at-every-slot sweep.
- **Parser fuzzing**: 26 stable-Rust proptest-кейсов —
  `decode_doesnt_panic` + roundtrip + edge-cases для каждого
  wire-format'а.
- **Property-test против reference-модели** (BTreeMap) для
  случайных Put/Delete/AppendLog/Commit/Reopen последовательностей.
- **Корректность пагинации**: 13 сценариев для `iter_log_after` /
  `iter_log_before`, покрывая empty / sparse / B+ split /
  cross-batch.
- **Multi-device контракт**: 8 сценариев для `commit_history`
  (dedup, reopen survival, isolation, post-compact reset).
- **Integrity Merkle walk**: 10 сценариев для `verify_integrity`,
  включая AEAD-corruption, локализованную в конкретные слоты.
- **Cancellation**: 10 сценариев для open + repack cancellation,
  включая async `run_cancellable` smoke.
- **Multi-process safety**: locking + readonly + sequential
  hand-off.
- **Memory + plaintext-leak hygiene**: type-level regression-тесты,
  фиксирующие `Zeroizing` обёртки на ключах и транзитном plaintext.

## Лицензия

Двойная лицензия — на ваш выбор:

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
