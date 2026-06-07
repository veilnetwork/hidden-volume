# Гайд по интеграции

[🇬🇧 English](../../en/guide/integration.md) · 🇷🇺 **Русский**

Как построить host-app — как правило, децентрализованный мессенджер — поверх
`hidden-volume`. Это нарративное дополнение к `DESIGN.md` (формальная
спецификация) и rustdoc по каждому API (reference). Читайте это первым.

Если что-либо в этом документе противоречит `DESIGN.md`, побеждает `DESIGN.md`.

## Что вы получаете

`hidden-volume` — это **локальный слой at-rest persistence**. Он владеет одним
файлом. Внутри этого файла находится 1+ зашифрованных пространств (spaces),
каждое разблокируется отдельным паролем. С точки зрения host-app каждое
space выглядит как маленький KV-store + namespace типа append-only log,
оба транзакционные.

Что в библиотеку НЕ входит:
- Сетевой транспорт. P2P, синхронизация, transit-шифрование — забота host-app.
- Identity / pairing / contact discovery. Забота host-app.
- Push-уведомления, состояние UI, кэши IME. Забота host-app.

Библиотека синхронная в ядре, с опциональной тонкой обёрткой над tokio.

---

## 1. Быстрый старт

```rust
use hidden_volume::{Container, crypto::kdf::Argon2Params};
use hidden_volume::space::index::Namespace;

# fn main() -> hidden_volume::Result<()> {
// Создаём контейнер. Выбираем пресет под класс железа:
let mut container = Container::create(
    "/path/to/messenger.store",
    Argon2Params::DEFAULT,  // про компромисс LIGHT/DEFAULT/HEAVY см. §2
)?;

// Создаём space (один профиль пользователя / одну партицию чата).
let mut space = container.create_space(b"correct horse battery staple")?;

// Записываем KV-настройки + пару контактов в одной транзакции.
let mut tx = space.begin_tx();
tx.put(Namespace::SETTINGS, b"username", b"alice")?;
tx.put(Namespace::CONTACTS, b"bob",   b"bob@example.com")?;
tx.commit()?;

// Дописываем сообщения в namespace message log.
let mut tx = space.begin_tx();
tx.append_log(Namespace::MESSAGE_LOG, 1, b"hi bob")?;
tx.append_log(Namespace::MESSAGE_LOG, 2, b"how are you")?;
tx.commit()?;

drop(space);
drop(container);

// Переоткрываем в другом месте.
let mut container = Container::open("/path/to/messenger.store")?;
let mut space = container.open_space(b"correct horse battery staple")?;
assert_eq!(
    space.get(Namespace::SETTINGS, b"username")?.as_deref(),
    Some(&b"alice"[..])
);
# Ok(()) }
```

---

## 2. Тюнинг под железо (пресеты Argon2)

Параметры Argon2id живут в открытом заголовке (задаются на момент создания).
Выбирайте один пресет на класс устройства — не пытайтесь подкручивать
динамически.

| Пресет | Память | Итерации | Параллелизм | Когда |
|---|---|---|---|---|
| [`Argon2Params::LIGHT`]   |  16 МиБ | 3 | 1 | Слабые ARM (Cortex-A53, embedded) |
| [`Argon2Params::DEFAULT`] |  64 МиБ | 3 | 1 | Среднее мобильное (телефоны последних 5 лет) |
| [`Argon2Params::HEAVY`]   | 256 МиБ | 4 | 4 | Десктоп / серверный класс |

[`Argon2Params::MIN`] — это пол; библиотека отказывается открывать или
создавать ниже него. Он существует, чтобы защитить от malicious-host-атаки,
которая принудительно выставила бы жертве тривиально brute-force-уемые
параметры.

Host-app должен выбрать один пресет на *новый* контейнер на основе
определения класса устройства. `Container::repack` — путь миграции для
перенастройки впоследствии.

### Параллелизм open-scan (фича `parallel-scan`)

Пресет Argon2 выше — это CPU-стоимость на одну разблокировку. Когда
Argon2 завершается, open-scan проходит по каждому chunk в файле (O(N)
trial-decrypt'ов AEAD). На больших контейнерах — мессенджеры с тяжёлой
историей, переходящие за ~200 МиБ — этот скан становится доминирующей
стоимостью разблокировки.

Cargo-фича `parallel-scan` (только Unix) распараллеливает этот скан
через work-stealing pool из rayon, ограниченный 4 потоками, с
process-wide пулом, кэшированным через `OnceLock`. Публичная поверхность:
[`Container::open_space_parallel`] / [`open_space_with_keys_parallel`]
(оба за `#[cfg(all(feature = "parallel-scan", unix))]`).

**Измеренное ускорение на 12-поточном x86 хосте** (полные числа в
[`docs/ru/contributing/benchmarks.md`](../contributing/benchmarks.md)):

| Размер профиля пользователя | Последовательная разблокировка | Параллельная разблокировка |
|---|---:|---:|
| Лёгкий (~40 МиБ) | 52 мс | 18 мс |
| Средний (~200 МиБ) | 608 мс | 264 мс |
| Тяжёлый (~400 МиБ) | **1.5 с** | **0.2 с** |

**TL;DR для разработчиков мессенджеров.** Включайте `parallel-scan` на
любом мультиядерном хосте с реалистичной для мессенджера историей
(≥ 40 МиБ). Ускорение растёт с размером — на 400 МиБ разблокировка
падает с 1.5 с («приложение зависло?») до 200 мс (незаметно). Оставляйте
фичу ВЫКЛЮЧЕННОЙ на одноядерном мобильном (класс Cortex-A53): кап в
4 потока схлопывается в 1, ускорения нет, и вы заплатите ~6 МиБ rayon
в бинаре впустую.

[`Container::open_space_parallel`]: ../src/container/mod.rs
[`open_space_with_keys_parallel`]: ../src/container/mod.rs

---

## 3. Две модели хранения внутри одного space

Внутри space вы выбираете, как хранить данные на каждый `Namespace`
(однобайтовый тег).

### KV namespace

Используйте [`Tx::put`] / [`Tx::delete`] / [`Space::get`] / [`Space::list`] /
[`Space::count`]. Бэкенд — B+ tree из chunks типа [`IndexNode`].

- Лимит на namespace: ~5 000–10 000 записей (зависит от размера ключа/значения).
- Ключи ≤ 256 байт; значения ≤ 2 048 байт.
- Используйте для: настроек, контактов, identity-материала — везде, где
  random-access по ключу выигрывает у последовательного скана.

### Log namespace (DataBatch)

Используйте [`Tx::append_log`] / [`Space::read_log`] / [`Space::iter_log_after`] /
[`Space::iter_log_before`] / [`Space::iter_log`]. Записи батчатся через zstd
и хранятся как chunk типа [`ChunkKind::DataBatch`] на каждую Tx.

- Вызывающий выбирает `log_id: u64` на запись (обычно монотонно
  возрастающий счётчик или таймстемп).
- Лимит на запись: 8 КиБ. Под более крупное медиа используйте отдельный
  KV namespace с content-addressed-ключом.
- Используйте для: лога сообщений, аудит-трейла событий, любого
  append-heavy-потока.

Предопределённые константы namespace: [`Namespace::SETTINGS`],
[`CONTACTS`], [`MESSAGE_LOG`], [`MEDIA`]. Свой определяйте через
`Namespace(byte)` для байтовых значений, не входящих в `RESERVED`.

---

## 4. Multi-space и multi-device

Этот раздел — TL;DR. Полный контракт — в
[`docs/ru/guide/multi-device.md`](multi-device.md).

### Несколько spaces в одном файле

```rust
# fn run(container: &mut hidden_volume::Container) -> hidden_volume::Result<()> {
let main   = container.create_space(b"main-password")?;
drop(main);
let hidden = container.create_space(b"hidden-password")?; // independent
drop(hidden);
let duress = container.create_space(b"duress-password")?; // decoy
# Ok(()) }
```

Каждое space криптографически независимо. Противник, держащий файл
плюс один пароль, не может доказать существование других spaces (D2 в
`DESIGN.md`).

### Multi-device-паттерны

Выбирайте **один** явно:

| Паттерн | Когда | Как |
|---|---|---|
| Одно устройство | по умолчанию | `Container::open` (`LOCK_EX` принудительно) |
| Последовательная передача (один общий файл, несколько процессов) | редко; нужна ФС, уважающая flock | каждый писатель открывает и закрывает; lock сериализует |
| Read-only fan-out (один писатель, много читателей) | snapshot UI, инструменты бэкапа | писатель держит `LOCK_EX`, читатели через [`Container::open_readonly`] (`LOCK_SH`) |
| Реплицированные контейнеры (один контейнер на устройство) | **рекомендуется для P2P-мессенджеров** | у каждого устройства свой файл, синхронизация на уровне message-log (ответственность host-app) |

Per-space rollback / fork detection: см. §7.

---

## 5. Пагинация (скроллинг истории сообщений)

Не вызывайте [`Space::iter_log`] на долгоживущем namespace — он
материализует весь namespace в память.

Используйте [`Space::iter_log_after`] (курсор oldest-first) или
[`Space::iter_log_before`] (курсор newest-first, канонический паттерн чата).

```rust
# fn run(space: &mut hidden_volume::Space<'_>) -> hidden_volume::Result<()> {
use hidden_volume::space::index::Namespace;

// Первая страница: 50 последних сообщений.
let page1 = space.iter_log_before(Namespace::MESSAGE_LOG, None, 50)?;
// Последующие страницы: передаём самый старый log_id с предыдущей страницы.
let cursor = page1.last().map(|(id, _)| *id);
let page2 = space.iter_log_before(Namespace::MESSAGE_LOG, cursor, 50)?;
# Ok(()) }
```

Граница памяти: `O(limit)` декодированных записей плюс несколько
затронутых DataBatch chunks (кэшируются на вызов). Не зависит от
суммарного размера namespace.

Для лент oldest-first (например, экспорт архива) используйте
`iter_log_after` с тем же паттерном курсора.

---

## 6. Cancellation (мобильный UX)

Длинные операции (скан в `open_space`, `repack`) должны быть прерываемы,
когда пользователь отменяет действие. `spawn_blocking` из tokio НЕ
прерывает выполняющуюся замыкание; библиотека использует кооперативную
cancellation через [`CancelToken`].

```rust
use hidden_volume::cancel::CancelToken;
# fn run(container: &mut hidden_volume::Container) -> hidden_volume::Result<()> {
let token = CancelToken::new();
let arm = token.clone();

// Запускаем cancel из другого потока — обычно это UI-обработчик кнопки.
std::thread::spawn(move || {
    std::thread::sleep(std::time::Duration::from_secs(5));
    arm.cancel();
});

match container.open_space_cancellable(b"password", &token) {
    Ok(_space) => { /* успели разблокировать */ }
    Err(hidden_volume::Error::Cancelled) => { /* пользователь нажал отмену */ }
    Err(other) => return Err(other),
}
# Ok(()) }
```

Cancellable API:
- [`Container::open_space_cancellable`] / [`open_space_with_keys_cancellable`]
- [`Container::repack_cancellable`]
- [`Container::compact_known_cancellable`]

Деривация Argon2 НЕ cancellable (RustCrypto непрерываем); проверка
cancel после Argon2 срабатывает прямо перед началом (cancellable) скана.

Для async-пути (отдельный crate `hidden-volume-async`) используйте
[`AsyncContainer::run_cancellable`]:

```rust,ignore
use hidden_volume_async::AsyncContainer;

let result = container.run_cancellable(token, |c, t| {
    let mut space = c.open_space_cancellable(b"password", t)?;
    let page = space.iter_log_before(Namespace::MESSAGE_LOG, None, 50)?;
    Ok(page)
}).await;
```

---

## 7. Rollback / fork detection (anchors)

Snapshot-противник может подменить файл его более старой копией.
Библиотека сама обнаружить это не может. Вы предоставляете **внешний
anchor**.

После каждого успешного коммита сохраняйте `space.commit_seq()` в
TPM / Secure Enclave / счётчике на сервере. На переоткрытии:

```rust
# fn run(space: &mut hidden_volume::Space<'_>, anchor_seq: u64) -> hidden_volume::Result<()> {
let cur = space.commit_seq();
let history = space.commit_history();
if cur < anchor_seq {
    panic!("rollback detected — file replaced with older version");
}
if !history.contains(&anchor_seq) {
    panic!("fork detected — timeline diverges from anchor");
}
// иначе: чистое продолжение, продолжаем.
# Ok(()) }
```

Полный алгоритм + компромиссы по хранению anchor:
[`docs/ru/guide/multi-device.md`](multi-device.md).

**Контракт приватности.** НЕ якорьте decoy / hidden spaces — сам anchor
выдаёт существование space.

---

## 8. Кэширование ключей (пропустить Argon2 при перезапуске)

Argon2id намеренно медленный (~100 мс–1 с на разблокировку). Для
приложения, которое переоткрывается часто, кэшируйте derived
[`SpaceKeys`] в platform-native secure storage (Keychain / Secret
Service / Android Keystore):

```rust
# fn run(container: &mut hidden_volume::Container) -> hidden_volume::Result<()> {
// Первая разблокировка — платим стоимость Argon2 один раз.
let keys = container.derive_space_keys(b"password")?;
// store_in_keychain(&keys);

// Последующие разблокировки — пропускаем Argon2.
// let keys = load_from_keychain();
let _space = container.open_space_with_keys(keys)?;
# Ok(()) }
```

Компромисс: атакующий, скомпрометировавший И файл, И keyring host OS,
получает данные без brute-force. Для maximum-paranoia spaces (decoy,
hidden) не кэшируйте — платите Argon2 каждый раз.

---

## 8b. UI Storage / About-this-profile ([`Space::stats`])

Для типичной странички мессенджера «Storage» / «About this profile»
используйте [`Space::stats`], чтобы получить все распространённые
счётчики одним вызовом:

```rust,ignore
let s = space.stats()?;
println!(
    "seq {}, history {} entries, {} chunks owned, {} total items",
    s.commit_seq,
    s.commit_history_len,
    s.owned_chunk_count,
    s.total_entries(),
);
for (ns, count) in &s.namespace_counts {
    println!("  namespace {} → {} entries", ns.0, count);
}
```

Стоимость: проход по KV-index дереву каждого активного namespace один
раз (то же, что сумма `count` по namespaces). Read-only безопасно.

## 9. Проверка целостности

Per-chunk AEAD уже защищает от bit-flip-повреждений (любое изменение
байта → `AuthFailed` на chunk). Для end-to-end-проверки цепочки Merkle
hash (Superblock → Commit → дерево IndexNode) вызывайте
[`Space::verify_integrity`]:

```rust
# fn run(space: &mut hidden_volume::Space<'_>) -> hidden_volume::Result<()> {
let report = space.verify_integrity()?;
println!(
    "verified {} chunks across {} namespaces, max tree depth {}",
    report.chunks_verified, report.namespaces_verified, report.max_depth,
);
# Ok(()) }
```

Возвращает `Error::IntegrityFailure { detail, slot }` при любом
несовпадении. Стоимость: O(N) chunk-чтений, где N — достижимое
поддерево (несколько мс для типичных историй мессенджера).

Когда вызывать: после синхронизации с пиром, периодически как
self-test, или после восстановления host-app от падения.

---

## 10. Padding и размер decoy

Single-snapshot deniability (D1) требует, чтобы файл выглядел как
случайный шум. Дефолты уже это удовлетворяют; для более сильной
multi-snapshot-стойкости используйте:

- [`ContainerOptions::initial_garbage_chunks`] — заранее пишет N decoy
  chunks на момент создания, чтобы файл имел нетривиальный начальный
  размер.
- [`PaddingPolicy::BucketGrowth`] — округляет размер файла вверх до
  кратных bucket'у на каждом коммите, маскируя per-commit рост.
- [`PaddingPolicy::FixedRatio`] — добавляет процент мусора на каждый
  записанный реальный chunk.

Задаётся через `Container::create_with_options` или в рантайме через
[`Container::set_padding_policy`].

---

## 10a. Стереть весь namespace

Когда пользователь нажимает «Очистить историю чата» или «Стереть
контакты», используйте [`Space::erase_namespace`] вместо ручного
цикла `Tx::delete`:

```rust,ignore
use hidden_volume::space::index::Namespace;

let removed = space.erase_namespace(Namespace::MESSAGE_LOG)?;
println!("dropped {removed} messages");
```

Это выполняет одну Tx, удаляющую все записи в namespace, и коммитит
её. Новый коммит исключает namespace из своего набора `IndexRoot`
(перестроенное дерево пусто); старые IndexNode chunks становятся
сиротами.

**Зазор forward-secrecy для log namespaces.** `vacuum_orphans`
(автоматически запускается при следующем `open_space`) скрабит
осиротевшие IndexNode chunks — то есть *ключи* пропали — но НЕ
скрабит chunks `DataBatch` (один batch может ещё держать живые
записи от других log_ids). Сами байты сообщений остаются на диске,
AEAD-decryptable любым обладателем пароля.

Чтобы закрыть этот зазор **без полного compact**, вызывайте
[`Space::vacuum_data_batches`] — он проходит по KV-index каждого
namespace, собирает referenced batch_slots и скрабит каждый
принадлежащий DataBatch chunk, на который нигде нет ссылок:

```rust,ignore
// «Очистить историю чата» — рекомендуемый рецепт (дёшево, in-place):
space.erase_namespace(Namespace::MESSAGE_LOG)?;
let scrubbed = space.vacuum_data_batches()?;
println!("scrubbed {scrubbed} orphan DataBatch chunks");
```

`vacuum_data_batches` также реклеймит сиротские батчи, созданные
**перезаписями** (повторный append того же `log_id` с новым payload
делает предыдущий batch недостижимым; полный compaction или этот
метод его очищают). Для «always-on» forward-secrecy в мессенджере,
который редактирует сообщения, запускайте `vacuum_data_batches`
периодически (например, раз на запуск приложения).

Когда вы реально хотите полную перезапись (реклейм размера, ротация
container_id, сброс истории), используйте `compact_known` —
см. §11.

Для KV namespaces (settings, contacts) post-vacuum_orphans-состояние
уже forward-secret; больше делать ничего не нужно.

## 10b. Смена пароля

Пользователи рано или поздно захотят сменить пароль space.
Используйте [`Container::change_passwords`]:

```rust,ignore
use hidden_volume::Container;

// Меняем "old-pw" → "new-pw"; hidden space оставляем нетронутым.
let other_kept: &[u8] = b"hidden-pw";
Container::change_passwords(
    path,
    &[(b"old-pw", b"new-pw"), (other_kept, other_kept)],
    options,
)?;
```

Каждая запись маппинга — это `(open_with, write_as)`:
- `open_with == write_as` → сохранить дословно.
- `open_with != write_as` → ротировать на новый пароль.

Spaces, НЕ упомянутые в маппинге, **сбрасываются** (та же деструктивная
семантика, что у `compact_known`). Чтобы сохранить space, чей пароль
не ротируется, перечислите его как no-op-пару `(p, p)`.

Механика: пишет свежий контейнер в `path.hv-rotate-tmp`, затем делает
атомарный rename поверх `path`. На любой ошибке временный файл
удаляется, а исходный `path` остаётся нетронутым. Cancellable-вариант
(`change_passwords_cancellable`) уважает `CancelToken` на каждой
границе namespace / Tx; на cancel временный файл удаляется и
возвращается `Error::Cancelled`.

**Заметка про forward-secrecy.** После ротации блоки старого
контейнера освобождаются файловой системе. Аллокатор может их
переиспользовать; для forensic-уровня скраба нижележащего хранилища
host-app должен запустить отдельный инструмент. На флэше FTL
дополнительно скрывает оригиналы, но строго гарантировать удаление
не может.

## 11. Compaction (forward-secrecy + реклейм размера)

Каждое открытие space запускает [`Space::vacuum_orphans`] →
предыдущие IndexNode chunks (осиротевшие из-за последнего коммита)
скрабятся. Это даёт forward-secrecy для KV-удалений после одного
переоткрытия.

Для DEEP-скраба (а также реклейма пространства DataBatch + сбрасывания
исторических Superblock-реплик + уменьшения размера) используйте:

```rust
# use hidden_volume::container::RepackOptions;
# fn run(path: &std::path::Path, options: RepackOptions) -> hidden_volume::Result<()> {
hidden_volume::Container::compact_known(path, &[b"main-pw"], options)?;
# Ok(()) }
```

Компромисс: `compact_known` НЕОБРАТИМО УНИЧТОЖАЕТ любое space, чей
пароль не передан. (Историческая заметка: до cleanup'а 2026-05-02
существовал синоним `compact_all`; удалён как дубликат
documentation-only. Та же деструктивная семантика — вызывающий
утверждает, что у него все пароли.)

После compaction у нового контейнера свежий `container_id`; host
обязан переякориться (см. §7).

---

## 12. Анти-паттерны

Чего НЕ делать:

- **Не вызывайте iter_log на namespace с 100K сообщений** — используйте
  пагинацию (§5).
- **Не якорьте decoy/hidden space** — его существование становится
  публичным.
- **Не передавайте пользовательский ввод как `Namespace`** — `Namespace`
  это однобайтовый тег, не идентификатор пользователя.
- **Не разделяйте файл между процессами через NFS**, если ваш NFS не
  уважает `flock(2)`. Захват lock библиотекой молча преуспеет, но
  возможно повреждение.
- **Не оборачивайте результаты `iter_log` в произвольное расширение
  памяти** — payload — это owned `Vec<u8>` (в
  `docs/ru/security/audits/plaintext.md` объясняется, почему
  библиотека НЕ оборачивает их в `Zeroizing`; ключевой материал и
  Rust-side password-копии в FFI / async / CLI зероизуются —
  audit pass 16 + 17). Для mlock host-app payload'ов делайте это
  на уровне процесса.
- **Не меняйте параметры Argon2 в рантайме** — параметры запекаются в
  cleartext-заголовок на момент создания. Используйте `repack` для
  перенастройки.
- **Не игнорируйте `Error::Busy`** — это значит, что эксклюзивный lock
  держит другой писатель. Не повторяйте в плотном цикле; пробрасывайте
  пользователю.

---

## 13. Частые вопросы

**Q: Насколько большим может быть контейнер?**
A: Жёсткий cap — `MAX_OPEN_SCAN_CHUNKS = 16M` чанков ≈ **64 ГиБ**
(audit pass 16 TM1 — ограничивает DoS через раздутый файл). И write-side
(`Container::create_with_options` initial garbage, post-commit padding,
`repack` destination growth), и read-side (open-scan) отказываются
переходить этот cap; write-side поверхность — `Error::ContainerTooLarge
{ extra, cap }` (audit pass 17 B), read-side — `Error::Malformed
("container exceeds open-scan budget")`. В пределах cap практический
лимит — RAM во время open scan; streaming-open держит RAM ограниченным
`O(M·16 B)`, где M = количество owned chunks (см. DESIGN §5). `repack`
тоже ограничен — audit pass 16 R-STREAMING-REPACK сделал его
постраничным по log-namespaces с working-set ≈ 4 МиБ на страницу.
На 4 ГиБ ARM 10 ГиБ контейнер сканируется за ~10 с.

**Q: Могут ли два spaces разделять данные?**
A: Нет. Каждое space криптографически независимо. Host-app может
держать список контактов на каждое space и маршрутизировать сообщения
на уровне приложения.

**Q: Можно ли удалить одно сообщение?**
A: Да — `Tx::delete(MESSAGE_LOG, log_id_key)`. Forward-secrecy через
`vacuum_orphans` (на следующем переоткрытии) очищает IndexNode chunk,
указывающий на него. DataBatch chunk, содержащий байты сообщения,
скрабится на следующем вызове `compact_known`.

**Q: Как узнать, что попытка разблокировки провалилась?**
A: `open_space` возвращает `Error::AuthFailed`. Та же ошибка покрывает
«неверный пароль» и «нет такого space» — by design (D2). Не пытайтесь
их различать; пробрасывайте обобщённое «unlock failed» пользователю.

**Q: Стабилен ли формат файла?**
A: До v1.0 формат на диске может меняться между релизами v0.x. После
v1.0 он замораживается. См. milestone v1.0 в `TASKS.md`.

**Q: Нужна ли особенная файловая система?**
A: ext4 / APFS / NTFS — все работают. Сетевые файловые системы должны
уважать `flock(2)`. Snapshots ZFS / Btrfs — нормально для бэкапов, но
intermediate-snapshot deniability ослаблен (см. DESIGN §1 T2').

---

## 14. Что читать дальше

| Тема | Документ |
|---|---|
| Обоснование спецификации формата, summary threat model, инварианты | `DESIGN.md` |
| Каноническая wire-format спецификация (v1.0-frozen byte layout) | `docs/ru/reference/format.md` |
| Формальная threat model (противники, история аудитов, запрос на ревью) | `docs/ru/security/threat-model.md` |
| Backup / restore / ротация ключей / recovery / рецепты scrub | `docs/ru/guide/operations.md` |
| Миграция между версиями формата (v1 → v2 — пустая оболочка до выхода v2) | `docs/ru/guide/migration.md` |
| Политика покрытия semver (что покрыто, что нет, post-v1.0) | `docs/ru/reference/semver.md` |
| Контракт P2P-sync, стратегия anchor | `docs/ru/guide/multi-device.md` |
| Constant-time аудит | `docs/ru/security/audits/constant-time.md` |
| Аудит memory hygiene | `docs/ru/security/audits/memory.md` |
| Аудит plaintext-leak | `docs/ru/security/audits/plaintext.md` |
| Аудит порядка fsync | `docs/ru/security/audits/fsync.md` |
| Бенчмарки / целевые числа | `docs/ru/contributing/benchmarks.md` |
| Roadmap | `TASKS.md` |
| Per-API rustdoc | `cargo doc --open` |

[`Argon2Params::LIGHT`]: ../src/crypto/kdf.rs
[`Argon2Params::DEFAULT`]: ../src/crypto/kdf.rs
[`Argon2Params::HEAVY`]: ../src/crypto/kdf.rs
[`Argon2Params::MIN`]: ../src/crypto/kdf.rs
[`Tx::put`]: ../src/tx/mod.rs
[`Tx::delete`]: ../src/tx/mod.rs
[`Tx::append_log`]: ../src/tx/mod.rs
[`Space::get`]: ../src/space/mod.rs
[`Space::list`]: ../src/space/mod.rs
[`Space::count`]: ../src/space/mod.rs
[`Space::read_log`]: ../src/space/mod.rs
[`Space::iter_log`]: ../src/space/mod.rs
[`Space::iter_log_after`]: ../src/space/mod.rs
[`Space::iter_log_before`]: ../src/space/mod.rs
[`Space::verify_integrity`]: ../src/space/mod.rs
[`Space::vacuum_orphans`]: ../src/space/mod.rs
[`Container::open_readonly`]: ../src/container/mod.rs
[`Container::set_padding_policy`]: ../src/container/mod.rs
[`Container::open_space_cancellable`]: ../src/container/mod.rs
[`open_space_with_keys_cancellable`]: ../src/container/mod.rs
[`Container::repack_cancellable`]: ../src/container/mod.rs
[`Container::compact_known_cancellable`]: ../src/container/mod.rs
[`Container::change_passwords`]: ../src/container/mod.rs
[`Space::erase_namespace`]: ../src/space/mod.rs
[`Space::stats`]: ../src/space/mod.rs
[`Space::vacuum_data_batches`]: ../src/space/mod.rs
[`AsyncContainer::run_cancellable`]: ../crates/hidden-volume-async/src/lib.rs
[`CancelToken`]: ../src/cancel.rs
[`Namespace::SETTINGS`]: ../src/space/index.rs
[`CONTACTS`]: ../src/space/index.rs
[`MESSAGE_LOG`]: ../src/space/index.rs
[`MEDIA`]: ../src/space/index.rs
[`IndexNode`]: ../src/space/index.rs
[`ChunkKind::DataBatch`]: ../src/chunk/kind.rs
[`ContainerOptions::initial_garbage_chunks`]: ../src/container/mod.rs
[`PaddingPolicy::BucketGrowth`]: ../src/padding.rs
[`PaddingPolicy::FixedRatio`]: ../src/padding.rs
