# Дизайн FFI — `hidden-volume-ffi`

[🇬🇧 English](../../en/reference/ffi.md) · 🇷🇺 **Русский**

Этот документ фиксирует архитектурные решения для milestone FFI v0.8.
Это reference для интеграторов, встраивающих `hidden-volume` в
не-Rust codebase (Kotlin, Swift, Python, Ruby).

## Статус

- v0.8.0 (этот коммит): **Rust-side scaffold + sync API surface
  готовы**. Собирается чисто, проходит 5 интеграционных тестов
  уровня FFI.
- v0.8.x: iOS `xcframework`, Android `.aar` / `.so`, Flutter
  sample app, CI matrix — **отложено** до тех пор, пока хотя бы
  одна команда host-приложения не будет готова интегрироваться
  (нет смысла собирать обвязку toolchain, которой никто не
  воспользуется).

## Решение 1 — инструмент bindings: **uniffi** (против `flutter_rust_bridge`, `cbindgen`, `cxx`)

| Tool | Языки | Memory safety | Поддержка | Flutter | Вердикт |
|---|---|---|---|---|---|
| **uniffi-rs** | Kotlin, Swift, Python, Ruby (+ community-порты для Go, C#, Dart) | Высокая — сгенерированные bindings владеют памятью, ошибки маппятся в типизированные исключения | Низкая — единственный Rust source of truth, опциональный UDL | через Dart-порт | **Выбран** |
| flutter_rust_bridge | Только Dart | Высокая — но Dart-специфичная | Средняя — отдельный `.dart` glue | Native | Single-target; для нативных Android Kotlin потребовался бы параллельный JNI-слой |
| cbindgen | C ABI → любой | Hand-rolled; ручные правила владения памятью | Высокая — каждому языку binding нужен собственный wrapper | Через FFI plugin | Слишком низкоуровневый; переизобретает то, что делает uniffi |
| cxx | Rust ↔ C++ | Отлично для C++ | Высокая — для каждого метода нужен C++ wrapper | Опосредованно | C++-специфичный; Kotlin/Swift всё равно нуждались бы в JNI/ObjC обёртке |

**Обоснование uniffi.** Messenger, отгружаемый на Android (Kotlin),
iOS (Swift) и desktop (Python или .NET), нуждается минимум в трёх
host-языках. uniffi даёт нам все три из единственного Rust source
of truth. Dart-порт (`uniffi-dart`) покрывает Flutter без
отдельного wrapper. Владение памятью генерируется корректно по
умолчанию — разработчики host-приложений, интегрирующих библиотеку,
никогда не пишут `unsafe` JNI-код или
`@_implementationOnly` Swift-glue.

Цена: один дополнительный шаг сборки (`uniffi-bindgen generate ...`)
на каждый целевой язык. Запускается один раз на `cargo build`,
а не в runtime.

**Почему не flutter_rust_bridge, несмотря на то что Flutter — главная
цель messenger?** Он Dart-only — нам всё равно понадобился бы
параллельный JNI/Kotlin слой для нативных Android UI (например,
обработчиков уведомлений, tile widgets), не идущих через Dart. Две
поверхности FFI хуже одной.

## Решение 2 — режим proc-macro (вместо UDL)

uniffi 0.31 поддерживает два стиля:

1. **UDL-файл** (`hidden_volume.udl`): WebIDL-подобная схема,
   отдельная от Rust-исходника. Старый стиль.
2. **Атрибуты proc-macro** (`#[derive(uniffi::Object)]`,
   `#[uniffi::export]`): аннотируют Rust-исходник напрямую.

Мы используем **proc-macros**, потому что:

- **Нет рассинхронизации.** Подход с UDL требует держать `.udl`
  и `.rs` синхронизированными; расхождения всплывают только во
  время bindgen.
- **Лучше диагностика.** `cargo build` ловит ошибки типов в
  месте Rust call-site.
- **Меньше файлов.** Один `lib.rs` вместо обвязки
  `lib.rs + .udl + build.rs`.

Trade-off: режим proc-macro требует uniffi 0.25+, что для нас
нормально, поскольку мы строим свежий crate.

## Решение 3 — комбинированная handle `Container + Space` (вместо двушаговой)

Естественный Rust API двухшаговый:

```rust
let mut c = Container::open(path)?;
let mut s = c.open_space(password)?;
s.put(...);
```

`Space<'f>` мутабельно заимствует у `Container`. В Rust это
прекрасно (borrow checker не даст держать два открытых space на
один и тот же container), но **не транслируется в FFI**, потому что:

- Объекты, экспортированные через uniffi, должны быть
  `Send + Sync + 'static`.
- Заимствование `&'f mut Container` не `'static`.
- Двушаговый API потребовал бы uniffi callback-interfaces (host
  передаёт callback в Rust с открытым space) — неуклюже в
  Kotlin/Swift.

Наша форма: один комбинированный конструктор `SpaceHandle`
открывает файл, открывает space и держит оба:

```kotlin
// Kotlin
val space = SpaceHandle.open("/storage/store.bin", "password".toByteArray())
space.commit(listOf(WriteOp.Put(/*ns*/1u, "username".encodeToByteArray(), "alice".encodeToByteArray())))
```

```swift
// Swift
let space = try SpaceHandle.open(path: "/storage/store.bin", password: Data("password".utf8))
try space.commit(ops: [.put(namespace: 1, key: Data("username".utf8), value: Data("alice".utf8))])
```

Для multi-space deniability-сценариев (на практике редкость —
один пользователь, один пароль, один space) шаблон такой:
дропнуть существующую handle, переоткрыть с другим паролем.
flock на файле в любом случае запрещает конкурентное
multi-handle использование.

### Self-referential реализация

Внутренне `SpaceHandle` держит `hidden_volume_rt::OwnedSpace` —
общий self-referential helper (см. crate `hidden-volume-rt`),
имеющий форму:

```rust
struct OwnedSpace {
    container: Box<Container>,           // stable address
    space: ManuallyDrop<Space<'static>>, // borrow with lifetime extended
}
```

`'static` — это ложь: `Space` валиден только пока `container`
живёт по своему текущему heap-адресу. Безопасность:

1. `container` аллоцирован через `Box`; адрес стабилен в течение
   жизни `OwnedSpace`.
2. После `transmute`-инга lifetime мы никогда не двигаем
   `container`.
3. `Drop for OwnedSpace` сначала дропает `space` (он заимствует у
   `container`), потом `container`. Без `ManuallyDrop`
   автоматический порядок drop полей в Rust дропнул бы
   `container` первым — UB.

Это стандартный self-referential FFI-шаблон; crates `self_cell`
и `ouroboros` существуют, чтобы абстрагировать его, но мы
используем прямую форму, чтобы избежать лишней dependency ради
~30 строк кода. unsafe-блок задокументирован в
`hidden_volume_rt::OwnedSpace::new`; и FFI-, и async-обёртки его
переиспользуют.

## Решение 4 — батчевый `commit(Vec<WriteOp>)` вместо per-op auto-commit

Наивная FFI-форма выставила бы `put` / `delete` / `append_log` / `delete_log`
прямо на `SpaceHandle`, каждый авто-оборачивающий в одну Tx.
Это расточительно, потому что:

- Каждая Tx стоит **3 fsync barriers** (~5 мс на SSD, сотни мс
  на дешёвом eMMC).
- Messenger, кладущий контакт, обновляющий его avatar URL и
  логирующий сообщение «contact added», заплатил бы 3× этот floor.

Вместо этого мы выставляем единственный `commit(ops: Vec<WriteOp>)`.
Host-приложение батчит на стороне call-site:

```kotlin
space.commit(listOf(
    WriteOp.Put(namespace = 2u, key = "alice".encodeToByteArray(), value = avatarUrl),
    WriteOp.Put(namespace = 2u, key = "alice.tag", value = tagBytes),
    WriteOp.AppendLog(namespace = 3u, logId = msgIdGen.next(), payload = "Added Alice".encodeToByteArray()),
))
```

`WriteOp.DeleteLog(namespace, logId)` удаляет logical id из ограниченного
индекса Log-namespace. Это не то же самое, что
`AppendLog(..., emptyPayload)`: последний сохраняет настоящую пустую запись и
не освобождает ёмкость индекса.

Это позволяет 3-fsync-стоимости естественно амортизироваться
по каждому логическому «действию», которое выполняет
host-приложение, точно соответствуя нижележащей транзакционной
модели. Пустой `commit(emptyList())` — no-op (возвращает
неизменённый `commit_seq`).

## Решение 5 — плоский error enum

Rust-овский `Error` — типизированный enum с 20 вариантами.
uniffi поддерживает маппинг этого в типизированные исключения на
foreign-стороне, но каждый variant должен быть FFI-friendly (без
`&'static str`, без opaque data).

Наш [`HvError`] — 1:1 зеркало, со всеми payload `&'static str`,
конвертированными в `String`. Атрибут `#[uniffi(flat_error)]`
заставляет uniffi генерировать идиоматичные Kotlin sealed
classes / Swift enums:

```kotlin
sealed class HvException : Exception() {
    object AuthFailed : HvException()
    object Busy : HvException()
    data class Malformed(val message: String) : HvException()
    data class IntegrityFailure(val detail: String, val slot: ULong) : HvException()
    // ...
}
```

```swift
public enum HvError: Error {
    case AuthFailed
    case Busy
    case Malformed(String)
    case IntegrityFailure(detail: String, slot: UInt64)
    // ...
}
```

Маппинг сохраняет **инвариант deniability**: `AuthFailed`
срабатывает и для wrong-password, И для no-such-space; foreign
callers не могут различить (и НЕ ДОЛЖНЫ ветвиться по разнице).

**«1:1» — несущее слово, и до report7 P1 оно было неправдой.**
`From`-impl обязан заканчиваться catch-all'ом, потому что
`hidden_volume::Error` помечен `#[non_exhaustive]`, а этот catch-all
отвечает `Internal("unknown error variant")` — ошибкой, чей
собственный доккомментарий говорит «указывает на баг библиотеки».
Там накопились четыре варианта: `UnreadableNewerState`,
`PublishUncertain` и два случая `RenameVisible*`. Каждый — штатный
исход с лечением, которого хост не угадает: *переоткрыть контейнер*
либо *перезапись ПРОШЛА, не повторять со старым паролем*, — и каждый
приезжал вместо этого как «библиотека сломана». Два из них поднимает
уборка сирот, которую Flutter-плагин вооружает на **каждом открытии**,
так что потеря была не теоретической. Тест
`every_core_variant_maps_to_something_other_than_unknown` в FFI-крейте
теперь падает, если любой поименованный вариант ядра снова попадёт
в catch-all.

**`HvError` пополняется только с конца.** `flat_error` пересекает
границу как **порядковый номер**, а рукописные Dart-биндинги
отображают его обратно в имя позиционно (`_hvErrorKinds`). Вариант,
вставленный в середину, молча переименовывает все ошибки после него
на стороне Dart. Добавлять в конец и тем же коммитом расширять
этот список.

## Решение 6 — обе поверхности API: sync и async (v0.8.1+)

Мы поставляем **два сосед-handle типа**:

- [`SpaceHandle`] — синхронный workhorse. Методы берут `&self`,
  блокируют вызывающий поток на нижележащем mutex + sync-core
  call.
- [`AsyncSpaceHandle`] — асинхронный сосед. Методы это `async fn`,
  они offload-ят нижележащую sync-работу в
  `tokio::task::spawn_blocking`.

### Почему оба, а не один

Storage-слой messenger сталкивается с двумя различными профилями
интеграторов:

| Профиль | Native idiom | Лучшая поверхность |
|---|---|---|
| Android / Kotlin coroutines | `suspend fun` | **Async** — `AsyncSpaceHandle` маппится в `suspend fun` |
| iOS / Swift `async/await` | `async throws` | **Async** — `AsyncSpaceHandle` маппится в `async throws` |
| iOS / GCD-only legacy code | `DispatchQueue.global` | **Sync** — caller уже оборачивает в свой scheduler |
| Pure-Rust desktop / server | tokio runtime | **Async** для неблокирующего storage |
| Server-side single-threaded scripts (Python, Ruby) | sync calls | **Sync** — overhead async неоправдан |
| Embedded ARM без Tokio | sync calls | **Sync** — async тянет Tokio (~700 KB бинарника) |

Поставка обоих позволяет каждому интегратору выбрать правильный
инструмент. Две handle **разделяют один и тот же внутренний
`hidden_volume_rt::OwnedSpace`** (boxed Container + ManuallyDrop'ed Space за
Mutex) — дублируется только обвязка методов, не логика
storage. Нет «async vs sync» runtime-разделения ни в формате,
ни в sync-core; async-поверхность — чистый offload-wrapper,
идентичный тому, что делает `hidden-volume-async` для
pure-Rust callers.

### Что async реально даёт

Wall-clock у sync-core доминируется 3-fsync floor (~5 мс на
SSD, сотни мс на дешёвом eMMC) и Argon2id (десятки–сотни мс
в зависимости от пресета). Async НЕ делает ни один отдельный
вызов быстрее. Что он даёт:

1. **Не блокирует UI-поток.** Messenger, вызывающий
   `space.get()` из main coroutine на Android, остаётся
   отзывчивым к скроллу / анимациям, потому что фактическая
   работа выполняется на потоке blocking-pool.
2. **Конкурирующие вызовы перекрываются.** Две
   `tokio::spawn`-нутые задачи могут каждая await-ить
   `AsyncSpaceHandle.get(...)`, и runtime интерливит их между
   page-cache промахами. Внутренний mutex по-прежнему
   сериализует фактический доступ к storage (только одна Tx на
   Space), но pre/post-работа вне lock может интерливить.
3. **Хуки cancellation.** Будущая итерация может пробросить
   `CancelToken` через границу FFI как Kotlin `Job` /
   Swift `Task` cancel — async-поверхность это естественное
   место.

### Требование к runtime

Host-процесс должен исполнять multi-thread runtime Tokio в
момент await-а async-методов. Feature `tokio` у uniffi
обрабатывает это автоматически для интеграторов Kotlin / Swift,
запуская runtime внутри Rust dylib при первом использовании.

Для pure-Rust callers оборачивайте в `#[tokio::main]` или
конструируйте runtime сами. Async-only crate
`hidden-volume-async` существует для pure-Rust async-сценариев
без overhead FFI.

### Покрытие методов

`AsyncSpaceHandle` 1:1 зеркалит **каждый** метод `SpaceHandle`:
конструкторы (`create`, `add_space`, `open`, `open_with_keys`), reads
(`get`, `count`, `list_namespaces`, `read_log`, `iter_log_range`,
`commit_seq`, `commit_history`, `space_keys`, `stats`,
`verify_integrity`) и write (`commit`). Те же аргументы, та же форма
ошибок, та же семантика — просто `async fn` повсюду.

`open_with_keys` / `space_keys` — пара для **мастер-пространства**:
`space_keys()` экспортирует `SpaceKeys` открытого пространства в виде
64 непрозрачных байт (`container_id ‖ aead_root`), а
`open_with_keys(path, keys)` повторно открывает это пространство по
этим байтам без пароля (минуя Argon2 через
`Container::open_space_with_keys`). Эти байты — корень расшифровки
конкретного пространства, **чувствительный материал**; хост-приложение
хранит их только внутри другого отрицаемого пространства (реестра
мастера) и никогда не логирует. Неверная длина → `Malformed`;
несовпадающие ключи → `AuthFailed`, тот же неразличимый путь, что и при
неверном пароле.

### Брошенные вызовы — реестр (аудит HV-02)

`spawn_blocking` не умеет прерывать уже начавшееся замыкание. Foreign-
вызывающий, обернувший `commit` в `withTimeout` / `Task.withTimeout` и
ушедший, не может узнать из самого вызова, зафиксировалась ли
транзакция, — а повтор неидемпотентного `append_log` наугад портит лог.

Каждый метод `AsyncSpaceHandle` идёт через собственный `OpLedger`
хендла, который переживает вызов:

| Метод | Что отвечает |
|---|---|
| `abandoned_operations()` | Все брошенные вызовы, старые первыми, с исходом **на момент этого вызова**. `Queued` / `Running` не финальны — спросить ещё раз. |
| `clear_settled_operations()` | Убрать завершённые записи; оставить те, за которыми ещё стоит следить. |
| `forgotten_abandonments()` | Сколько записей вытеснено на пределе в 128. Ненулевое значит: приложение бросает быстрее, чем сверяет. |

Ветвиться нужно по `AbandonedOperation.may_have_mutated`. Он `false`
только для `NeverStarted`, за которым стоит доказательство, что
замыкание не тронуло контейнер, — единственное состояние, при котором
неидемпотентный вызов можно повторить вслепую. Любой другой исход,
включая `Running`, означает «сначала сверься».

Реестр также допускает **одну** блокирующую операцию на хендл
одновременно. Вызывающие ждут пропуск как обычные async-задачи —
дёшево и отменяемо бесплатно — а не как припаркованные потоки
`spawn_blocking`, все стоящие в очереди к одному мьютексу.

Конструкторы (`create`, `open`, `add_space`, `open_with_keys`) остаются
на простом пути `run_blocking`: брошенному конструктору некому
докладывать — хендла ещё нет.

### Что мы по-прежнему не поставляем

- **Streaming `iter_log_*`**. uniffi async возвращает одиночные
  futures, а не streams. Для неограниченного scrollback
  host-приложение пагинирует через `iter_log_range` в цикле (так
  же, как для sync). Stream-based FFI потребовал бы uniffi
  callback-interfaces или адаптера Flow / AsyncSequence на
  foreign-стороне.
- **Cancellation tokens через границу FFI**. Потребовали бы
  поддержки uniffi callback-interface; откладываем до
  фактического спроса. Сброс future вызова *уже* заведён на токен
  внутри (см. реестр выше): до старта замыкания брошенность — это
  настоящая отмена, и запись говорит `NeverStarted`; после старта у
  синхронного ядра нет собственных точек проверки отмены, поэтому
  операция доходит до конца и о ней докладывают, а не делают вид,
  что её не было.
- **Pagination helpers на основе `async-stream`** вроде
  pure-Rust методов
  `hidden-volume-async::AsyncSpace::stream_log_pages_*`.
  Pure-Rust callers должны использовать `hidden-volume-async`
  напрямую для Stream-style API.

## Генерация bindings (v0.8.1+)

Мы поставляем **in-tree** драйвер `uniffi-bindgen`:
[`crates/hidden-volume-ffi/src/bin/uniffi-bindgen.rs`](../../../crates/hidden-volume-ffi/src/bin/uniffi-bindgen.rs).
Рекомендуемый шаблон с uniffi 0.25+: вместо `cargo install
uniffi-bindgen-cli` (который может разойтись по версии с runtime
crate) каждый FFI crate поставляет собственный bindgen-бинарь,
закреплённый на той же версии uniffi, что использует для
exports.

Перегенерация всех четырёх поддерживаемых языков:

```sh
cargo build -p hidden-volume-ffi --release
for lang in kotlin swift python ruby; do
    cargo run --bin uniffi-bindgen --features bindgen-cli -p hidden-volume-ffi -- \
        generate \
        --library target/release/libhidden_volume_ffi.so \
        --language "$lang" \
        --out-dir "bindings/$lang"
done
```

Output закоммичен как reference под `bindings/`, чтобы
интеграторы могли просматривать поверхность, которую им
предстоит потреблять, без необходимости собирать проект.
Bindings детерминированны — повторный запуск команды на
неизменённом FFI crate выдаёт байт-в-байт идентичный output (по
модулю предупреждений форматтера, которые срабатывают только
если установлены `ktlint` / `swiftformat` / `yapf` / `rubocop`).

### End-to-end тест на Python

`bindings/python/test_smoke.py` — canary-тест корректности
binding. Он загружает `libhidden_volume_ffi.so` через `ctypes`
(через автогенерированный Python-модуль) и упражняет полную
поверхность FFI sync + async: конструкторы, opaque handles,
байтовые массивы, optional values, vector returns,
типизированные исключения по error variant. Прохождение
Python-прогона — сильное доказательство, что Kotlin / Swift /
Ruby bindings тоже корректны, поскольку per-language кодогены
uniffi разделяют общий AST, извлечённый из Rust crate.

```sh
cd bindings/python
python3 test_smoke.py
# all 5 tests passed
```

Тест должен быть добавлен в CI для любого PR, трогающего
`crates/hidden-volume-ffi/src/lib.rs`.

## Отложено для v0.8.x

Rust-сторона готова; что остаётся — это **platform packaging**:

| Item | Почему отложено | Триггер запуска |
|---|---|---|
| **iOS xcframework** | Нужны Xcode + iOS SDK на macOS-build хосте; недоступно в Linux sandbox. | Первый запрос iOS-интегратора ИЛИ выделенный macOS GitHub Actions runner. |
| **Android `.aar` / `.so` per ABI** | Нужен Android NDK; cargo-ndk + uniffi-bindgen-kotlin скрипты в CI. | Первый запрос Android-интегратора. |
| **Linux/macOS/Windows desktop binaries** | Cross-compile через `cargo` тривиален, но потребителей пока нет. | Первый desktop messenger fork, желающий встроить. |
| **CI matrix для всех целей** | Стоит CI-минут; пропускаем, пока binaries фактически не публикуются. | Тот же триггер, что для binary-задач выше. |
| **Flutter typed Dart API** | **Реализован.** Hand-written `dart:ffi` typed API (~1116 + 518 строк, 18 тестов) живёт в [`experimental/flutter_plugin/hidden_volume/`](../../../experimental/flutter_plugin/); `UnimplementedError`-заглушек больше нет. Пока под `experimental/` в ожидании packaging нативных артефактов на всех целевых ABI. | — (готово) |
| **`docs/ru/guide/flutter.md`** | Документирует реализованный плагин + quick-start рецепт. | — |

Rust-side обвязка НЕ зависит ни от чего из этого — это чистая
работа deployment / packaging. Интегратор, желающий получить
Kotlin bindings уже сегодня, может выполнить:

```sh
cargo install uniffi-bindgen-kotlin    # community CLI
uniffi-bindgen-kotlin --library target/debug/libhidden_volume_ffi.so --out-dir bindings/kotlin
```

…и получить рабочий `.kt` файл. То же для Swift через
`uniffi-bindgen-swift`. Bindgen-инструменты не вендорятся в этот
repo, потому что эволюционируют независимо от поверхности FFI.

## `StatsInfo` — две вещи, которые опрос терял (report10 HV-04)

`stats()` — это то, что host опрашивает. Две величины, которые core
всегда держал, границу не пересекали, и обе — из тех, на которые
может отреагировать только host.

**`reusable_slot_count`.** Пул decoy: слоты, которые это space вывело
из обращения и переиспользует раньше, чем снова нарастит файл. Без
него единственным сигналом для компактизации по эту сторону границы
был `utilization_ratio`, а он в одиночку отвечает неверно в обе
стороны — низкое отношение при большом пуле означает здорово
перерабатывающий контейнер, и компактизация перепишет весь файл и
провернёт `container_id` впустую; низкое отношение при пуле около
нуля — это как раз та форма, которой `compact_known` действительно
нужен. Читать их только вместе. (Это ещё и множество анонимности, в
котором прячется переиспользованный слот — см. DESIGN §9.1.)

**`hardening_failure`.** Запись о post-commit padding / churn / fsync,
несущая **какой именно** шаг отказал:

| Шаг | Что перестало быть правдой |
|---|---|
| `Padding` | РАЗМЕР этого commit читается противником с несколькими снимками |
| `Churn` | слоты, которые этот commit ПЕРЕИСПОЛЬЗОВАЛ, стоят в diff снимков в одиночку |
| `Sync` | ни одна из маскирующих записей ещё не на пластине |

`Some(_)` не означает, что commit провалился — он durable. Слабее
обещанного оказалась маскировка вокруг него, и именно поэтому запись
едет на `stats`, а не в возврате `commit`.

### Почему она липкая и зачем подтверждение

Запись — это **не** «исход последнего commit». Однажды выставленная,
она держится до `acknowledge_hardening_error()`, и не снимается ничем
другим: ни последующим успешным commit, ни vacuum, ни ещё одним
чтением `stats`. Последующий отказ её тоже не вытесняет — побеждает
первый неподтверждённый, по тому же правилу, которое `commit_tx` уже
применяет к трём шагам внутри одного commit.

Иначе нельзя, потому что host узнаёт об этом ОПРОСОМ. Core записывал
исход только свежайшего commit, поэтому обычный второй commit,
приземлившийся между двумя опросами, стирал предупреждение, и о
записи с провалившейся маскировкой не узнавал никто. Поле, которое
просто пересекло бы границу, не став липким, отодвинуло бы потерю на
шаг наружу, а не закрыло её.

`acknowledge_hardening_error()` — вторая половина: липкое без способа
снять — это предупреждение, которое висит на экране всегда, а это учит
читающего его не читать. Вызывать после того, как предупреждение
действительно показано: подтвердить непрочитанное — значит выбросить
то же предупреждение вручную. Идемпотентно, а отказ, записанный
после, липнет в свою очередь.

Экспортировано и на `SpaceHandle`, и на `AsyncSpaceHandle`. Состояние
живёт в памяти: переоткрытая handle стартует чистой.

## Threading model — Mutex per handle

uniffi генерирует `Arc<SpaceHandle>` — несколько foreign-side
ссылок разделяют один Rust-объект. Мы оборачиваем внутреннее
состояние в `Mutex<hidden_volume_rt::OwnedSpace>`, чтобы
удовлетворить `Sync`. Конкурирующие FFI-вызовы из foreign-потоков
сериализуются на lock.

Это тот же шаблон, что у `AsyncContainer` в
`hidden-volume-async`. Согласно дизайну sync-core, в каждый
момент в одном `Space` может быть активна только одна `Tx` —
mutex обеспечивает это на границе FFI, точно так же, как
borrow-checker обеспечивает это для нативных Rust callers.

## Владение памятью

uniffi обрабатывает lifecycle объектов через
ref-counted handles:

- Foreign caller получает `Arc<SpaceHandle>` (Rust-side),
  обёрнутый в language-native ref-counted handle
  (`AutoCloseable` в Kotlin, ARC-managed класс в Swift).
- Когда foreign-side handle сбрасывается до нуля refs, uniffi
  вызывает Rust-овский `Drop`. Наш
  `Drop for hidden_volume_rt::OwnedSpace` отпускает `LOCK_EX` на
  нижележащем файле.
- Bytes (`Vec<u8>`) пересекают границу FFI **копированием** в
  обе стороны. Это единственный безопасный выбор — foreign-сторона
  может пережить любой одиночный Rust-вызов. Для типичных
  payload messenger (≤8 KiB log entries, ≤2 KiB KV-значения)
  стоимость копирования пренебрежима по сравнению с AEAD
  seal/open.

### Гигиена password-буферов (audit pass 16 + 17)

Каждая точка входа с паролем в этом крейте И в `hidden-volume-async`
оборачивает входящий `Vec<u8>` в `zeroize::Zeroizing` сразу при
вызове функции:

- Sync: `SpaceHandle::create`, `SpaceHandle::add_space`, `SpaceHandle::open`.
- Async: `AsyncSpaceHandle::create`, `AsyncSpaceHandle::add_space`,
  `AsyncSpaceHandle::open`.
  Zeroizing-обёртка перемещается ВНУТРЬ `run_blocking`-замыкания,
  чтобы scrub отрабатывал на drop замыкания на пути нормального
  возврата. Под `panic = "abort"` (`[profile.release]` в workspace
  `Cargo.toml`) destructor'ы НЕ запускаются на panic — «scrub» на
  panic-пути это OS process teardown; Zeroizing-обёртка по-прежнему
  даёт детерминированное обнуление до того, как аллокатор
  переиспользует байты на success-пути.
- Top-level: `compact_known(path, passwords)` дренажит
  `Vec<Vec<u8>>` в `Vec<Zeroizing<Vec<u8>>>`;
  `change_passwords(path, rotations)` дренажит каждый
  `PasswordRotation` в пару `Zeroizing`-буферов.

`PasswordRotation` намеренно НЕ деривит `Clone` (audit pass 17
F-2) — derived `Clone` позволил бы внутреннему `.clone()` молча
создать non-`Zeroizing`-копию вне wrapper-flow.

Foreign-side ownership остаётся гигиенической задачей host-app:
переданный вами Kotlin `ByteArray` / Swift `Data` / Python
`bytes` копируется через границу FFI, но source-буфер остаётся
под вашим контролем со стороны foreign. Затрите его сами после
завершения вызова (Kotlin: `pw.fill(0)`; Swift:
`pw.resetBytes(in: 0..<count)`).

#### Что Dart-плагин затирает на своей стороне (report9 HV-01 / HV-02)

Правило выше — про ВАШ буфер. Между ним и Rust-овским `Zeroizing`
лежат копии, которые делает сам binding-слой, и
`experimental/flutter_plugin/hidden_volume/` теперь затирает каждую:

- **Наружу** — в `_bufferFromBytes` (`calloc`-буфер, затирается до
  `free`) и в `_bufferFromOwnedSecret`, единственном владеющем
  помощнике за `_bufferFromByteVec`, `_writeRotations` и
  `_writeBytesSequence`. Последние два кодируют все пароли вызова
  `change_passwords` / `compact_known` в один блоб — самый плотный
  секрет, который строит плагин.
- **Внутрь** — в `_bufferToBytes`: Rust-овский буфер затирается между
  копированием наружу и `_freeBuffer`. Обе границы несущие.
  `spaceKeys()` дополнительно затирает framed-промежуток через
  `_secretByteVecFrom` — именно там 64 сырых байта ключа лежат между
  ответом FFI и декодированным результатом.
- **Между изолятами.** `Isolate.spawn` / `Isolate.run` глубоко копируют
  сообщение, поэтому bootstrap-пароль воркера и список ротаций
  одноразового изолята — СОБСТВЕННЫЕ буферы этого изолята; каждый
  затирается в `finally`, включая путь неудачного открытия.
  Синхронные `changePasswords` и `compactKnown` намеренно так НЕ
  делают: там списки принадлежат вызывающему, а `oldPwd == newPwd` —
  документированный no-op, который законно передаёт один экземпляр
  дважды. Ваш буфер по-прежнему затирать вам.

**Известный остаток.** `space_keys` возвращает 64-байтный `Vec<u8>`,
который uniffi-евский `Lower` забирает по move; эта копия на стороне
Rust не обёрнута. Обёртка `Zeroizing` здесь добавила бы ТРЕТЬЮ копию
и вычистила бы не ту, поэтому остаток зафиксирован, а не обойдён. Это
касается sync-, async- и multi-space-экспортов одинаково.

## Versioning

FFI crate версионируется независимо от core `hidden-volume`,
следуя той же политике SemVer (`docs/ru/reference/semver.md`).
Ломающие изменения в вариантах `HvError`, форме `WriteOp` или
сигнатурах методов `SpaceHandle` поднимают major. Добавление
новых вариантов / методов — minor.

## См. также

- [`crates/hidden-volume-ffi/src/lib.rs`](../../../crates/hidden-volume-ffi/src/lib.rs) — реализация
- [`docs/ru/guide/integration.md`](../guide/integration.md) — экскурсия по интеграции host-приложений на стороне Rust
- [`docs/ru/guide/multi-device.md`](../guide/multi-device.md) — контракт anchor / rollback (одинаков на всех сторонах FFI)
- [`docs/ru/reference/semver.md`](semver.md) — политика версионирования
