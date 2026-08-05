# Интеграция с Flutter — `hidden-volume`

[🇬🇧 English](../../en/guide/flutter.md) · 🇷🇺 **Русский**

Как встроить хранилище `hidden-volume` в Flutter-приложение мессенджера.

## Статус (по состоянию на audit pass 19, 2026-05-28)

| Слой | Статус | Примечания |
|---|---|---|
| Rust core (`hidden-volume`) | ✅ Стабильно | 397 тестов по всему workspace; замороженный в v1.0.0 формат v3 (cluster #8 kind-tags + #9 version-bind + #10 per-space `container_id`, 2026-05-28) |
| FFI-поверхность (`hidden-volume-ffi`) | ✅ Стабильно | sync + async (Tokio), uniffi 0.31 proc-macros, password-буферы обёрнуты в `Zeroizing` (audit pass 16 + 17) |
| Автогенерируемые Kotlin / Swift биндинги | ✅ Генерируются | [`bindings/kotlin/`](../../../bindings/kotlin/), [`bindings/swift/`](../../../bindings/swift/) — gitignored, регенерируются локально |
| **Flutter plugin scaffolding** | ✅ Реализовано | [`experimental/flutter_plugin/hidden_volume/`](../../../experimental/flutter_plugin/hidden_volume/) — `pubspec.yaml`, Android `build.gradle` + Kotlin glue, iOS `.podspec` + Swift glue, typed Dart-фасад. Живёт под [`experimental/`](../../../experimental/README.md) в ожидании packaging нативных артефактов на всех целевых ABI. |
| **Build-скрипты** | ✅ Доступно | [`scripts/build-android.sh`](../../../scripts/build-android.sh) (cargo-ndk, все 4 ABI), [`scripts/build-ios.sh`](../../../scripts/build-ios.sh) (xcframework, требует macOS) |
| **CI сборка нативных артефактов** | ✅ Доступно | [`.github/workflows/flutter-build.yml`](../../../.github/workflows/flutter-build.yml) — `.so` × 4 ABI на Ubuntu + `xcframework` на macOS-14 |
| **Dart/Flutter typed API** | ✅ Реализовано | [`lib/hidden_volume.dart`](../../../experimental/flutter_plugin/hidden_volume/lib/hidden_volume.dart) — hand-written `dart:ffi` typed API (~1116 + 518 строк, 18 тестов); `UnimplementedError`-заглушек больше нет. Bindings-glue в [`lib/src/bindings.dart`](../../../experimental/flutter_plugin/hidden_volume/lib/src/bindings.dart). |
| Пример Flutter-приложения | ✅ Присутствует | [`experimental/flutter_plugin/hidden_volume/example/`](../../../experimental/flutter_plugin/hidden_volume/example/). |

Flutter-плагин полностью реализован; запуск на устройстве требует
сборки нативных артефактов / host-setup'а по гайду ниже.

## Quick start

```sh
# 1. Установить один раз (~10 мин):
rustup target add aarch64-linux-android armv7-linux-androideabi \
                  x86_64-linux-android i686-linux-android \
                  aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
cargo install cargo-ndk
# Установить $ANDROID_NDK_HOME в путь к NDK r25c+.

# 2. Собрать нативные артефакты:
./scripts/build-android.sh           # Linux / Windows / macOS — 4 .so файла
./scripts/build-ios.sh               # только macOS — HiddenVolumeFFI.xcframework

# 3. (Пере)генерировать language-биндинги:
cargo build -p hidden-volume-ffi --release
for lang in kotlin swift; do
    cargo run --bin uniffi-bindgen --features bindgen-cli \
        -p hidden-volume-ffi -- generate \
        --library target/release/libhidden_volume_ffi.so \
        --language "$lang" --out-dir "bindings/$lang"
done

# 4. Из вашего Flutter-приложения:
flutter pub add hidden_volume \
    --path /path/to/this/repo/experimental/flutter_plugin/hidden_volume
flutter pub get
flutter run
```

CI делает шаги 2-3 за вас на каждом release-теге (`v*.*.*`) и на
manual workflow-dispatch; артефакты можно скачать из Actions-run,
если у вас нет NDK / Mac на dev-машине (например, Windows-only
контрибьютор может запросить manual run и взять `.so` файлы из него).

Этот документ — рецепт интеграции **сегодня** с инструментами,
которые существуют сегодня. Путь A (uniffi-dart напрямую) — это
долгосрочная цель; Путь B (per-platform plugin) работает уже сейчас.

## Путь A — напрямую через `uniffi-dart` (рекомендуется после стабилизации)

[`uniffi-dart`](https://github.com/NiwakaDev/uniffi-dart) генерирует
Dart-биндинги из тех же `#[uniffi::*]`-аннотаций, которые потребляют
генераторы Kotlin / Swift / Python. Когда он достигнет стабильной
версии (отслеживайте issues [#5](https://github.com/NiwakaDev/uniffi-dart/issues/5),
[#42](https://github.com/NiwakaDev/uniffi-dart/issues/42) для известных
пробелов), интеграция сократится до:

```sh
# В директории `rust/` вашего Flutter-приложения.
cargo build -p hidden-volume-ffi --release \
    --target aarch64-linux-android \
    --target armv7-linux-androideabi \
    --target x86_64-linux-android

# Генерация Dart-биндингов.
cargo install uniffi-bindgen-dart   # после стабилизации
uniffi-bindgen-dart \
    --library target/release/libhidden_volume_ffi.so \
    --out-dir lib/src/bindings
```

Затем в вашем Flutter-коде:

```dart
import 'package:my_app/src/bindings/hidden_volume_ffi.dart' as hv;

Future<void> openSpace() async {
  final space = await hv.AsyncSpaceHandle.open(
    path: '/data/data/com.example.app/files/store.bin',
    password: utf8.encode('my-password'),
  );
  final value = await space.get(namespace: 1, key: utf8.encode('username'));
  print(utf8.decode(value!));
}
```

Распространяйте per-ABI `.so`-файлы через
[`flutter_rust_bridge`-style](https://github.com/fzyzcjy/flutter_rust_bridge)
plugin layout под `android/src/main/jniLibs/` и аналогично для iOS.

**Отслеживать для миграции:** когда выйдет uniffi-dart 1.0, async-поверхность
со стороны Dart должна напрямую отображаться в Dart `Future<T>` без
adapter-кода. До этого момента ожидайте небольшой ручной обёртки.

## Рукописные Dart-биндинги и их таблица checksums

`experimental/flutter_plugin/hidden_volume/lib/src/bindings.dart` привязан
напрямую к C ABI uniffi 0.31 (почему не генерируется — см. шапку файла). У
рукописных биндингов нет страховки, которая есть у сгенерированных: uniffi
экспортирует по одному checksum-символу на метод, и сгенерированный биндинг
сверяет каждый со значением, зашитым при генерации, отказываясь работать при
расхождении.

Без этой сверки библиотека постарее или подменённая, но с тем же *contract
version*, принималась, и первый же вызов декодировал не те байты — нативный
крэш, если повезёт, и тихо неверные аргументы поверх настоящего контейнера
пользователя, если нет (audit HV-05). Теперь `bindings.dart` несёт таблицу и
сверяет каждую запись до первого FFI-вызова.

**Перегенерировать таблицу после ЛЮБОГО изменения сигнатуры Rust FFI:**

```sh
cargo build -p hidden-volume-ffi --release
scripts/regen-dart-checksums.py            # переписать таблицу на месте
scripts/regen-dart-checksums.py --check    # режим CI: упасть, если устарела
```

Скрипт делает dlopen собранной cdylib и ВЫЗЫВАЕТ каждый checksum-символ —
значение это то, что символ возвращает, а не его имя, поэтому `nm` / `strings`
его не дадут, а вызов работает одинаково для `.dylib` / `.so` / `.dll`. Набор
ключей выводится из самих lookup'ов в `bindings.dart`, так что новый
привязанный метод подхватывается без правки второго списка.

Устаревшая таблица падает на запуске fail-closed — это уже свой собственный
простой, поэтому `--check` стоит держать в pre-tag гейте.

## Путь B — per-platform plugin (работает сегодня)

Оберните Kotlin- и Swift-биндинги в стандартный Flutter plugin
(`flutter create --template=plugin`). На каждой платформе нативный
код плагина вызывает сгенерированные биндинги:

```
my_storage_plugin/
├── android/src/main/kotlin/com/example/MyStoragePlugin.kt
│   └── (вызывает bindings/kotlin/uniffi/hidden_volume_ffi/...)
├── ios/Classes/MyStoragePlugin.swift
│   └── (вызывает bindings/swift/...)
└── lib/my_storage_plugin.dart
    └── (Dart → method-channel → нативный код)
```

Это требует больше работы — вы пишете method-channel passthrough на
каждой стороне — но базовые типы `hidden-volume-ffi` стабильны, и
тяжёлая работа (FFI ABI, маппинг ошибок, async runtime) уже
выполнена. Примерно ~200 строк Kotlin + ~200 строк Swift + ~100 строк
Dart для полного покрытия.

Компромисс по сравнению с Путём A: каждое изменение API в Rust-крейте
требует обновления двух нативных wrapper-файлов (Kotlin, Swift) и
Dart method-channel поверхности. С uniffi-dart это одна команда
регенерации.

## Рекомендуемый начальный набор методов для экспорта

MVP мессенджера нуждается в минимальном подмножестве; остальное отложите:

1. `SpaceHandle.create(path, password, argon, ...)` — настройка при первом запуске
2. `AsyncSpaceHandle.open(path, password)` — путь запуска (async, чтобы
   UI оставался отзывчивым во время open-time scan)
3. `commit(ops: List<WriteOp>)` — одна batched-запись (настройки,
   контакты, сообщения — см. DESIGN.md §11.4 namespace assignments)
4. `get(namespace, key)` — KV-чтения (настройки, метаданные контактов)
5. `iter_log_range(namespace, start, end, limit)` — пагинация истории
   чата (объедините `log_id` с timestamp-encoded u64)
6. `commit_seq()` + `commit_history()` — для anchor-ов rollback-detection
   (см. [`multi-device.md`](multi-device.md))

Пропустите до возникновения необходимости: `verify_integrity`, `stats`,
`header_info`. Они только диагностические, и host-app редко выводит
их в основные UI-потоки.

## Модель потоков

Async-поверхность (`AsyncSpaceHandle`) — это правильный default для
Flutter — каждый метод await-ится, никогда не блокируя event loop
Dart-изолята. Внутри каждый вызов offload-ится в blocking-пул Tokio;
uniffi запускает runtime внутри Rust dylib при первом использовании.

Синхронный `SpaceHandle` также доступен, но **не вызывайте его из
основного изолята** — open-time scan может занимать сотни мс на
слабом железе и заморозит UI. Используйте sync только из Dart-изолята,
запущенного через `compute()` / `Isolate.spawn()`.

Параллельные вызовы на одном handle сериализуются на внутреннем
mutex (соответствует инварианту синхронного ядра «одна Tx на Space
одновременно»). Два `await space.get(...)` из разных async-функций
выполнятся последовательно под капотом.

### Таймаут ничего не отменяет (аудит HV-07)

Dart-`Future` отменить нельзя. `await space.commit(ops)
.timeout(...)` прекращает ожидание **у вас**; воркер-изолят при этом
не останавливается — он доработает вызов и отправит ответ в порт,
который никто не читает. То есть после таймаута вызывающий не знает,
легла запись или нет, а на отрицаемом хранилище альтернатива знанию —
догадка и, возможно, повторное применение.

Поэтому `HvAsyncSpace` выдаёт идентификатор на операцию и хранит
исход:

```dart
final op = space.commitOperation(ops);   // id доступен сразу
try {
  await op.result.timeout(const Duration(seconds: 2));
} on TimeoutException {
  // Спросить позже — НЕ пересылать вслепую.
  switch (space.outcomeOf(op.id)) {
    case HvOpPending():   /* всё ещё выполняется */
    case HvOpSucceeded(): /* легла; переделывать нечего */
    case HvOpFailed(:final mayHaveApplied):
      // Воркер ответил, ядро отказало. Спросить у ВИДА ошибки, доказывает
      // ли этот отказ отсутствие эффекта: если нет — переоткрыть.
      if (mayHaveApplied) { /* переоткрыть и посмотреть */ } else { /* ретрай безопасен */ }
    case HvOpIndeterminate(): /* воркер УМЕР под вызовом — переоткрыть и посмотреть */
    case HvOpUnknown():   /* не выдавался или вытеснен из истории */
  }
}
```

**`HvOpFailed` и `HvOpIndeterminate` — не один и тот же ответ**, и
разница важна ровно тогда, когда она вообще важна. `HvOpFailed` значит,
что воркер был жив, выполнил вызов и ядро отказало. `HvOpIndeterminate`
значит, что воркер *умер* под вызовом, — а изолят может умереть уже
ПОСЛЕ того, как нативная фиксация легла на диск, и ДО того, как ушёл
ответ, поэтому со стороны Dart неизвестно, применилась запись или нет.
Переоткрыть контейнер и посмотреть.

**Отказ сам по себе не доказывает отсутствия эффекта** (report8 H-09).
Это руководство — и сам `HvOpFailed` — раньше говорили «ничего не
закоммичено, ретрай безопасен» про ЛЮБОЙ отказ, тогда как
[`docs/ru/security/audits/fsync.md`](../security/audits/fsync.md) писал,
что caller «НЕ должен ретраить тот же Tx без предварительного re-open
контейнера». Ядро на стороне аудит-документа: коммит, чья публикация
Superblock'а сорвалась, отвечает `PublishUncertain`, который и
существует, чтобы сказать «реплика может уже быть на диске». Читать
`HvOpFailed.mayHaveApplied` (то есть `HvException.mayHaveApplied`): он
`true` для `PublishUncertain` и двух видов `RenameVisible*` и `false`
для отказов, случившихся до единой записи.

Это зеркалит ядро на Rust, которое моделирует потерянную операцию как
ту, что **могла изменить состояние**; доказательство отсутствия эффекта
там несёт только `Cancelled`. До report7 P2 сторона Dart записывала
смерть воркера как `HvOpFailed`, то есть утверждала «ничего не
закоммичено» про операцию, чьё завершение никто не наблюдал, — и это
руководство советовало на ней ретраить.

Аналогично `eraseNamespaceOperation`, `setPaddingPolicyOperation`,
`vacuumDataBatchesOperation` и `vacuumAfterOpenOperation`. Обычные
`commit` / `eraseNamespace` / … не изменились и делегируют сюда.

У Rust-FFI есть собственный реестр для этого
(`AsyncSpaceHandle::abandoned_operations`), но он живёт на
**асинхронном** хендле, а рукописные Dart-биндинги подключают только
синхронные символы — воркер держит `SpaceHandleBindings` — так что из
Dart он недостижим. `outcomeOf` — это его Dart-аналог, а не привязка к
нему.

Исходы хранятся для последних 128 операций на хендл; дальше
`outcomeOf` отвечает `HvOpUnknown`, что намеренно отличается от
`HvOpPending`.

## Бюджет хранилища на мобильных устройствах

Размер контейнера пользователя мессенджера масштабируется с историей
сообщений. Из
[`docs/en/contributing/benchmarks.md`](../contributing/benchmarks.md):

| Профиль пользователя | Размер | Время открытия (parallel-scan) |
|---|---|---|
| Лёгкий (~6 месяцев, 1 контакт) | 40 МиБ | 18 мс |
| Средний (~2 года, 5 контактов) | 200 МиБ | 264 мс |
| Тяжёлый (~5 лет, 20 контактов) | 400 МиБ | 204 мс |

Для Flutter на Android: включите feature `parallel-scan` при сборке
cdylib (`cargo build -p hidden-volume-ffi --release --features parallel-scan`).
На iOS feature тоже можно включить — лимит rayon на 4 потока удерживает
энергопотребление в рамках. См.
[`docs/en/contributing/benchmarks.md`](../contributing/benchmarks.md) §"Parallel-scan tuning" для эмпирической
кривой масштабирования.

## Выбор Argon2-пресета

| Класс устройства | Пресет | Разблокировка при первом запуске |
|---|---|---|
| Cortex-A53 (2017+) low-end Android | `ArgonPreset.LIGHT` | ~30 мс |
| Mid-range / flagship Android, A12+ iPhone | `ArgonPreset.DEFAULT` | ~100 мс |
| Desktop Linux/macOS/Windows | `ArgonPreset.HEAVY` | ~250 мс |

Выберите во время `create` — пресет запекается в заголовок
контейнера. Миграция на более сильный пресет позже делается через
no-op ротацию `change_passwords` с новыми параметрами Argon2
(см. [`operations.md`](operations.md) §3).

## Резервное копирование / восстановление на мобильных устройствах

И Android, и iOS имеют OS-level хуки бэкапа (Android Auto Backup,
iCloud Keychain + Documents). Файл контейнера — это **единый
непрозрачный blob** — бэкапьте его целиком. См.
[`operations.md`](operations.md) §1 для cold-backup процедуры
(LOCK_SH + предупреждение про anchor).

## Что этот гайд НЕ покрывает

- **Hot reload Rust-кода в Flutter dev mode** — не поддерживается
  uniffi; требуется перезапуск приложения при изменениях в Rust.
- **iOS xcframework packaging** — см. [`TASKS.md`](../../../TASKS.md) v0.8;
  рецепт отложен до первого iOS-интегратора.
- **Android `.aar` packaging** — то же самое, рецепт в
  [`bindings/README.md`](../../../bindings/README.md) §Kotlin.
- **Flutter Web** — `hidden-volume` требует настоящих flock + fsync;
  browser sandbox не предоставляет ни того, ни другого. Используйте
  серверный вариант (например, WebSocket-шлюз к бэкенду, на котором
  работает `hidden-volume`).

## См. также

- [`docs/en/reference/ffi.md`](../reference/ffi.md) — архитектурные решения
  (uniffi vs альтернативы, threading, маппинг ошибок, async/sync split)
- [`bindings/README.md`](../../../bindings/README.md) — примеры использования
  по языкам (Python, Kotlin, Swift, Ruby)
- [`docs/en/guide/integration.md`](integration.md) — обзор интеграции
  на стороне Rust для host-app (anchors, rollback, sync)
- [`docs/en/guide/multi-device.md`](multi-device.md) — контракт sync /
  anchor / rollback-detection
