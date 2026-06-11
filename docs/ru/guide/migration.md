# Миграция формата

[🇬🇧 English](../../en/guide/migration.md) · 🇷🇺 **Русский**

**Статус.** Pre-1.0. Поколение формата уже дважды бампилось в
pre-1.0 (v1 → v2 в audit pass 13, v2 → v3 — 2026-05-28); эти
bump-ы **намеренно breaking**, in-place migration-tool не
поставляется. Cross-version переходы идут через export-and-reimport.

Этот документ покрывает:

- Текущую cross-version reject-политику (`Argon2Params::validate`
  отвергает любой `format_version` != текущий; в v3 это также
  криптографически связано — см. [§7 `format.md`](../reference/format.md)).
- Рецепт export-and-reimport для переноса данных из контейнера vN
  в контейнер vM.
- Post-1.0 план: на момент релиза v1.0 формат **заморожен**;
  последующие breaking changes требуют нового поколения и
  полноценного migration-tool'а.

## Текущее поколение формата

`hidden-volume` сейчас пишет **v3** (с 2026-05-28). Старые поколения:

| Gen | Статус | Введён | Удалён | Замечания |
|---|---|---|---|---|
| v1 | не поддерживается | старт проекта | audit pass 13 | Изначальная раскладка. |
| v2 | не поддерживается | audit pass 13 (R-NSKIND) | v3 bump (2026-05-28) | Добавлен per-`IndexRoot` байт `kind`. |
| **v3** | **текущий** | 2026-05-28 | — | Добавлены kind-tag bytes (#8), криптографическая привязка версии (#9), per-space derived `container_id` (#10). Убран cleartext `container_id` из header'а. |

Intra-version миграции (без bump'а формата):

- **Изменение Argon2-параметров** — см. [`operations.md`](../../en/guide/operations.md) §3.
- **Смена пароля** — см. [`operations.md`](../../en/guide/operations.md) §2.
- **Compaction / возврат места** — см. [`operations.md`](../../en/guide/operations.md) §5.
- **Схемы multi-device sync** — см. [`multi-device.md`](../../en/guide/multi-device.md).

Они остаются внутри v3.

## Cross-version policy

v3 reader отказывается открывать v1- или v2-контейнеры. v1/v2
reader'ы аналогично отказываются открывать v3-контейнеры. В v3
reject **двойной**:

1. **Политика:** [`Argon2Params::validate`](../../../crates/hidden-volume/src/crypto/kdf.rs)
   отвергает `format_version != PARAMS_VERSION` на open'е.
2. **Криптография (v3 #9):** [`derive_master_key`](../../../crates/hidden-volume/src/crypto/kdf.rs)
   свёртывает `params.version` в master key через post-Argon2
   BLAKE3-step. Гипотетический reader, который ослабит policy gate,
   всё равно вычислит другой `master_key` и упадёт с `AuthFailed`
   на первой же AEAD-попытке.

In-place миграции нет. Единственный способ перенести данные через
границу версий формата — **экспортировать из источника,
импортировать в свежее назначение**.

## Рецепт миграции (vN → vM, любой cross-version переход)

Рецепт ниже работает для любой cross-version пары, где есть
билд библиотеки, читающий поколение источника, И (возможно
другой) билд, пишущий поколение назначения.

```rust,ignore
// Псевдокод. Замените `ContainerVN` / `ContainerVM` на ту версию
// крейта, которая читает / пишет каждое поколение.

// 1. Открыть источник под *старой* сборкой библиотеки.
let src = ContainerVN::open(&src_path)?;
let src_space = src.open_space(&password)?;

// 2. Перечислить каждый namespace, который знает host-app.
//    Глобального итератора по namespaces нет; host-app должен
//    помнить, какие namespace-id он использовал (это часть
//    integration-контракта — см. docs/en/guide/integration.md §3).
let known_namespaces = host_app_namespace_registry();

// 3. Создать свежее назначение под *новой* сборкой библиотеки.
let dst = ContainerVM::create(&dst_path, Argon2Params::DEFAULT)?;
let mut dst_space = dst.create_space(&password)?;

// 4. Стримить каждую KV-пару и каждую log-запись в назначение.
let mut tx = dst_space.begin_tx();
for ns in &known_namespaces {
    for (k, v) in src_space.list(*ns)? {
        tx.put(*ns, &k, &v)?;
    }
    // Log-записи: итерируем log источника; добавляем по порядку.
    for entry in src_space.iter_log_after(*ns, 0)? {
        let (log_id, payload) = entry?;
        tx.append_log(*ns, log_id, &payload)?;
    }
}
tx.commit()?;

// 5. Проверить integrity назначения до удаления источника.
dst_space.verify_integrity()?;

// 6. Атомарно переименовать или забэкапить источник. Держите
//    его читаемым, пока назначение не переживёт хотя бы одну
//    полную сессию приложения.
```

Замечания:

- Это **полный plaintext round-trip**. Нет shortcut'а, который
  сохранял бы AEAD ciphertext — разные поколения дeriviт разные
  `master_key`s для одного и того же password+salt, поэтому
  chunk'и нельзя re-tag'нуть на месте.
- Назначение имеет **свежий `container_salt`** (а в v3 —
  свежедеривированный per-space `container_id`); host-app'ы,
  отслеживающие rollback-anchor'ы по
  [`multi-device.md`](../../en/guide/multi-device.md), ОБЯЗАНЫ
  сбросить anchor-state в `commit_history = [1]` после миграции.
- `Container::repack` — **не** cross-version migration tool.
  Repack остаётся в пределах одного поколения формата; он
  обновляет Argon2-параметры / padding policy / replica count,
  но НЕ бампит `format_version`.

## Чего НЕ делать

- **Не редактируйте байты header вручную**, чтобы заявить другой
  format version. v3 криптографическая привязка версии означает,
  что результирующий файл всё равно не откроется, даже если
  policy gate был бы обойдён.
- **Не предполагайте, что миграция обратима.** Plaintext-экспорт
  раскрывает всё, что было зашифровано в источнике; как только вы
  записали назначение, относитесь к источнику как к тому, чей
  plaintext был тронут (zeroize буферы, scrub если нужно).
- **Не запускайте миграцию на живом writer.** Снимите источник с
  использования (закройте все handle'ы в host-app) до чтения;
  `flock(LOCK_EX)` отклонит второго writer, но если файловая
  система не уважает `flock` (NFS без lockd, некоторые конфигурации
  FUSE), назначение можно молча испортить.
- **Не удаляйте источник, пока назначение не верифицировано.**
  Запустите `Space::verify_integrity` на назначении и проведите
  его через полную сессию host-app (вкл. хотя бы один commit на
  назначении) до удаления источника.

## Post-1.0 план

На момент релиза v1.0 формат будет **заморожен** для линии v1.x.
Любое позднейшее breaking change (вводящее v4):

1. Поставится с major-version bump'ом библиотеки (v2.x).
2. Понесёт полноценный migration tool
   (`hidden_volume::migrate::v3_to_v4` или эквивалент), оборачивающий
   рецепт export-and-reimport выше в один API-call.
3. Будет задокументирован здесь с рецептом `vN → vM` + критериями
   приёмки.
4. Будет следовать cross-version policy: v2.x библиотека
   отказывается писать v3-файлы (read-only fallback может
   существовать максимум один major version, после чего поддержка
   v3 убирается).

Pre-1.0 политика «нет migration tool» уйдёт на v1.0; заморозка
размывает гибкость в пользу стабильности.

## Audit log

| Дата | Событие | Документ |
|---|---|---|
| старт проекта | v1 введён | `DESIGN.ru.md` (исторический) |
| audit pass 13 (R-NSKIND) | v2 введён (per-`IndexRoot` байт `kind`) | `CHANGELOG.md` pass-13 entry |
| 2026-05-28 | **v3 введён** (#8 kind-tag bytes + #9 криптографическая привязка версии + #10 per-space derived `container_id`) | [`format.md` §13](../reference/format.md) |
| v1.0 (планируется) | Format freeze | TBD |
| post-1.0 (TBD) | Первый полноценный migration tool | Этот документ, расширенный |

## Перекрёстные ссылки

- [`format.md`](../reference/format.md) §7 — cross-version policy
  reject-таблица; §13 — журнал изменений формата.
- [`format.md`](../reference/format.md) §3 — v3 key schedule со
  step'ом version-bind.
- [`operations.md`](../../en/guide/operations.md) §3 —
  intra-version Argon2-param миграция (не меняет `format_version`).
- [`../security/threat-model.md`](../security/threat-model.md) §4.1
  F-PAD — как v3 закрывает silent-degrade поверхность
  v2-padding-downgrade как побочный эффект #9.
- [`multi-device.md`](../../en/guide/multi-device.md) — стратегия
  anchor'а через миграции; reset `commit_history` после
  export-and-reimport.
