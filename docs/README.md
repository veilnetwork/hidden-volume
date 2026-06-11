# hidden-volume — documentation

🇬🇧 **English** · [🇷🇺 Русский](#русский)

`hidden-volume` is a deniable multi-space encrypted append-only
container — a storage primitive for messengers and other apps that
need plausible-deniability against compelled-key disclosure.

This index is bilingual: every document below has both an English
and a Russian version. Click the flag in any document's header to
switch languages.

## Quick links

- **[Project root README](../README.md)** — what `hidden-volume` is
  and why you might want it. ([Русский](../README.ru.md))
- **[DESIGN.md](../DESIGN.md)** — formal design document, single
  source of truth for invariants. ([Русский](../DESIGN.ru.md))
- **[CHANGELOG.md](../CHANGELOG.md)** — what changed and when.
- **[SECURITY.md](../SECURITY.md)** — vulnerability reporting +
  audit history. ([Русский](../SECURITY.ru.md))

## English documentation

### Guide — host-app integration ([en/guide/](en/guide/))

Practical recipes for building on top of `hidden-volume`. Read the
integration guide first; everything else is reference material you
consult as needed.

| Document | Description |
|---|---|
| [Integration guide](en/guide/integration.md) | Narrative walkthrough of host-app integration: spaces, transactions, deniability invariants, anti-patterns. **Start here.** |
| [Operations playbook](en/guide/operations.md) | Deploying, backing up, migrating, repacking, and recovering containers. |
| [Multi-device contract](en/guide/multi-device.md) | Locking primitives, sync semantics, anchor patterns for multi-device messengers. |
| [Flutter integration](en/guide/flutter.md) | Embedding `hidden-volume` in a Flutter app via the FFI bindings. |
| [Format migration](en/guide/migration.md) | Reserved for the eventual v1 → v2 on-disk format migration. |

### Reference — formal specs ([en/reference/](en/reference/))

| Document | Description |
|---|---|
| [On-disk format v1](en/reference/format.md) | Canonical byte-level wire format spec. |
| [Public API surface](en/reference/api-surface.txt) | Snapshot of every `pub` item at v1.0 (frozen). |
| [Semver policy](en/reference/semver.md) | What constitutes a breaking change in the v1.x line. |
| [FFI design](en/reference/ffi.md) | Architecture of the `hidden-volume-ffi` crate (uniffi 0.31). |

### Security — threat model + audits ([en/security/](en/security/))

| Document | Description |
|---|---|
| [Threat model](en/security/threat-model.md) | Formal threat model for v1.0 external review. |
| [Constant-time audit](en/security/audits/constant-time.md) | v0.5 audit: every `==` / `!=` site checked for timing leaks. |
| [fsync ordering audit](en/security/audits/fsync.md) | v0.5 audit: 3-fsync commit protocol verified. |
| [Memory hygiene audit](en/security/audits/memory.md) | v0.5 audit: zeroize coverage on every secret type. |
| [Plaintext-leak audit](en/security/audits/plaintext.md) | v0.5 audit: transient pre/post-encryption buffers. |

### Contributing — for project contributors ([en/contributing/](en/contributing/))

| Document | Description |
|---|---|
| [Contributing guide](en/contributing/guide.md) | Open-source workflow: branches, PRs, review etiquette. |
| [Benchmarks](en/contributing/benchmarks.md) | `cargo bench` baseline + perf-target validation. |

---

<a name="русский"></a>

# hidden-volume — документация

[🇬🇧 English](#hidden-volume--documentation) · 🇷🇺 **Русский**

`hidden-volume` — отрицаемый мультипространственный шифрованный
append-only контейнер, примитив хранения для мессенджеров и других
приложений, которым нужна правдоподобная отрицаемость при
принудительном раскрытии ключей.

Индекс двуязычный: у каждого документа есть английская и русская
версии. Переключение языков — по флагу в шапке документа.

## Быстрые ссылки

- **[README проекта](../README.ru.md)** — что такое `hidden-volume`
  и зачем он нужен. ([English](../README.md))
- **[DESIGN.ru.md](../DESIGN.ru.md)** — формальный дизайн-документ,
  единый источник истины по инвариантам. ([English](../DESIGN.md))
- **[CHANGELOG.md](../CHANGELOG.md)** — что и когда менялось.
- **[SECURITY.ru.md](../SECURITY.ru.md)** — отчёт об уязвимостях +
  история аудитов. ([English](../SECURITY.md))

## Документация на русском

### Гайд — интеграция в host-app ([ru/guide/](ru/guide/))

Практические рецепты построения поверх `hidden-volume`. Сначала
читайте гайд по интеграции; остальное — справочный материал на
обращение по мере надобности.

| Документ | Описание |
|---|---|
| [Гайд по интеграции](ru/guide/integration.md) | Нарративное руководство по интеграции в host-app: пространства, транзакции, инварианты отрицаемости, анти-паттерны. **Начните отсюда.** |
| [Operations playbook](ru/guide/operations.md) | Развёртывание, резервное копирование, миграция, repack и восстановление контейнеров. |
| [Контракт multi-device](ru/guide/multi-device.md) | Примитивы блокировок, семантика синхронизации, паттерны якорей для multi-device мессенджеров. |
| [Интеграция с Flutter](ru/guide/flutter.md) | Встраивание `hidden-volume` в Flutter-приложение через FFI-биндинги. |
| [Миграция формата](ru/guide/migration.md) | Резерв под будущую миграцию on-disk формата v1 → v2. |

### Reference — формальные спецификации ([ru/reference/](ru/reference/))

| Документ | Описание |
|---|---|
| [On-disk формат v1](ru/reference/format.md) | Каноническая байтовая спецификация on-wire формата. |
| [Поверхность публичного API](en/reference/api-surface.txt) | Снимок каждого `pub` элемента на v1.0 (frozen). Файл нейтрален по языку — общий с английской версией. |
| [Политика semver](ru/reference/semver.md) | Что является ломающим изменением в линии v1.x. |
| [Дизайн FFI](ru/reference/ffi.md) | Архитектура крейта `hidden-volume-ffi` (uniffi 0.31). |

### Безопасность — модель угроз + аудиты ([ru/security/](ru/security/))

| Документ | Описание |
|---|---|
| [Модель угроз](ru/security/threat-model.md) | Формальная модель угроз для внешнего ревью v1.0. |
| [Constant-time аудит](ru/security/audits/constant-time.md) | v0.5 аудит: каждый `==` / `!=` проверен на timing-утечки. |
| [Аудит fsync-упорядочивания](ru/security/audits/fsync.md) | v0.5 аудит: 3-fsync протокол коммита проверен. |
| [Аудит чистоты памяти](ru/security/audits/memory.md) | v0.5 аудит: zeroize-покрытие на каждом секретном типе. |
| [Аудит утечек plaintext](ru/security/audits/plaintext.md) | v0.5 аудит: транзитные буферы до и после шифрования. |

### Contributing — для контрибьюторов ([ru/contributing/](ru/contributing/))

| Документ | Описание |
|---|---|
| [Гайд контрибьютору](ru/contributing/guide.md) | Open-source workflow: ветки, PR, этика ревью. |
| [Бенчмарки](ru/contributing/benchmarks.md) | Baseline `cargo bench` + валидация целевых perf-метрик. |

---

## Status / Статус

Pre-1.0 freeze. Code-side complete; release engineering + external
crypto review remain. See [`TASKS.md`](../TASKS.md) for the full
backlog (project file, mixed Russian/English).

Pre-1.0 freeze. Кодовая часть готова; остаются release-инжиниринг
и внешнее crypto-ревью. Полный backlog — в [`TASKS.md`](../TASKS.md)
(внутренний рабочий файл, смесь русского и английского).
