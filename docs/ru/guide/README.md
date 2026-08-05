# Гайд — интеграция в host-app

[🇬🇧 English](../../en/guide/README.md) · [🇷🇺 Русский](README.md)

Практические рецепты построения host-app поверх `hidden-volume`.
Сначала прочитайте [`integration.md`](integration.md); остальное —
справочный материал на обращение по мере надобности.

## Документы

- **[integration.md](integration.md)** — нарративное руководство.
  Пространства, транзакции, инварианты отрицаемости, анти-паттерны,
  смена пароля, пагинация message-history. **Начните отсюда.**
- **[operations.md](operations.md)** — operations playbook.
  Развёртывание, бэкап, repack/compact, проверка целостности,
  восстановление после типовых отказов.
- **[multi-device.md](multi-device.md)** — формальный контракт для
  multi-device host-app'ов. Примитивы блокировок, паттерны якорей,
  семантика синхронизации, замечания о replay-rollback.
- **[flutter.md](flutter.md)** — встраивание `hidden-volume` в
  Flutter-приложение через FFI-биндинги (uniffi 0.31).
- **[migration.md](migration.md)** — политика межпоколенческой
  миграции формата. До 1.0 on-disk формат менялся дважды
  (v1 → v2 → v3), ломающе by design и без in-place-инструмента;
  текущее поколение — v3.

## Что читать дальше

После гайда обычно нужно одно из:

- [`reference/format.md`](../reference/format.md) — байтовая
  спецификация формата для понимания того, что лежит на диске.
- [`security/threat-model.md`](../security/threat-model.md) — от
  каких угроз `hidden-volume` защищает (а от каких нет).
- [`reference/semver.md`](../reference/semver.md) — что стабильно,
  а что может сломаться между минорными версиями.
