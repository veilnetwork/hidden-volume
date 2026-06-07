# Contributing — для контрибьюторов проекта

[🇬🇧 English](../../en/contributing/README.md) · [🇷🇺 Русский](README.md)

Если вы контрибьютите код, тесты, доки или бенчмарки — начинайте
отсюда.

## Документы

- **[guide.md](guide.md)** — open-source workflow. Ветки, PR,
  этикет ревью, code-conventions (rustfmt, строгость clippy,
  политика `#![deny(missing_docs)]`), стиль commit-message.
- **[benchmarks.md](benchmarks.md)** — baseline `cargo bench
  --bench throughput` + таблица валидации perf-таргетов.

## Быстрый ориентир

| Вы хотите … | См. |
|---|---|
| Открыть PR | `guide.md` § Workflow |
| Запустить бенчмарки локально | `benchmarks.md` § Run |
| Сообщить об уязвимости | [`../../../SECURITY.md`](../../../SECURITY.md) |
| Понять правила format-stability перед изменением типов | [`../reference/semver.md`](../reference/semver.md) |
