# Проверка релиза

Каждый tagged-релиз публикует:

- Per-target бинарники: `hv-<target>` (CLI) и
  `libhidden_volume_ffi-<target>.{so,dylib,dll}` (uniffi cdylib).
- `SHA256SUMS` — построчно `<sha256>  <filename>` для каждого
  бинарника, отсортировано по имени файла.
- `SHA256SUMS.cosign.bundle` — Sigstore bundle (cosign keyless
  signature + Fulcio cert chain + Rekor transparency-log entry,
  в одном self-contained JSON-файле).

Проверка подтверждает две вещи:

1. Файл `SHA256SUMS` подписан именно [release-workflow этого
   репозитория][release-yml], запущенным на *валидном SemVer-теге* —
   никто другой не может произвести совпадающую подпись.
2. Скачанный бинарник побайтово совпадает со своей строкой в
   `SHA256SUMS` — нет on-the-wire tamper'а, нет обрезания.

Оба шага обязательны. Подписанный `SHA256SUMS` с несовпадающим
бинарником означает, что файл подменили после релиза;
неподписанный совпадающий `SHA256SUMS` не доказывает ничего о том,
кто его произвёл.

## Однократная настройка

Установите [`cosign`][cosign]. macOS:

```sh
brew install cosign
```

Linux (любой дистрибутив, без root):

```sh
curl -L https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 \
  -o ~/.local/bin/cosign && chmod +x ~/.local/bin/cosign
```

Проверьте, что версия актуальная (рекомендуется `>= 2.0`):

```sh
cosign version
```

Управлять ключами не нужно. Публичные roots Sigstore поставляются
вместе с cosign.

## Проверка релиза

Скачайте четыре файла под вашу платформу со страницы релиза:

- Бинарник, например `hv-aarch64-apple-darwin`
- Соответствующий `libhidden_volume_ffi-<target>.{so,dylib,dll}`,
  если ваше приложение его линкует
- `SHA256SUMS`
- `SHA256SUMS.cosign.bundle`

Положите все четыре в одну директорию, затем:

```sh
# 1. Проверьте, что SHA256SUMS подписан release-workflow ЭТОГО
#    репозитория на SemVer-теге. Замените OWNER/REPO на координаты
#    GitHub, откуда вы скачивали.
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/OWNER/REPO/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS

# Ожидаемый вывод: `Verified OK`. Любой другой = НЕ доверять файлу.

# 2. Проверьте бинарники против (уже доверенного) SHA256SUMS.
sha256sum --ignore-missing -c SHA256SUMS    # GNU sha256sum (Linux)
# ИЛИ:
shasum -a 256 -c SHA256SUMS                 # macOS / BSD
```

`--ignore-missing` позволяет держать `SHA256SUMS` целиком,
проверяя только тот набор бинарников, что вы скачали.

## Что подпись фиксирует

Sigstore bundle пинит:

| Поле | Значение | Что доказывает |
|---|---|---|
| `subject` | SHA-256 хэш файла `SHA256SUMS` | у вас именно тот файл, который был подписан |
| Certificate `Subject Alternative Name` | `https://github.com/OWNER/REPO/.github/workflows/release.yml@refs/tags/v…` | подписал *этот* workflow в *этом* репо на *этом* теге |
| Certificate `oidc.issuer` | `https://token.actions.githubusercontent.com` | workflow выполнился на GitHub-hosted Actions (не на self-hosted runner'е, который мог бы leak'нуть OIDC-токен) |
| Rekor log entry | inclusion proof | подпись записана в публичный Sigstore transparency-log; атакующий не может тихо выписать параллельную подпись без публичного следа |

Все вместе эти проверки означают: *если SHA256SUMS прошёл
`cosign verify-blob` с identity-регулярным выражением,
привязанным к этому repo+workflow+tag-паттерну — только run
именно этого workflow в этом репо на SemVer-теге мог его
подписать.*

## Что подпись НЕ фиксирует

- **Source commit.** Подпись привязана к *тегу*, не к конкретному
  commit SHA. Если нужно привязаться к коммиту, сверьте ссылку на
  коммит со страницы релиза против вашей git-истории.
- **Pre-1.0 стабильность формата.** Даже если бинарник
  верифицируется, on-disk формат контейнера может поломаться при
  v0.x → v0.y bump — см.
  [`docs/ru/reference/semver.md`](../reference/semver.md) для
  политики pre-1.0.
- **Публикацию крейтов на crates.io.** Каждый workspace-крейт имеет
  `publish = false` до завершения внешнего crypto-review (см.
  [`TASKS.md`](../../../TASKS.md) v1.0). Верификация артефактов
  независима от того, лежат ли крейты на crates.io.

## Что может пойти не так

| Симптом | Вероятная причина | Действие |
|---|---|---|
| `cosign verify-blob`: `no matching signatures` | `SHA256SUMS` был изменён после релиза; ИЛИ `.cosign.bundle` от другого релиза | Скачайте оба заново с canonical-страницы релиза |
| `cosign verify-blob`: `certificate identity does not match` | Bundle подписан другим workflow / другим репо / не-теговым ref | Отказать — кто-то может имитировать pipeline этого репо |
| `cosign verify-blob` ОК, `sha256sum -c` падает на одном файле | Этот файл был подменён в транзите; остальной релиз может быть целым | Перекачайте только проблемный файл другой сетью / зеркалом |
| `sha256sum -c`: `WARNING: N lines are improperly formatted` | Вы конкатенировали несколько `SHA256SUMS` | Начните заново с файлов одного релиза |

## Сообщение о провале проверки

Если verification падает И re-download с canonical-страницы
релиза воспроизводит фейл — это инцидент supply chain. Откройте
[security advisory][advisory] и напишите maintainer'у по
[`SECURITY.ru.md`](../../../SECURITY.ru.md). Неверифицированные
бинарники **не** устанавливайте.

[release-yml]: ../../../.github/workflows/release.yml
[cosign]: https://github.com/sigstore/cosign
[advisory]: https://github.com/veilnetwork/hidden-volume/security/advisories
