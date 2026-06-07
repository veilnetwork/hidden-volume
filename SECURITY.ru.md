# Security policy

[🇬🇧 English](SECURITY.md) · 🇷🇺 **Русский**

## Сообщение об уязвимости

Если вы обнаружили проблему безопасности в `hidden-volume`, пожалуйста,
сообщите о ней **приватно** до публичного раскрытия.

Мы относимся к безопасности серьёзно, поскольку эта библиотека лежит в
основе заявлений о plausible deniability для мессенджеров. Уязвимость в
криптографической поверхности или в логике deniability может привести к
реальному вреду пользователям во враждебных условиях.

### Как сообщить

- Откройте приватный GitHub Security Advisory (вкладка «Security» →
  «Report a vulnerability»), если проект размещён на GitHub.
- Либо напишите мейнтейнеру письмо с подробным описанием, шагами
  воспроизведения и диапазоном затронутых версий.
- Зашифруйте отчёт PGP, если он содержит детали эксплойта. Отпечаток
  PGP-ключа мейнтейнера будет опубликован после релиза проекта.

### Что включить

- Затронутая версия (хеш коммита для пре-релиза).
- Описание проблемы и предполагаемая модель противника.
- Шаги воспроизведения (тест-кейс, файл, последовательность вызовов API).
- Предлагаемое смягчение, если есть.

### Реакция

- Мы стремимся подтверждать получение отчётов в течение 7 дней.
- Критические проблемы (обход deniability, восстановление ключа, обход
  AEAD) получают патч и скоординированное раскрытие в течение 30 дней.
- Менее серьёзные проблемы (отказ в обслуживании, производительность,
  неэффективность формата) могут быть включены в следующий релизный цикл.

### Bug bounty (community review, без денежного вознаграждения)

Standing offer для security-researcher'ов, готовых challenge'нуть
deniability и криптографические claim'ы этого проекта:

- **В scope.** Vulnerabilities, нарушающие D1 (single-snapshot
  indistinguishability), D2 (compelled-key deniability), I1
  (per-chunk integrity), I2 (tail-corruption tolerance), I3
  (cross-space isolation), R1 (rollback resistance с anchor'ом),
  M1 (memory hygiene of keys), C1 (cancellation safety). Плюс
  любой panic-via-input, достижимый через public Rust / FFI API,
  любая memory-safety проблема в `unsafe`-блоках
  `hidden-volume-rt`, и любой flaw в signing chain'е release-
  pipeline'а.
- **Out of scope.** Всё из threat-model'а §4 «Out-of-scope
  mitigations» (multi-snapshot byte-diff, NFS / FUSE / shared-
  storage Android, CPU-level side channels, host-app data leaks).
  TM1 (open-time timing oracle) — *acknowledged-open*; конкретные
  числа, улучшающие документированную характеристику, welcome;
  re-reporting голого факта существования — нет.
- **Reward.** Credit (запись в CHANGELOG + строка в hall-of-fame
  в SECURITY.md) и early access к фиксу. **Без денежного
  вознаграждения** — budget reality. Псевдонимные reporter'ы
  явно welcome; maintainer тоже псевдонимен. Выберите любой
  handle, какой хотите в credit-line.
- **Disclosure.** Coordinated, 90-day default, fast-track для
  critical findings. Reporter, дождавшийся timeline'а и затем
  опубликовавший публичный technical write-up, фактически
  становится *external reviewer'ом* этого проекта — см.
  [`docs/ru/security/audits/self-audit.md`](docs/ru/security/audits/self-audit.md)
  §9 о том, почему этот путь здесь важен.
- **Channel.** GitHub Private Vulnerability Reporting
  (предпочтительно — end-to-end зашифровано на maintainer-ключи
  в GitHub-аккаунте, без email'а) или email-путь выше с PGP.
- **Никаких invoice'ов и контрактов.** Это community-offer, не
  service agreement. Maintainer не может оплачивать invoice'ы
  без де-анонимизации — см. dossier §1 о budget/anonymity
  rationale.

### Self-audit dossier

Почему нет внешнего платного аудита, какой процесс его замещает,
какие криптографические свойства claim'ятся, и как независимо
верифицировать каждый claim:
[`docs/ru/security/audits/self-audit.md`](docs/ru/security/audits/self-audit.md)
(EN: [`docs/en/security/audits/self-audit.md`](docs/en/security/audits/self-audit.md)).

## Проверка release-артефактов

Каждый SemVer-tagged релиз подписан workflow
[`.github/workflows/release.yml`](.github/workflows/release.yml) через
**cosign keyless** (Sigstore). Долгоживущих ключей подписи не
существует; `SHA256SUMS` каждого релиза подписан коротко­живущим
сертификатом, subject которого — OIDC-токен GitHub Actions этого
конкретного workflow-run'а, с записью подписи в публичный Rekor
transparency-log.

Быстрая проверка:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/veilnetwork/hidden-volume/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS

sha256sum --ignore-missing -c SHA256SUMS    # Linux
shasum -a 256 -c SHA256SUMS                 # macOS / BSD
```

Полная процедура (что каждая проверка доказывает, что нет, как
реагировать на провал):
[`docs/ru/contributing/verifying-release.md`](docs/ru/contributing/verifying-release.md).

## Модель угроз

Контекст того, что входит и не входит в область применения, см. в
[`DESIGN.ru.md`](DESIGN.ru.md) §1 и в разделах README «Что это защищает» /
«Что это НЕ защищает». Кратко:

**В области применения** — уязвимости, нарушающие любое из:
- D1 (неотличимость единичного снапшота)
- D2 (plausible deniability при принудительном раскрытии ключа)
- I1 (целостность каждого чанка)
- I2 (терпимость к повреждению хвоста)
- I3 (изоляция между пространствами)

**Вне области применения** (ответственность хост-приложения):
- Сайд-каналы прикладного уровня (списки недавно открытых файлов, кеши
  IME, превью-миниатюры, своп, системные логи)
- Многоснапшотный побайтовый дифф-анализ (T2'): in-place перезаписи и
  tombstones оставляют сигналы «этот байт изменился»; задокументировано
  как принятый компромисс
- Атаки отката без внешнего якоря
- Сайд-каналы уровня CPU (Spectre, MDS) — защита со стороны
  ОС/микрокода
- Криминалистические дампы RAM — защита через FDE + secure boot

## История безопасности

### Проведённые аудиты

- **v0.5 аудит memory hygiene** ([`docs/ru/security/audits/memory.md`](docs/ru/security/audits/memory.md)):
  проверена каждая аллокация ключевого материала. Найдены и исправлены
  два пути утечки (`derive_chunk_key` / `derive_subkey`, возвращавшие
  сырой `[u8; 32]`). Отложенные пункты (zeroize пользовательских
  данных) задокументированы с обоснованием.
- **v0.5 аудит constant-time** ([`docs/ru/security/audits/constant-time.md`](docs/ru/security/audits/constant-time.md)):
  проверены 17 различных мест сравнения; ни одно не оперирует
  секретными данными. Всё сравнение, касающееся секретов, находится
  внутри крейтов RustCrypto (проверка тега Poly1305, Argon2id KDF), оба
  CT by construction.
- **v0.5 аудит порядка fsync** ([`docs/ru/security/audits/fsync.md`](docs/ru/security/audits/fsync.md)):
  прослежены 7 мест fsync; все в корректных позициях. Протокол
  3-fsync-барьеров в `Space::commit_tx` соответствует `DESIGN.md` §6, а
  заявления о crash-safety валидированы 8 сценариями усечения в
  `tests/crash_recovery.rs`. Проблем не найдено.
- **Audit pass 16 (2026-05-09) — R-STREAMING-REPACK + TM1 + R-FFI-PWD-Z**:
  закрыты три pass-14 roadmap-пункта в одном коммите.
  `Container::repack` переписан как streaming-pipeline (working-set
  ≈ 4 МиБ на страницу, было O(total plaintext) — multi-GiB
  log-namespaces больше не OOM'ят хост). Новый `MAX_OPEN_SCAN_CHUNKS
  = 16M` (≈ 64 ГиБ) cap на open-scan, ограничивающий DoS через
  раздутие файла T2-противником. FFI password-буферы обёрнуты в
  `Zeroizing` на каждой точке входа (`SpaceHandle::{create,open}`,
  `AsyncSpaceHandle::{create,open}`, `compact_known`,
  `change_passwords`). 387 тестов проходят.
- **Audit pass 17 (2026-05-09) — security/quality follow-through**:
  новый `Error::ContainerTooLarge` variant + симметричный write-side
  `MAX_OPEN_SCAN_CHUNKS` gate (закрывает create-then-can't-reopen
  footgun). `Container::open_space_verified` отсрочил auto-vacuum
  до успешного `verify_integrity` (сохраняет гарантию «no observable
  mutation on verify failure»). `PaddingPolicy::garbage_after_commit`
  возвращает `Result<u64>` (extreme-input арифметика теперь
  surface'ится как `Error::Internal` вместо panic / silent wrap).
  `Space::iter_log_after / before / range` строго отвергает
  не-8-байтовые ключи (теперь возвращает `Error::WrongNamespaceKind`
  вместо silent skip). `hidden-volume-async::AsyncSpace::create /
  open` и CLI `hv` password-буферы обёрнуты в `Zeroizing`.
  `PasswordRotation` больше не деривит `Clone` (defense-in-depth
  против случайного обхода pass-16 zeroizing-flow). `unreachable!()`
  в decode-путях `space/index.rs` заменён на `Err(Error::Internal)`.
  MSRV 1.85 → 1.89. **389 тестов проходят.**

### Исправленные уязвимости

Пока ничего не опубликовано — этот раздел будет содержать CVE /
advisory после выхода проекта на v1.0.

### Запланированные аудиты

- Внешний криптографический ревью (Trail of Bits / Cure53 / NCC) до
  заморозки v1.0. Отслеживается в [`TASKS.md`](TASKS.md), milestone v1.0.
- Fuzzing-кампания (`cargo-fuzz`, как только появится CI-инфраструктура
  для многочасовых прогонов).

## Supply-chain — принятые advisory

CI прогоняет `cargo audit` и `cargo deny check` на каждом tagged
release'е и на manual workflow-dispatch (см.
[`.github/workflows/ci.yml`](.github/workflows/ci.yml); branch-push и
PR с 2026-05-09 больше не триггерят CI — локальные вызовы
`cargo audit` / `cargo deny check` теперь pre-tag gate). Один advisory
класса `unmaintained` явно игнорируется в [`deny.toml`](deny.toml); это
compile-time-only транзитивная зависимость proc-macro toolchain'а
`uniffi 0.31`. Он не попадает в runtime-код отгружаемой
библиотеки.

| Advisory | Крейт | Почему игнор | Путь устранения |
|---|---|---|---|
| [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436) | `paste 1.0.15` | Автор архивировал репозиторий `paste`. Транзитивная compile-time зависимость `uniffi_bindgen` и `uniffi_core`; используется при раскрытии proc-macro для конкатенации идентификаторов (без runtime-эффекта). Community drop-in замена — [`pastey`](https://crates.io/crates/pastey), source-совместимая. | Gate на миграцию uniffi с `paste` на поддерживаемую альтернативу (R-DEPS в `TASKS.md`). |

> `RUSTSEC-2025-0141` (`bincode 1.3.3`) ранее игнорировался здесь, но
> был удалён после перехода workspace на `uniffi 0.31`, который заменил
> bincode на `postcard` — bincode больше нет в дереве зависимостей.

**Нет runtime-exposure.** Этот крейт участвует только в code generation,
которая работает во время `cargo build` proc-macro consumer'а
`hidden-volume-ffi`. Его скомпилированный код отсутствует в отгружаемой
`libhidden_volume_ffi.{so,dylib,dll}`. Атакующему пришлось бы
subvert'нуть compiler toolchain build-хоста — это out-of-scope (покрыто
host trust в
[`docs/ru/security/threat-model.md`](docs/ru/security/threat-model.md) §2 out-of-scope).

**Триггер пересмотра.** Когда `uniffi` отгрузит ≥ 0.29, оба ignore'а
должны быть переоценены, а версия бампнута в том же commit'е, который
их удаляет. CI `cargo deny check` упадёт громко, если advisory всё ещё
процитирован, но соответствующего крейта в `Cargo.lock` уже нет —
предотвращая накопление stale ignore-политики.
