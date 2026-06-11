# Безопасность — модель угроз + аудиты

[🇬🇧 English](../../en/security/README.md) · [🇷🇺 Русский](README.md)

Модель угроз и четыре v0.5 hardening-аудита. Сначала читайте
модель угроз, чтобы понять security-postьu; аудиты — это
доказательство того, что реализация соответствует модели.

## Документы

- **[threat-model.md](threat-model.md)** — формальная модель угроз.
  Возможности противника (T0 пассивное чтение, T1 single-snapshot,
  T2 file-write tamper, T2' multi-snapshot diff, T3 принуждённый
  ключ), что в scope / out-of-scope, и mitigations по каждому
  классу атак.

### Аудиты ([audits/](audits/))

- **[self-audit.md](audits/self-audit.md)** — dossier (2026-05-28).
  Почему нет внешнего платного аудита (анонимность + no-budget),
  какой процесс его замещает, каждое cryptographic property
  statement с code references и как независимо верифицировать
  каждый claim. Это документ, который посылают любому, кто
  спрашивает «было ли audited».
- **[adversarial-stance.md](audits/adversarial-stance.md)** — pass 1
  серии deeper-review (2026-05-28). Inverted-stance аудит: ~34
  попытки атак против D1/D2/I1/I2/I3/R1/M1/C1, с verdict'ами
  (defended / acknowledged-out-of-scope / mitigation-tracked). Ноль
  critical/high/medium находок; одна LOW (собственная «64-byte»
  doc-inconsistency dossier'а, пофикшена в том же коммите).
- **[primitive-level.md](audits/primitive-level.md)** — pass 2
  серии deeper-review (2026-05-28). Challenge'ит *выборы
  криптографических примитивов* (Argon2id / XChaCha20-Poly1305 /
  BLAKE3 / `getrandom` / `zeroize` / `subtle`) против литературы
  2026 (OWASP, NIST, RFC 9106/8439, CFRG). Две LOW находки:
  P-LOW1 (Argon2Params::MIN m_cost ниже OWASP low-end — rustdoc
  warning применён) и P-LOW2 (label-length domain-separation
  convention — defense-in-depth opportunity для v3 format bump).
- **[side-channel-surface.md](audits/side-channel-surface.md)** —
  pass 3 серии deeper-review (2026-05-28). Картографирует
  каждый non-TM1 side channel (timing, memory, filesystem,
  logging, microarchitectural) к: defended / acknowledged-out-
  of-scope / defense-in-depth opportunity. Ноль
  critical/high/medium/low находок; 2 INFO (SC-INFO1
  constant-time decode pass для key-holder-self-DoS; SC-INFO2
  TM1 bench должен покрывать parallel + mmap variants).
- **[format-fuzzing.md](audits/format-fuzzing.md)** — pass 4
  серии deeper-review (2026-05-28). Формальная boundary-
  enumeration каждой публичной `decode` entry-точки (9
  decoder'ов + 2 discriminator-parsers), каждая замаплена к
  своей defending code line и к конкретному fuzz / proptest
  тесту, который её упражняет. Ноль uncovered boundary-
  классов; 1 INFO (FZ-INFO1 re: CI-failure-on-fuzz-finding
  gate, сейчас continue-on-error by design).
- **[threat-model-challenge.md](audits/threat-model-challenge.md)**
  — pass 5 (финальный) серии deeper-review (2026-05-28).
  Narrative-stance: 7 step-by-step scenario'ев (border
  seizure, snapshot diff, compelled-password disclosure,
  malicious host-app, kernel-level observer, multi-stage
  cumulative, multi-device), проходящих через то, что
  каждый named adversary узнаёт на каждом этапе. Ноль new
  findings; подтверждает analytical-results из passes 1-4 в
  narrative-форме. Включает cross-series carried-forward
  action list.

Все четыре аудита были проведены в рамках v0.5 hardening pass и
ратифицированы до любых соображений о v1.0 freeze.

- **[constant-time.md](audits/constant-time.md)** — каждое сравнение
  `==` / `!=` классифицировано. **Constant-time проблем не
  найдено.** Документирует, какие сравнения на публичных значениях
  (OK, могут быть data-dependent), а какие на ключевом/тэг-материале
  (должны быть `subtle::ct_eq`).
- **[fsync.md](audits/fsync.md)** — аудит 3-fsync протокола
  коммита. Каждый барьер в `Space::commit_tx` соответствует
  протоколу DESIGN §6; порядок верифицируется в crash-recovery
  тестах.
- **[memory.md](audits/memory.md)** — zeroize-покрытие на каждом
  секретном типе. Master-ключи, derived-subkeys, AEAD-теги, байты
  паролей — всё обёрнуто в `Zeroizing<...>` или
  `#[derive(ZeroizeOnDrop)]`.
- **[plaintext.md](audits/plaintext.md)** — транзитные буферы до и
  после шифрования. Проверяет, что plaintext не задерживается в
  промежуточных аллокациях `Vec<u8>` после завершения AEAD seal.

## Сообщить об уязвимости

Политика disclosure — в [`../../../SECURITY.md`](../../../SECURITY.md).
