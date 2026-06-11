# Аудит constant-time

[🇬🇧 English](../../../en/security/audits/constant-time.md) · 🇷🇺 **Русский**

**Статус:** первый проход v0.5 завершён. **Проблем constant-time не обнаружено.**

Этот документ фиксирует методологию и находки аудита constant-time
(CT) в `hidden-volume`. Обновлять при каждом изменении модуля
`crypto/` или любого кода, работающего с паролем / key material.

## Методология

Timing side-channel возникает, когда длительность сравнения или ветвления
по wall-clock зависит от секрета. Мы grep'нули каждый оператор `==` / `!=`
в `src/`, классифицировали по тому, что сравнивается, и задались вопросом:

  > Может ли атакующий, который **не находится внутри процесса**, наблюдать
  > этот тайминг И извлечь из него что-то полезное?

Если да → использовать `subtle::ConstantTimeEq`. Если нет → обычный `==` подходит.

## Область применения (где CT действительно важен)

Три конкретных вектора атак, против которых защищают CT-сравнения:

1. **Верификация пароля.** Сравнение хранимого хеша пароля с попыткой,
   присланной пользователем. `hidden-volume` НЕ хранит хеши паролей —
   пароли проходят через Argon2id, результат — это ключ, ключ
   используется для AEAD-decrypt, и проверка AEAD tag и есть сигнал
   pass/fail. **В нашем коде нет сравнения хешей паролей.**

2. **Верификация AEAD authentication tag.** Не-CT сравнение tag
   позволило бы атакующему подделывать ciphertext побайтно через
   тайминг. `hidden-volume` НЕ сравнивает tag напрямую — это
   делегируется `chacha20poly1305::XChaCha20Poly1305::decrypt`,
   который внутри использует CT-сравнение (Poly1305 by construction).

3. **Сравнения хешей секретов.** Сравнение `H(secret)` побайтно с
   ожидаемым значением может утекать совпадения префиксов.
   `hidden-volume` использует BLAKE3 хеши как integrity tag на
   **уже зашифрованных** chunk'ах; хешируемые байты — это публичный
   ciphertext + AAD. **Хеш plaintext-секрета не сравнивается.**

Коротко: каждое чувствительное сравнение в этом крейте происходит внутри
крейтов `chacha20poly1305` и `argon2` от RustCrypto, оба constant-time
by design. **В нашем собственном коде нет CT-сравнения, которое
закрывало бы timing-канал.**

## Аудит сравнение-за-сравнением

Каждый оператор `==` и `!=` в `src/` (на момент аудита):

| Сравнение | Операнды | Чувствительность | Вердикт |
|---|---|---|---|
| `params.version != PARAMS_VERSION` | u32 vs u32 | публичные параметры | OK |
| `salt.len() != HEADER_SALT_LEN` | usize vs usize | длина | OK |
| `pt.kind == ChunkKind::Superblock` | enum vs enum | discriminant (публичный type tag) | OK |
| `pt.kind != ChunkKind::DataBatch` | то же | то же | OK |
| `pt.kind != ChunkKind::Commit` | то же | то же | OK |
| `pt.kind != ChunkKind::IndexNode` | то же | то же | OK |
| `key.len() != 8` | проверка длины | публично | OK |
| `r.namespace == ns` | u8 newtype | namespace tag (публичный) | OK |
| `root_slot == NO_RECORD` | u64 vs sentinel | slot index (публичный) | OK |
| `len % CHUNK_SIZE as u64 != 0` | u64 modulo | размер файла (публично) | OK |
| `bytes[0] != NODE_TYPE_LEAF / INTERNAL` | u8 байт | type tag (публично) | OK |
| `klen == 0`, `klen > MAX_KEY_LEN` | u16 | границы длины | OK |
| `buf[0..4] != MAGIC` | байты vs константа | magic-байты публичны | OK |
| `namespace == Namespace::RESERVED` | u8 vs sentinel | публично | OK |
| `*id == log_id` (в `find_in_batch`) | u64 vs u64 | log_id передаёт caller (он его уже знает) | OK |
| `value.len() != 8` | длина | OK |
| `source == dest` | path | filesystem identity, публично | OK |

Никакое сравнение не происходит над:
- сырым key material (`SpaceKeys.aead_root` — поля `master` и `kdf`
  удалены при чистке 2026-05-02 как dead code; только `aead_root`
  потребляется `derive_chunk_key`)
- per-chunk derived keys
- AEAD tag
- байтами пароля
- hash output'ами над plaintext-secret данными

## Defense-in-depth: где безопасно добавлять CT

Если когда-нибудь захотим defense-in-depth (на случай, если будущее
изменение введёт чувствительное сравнение), модуль [`crate::crypto::ct`]
предоставляет хелперы поверх [`subtle::ConstantTimeEq`]:

```rust
use hidden_volume::crypto::ct;
let same = ct::eq_32(&hash_a, &hash_b);
let same_slice = ct::eq_slice(&buf_a, &buf_b);
```

Они компилируются в тот же код, что и `==`, но через volatile-write
трюки `subtle` сравнение не может быть short-circuit'нуто компилятором.

## Что этот аудит НЕ покрывает

- **Тайминг Argon2id.** Сам KDF timing-stable в реализации RustCrypto;
  мы доверяем их аудиту. Быстрый пароль выводится так же, как и медленный.
- **Тайминг AEAD decrypt полных chunk'ов.** ~5 µs на 4 KiB chunk; не
  варьируется по корректности ключа в пределах нескольких бит —
  chacha20poly1305 всегда обрабатывает полный блок, а проверка tag
  в конце CT.
- **Тайминг BLAKE3 keyed-hash.** Время выхода зависит только от длины
  входа, не от содержимого ключа. RustCrypto blake3 — CT.
- **Side-channel'ы уровня CPU** (Spectre, MDS, BHB). Защищены на
  уровне OS / CPU microcode, не CT-сравнениями уровня библиотеки.
- **Cache timing на паттернах доступа к памяти** (например, обход
  B+ tree может раскрыть, какой ключ искали, через паттерны cache hit/miss).
  Не применимо к workload'ам мессенджера на локальном хранилище —
  атакующий не может тайминговать это извне процесса. Для сетевого
  кода история другая и она вне области аудита.

## Журнал аудита

| Дата | Изменение | Ревьюер |
|---|---|---|
| Initial v0.5 | Первый проход. Проаудировано 17 различных сравнений в `src/`; ни одно не оперирует секретными данными. Codebase CT-safe в силу делегирования всех secret-touching операций крейтам RustCrypto. Добавлен placeholder-модуль `crypto::ct` для forward-compatible CT-хелперов. | Self-audit |
