# Аудит утечек plaintext

[🇬🇧 English](../../../en/security/audits/plaintext.md) · 🇷🇺 **Русский**

**Статус:** первый проход v0.5 завершён. Все transient pre/post-
encryption буферы обёрнуты в `Zeroizing`; долгоживущие user-data
буферы явно отложены (cross-reference в [`memory.md`](memory.md)).

Этот документ дополняет [`memory.md`](memory.md). Memory-hygiene аудит
фокусируется на lifetime'ах **key material**; этот аудит фокусируется
на **plaintext-данных** — байтах, которые только что были (или
вот-вот будут) AEAD-decrypted / AEAD-sealed и которые кратковременно
живут в heap или stack-памяти.

Адресуемая угроза: memory-disclosure adversary (allocator reuse,
swap-страницы, /dev/mem на скомпрометированном хосте), который
читает освобождённые регионы вскоре после того, как библиотека
закончила chunk read или write. Per-chunk keys уже zeroized
(memory audit §A); plaintext — следующий слой.

## Методология

1. Перечислить каждый code-path, где plaintext-байты существуют
   между AEAD open/seal и границей функции.
2. Классифицировать по lifetime:
   - **Transient** — буфер живёт только внутри обёрточной функции
     encrypt или decrypt; после её возврата байты больше недостижимы
     ни через какую owned-ссылку.
   - **User-owned** — буфер создан из / передан в user-код;
     lifetime диктуется caller'ом, не библиотекой.
3. Для transient-буферов оборачивать в `zeroize::Zeroizing`, чтобы
   heap-регион scrub'ился во время drop.
4. Для user-owned буферов задокументировать откладывание и сделать
   cross-reference на [`memory.md`](memory.md) §C.

## Transient plaintext-сайты — обёрнуты ✓

| Сайт | Буфер | Тип | Lifetime |
|---|---|---|---|
| `crypto::aead::ChunkAead::open` (return value) | полный декодированный chunk-plaintext | `Zeroizing<Vec<u8>>` | один chunk read; drop в конце read-fn caller'а |
| `space::Space::append_chunk` (`pt_bytes`) | encoded `Plaintext` (`[u8; PLAINTEXT_LEN]`) до seal | `Zeroizing<[u8; PLAINTEXT_LEN]>` | один chunk write; drop в конце fn |
| `space::log::encode_batch` (`raw`) | сконкатенированные record-байты до zstd | `Zeroizing<Vec<u8>>` | передаётся в zstd, затем drop |
| `space::log::decode_batch` (`raw`) | zstd-декомпрессованные record-байты | `Zeroizing<Vec<u8>>` | пройден один раз для slice'а per-record `payload`, затем drop |
| `space::Space::write_tree_for_namespace` (single-leaf `bytes`) | output `LeafNode::encode()` до AEAD seal | `Zeroizing<Vec<u8>>` | передаётся в `append_chunk`, затем drop |
| `space::Space::write_tree_for_namespace` (per-leaf `bytes` в split) | output `LeafNode::encode()` | `Zeroizing<Vec<u8>>` | передаётся в `append_chunk`, затем drop |
| `space::Space::write_tree_for_namespace` (`internal` `bytes`) | output `InternalNode::encode()` (несёт user `first_key` байты) | `Zeroizing<Vec<u8>>` | передаётся в `append_chunk`, затем drop |

Косвенно (уже покрыто upstream RustCrypto):

| Сайт | Буфер | Механизм |
|---|---|---|
| `chacha20poly1305::XChaCha20Poly1305` внутренний scratch | per-call cipher state | крейты `chacha20` и `aead` имплементят `ZeroizeOnDrop` для cipher state |
| Per-slot AEAD key, переданный в `ChunkAead::new` | `[u8; 32]` | `derive_chunk_key` возвращает `Zeroizing<[u8; 32]>` — wipe'ается после конструирования `ChunkAead` |

## User-owned plaintext-сайты — отложено (host-app контролирует)

Это буферы, которые библиотека производит или принимает в рамках
своего публичного API. Оборачивание их в `Zeroizing` изменило бы
публичные сигнатуры и заставило бы каждый host-app адоптировать
обёртку или сражаться с type errors. Соотношение цена/выгода
неблагоприятно для v0.5; угроза реальна, но вторична (тот же
memory-disclosure adversary имеет доступ к UI-буферам host-app, IME-
кешам и т.д., где user-data тоже живёт).

| Сайт | Буфер | Причина откладывания |
|---|---|---|
| `Plaintext.payload: Vec<u8>` | декодированный chunk payload | Поля используются повсеместно через `space/`, `tx/`, `chunk/`; форсило бы `Zeroizing<Vec<u8>>` через `Plaintext::decode` и поломало бы тестовые assertion'ы на equality с raw `Vec<u8>`. Полный pre-decode буфер (return `aead.open`) ОБЁРНУТ, поэтому более широкий plaintext уже scrub'ится; только этот `to_vec()`-копированный subrange ускользает. |
| `Space::get(...) -> Vec<u8>` return | KV-значение, переданное caller'у | Библиотека не может диктовать lifetime хранения host-app. |
| `Space::list / iter_log / read_log` returns | KV / log records, переданные caller'у | То же. |
| `log::decode_batch` возвращаемый `Vec<(u64, Vec<u8>)>` per-record `payload` | per-record plaintext, скопированный из обёрнутого `raw` буфера | Так же как `Plaintext.payload` — копированный subrange ускользает. |

## Внутренние копии — закрыто через `Redacted<T>` (аудит HV-01 / HV-07)

Три откладывания выше (`Tx::pending_kv`, `Tx::pending_log`,
`IndexNode::Leaf.entries`) закрыты. Newtype `SecretVec`, который этот
документ называл кандидатом на v0.5.x, теперь существует как
[`redact::Redacted<T>`](../../../../crates/hidden-volume/src/redact.rs): он
`Deref`'ится в `T`, поэтому места чтения и мутации не изменились, и делает
сверх этого две вещи.

| Поле | Теперь | Scrub'ится когда |
|---|---|---|
| `Tx::pending_kv` | `Redacted<PendingKv>` | `commit_tx` возвращает управление — и на успехе, и на ошибке, так как обёртка перемещена в него |
| `Tx::pending_log` | `Redacted<PendingLog>` | то же, плюс per-namespace переобёртывание внутри drain'а Phase 0 |
| `LeafNode::entries` | `Redacted<Vec<(Vec<u8>, Vec<u8>)>>` | декодированный узел дропается |
| `ChildPointer::first_key` | `Redacted<Vec<u8>>` | то же |
| `SpaceState::roots_payload_cache` | `Option<(u64, Redacted<Vec<u8>>)>` | заканчивается commit-эра (был `Zeroizing` — он scrub'ит, но не редактирует) |

**Что именно это обещает.** *Внутренние* копии расшифрованного ключа,
значения или payload'а не переживают операцию, которая их построила. Это
**не** утверждение, что plaintext исчез из процесса: `Vec`, выросший при
построении, оставил позади прежнюю аллокацию, значение, которое API
*возвращает*, принадлежит вызывающему, а через UniFFI оно копируется в
чужую кучу, которой этот крейт не видит. Всё это по-прежнему на host-app,
и рекомендация `mlock` + hardened-аллокатор ниже остаётся ответом для них.

## Форматирование — второй класс утечки (аудит HV-01)

`Zeroizing` scrub'ит на drop и ничего не говорит про `{:?}` — upstream-крейт
*выводит* `Debug` на нём, поэтому `Zeroizing<Vec<u8>>` печатает свои байты
дословно. Редакция — отдельный механизм, а не побочный эффект зануления, и
её обеспечивают два правила:

1. Поле, несущее plaintext, имеет тип `Redacted<T>`, чей `Debug` печатает
   `{ items, bytes }` и никогда содержимое. Безопасно под
   `#[derive(Debug)]`, безопасно при печати само по себе, безопасно если
   будущий автор внесёт его в `debug_struct`.
2. `Debug` его контейнера написан allow-list-макросом `redacted_debug!` и
   заканчивается `finish_non_exhaustive()`, поэтому добавленное позже поле
   не печатается вообще, пока кто-то его явно не назовёт.

Первого правила в одиночку и не хватило прошлому проходу: он отредактировал
`KvOp`, `WriteOp`, `LogEntry` и `Plaintext`, а `Tx`, `LeafNode`,
`ChildPointer`, `SpaceState` и `Space` оставил выводить `Debug` поверх них.
Второе правило — то, что делает *новое* поле безопасным без чьей-либо
памяти. Sentinel — `tests/debug_redaction.rs`.

**Рекомендация для host-apps, которым нужны более сильные гарантии.**
Запускать весь процесс под `mlock` + private memory mapping +
hardened-аллокатор (например, `secret-allocator`). Это защищает UI
state, swap и library state единообразно, без per-API plumbing.

## Почему мы оборачиваем transient-буферы, но не user-owned

Оборачивание transient-буфера **невидимо для публичного API**: caller'ы
`aead.open` видят auto-deref `Zeroizing<Vec<u8>>` в `Vec<u8>` в
`&[u8]`; ничего не ломается. Оборачивание user-owned буфера — это
**breaking change публичного API**, которое пропагируется каждому
caller'у и cargo-cult копируется по host-apps вне зависимости от того,
нужна ли им эта гарантия фактически.

Асимметрия: transient-обёртки — чистая победа (one-line change, scrub
on drop, no API surface impact). User-owned обёртки — это tradeoff,
и они должны идти за спросом от конкретных host-apps с конкретными
threat-моделями. Откладывать до тех пор, пока v0.5.x не получит хотя
бы один host-app, который драйвит требование.

## Stack vs. heap

- **Heap** (`Vec<u8>`): freed-страницы могут быть переаллоцированы для
  несвязанных данных. `Zeroizing<Vec<u8>>` перезаписывает содержимое
  в деструкторе до возврата аллокации. ✓
- **Stack** (`[u8; PLAINTEXT_LEN]` в `append_chunk`): stack frame
  переиспользуется на следующем function-call'е без scrub'а по
  умолчанию. `Zeroizing<[u8; N]>` запускает `Zeroize for [T; N]`
  (с `zeroize` 1.6) на drop, scrub'я stack-регион. ✓

Компилятору позволено оптимизировать dead writes — крейт `zeroize`
защищается от этого через `#[inline(never)]` + volatile writes в impl.
Мы полагаемся на эту гарантию; она держится в audit-истории крейта.

## Out-of-scope для этого аудита

- **Compiler-optimized stack scratch** в криптографических примитивах
  (например, ChaCha20 round state). RustCrypto это обрабатывает; мы
  не лезем во внутренности `chacha20poly1305`.
- **CPU register spills** plaintext-байт во время AEAD-операций.
  Защищено только на уровне CPU microcode / OS-context-switch.
- **Compiler reordering zeroize-записей**. `zeroize` использует
  `core::ptr::write_volatile` для предотвращения этого; мы доверяем крейту.

## Журнал аудита

| Дата | Изменение | Ревьюер |
|---|---|---|
| аудит HV-01 / HV-07 | Закрыты откладывания `Tx::pending_kv` / `Tx::pending_log` / `LeafNode::entries` через `redact::Redacted<T>`, распространено на `ChildPointer::first_key` и `SpaceState::roots_payload_cache`, редакция отделена от зануления (`Zeroizing` выводит `Debug`). Добавлен `tests/debug_redaction.rs`. | Self-audit |
| Initial v0.5 | Первый проход. Обёрнуто 7 transient plaintext-сайтов (1 в `aead`, 1 в `space::append_chunk`, 2 в `space::log`, 3 в `space::write_tree_for_namespace`). Задокументировано 7 user-owned сайтов как отложенных с cross-ref на [`memory.md`](memory.md) §C. Добавлен `tests/plaintext_hygiene.rs` для type-level регрессионных проверок. | Self-audit |

## Cross-references

- `docs/ru/security/threat-model.md` §3 (M1 invariant) — формальная формулировка, которую этот проход аудита поддерживает
- `docs/ru/security/audits/memory.md` §C — пересекающиеся откладывания для user-data Vec'ов
- `docs/ru/security/audits/constant-time.md` — проход constant-time (companion-аудит)
- `docs/ru/security/audits/fsync.md` — проход fsync ordering (companion-аудит)
- `tests/memory_hygiene.rs` — type-level регрессия для derived keys
- `tests/plaintext_hygiene.rs` — type-level регрессия для plaintext-обёрток
- `tests/debug_redaction.rs` — sentinel для контракта редакции `Debug`
