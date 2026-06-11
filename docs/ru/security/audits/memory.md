# Аудит memory hygiene

[🇬🇧 English](../../../en/security/audits/memory.md) · 🇷🇺 **Русский**

**Статус:** проход аудита v0.5 завершён. Находки + решения ниже.

Этот документ отслеживает каждое место в крейте, где key material или
байты user-secret находятся в памяти, применённую гигиену и любые
отложенные решения. Обновлять при каждом изменении модулей crypto /
space / tx.

## Методология

- Grep по фиксированным массивам ключевой длины (`[u8; 32]`, `[u8; 24]`,
  `[u8; 16]`).
- Grep по `Vec<u8>`, несущим пользовательские данные (KV-значения,
  log payload'ы, декодированные plaintext'ы).
- Trace lifetime: где аллоцируется, в каком scope, когда drop'ается,
  scrub'ятся ли байты до того, как heap-регион освобождён.
- Различать: **secret material** (zeroize обязателен) vs **public
  material** (без обязательств; например, container_id, salt, BLAKE3 хеши).

## Находки (текущее состояние)

### A. Key material — zeroized ✓

| Объект | Локация | Механизм |
|---|---|---|
| Argon2-derived master key | `derive_master_key` return | `Zeroizing<[u8; 32]>` |
| `SpaceKeys.aead_root` | `crypto/derive.rs` | `#[derive(ZeroizeOnDrop)]` на структуре (2026-05-02: поля `master` и `kdf` не использовались — удалены как dead code) |
| `SpaceState.keys` | `space/mod.rs` | пропагирован `SpaceKeys` |
| Per-slot AEAD key | `derive_chunk_key` return | `Zeroizing<[u8; 32]>` (исправлено в этом аудите) |
| BLAKE3 keyed-hash subkey | `derive_subkey` return | `Zeroizing<[u8; 32]>` (исправлено в этом аудите) |
| `XChaCha20Poly1305` cipher state | внутри `ChunkAead` | `Zeroize` impl на cipher state RustCrypto — автоматически через `ZeroizeOnDrop` крейта `cipher` (для этой версии крейта явный feature gate не нужен) |
| Внутренний буфер `key32` в `derive_subkey` | `crypto/derive.rs:42` | `Zeroizing<[u8; 32]>` (был вызов `.zeroize()`; теперь чище) |

### B. Public material — без обязательств ✓

| Объект | Почему не secret |
|---|---|
| `container_id` (`[u8; 32]`) | Хранится в открытом виде в header; служит AAD-префиксом |
| Container salt (`[u8; 32]`) | Хранится в открытом виде в header |
| Argon2 params (`u32 × 4`) | Хранятся в открытом виде в header |
| Per-record `payload_hash` (BLAKE3) | Хеш уже зашифрованного ciphertext; ничего не раскрывает |
| `Superblock.root_hash` | То же |
| `IndexRoot.payload_hash` | То же |
| `ChildPointer.child_hash` | То же |
| AEAD nonce (`[u8; 24]`) | Random per-write; OK хранить |
| AEAD AAD (`[u8; 40]`) | `container_id || slot` — оба публичны |

### C. User-secret data — НЕ zeroized (отложено)

**См. также `docs/en/security/audits/plaintext.md`** — отдельный проход
аудита по transient plaintext-буферам (байты, кратковременно
существующие между AEAD seal/open и следующей передачей). Тот аудит
дополняет §C ниже: *transient* pre/post-encryption plaintext-буферы
ОБЁРНУТЫ в `Zeroizing` (например, return `aead.open`,
`log::encode_batch`/`decode_batch` raw, encoded leaf bytes до seal);
*user-owned* Vec'и, перечисленные ниже, остаются отложены.

| Объект | Риск | Решение |
|---|---|---|
| `Tx.pending_kv: BTreeMap<u8, Vec<KvOp>>` value bytes | KV-значения держатся в памяти до commit | **Отложено:** обернуть каждый `Vec<u8>` в `Zeroizing<Vec<u8>>` инвазивно через весь stack. Байты шифруются в chunk-plaintext, и оригинальный `Vec<u8>` drop'ается без scrub'а. |
| `Tx.pending_log` payload'ы | То же | То же |
| `Plaintext.payload: Vec<u8>` | Декодированный chunk-plaintext при чтении; живёт до function-scope drop | **Отложено:** то же. |
| Compressed batch `raw` буфер в `log::encode_batch` | Pre-zstd plaintext | **Отложено.** `Vec<u8>` drop'ается без scrub'а. |
| Decompressed batch `raw` в `log::decode_batch` | То же | **Отложено.** |
| Encoded `IndexNode` payload до шифрования | `Vec<u8>` | **Отложено.** |
| `IndexNodePayload.entries` `Vec<(Vec<u8>, Vec<u8>)>` | Декодированные KV-записи | **Отложено.** |

**Обоснование откладывания zeroize для user-data.** Добавление
`Zeroizing<Vec<u8>>` или newtype `SecretVec` через все KV/log пути
затрагивает ~40 call site'ов. Угроза, которую это адресует
(memory-disclosure атакующий, читающий освобождённые heap-страницы),
реальна, но вторична — тот же атакующий мог бы прочитать plaintext,
пока Tx ещё жив в памяти, или прочитать его из render-пути в host-app.
Митигация имеет высокую инвазивность и скромную выгоду; tracking
как кандидат v0.5.x.

Для host-apps, которым НУЖНА устойчивость к memory-disclosure,
рекомендуемый подход — OS-level mlock + private memory mapping для
всего процесса app, что защищает всё, включая UI state.

## Верификация

Библиотека имеет автоматизированные регрессионные тесты для гарантий
type-level (см. `tests/memory_hygiene.rs`):

- `derive_chunk_key` возвращает `Zeroizing<[u8; 32]>` (compile-time check)
- `derive_subkey` возвращает `Zeroizing<[u8; 32]>`
- `derive_master_key` возвращает `Result<Zeroizing<[u8; 32]>>`
- `SpaceKeys` реализует `ZeroizeOnDrop`
- Сигнатуры выше не могут регрессировать без поломки этих тестов.

Runtime zeroing stack-памяти напрямую не наблюдаем в safe Rust;
полагаемся на аккуратную inline-asm-based реализацию крейта `zeroize`,
которую компилятор не оптимизирует (`#[inline(never)]` + volatile
writes).

## Out-of-scope для этого аудита

- **Утечки heap через переиспользование аллокатором.** После того,
  как `Vec<u8>` drop'нут, освобождённые страницы могут быть
  переаллоцированы для несвязанных данных. Последующий процесс,
  читающий эти страницы (через /dev/mem на Linux или post-mortem
  swap-анализ), может найти старый plaintext. Митигация требует
  привилегированной OS-level изоляции, не работы уровня библиотеки.
- **CPU side channels.** Атаки класса Spectre, читающие kernel/cipher
  state из speculative execution. Защищено только на уровне OS / CPU
  microcode.
- **Forensic RAM dumps.** Cold-boot-атаки. Защищено только full-disk
  encryption + secure boot; не забота библиотеки.

## Журнал аудита

| Дата | Изменение | Ревьюер |
|---|---|---|
| Initial v0.5 | Первый проход. Исправлены `derive_chunk_key` и `derive_subkey` для возврата `Zeroizing<[u8; 32]>`. Задокументирован отложенный zeroize для user-data. | Self-audit |
