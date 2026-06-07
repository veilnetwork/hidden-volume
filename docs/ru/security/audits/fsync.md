# Аудит fsync ordering

[🇬🇧 English](../../../en/security/audits/fsync.md) · 🇷🇺 **Русский**

**Статус:** первый проход v0.5 завершён. **Все barrier'ы на месте;
проблем не обнаружено.**

Этот документ трассирует каждый вызов `fsync` через codebase, проверяет
инварианты ordering, задокументированные в `DESIGN.md` §6 / `src/tx/mod.rs`,
и фиксирует анализ failure-mode. Обновлять при каждом изменении
`commit_tx`, `vacuum_orphans` или любого пути, который пишет chunk'и.

## Методология

`grep -rn "fsync\|sync_all" src/`. Каждое место вызова классифицировано по:

  - Какие запись(и) ему предшествовали
  - Какой инвариант оно устанавливает
  - Что значит для crash-safety, если вызов пропущен или out of order

`File::sync_all()` — это базовый syscall. На Linux это `fsync(2)`
(и data, и metadata). На macOS — `fsync(2)` (важно: macOS `fsync` по
умолчанию НЕ flush'ит disk write cache; для более сильной durability
нужен `F_FULLFSYNC` — это забота host-app, см. §3 ниже).

## Инвентарь fsync-сайтов

| Сайт | Что было записано | Установленный инвариант |
|---|---|---|
| `ContainerFile::create` | 1 header chunk | header durable до того, как может начаться создание space |
| `Container::create_with_options` (после initial-garbage) | 0..N garbage chunks | initial decoy size durable до того, как app увидит "ready" контейнер |
| `Space::create` (после initial Superblock replicas) | N SB chunks | initial Superblock space видим после того, как Container::create_space вернёт Ok |
| `Space::commit_tx` Barrier 1 (после Phase 0/1) | DataBatch + IndexNode chunks для этого Tx | data durable до того, как ссылающийся Commit будет записан |
| `Space::commit_tx` Barrier 2 (после Commit) | Commit chunk | "intent" durable до того, как Superblock будет записан |
| `Space::commit_tx` Barrier 3 (после Superblock replicas) | N новых SB chunks | новое состояние видимо — recovery выбирает max-seq SB, которым теперь является этот |
| `Space::commit_tx` (после padding, условно) | 0..(bucket-1) garbage chunks | post-commit padding durable; следующее измерение размера файла наблюдателем отражает bucket |
| `Space::vacuum_orphans` (условно, после scrub) | 0..N scrubbed slots | orphan IndexNode'ы перезаписаны random; scrub durable после возврата функции с Ok |

Итого: **7 различных fsync-сайтов**, из которых **3 — безусловные barrier'ы
в `commit_tx`** (соответствует задокументированному протоколу "3-fsync barrier").

## Trace ordering для Tx::commit

Это критический путь. Walk-through:

```text
Tx::commit
  └── Space::commit_tx
       │
       │  -- Phase 0: log → DataBatch chunks --
       │  for each log namespace with pending appends:
       │    encode_batch(zstd) → bytes
       │    append_chunk(DataBatch, bytes)        ◄── extends file
       │    record batch_slot in pending_kv
       │
       │  -- Phase 1: KV → IndexNode chunks --
       │  for each touched namespace:
       │    flatten + apply ops
       │    write_tree_for_namespace:
       │      try single-leaf encode
       │      else pack_into_leaves greedy first-fit
       │      append leaf chunks                  ◄── extends file
       │      append InternalNode chunk           ◄── extends file
       │
       │  ★ BARRIER 1: file.fsync()
       │    All Phase 0 + Phase 1 chunks now durable.
       │
       │  -- Phase 2: Commit chunk --
       │  build CommitPayload { roots: [...], tx_root_hash }
       │  encode → cp_bytes
       │  append_chunk(Commit, cp_bytes)          ◄── extends file
       │
       │  ★ BARRIER 2: file.fsync()
       │    Commit chunk durable. Without Phase 2 visible, no SB will
       │    point here in step 3. Crash before this barrier → no
       │    Commit chunk → recovery uses old SB.
       │
       │  -- Phase 3: Superblock replicas --
       │  build new_sb { seq, root_slot=commit_slot, root_hash }
       │  for _ in 0..superblock_replicas:
       │    append_superblock(&new_sb)            ◄── extends file
       │
       │  ★ BARRIER 3: file.fsync()
       │    New SB visible. After this point, the new state is
       │    "committed" — recovery picks max-seq SB which is now this.
       │
       │  state.superblock = new_sb (in-memory bookkeeping)
       │
       │  -- Phase 4 (conditional): padding --
       │  if padding_policy says we need pad_count > 0:
       │    append_garbage_chunks(pad_count)      ◄── extends file
       │    ★ BARRIER 4: file.fsync()
       │
       └── return new_seq
```

## Анализ crash-safety по barrier'ам

### Crash до Barrier 1
Файл содержит некий префикс новых chunk'ов (DataBatch + IndexNode).
Новые Commit и SB не существуют. Recovery сканирует, выбирает SB с
наивысшим seq, который ещё читается (предыдущий). Orphan chunk'и
с точки зрения восстановленного состояния читаются как garbage.

**Результат:** rollback к предыдущему commit. Покрыто тестом
`crash_after_index_node_before_commit_rolls_back`.

### Crash между Barrier 1 и Barrier 2
Файл содержит все Phase 0/1 chunk'и (durable) плюс, возможно, Commit
chunk, если запись вернула, но fsync не завершился. В любом случае
новый SB ещё не записан. Recovery выбирает предыдущий SB.

**Результат:** rollback. Тот же recovery-путь, что выше.

### Crash между Barrier 2 и Barrier 3
Файл содержит все data + Commit (durable) плюс, возможно, новый SB,
если запись вернула, но fsync не завершился. Два под-случая:

- Новый SB chunk полностью записан и flush'нут на диск OS до
  crash'а: AEAD проходит при сканировании, становится max-seq SB →
  **Tx видим.**
- Новый SB chunk записан частично или не дошёл до диска: AEAD
  падает при сканировании, отбрасывается из `found` → max-seq SB —
  предыдущий → **Tx откатан.**

Любой исход приемлем: пользователь либо видит новое состояние
(success), либо предыдущее (rollback). Никакого torn / inconsistent
состояния. Покрыто тестом
`crash_after_commit_before_superblock_rolls_back`.

### Crash между Barrier 3 и Barrier 4 (padding)
Tx durably committed (новый SB видим). Padding garbage chunk'и могут
быть на диске, могут не быть. В любом случае:
- Новый SB ссылается на Commit. Commit ссылается на свои data chunks.
- Все data chunks durable (Barrier 1).
- Padding chunks читаются как random в любом случае (они И ЕСТЬ
  random) — AEAD падает и они просто игнорируются recovery scan'ом.

**Результат:** Tx видим. Файл может быть слегка короче, чем
предполагала pad-policy; на следующем commit padding догонит.

### Crash во время Barrier 4 (условный padding)
Тот же исход, что и в предыдущем пункте. Padding fsync — best-effort;
его единственная цель — сделать размер файла наблюдаемым snapshot-
adversary'ем как bucket-rounded значение, не data integrity.

## Прочие fsync-пути

### `Space::create`
Пишет N initial SB-реплик, затем единственный fsync. После того, как
этот fsync вернёт, space существует durably, и свежий
`Container::open_space` его найдёт. Никакое partial-create-state не
видно последующим вызовам.

### `Space::vacuum_orphans`
Сканирует, идентифицирует orphan IndexNode chunk'и, scrub'ит их
in place. После scrub'а всех выбранных slot'ов — ОДИН fsync (только
если хотя бы один chunk был scrub'нут; пустое множество — no-op).

Crash в середине vacuum:
- Часть slot'ов scrub'нута, часть нет. Новый SB не меняется (vacuum
  не пишет новый SB).
- Recovery: последний SB по-прежнему валиден; reachable tree не
  тронут (vacuum трогает только orphan'ы).
- Повторный запуск vacuum при следующем open идемпотентен —
  уже-scrub'нутые slot'ы просто AEAD-fail и не попадают в
  orphan-кандидаты.

**Результат:** корректно при crash'е. Идемпотентно при повторе.

## Заметки по failure-mode

### Ошибки `sync_all()`
Каждый вызов `fsync()` пропагирует ошибки через `?`. Если
`sync_all()` вернёт `Err`, Tx прерывается. Caller видит
`Error::Io(_)`. On-disk state может быть: любой префикс записей
durable, post-error записи volatile в OS-буферах — тот же crash-
safety анализ, что выше. Caller НЕ должен ретраить тот же Tx без
предварительного re-open контейнера для повторного derive state.

### macOS `F_FULLFSYNC`
На macOS `fsync(2)` flush'ит filesystem buffer cache на disk write
cache, но НЕ форсит запись с диска на пластину (folks из SQLite
задокументировали это подробно). Для сильной durability на macOS
правильный вызов — `F_FULLFSYNC`. Мы используем `sync_all`, который
маппится на `fsync` — host-app должно об этом знать. Задокументировано
как out-of-scope на этом слое; tracking как опция v0.5.x для
per-platform поведения.

### Linux `fsync` и write-cache
Современные Linux-ядра с дефолтно-смонтированными ext4/xfs/btrfs
ФЛАШАТ disk write cache по `fsync(2)`. Команды SATA `FLUSH CACHE` /
NVMe `FLUSH` отправляются. Это соответствует нашей модели durability.
Старые ядра или tuned-for-performance монтирования (`barrier=0`,
`nobarrier`) могут пропускать device flush — ответственность
host-app смонтировать с дефолтными опциями.

### Out-of-scope
- Disk firmware игнорирующий FLUSH (редко; влияет на все fsync-
  системы одинаково).
- Power loss между disk-FLUSH-CACHE и platter-write (обрабатывается
  современными enterprise-дисками через supercap / power-loss-
  protection).
- Filesystem-level torn writes внутри 4 KiB chunk'а на FS, не
  гарантирующих atomic 4 KiB writes (большинство современных FS
  ГАРАНТИРУЮТ; мы на это полагаемся).

## Журнал аудита

| Дата | Изменение | Ревьюер |
|---|---|---|
| Initial v0.5 | Первый проход. Трассировано 7 fsync-сайтов; все в правильных позициях. Протокол "3-fsync barrier" в `commit_tx` соответствует `DESIGN.md` §6. Crash-семантика корректна на каждом barrier'е (валидировано `tests/crash_recovery.rs`). Фиксы не нужны. | Self-audit |
