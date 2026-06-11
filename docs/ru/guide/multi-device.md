# Multi-device contract

[🇬🇧 English](../../en/guide/multi-device.md) · 🇷🇺 **Русский**

**Статус:** v0.4 — locking primitives стабильны; sync-семантика заморожена.

`hidden-volume` — это single-file, single-writer зашифрованное
хранилище. Этот документ — contract между библиотекой и любым
host-app, который работает на более чем одном устройстве, синхронизируется
по сети, или передаёт контейнер между процессами. Он определяет, что
библиотека гарантирует, чего она НЕ делает, и какие паттерны
host-app'ы должны соблюдать.

Если что-то в этом документе противоречит `DESIGN.md`, побеждает
`DESIGN.md`.

## TL;DR

- Библиотека сериализует writer'ов per-file через `flock(LOCK_EX)`.
  Два процесса, открывающие тот же файл в write-mode одновременно →
  второй получит `Error::Busy`. Readers (`open_readonly`) сосуществуют
  свободно; writer блокирует всех readers.
- Библиотека НЕ занимается P2P-sync, vector clocks, conflict
  resolution или merging. Файл контейнера представляет один
  timeline; если у вас несколько устройств — у вас несколько
  файлов, и reconciliation — это забота host-app на уровне
  KV / message-log, выше библиотеки.
- Rollback / fork detection предоставляется host-app в виде двух
  примитивов: [`Space::commit_seq`] и [`Space::commit_history`].
  Host-app хранит anchors снаружи (TPM, server counter, signed log)
  и сравнивает их при reopen.

## Что предоставляет библиотека

### Per-file write exclusion (v0.4)

- `Container::create` и `Container::open` берут `LOCK_EX` на
  underlying-файле. Auto-release на drop. Ошибка: `Error::Busy`
  при contention (отличается от `Error::Io`).
- `Container::open_readonly` берёт `LOCK_SH`. Несколько readers
  сосуществуют. Writer блокирует всех readers и наоборот. Write-методы
  на read-only handle возвращают `Error::ReadOnly`.
- Lock-семантика — POSIX `flock(2)` (per-OFD на Linux/macOS через
  Rust 1.89+ `File::try_lock`). NFS и другие распределённые
  файловые системы могут это ослабить — не запускайте контейнер на
  network-filesystem, который не поддерживает `flock`.

### Per-space monotonic seq

[`Space::commit_seq`] возвращает `u64`, который увеличивается на 1
при каждом успешном `commit_tx`. Начальное значение — 1
(назначается при `create_space`). Успешный commit → новое значение
durable на диске до возврата вызова.

### Per-space history of recoverable anchors

[`Space::commit_history`] возвращает sorted-ascending срез всех
`seq`, чей Superblock chunk ещё на диске и расшифровывается
ключом этого space. Replicas с одинаковым seq дедуплицируются.

Срез вычисляется один раз при open (во время trial-decrypt scan,
который и так выполняется) и обновляется in-place каждым успешным
`commit_tx`. Никакого дополнительного I/O на read-пути.

## Чего библиотека НЕ предоставляет

| Capability | Почему нет | Где это место |
|---|---|---|
| Concurrent writers с двух устройств | Формат append-only с одним seq counter; concurrent writers гонялись бы за seq и порвали бы 3-fsync barrier | Host-app: сериализуйте writer'ов (одно устройство за раз) |
| Vector clocks / Lamport clocks | Библиотека отслеживает один timeline | Host-app: закодируйте clock как KV-записи внутри space |
| Merge / conflict resolution | «Latest wins» слишком грубо для мессенджера; выбор CRDT app-specific | Host-app: прочитайте обе стороны через `iter_log` / `list`, merge'ните в коде, запишите merged-state в одном tx |
| Network sync, transport, encryption-in-flight | Out of scope (другая threat model, чем at-rest) | Host-app: TLS / Noise / Signal protocol поверх вашего transport |
| Cross-device replay protection | Библиотека — local-store; что *попадает* в неё — забота host-app | Host-app: подписанные сообщения, dedup-ключи |

## Multi-device паттерны

Библиотека поддерживает четыре host-app паттерна. Выберите один
явно; не смешивайте их.

### Pattern A — Single device

Default. Один физический файл, один процесс одновременно, `LOCK_EX`
обеспечивает это. Используйте `Container::open` и
`Container::open_readonly` свободно.

### Pattern B — Sequential hand-off (один общий файл, несколько процессов)

Один файл контейнера, в который несколько процессов (возможно, на
разных устройствах через общую файловую систему) пишут по очереди.

- Только ОДИН writer одновременно. `LOCK_EX` библиотеки обеспечивает
  это на файловых системах, поддерживающих `flock`.
- Каждый writer монотонно инкрементирует `commit_seq`. Чтение
  `commit_seq` сразу после `Container::open_space` говорит новому
  writer'у, где именно остановился предыдущий.
- Storage ДОЛЖЕН поддерживать `flock`-семантику. Network-filesystem,
  тихо игнорирующий locks (некоторые NFSv3-конфигурации, SMB без
  правильного setup), позволит конкурентных writer'ов и *повредит*
  файл. Библиотека не может это обнаружить — host-app deployer должен.

Этот паттерн — самый простой, если у вас реально есть координирующая
файловая система. Это НЕ рекомендуемый default для P2P-мессенджера —
см. Pattern D.

### Pattern C — Read-only fan-out

Один writer-процесс, много readers. Writer держит `LOCK_EX`, readers
используют `Container::open_readonly` (`LOCK_SH`). Readers видят
snapshot, который был на диске на момент open; новые commits
становятся видны только при re-open. Не смешивайте readers с
`Container::open` — `Container::open` это `LOCK_EX` и будет
заблокирован readers'ами.

### Pattern D — Replicated containers (один контейнер на устройство)

Рекомендуемый паттерн для P2P-мессенджера.

У каждого устройства СВОЙ файл контейнера. «Тот же разговор»
существует как отдельные KV / log записи на каждом устройстве,
реплицируемые sync-протоколом host-app. Библиотека не знает о
репликации.

Практические следствия:

- `commit_seq` каждого устройства независим. `commit_history`
  устройства отражает его локальный timeline, не глобальный.
- Conflict resolution живёт целиком в host-app. Распространённые варианты:
  - **CRDT** (operation-based или state-based). Каждая KV-запись
    это CRDT cell; merging state двух устройств детерминирован.
  - **Vector clock per message**. Закодируйте `(device_id, counter)`
    в значении каждой log-записи. Разрешайте конфликты тотальным
    порядком над vector clocks.
  - **Server-as-source-of-truth**. Центральный сервер держит
    canonical timeline; контейнер каждого устройства его кэширует.
- Библиотека не узнаёт о других устройствах. Device identity,
  pairing и authentication — это заботы host-app.

Этот паттерн локально на каждом устройстве компонуется с Pattern A.

## Anchor-паттерны (rollback detection)

Snapshot adversary (T2 в `DESIGN.md` §1) может заменить файл
копией с предыдущего момента. Библиотека сама не может это
обнаружить — у неё нет понятия «какое сейчас время» или «какое
state я последний раз закоммитил». Host-app предоставляет внешние
anchors.

### Anchor primitive

После каждого успешного commit host-app записывает `commit_seq()`
плюс опционально fingerprint (например, BLAKE3 поверх Superblock seq
и root_hash байтов — оба уже хранятся в state'е `Space`) в
место, которое adversary не может переписать:

| Storage | Pros | Cons |
|---|---|---|
| TPM / Secure Enclave NV counter | Hardware-rooted; переживает переустановку OS | Mobile platform restrictions; counter exhaustion |
| Server-side counter (HMAC'd) | Легко развернуть; quota'd | Online-зависимость; компрометация сервера = нет anchor |
| Signed log на отдельном устройстве | Без online-зависимости | UX-стоимость out-of-band sync |
| Plain file на том же диске | Тривиально побеждается тем же snapshot adversary | Бесполезно само по себе; только как defense-in-depth |

### Алгоритм rollback / fork-detection

На `Container::open_space`:

1. Прочитать внешний anchor `(anchor_seq, anchor_fp)`.
2. Вычислить текущий `current_seq = space.commit_seq()`.
3. Сравнить:
   - `current_seq < anchor_seq` → **rollback (откат)**. Отказаться
     продолжать; файл заменён более старой версией. Сообщите
     пользователю; НЕ принимайте тихо новые записи (вы потеряете
     anchored-данные).
   - `current_seq >= anchor_seq` И `anchor_seq` есть в
     `space.commit_history()` → **clean continuation**. Принимаем.
   - `current_seq >= anchor_seq` И `anchor_seq` НЕТ в
     `space.commit_history()` → **fork**. Timeline файла
     расходится с вашим anchor. Считайте враждебным.

Тест на membership в `commit_history()` — это часть, отличающая
«кто-то сбросил файл к ещё *новому* state, который я никогда не
коммитил» от «я просто открыл файл, который не трогал какое-то время».

### Что anchors раскрывают

Adversary, который может прочитать ваш anchor, узнаёт о существовании
и activity-rate *anchored* space. Anchoring space'а — это
deniability tradeoff:

- **Main / public space** — anchor свободно. Его существование
  признано.
- **Decoy / duress space** — НЕ anchor. Весь смысл в plausible
  deniability, и публично-читаемый anchor для «скрытого» space —
  самопротиворечив.
- **Hidden space (real)** — anchor только в storage location, чьё
  присутствие само по себе plausibly deniable (ваш TPM имеет много
  применений; сервер, который вы используете и для несвязанных
  вещей).

Библиотека это не enforce'ит — это host-app policy. Храните выбор
(«какие spaces anchored») зашифрованным внутри space, чей anchor
вы защищаете, никогда в открытом виде.

## Compaction и история

`Container::compact_known` производит свежий контейнер со свежим
salt и `container_id`. У destination'а `commit_history` для каждого
space начинается с `[1]` независимо от истории source.

Обязанности host-app во время compaction:

1. Re-anchor каждый anchored space против нового `commit_seq`
   после первого post-compaction commit.
2. Пока новый anchor не durable, считайте новый контейнер
   «pending verification» — snapshot adversary, захвативший момент
   между compaction и re-anchor, может replay'нуть старый
   контейнер с полной authority.
3. Compaction — это сам по себе event, о котором ваши другие
   устройства, возможно, должны знать (`container_id` файла
   изменился). Если вы синхронизируетесь на file-уровне (Pattern B),
   каждое другое устройство должно быть проинформировано; если
   вы синхронизируетесь на application-уровне (Pattern D), с точки
   зрения peer'а ничего не меняется.

## Cross-references

- `DESIGN.md` §5 — discovery scan, что лежит на диске
- `DESIGN.md` §6 — fsync barriers, что значит «успешный commit»
- `DESIGN.md` §7 — Superblock replicas, что переживает torn write
- `DESIGN.md` §11.2 — rollback ordering invariant
- `tests/multi_device.rs` — test coverage для этих примитивов
- `tests/locking.rs` — `flock` semantics tests
- `tests/readonly.rs` — `LOCK_SH` semantics tests

[`Space::commit_seq`]: ../src/space/mod.rs
[`Space::commit_history`]: ../src/space/mod.rs
