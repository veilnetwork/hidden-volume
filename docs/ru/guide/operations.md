# Operations playbook

[🇬🇧 English](../../en/guide/operations.md) · 🇷🇺 **Русский**

Практические рецепты для **развёртывания, резервного копирования,
миграции и восстановления** контейнера `hidden-volume`. Аудитория:
ops-ориентированные разработчики host-app и системные интеграторы.
Написано как исполняемые рецепты, а не теория.

Если что-то здесь противоречит `DESIGN.md` или
`docs/ru/security/threat-model.md`, побеждают эти документы.

## Содержание

- §1. Бэкап и восстановление
- §2. Ротация ключей (смена пароля)
- §3. Миграция параметров Argon2 (re-tuning класса устройства)
- §4. Восстановление после corruption / partial writes
- §5. Управление бюджетом хранилища (compact, vacuum)
- §6. Рецепты multi-device развёртывания
- §7. Forensic scrub перед утилизацией
- §8. Мониторинг размера контейнера
- §9. Что делать, когда что-то пошло не так

---

## 1. Бэкап и восстановление

### 1.1 Что значит «бэкап» здесь

Контейнер `hidden-volume` — это **один файл**. Бэкап = скопировать
файл. Восстановление = положить файл обратно. Нет специального
формата экспорта или импорта — файл *и есть* данные, в зашифрованном
виде.

### 1.2 Когда делать бэкап

- **Cold backup** — копирование файла, когда ни один процесс не
  держит на нём эксклюзивный lock. Используйте для регулярных
  ежедневных / часовых бэкапов. Возьмите `LOCK_SH` через
  [`Container::open_readonly`], чтобы гарантировать, что нет
  конкурентного writer'а посреди commit'а, скопируйте байты,
  отпустите lock.
- **Hot backup** — копирование файла, пока writer открыт. Избегайте.
  Если неизбежно, commit-in-progress writer'а может оставить
  недописанный хвост; получившийся бэкап почти наверняка
  recoverable (3-fsync protocol + property-based crash-recovery
  test), но нет гарантии о том, *к какому* commit'у вы
  восстановитесь.

### 1.3 Рецепт cold-backup

```rust,ignore
// Берём LOCK_SH на время копирования.
let _guard = hidden_volume::Container::open_readonly(path)?;
std::fs::copy(path, &backup_path)?;
// _guard дропается здесь, освобождая shared lock.
```

Shared lock не даёт взять новые writer-lock'и во время копирования.
Существующие writer'ы (если есть) заканчивают свой текущий Tx;
новый Tx не может начаться, пока lock не освободится.

### 1.4 Рецепт восстановления

```rust,ignore
// 1. Убедиться, что ни один writer не держит оригинал.
//    (Если уверенности нет, безопасный путь — упасть громко.)
// 2. Атомарно заменить файл.
std::fs::rename(&backup_path, path)?; // перезаписывает
// 3. Re-anchor каждый space, чьё host-app использует commit_seq для
//    rollback detection (см. docs/ru/guide/multi-device.md).
//    Restore НЕОТЛИЧИМ от rollback-атаки с точки зрения библиотеки —
//    ваша anchor-стратегия должна явно авторизовать
//    «этот restore намеренный».
```

**Anchor warning.** Если host-app реализует rollback detection
относительно внешнего anchor'а (TPM / server counter / signed log),
восстановление бэкапа сработает как rollback alarm, потому что
`commit_seq()` восстановленного файла старше anchor'а.
Host-app должен предоставить путь «я восстанавливаю backup»,
явно признающий падение seq и re-anchoring. Иначе пользователи
будут заблокированы после каждого восстановления.

### 1.5 Верификация бэкапа

После бэкапа проверьте, что файл расшифровывается и Merkle chain
не повреждён:

```rust,ignore
let mut c = hidden_volume::Container::open_readonly(&backup_path)?;
for password in known_passwords {
    let mut s = c.open_space(password)?;
    let _report = s.verify_integrity()?;
}
```

`verify_integrity` проходит Merkle hash chain end-to-end (~125 µs
для namespace на 1 100 записей; см. `docs/ru/contributing/benchmarks.md`)
и сообщает о любом несовпадении hash через
`Error::IntegrityFailure { detail, slot }`.

---

## 2. Ротация ключей (смена пароля)

### 2.1 Один space

```rust,ignore
let old: &[u8] = b"current-password";
let new: &[u8] = b"new-password";
hidden_volume::Container::change_passwords(
    path,
    &[(old, new)],
    options,
)?;
```

Механика: пишет свежий контейнер в sibling-temp с именем
`.{stem}.hv-rotate.{16hex}.tmp` (случайный 16-hex суффикс
избегает коллизий; ведущая точка убирает файл из обычных
листингов), затем `rename(2)`-ит его поверх `path` под source
`LOCK_EX` с `fsync` родительской директории. При любой ошибке
temp удаляется, а оригинальный `path` остаётся нетронутым. Полный
contract см. в [`Container::change_passwords`].

**Предупреждение: потеря данных by design.** Spaces, НЕ
перечисленные в password-mapping, **молча и безвозвратно
отбрасываются** — см. §2.2 и врезку там. Это в равной мере
относится к `change_passwords` и `compact_known`. Библиотека не
может перечислить deniable spaces (в этом весь смысл формата),
поэтому она не способна обнаружить «вы забыли space» и не может
предупредить. Host-app единолично отвечает за подтверждение того,
что набор паролей полон, перед вызовом.

### 2.2 Multi-space — изменить один, сохранить остальные

```rust,ignore
let main_old: &[u8] = b"main-old";
let main_new: &[u8] = b"main-new";
let hidden_kept: &[u8] = b"hidden-pw";
hidden_volume::Container::change_passwords(
    path,
    &[
        (main_old, main_new),         // ротация
        (hidden_kept, hidden_kept),   // сохранить как есть
    ],
    options,
)?;
```

> **⚠ ПОТЕРЯ ДАННЫХ BY DESIGN.** Spaces, НЕ упомянутые в mapping,
> **молча и безвозвратно отбрасываются** — та же деструктивная
> семантика, что и у `compact_known`. Пустой или неполный список
> паролей отбросит *каждый* непереисленный space. Это **свойство
> deniability, а не баг**: библиотека не может и не должна
> перечислять deniable spaces, поэтому она не способна узнать о
> существовании space, который вы забыли перечислить, и
> следовательно не может обнаружить или предупредить о потере
> данных. Host-app ОБЯЗАН подтвердить полноту набора паролей перед
> вызовом. Чтобы сохранить space, перечислите его как no-op пару
> `(p, p)`.

### 2.3 После ротации

- Re-anchor (см. anchor warning §1.4) — `commit_history` сбрасывается
  до `[1]` после неявного repack. Любой anchor, ссылавшийся на
  pre-rotation seq, будет выглядеть как fork.
- Запустите [`Space::verify_integrity`] на каждом space для
  подтверждения.
- OS allocator может переиспользовать блоки старого контейнера
  под несвязанные данные. Для forensic-grade scrub нижележащего
  storage см. §7.

---

## 3. Миграция параметров Argon2

Параметры Argon2id живут в cleartext header (устанавливаются при
создании). Библиотека отказывается открывать контейнер с параметрами
ниже `Argon2Params::MIN`; нельзя DOWNGRADE контейнер на месте.
Чтобы re-tune (например, пользователь обновился с Cortex-A53
на флагман и unlock-бюджет теперь больше), выполните no-op
ротацию паролей с новыми параметрами Argon2 через
[`Container::change_passwords`]:

```rust,ignore
use hidden_volume::container::RepackOptions;
use hidden_volume::crypto::kdf::Argon2Params;

// Ротация с identity-mapping (каждый пароль отображён сам на себя)
// проводит миграцию параметров через безопасный IN-PLACE-примитив
// (atomic_rewrite_under_source_lock): source LOCK_EX удерживается
// весь rename, fsync родительской директории, temp удаляется при
// ошибке.
hidden_volume::Container::change_passwords(
    path,
    &[(password, password)],   // identity map = мигрируем только параметры
    RepackOptions {
        argon2: Argon2Params::HEAVY,   // было DEFAULT
        ..Default::default()
    },
)?;
```

> **⚠** Перечислите пароль КАЖДОГО space в identity-map. Любой
> space, чей пароль опущен, отбрасывается (см. §2.2 предупреждение
> о потере данных).

НЕ изобретайте свой `Container::repack(path, dest, ..)` +
`std::fs::rename(dest, path)`: это снова вносит M1 lost-update
race, который библиотека чинит внутри — source-lock не
удерживается через rename, нет fsync родительской директории, а
упавший repack оставляет partial `dest` на cleanup вызывающему.
`change_passwords` (и `compact_known`) идут через in-place-
примитив, закрывающий все три бреши.

Те же anchor / verify оговорки, что и в §2.

**Memory footprint.** Audit pass 16 (R-STREAMING-REPACK) сделал
`Container::repack` memory-bounded: log-namespaces проходятся
постранично, с per-page `Tx::commit`, working-set ≈ 4 МиБ на
страницу независимо от общего объёма лога. Multi-GiB
log-namespaces больше не требуют мониторинга RSS хоста во время
repack; KV-namespaces всё ещё собираются целиком на namespace, но
структурно ограничены 2-уровневым B+ tree cap'ом.

**File-size cap.** Рост destination в repack ограничен
`MAX_OPEN_SCAN_CHUNKS = 16M` чанков ≈ 64 ГиБ (audit pass 17 B);
превышение surface'ится как `Error::ContainerTooLarge { extra, cap }`.
Учтите, что это срабатывает **посреди копирования**, а не до
первой записи — когда вы вызываете сырой примитив
`Container::repack(path, dest, ..)` напрямую, partial `dest` уже
может существовать на диске в момент возврата ошибки, и он
**принадлежит вызывающему**: вы должны удалить его сами. In-place
обёртки `change_passwords` / `compact_known` делают эту очистку за
вас (temp удаляется при любой ошибке). Cap симметричен с open-side
scan-budget'ом — успешно отрепакнутый файл гарантированно можно
открыть.

**Выбор параметров.** См. `DESIGN.md` §11.1:

| Preset | Память | Iterations | Use case |
|---|---|---|---|
| `LIGHT`   |  16 MiB | 3 | Слабые ARM (Cortex-A53) |
| `DEFAULT` |  64 MiB | 3 | Mid-range мобильные (последние 5 лет) |
| `HEAVY`   | 256 MiB | 4 | Desktop / server-class |

Не подстраивайте параметры динамически в процессе развёртывания —
выбирайте при создании, и мигрируйте через repack только когда
устройство пользователя меняет класс.

---

## 4. Восстановление после corruption / partial writes

### 4.1 Что такое recovery

Recovery-модель библиотеки описана в `DESIGN.md` §7. Кратко:
open-path scan выбирает Superblock с максимальным seq, который
AEAD-decrypt'ится под ключом space. Torn write на хвосте файла
(truncate-at-chunk-boundary или kernel-panic-mid-fsync) оставляет
предыдущий Superblock как max-seq, и система откатывается (rollback).

### 4.2 Диагностический рецепт

```rust,ignore
// 1. Открыть read-only — пропускает auto-vacuum tree-walk, который
//    иначе пропагировал бы corruption-ошибки как AuthFailed.
let mut c = hidden_volume::Container::open_readonly(path)?;
let mut s = c.open_space(password)?;

// 2. Пройти по Merkle chain.
match s.verify_integrity() {
    Ok(report) => println!("OK: {report:?}"),
    Err(hidden_volume::Error::IntegrityFailure { detail, slot }) => {
        eprintln!("corruption на slot {slot}: {detail}");
        // переходим к §4.3
    }
    Err(other) => return Err(other),
}
```

### 4.3 Если `verify_integrity` сообщает о mismatch

Corruption локализована до указанного slot. Опции восстановления
в порядке возрастающей деструктивности:

1. **Bit-flip (filesystem-level)** — переворот одного байта в
   chunk Superblock. С multi-replica конфигурацией
   (`superblock_replicas` ≥ 2; default 3) другие replica
   выживают; open path тихо выбирает целую. Никаких действий не
   требуется кроме будущего `compact_known` для возврата
   повреждённого chunk.
2. **Один IndexNode chunk повреждён** — tree namespace'а сломано.
   Запустите `Container::compact_known` со всеми известными
   паролями: данные внутри повреждённого subtree теряются, но
   остальные достижимые записи namespace сохраняются.
3. **Один Commit chunk повреждён** — теряется весь последний
   commit; предыдущие commit'ы сохраняются. Recovery
   автоматически откатывает (rollback) к предыдущему max-seq
   Superblock (как описано в `DESIGN.md` §7); недавно записанные
   данные теряются.
4. **Header chunk повреждён** — контейнер невосстановим.
   Восстановите из бэкапа (§1.4).

### 4.4 Если файл truncated

Truncate-at-chunk-boundary: recovery выбирает последний
полностью записанный Superblock и откатывается. Особых действий
не нужно, кроме повторного открытия файла.

Truncate-mid-chunk (размер файла не выровнен до 4 KiB):
библиотека **допускает** невыровненный хвост в конце — сетка
chunk'ов считается как `N = (file_size / CHUNK_SIZE) - 1` (с
округлением вниз), поэтому частичный последний chunk игнорируется
и трактуется как переиспользуемое свободное место (см.
`docs/ru/reference/format.md` §1). Recovery затем выбирает
последний полностью записанный Superblock, ровно как в выровненном
случае. Hex-редактор для truncate не нужен; достаточно повторно
открыть файл.

---

## 5. Управление бюджетом хранилища

### 5.1 Почему файл растёт монотонно

Контейнер мессенджера растёт из-за:

- Новых сообщений (DataBatch chunks).
- Edits / overwrites (orphan DataBatch chunks).
- Deletes (orphan IndexNode chunks до vacuum_orphans).
- Padding / decoy chunks (size obfuscation).

**Принципиально: scrub'нутые слоты НЕ переиспользуются** последующими
записями. Это **load-bearing для deniability** (DESIGN §9 — см.
подсекцию «slot-reuse prohibition»): in-place перезапись известного
file offset дала бы multi-snapshot противнику (T2') однозначный
сигнал «этот slot активен», который нельзя списать на decoy growth.
Поэтому каждый Tx commit append'ит в конец файла; «дыры», оставшиеся
после `vacuum_orphans` / `vacuum_data_batches`, остаются на диске
как uniform-random байты.

Единственный способ вернуть disk space — **L5: полная компакция**
(`Container::compact_known`), которая переписывает файл с нуля под
одним `LOCK_EX`-flock'ом и ротирует `container_id`. Audit pass 16
(R-STREAMING-REPACK) сделал её memory-bounded (≈ 4 MiB working set
на страницу), так что её можно безопасно запускать на слабом
оборудовании даже с multi-GiB log namespaces.

### 5.2 Замер live-ratio: `Space::utilization_ratio`

`SpaceStats::utilization_ratio()` возвращает долю slot-grid файла,
принадлежащую этому space, в `[0.0, 1.0]`. Multi-space контейнер
будет иметь ratios, сумма которых меньше 1.0 (остаток —
garbage padding + чужие hidden spaces); single-space контейнер
приближается к 1.0 минус padding overhead.

```rust,ignore
let stats = space.stats()?;
println!(
    "live: {} / {} chunks ({:.1}% utilization)",
    stats.owned_chunk_count,
    stats.total_slot_count,
    stats.utilization_ratio() * 100.0,
);
```

CLI выдаёт то же число: `hv dump-stats <path>` печатает
`utilization_ratio: 0.612 (61.2% live)`.

### 5.3 Рецепт reclaim (lightweight)

```rust,ignore
// Дешёвый forward-secrecy + cleanup для log namespaces.
// Безопасно запускать на живом writer'е — нет rename, нет temp file.
// НЕ уменьшает файл; только обнуляет orphan DataBatch slots.
space.vacuum_data_batches()?;
```

Запускайте периодически (например, раз на запуск приложения),
чтобы вернуть batches, осиротевшие после edits / deletes сообщений.
Стоимость: несколько ms на активный log namespace.

### 5.4 Рецепт reclaim (полный) — когда компактить

```rust,ignore
// Heavyweight: полный repack + size reclaim + ротация container_id.
// Сбрасывает commit_history до [1]; требуется re-anchor.
drop(space);                  // сначала освободить flock
drop(container);
hidden_volume::Container::compact_known(path, &all_passwords, options)?;
```

**Триггеры — выберите один или комбинируйте.** Библиотека не
навязывает расписание; host-app — правильное место для решения,
потому что нужная частота зависит от UX (мешает ли компакция при
запуске воспринимаемому startup time?) и от storage-budget'ов:

```rust,ignore
// Pattern 1: live-ratio threshold (рекомендация для мессенджера).
// Heavy-delete нагрузки (просроченные переписки, «удалить аккаунт X»)
// поднимают high-water mark файла, тогда как live-контент сжимается.
const RECLAIM_THRESHOLD: f64 = 0.5;
if stats.utilization_ratio() < RECLAIM_THRESHOLD
    && stats.total_slot_count > 1024  // пропускаем почти-пустые свежие контейнеры
{
    schedule_compact();
}

// Pattern 2: абсолютный size-budget (вспомогательный).
// User-визуальная квота — типичная цель для мобильных ≤ 1 GiB.
const SIZE_BUDGET_CHUNKS: u64 = 256 * 1024;  // 1 GiB при CHUNK_SIZE
if stats.total_slot_count > SIZE_BUDGET_CHUNKS {
    schedule_compact();
}

// Pattern 3: idle-time defer (наименее интрузивный UX).
// Запуск при первом старте после ≥ N дней неактивности, когда
// пользователь не ждёт открытия чата.
let last_compact_age = last_compact_at.elapsed();
if last_compact_age > Duration::from_secs(14 * 24 * 3600) {
    schedule_compact_on_next_idle();
}

// Pattern 4: privacy event (немедленно).
// Пользователь только что нажал «удалить этот аккаунт» / «стереть
// историю». Гарантированный физический scrub требует compact
// (заодно ротирует container_id — защищает от multi-snapshot
// byte-diff, который мог уже захватить live-данные до удаления).
on_privacy_action(|| {
    schedule_compact();
});
```

Используйте любую комбинацию. Для мессенджера типичная пара —
Pattern 1 + Pattern 4: ambient drift через live-ratio,
explicit-deletes — немедленно.

**Стоимость.** `compact_known` выполняет полный Tx-by-Tx rewrite
каждого разблокированного space. На x86 desktop пропускная
способность реалистична на ~300-500 MB/s; на слабом ARM
~50-100 MB/s. Стоимость Argon2 платится один раз на разблокированный
space (одна свежая деривация против нового salt). Audit pass 16
сделал память ≈ 4 MiB на страницу независимо от общего размера —
никакого babysitting'а RSS хоста не требуется.

**Атомарность.** `compact_known` работает in-place: записывает
sibling tmp-файл с именем `.{stem}.hv-compact.{16hex}.tmp` (ротация
использует `.{stem}.hv-rotate.{16hex}.tmp`), делает `fsync`, затем
`rename` поверх source под `LOCK_EX` + `fsync_parent_dir`. Crash
посреди rename либо оставляет старый файл нетронутым, либо атомарно
его заменяет; никогда partial-state.

**Очистка stale-temp.** Crash *до* rename может оставить sibling
`.{stem}.hv-rotate.{16hex}.tmp` или `.{stem}.hv-compact.{16hex}.tmp`.
Эти файлы инертны (они никогда не заменяли живой контейнер), но
занимают место и ничего не утекают. Host-app'ам стоит при старте
проходить директорию контейнера по маске `.{stem}.hv-*.{hex}.tmp`
и удалять такие siblings, **пока контейнер не открыт** (удаление
temp, который активно пишет конкурентная in-progress
rotate/compact, повредит ту операцию — подметайте только когда
держите контейнер сами или знаете, что его никто не держит).

Используйте этот рецепт когда:
- Live-ratio упало ниже порога (см. триггеры выше).
- Размер файла доминируется garbage / orphan chunks (типично после
  массового удаления).
- Параметры Argon2 нужно изменить (§3).
- Padding policy или initial garbage budget нужно изменить.

### 5.4 Decoy size obfuscation

`ContainerOptions::initial_garbage_chunks` и
`PaddingPolicy::{BucketGrowth, FixedRatio}` существуют, чтобы
сделать размер файла неинформативным для snapshot adversary.
Defaults — НЕ добавлять padding (zero-байтовый overhead).
Production-развёртывания, защищающиеся от T2' (multi-snapshot
byte-diff), должны:

- Установить `initial_garbage_chunks` так, чтобы файл стартовал с
  «это могло бы быть чем угодно» размера (например, 32-256 MiB).
- Установить `padding_policy = BucketGrowth { bucket_chunks: N }`,
  чтобы размер файла прыгал инкрементами по N chunks вместо
  раскрытия per-commit роста.

См. `DESIGN.md` §1, что это защищает, и §8, как работает policy.

---

## 6. Рецепты multi-device развёртывания

Выберите **один** паттерн явно. Их смешивание тихо повреждает
state. Полный contract: `docs/ru/guide/multi-device.md`.

### 6.1 Pattern A — single device

Default. Один файл, один процесс, `LOCK_EX` обеспечивается.
Никаких особых ops.

### 6.2 Pattern B — sequential hand-off (один общий файл)

Несколько процессов / устройств пишут по очереди. ТОЛЬКО ОДИН
writer одновременно; `LOCK_EX` библиотеки обеспечивает это на
файловых системах, поддерживающих `flock(2)`. Storage ДОЛЖЕН
поддерживать flock семантику — NFSv3 без `lockd`, SMB без
правильного setup, FUSE filesystems и т. д. могут тихо
разрешить конкурентных writer'ов и повредить файл. Тестируйте
с two-writer интеграцией перед развёртыванием.

### 6.3 Pattern C — read-only fan-out

Один writer-процесс, много readers. Writer держит `LOCK_EX`
(default open path); readers используют
`Container::open_readonly` (`LOCK_SH`). Несколько readers
сосуществуют с одним writer'ом; readers видят snapshot на
время своего открытия и наблюдают новые commits только
при re-open.

### 6.4 Pattern D — replicated containers (РЕКОМЕНДУЕТСЯ для мессенджеров)

Один контейнер на устройство. У каждого устройства независимый
commit_seq. Reconciliation живёт в sync-слое host-app (CRDT,
vector clock, или server-as-source-of-truth). Библиотека
sync-unaware.

---

## 7. Forensic scrub перед утилизацией

Когда пользователь выводит устройство из эксплуатации, файл
контейнера должен стать невосстановимым. Библиотека сама не
может это гарантировать, потому что:

- Современная flash-память (SSD, eMMC, UFS) реализует
  wear-leveling через FTL. Запись нулей в файл НЕ перезаписывает
  физические NAND-ячейки; FTL просто перемапит LBA. Старые
  NAND-ячейки могут быть доступны через firmware-level extraction.
- Магнитные диски поддерживают secure erase через
  `hdparm --security-erase`, но это только whole-drive.

### 7.1 Best-effort logical scrub

```rust,ignore
// Перезаписываем файл случайными байтами, потом удаляем.
let len = std::fs::metadata(path)?.len();
let f = std::fs::OpenOptions::new().write(true).open(path)?;
let mut buf = [0u8; 4096];
let mut written = 0u64;
while written < len {
    hidden_volume::crypto::rng::fill(&mut buf)?;
    use std::io::{Seek, SeekFrom, Write};
    let mut f = &f;
    f.seek(SeekFrom::Start(written))?;
    let to_write = std::cmp::min(buf.len() as u64, len - written) as usize;
    f.write_all(&buf[..to_write])?;
    written += to_write as u64;
}
f.sync_all()?;
drop(f);
std::fs::remove_file(path)?;
```

Это best-effort против software-level recovery. Против
forensic adversary с hardware-доступом только **whole-device
secure erase** (vendor-specific) или **физическое уничтожение**
носителя дают сильные гарантии.

### 7.2 Defense-in-depth рекомендация

Для пользователей в адверсарных средах:

1. Храните контейнер на FDE-томе (LUKS / FileVault / BitLocker).
   Утилизация становится «выкинуть FDE-ключ», а не «вычистить
   файл».
2. На Linux запускайте на `tmpfs`, если persistence не требуется —
   power-off уничтожает данные без disk-следов.
3. В паре с bootable USB, на котором живёт FDE-ключ — потеря USB
   делает диск нечитаемым.

---

## 8. Мониторинг размера контейнера

```rust,ignore
let stats = space.stats()?;
let owned_bytes = stats.owned_chunk_count as u64 * 4096;
let file_bytes = std::fs::metadata(path)?.len();
let overhead_pct = 100 * (file_bytes - owned_bytes) / file_bytes;
println!(
    "{} owned chunks ({} KiB) in a {} KiB file ({}% padding/orphans)",
    stats.owned_chunk_count,
    owned_bytes / 1024,
    file_bytes / 1024,
    overhead_pct,
);
```

Интерпретация:

- **0-30% overhead** — типичный steady-state: padding policy и
  decoy garbage. Никаких действий.
- **30-70%** — накопленные orphan'ы от deletes / overwrites.
  Запустите `vacuum_data_batches` (дешёво) или `compact_known`
  (полное).
- **>70%** — патологическое накопление. Изучите workload
  (быстрые put-delete циклы? частые ротации `commit_seq`?)
  до compaction.

---

## 9. Что делать, когда что-то пошло не так

| Симптом | Диагноз | Рецепт |
|---|---|---|
| `Error::AuthFailed` на каждом space | Неверный пароль ИЛИ неверный файл ИЛИ corruption header | Попробуйте другие пароли; убедитесь, что `container_id` в header не изменился относительно known-good бэкапа; если всё мимо — restore из бэкапа |
| `Error::Busy` | Другой writer держит `LOCK_EX` | Подождите; повторите один раз после задержки; НЕ зацикливайтесь — это почти всегда зависший процесс или stale lock от упавшего peer |
| `Error::Malformed` на open | Header повреждён (truncated mid-chunk *хвост* допускается, а не отклоняется — см. §4.4) | Restore из бэкапа |
| `Error::IntegrityFailure { slot, detail }` | Конкретный chunk имеет неверный hash; AEAD прошёл, а Merkle нет | §4.3 |
| `Error::ReadOnly` от write-вызова | Контейнер открыт через `open_readonly` | Переоткройте через `Container::open` (берёт `LOCK_EX`) |
| `Error::Cancelled` | `CancelToken` был сработал во время операции | Операция aborted; безопасно повторить (нет partial state на диске) |
| `Error::PayloadTooLarge` на commit | Одиночная запись превышает chunk capacity | Уменьшите размер записи; для сообщений > 8 KiB храните в отдельном KV namespace с content-addressed ключом |
| Диск переполнился во время commit | OS вернул `ENOSPC` | Commit aborted до fsync — recovery откатывается к предыдущему commit. Освободите место, повторите |
| Процесс убит во время Tx | OS убила процесс до завершения commit | Recovery откатывается к предыдущему commit при следующем open; никаких действий не требуется |
| Процесс убит во время fsync | То же самое, возможно с torn last-chunk write | Recovery выбирает max-seq Superblock; torn chunk тихо игнорируется |
| Open успешен, но количество namespace = 0 | Пустой space (commits ещё не было) ИЛИ `commit_history` откатилось | Проверьте `commit_seq()` и `commit_history()` против внешнего anchor'а |

---

## 10. Cross-references

- `docs/ru/guide/integration.md` — host-app integration narrative.
- `docs/ru/guide/multi-device.md` — host-app sync / anchor contract.
- `docs/ru/security/threat-model.md` — формальный каталог adversary / инвариантов.
- `DESIGN.md` — on-disk format и crash-safety инварианты.
- `docs/ru/contributing/benchmarks.md` — performance baselines и Argon2 tuning targets.
- `SECURITY.md` — политика disclosure уязвимостей.

[`Container::open_readonly`]: ../src/container/mod.rs
[`Container::change_passwords`]: ../src/container/mod.rs
[`Container::repack`]: ../src/container/mod.rs
[`Space::verify_integrity`]: ../src/space/mod.rs
