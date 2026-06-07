# Adversarial-stance audit pass

**Дата.** 2026-05-28. **Reviewer.** LLM-assisted, проинструктирован
*пытаться сломать* инварианты проекта, а не верифицировать их
defensively. **Код против которого проверено.** `master` плюс
dossier-коммит `e3382a6`.

## Методология

[Self-audit dossier](self-audit.md) §4 перечисляет, что claim'ится
о каждом security-инварианте и как код это enforce'ит. Dossier
написан в defensive-стойке: *«claim X, код enforce'ит через Y»*.
Этот pass инвертирует mindset: *«как бы я, как противник одного
из тиров T1/T2/T2'/T3, попытался нарушить каждый claim?»*

Для каждой попытки атаки фиксируется:

- **Имя атаки** и **тир противника**.
- **Метод** — конкретные шаги, которые делает противник.
- **Code path, который защищает** (или не защищает).
- **Outcome** — *defended*, *утекает acknowledged-and-bounded
  информация*, или *real finding to fix*.

Out-of-scope items из threat-model'а ([§4 threat-model.md](../threat-model.md))
каталогизированы, чтобы подтвердить, что мы случайно не дрейфанули
*внутрь* защиты того, что dossier говорит, что не защищаем, и
чтобы newcomer'ы видели явные границы T2' / OS-уровня / CPU-
side-channel'ов.

Severity-legend: **CRITICAL** (claim сломан), **HIGH** (mitigation
bypass), **MEDIUM** (утечка beyond того, что threat-model
acknowledge'ит), **LOW** (doc-inconsistency или defense-in-depth),
**INFO** (атака закаталогизирована, но уже задокументирована как
defended / out-of-scope).

## Headline

**Никаких critical / high / medium находок.** Каждая попытка атаки
либо:

- (a) код защищает корректно (большинство случаев), либо
- (b) атака документировано out-of-scope (T2', OS-уровень, CPU-
  side-channel), либо
- (c) утечка задокументирована и квантифицирована (TM1 timing
  oracle, F-PAD downgrade, file-size visibility).

**Одно LOW finding:** мой собственный `self-audit.md` §4 (dossier,
закоммиченный в `e3382a6`) описывает cleartext-header как «64-
байтный» в D1 invariant statement'е. Каждый другой документ и
source-константы (`HEADER_LEN = 80`) говорят 80. Fix включён в
этот audit-pass коммит.

## Каталог атак

### Против **D1** (single-snapshot indistinguishability)

#### D1-A1. Garbage vs real-chunk distinguishability по byte distribution

- **Тир.** T1.
- **Метод.** Собрать byte-frequency / entropy / autocorrelation
  statistics над каждым 4096-байтовым chunk'ом после header'а.
  Искать bimodal distribution, разделяющую encrypted chunk'и и
  garbage.
- **Почему должно провалиться.** Garbage chunks — это `getrandom`
  output ([`ContainerFile::append_garbage_chunks`](../../../../crates/hidden-volume/src/container/file.rs)).
  Encrypted chunks — `nonce (24, getrandom) ‖
  XChaCha20-Poly1305(...)` — keystream computationally
  неотличим от random под стандартным ChaCha20-assumption'ом, и
  16-байтный Poly1305-tag — high-entropy функция от (key, nonce,
  ad, plaintext) tuple'а.
- **Verdict.** **Defended.** Статистические тесты на randomness
  не дают сигнала под любым стандартным CSPRNG-assumption'ом.
- **Severity.** INFO.

#### D1-A2. Cleartext-header fingerprint выдаёт «это `hidden-volume` файл»

- **Тир.** T1.
- **Метод.** Парсить первые 48 байт как `salt (32) ‖
  Argon2Params (16)` (v3 layout; v2 имел дополнительные 32 байта
  cleartext `container_id` по offset 32..64 — закрыто v3 #10).
  Проверить, содержит ли 16-байтный `Argon2Params` блок значения
  в plausible-диапазоне (`m_cost_kib ∈ [8192, 2²⁰]`,
  `t_cost ∈ [2, 100]`, `p_cost ∈ [1, 64]`,
  `format_version == 3`, padding-policy биты 16..24 ∈
  {0, 1, 2, 3}, reserved биты 24..32 == 0). Если всё парсится, с
  высокой вероятностью это `hidden-volume` контейнер.
- **Почему это успешно.** D1 claim'ит indistinguishability от
  uniform-random **после** cleartext-header'а. Header — by design
  cleartext и structured (альтернатива — «trial-decrypt» на open,
  см. threat-model §4 hidden-header дискуссия). v3 #10 сократил
  attack surface cleartext-header'а, убрав per-space `container_id`
  — в открытом header'е больше нет ни одного per-space
  идентификатора, поэтому fingerprint — это «это контейнер», а не
  «это *пространство N* контейнера».
- **Verdict.** **Acknowledged out-of-scope.** D1 явно вырезает
  48-байтный structured header; «файл — контейнер» детектируется,
  но «*какие spaces и какой content* внутри» — нет.
- **Severity.** INFO (документированная limitation; further
  hidden-header работа отслеживается как кандидат на v4-format
  change в [migration.md](../../guide/migration.md)).

#### D1-A3. Видимость slot count через `stat`

- **Тир.** T1.
- **Метод.** `stat` файла. Вычислить
  `slot_count = (file_size - CHUNK_SIZE) / CHUNK_SIZE` (первый
  chunk хранит header). Это раскрывает, сколько storage
  использует контейнер.
- **Почему это успешно.** File size неизбежно публичен.
- **Verdict.** **Acknowledged out-of-scope.** Размер любого файла
  наблюдаем; это не раскрывает *content*. Aggregate file size +
  cleartext-header fingerprint (D1-A2) раскрывает «у этого
  пользователя ≈N chunks hidden-volume-хранилища», что metadata,
  не D1-нарушающее content disclosure.
- **Severity.** INFO.

#### D1-A4. Padding-policy byte tamper (F-PAD)

- **Тир.** T2.
- **Метод.** Флипнуть `Argon2Params.version` биты 16..24 с `3`
  (`Bucket16Mib`) на `0` (`None`). На следующем commit'е
  padding-политика writer'а degrade'ит к `None` — последующие
  commit'ы шлют ровно те data-chunks, что писали, без garbage
  padding'а для маскировки роста размера.
- **Почему частично успешно.** Byte unauthenticated; только
  верхние 8 бит (reserved) обнулены и валидированы
  `Argon2Params::validate`. Padding-policy byte намеренно
  unauthenticated, потому что binding его к AEAD сломал бы F-PAD
  privacy (можно было бы *детектировать*, что writer изменил
  политику, что само по себе privacy-сигнал).
- **Почему impact bounded.** Принуждает padding к `None` — privacy
  degradation только для **multi-snapshot противников** (T2').
  Single-snapshot D1 держится: chunks остаются uniform random.
- **Defense.** Host-app override: `set_padding_policy()` в runtime
  игнорирует persisted byte. Документировано в F-PAD escape
  hatch и dossier §4 D1 caveat.
- **Verdict.** **Acknowledged limitation** (F-PAD §4.1).
- **Severity.** INFO.

#### D1-A5. Argon2-param header tamper для ослабления brute-force

- **Тир.** T2.
- **Метод.** Флипнуть header-байты, установив `m_cost_kib =
  MIN_M_COST_KIB = 8192`, `t_cost = MIN_T_COST = 2`, `p_cost =
  MIN_P_COST = 1`, затем захватить файл и brute-force'ить
  offline.
- **Почему проваливается.** Argon2-params — *input* в KDF-цепочку:
  legitimate seal вычислил `derive_master(password, salt,
  ORIGINAL_PARAMS)`. После tamper'а следующий open вычисляет
  `derive_master(password, salt, WEAK_PARAMS)`, derive'ит
  *другой* `master_key`, отсюда другой per-slot AEAD key,
  отсюда AEAD падает на каждом chunk'е — legitimate user видит
  `AuthFailed`. Атакующий захватил файл *до* tamper'а; для
  offline brute-force атакующий обязан использовать какие
  params'ы были sealed under, так что weakening header on-disk
  не ускоряет brute-force против captured файла.
- **Verdict.** **Defended.** Лучшее, что атака даёт — DoS на
  legitimate user (и DoS этот recoverable восстановлением
  header'а из backup'а или trial-trying `Argon2Params::DEFAULT`
  + стандартных preset-вариантов).
- **Severity.** INFO.

#### D1-A6. Header-padding-bytes раскрывают commit timing

- **Тир.** T1.
- **Метод.** Первый chunk — `HEADER_LEN (80) ‖ uniform random
  padding (4016 байт)`. Padding-байты random в момент create.
  Могут ли *entropy* или *pattern* этих байт раскрыть, когда
  контейнер был создан?
- **Почему проваливается.** `getrandom` output. Никакого
  timestamp'а embedded.
- **Verdict.** **Defended.**
- **Severity.** INFO.

#### D1-LOW1. Dossier doc-inconsistency: «64-byte» cleartext-header

- **Где.** [`self-audit.md`](self-audit.md) §4 D1-statement:
  *«... 64-байтового cleartext-header'а (`salt (32) ‖
  container_id (32) ‖ Argon2Params (16) ‖ ...`)»*. Арифметика
  внутри скобок суммирует в 80, не 64. Source-константа
  ([`lib.rs:183`](../../../../crates/hidden-volume/src/lib.rs):
  `pub(crate) const HEADER_LEN: usize = 80;`), `format.md`,
  `threat-model.md`, root `README.md`, и `guide/migration.md`
  все говорят 80.
- **Severity.** LOW (doc consistency в файле, который я авторил
  в той же сессии, что и этот audit).
- **Fix.** Включён в коммит этого audit'а — «64-байтового» →
  «80-байтового» на line 122 RU dossier'а и «64-byte» →
  «80-byte» на line 122 EN dossier'а.

### Против **D2** (compelled-key plausible deniability)

#### D2-A1. TM1 open-time timing oracle (глубже)

- **Тир.** T1 с side-channel access (пассивный наблюдатель
  open-time CPU usage / wallclock).
- **Метод.** Профилировать `Container::open_space` wallclock как
  функцию от `frac_owned = owned_chunks / total_chunks`. Bench
  [`benches/timing_oracle.rs`](../../../../crates/hidden-volume/benches/timing_oracle.rs)
  установил ~75 µs-per-chunk swing, привязанный к MAC-fail-then-
  skip vs MAC-pass-then-decrypt.
- **Что утекает.** Приблизительный `frac_owned` (±10-20%) для
  наблюдаемого space'а. **Не** идентифицирует, *какие* slot'ы
  владеются; **не** различает «space B существует с низким
  frac» от «нет space B, эти slot'ы — garbage padding».
- **Почему D2 всё ещё держится в strict смысле.** D2 claim'ит,
  что противник с паролем `S_A` не может доказать существование
  `S_B`. Frac-owned leak наблюдается во время *legitimate open
  `S_A`*, наблюдателем runtime того open'а. С точки зрения
  key-holder'а `S_A`, *каждый non-owned chunk* неотличим (AEAD
  падает одинаково для «wrong space» и «garbage»). Frac-owned
  leak даёт «такая доля файла — *не* `S_A`'s» — что также
  утекает file size'ом (D1-A3), modulo padding. Так что TM1
  обостряет уже-leaked сигнал; он не создаёт новый сигнал, *что
  различает* «другой space» и «garbage padding».
- **Mitigation roadmap.** Заменить MAC-fail-fast на constant-
  time AEAD path, всегда прогоняющий ChaCha20 над body. ~2×
  cost на garbage chunks, но устраняет timing leak. Tracked как
  TM1-v1.x в [threat-model F-TM1](../threat-model.md).
- **Verdict.** **Acknowledged, bounded, mitigation-tracked.**
- **Severity.** INFO (уже задокументировано на ровно этом
  уровне).

#### D2-A2. Wrong-password vs not-our-chunk error discrimination

- **Тир.** T1 + доступ к error-stream caller'а API.
- **Метод.** Атакующий вызывает
  `Container::open_space(path, wrong_password)` и наблюдает
  возвращаемую ошибку. Сравнить с
  `Container::open_space(path_with_only_garbage, any_password)`.
  Если ошибки различаются (разный error-variant, разное
  сообщение, разная latency), атакующий может различать «у этого
  файла ЕСТЬ какой-то space» от «этот файл — garbage», что
  D2-relevant.
- **Почему проваливается.** Оба пути возвращают
  `Error::AuthFailed` ([`error.rs`](../../../../crates/hidden-volume/src/error.rs)).
  Верифицировано grep'ом каждого `try_decrypt` call site'а:
  `.ok()?` pattern молча skip'ит failures во время discovery
  scan'а ([`open/mod.rs::try_decrypt`](../../../../crates/hidden-volume/src/open/mod.rs)).
  Final return — `Err(AuthFailed)` если ни один superblock не
  decrypt'ился — тот же variant вне зависимости от того,
  garbage файл или unrelated spaces. Timing — это TM1-вопрос
  (см. D2-A1).
- **Verdict.** **Defended.** D2-closure для error-канала:
  подтверждено.
- **Severity.** INFO.

#### D2-A3. Recovery-path observability через множественные opens

- **Тир.** T1 с repeated-observation capability (например, side-
  channel watcher process activity во времени).
- **Метод.** Наблюдать wallclock `n` последовательных opens
  одного файла с одним паролем. Есть ли variation across opens,
  коррелирующие с file content (caches, recovery fallbacks)?
- **Что есть.** OS page cache после первого open укорачивает
  следующие. Это OS-уровень, content-independent в D2-смысле
  (caches не знают, какие slot'ы какому space'у).
- **Что НЕТ.** Никакого per-open randomness в scan-алгоритме —
  slot-order детерминирован.
- **Verdict.** **Defended** на library-границе. OS-caches
  out-of-scope (threat model кладёт kernel + filesystem внутрь
  trusted base для `T0–T3`; `T2'` противники с kernel-level
  tap'ами явно out of scope).
- **Severity.** INFO.

#### D2-A4. Writer-active сигнал через file-size growth на commit

- **Тир.** T2'.
- **Метод.** У атакующего snapshot'ы в моменты `t1 < t2`. Они
  diff'ят byte-ranges. Размер вырос на `Δ` chunks ⇒ writer был
  активен между `t1` и `t2`.
- **Почему D2 не ломается.** D2 — про *какой space* у writer'а,
  не про *произошла ли запись*. File size growth говорит «*
  какой-то* writer трогал файл»; не pin'ит конкретный space.
- **Bounded by padding.** С `Bucket16Mib` политикой growth
  округлён до bucket-boundaries → намного coarser size-сигнал.
  F-PAD downgrade (D1-A4) flatten'ит обратно к per-commit
  granularity.
- **Verdict.** **Acknowledged out-of-scope (T2').**
  Документировано в threat-model §2 + §4.
- **Severity.** INFO.

#### D2-A5. Commit-history exposure через `Space::commit_history`

- **Тир.** T1 + ключ для `S_A`.
- **Метод.** Атакующий держит пароль `S_A`. Открывает и зовёт
  `commit_history()` — возвращает список seq-значений
  superblock'ов `S_A`. Может ли это раскрыть *что-то* о `S_B`?
- **Почему проваливается.** `commit_history` итерирует только
  superblock'и, decrypt'ящиеся под ключом `S_A`. Superblock'и
  `S_B` падают AEAD, skip'ятся. Seq-последовательность —
  internal `S_A` history; она не включает seq'и `S_B` (они
  encrypted под другим ключом).
- **Возможная cross-leak?** Оба space разделяют *файл*. Если
  оба commit'ятся, оба пишут superblock'и в distinct slot'ах.
  Commit_history `S_A` раскрывает «у этого файла как минимум
  `len(history)` superblock'ов, владеемых `S_A`». Не раскрывает
  существование `S_B`, если key-holder `S_A` также не может
  читать filesystem-уровень metadata (slot count) — что они
  могут (D1-A3, file size). Отношение `len(commit_history) /
  slot_count` раскрывает «какая доля slot'ов — superblock'и
  `S_A`», что намного coarser сигнал, чем TM1 уже даёт.
- **Verdict.** **Defended.** D2 держится.
- **Severity.** INFO.

#### D2-A6. Cross-key chunk-relocation: подделать chunk `S_B` из материала `S_A`

- **Тир.** T3 (compelled-key для `S_A`).
- **Метод.** У атакующего ключ `S_A` + ciphertext chunk'а
  (`nonce ‖ ct ‖ tag`). Могут ли они relocate'нуть или
  repurpose'нуть его, чтобы расшифровать под ключом `S_B` или
  иначе утечь `S_B`?
- **Почему проваливается.**
  1. Per-slot AEAD-key = `BLAKE3-keyed(aead_root, container_id,
     slot)`. `aead_root` derive'ится из `master_key` →
     `Argon2id(password, salt, params)`. Разный пароль → разный
     `aead_root` → разные per-slot ключи для каждого slot'а.
  2. AAD привязывает `container_id ‖ slot`. Тот же container_id
     (оба space в одном файле), но другой slot ⇒ AAD различается.
  3. Подделка валидного `(nonce, ct, tag)` для ключа `S_B`
     требует ключа. AEAD security assumption.
- **Verdict.** **Defended.** Стандартный AEAD + per-slot
  binding.
- **Severity.** INFO.

### Против **I1** (per-chunk integrity)

#### I1-A1. Bit-flip атака на ciphertext chunk'а

- **Тир.** T2.
- **Метод.** Флипнуть один бит где угодно в `nonce ‖ ct ‖ tag`
  chunk'а.
- **Outcome.** Poly1305-MAC verification падает (вероятность
  false-positive: 2⁻¹⁰⁰). `AuthFailed` из
  [`ChunkAead::open`](../../../../crates/hidden-volume/src/crypto/aead.rs).
- **Verdict.** **Defended.** Стандартный AEAD.
- **Severity.** INFO.

#### I1-A2. Slot reorder (swap двух slot ciphertexts)

- **Тир.** T2.
- **Метод.** Поменять местами contents слотов `A` и `B` (один
  контейнер, один space).
- **Outcome.** AAD chunk'а привязывает `container_id ‖ slot`.
  После swap'а, chunk изначально sealed для slot `A` читается
  на slot `B` — AEAD-decrypt использует AAD `(container_id ‖ B)`,
  но seal использовал `(container_id ‖ A)`. MAC падает.
- **Verdict.** **Defended** через AAD slot binding.
- **Severity.** INFO.

#### I1-A3. Cross-container chunk relocation

- **Тир.** T2.
- **Метод.** Копировать chunk из контейнера `X` (slot `S`) в
  контейнер `Y` (slot `S`).
- **Outcome.** Двухслойная защита: AAD включает AD'шный
  `container_id`, так AAD различается (X.id vs Y.id) ⇒ MAC
  падает. И per-slot ключ derive'ится из `container_id`, так
  что даже если AAD совпал, ключ различается.
- **Verdict.** **Defended.** Doubly-bound.
- **Severity.** INFO.

#### I1-A4. Hash-collision на Merkle chain

- **Тир.** T-key-holder.
- **Метод.** Атакующий держит пароль (insider). Конструирует
  два IndexNode payload'а с тем же BLAKE3-256 хэшем.
- **Outcome.** BLAKE3 collision resistance ≥ 128-bit,
  practical collisions infeasible (≥ 2¹²⁸ work для нахождения
  одной).
- **Verdict.** **Defended.** Стандартный криптографический хэш.
- **Severity.** INFO.

### Против **I2** (tail-corruption tolerance)

#### I2-A1. Truncate-tail атака

- **Тир.** T2.
- **Метод.** Truncate'нуть файл на любой byte-boundary mid-
  chunk.
- **Outcome.**
  [`ContainerFile::read_slot`](../../../../crates/hidden-volume/src/container/file.rs)
  вычисляет `slot_count` из file length деленной на `CHUNK_SIZE`;
  trailing partial chunk исключается
  (`(len - HEADER_OFFSET) / CHUNK_SIZE - 0`). Последний
  complete superblock, AEAD-decrypt'ящийся под нашим ключом —
  recovered state.
- **Verdict.** **Defended.** Recovery выбирает highest-seq
  *complete-and-decryptable* superblock; truncation past
  последнего superblock'а — семантически no-op.
- **Severity.** INFO.

#### I2-A2. Tamper одной superblock-replica

- **Тир.** T2.
- **Метод.** Перезаписать байты одной replica garbage'ом.
  Другие replicas того же seq нетронуты.
- **Outcome.**
  [`open/mod.rs::scan_and_recover`](../../../../crates/hidden-volume/src/open/mod.rs)
  итерирует superblock-кандидатов по убыванию seq; same-seq
  replicas asserted bit-identical через `debug_assert` (pass-14
  D4 hardening). Одна tampered replica падает AEAD; следующая
  same-seq replica (или next-highest-seq, если все replicas
  этого seq tampered) побеждает.
- **Verdict.** **Defended.** Replica-redundancy работает.
- **Severity.** INFO.

#### I2-A3. Подделать high-seq superblock

- **Тир.** T2 (без ключа).
- **Метод.** Записать random байты в любой slot-позиции, надеясь,
  что scan выберет их как «high-seq superblock».
- **Outcome.** Без ключа атакующий не может произвести валидный
  AEAD-ciphertext, decrypt'ящийся в `Superblock` plaintext с
  высоким `seq`. Scan-and-recover'овский `try_decrypt`
  возвращает `None` на garbage; только AEAD-валидные кандидаты
  входят в superblock-seq sort.
- **Verdict.** **Defended.** Стандартный AEAD.
- **Severity.** INFO.

### Против **I3** (cross-space isolation)

#### I3-A1. Cross-space chunk relocation внутри одного контейнера

- **Тир.** T3 (compelled-key для `S_A`, хочет утечь `S_B`).
- **Метод.** Прочитать ciphertext `S_B` на slot `B`, записать
  его в slot, pretend-owned-by-`S_A`, надеяться, что
  decrypt'ится под `S_A`.
- **Outcome.** Per-slot AEAD-ключ = `BLAKE3(aead_root,
  container_id, slot)`. `aead_root` `S_A` отличается от
  `aead_root` `S_B` (разные master_key). Даже если AAD
  `(container_id, slot)` были бы forced на совпадение, ключ
  всё ещё различается ⇒ AEAD падает.
- **Verdict.** **Defended.** Per-key isolation.
- **Severity.** INFO.

### Против **R1** (rollback / fork-detection, host-app
cooperative)

#### R1-A1. File-уровень rollback

- **Тир.** T2.
- **Метод.** Атакующий заменяет current файл более ранним
  snapshot'ом.
- **Library-уровень outcome.** Библиотека открывает файл fine;
  current `commit_seq` — более старый seq.
- **Что библиотека не делает.** Self-contained rollback
  detection. R1 говорит: host-app хранит `commit_seq` externally
  (anchor) и re-check'ит на следующем open'е. Если host-app
  делает это, rollback detectable.
- **Verdict.** **Defended на документированной границе.** R1 —
  *cooperative* — library выставляет `commit_seq()` +
  `commit_history()`; host-app обязан использовать их.
  Документировано в [`guide/multi-device.md`](../../guide/multi-device.md).
- **Severity.** INFO.

#### R1-A2. Fork attack — представить файл с другой историей

- **Тир.** T2'.
- **Метод.** Атакующий представляет файл, который *также*
  decrypt'ится под ключом пользователя, но с другой commit-
  историей (например, forked на каком-то seq и сделал другие
  commits).
- **Library outcome.** Library открывает его; commit_history
  показывает forked history. External-anchor seq user'а может
  быть *выше* file's commit_seq (file rollback) или
  *отсутствовать в commit_history* (genuine fork —
  divergent timeline).
- **Verdict.** **Detectable через R1 host-app cooperative
  check.** Bounded diligence'ом host-app.
- **Severity.** INFO.

### Против **M1** (memory hygiene)

#### M1-A1. Heap-residual password после panic

- **Тир.** T-process-memory (memory dump после panic'а).
- **Метод.** Триггернуть panic в FFI-surface (например, через
  malformed input, попавший в unwrap... если такой есть).
- **Outcome.**
  - В release: `panic = "abort"` (workspace Cargo.toml). На
    panic, процесс aborted; ОС reclaim'ит address space.
    Destructor не запускается, но observer также не может
    читать scrubbed memory.
  - В dev/test: `panic = "unwind"`. Destructor'ы запускаются.
    `Zeroizing<Vec<u8>>` на каждом FFI password entry'е
    scrub'ит heap-копию.
  - Actual panic-surface: каждый FFI lock-acquire мапит
    `PoisonError` к `HvError::Internal` (pass-1 D4,
    верифицировано grep'ом по
    [`ffi/lib.rs`](../../../../crates/hidden-volume-ffi/src/lib.rs)).
    Никаких `.unwrap()` / `.expect()` на locks в production
    code.
- **Verdict.** **Defended.** Memory hygiene story
  валидирована в [`audits/memory.md`](memory.md) +
  [`audits/plaintext.md`](plaintext.md). Panic + abort = scrub
  через OS teardown; panic + unwind = scrub через Drop.
- **Severity.** INFO.

#### M1-A2. Cold-boot атака — DRAM remanence

- **Тир.** Physical access с cold-boot capability.
- **Метод.** Power-cycle host-машины быстро, dump DRAM, искать
  key material.
- **Outcome.** Out of scope. Документировано в
  [threat-model §2](../threat-model.md) (RAM-dump атаки
  защищаются full-disk encryption + secure-boot на host-уровне).
- **Verdict.** **Acknowledged out-of-scope.**
- **Severity.** INFO.

### Против **C1** (cancellation safety)

#### C1-A1. Cancel mid-commit между data write и superblock fsync

- **Тир.** T-cooperative-cancel (например, async task
  cancellation).
- **Метод.** Issue `await` cancel между Phase 1 (data write)
  и Phase 3 (superblock fsync).
- **Outcome.** Несколько data-chunks приземляются на диск, но
  unreachable из любого superblock'а. На reopen
  `vacuum_orphans` scrub'ит их (IndexNode orphan'ы), и
  `vacuum_data_batches` обрабатывает DataBatch orphan'ы (с
  explicit-call документированным для post-commit-error
  случая). Superblock state pre-cancel сохранён.
- **Verdict.** **Defended** через 3-fsync протокол.
- **Severity.** INFO.

#### C1-A2. Cancel после superblock fsync, но до padding step'а

- **Тир.** T-cooperative-cancel.
- **Метод.** Cancel во время post-commit garbage-padding step'а.
- **Outcome.** Pass-18 M1 hardening: padding failures stash'атся
  в `last_padding_error`, и `Ok(new_seq)` возвращается.
  Durability не downgrade'ится. Privacy-padding loss bounded
  этим одним commit'ом, observable multi-snapshot противникам
  (T2'); то же, что F-PAD-tamper outcome для этого commit'а.
- **Verdict.** **Defended** на durability-слое; bounded
  privacy degradation acknowledged.
- **Severity.** INFO.

### Format / parsing surface (decode safety)

#### F-A1. Argon2 OOM через header tamper (closed pre-pass)

- **Тир.** T2.
- **Метод.** Tamper Argon2Params в extreme значения
  (`m_cost_kib = u32::MAX`).
- **Outcome.** `Argon2Params::validate` отвергает с explicit
  caps (`m_cost_kib ≤ 1 GiB`, `t_cost ≤ 100`, `p_cost ≤ 64`,
  `format_version == 2`, reserved биты 24..32 == 0). Closed
  в audit pass 1 (D1).
- **Verdict.** **Defended.**
- **Severity.** INFO.

#### F-A2. zstd compression bomb в DataBatch

- **Тир.** T-key-holder ИЛИ T-malformed-AEAD-valid (если writer
  был buggy и произвёл valid-AEAD bomb).
- **Метод.** Сконструировать `DataBatch` chunk, чей 4040-байт
  ciphertext (compressed) decompress'ится в гигабайты zeros.
- **Outcome.** Pass-11 M5: `decode_batch` использует streaming
  `Read::take(MAX_DECODED_BATCH_LEN + 1) ≈ 8.4 MiB`. Bomb
  hit'ит cap → `Error::Malformed("batch decompressed size
  exceeds cap")`.
- **Verdict.** **Defended.**
- **Severity.** INFO.

#### F-A3. B+ tree node-count allocation amplifier

- **Тир.** То же, что F-A2.
- **Метод.** Сконструировать IndexNode payload, claim'ящий
  `num = u16::MAX` entries с under-capacity body.
- **Outcome.** Pass-5 G2/G3: pre-allocation bound check
  `num.saturating_mul(MIN_*_BYTES) ≤ bytes.len() - HEADER_LEN`
  в обоих `LeafNode::decode` и `InternalNode::decode`.
  Отвергает до `Vec::with_capacity(num)` allocation.
- **Verdict.** **Defended.**
- **Severity.** INFO.

#### F-A4. Open-scan budget bypass

- **Тир.** T2.
- **Метод.** Inflate файл к 100 GiB для форсирования 100-GB
  AEAD-scan-цикла на open'е.
- **Outcome.** Pass-16 TM1-budget: `MAX_OPEN_SCAN_CHUNKS = 16 ×
  1024 × 1024 ≈ 16M` (= 64 GiB при 4 KiB chunks). Все три
  scan entry-точки (sequential, parallel, mmap) gate через
  `check_scan_budget(total)` перед циклом. Симметричный
  `check_write_budget` на write side'е
  ([`container/file.rs`](../../../../crates/hidden-volume/src/container/file.rs)
  `append_slot` + `append_garbage_chunks`).
- **Verdict.** **Defended.**
- **Severity.** INFO.

#### F-A5. Cycle в B+ tree (key-holder self-DoS)

- **Тир.** T-key-holder ИЛИ writer-bug regression.
- **Метод.** Key-holder создаёт InternalNode на slot A,
  указывающий на InternalNode на slot B, указывающий обратно
  на A. Чтение дерева → бесконечная рекурсия → stack
  overflow.
- **Outcome.** Writer-side инвариант гарантирует depth ≤ 2,
  потому что `write_tree_for_namespace`
  ([`space/commit.rs`](../../../../crates/hidden-volume/src/space/commit.rs))
  emit'ит только Leaf или one-level-of-Internal-over-Leaves.
  Рекурсивные walker'ы (`collect_leaves`, `count_leaves`,
  `iter_log_*`, `vacuum_orphans::collect_tree_chunks_into_set`)
  не имеют visited-set'а или depth-cap'а.
- **`verify_integrity`** *cycle-resistant* — Merkle hash-chain
  требует `H(B) = recorded_child_hash_in_A` и `H(A) =
  recorded_child_hash_in_B`, что форсирует BLAKE3 preimage
  атаку для конструирования. Так что атакующий без preimage
  capability не может сделать cycle, проходящий
  `verify_integrity`.
- **Threat-model статус.** Key-holder *не* defended-against
  противник в этой библиотеке (он — legitimate owner данных;
  ничего в scope не говорит, что мы защищаем maintainer'а от
  себя самого). Writer-bug regression был бы self-foot-gun.
- **Defense-in-depth идея (deferred).** Добавить depth-cap
  (например, `MAX_TREE_DEPTH = 3`) проверку в рекурсивных
  walker'ах. Cheap и ловит и adversarial key-holder'а, и любую
  future writer-regression. Tracked как v1.x defense-in-depth
  в [self-audit.md §5](self-audit.md).
- **Verdict.** **Acknowledged, out-of-strict-threat-model,
  defense-in-depth opportunity.**
- **Severity.** INFO.

### Build / supply-chain

#### S-A1. Подделать signed release без OIDC-identity workflow'а

- **Тир.** Supply-chain.
- **Метод.** Атакующий пытается произвести
  `SHA256SUMS.cosign.bundle`, верифицирующийся под
  `https://github.com/veilnetwork/hidden-volume/.github/workflows/release.yml@refs/tags/v.*`
  identity-регулярным выражением без фактического запуска
  workflow'а.
- **Outcome.** Cosign keyless привязывает подписи к OIDC-токену
  *фактического* workflow-run'а, с подписью записанной в
  публичный Rekor transparency-log. Подделка требует одного из:
  (a) compromise OIDC issuer'а (`token.actions.githubusercontent.com`),
  (b) compromise Sigstore Fulcio's signing CA,
  (c) compromise Rekor's append-only log.
  Каждый — существенная атака public-infrastructure с
  transparency-log сигналом.
- **Verdict.** **Defended на Sigstore transparency уровне.**
- **Severity.** INFO.

#### S-A2. Workflow-file tamper для подписи attacker-кода

- **Тир.** Repository write access.
- **Метод.** PR, edit'ящий `.github/workflows/release.yml` для
  билда attacker-кода, запуска cosign-sign, attach'а к release'у.
- **Outcome.** Sigstore certificate включает *workflow file path
  + git ref*. Tampered workflow на теге всё ещё подпишет как
  `release.yml@refs/tags/vX.Y.Z`. Защита:
  - Repo write-access control (maintainer/GitHub).
  - Public diff `release.yml` — любое изменение visible в
    commit-истории.
  - Transparency-log записывает *что* было подписано;
    downstream verifier'ы могут re-derive SHA256 workflow-файла
    на tag's commit SHA и подтвердить совпадение с expected
    content.
- **Verdict.** **Bounded repo access control + transparency.**
  Downstream verifier, paranoid про workflow-tamper, должен
  сравнить `release.yml` на tag's commit SHA против trusted
  reference (например, той версии, которую они в последний раз
  reviewed).
- **Severity.** INFO.

## Summary table

| ID | Атака | Тир | Verdict | Severity |
|---|---|---|---|---|
| D1-A1 | Byte-distribution distinguisher | T1 | Defended | INFO |
| D1-A2 | Header fingerprint | T1 | Acknowledged out-of-scope | INFO |
| D1-A3 | Slot count через `stat` | T1 | Acknowledged out-of-scope | INFO |
| D1-A4 | Padding-policy downgrade (F-PAD) | T2 | Acknowledged out-of-scope | INFO |
| D1-A5 | Argon2-param weaken-then-brute | T2 | Defended | INFO |
| D1-A6 | Header-padding-bytes timing reveal | T1 | Defended | INFO |
| **D1-LOW1** | **`self-audit.md` «64-byte» doc-inconsistency** | — | **Fix в этом коммите** | **LOW** |
| D2-A1 | TM1 timing oracle | T1 + side-channel | Acknowledged + mitigation-tracked | INFO |
| D2-A2 | Wrong-pwd vs not-our-chunk | T1 | Defended | INFO |
| D2-A3 | Repeated-open variance | T1 + side-channel | Defended | INFO |
| D2-A4 | Writer-active сигнал | T2' | Acknowledged out-of-scope | INFO |
| D2-A5 | `commit_history` exposure | T1 + key | Defended | INFO |
| D2-A6 | Cross-key chunk forgery | T3 | Defended | INFO |
| I1-A1 | Bit-flip | T2 | Defended | INFO |
| I1-A2 | Slot reorder | T2 | Defended | INFO |
| I1-A3 | Cross-container relocation | T2 | Defended | INFO |
| I1-A4 | Merkle hash collision | T-key-holder | Defended | INFO |
| I2-A1 | Tail truncate | T2 | Defended | INFO |
| I2-A2 | Одна replica tamper | T2 | Defended | INFO |
| I2-A3 | Forge high-seq superblock | T2 | Defended | INFO |
| I3-A1 | Cross-space chunk relocation | T3 | Defended | INFO |
| R1-A1 | File rollback | T2 | Defended на host-app границе | INFO |
| R1-A2 | Fork (divergent timeline) | T2' | Defended на host-app границе | INFO |
| M1-A1 | Heap-residual password после panic | T-process-memory | Defended | INFO |
| M1-A2 | Cold-boot RAM dump | Physical | Acknowledged out-of-scope | INFO |
| C1-A1 | Cancel mid-commit | T-cancel | Defended | INFO |
| C1-A2 | Cancel mid-padding | T-cancel | Defended (durability) | INFO |
| F-A1 | Argon2 OOM через header tamper | T2 | Defended (pass 1 D1) | INFO |
| F-A2 | zstd compression bomb | T-key-holder | Defended (pass 11 M5) | INFO |
| F-A3 | B+ tree alloc amplifier | T-key-holder | Defended (pass 5 G2/G3) | INFO |
| F-A4 | Open-scan budget bypass | T2 | Defended (pass 16) | INFO |
| F-A5 | B+ tree cycle | T-key-holder | Out-of-strict-model; defense-in-depth opportunity | INFO |
| S-A1 | Forge signed release | Supply-chain | Defended (Sigstore transparency) | INFO |
| S-A2 | Workflow tamper | Repo-access | Bounded repo access control + transparency | INFO |

**Подсчёты:** 0 CRITICAL, 0 HIGH, 0 MEDIUM, 1 LOW (включён в этот
коммит), остальные INFO.

## Что этот pass НЕ покрыл

Намеренно отложено к более поздним специализированным pass'ам
(уже scheduled — см. plan'а user'а + [self-audit.md §9](self-audit.md)):

- **Primitive-level review**: Argon2id parameter choice vs
  литературы 2026, ChaCha20 key-schedule edge cases, BLAKE3-
  keyed domain-separation analysis. (Adversarial pass брал
  примитивы как black boxes; primitive-level pass challenge'нет
  сами примитивы.)
- **Side-channel surface map (beyond TM1)**: cache-timing в
  AEAD path, branch prediction в `decode_*` функциях,
  allocator behaviour на failed путях.
- **Format fuzzing analysis**: формальная boundary-enumeration
  каждой `decode` функции с adversarial inputs на каждом
  boundary.
- **Threat-model challenge**: полная T2/T2'/T3 step-by-step
  attack construction с attacker-stance narrative.
