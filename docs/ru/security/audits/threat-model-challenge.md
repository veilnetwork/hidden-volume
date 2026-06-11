# Threat-model challenge

**Дата.** 2026-05-28. **Pass.** 5 из 5 — финальный pass серии
deeper-review. **Reviewer.** LLM-assisted. **Stance.** Narrative.
Pass 1 перечислил ~34 atomic-атаки defensively; этот pass берёт
меньшее число *full scenario'ев* и проходит каждый end-to-end как
конкретного adversary с конкретными capabilities, step-by-step,
наблюдая, что они узнают на каждом этапе и где claim'ы threat-
model держатся, либо явно punt'ятся.

## Методология

Pass 1 ([adversarial-stance.md](adversarial-stance.md)) был
analytical: каждый row — single attack hypothesis, verdict
записан, дальше. Этот pass — narrative: каждая section — история
про конкретного adversary с named capabilities, проходящего, что
они могут делать в течение часов или дней. Две stance'и должны
сходиться там, где overlap'ятся; narrative-формат surfaces
*cumulative* leaks, которые atomic-enumeration может пропустить.

References инвариантов из [threat-model.md](../threat-model.md)
§3 (D1, D2, I1, I2, I3, R1, M1, C1) и тиров противника из §2
(T1, T2, T2', T3).

Severity-legend без изменений от prior pass'ей.

## Headline

**0 CRITICAL / 0 HIGH / 0 MEDIUM / 0 LOW / 0 INFO находок.**

Narrative-pass подтверждает то, что analytical-pass нашёл: каждый
in-scope adversary-тир имеет свой claim либо defended на library-
boundary, либо held host-app cooperation per документированному
contract. Два cumulative-leak вектора, которые narrative-format
иногда surfaces — (a) multi-stage adversary, alternating
snapshot, key extraction, и follow-up snapshot, и (b) patient
observer, watching metadata evolve over time — уже перечислены в
adversarial-stance D2-A4, D2-A5, и R1-A1/A2, с trade-off'ами
задокументированными в [threat-model §4](../threat-model.md).

## Scenario A — Border-seizure телефона (T2 single-snapshot, no compelled key yet)

**Setup.** Телефон traveller'а изъят на границе. Customs officer
забирает device в lab, делает forensic image внутреннего
storage, затем возвращает телефон. Traveller не задержан;
password не compelled.

**Adversary capabilities.** T2 — single snapshot container'а
(и любых других файлов на device).

**Step-by-step.**

1. **Officer парсит container-файл.** Замечает 80-байтный
   structured prefix, матчащий `hidden-volume` cleartext-header
   layout: 32-байт high-entropy и 16 байт, выглядящих как
   Argon2id-параметры (`m_cost_kib`, `t_cost`, `p_cost`, version).
   Если знают формат, узнают «это deniable-storage контейнер».
   - **Что узнают.** Файл — `hidden-volume` контейнер. Могут
     прочесть: salt (32 random байта), Argon2-параметры
     (например, `m=64 MiB, t=3, p=1, format_version=3,
     padding=Bucket16Mib`).
   - **Что defended.** D1 explicitly carves out 48-byte
     cleartext header (v3; было 80-byte в v2 — fingerprint
     `container_id` по offset 32..64 закрыт v3 #10 per-space
     deriviром). То, что «это контейнер» known — acknowledged
     out-of-scope в [threat-model §3.D1](../threat-model.md).
     Полное устранение «это контейнер» surface'а потребовало бы
     password-derived'ного header'а (никакой фиксированной
     cleartext-раскладки), что является изменением v4-класса,
     пока не зафиксированным.

2. **Officer измеряет file size.** Вычисляют
   `slot_count = (file_size - 4096) / 4096`. Скажем, 50000
   слотов ≈ 200 MiB.
   - **Что узнают.** Approximate storage usage.
   - **Что defended.** File size unavoidably public. Padding-
     политика `Bucket16Mib` округлила размер до 16 MiB
     границы, так получают coarse-grained usage info, не exact
     content count.

3. **Officer пытается byte-level statistical analysis** байтов
   80..end. Прогоняют entropy tests, autocorrelation, frequency-
   distribution.
   - **Что узнают.** Ничего. XChaCha20-Poly1305 ciphertext +
     uniform random garbage + random padding computationally
     неотличимы от uniform random под стандартным ChaCha20
     assumption'ом.
   - **Defended.** D1.

4. **Officer пытается enumerate spaces.** Без пароля они не
   могут derive никакой per-slot AEAD-ключ. Каждый chunk
   неотличим. У них нет способа считать или локализовать
   spaces.
   - **Defended.** D2 (unobservability «есть ли тут space
     вообще?» расширяется к «сколько» и «где»).

5. **Officer пытается offline brute-force** common-паролей
   (например, день рождения пользователя, common patterns)
   против любого random chunk'а в файле.
   - **Что происходит.** Каждый guess требует прогона
     `Argon2id(guess, salt, params)` для derive `master_key`,
     затем `master_key → aead_root → derive_chunk_key →
     ChunkAead::open` на chunk'е. При `m=64 MiB, t=3, p=1`,
     один guess занимает ~700ms на lab-железе. Dictionary
     10⁹ паролей занимает ~22 года на одной машине. GPU-
     кластеры снижают это в тысячи раз, но Argon2id memory-
     hard свойство ограничивает GPU parallelism (12 KB GPU
     shared memory per stream multiprocessor; 64 MiB per
     Argon2 call → ~5K streams max per GPU).
   - **Practical conclusion.** Offline brute-force gated
     strength пользовательского пароля, с Argon2id work-
     factor'ом, amplifying cost.

6. **Officer ищет файл «magic bytes»**, suggesting known
   plaintext at known offset (например, `Plaintext::MAGIC`
   `b"HVC1"`).
   - **Что находят.** Magic *внутри* AEAD-protected
     plaintext, никогда не exposed в ciphertext. Находят
     ничего.
   - **Defended.** D1.

**Scenario A conclusion.** Deniability traveller'а держится.
Officer узнаёт:
- файл — deniable-storage контейнер (acknowledged);
- approximate storage usage (acknowledged);
- ничего о actual content, number of spaces, или даже
  whether файл содержит *любые* live spaces.

Их единственный path forward — compel password (→ scenario C).

## Scenario B — Возвращающийся traveller (T2', snapshot diff over time)

**Setup.** Та же граница, но шесть месяцев спустя traveller
возвращается. Customs lab всё ещё имеет original forensic image;
делают свежий.

**Adversary capabilities.** T2' — два snapshot'а в известные
моменты.

**Step-by-step.**

1. **Lab diff'ит два snapshot'а byte-by-byte.**
   - **Что наблюдают.** Некоторые byte-ranges unchanged
     (chunks, которые не были переписаны). Другие differ —
     range slot'ов `[N1, N2)` новый (файл вырос на N2-N1
     chunks с первого snapshot'а).
   - **Defended.** D1 всё ещё держится *внутри* каждого
     snapshot'а. T2' explicitly out of scope per
     [threat-model §2 + §4](../threat-model.md): «single-
     snapshot indistinguishability НЕ extends к byte-diff
     over time».

2. **Lab оценивает, сколько commits произошло.** С политикой
   padding `Bucket16Mib` каждое growth commit'а округляется
   вверх. Так lab видит aggregate growth в 16 MiB
   increment'ах и не может pin per-commit boundaries.
   - **Что наблюдают.** Примерно «пользователь написал
     между 5 и 10 commits», скажем.
   - **Defended.** D1 invariant per-snapshot
     indistinguishability не нарушен. T2'-level leak —
     acknowledged.

3. **Lab пытается идентифицировать, какие slots новые vs
   updated-in-place.** Эта библиотека append-only (Inv-W1) —
   slots никогда не reused. Так newly-grown slots на file
   tail; older slots untouched.
   - **Что наблюдают.** Append-only growth pattern
     detectable (файл просто стал длиннее). Older content
     «fingerprinted» через byte-ranges, матчащиеся первый
     snapshot, unchanged.
   - **Defended.** Append-only design-explicit (DESIGN §9).
     Это contributes к T2' leak; mitigated `vacuum_orphans`
     + `compact_known`, переписывающим весь файл со свежим
     `container_id`.

4. **Lab спекулирует, какой space active.** Видят, *какой-то*
   space записывается. Не могут identify, какому паролю
   соответствует без compelled-key.
   - **Что defended.** D2 — не могут доказать «space B
     существует из-за этого growth». Growth мог бы equally
     быть «garbage padding под F-PAD upgrade», «commits
     space A» или «commits space B».

5. **Lab combines с metadata snooping.** Если бы имели доступ
   к mtime/atime device через тот же forensic image, знали бы
   *когда* writes happened (correlatable с known activity-
   временами пользователя).
   - **Что defended на library-layer.** Ничего — mtime —
     filesystem-level, observed at snapshot.
   - **Documented out-of-scope.** Host-app должен mount
     контейнер на `noatime`, если mtime correlation — part
     of adversary model.

**Scenario B conclusion.** T2' acknowledged out-of-scope.
Narrative подтверждает: leak — «пользователь написал *что-то*
в каких-то интервалах», не «что написал, в каком space, с
каким паролем». Cumulative leak не превышает что analytical
adversarial-stance D2-A4 (writer-active signal) предсказал.

## Scenario C — Compelled-password disclosure (T3, single space)

**Setup.** Traveller задержан. Под давлением раскрывает пароль
к space `S_A`. НЕ раскрывает `S_B` (который держит genuinely
sensitive content). Officer держит forensic image и теперь
пароль `S_A`.

**Adversary capabilities.** T3 для `S_A`; T2 (file image)
overall.

**Step-by-step.**

1. **Officer открывает space `S_A`.** `Container::open_space(path,
   S_A_password)` succeeds. Читают всё в `S_A`: contacts,
   settings, message log, etc.
   - **Что узнают.** Полный content `S_A`. By design — у них
     есть key.
   - **Defended на границе.** T3-for-S_A *не* defended; claim
     D2 в том, что disclosure content'а `S_A` не утекает
     `S_B`.

2. **Officer enumerate'ит commit_history `S_A`.** Получают
   список seq superblock'ов `S_A`.
   - **Что узнают.** Commit history `S_A` (R1 anchor data).
     НЕ узнают commit history `S_B` — его superblock'и
     падают AEAD под ключом `S_A`.
   - **Defended.** D2-A5 в adversarial-stance pass'е.

3. **Officer пытается идентифицировать slots `S_B`.** Они
   time'ят open-call (это TM1 oracle).
   - **Что узнают.** Approximate `frac_owned` для `S_A`.
     Скажем, `S_A` владеет 30% слотов. Остальные 70%
     поделены между «другим space» и «garbage padding» — но
     библиотека treat'ит оба identically (AEAD падает
     одинаково для «not our chunk» и «uniform random
     padding»).
   - **Defended.** TM1 leak quantified (±10-20% on
     `frac_owned`) и это тот же leak, что D1-A3 file-size
     visibility, plus per-chunk granularity «не owned нами».

4. **Officer asks: «есть ли другой space?»** Пробуют common
   alternative passwords (другие пароли пользователя, family-
   member names, dates).
   - **Что происходит.** Каждый guess re-runs Argon2id и
     пытается open. Каждый занимает ~700ms. Каждый, что
     fails, неотличим от «no space matches that password».
   - **Defended.** D2 — нет observable difference между
     «guessed password matches no space в этом файле» и
     «guessed password matches space, но он empty».

5. **Officer demands ВТОРОЙ пароль.** Пользователь — armed
   deniability-историей — говорит «нет второго пароля, у меня
   только тот, что я дал, и unowned 70% — просто garbage
   padding from my paranoid setting».
   - **Что это backs up.**
     - Padding-политика `Bucket16Mib` IS в cleartext header
       (officer её видит). Она бы, in fact, generate large
       garbage runs.
     - Библиотека не делает out-of-band declaration «у меня
       N spaces». Каждый chunk, что AEAD-fails под ключом
       `S_A`, — behaviorally, garbage padding.
     - TM1 timing leak не различает «chunk другого space» от
       «garbage padding chunk».
   - **Что officer не может сделать.** Доказать, что user
     lying. «Deniability» — не «файл выглядит, как будто
     нет другого space» — это «файл consistent с историей
     user'а, что нет другого space, и нет cryptographic
     evidence to refute it».
   - **Defended.** D2, by design.

6. **Officer забирает device домой для «extended analysis».**
   У них unlimited time + forensic image + пароль `S_A`.
   - **Они пробуют каждый plausible second-password.**
     Argon2id work factor amplifies cost. Получают ничего
     matchable.
   - **Они пробуют sophisticated TM1 analysis.** Измеряют
     per-chunk MAC-fail-vs-pass timing across unowned slots.
     С достаточным resolution могли бы partition unowned
     slots в «MAC этого chunk'а verifies под КАКИМ-ТО
     паролем» vs «garbage». НО: для verify MAC под КАКИМ-
     ТО паролем им бы нужно guess пароль — обратно к brute-
     force-Argon2id.
   - **Defended.** D2, даже под unlimited offline analysis,
     given strong second-password.

**Scenario C conclusion.** D2 держится на library-boundary.
Officer узнаёт content'ы `S_A` и не может доказать существование
`S_B`. Deniability-история для user'а («у меня только один
space; остальное — padding») cryptographically supported.

Caveats, которые user (и host-app) должны respect:
- Если пароль `S_B` слабый, offline brute-force eventually его
  находит.
- Если host-app записывает «у user два spaces» elsewhere
  (например, UI-cache, backup manifest), officer читает это
  вместо.
- Если у user есть другое device elsewhere, держащее R1 anchor
  к `commit_seq` `S_B`, officer может compel и его.

Это всё host-app's domain (см.
[multi-device.md](../../guide/multi-device.md)).

## Scenario D — Compromised host-app (T-host-app malicious)

**Setup.** User устанавливает обновлённую версию своего
messenger app. Update silently модифицирован adversary
(например, через supply-chain атаку на app-store, или
malicious-app, pretending to be legitimate one). Container-
файл сам intact.

**Adversary capabilities.** Полный контроль host-process в
runtime'е. Библиотека loaded by them и called с их arguments.

**Step-by-step.**

1. **Malicious app просит user'а пароль.** User вводит
   пароль `S_A`. App capture'ит, также derive'ит пароль `S_B`
   через whatever user вводит next, etc.
   - **Что defended.** Ничего на library-layer — пароль в
     host-app address-space. Discipline `Zeroizing` библиотеки
     scrub'ит *копию библиотеки*, но host-app's копия — их to
     manage.
   - **Documented out-of-scope.** Host-app trust required
     threat-model §1.3.

2. **Malicious app exfiltrate'ит container-файл.** Прямой
   filesystem access.
   - **Что defended.** Ничего. Файл на диске, host-app
     читает его.

3. **Malicious app пытается forge «extra space», appearing to
   принадлежать user'у.** У них есть пароль `S_B`
   (extracted in step 1). Могут писать new chunks под
   ключом `S_B`. Но superblock-chain файла AEAD-integrity-
   protected; не могут писать fake «old commit» в `S_B` без
   ключа `S_B` — который у них есть. Так что CAN forge
   anything they want с captured паролем.
   - **Что defended.** Forge-resistance против атакующего
     *без* ключа (T2/T2' adversaries). Не против host-app,
     имеющего ключ.
   - **Documented out-of-scope.** «Host-app trust required.»

**Scenario D conclusion.** Out-of-scope adversary class. Library
не может защитить против malicious host-app с user-паролем.
Mitigation на host-app supply-chain слое (reproducible signed
builds, code signatures, app-store review). Library *contributes*
к этому слою через свои [reproducible signed releases](../../contributing/verifying-release.md).

## Scenario E — Patient kernel-level adversary

**Setup.** Lab-class adversary с kernel-level access к device
(например, rooted phone, bypassed secure-boot). Наблюдают, как
user открывает container, watch каждый syscall, каждый page-
fault, каждый cache-line access.

**Adversary capabilities.** Beyond T2/T3 — observability в
running-process на kernel + microarchitecture level.

**Step-by-step.**

1. **Kernel-level observer логирует каждый `pread(fd, buf,
   4096, offset)` call** в течение open'а.
   - **Что наблюдают.** Slot-access-order в течение scan'а.
     В sequential mode каждый slot читается once in order. В
     parallel mode slot-order non-deterministic per thread. В
     mmap mode slots accessed как page-faults.

2. **Они correlate access timing с TM1.** У них per-chunk
   timing resolution (не just aggregate open-time).
   - **Что наблюдают.** Per-slot MAC-fail-vs-pass timing.
     Могут identify «which specific slots — space этого
     user'а» — TM1 на chunk granularity.
   - **Что defended.** Ничего — kernel-level cache/timing
     attacks explicitly out-of-scope
     ([threat-model §1.3](../threat-model.md): «OS / firmware /
     CPU / RAM» все в trusted base).
   - **Documented.** Это rationale для trusted base:
     deniable-storage library не может защитить против
     adversary с full machine access без замечания user'ом.

3. **Они dump'ят RAM в течение open'а** и extract'ят master-
   key из heap.
   - **Что defended.** Ничего на live-memory phase.
     Discipline `Zeroizing` библиотеки scrub'ит после того,
     как ключ no longer needed, но во время active use ключ
     в памяти.
   - **Documented out-of-scope.** «Forensic RAM dumps —
     защищаются full-disk encryption + secure boot на host-
     level.»

**Scenario E conclusion.** Kernel-level adversaries out-of-
scope. Library не делает claim против этого тира и delegate'ит
OS / secure-boot / TPM / full-disk-encryption слоям.

## Scenario F — Multi-stage cumulative leak

**Setup.** Patient adversary execute'ит scenarios A → B → C → A
в последовательности в течение года. Snapshot в январе,
snapshot в июле (diff), compelled `S_A` password в августе,
snapshot в октябре.

**Adversary capabilities.** Cumulative T1 + T2' + T3.

**Step-by-step combined analysis.**

1. **Январский snapshot.** Знают: файл — hidden-volume
   контейнер, ~200 MiB, header-параметры (Argon2 `m=64 MiB`,
   `Bucket16Mib` padding). Conclusions Scenario A.

2. **Июльский snapshot diff.** Знают дополнительно: файл
   вырос на ~32 MiB между январём и июлем (округлено вверх
   `Bucket16Mib`), append-only growth pattern, slot-range
   `[Jan_count, Jul_count)` «new since January». Conclusions
   Scenario B.

3. **Августовский compelled-password (S_A).** Знают
   дополнительно: полный content `S_A`, commit-history `S_A`,
   ~`S_A`-frac от TM1.
   - **Cross-reference с B.** Cross-reference commits `S_A`-
     since-January с July diff. Если `S_A` contribution к
     file-growth — скажем, 10 MiB из 32 MiB grown,
     оставшиеся 22 MiB либо garbage padding ЛИБО commits
     `S_B`.
   - **Bucket16Mib + grown-by-32MiB.** Политика Bucket16Mib
     округляет каждый commit вверх до 16 MiB. 10 MiB real-
     data `S_A` могло account'ить ~16 MiB file-growth (один
     bucket). Оставшиеся 16 MiB *могли бы* быть commits
     `S_B`, ИЛИ additional `S_A` activity, fit within
     bucket boundary, ИЛИ (если F-PAD-downgrade happened in
     between) variable padding.
   - **Concrete leak.** Aggregate file-growth `Δ` vs
     `S_A` accounted commits ≈ «$\Delta$ - S_A_contrib» →
     upper bound на `S_B` activity. Bucketed padding
     obscures это; coarser per-commit'а, но не invisible.

4. **Октябрьский snapshot.** Тот же analysis что B → C,
   refined ещё 3-month window'ом.

**Cumulative conclusion.** Patient T2' + T3 adversary CAN, over
time, build probabilistic argument, что «user был active с
другим space», subtracting accounted commits `S_A` от total
file-growth. Они не могут identify *что* `S_B` contains или
*prove* его существование в cryptographic-смысле — remainder
мог бы equally быть aggressive padding под другой политикой.
Это T2'-территория by definition, с deniability preserved на
*content* level'е, но eroded на *activity-existence* level'е.

**Defended at boundary.** Strict-claim D2 («cannot prove
existence») держится: user всегда может сказать «я изменил
padding-политику на aggressive в марте; это объясняет extra
growth». Cryptographic story не refutes это. Probabilistic
inference — T2' acknowledged-out-of-scope leak.

## Scenario G — Adversary с контролем одного из нескольких devices

**Setup.** User sync'ит контейнер across two devices (например,
phone + laptop) через какой-то host-app sync-механизм.
Adversary controls laptop полностью (T-host-app на laptop'е).

**Adversary capabilities.** Полный контроль laptop; T3-for-
spaces laptop'а; пассивно observe sync-трафик, если app routes
через cloud.

**Step-by-step.**

1. **Adversary читает laptop-пароль user'а.** Keylog'ят его.

2. **Они открывают synced контейнер на laptop'е.** Получают
   content `S_A` с laptop-стороны.

3. **Они observe sync-traffic.** Если host-app делает file-
   level sync (rsync-style), видят каждый ciphertext chunk'а
   на wire'е — но никакого plaintext'а (chunks AEAD).

4. **Они ждут, когда телефон user'а commit'нёт.** Sync
   приносит новые chunks к laptop'у. Adversary observe'ит file
   size growth.
   - **Что узнают.** Тот же T2' growth pattern что scenario
     B.

5. **R1 anchor check.** Если host-app использует R1-anchor'ы
   (commit_seq externally stored), и laptop adversary'а имеет
   access к anchor-store, могут detect rollback / fork атаки
   между phone и laptop'ом.
   - **Что defended.** R1 — host-app-cooperative property;
     library экспозит примитивы, host-app stores и checks
     anchors. Документировано в
     [multi-device.md](../../guide/multi-device.md).

**Scenario G conclusion.** Multi-device threat model — host-
app responsibility per документированному contract'у. Library
делает свою часть: chunks AEAD-protected end-to-end,
container_id уникален per container (так cross-container
relocation падает), `commit_seq` exposed для anchor checks.
Library не делает, и не может, защитить против fully-
compromised endpoint'а.

## Cross-scenario findings

**Cumulative leaks, которые narrative-pass surfaces (никаких
new):**

1. **File-growth-minus-accounted-commits → upper-bound
   S_B-activity.** Scenario F. Уже covered D2-A4 (writer-
   active signal) + acknowledged T2'-out-of-scope. Никаких new
   findings.
2. **R1 anchor reliance on host-app honesty.** Scenarios G.
   Уже документировано в multi-device.md. Никаких new
   findings.
3. **TM1 at chunk-granularity для kernel-level observers.**
   Scenario E. Уже noted в side-channel-surface T-9 + M-3
   как kernel-level out-of-scope. Никаких new findings.

**Scenarios, где library actively помогает:**

- Reproducible signed builds (cosign keyless) defend против
  scenario D (compromised host-app в *install* time, before user
  enters пароль). Verifiable per
  [verifying-release.md](../../contributing/verifying-release.md).
- «No observable difference между not-our-chunk и garbage»
  свойство (TM1's granularity limit) — actual cryptographic
  backing для deniability-истории в scenario C.

## Что этот pass completes

Pass 5 closes deeper-review series scheduled в
[self-audit.md §9](self-audit.md). Серия produced:

| Pass | Файл | Headline |
|---|---|---|
| 1 | [adversarial-stance.md](adversarial-stance.md) | 34 atomic-атаки vs D1/D2/I1-3/R1/M1/C1; 0 critical/high/medium, 1 LOW (dossier doc-inconsistency, fixed в том же commit'е) |
| 2 | [primitive-level.md](primitive-level.md) | Argon2/ChaCha/BLAKE3/getrandom/zeroize/subtle vs 2026 literature; 0 critical/high/medium, 2 LOW (Argon2Params::MIN ниже OWASP — doc warning applied; label-length convention — defense-in-depth opp) |
| 3 | [side-channel-surface.md](side-channel-surface.md) | 24 канала classified; 0 находок; 2 INFO (constant-time decode shell, TM1 multi-variant bench) |
| 4 | [format-fuzzing.md](format-fuzzing.md) | 9 decoder'ов + 2 discriminator parser'а, каждый boundary class замаплен к defender + test; 0 uncovered; 1 INFO (CI fuzz-gate — continue-on-error) |
| 5 | [threat-model-challenge.md](threat-model-challenge.md) | 7 narrative-scenario'ев (border seizure, snapshot diff, compelled-password, malicious host-app, kernel-level observer, multi-stage cumulative, multi-device); 0 new findings; подтверждает analytical results в narrative-форме |

**Cross-series total:** 0 CRITICAL, 0 HIGH, 0 MEDIUM, 3 LOW
(все в passes 1-2, все либо fixed in-pass, либо tied к v3
format bump).

## Recommended actions (carried forward to v1.x)

Consolidated list из passes 1-5, в порядке effort'а:

1. **P-LOW1 rustdoc warning на `Argon2Params::MIN`** — applied
   в pass 2 commit `df9dbc8`. Done.
2. **D1-LOW1 dossier «64-byte» → «80-byte» fix** — applied в
   pass 1 commit `230d40a`. Done.
3. **SC-INFO1 constant-time decode shell** — defense-in-depth,
   ~4 KiB extra work per chunk per decode call. Closes key-
   holder-self-DoS only. Tracked для v1.x.
4. **SC-INFO2 TM1 bench across feature variants** — расширить
   `benches/timing_oracle.rs` для покрытия parallel-scan +
   mmap. Documentation only. Tracked для v1.x.
5. **F-A5 cycle-detection в walker'ах** — defense-in-depth
   depth-cap в `collect_leaves` / `count_leaves` /
   `iter_log_*` / `vacuum_orphans` recursive paths. Closes
   только writer-bug-regression + adversarial-key-holder
   scenarios. Tracked для v1.x.
6. **P-LOW2 label-length domain-separation hardening** — tied
   к v3 format bump (любое length-prefix или kind-tag byte
   change KDF chain'а — format-breaking).
7. **v3 cryptographic version-binding** (из dossier §3) —
   bind `format_version` в Argon2 input или AAD. v3 format
   bump.
8. **TM1 constant-time AEAD mitigation** (из
   [threat-model F-TM1](../threat-model.md)) — replace
   MAC-fail-fast с always-decrypt-body. ~2× cost on garbage
   chunks. v1.x.
9. **Hidden-header v3 roadmap** (из
   [migration.md](../../guide/migration.md)) — сделать
   header password-derived'ным; устранить «is this a hidden-
   volume container» cleartext fingerprint. v3 format bump.

Items 1-2 done в этой серии; items 3-9 carried forward как
v1.x candidates. Items 6-9 cluster naturally в «v3 format
change», которая была бы next-after-1.0 work item, если
weakness motivates a format bump.
