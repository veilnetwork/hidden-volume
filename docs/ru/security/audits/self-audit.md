# Self-audit dossier

**Последнее обновление:** 2026-05-28. **Код против которого
проверено:** `master` на коммите [`848752a`](https://github.com/veilnetwork/hidden-volume/commit/848752a)
+ три последующих локальных коммита (`f67281f`, `53b5720`,
`848752a`). **Identity reviewer'а:** maintainer + LLM-assisted
audit passes; **внешнего платного review не было**.

Этот документ **не** замещает внешний crypto-review от
устоявшейся firmы. Это сознательная альтернатива для проекта,
который поставляет deniable-storage примитив: оплата audit-firmе
под real-world identity maintainer'а сломала бы анонимность
проекта, а downstream-пользователи библиотеки deniable-хранилища
в любом случае должны верифицировать свойства из кода, а не из
бэйджа третьей стороны.

Читайте этот документ как: *вот что верифицировано, вот
доказательства, вот как можно независимо переверифицировать без
доверия к maintainer'у.*

---

## 1. Зачем этот документ

`hidden-volume` — это at-rest storage layer децентрализованного
мессенджера. Его security-claim'ы нетривиальны:

- Pre-1.0 криптографический формат, валидность которого опирается
  на тщательный выбор Argon2id параметров, дисциплину
  XChaCha20-Poly1305 nonce, AAD binding и append-only commit
  protocol.
- Инвариант *deniability* — single-snapshot indistinguishability
  от random + compelled-key plausible deniability — требующий,
  чтобы каждый code path избегал утечки информации о том, какие
  slot'ы принадлежат какому паролю.
- Rust workspace с одним load-bearing `unsafe { transmute }` блоком
  в `hidden-volume-rt` для self-referential `OwnedSpace` паттерна.

Разумный вопрос читателя: *«почему я должен верить, что это
держится вместе?»*

Conventional ответ: «внешняя firma провела аудит». Этот ответ
здесь недоступен по двум открыто заявленным причинам:

1. **Нет бюджета.** Maintainer финансирует проект без
   коммерческого backer'а; engagement'ы с Trail of Bits / Cure53 /
   NCC начинаются от десятков тысяч USD.
2. **Анонимность.** Оплата audit-firmе требует выставления счёта
   под real-world identity, что деанонимизирует maintainer'а. Для
   проекта, который поставляет примитив *deniability* — где
   threat model включает nation-state давление на идентифицируемых
   участников — это неприемлемый trade-off.

Этот dossier — **process substitute**: публичный, code-anchored
record того, что верифицировано, кем, против какого claim'а, и как
читатель может независимо воспроизвести верификацию. Substitute
слабее third-party бэйджа в *репутации*, но как минимум так же
силён в *техническом содержании* и *воспроизводимости*.

---

## 2. Что сделано (process)

| Слой | Механизм | Доказательство |
|---|---|---|
| **In-tree audit history** | 18 нумерованных audit-проходов (audit pass 1 — pass 18, 2026-05-02 → 2026-05-10) — каждый с секцией `Refactoring backlog — pass N` в [`TASKS.md`](../../../../TASKS.md), перечисляющей каждое finding, severity и закрывающий коммит. | TASKS.md, git log |
| **Topic-specific audits** | Четыре focused аудита с полными code refs и выводами: [constant-time](constant-time.md), [fsync ordering](fsync.md), [memory hygiene](memory.md), [plaintext residency](plaintext.md). | Каждый файл под этой директорией |
| **Property-level review** | Этот документ — явные statement'ы каждого криптографического инварианта из threat model, код который его enforce'ит, что его сломало бы, и как верифицировать. | §4 этого документа |
| **Read-only re-audit (2026-05-28)** | Независимый pass против того же кода, ищущий пропущенные/регрессировавшие findings. **0 critical/high/medium**, 7 LOW (все doc-accuracy); все 7 поправлены в коммитах `f67281f` + `53b5720`. | Audit pass commits, [TASKS.md §Refactoring backlog](../../../../TASKS.md) |
| **Reproducible signed builds** | `cosign keyless` подписи на каждом SemVer-tagged релизе; длительно-живущих signing-ключей не существует. | [`.github/workflows/release.yml`](../../../../.github/workflows/release.yml), [`docs/ru/contributing/verifying-release.md`](../../contributing/verifying-release.md) |
| **Публичный threat model** | Явные тиры противника T1/T2/T2'/T3, инварианты D1/D2/I1/I2/I3/R1/M1/C1, out-of-scope mitigations перечислены. | [`docs/ru/security/threat-model.md`](../threat-model.md) |
| **Тестовая база** | 391 тест проходит (unit + integration + proptest + crash-recovery + log-pagination + repack + property-full). | `cargo test --workspace` |
| **Fuzz targets** | `container_open` fuzz-target плюс parser fuzz integration test. | [`crates/hidden-volume/fuzz/`](../../../../crates/hidden-volume/fuzz/), `tests/parser_fuzz.rs` |
| **Pre-tag CI gate** | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo doc -D warnings`, `cargo test`, `cargo audit`, `cargo deny check`, `scripts/dump-public-api.sh --check`. Trigger: `push: tags: ['v*.*.*']` + `workflow_dispatch`. | [`.github/workflows/ci.yml`](../../../../.github/workflows/ci.yml) |
| **Bug bounty (community review)** | No-monetary, credit + coordinated-disclosure timeline. Псевдонимные отчёты welcomed через GitHub Private Vulnerability Reporting. | [`SECURITY.ru.md`](../../../../SECURITY.ru.md) |

Что в этом списке **НЕТ**, намеренно:

- Third-party paid audit
- Liability / insurance backing
- Formal-verification tool runs (KLEE, Tamarin, ProVerif, SAW)
- Side-channel testing на реальном hardware (power analysis, EM,
  acoustic) — out of scope для software-библиотеки

---

## 3. Выбор криптографических примитивов

Каждый выбранный примитив и обоснование. Верифицируется чтением
[`crates/hidden-volume/src/crypto/`](../../../../crates/hidden-volume/src/crypto/).

| Примитив | Выбор | Почему | Риск если ошибка |
|---|---|---|---|
| **Password-based KDF** | Argon2id, RustCrypto `argon2 = "0.5"` | RFC 9106 (IETF, 2021); Argon2 выиграл PHC competition; `id` вариант противостоит и side-channel (Argon2i), и TMTO (Argon2d) атакам. | Медленнее brute-force ⇒ realistic password-strength assumption. Default params (`m=64 MiB, t=3, p=1`) дают ~700 ms на mid-range mobile, валидировано в benches. |
| **Symmetric AEAD** | XChaCha20-Poly1305, RustCrypto `chacha20poly1305 = "0.10"` | 192-bit random nonce (vs 96-bit у ChaCha20-Poly1305) делает nonce collision пренебрежимым без per-message counter discipline; constant-time AEAD tag check в RustCrypto. | Nonce reuse = катастрофическое восстановление ключа. 192-bit space делает random-nonce безопасным для ~10²⁰ chunk'ов; контейнер cap'ится на 16M chunk'ов (~64 GiB) по unrelated DoS-причинам. |
| **Version-bind step (v3 #9)** | `versioned_master = BLAKE3-keyed(argon_out, b"hv/v3/master" \|\| u32_le(params.version))` | Свёртывает весь u32 `params.version` (format_version + padding_policy_index + reserved) в master key. **Закрывает v2 lock-down требование**, отмеченное в [`make_aad`](../../../../crates/hidden-volume/src/crypto/aead.rs) rustdoc'е — cross-version key reuse теперь закрыт криптографически, не только политикой. | Любой будущий v4 reader, ослабивший `validate`, всё равно дeriviл бы другой `master_key` (другой label `b"hv/v4/master"`), сохраняя cross-version reject. |
| **KDF→AEAD root + per-space container_id (v3 #8 + #10)** | `aead_root = BLAKE3-keyed(versioned_master, [0x01] \|\| b"hv/v3/aead_root")`; `container_id = BLAKE3-keyed(versioned_master, [0x01] \|\| b"hv/v3/container_id")` | BLAKE3-keyed constant-time, parallelizable, modern (2020); keyed mode = сильная domain separation. Kind-tag byte `0x01` (`SUBKEY_KIND_TAG`) перед context label'ом — v3 #8 explicit-domain-separation step (заменяет v2 length-distinguishes конвенцию, audit pass 7 D3). v3 #10 деривит `container_id` per-space, не читая из cleartext header'а, закрывая D1-A2 fingerprint. | Разный label per subkey purpose → no cross-purpose key reuse. Convention зафиксирован в [`derive.rs`](../../../../crates/hidden-volume/src/crypto/derive.rs). |
| **Per-slot AEAD key (v3 #8 kind-tag 0x02)** | `chunk_key(slot) = BLAKE3-keyed(aead_root, [0x02] \|\| container_id \|\| u64_le(slot))` — см. [`derive_chunk_key`](../../../../crates/hidden-volume/src/crypto/derive.rs) | Привязывает slot-индекс в ключ, бьёт slot-shuffle атаки сверх AAD binding. Kind-tag byte `0x02` (`CHUNK_KEY_KIND_TAG`) отличает этот вход от subkey-входов (kind-tag `0x01`). | Если бы несколько slot'ов делили ключ, slot-shuffle был бы one-byte swap атакой на ciphertext. |
| **AAD** | `container_id (32) ‖ slot (8 LE)` — см. [`make_aad`](../../../../crates/hidden-volume/src/crypto/aead.rs) | Привязывает chunk'и к *этому* контейнеру (бьёт cross-container chunk relocation) и к *этому* slot'у. | Отсутствие AAD binding = chunk'и портабельны между контейнерами/slot'ами. |
| **RNG** | OS CSPRNG через crate `getrandom` | Стандарт для cryptographic randomness; один источник для nonces, salts, container_ids, padding, temp-имён. | Любой не-CSPRNG путь = nonce predictability ⇒ катастрофический. Нет seeded/test RNG в production. Верифицировано grep'ом — единственный funnel в [`crypto/rng.rs`](../../../../crates/hidden-volume/src/crypto/rng.rs). |
| **Merkle tree hash** | BLAKE3 unkeyed для IndexNode payload hashes (cross-Tx integrity links). | Unkeyed корректен здесь — эти хэши *публичные commitments*, читаемые из plaintext'а зашифрованного chunk'а под ключом; их роль — integrity, не secrecy. | Non-collision-resistant хэш здесь позволил бы key-holder'у произвести inconsistent index-tree, проходящие `verify_integrity`. BLAKE3 = 256-bit collision resistance. |

**Открытый primitive-level вопрос (документирован, отложен в v3):**
Format `version` сейчас не в Argon2 input и не в AAD. Cross-
version key reuse закрыт *политикой* (`Argon2Params::validate`
отвергает unknown `format_version`), не *криптографией*. Lock-down
требование: любой v3 bump должен включить `version` в Argon2
input или в AAD. См. [`make_aad`](../../../../crates/hidden-volume/src/crypto/aead.rs)
rustdoc и threat-model F-PAD §4.1.

---

## 4. Security-инварианты — claim'ы, enforcement и как верифицировать

Каждый инвариант claim'ится в [threat-model.md](../threat-model.md).
Для каждого — *код*, который его enforce'ит, *противник*, против
которого он держится, и *тест*, который можно запустить самому.

### D1 — Single-snapshot indistinguishability

**Claim:** Противник T1 с одним снимком файла контейнера не может
отличить его от uniform random той же длины, за исключением
48-байтового structured cleartext-header'а
(`salt (32) ‖ Argon2Params (16)`); остаток первого chunk'а
(байты 48..4096) — uniform random padding, неотличимый от
data-chunks. **v3 #10** удалил cleartext-поле `container_id`
(теперь оно деривится per-space внутри
`SpaceKeys::from_master`).

**Enforcement:**
- File-level: каждый chunk — это `nonce (24) ‖ AEAD ciphertext +
  tag`, с nonce из `getrandom` per chunk ([`Space::append_chunk`](../../../../crates/hidden-volume/src/space/mod.rs)).
  Keystream XChaCha20 computationally indistinguishable от random
  под стандартным ChaCha20 assumption'ом.
- Header-level: `Argon2Params` (16 байт) — единственный structured
  range. Reserved bits обнулены и валидированы ([`Argon2Params::validate`](../../../../crates/hidden-volume/src/crypto/kdf.rs)).
  Padding-policy byte — acknowledged-cleartext (F-PAD §4.1,
  accepted scope).
- Garbage chunks: неотличимы от real chunk'ов. Uniform random
  байты пишутся через тот же `append_slot` ([`ContainerFile::append_garbage_chunks`](../../../../crates/hidden-volume/src/container/file.rs)).

**Защищает против:** T1 (single-snapshot passive). Держится.

**Противник ПРОТИВ КОТОРОГО НЕ ДЕРЖИТСЯ:** T2' (multi-snapshot
byte-diff во времени). Документировано out-of-scope в threat-model §4.

**Верифицировать самому:**
1. Прочитать threat-model §3.D1.
2. Grep'нуть каждый `append_*` и `write` вызов в
   [`crates/hidden-volume/src/container/`](../../../../crates/hidden-volume/src/container/).
   Подтвердить, что каждый non-header байт — это одно из: AEAD
   output, raw `getrandom` байты (scrub или garbage), или random
   nonce. Plaintext-структура не утекает.
3. Запустить `cargo test -p hidden-volume --test property_full` —
   включает randomness statistical test на свежем контейнере.

### D2 — Compelled-key plausible deniability

**Claim:** Противник T3, извлёкший пароль `P` для space `S_A`,
получает достаточно для дешифровки chunk'ов `S_A`, но **не может**
доказать (или даже детектировать) существование другого space `S_B`,
чьи chunk'и сосуществуют в том же файле.

**Enforcement:**
- Per-slot AEAD-decrypt с ключом `S_A` на chunk'ах `S_B` падает
  с `AuthFailed`. Failed decrypt'ы *ненаблюдаемы для caller'а* —
  discovery scan пропускает молча (`.ok()?` pattern в
  [`open/mod.rs::try_decrypt`](../../../../crates/hidden-volume/src/open/mod.rs)).
- `Error::AuthFailed` — единственный variant, мапящий и
  «неверный пароль / нет такого space» И «этот конкретный chunk
  не наш» в одно и то же внешнее наблюдение ([`error.rs`](../../../../crates/hidden-volume/src/error.rs)).
- AEAD tag check constant-time (RustCrypto invariant).

**Защищает против:** T3 (compelled-key для одного space). Держится.

**Противник ПРОТИВ КОТОРОГО НЕ ДЕРЖИТСЯ:**
- T2' (multi-snapshot): writer-active сигналы (рост размера на
  commit) показывают, что *что-то* изменилось. Защищает *какому
  space* принадлежит изменение, но не *что активность произошла*.
- TM1 (open-time timing oracle): пассивный наблюдатель одного
  open измеряет примерно owned-fraction контейнера (±10-20%); не
  раскрывает какие slot'ы, но раскрывает приблизительную sparsity.
  См. [threat-model F-TM1](../threat-model.md).

**Верифицировать самому:**
1. Запустить `cargo test --test multi_device -- deny_test`
   (cross-space isolation tests).
2. Запустить `cargo bench --bench timing_oracle -- --quick` и
   лично наблюдать величину leak'а.
3. Сконструировать два пароля для одного файла, писать по-разному
   каждым, подтвердить, что `Container::open_space` с паролем
   `S_B` на файле, написанном `S_A`, возвращает ту же
   error/timing как на garbage-файле.

### I1 — Per-chunk integrity

**Claim:** Любой single-bit flip в ciphertext'е chunk'а, nonce'е или
AAD-привязанной metadata всплывает как `AuthFailed` (во время
discovery scan) или `IntegrityFailure` (при явном
`verify_integrity`).

**Enforcement:**
- ChaCha20-Poly1305 с 16-байтовым tag'ом — Poly1305 MAC над (AAD ‖
  ciphertext) делает любую модификацию детектируемой с
  пренебрежимой вероятностью промаха (2⁻¹⁰⁰).
- AAD = `container_id ‖ slot_le` — slot-shuffle детектируется,
  потому что decrypt под другим slot AAD падает.
- [`Space::verify_integrity`](../../../../crates/hidden-volume/src/space/integrity.rs)
  обходит Merkle hash chain (Superblock → CommitPayload →
  IndexNode tree → DataBatch leaves) и re-hash'ит plaintext
  каждого chunk'а, сравнивая с recorded hash родителя. Hash
  mismatch ⇒ `IntegrityFailure { detail, slot }`.

**Верифицировать самому:** `tests/integrity.rs` упражняет мутацию
на каждом слое; `cargo test --test integrity` подтверждает 0
failures.

### I2 — Tail-corruption tolerance

**Claim:** Частичный write на tail файла (crash в mid-fsync,
truncation, ENOSPC) не откатывает commit'ы, уже сделанные durable
предыдущим Superblock'ом.

**Enforcement:**
- 3-fsync commit protocol: data → CommitPayload → Superblock.
  Superblock публикуется последним; recovery выбирает highest-seq
  Superblock, дешифрующийся под нашим ключом
  ([`open/mod.rs::scan_and_recover`](../../../../crates/hidden-volume/src/open/mod.rs)).
- Multi-replica Superblock (configurable, default 3): частичный
  write, стирающий одну replica, всё ещё оставляет остальные.
- `Argon2Params::validate` защищает от tampered header'ов, которые
  форсировали бы bogus-but-AEAD-valid Superblock.

**Верифицировать самому:** `tests/crash_recovery.rs` и
`tests/crash_proptest.rs` упражняют crash-injection на каждой
byte boundary commit-path'а.

### I3 — Cross-space isolation

**Claim:** Chunk'и одного space нельзя переместить в другой space
(или в другой контейнер) и успешно расшифровать под ключом цели.

**Enforcement:**
- AAD привязывает `container_id` (32 байта, random при create).
- Per-slot key derive'ится от `container_id` И slot'а, так что
  даже гипотетическая key-graft атака падает: relocation в новый
  container_id производит ключ, под которым chunk'и не были
  sealed.
- Верифицировано [`tests/tx_multi.rs`](../../../../crates/hidden-volume/tests/tx_multi.rs).

### R1 — Rollback / fork-detection (host-app cooperative)

**Claim:** Host-app, хранящий external anchor (последний
наблюдённый `commit_seq`), может детектировать file-level rollback,
проверив `Space::commit_seq()` на следующем open.

**Enforcement:** [`Space::commit_seq`](../../../../crates/hidden-volume/src/space/mod.rs)
+ [`commit_history`](../../../../crates/hidden-volume/src/space/mod.rs) +
per-Superblock-replica decryption pattern.

**Это НЕ adversary defense самой библиотекой.** Требует кооперации
host-app per [`docs/ru/guide/multi-device.md`](../../guide/multi-device.md).
Библиотека выставляет примитивы; host-app должен хранить и
проверять anchor.

### M1 — Memory hygiene of key material

**Claim:** Расшифрованный plaintext и key material скрабблятся из
heap/stack до того, как соответствующая память может быть
переиспользована.

**Enforcement:** Audit'ировано end-to-end в [`audits/memory.md`](memory.md)
и [`audits/plaintext.md`](plaintext.md). Каждый AEAD-output буфер,
plaintext encode-буфер, decompressed batch, и password-копия
обёрнуты в `zeroize::Zeroizing`. Master/subkeys derive
`ZeroizeOnDrop`.

**Caveat (acknowledged):** Под `panic = "abort"` (release profile)
destructor'ы не запускаются на panic — OS process teardown это
scrub. Документировано в
[`ffi/lib.rs` SpaceHandle::create](../../../../crates/hidden-volume-ffi/src/lib.rs)
и [`docs/ru/reference/ffi.md` §Гигиена password-буферов](../../reference/ffi.md).

### C1 — Cancellation safety

**Claim:** Cancellation-токены, проверяемые в документированных
checkpoint'ах, не оставляют контейнер в inconsistent on-disk
состоянии.

**Enforcement:** [`audits/fsync.md`](fsync.md) аудитит каждый
cancel-between-write-and-fsync window. 3-fsync барьер
обеспечивает, что любой cancellation во время commit либо roll
forward (Superblock написан), либо roll back (Superblock не
написан, recovery выбирает prior seq).

---

## 5. Открытые items + признанные пробелы

Эти **известны** и **документированы**; они не баги.

| Item | Что | Почему открыт | Где документирован |
|---|---|---|---|
| **TM1** | Open-scan timing oracle утекает ~owned-fraction наблюдателю процесса | **Частично смягчено 2026-05-28**: opt-in `Container::open_space_constant_time` запускает ChaCha20-equalizer на MAC-fail, закрывая ChaCha20-body компоненту (~1-3 µs из ~40 µs/chunk swing). Parsing/alloc residual остаётся; полное закрытие отложено как v1.x #7 follow-up. | [threat-model F-TM1 §4.4](../threat-model.md) |
| **F-PAD** | (v2) Padding-policy byte в cleartext header'е не аутентифицирован, позволял T2-противнику silent privacy degradation | **Реклассифицирован в DoS-class в v3** (2026-05-28). v3 криптографический version-binding step (#9) свёртывает весь u32 `params.version` (включая `padding_policy_index`) в `master_key`. Tamper теперь даёт `AuthFailed`, не silent degradation. DoS-поверхность остаётся приемлемой (любой cleartext-header tamper и так может denied open). | [threat-model F-PAD §4.1](../threat-model.md) |
| **R-LOG-INDEX-3L** | 2-level B+ tree капается на ~10-20K unique log_id'ов в Log namespace | Caller-side partitioning — текущая рекомендация; 3-level tree поднял бы до ~1.5M. Решение отложено до первого интегратора, упёршегося в cap. | [`docs/ru/guide/integration.md`](../../guide/integration.md) §13 |
| **Cycle detection в non-verify walker'ах** | `collect_leaves`, `count_leaves`, `iter_log_*`, `vacuum_orphans` рекурсивны на writer-produced деревьях без visited-set'а | Writer-side инвариант гарантирует depth ≤ 2. Adversarial cycle требует key-holder threat (out-of-scope). `verify_integrity` cycle-resistant по Merkle-hash binding'у. | Этот dossier |
| **Format v1 final freeze** | Pre-1.0 status; формат может ломаться в v0.x → v0.y bump'ах | Gated на «ready to commit forever»; завязан на external community review. | [`docs/ru/reference/semver.md`](../../reference/semver.md) |

---

## 6. Что out-of-scope (be honest)

Библиотека **не** защищает от:

- **Multi-snapshot byte-diff во времени** (T2'). In-place rewrites
  и tombstone'ы оставляют сигналы «этот байт изменился».
  Документированный accepted trade-off — см. threat-model §2 + §4.
- **Rollback атак без external anchor.** Требует host-app
  кооперации per [`docs/ru/guide/multi-device.md`](../../guide/multi-device.md).
- **Application-layer side channels.** Recently-opened files,
  thumbnails, IME caches, swap-страницы, system logs — всё это
  OS-level host-app responsibility.
- **CPU-level side channels.** Spectre, MDS, Foreshadow —
  защищается OS/microcode.
- **Forensic RAM dumps.** Защищается full-disk encryption +
  secure boot на host-уровне.
- **NFS / FUSE / network filesystems**, игнорирующие или
  ослабляющие `flock(2)`.
- **Android multi-process write** без явной application-layer
  serialization (per-app UID sandbox — assumed isolation
  boundary; in-process `Mutex` enforce'ит within-process single-
  writer).
- **Container parent directory writable by attacker UID.**
  `atomic_rewrite_under_source_lock` примитив поднимает cost
  TOCTOU substitution атаки, но не закрывает её полностью на
  hostile parent dir.

---

## 7. Как самому верифицировать claim'ы проекта

Проект спроектирован для *reader verification*, не *reader
trust*. Конкретные проверки:

### 7.1 Cryptographic-property checks

```sh
# 1. Подтвердите выбор AEAD-примитива и что nonce'ы из getrandom
grep -rn "ChaCha20Poly1305\|XChaCha20\|getrandom" crates/hidden-volume/src/crypto/

# 2. Подтвердите, что AAD привязывает container_id + slot
grep -rn "make_aad\|AAD_LEN" crates/hidden-volume/src/crypto/

# 3. Подтвердите, что KDF parameters валидируются
sed -n '/fn validate/,/^    }/p' crates/hidden-volume/src/crypto/kdf.rs

# 4. Запустите полную test suite — 391 тест покрывают вышеупомянутые инварианты
cargo test --workspace --all-features --no-fail-fast
```

### 7.2 Build verification

```sh
# Воспроизведите release-build матрицу локально для вашей платформы:
cargo build -p hidden-volume --release --features cli --target $(rustc -vV | awk '/host:/{print $2}')

# Сравните ваш локальный SHA256 с опубликованным SHA256SUMS:
sha256sum target/$(rustc -vV | awk '/host:/{print $2}')/release/hv
```

### 7.3 Signed-release verification

См. [`docs/ru/contributing/verifying-release.md`](../../contributing/verifying-release.md).
TL;DR — каждый SemVer-тег публикует `SHA256SUMS`, подписанный
GitHub-Actions OIDC identity'ю release workflow'а через cosign
keyless; подпись лежит в Sigstore Rekor transparency log'е.

### 7.4 Independent audit replay

Этот документ и per-pass-записи в [`TASKS.md`](../../../../TASKS.md)
перечисляют каждое finding с code references. Любой может
пройти заново те же diff'ы и подтвердить закрытие.

### 7.5 Format-spec verification

[`docs/ru/reference/format.md`](../../reference/format.md) —
authoritative byte-layout. Rust-source обязан быть с ним
консистентен. Чтобы проверить: реализуйте минимальный
независимый parser на другом языке против `format.md`, направьте
на маленький test-контейнер, подтвердите совпадение
интерпретации полей.

---

## 8. Community review (bug bounty без денег)

См. [`SECURITY.ru.md`](../../../../SECURITY.ru.md) для standing
offer'а. Кратко:

- **В scope:** vulnerabilities, нарушающие D1, D2, I1, I2, I3,
  R1, M1, или C1; любой panic-via-input через public API; любая
  memory-safety проблема в `unsafe` блоках.
- **Reward:** credit (в CHANGELOG + SECURITY.md hall of fame) +
  early access к фиксу. **Без денежного вознаграждения** —
  budget reality. Reporter'ы welcome оставаться псевдонимными.
- **Disclosure:** coordinated, 90-day default, fast-track для
  critical findings.
- **Channel:** GitHub Private Vulnerability Reporting
  (предпочтительно) или email из `SECURITY.ru.md`.

---

## 9. Roadmap для дополнительного review

В порядке ожидаемой cost-effectiveness:

1. **Anonymous academic preprint** (free, pseudonymous) — submit
   threat-model + format spec в IACR ePrint (`cs.CR`). Заставляет
   пройти через реальные habits of mind cryptographer'ов через
   citations.
2. **Community-eyes посты** на `/r/crypto`, lobste.rs, modern-
   crypto mailing list, с явным «please challenge X» обрамлением.
3. **Cross-link с peer-проектами** (VeraCrypt, age, rage,
   tomb) — попросить maintainer'ов о review trades.
4. **Опциональные v1.x mitigations**, закрывающие признанные
   пробелы без external input'а:
   - TM1 constant-time AEAD path.
   - v3 format с cryptographic version-binding.
   - 3-level B+ tree (R-LOG-INDEX-3L) когда первому интегратору
     понадобится.
5. **Если security-researcher engage'нется с проектом** (через
   bug bounty или community), их публичный отчёт становится
   external review'ом по факту публичности + technical-ности +
   sign'ировки.

---

## 10. История документа

| Дата | Изменение | Reviewer |
|---|---|---|
| 2026-05-28 | Initial dossier. Покрывает audit-passes 1-18 + pass-19 read-only audit. | Maintainer + LLM-assisted |
