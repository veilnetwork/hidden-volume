# Side-channel surface map

**Дата.** 2026-05-28. **Pass.** 3 из 5 серии deeper-review.
**Reviewer.** LLM-assisted, проинструктирован перечислить каждый
канал, через который side-channel наблюдатель (timing, memory
layout, filesystem syscalls, logs) мог бы узнать что-то, что
threat model claim'ит спрятанным.

## Методология

Существующий [`audits/constant-time.md`](constant-time.md)
audit'ил каждый `==` / `!=` comparison site. Известный timing-
leak TM1 документирован в [threat-model F-TM1](../threat-model.md).
Этот pass каталогизирует *каждый другой* side-channel вектор —
подтверждает defended, флагает defense-in-depth возможности, и
explicit про то, что out-of-scope.

Категории surface:

1. **Timing.** Wall-clock или CPU-cycles, наблюдаемые
   противником на той же машине (например, через
   `getrusage()`, process monitoring, syscall-tracing) или
   через remote-network response times.
2. **Memory layout.** Allocation patterns, page faults, TLB
   pressure, наблюдаемые in-process или kernel-level
   противнику.
3. **Filesystem.** Syscall traces, mtime/atime/ctime, file size
   evolution, наблюдаемые kernel-level противнику.
4. **Logging.** Library-emitted log-сообщения или error-строки,
   которые могли бы содержать content.
5. **Microarchitectural.** Cache-timing, branch prediction,
   Spectre / MDS — out-of-scope, но перечислены для полноты.

Для каждого канала: code refs, что утекает, threat-model
position, action (если есть).

## Headline

**0 CRITICAL / 0 HIGH / 0 MEDIUM, 0 LOW.** Каждый side-channel
вектор, который я нашёл, либо уже defended (constant-time
primitives, explicit `subtle::ct_eq` на key/tag material, нет
production logging'а), либо документирован out-of-scope (TM1
timing oracle, T2' multi-snapshot temporal patterns, kernel-
level syscall taps, CPU microarchitecture), либо unreachable
для non-key-holder противника (decode-path timing внутри AEAD-
protected plaintext).

Два **INFO observations** worth-flagging для v1.x roadmap:

- **SC-INFO1.** Decode paths (`Plaintext::decode`,
  `LeafNode::decode`, `InternalNode::decode`, `decode_batch`)
  short-circuit на первом malformed-байте и поэтому занимают
  variable time. Не reachable non-key-holder'ами (AEAD-decrypt
  должен succeed первым), так что не real channel сегодня.
  Constant-time decode pass был бы defense-in-depth против
  adversarial-key-holder сценария, но key-holder explicitly
  out of threat model.
- **SC-INFO2.** `parallel-scan` и `mmap` features меняют
  observable syscall/page-fault pattern на open time. Любой
  side-channel analysis TM1 должен трактовать их как отдельные
  variants — bench `timing_oracle.rs` прогоняет только
  sequential path, так что parallel/mmap paths independently
  не characterised.

## Per-channel analysis

### 1. Timing channels

#### T-1. Argon2id derivation time

- **Где.** [`crypto/kdf.rs::derive_master_key`](../../../../crates/hidden-volume/src/crypto/kdf.rs).
- **Что observable.** Общее `Container::open_space` время
  включает Argon2 KDF run. С `Argon2Params::DEFAULT`
  (`m=64 MiB, t=3, p=1`) это ~700ms на mid-range mobile,
  dominating каждый другой источник timing variance.
- **Content-dependence.** Argon2id data-dependent by design
  (`d` половина `id` использует password-dependent memory
  access patterns; это что делает Argon2d resist TMTO атаки).
  `i` половина data-independent (resist cache-timing). `id`
  combined variant имеет НЕКОТОРУЮ cache-side-channel resistance,
  но не full constant-time wrt password content. Это inherent
  property Argon2-family и документировано в RFC 9106 §6.
- **Threat-model position.** Acknowledged out-of-scope в
  [threat-model §4](../threat-model.md) («CPU-level side
  channels — защищаются OS/microcode»). Cache resistance
  Argon2id достаточна для threat model'а (атакующий не может
  получить cache-resolution timing на mobile/desktop жертве
  без local code execution).
- **Verdict.** **Acknowledged out-of-scope.**

#### T-2. ChaCha20 keystream / Poly1305 MAC

- **Где.**
  [`crypto/aead.rs::ChunkAead`](../../../../crates/hidden-volume/src/crypto/aead.rs).
- **Что observable.** AEAD seal / open время per chunk (~µs).
- **Content-dependence.** ChaCha20 реализован как
  ADD / XOR / ROTATE операции на `u32` lanes; constant-time
  на каждой supported архитектуре. Poly1305 field multiplication
  mod 2¹³⁰ − 5 реализован constant-time в RustCrypto.
- **AEAD tag check.** `Aead::decrypt` RustCrypto использует
  `subtle::ct_eq` для финального Poly1305 tag-comparison
  ([`audits/constant-time.md`](constant-time.md)).
- **Verdict.** **Defended.** Constant-time на primitive-уровне.

#### T-3. BLAKE3 hash

- **Где.** Subkey derivation, per-slot key derivation, Merkle
  payload hashes.
- **Что observable.** Per-hash время (~ns).
- **Content-dependence.** ADD / XOR / ROTATE на `u32` lanes;
  constant-time на каждой supported архитектуре (BLAKE3
  specification §6.4).
- **Verdict.** **Defended.**

#### T-4. AEAD MAC-fail-then-skip vs MAC-pass-then-decrypt (TM1)

- **Где.** [`open/mod.rs::try_decrypt`](../../../../crates/hidden-volume/src/open/mod.rs)
  + benches [`benches/timing_oracle.rs`](../../../../crates/hidden-volume/benches/timing_oracle.rs).
- **Что observable.** ~75 µs/chunk swing в scan time tied к
  ownership; aggregate утекает `frac_owned` (±10-20%) для
  observed space'а. Per-chunk идентификация «owned vs not»
  требует per-chunk timing resolution, что process-level
  observer обычно не имеет.
- **Threat-model position.** TM1 — quantified, документирован
  в [threat-model F-TM1](../threat-model.md). Mitigation
  (constant-time AEAD path, всегда прогоняющий ChaCha20 над
  body) tracked для v1.x.
- **Verdict.** **Acknowledged + mitigation-tracked.**

#### T-5. Decode-path early-return variance (SC-INFO1)

- **Где.**
  [`chunk/format.rs::Plaintext::decode`](../../../../crates/hidden-volume/src/chunk/format.rs),
  [`space/index.rs::{LeafNode,InternalNode}::decode`](../../../../crates/hidden-volume/src/space/index.rs),
  [`tx/commit.rs::CommitPayload::decode`](../../../../crates/hidden-volume/src/tx/commit.rs),
  [`space/log.rs::decode_batch`](../../../../crates/hidden-volume/src/space/log.rs).
- **Что observable.** Каждая decode-функция возвращает
  `Err(Malformed(...))` на первом invalid-байте. Разные
  malformed inputs занимают разное время.
- **Reachability.** Никакая для non-key-holder'ов: каждый
  decode работает на AEAD-decrypted plaintext, который
  атакующий не может произвести без ключа. Key-holder *мог
  бы* сконструировать malformed plaintexts и time'ить parser,
  но key-holder explicitly не defended-against противник в
  этой библиотеке (key-holder имеет full access к своим
  данным; ничего о threat-model'е не говорит, что мы защищаем
  maintainer'а от него самого).
- **Defense-in-depth.** Constant-time decode pass прошёл бы
  весь payload regardless of validity, produce early-
  rejection result в конце. ~4 KiB overhead per chunk per
  decode call. Negligible cost; minimal benefit (только
  closes key-holder-self-DoS сценарий).
- **Verdict.** **INFO** (defense-in-depth opportunity tracked
  для v1.x; не real channel сегодня).

#### T-6. zstd decompression time variance

- **Где.** [`space/log.rs::decode_batch`](../../../../crates/hidden-volume/src/space/log.rs).
- **Что observable.** Per-batch decompression time зависит от
  compressed size и entropy of input.
- **Reachability.** Decompression работает на AEAD-decrypted
  batches — non-key-holder не может probe.
- **Verdict.** **Defended на AEAD-слое.**

#### T-7. Argon2 parameters parsing

- **Где.** [`Argon2Params::validate`](../../../../crates/hidden-volume/src/crypto/kdf.rs).
- **Что observable.** Open-time spent parsing cleartext
  header (cheap, ~ns).
- **Content-dependence.** `validate()` делает branching на
  `m_cost_kib` / `t_cost` / `p_cost` / `format_version` /
  reserved-bits checks — variable time.
- **Reachability.** Cleartext header публичен, так атакующий с
  file-read access уже знает params. Timing validate-call не
  утекает ничего нового.
- **Verdict.** **Defended (cleartext-equivalent).**

#### T-8. Superblock candidate sort

- **Где.** [`open/mod.rs::scan_and_recover`](../../../../crates/hidden-volume/src/open/mod.rs).
- **Что observable.** Время собрать distinct-seq superblocks в
  `BTreeMap` и итерировать descending. Зависит от superblock
  count.
- **Content-dependence.** Superblock count — функция commit
  history × replicas — metadata-level сигнал (D2-A5 в
  adversarial-stance).
- **Verdict.** **Defended на metadata-слое** (commit-history
  exposure уже проанализирована).

#### T-9. Cache-line patterns в scan loops

- **Где.** Sequential, parallel-scan, mmap variants
  `scan_and_recover`.
- **Что observable.** Memory-access patterns внутри single
  open call.
- **Reachability.** Требует CPU-level cache-timing (Spectre /
  Flush+Reload). Out-of-scope CPU side-channel.
- **Verdict.** **Acknowledged out-of-scope.**

### 2. Memory channels

#### M-1. Heap allocation sizes

- **Где.** Каждый `Vec::with_capacity(n)` где `n` derive'ится
  из chunk content: B+ tree node decode, batch decode,
  CommitPayload decode.
- **Что observable.** С in-process или allocator-stats
  наблюдателем (`mallinfo()`, jemalloc dumps), allocation
  sizes per decode раскрывают *что-то* про underlying chunk.
- **Reachability.** In-process observer требует running на
  том же процессе (например, malicious sibling thread).
  Библиотека не экспозит hooks для allocator introspection.
- **Verdict.** **Out-of-scope** (sibling-thread / allocator-
  tap атаки на OS-process-isolation границе, не библиотеки).

#### M-2. Stack frame sizes

- **Где.** Все Rust-функции.
- **Что observable.** Stack growth depth.
- **Content-dependence.** Rust stack frames content-
  independent для normal-функций (нет `alloca`-style stack
  growth без `unsafe`). Recursion в B+ tree walker'ах
  bounded depth ≤ 2 (writer invariant).
- **Verdict.** **Defended.**

#### M-3. Page-fault patterns в mmap mode

- **Где.** [`open/mod.rs::scan_and_recover_mmap`](../../../../crates/hidden-volume/src/open/mod.rs)
  (feature `mmap`).
- **Что observable.** Page faults раскрывают, какой slot scan
  currently accessing kernel-level observer'у.
- **Threat-model position.** Kernel-level taps out-of-scope
  ([threat-model §1.3](../threat-model.md) trust'ит kernel +
  filesystem для тиров T0–T3; T2' противники с kernel-tap'ами
  explicitly out of scope).
- **Verdict.** **Acknowledged out-of-scope.**

#### M-4. Heap-residual key material после drop

- **Где.** Каждый `Zeroizing<...>` wrapper.
- **Что observable.** Heap state post-Drop.
- **Defense.** `Zeroizing<...>` (volatile + compiler_fence)
  на каждом secret-bearing buffer'е. Документировано в
  [`audits/memory.md`](memory.md) +
  [`audits/plaintext.md`](plaintext.md).
- **Caveat.** Под `panic = "abort"` в release: нет Drop на
  panic; OS process teardown — scrub. Acknowledged в pass-1
  коммите `f67281f` и в dossier §4 M1.
- **Verdict.** **Defended.**

### 3. Filesystem channels

#### F-1. Видимость file size

- **Где.** `stat()` syscall на container-файле.
- **Что утекает.** Slot count = `(file_size - CHUNK_SIZE) / CHUNK_SIZE`.
- **Threat-model position.** Документировано out-of-scope
  (file size — metadata, threat-model T1 не claim'ит, что
  спрятано).
- **Verdict.** **Acknowledged out-of-scope.**

#### F-2. mtime / atime / ctime evolution

- **Где.** Filesystem metadata, обновляется на каждой записи
  (mtime), каждом чтении (atime, если не mounted noatime).
- **Что утекает.** Приблизительные write / read times T2'-
  observer'у.
- **Verdict.** **Acknowledged out-of-scope (T2').**

#### F-3. Syscall trace на open

- **Где.** Linux: visible через `strace`. macOS: `dtrace`.
  Windows: ETW.
- **Что утекает.** Последовательность `pread(fd, buf, 4096,
  offset)` calls раскрывает slot access order во время scan'а.
- **Threat-model position.** Syscall-level taps — kernel-
  level — out-of-scope ([threat-model §1.3](../threat-model.md)).
- **Verdict.** **Acknowledged out-of-scope.**

#### F-4. flock acquisition pattern

- **Где.** [`container/file.rs`](../../../../crates/hidden-volume/src/container/file.rs)
  `try_lock_exclusive` / `try_lock_shared`.
- **Что observable.** Flock attempts visible через `lsof` или
  аналог. Concurrent-process attempts return WouldBlock fast.
- **Verdict.** **Acknowledged out-of-scope** (lock visibility
  — filesystem-level metadata; *content* protected lock'ом —
  encrypted file).

### 4. Logging channels

#### L-1. Production library logging

- **Где.** Verified grep'ом по всем `crates/*/src/`:
  - `log::*` macros: **0 production sites**.
  - `tracing::*` macros: **0 production sites**.
  - `println!` / `eprintln!`: **0 production sites** (только в
    `bin/hv.rs` CLI's stderr-progress + `examples/`).
  - `dbg!()`: **0 sites** anywhere.
- **Что это доказывает.** Библиотека не emit'ит log-сообщения
  во время normal-операций. Logging-subsystem, capturing
  host-process logs, не видит ничего от библиотеки.
- **Verdict.** **Defended by absence.** No log channel exists.

#### L-2. Содержание error-сообщений

- **Где.** [`error.rs`](../../../../crates/hidden-volume/src/error.rs).
- **Что observable.** `Error::Display` strings, возвращаемые
  API caller'у.
- **Content-dependence.** Все varianты используют static
  `&'static str` payloads или `{slot: u64}` / `{limit:
  usize}` numeric поля. Никакой variant не интерполирует key
  material, password content, или plaintext bytes
  (verified grep'ом для `format!`-паттернов, включающих
  «password»/«key» — только test-файлы матчатся).
- **Verdict.** **Defended.** Error-сообщения deniability-safe
  (D2 — wrong-password и not-our-chunk unify в `AuthFailed`).

#### L-3. Содержание panic-сообщений

- **Где.** Production-reachable `panic!` / `unreachable!` /
  `unwrap` / `expect` sites: 0 в production-коде
  ([adversarial-stance M1-A1](adversarial-stance.md), verified
  pass-1).
- **Verdict.** **Defended.** No panic path может leak content,
  потому что no panic path reachable от production-inputs.

### 5. Microarchitectural channels (out-of-scope, enumerated)

#### MA-1. Spectre / MDS / Foreshadow

- **Threat-model position.** Out-of-scope ([§4](../threat-model.md)).
  Mitigation — OS-level (microcode updates + kernel KPTI /
  speculative-execution mitigations).
- **Verdict.** **Out-of-scope.**

#### MA-2. Cache-timing на AES-инструкциях

- **Reachability.** N/A — проект использует ChaCha20, не AES.
  AES-NI cache-timing irrelevant.
- **Verdict.** **N/A.**

#### MA-3. Branch-prediction probes

- **Где.** Любой branch в production-коде.
- **Threat-model position.** CPU-level. Out-of-scope.
- **Verdict.** **Out-of-scope.**

#### MA-4. Power / EM / acoustic emanations

- **Threat-model position.** Out-of-scope для software-
  библиотеки (это physical-side-channel'ы, требующие lab-
  оборудования).
- **Verdict.** **Out-of-scope.**

### 6. Feature-variant differences (SC-INFO2)

Библиотека экспозит три open-scan variants:

| Variant | Где | Channel signature |
|---|---|---|
| Sequential | default | per-slot read в slot order |
| Parallel | feature `parallel-scan` (Linux/macOS) | rayon work-stealing; access order non-deterministic across runs |
| mmap | feature `mmap` (Linux/macOS) | один `mmap()` syscall + page faults per accessed slot |

Bench TM1 ([`benches/timing_oracle.rs`](../../../../crates/hidden-volume/benches/timing_oracle.rs))
упражняет *sequential* path. Parallel и mmap paths не
independently timing-characterised.

- **Expected outcome.** Parallel: per-thread variance вымывает
  per-chunk MAC-fail-vs-pass сигнал на aggregate open-time
  уровне, *но* observer с thread-level visibility мог бы re-
  aggregate. Mmap: page-fault pattern раскрывает access order
  kernel-level observer'у (M-3).
- **Verdict.** **INFO** для v1.x: расширить
  `timing_oracle.rs` для покрытия обоих feature-variants и
  документировать per-variant TM1 leak shape в threat-model
  F-TM1 section'е. Не new channel; refinement TM1
  characterisation.

## Summary table

| ID | Channel | Observable | Verdict | Severity |
|---|---|---|---|---|
| T-1 | Argon2 timing | derivation time | Acknowledged out-of-scope (CPU-level) | INFO |
| T-2 | ChaCha20 / Poly1305 | per-AEAD-op time | Defended (primitives constant-time) | INFO |
| T-3 | BLAKE3 timing | hash time | Defended (constant-time) | INFO |
| T-4 | TM1 open-scan oracle | frac_owned ±10-20% | Acknowledged + mitigation-tracked v1.x | INFO |
| **T-5** | **Decode-path early-return** | malformed-input rejection time | **Не reachable сегодня; defense-in-depth opp** | **INFO (SC-INFO1)** |
| T-6 | zstd decompression timing | batch decompress time | Defended на AEAD layer | INFO |
| T-7 | Argon2-params validate timing | header-parse time | Defended (cleartext) | INFO |
| T-8 | Superblock-candidate sort | sort time | Defended на metadata layer | INFO |
| T-9 | Cache-line patterns в scan | scan-thread cache misses | Acknowledged out-of-scope (CPU-level) | INFO |
| M-1 | Heap allocation sizes | alloc dumps | Out-of-scope (sibling-thread / allocator taps) | INFO |
| M-2 | Stack frame sizes | content-independent в Rust | Defended | INFO |
| M-3 | mmap page-fault patterns | kernel-level | Acknowledged out-of-scope | INFO |
| M-4 | Heap-residual key material | post-Drop heap | Defended (`Zeroizing`); panic=abort caveat | INFO |
| F-1 | File size | `stat()` | Acknowledged out-of-scope | INFO |
| F-2 | mtime/atime/ctime | filesystem metadata | Acknowledged out-of-scope (T2') | INFO |
| F-3 | Syscall trace | strace / dtrace / ETW | Acknowledged out-of-scope (kernel-level) | INFO |
| F-4 | flock pattern | `lsof` visibility | Acknowledged out-of-scope | INFO |
| L-1 | Production logging | log / tracing / println | **Defended by absence** (0 production sites) | INFO |
| L-2 | Error message content | API caller observable | Defended (no secret content) | INFO |
| L-3 | Panic message content | unwrap / expect / panic! | Defended (0 production sites) | INFO |
| MA-1 | Spectre / MDS / Foreshadow | CPU microarchitecture | Out-of-scope | INFO |
| MA-2 | AES cache-timing | N/A (not used) | N/A | INFO |
| MA-3 | Branch-prediction probes | CPU-level | Out-of-scope | INFO |
| MA-4 | Power / EM / acoustic | physical | Out-of-scope | INFO |
| **SC-INFO2** | **TM1 через feature variants** | parallel / mmap не bench'д | **Расширить bench в v1.x** | **INFO** |

**Counts:** 0 CRITICAL, 0 HIGH, 0 MEDIUM, 0 LOW. 2 INFO
observations (SC-INFO1 decode-path constant-time defense-in-
depth, SC-INFO2 TM1 multi-variant characterisation).

## Что этот pass НЕ покрыл

- **Quantitative timing experiments beyond existing
  `timing_oracle.rs` bench.** Прогон bench'а по hardware-
  variants (x86, ARM, NEON-on/off) out of scope для static-
  analysis pass'а.
- **Concrete fuzzing of decode paths.** Это [pass-4 format
  fuzzing analysis](./format-fuzzing.md) (next).
- **End-to-end attack narrative.** Это [pass-5 threat-model
  challenge](./threat-model-challenge.md) (final).
- **External-tool runs** (Valgrind cachegrind, Callgrind,
  ptrace bench harnesses). Это был бы отдельный dependent-
  tooling audit.

## Recommended actions (v1.x roadmap)

Ни один — current bug; оба — defense-in-depth options для
рассмотрения во время v1.x security-hardening pass'а:

1. **SC-INFO1 (constant-time decode pass).** Добавить
   constant-time variant `Plaintext::decode` /
   `LeafNode::decode` / `InternalNode::decode` /
   `decode_batch`, обходящий full payload regardless of
   validity. Wrap existing decode в fixed-time shell. Cost:
   ~4 KiB extra work per chunk per decode; negligible против
   per-chunk AEAD-decrypt cost'а. Benefit: closes key-holder-
   self-DoS scenario; matters только если writer-side
   regression produces malformed plaintexts.
2. **SC-INFO2 (TM1 multi-variant bench).** Расширить
   `benches/timing_oracle.rs` для включения parallel-scan и
   mmap variants. Документировать per-variant TM1 leak shape
   в threat-model F-TM1 section'е. No code change needed;
   просто bench + doc.
