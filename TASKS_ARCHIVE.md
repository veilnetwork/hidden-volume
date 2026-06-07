# hidden-volume — TASKS archive

Historical record of completed tasks per milestone. The active work-list
is in [`TASKS.md`](TASKS.md); this file preserves the closed checkboxes
so future audits can trace what was done, why, and where.

Generated: 2026-05-02 from a TASKS.md with **152 completed / 14 open**
items. Milestones v0.1, v0.4, v0.5, v0.6, v0.7 are 100% closed and
moved here in full. v0.2, v0.3, v0.8, v1.0 still have a few open items
which remain in `TASKS.md`; their **closed** items are archived here.

---

## v0.1 — Foundation (closed)

**Goal:** работающий фундамент: crypto primitives, chunk format, append-only
file, single-record commit, базовый scan/recover.

### Tasks

- [x] Cargo skeleton + deps + lints
- [x] `error::Error` с единым `AuthFailed`
- [x] `crypto::kdf` (Argon2id с настраиваемыми параметрами)
- [x] `crypto::aead` (XChaCha20-Poly1305 per chunk + AAD)
- [x] `crypto::derive` (`SpaceKeys`, `derive_chunk_key`)
- [x] `crypto::rng` (getrandom-backed)
- [x] `chunk::format::Plaintext` encode/decode
- [x] `chunk::ChunkKind`
- [x] `container::Header` (salt + container_id)
- [x] `container::ContainerFile` (`append_slot`, `write_slot`, `read_slot`)
- [x] `open::scan_and_recover` (basic)
- [x] Smoke test: create → write superblock → reopen → recover
- [x] Smoke test: in-place rewrite preserves slot count
- [x] Расширить `Header` 16 байтами Argon2 params (DESIGN §11.1)
- [x] `ContainerFile::create(path, params)` — принимает params, валидирует floor
- [x] `ContainerFile::open(path)` — читает params из header
- [x] `Argon2Params::{MIN, LIGHT, DEFAULT, HEAVY}` пресеты
- [x] `Container::create(path, params)` — высокоуровневый публичный API
- [x] `Container::create_space(password)` (с collision-detection)
- [x] `Container::open_space(password)`
- [x] `Space::commit_seq()` для host-app anchor
- [x] `Space::commit_record(payload)` single-record commit (later replaced by Tx in v0.2)
- [x] `Space::read_latest_record()`
- [x] `NO_RECORD` sentinel в Superblock для пустого пространства
- [x] `Error::SpaceAlreadyExists` для collision при create_space
- [x] Property test P1: chunk plaintext encode→decode roundtrip
- [x] Property test P2: scan детерминирован (3 reopen'а → identity)
- [x] Property test P3: чужой пароль никогда не находит superblock (D2-критичный)
- [x] `Error::PayloadTooLarge` для payload > PAYLOAD_CAP с явным guard'ом
- [x] Crate-level rustdoc с safety/threat caveats + quickstart example

---

## v0.2 — Spaces, transactions, индексы (mostly closed; 3 deferred items remain in TASKS.md)

**Goal:** реальная многоблочная транзакция, KV-индекс, message-log batching,
rewrite/tombstone, padding policies, pre-allocation.

### Closed tasks

#### Журнал и транзакции (DESIGN §6, §7)
- [x] `tx::commit::CommitPayload` — кодирование (data_slot + payload_hash) × N + root_hash
- [x] `ChunkKind::Commit` обработка через CommitPayload
- [x] `Tx` state-machine: begin_tx → put_record × N → commit (3-fsync барьеры)
- [x] Recovery: scan picks max-seq Superblock; root_slot указывает на Commit
- [x] `MAX_RECORDS_PER_TX = 100`
- [x] `Space::commit_record` стал sugar над `begin_tx + put_record + commit`
- [x] `Space::read_latest_records()`
- [x] **Crash injection тесты (9 сценариев)** — truncate-at-chunk-boundary модель,
      покрывает все точки обрыва 3-fsync протокола.

#### KV-индекс (DESIGN §11.4 — hybrid)
- [x] `space::index::IndexNodePayload` — sorted vector внутри одного `IndexNode` chunk
- [x] `Namespace` newtype с `RESERVED/SETTINGS/CONTACTS/MESSAGE_LOG/MEDIA` константами
- [x] `Tx::put(ns, key, value)` / `Tx::delete(ns, key)`
- [x] `Space::get(ns, key)` / `Space::list(ns)` / `Space::count(ns)`
- [x] `CommitPayload` рефакторинг под `(ns → IndexNode slot, payload_hash)` map
- [x] Untouched namespaces carry-through в новом Commit
- [x] MAX_KEY_LEN=256, MAX_VALUE_LEN=2048
- [x] BREAKING: dropped raw records — KV единственная storage-модель
- [x] **B+ tree split** когда IndexNode > PAYLOAD_CAP (2-level: Leaf | Internal+Leaves).

#### DataBatch для message log
- [x] `ChunkKind::DataBatch` — zstd-compressed concat записей
- [x] `src/space/log.rs` — encode_batch / decode_batch / find_in_batch с ZSTD_LEVEL=3
- [x] `Tx::append_log(ns, log_id, payload)`
- [x] `Space::commit_tx` Phase 0: для каждого log namespace flush'ит batch chunk
- [x] `Space::read_log(ns, log_id)`
- [x] Coalesce duplicate log_ids в одном tx через BTreeMap (last-write-wins)
- [x] MAX_LOG_PAYLOAD_LEN=8KiB, MAX_RECORDS_PER_BATCH=1024
- [x] Cross-space log isolation подтверждён тестом
- [x] Realistic messenger workload test: 5 conversations × 100 msgs
- [x] **Auto-splitting log batches at commit time** — `log::encode_batches_split`
- [x] **`Space::iter_log_range(ns, start, end, limit)`** — half-open range query

#### Rewrite / tombstone (DESIGN §6 Inv-W1 revised)
- [x] `ContainerFile::scrub_slot(slot)` — overwrite uniform random
- [x] **`Space::vacuum_orphans()`**
- [x] **Auto-vacuum on `Container::open_space`**
- [x] `Space::audit_owned_chunk_count()`
- [x] **`Space::stats() -> SpaceStats`**
- [x] **`Space::erase_namespace(ns) -> Result<usize>`**
- [x] DESIGN.md §6 Vacuum block с описанием trade-off
- [x] **DataBatch forward-secrecy без full compact** —
      `Space::vacuum_data_batches() -> Result<usize>`

#### Pre-allocation и padding (DESIGN §8, §11)
- [x] `PaddingPolicy::{None, BucketGrowth, FixedRatio}`
- [x] `ContainerOptions { argon2, initial_garbage_chunks, padding_policy }`
- [x] `Container::create_with_options`
- [x] `Container::set_padding_policy` / `padding_policy()`
- [x] `ContainerFile::append_garbage_chunks(n)`
- [x] Hook в `Space::commit_tx` after final fsync
- [x] tests/padding.rs (8 scenarios)

---

## v0.3 — Compaction & integrity (mostly closed; 1 deferred item remains in TASKS.md)

**Goal:** repack-примитив с compact_known/compact_all, multiple superblock
replicas, Merkle integrity на дереве индекса.

### Closed tasks

#### Repack (DESIGN §9)
- [x] `Space::list_namespaces()`
- [x] `Space::iter_log(ns)` — full enumerate с batch caching
- [x] `RepackOptions { argon2, initial_garbage_chunks, padding_policy, log_namespaces }`
- [x] `Container::repack(source, dest, passwords, options)`
- [x] `Container::compact_known(path, passwords, options)`
- [x] `Container::compact_all(path, passwords, options)`
- [x] tests/repack.rs (12 scenarios)
- [x] Closes v0.2 DataBatch leak: deleted message bytes physically eliminated
- [x] **`Container::change_passwords(path, mapping, options)`** + cancellable variant

#### Multiple superblock replicas (DESIGN §7)
- [x] `DEFAULT_SUPERBLOCK_REPLICAS = 3`
- [x] `ContainerOptions::superblock_replicas` + `RepackOptions`
- [x] `Container::set_superblock_replicas` / `superblock_replicas()`
- [x] `Space::create` пишет N initial SB replicas
- [x] `Space::commit_tx` пишет N replicas вместо 1
- [x] Recovery: max-seq SB фильтруется по AEAD success
- [x] `tests/sb_replicas.rs` (9 scenarios)

#### Integrity (DESIGN §3, §11)
- [x] BLAKE3 Merkle tree над IndexNode children
- [x] **`Space::verify_integrity() -> Result<IntegrityReport>`**
- [x] `tests/integrity.rs` (10 scenarios)

#### Tooling
- [x] **CLI-утилита `hv`** (feature-gated `cli`).
      Subcommands: info, create, create-space, inspect, get, put, verify,
      dump-stats, repack. 13 тестов в `tests/cli.rs`.

---

## v0.4 — Locking, multi-device contract (closed)

**Goal:** безопасная работа из нескольких процессов, явный contract для P2P
overlay-синхронизации, host-app anchor API окончательно зафиксирован.

### Tasks

- [x] **Writer-mode `flock(LOCK_EX | LOCK_NB)` на open**, error `Error::Busy`
- [x] tests/locking.rs (8 scenarios)
- [x] **Reader-mode `flock(LOCK_SH)`** + std's File::try_lock_shared
- [x] **`Container::open_readonly(path)`** + `is_readonly()` + `Error::ReadOnly`
- [x] tests/readonly.rs (10 scenarios)
- [x] `Space::commit_seq()`
- [x] `Space::commit_history()` — sorted-asc deduped seqs
- [x] Doc: `docs/MULTI_DEVICE.md` (4 patterns + anchor strategies)
- [x] Reference в `DESIGN.md` §11.2
- [x] `tests/multi_device.rs` (8 scenarios)

---

## v0.5 — Hardening (closed)

**Goal:** доказательная база безопасности — fuzz, audit-passes,
constant-time review.

### Tasks

#### Fuzzing
- [x] **Stable-Rust proptest fuzzing** через `tests/parser_fuzz.rs` (26 tests)
- [x] **cargo-fuzz scaffold** в `crates/hidden-volume/fuzz/` (3 targets)
- [x] **cargo-fuzz CI integration** — `fuzz-smoke` job (5 min/target on nightly)
- [x] **Target: `Container::open` на random byte file** (`fuzz_targets/container_open.rs`)
- [x] **Target: post-AEAD decoder family** (`fuzz_targets/decoder_family.rs`)

#### Audit passes
- [x] **Constant-time pass** (`docs/CT_AUDIT.md`) — 17 sites; codebase already CT-safe
- [x] **Memory hygiene pass** (`docs/MEMORY_AUDIT.md`) — derive_chunk_key /
      derive_subkey wrapped in `Zeroizing`; type-level regression tests
- [x] **fsync ordering pass** (`docs/FSYNC_AUDIT.md`) — 7 sites; matches DESIGN §6
- [x] **Plaintext leak pass** (`docs/PLAINTEXT_AUDIT.md`) — 7 transient buffers wrapped

#### Property tests расширение
- [x] **Random ops vs reference model** (`tests/property_full.rs`)
- [x] 6 deterministic regression тестов
- [x] **Property-based crash recovery** (`tests/crash_proptest.rs`) — 24 cases × 30 ops
- [x] **Fault injection beyond truncate** (`tests/fault_injection.rs`) — 10 scenarios.
      Bonus discovery: `Container::open` lenient unaligned files fix.

---

## v0.6 — Performance (closed)

**Goal:** scan/append производительность достаточна для 10 GiB контейнера на mobile.

### Tasks

- [x] **Benchmarks (criterion)** в `benches/throughput.rs` (14 benchmarks)
- [x] **Scaling validation** для parallel-scan (10K / 50K / 100K slots)
- [x] **Параллельный scan через rayon, feature-gated** (`parallel-scan`, Unix only)
- [x] **Streaming open** — O(M·16 B) memory вместо O(M·4 KiB)
- [x] **mmap reader** (`mmap` feature, Unix-only)
- [x] **Targets validated** (см. `BENCH.md`):
  - scan: 2.0–2.2 GiB/s x86 (target 5 GiB/s missed; bottleneck inherent in per-chunk AEAD)
  - repack: ~333 MiB/s (target 100 MB/s **met**)
  - append: переформулирован — wall-clock dominated by 3-fsync floor
  - ARM: deferred до v0.8 (нужен deployable `.aar`)
- [x] **Public API baseline snapshot** — `docs/PUBLIC_API_v1.txt`

---

## v0.7 — Async wrapper crate (closed)

**Goal:** отдельный crate `hidden-volume-async` с tokio-friendly API,
ядро остаётся sync.

### Tasks

- [x] **Workspace split**: `crates/hidden-volume` (sync core) + `crates/hidden-volume-async`.
      `async` feature flag удалён.
- [x] **`hidden-volume-async`**: thin wrapper, всё через `tokio::task::spawn_blocking`
- [x] **Cancellation safety** — cooperative `CancelToken` (Arc<AtomicBool>);
      `tests/cancellation.rs` (10 scenarios)
- [x] **Repack cancellation** — `compact_*_cancellable` + `tests/repack_cancellation.rs` (7)
- [x] **Backpressure через paginated log API** — `iter_log_after` / `iter_log_before` /
      `iter_log_range`; `tests/log_pagination.rs` (13 scenarios)
- [x] **Async `Stream<Item=Vec<(u64, Vec<u8>)>>` wrapper** — `AsyncSpace` тип,
      3 stream методa; `tests/async_streaming.rs` (10 scenarios)
- [x] Docs: clarification "это не nonblocking IO, это threadpool offload"
- [x] **`docs/INTEGRATION.md`** — host-app integration guide (~440 строк)

---

## v0.8 — FFI и интеграция с Flutter (3 deferred items remain in TASKS.md)

**Goal:** crate `hidden-volume-ffi` + sample Flutter приложение,
бинарные сборки под iOS/Android.

### Closed tasks

#### FFI surface
- [x] **uniffi выбран** over flutter_rust_bridge / cbindgen / cxx (ADR в `docs/FFI_DESIGN.md`)
- [x] **`hidden-volume-ffi` crate** с opaque `SpaceHandle` (combined Container + Space)
- [x] **Error mapping**: `HvError` flat enum (1:1 mirror of `hidden_volume::Error`)
- [x] **Async surface для FFI** — `AsyncSpaceHandle` + uniffi `tokio` runtime feature

#### Bindings generation
- [x] **In-tree `uniffi-bindgen` bin**
- [x] **Bindings под все 4 supported языка** (Python, Kotlin, Swift, Ruby) в `bindings/`
- [x] **Python end-to-end smoke test** — 5/5 pass на Python 3.14

#### Build pipeline (partial)
- [x] **Linux/macOS/Windows desktop binaries** — `release-build` matrix job (5 targets) +
      local `scripts/release.sh`
- [x] **CI matrix для всех targets** (existing jobs + ffi-bindings-python + fuzz-smoke + release-build)

#### Sample app docs
- [x] **`docs/FLUTTER_INTEGRATION.md`** — Path A (uniffi-dart) + Path B (per-platform plugin)

---

## v1.0 — Production release (release-eng items remain in TASKS.md)

### Closed tasks

#### Format freeze
- [x] **`docs/FORMAT_v1.md`** — canonical byte-level wire format spec (~480 строк)
- [x] Reservation байтов под будущие version-bumps (`FORMAT_v1.md` §8)

#### API freeze
- [x] **Public API baseline** — `docs/PUBLIC_API_v1.txt` (grep-extracted snapshot)
- [x] **`docs/SEMVER.md`** — semver coverage policy
- [x] **`#![deny(missing_docs)]` enforced** на оба crate'а (76 missing-doc warnings closed)
- [x] **`#[must_use]` markers** на 40 чистых методов
- [x] **`#[deprecated]` audit** — pre-1.0 zero deprecated items snapshot

#### Docs
- [x] **`docs/THREAT_MODEL.md`** — формальный threat model для external review
- [x] **`docs/OPERATIONS.md`** — operations playbook (9 секций)
- [x] **`docs/MIGRATION.md`** — empty shell для v1→v2 format migration
- [x] **`SECURITY.md`** — disclosure policy + threat-model pointers
