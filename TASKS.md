# hidden-volume — implementation plan

План доведения библиотеки до production-ready релиза. Источник истины по
формату и инвариантам — `DESIGN.md`; этот файл — "что и в каком порядке".

Закрытая работа архивирована в [`TASKS_ARCHIVE.md`](TASKS_ARCHIVE.md)
(152 completed tasks across v0.1–v1.0). Ниже — только открытые пункты.

## Status overview

| Milestone | Status | Open count |
|---|---|---:|
| v0.1 — Foundation | ✅ Closed | 0 |
| v0.2 — Spaces, transactions, индексы | ✅ Closed (3 deferred items skipped 2026-05-04) | 0 |
| v0.3 — Compaction & integrity | ✅ Closed (1 deferred item skipped 2026-05-04) | 0 |
| v0.4 — Locking, multi-device | ✅ Closed | 0 |
| v0.5 — Hardening | ✅ Closed | 0 |
| v0.6 — Performance | ✅ Closed | 0 |
| v0.7 — Async wrapper crate | ✅ Closed | 0 |
| v0.8 — FFI и интеграция с Flutter | ✅ Closed (iOS xcframework + simulator integration test done 2026-05-28) | 0 |
| **v0.1.0 — first SemVer release** | ✅ **Tagged 2026-05-10** (commit `996c7b5`, [GitHub Release](https://github.com/veilnetwork/hidden-volume/releases/tag/v0.1.0)) | 0 |
| **v1.0.0 — Production release** | ✅ **Tagged 2026-05-28** (format freeze + TM1 CT companions for parallel/mmap + crate version bump) | 0 (`cargo publish` deliberately deferred — maintainer decision; workspace stays path-dep-only post-1.0) |

**Code-side open: 0**. Refactor passes 1–19 closed; 4 deferred-forever
items explicitly skipped (v0.2 ×3 + v0.3 ×1) — see "SKIPPED" sections
below for rationale. Remaining 4 items split into:
- **Platform packaging** (0): iOS xcframework closed 2026-05-28 (built
  on an Apple-silicon macOS host, simulator integration test green —
  binary **rebuilt on v3 Rust source** 2026-05-28 in pass 19 round 5,
  Swift + Dart bindings actualized in the same commit).
  Android `.so` per ABI and Flutter demo closed 2026-05-10.
- **Release infrastructure** (0): signed-release pipeline
  (cosign keyless, GitHub Release auto-create, `cargo publish` with
  per-crate `publish = false` auto-skip) closed 2026-05-28 — see
  [`.github/workflows/release.yml`](.github/workflows/release.yml) +
  [`docs/en/contributing/verifying-release.md`](docs/en/contributing/verifying-release.md).
- **External-review substitute** (0): bug-bounty (no-money) policy
  + public self-audit dossier closed 2026-05-28 — see
  [`docs/en/security/audits/self-audit.md`](docs/en/security/audits/self-audit.md)
  (RU: [`docs/ru/security/audits/self-audit.md`](docs/ru/security/audits/self-audit.md))
  + [`SECURITY.md` §Bug bounty](SECURITY.md). Paid third-party audit
  is **deliberately skipped** for this project (anonymity +
  no-budget); the dossier §1 explains the rationale and the
  substitute process.
- **Pre-1.0.0 tag** (3): version-1 format freeze, flip
  `publish = false` on the crates we want on crates.io, push the
  1.0.0 tag. See "v1.0 — Open items" below.

### Audit pass 19 (2026-05-28) — read-only audits + follow-through

Five rounds of read-only audit + follow-through commits:

- **Round 1** (`6b9a5a1`): v3 doc-actualization sweep (format.md,
  threat-model.md, audit dossiers, migration.md, both EN+RU);
  unified depth-cap operator `>=` → `>` in `Space::get`;
  `derive_subkey` made zero-allocation via blake3 incremental
  hasher; new `tests/v3_key_schedule.rs` regression invariants
  (4 tests); new `scripts/check-docs-version-drift.sh` pre-tag
  gate.
- **Round 2** (`e689b8a`): local CI-equivalent run uncovered two
  real CI breaks — `bindings/python/test_smoke.py` still asserted
  v2-only `container_id_hex`; `deny.toml` carried a dead
  `RUSTSEC-2024-0436` ignore (`paste 1.0.15` no longer in dep
  tree). Both fixed.
- **Round 3** (`b1672a3`): comprehensive top-level narrative
  sweep — DESIGN.md / DESIGN.ru.md / README.md / README.ru.md /
  CLAUDE.md actualized for v3; `uniffi 0.28` → `uniffi 0.31`
  across 12 files; drift-gate scope extended from `docs/` to also
  cover the 7 top-level narrative MD files; new Pattern 3 in the
  drift checker for stale `uniffi 0.X` refs.
- **Round 4** (read-only): four-pass deep audit; found that the
  experimental Flutter plugin was on a fully-consistent v2 stack
  (iOS xcframework built 2026-05-27 23:37, before v3 commit at
  14:33 next day; hand-written Dart FFI bindings still expected
  6-field `HvHeaderInfo`).
- **Round 5** (this commit): closed round 4's HIGH findings.
  iOS xcframework rebuilt on v3 Rust source; Swift bindings
  regenerated via uniffi-bindgen; hand-written Dart
  `bindings.dart` actualized (`HvHeaderInfo` lost
  `containerIdHex`, `HvIntegrityResult` gained
  `dataBatchesVerified`, `HvStatsInfo.utilizationRatio` corrected
  to match Rust semantics for empty containers, `eraseNamespace`
  docstring fixed); test dylib resolver made portable
  (`.dylib`/`.so`/`.dll`) via shared `test/test_dylib.dart`; Rust
  decoders (`Superblock`, `Commit`, `LeafNode`, `InternalNode`,
  `decode_batch`) tightened to reject trailing bytes after the
  canonical-form payload; stale v2 refs in audit dossiers
  (`adversarial-stance.md` EN+RU, `self-audit.md` RU,
  `format-fuzzing.md` RU, `primitive-level.md` EN+RU) cleaned;
  README example display path fixed; drift-gate extended to
  `experimental/flutter_plugin/.../bindings.dart` to prevent the
  next regression of this class.

Community-driven review is a *process*, not a milestone — it
continues across 1.0 and beyond. Roadmap and substitute mechanisms
live in [self-audit dossier §9](docs/en/security/audits/self-audit.md).

Maintainer one-time repo toggle (cannot be set from CLI): enable
GitHub Private Vulnerability Reporting under repo Settings →
Security → Code security and analysis. Required for the
"Open a private GitHub Security Advisory" channel in
[`SECURITY.md`](SECURITY.md) to actually work.

**Architectural backlog: empty.** D10 / E5 / E6 / S1 closed in audit
pass 8 (consolidated into `hidden-volume-rt`, header-persisted padding
index, `_inner` consolidation). E7 reassessed 2026-05-10 as WONTFIX
(`space/mod.rs` shrank to 689 lines, splitting no longer warranted).
TM1 verified 2026-05-10 with quantified leak, constant-time AEAD
mitigation tracked for v1.1.

---

## v0.2 — SKIPPED (decision: won't implement)

All three items were originally roadmapped, then deferred, now
**explicitly skipped** (2026-05-04). Each has been superseded by
shipped functionality; implementing them now would be feature
churn with no user-facing value.

- [x] ~~**`space::journal::Journal`** — intent-log for in-place
      updates~~ — **SKIPPED.** Superseded by `vacuum_orphans` +
      `vacuum_data_batches` + auto-vacuum-on-open. The "intent log"
      semantics (atomic crash-safe in-place updates) are achieved
      via append-only writes + scrub-old-on-success; both passes are
      shipped and tested by `tests/crash_recovery.rs` +
      `tests/crash_proptest.rs`.
- [x] ~~**3-level B+ tree (Phase 3)**~~ — **SKIPPED.** The current
      2-level B+ tree handles ~5–10K KV entries per namespace, which
      covers every documented use case for the messenger. Larger
      collections (message logs at 100K+) use `DataBatch` chunks via
      `append_log` — a different data structure that's already
      shipped and is more efficient than a deeper KV tree for that
      access pattern. `Error::IndexFull` is an explicit sentinel for
      anyone who hits the cap.
- [x] ~~**`Tx::update_slot`** for in-place rewrite~~ — **SKIPPED.**
      Same rationale as `Journal`: superseded by `vacuum` + `scrub`.
      In-place rewrite is fundamentally incompatible with the
      append-only write invariant (Inv-W1) that's load-bearing for
      crash-safety.

---

## v0.3 — SKIPPED (decision: won't implement)

- [x] ~~**Hot-path hash chain verification** on every read~~ —
      **SKIPPED** (2026-05-04). AEAD per-chunk integrity (with `slot`
      bound in AAD blocking slot-shuffle attacks) plus the explicit
      `Space::verify_integrity()` Merkle walk cover the diagnostic
      use case without paying a hash-chain cost on every `get`/
      `list` call. Production messenger reads would slow ~3× for no
      added security against any in-scope adversary.

---

## v0.8 — CLOSED (2026-05-28)

Bindings сгенерированы в [`bindings/`](bindings/) под все 5
поддерживаемых языков (Kotlin/Swift/Python/Ruby/Dart). Последний
открытый item (iOS packaging) закрыт на Apple-silicon macOS host.

- [x] **iOS `xcframework`** (arm64 device + arm64/x86_64 simulator) —
      closed 2026-05-28 on an Apple M5 Pro / macOS 26.5 / Xcode 26.5
      host. Built via [`scripts/build-ios.sh`](scripts/build-ios.sh)
      (3 iOS Rust targets + `lipo` fat simulator slice +
      `xcodebuild -create-xcframework`), output staged at
      `experimental/flutter_plugin/hidden_volume/ios/HiddenVolumeFFI.xcframework`.
      Swift bindings regenerated against uniffi 0.31 in
      `bindings/swift/` (note: on macOS the cdylib is `.dylib`, not the
      `.so` the `bindings/README.md` recipe hard-codes — adapt the
      `--library` flag).
      **iOS link fix (2026-05-28):** with Flutter's `use_frameworks!`
      the Rust staticlib is linked into the dynamic `hidden_volume`
      framework via `-l"hidden_volume_ffi"`, but the only compiled code
      in that framework is the no-op `HiddenVolumePlugin` stub — so the
      linker pulled in ZERO objects from the archive and the framework
      shipped without a single Rust symbol, making the Dart-side
      `DynamicLibrary.process()` lookup fail at first call
      (`dlsym … ffi_hidden_volume_ffi_uniffi_contract_version: symbol
      not found`). Fixed by adding
      `OTHER_LDFLAGS = -force_load "${PODS_XCFRAMEWORKS_BUILD_DIR}/hidden_volume/libhidden_volume_ffi.a"`
      to the podspec `pod_target_xcconfig`, which pulls every object
      from the archive into the framework so the C ABI symbols are
      present and exported for the process-scope lookup. Verified by
      `flutter test integration_test/app_test.dart -d <iphone-sim>`
      (iPhone 17, iOS 26.5) passing end-to-end — same Dart code path
      as Windows desktop and the Android emulator. The same xcframework
      slices cover physical iOS devices (arm64) once an integrator
      provisions signing.
- [x] **Android `.aar` / `.so` per ABI** — closed 2026-05-10.
      All 4 ABIs (arm64-v8a / armeabi-v7a / x86_64 / x86) build via
      [`scripts/build-android.sh`](scripts/build-android.sh) (cargo-ndk
      4.1.2 + NDK r27d). Output staged in
      `experimental/flutter_plugin/hidden_volume/android/src/main/jniLibs/`,
      bundled into downstream Flutter `.aar` automatically. Kotlin
      bindings regenerated against uniffi 0.31 in `bindings/kotlin/`.
- [x] **Минимальный Flutter-демо** в `experimental/flutter_plugin/hidden_volume/example/` —
      closed 2026-05-10 via Path C (hand-written `dart:ffi` over the
      stable uniffi 0.31 C ABI; uniffi-bindgen-dart 0.1.3 had blocking
      bugs in enum marshalling and async-constructor codegen, so we
      bypassed it). Full sync + async surface
      ([`lib/src/bindings.dart`](experimental/flutter_plugin/hidden_volume/lib/src/bindings.dart)
      + [`lib/src/async_bindings.dart`](experimental/flutter_plugin/hidden_volume/lib/src/async_bindings.dart)),
      18 unit/feature tests pass, integration test (`flutter test
      integration_test/app_test.dart -d windows`) passes end-to-end on
      Windows desktop AND on Android emulator (API 36, x86_64). Same
      Dart code targets iOS once xcframework available (above).
      Pattern guide: [`docs/en/guide/flutter.md`](docs/en/guide/flutter.md).
      **Android fix (2026-05-10):** stable Rust 1.89 `File::try_lock`
      is not implemented for `target_os = "android"` (returns literal
      `"try_lock() not supported"`). Added `cfg(target_os = "android")`
      branches in [`crates/hidden-volume/src/container/file.rs`](crates/hidden-volume/src/container/file.rs)
      that skip flock on Android — the per-app UID sandbox provides
      equivalent isolation, and the in-process `Mutex` inside
      `SpaceHandle` already enforces single-writer semantics within a
      process. No security regression: cross-process sharing of an
      Android container file is not a supported use-case.

---

## v0.1.0 — Released 2026-05-10

First formal SemVer tag. Snapshot at the close of v0.8 (FFI + Flutter
integration) plus audit pass 18.

- [x] **Tag `v0.1.0`** — pushed at commit `996c7b5` (audit pass-18
      close). CI `tags: ['v*.*.*']` trigger fired run [#25632516846](https://github.com/veilnetwork/hidden-volume/actions/runs/25632516846)
      (17 min, success); per-target Rust artifacts + Android `.so`
      per ABI + regenerated bindings produced.
- [x] **CHANGELOG section** — `## [0.1.0] — 2026-05-10` cut from
      `[Unreleased]` (commit `fc2c55f`).
- [x] **GitHub Release** — published with summary paragraph + full
      CHANGELOG link + CI artifacts attached.

Pre-1.0 status retained: on-disk format and public API may break in
v0.x → v0.y bumps. v1.0 still gated on the items in the next section.

---

## v1.0 — Open items (community review + format freeze)

Code-level v1.0 blockers все закрыты. Release infrastructure готова.
External-review substitute (self-audit dossier + no-money bug-bounty)
закрыт 2026-05-28. Открытые items — community-review-driven и
out-of-band:

- [x] **External crypto-review** — **намеренно skipped** для этого
      проекта (анонимность + no-budget). Substitute — [self-audit
      dossier](docs/en/security/audits/self-audit.md) §1
      (rationale) + §2 (process substitute mechanisms). Если позже
      security-researcher engage'нется через bug bounty и
      опубликует technical write-up по timeline'у — этот write-up
      становится external review по факту.
- [x] **Bug-bounty policy** — closed 2026-05-28 в [`SECURITY.md`](SECURITY.md)
      §«Bug bounty (community review, no monetary reward)»:
      coordinated disclosure (90 days default), credit-only reward,
      pseudonymous reporters welcomed, scope анкорен на D1-D2/I1-3/
      R1/M1/C1 + panic-via-input + `unsafe`-блоки. (Опциональный
      пункт изначального плана — теперь required substitute для (B)-
      reputation измерения внешнего аудита.)
- [x] **Версия `1` формата объявляется final** — closed 2026-05-28
      одновременно с v1.0.0 tag. `format_version = 3` — финальная
      v1.0 generation. Future readers поддерживают v3 как минимум
      один major-version cycle (v2.x читает v3; v3.x может убрать
      v3 support). Format breaks — major-bump + migration tool. См.
      [`docs/en/reference/format.md`](docs/en/reference/format.md)
      §7 cross-version policy + §13 format change log.
- **`cargo publish`** — **deliberately not pursued at v1.0.0**
      (maintainer decision 2026-05-28). The release pipeline at
      [`.github/workflows/release.yml`](.github/workflows/release.yml)
      already auto-skips crates marked `publish = false`, so the
      v1.0.0 tag publishes nothing to crates.io by design. If
      future maintenance ever wants to flip this:
      (а) убрать `publish = false` из соответствующих `Cargo.toml`,
      (б) добавить `CARGO_REGISTRY_TOKEN` в repo secrets, (в) пушнуть
      тег. Until then the workspace stays path-dependency-only;
      consumers vendor via git or `path` deps. This is not a v1.0
      gap — it is a published-distribution-channel choice.
- [x] **GitHub release** с подписанными бинарями — pipeline закрыт
      2026-05-28. [`.github/workflows/release.yml`](.github/workflows/release.yml)
      на push SemVer-тега: пересобирает 5-target матрицу, генерит
      `SHA256SUMS`, подписывает его через **cosign keyless** (Sigstore
      OIDC, без длительно-живущих ключей), кладёт всё в GitHub Release
      с инструкцией по верификации. Workflow_dispatch с
      `dry_run: true` собирает + подписывает, но не публикует release
      и не трогает crates.io — surface signed bundle как workflow
      artifact для smoke-проверки. Полная процедура верификации:
      [`docs/en/contributing/verifying-release.md`](docs/en/contributing/verifying-release.md)
      ([RU](docs/ru/contributing/verifying-release.md)). SECURITY.md
      §«Verifying release artifacts» — точка входа для downstream.
- [x] **Версия 1.0.0 тэгнута** — closed 2026-05-28 одновременно с
      format freeze + TM1 CT companions ship. Workspace `Cargo.toml`
      versions: 0.1.0 → 1.0.0; CHANGELOG `[Unreleased]` cut to
      `[1.0.0] — 2026-05-28`. Gate на external review снят: review
      substitute (self-audit dossier) принят как закрытие по
      политическому решению maintainer'а; community-research engage
      via bug-bounty продолжает работать as a process, не milestone.

---

## v1.x — Carried-forward from deep-review audit series (2026-05-28)

Этот блок собирает 7 follow-up items, которые surfaced'нулись в
deep-review-серии (passes 1-5, см.
[`docs/en/security/audits/`](docs/en/security/audits/)). Это не
v1.0 blockers — они либо defense-in-depth (опциональные), либо
кластеризуются с v3 format-bump (см. следующую секцию). Tracked
здесь для discoverability — full rationale в audit-документах.

### Done in this series

- [x] **D1-LOW1** — dossier «64-byte» → «80-byte» cleartext-header
      doc-inconsistency fixed в pass 1 commit `230d40a`. См.
      [adversarial-stance.md](docs/en/security/audits/adversarial-stance.md)
      D1-LOW1.
- [x] **P-LOW1** — rustdoc warning на `Argon2Params::MIN`
      (8 MiB ниже OWASP 2024 low-end 12 MiB; объясняет, кто
      должен использовать MIN, и quantifies ~70× brute-force
      speedup). Fixed в pass 2 commit `df9dbc8`. См.
      [primitive-level.md](docs/en/security/audits/primitive-level.md)
      P-LOW1.

### v1.x defense-in-depth (independent, low effort)

- [x] **SC-INFO2** — `timing_oracle.rs` extended to bench all
      three scan-mode variants (sequential, parallel-scan, mmap).
      Multi-variant table опубликована в
      [threat-model F-TM1 §4.4](docs/en/security/threat-model.md).
      **Key finding:** parallel-scan и mmap **не mitigate'ят**
      TM1-leak — все три mode'а демонстрируют ≈40 µs/chunk swing
      (M5 Pro, 2026-05-28) или ≈75 µs/chunk (Windows/NVMe,
      pass-15 prior characterisation). Гипотеза «work-stealing
      вымоет per-chunk signal» — refuted. Closed 2026-05-28
      via `timing_oracle.rs` extension + threat-model §4.4
      documentation.
- [x] **F-A5 / depth-cap walkers** — closed 2026-05-28. Added
      [`pub(crate) const MAX_TREE_DEPTH: u8 = 3`](crates/hidden-volume/src/space/index.rs)
      and depth-cap checks in every B+ tree walker:
      `Space::get` descent loop,
      `collect_leaves` / `count_leaves` (space/mod.rs),
      `collect_tree_chunks_into_set` (space/vacuum.rs),
      `collect_leaves_after` / `_before` / `_in_range`
      (space/log_iter.rs),
      `verify_subtree` / `collect_log_batch_slots` (space/integrity.rs).
      Walkers exceeding the cap return `Error::Malformed("tree depth
      exceeded MAX_TREE_DEPTH")` (or `IntegrityFailure` from the
      integrity walker). 391 tests pass — honest depth-≤-2 trees
      unaffected. See
      [adversarial-stance.md F-A5](docs/en/security/audits/adversarial-stance.md).
- [ ] **SC-INFO1 / constant-time decode shell** — **REJECTED**
      для текущего scope: защищает out-of-strict-scope противника
      (key-holder), maintenance burden > benefit. Может быть
      пересмотрено если future threat-model расширится. См.
      [side-channel-surface.md SC-INFO1](docs/en/security/audits/side-channel-surface.md).
- [x] **TM1 constant-time AEAD mitigation** — shipped 2026-05-28
      как opt-in API:
      [`Container::open_space_constant_time(password)`](crates/hidden-volume/src/container/mod.rs)
      и keys-driven sibling
      `open_space_with_keys_constant_time(keys)`. Per slot scan
      запускает real AEAD-decrypt; на MAC-fail запускает
      [`crypto::aead::equalize_timing_via_chacha20`](crates/hidden-volume/src/crypto/aead.rs)
      (XChaCha20 stream length=`PLAINTEXT_LEN` constant key/nonce)
      для CPU-time equalization. Aggregate per-chunk wall-clock
      становится независимым от ownership. **Cost:** ≈2× open-time
      на garbage-heavy контейнерах. **Scope:** в v1.0 (commit
      `4c90ba8`) добавлены CT companion'ы для всех трёх scan-режимов
      — `open_space_constant_time` (sequential),
      `open_space_parallel_constant_time` (parallel-scan),
      `open_space_mmap_constant_time` (mmap), плюс `_with_keys_*`
      siblings. Tests:
      `tests/constant_time_scan.rs` + `tests/parallel_scan_constant_time.rs` +
      `tests/mmap_scan_constant_time.rs` (2 + 2 + 2 = 6 cases). См.
      [threat-model F-TM1 §4.4](docs/en/security/threat-model.md)
      §"Mitigation (v1.0, shipped 2026-05-28)".

### v3 format-bump — closed 2026-05-28

Все три закрыты одним format-break'ом (pre-1.0 OK). `PARAMS_VERSION`
bumped 2 → 3; v2 контейнеры не открываются v3-reader'ом (validate
rejects unknown format_version). Migration-tool отсутствует — fresh
start приемлем pre-1.0.

- [x] **P-LOW2 / domain-separation hardening (#8)** —
      [`crate::crypto::derive::derive_subkey`](crates/hidden-volume/src/crypto/derive.rs)
      теперь префиксирует input леад-tag-байтом `0x01`;
      [`derive_chunk_key`](crates/hidden-volume/src/crypto/derive.rs) —
      `0x02`. Domain separation explicit by content, не by input-
      length. Закрывает audit pass 7 D3 convention-fragility.
- [x] **#9 cryptographic version-binding** —
      [`derive_master_key`](crates/hidden-volume/src/crypto/kdf.rs)
      добавляет post-Argon2id BLAKE3-keyed step:
      `versioned = BLAKE3-keyed(argon_out, b"hv/v3/master" ‖
      version_le_u32)`. Cross-version key reuse закрыт
      криптографически, не только `validate()`-policy.
- [x] **#10 per-space derived `container_id`** —
      [`SpaceKeys`](crates/hidden-volume/src/crypto/derive.rs)
      теперь несёт `container_id: [u8; 32]`, derived per-space из
      versioned-master через `derive_subkey(versioned_master,
      b"hv/v3/container_id")`. Cleartext-header больше не содержит
      32-байт container_id; layout v3:
      `salt (32) + Argon2Params (16)` = 48 bytes structured,
      остальное first-chunk'а — uniform random padding. Cross-
      container relocation defense сохраняется (разные salts → разные
      master_keys → разные per-space container_ids). Closes D1-A2
      per-space-identifier fingerprint at offset 32..64.

API impacts:
- FFI `HeaderInfo` потерял поле `container_id_hex` (per-space derived
  сейчас, no longer cleartext).
- CLI `hv info` больше не печатает `container_id:` (по той же
  причине).
- F-PAD persistent padding-policy сохранён (params остались в
  cleartext header'е).

Test count: 393 (unchanged, все проходят).

---

## Refactoring backlog (audit findings — 2026-05-02)

Из refactoring audit: **~150–200 строк removable + 1 dead subkey
derivation per space-open**. Sorted by value/effort. **Total removable:
~150-200 lines + 1 dead BLAKE3 derivation per open + cleanup in
FORMAT_v1.md.**

### Security / correctness (mandatory pre-v1.0)

- [x] **D1 HIGH** — closed in pass 1 (commit `364e9cf`).
      `Argon2Params::validate()` enforces `m_cost_kib ≤ 1 GiB`,
      `t_cost ≤ 100`, `p_cost ≤ 64`. Header-tamper regression test
      in `tests/header_params.rs`.
- [x] **B3** — closed in pass 1. `Plaintext::decode` rejects
      non-zero reserved flags byte with
      `Error::Malformed("non-zero reserved flags")`. Forward-compat
      hole sealed; verified by proptest
      `p1_non_zero_reserved_flags_byte_rejected`.
- [x] **D2** — closed in pass 1. Recovery now iterates Superblock
      candidates by descending seq and falls back if
      `Superblock::decode` fails on the highest-seq replica.

### Hardening — mechanical fixes

- [x] **D4** — closed in pass 1. FFI mutex-poisoning sites map to
      `HvError::Internal("mutex poisoned")` instead of panicking
      across the foreign-language boundary.
- [x] **D7+D8** — closed by **G6** in pass 5.
      `windows(2)` + `w[0]/w[1]` in `LeafNode::decode` and
      `InternalNode::decode` replaced with `let [a, b] = w else
      { unreachable!(...) }` slice patterns.
- [x] **B4** — `CancelToken::is_cancelled` was a candidate for
      `pub(crate)`, but `tests/cancellation.rs` uses it directly
      (integration tests are external crates from Rust's perspective).
      Audit conclusion was wrong about "no external callers". Kept
      `pub` with a doc note steering production callers to
      [`Self::check`].

### Dead code / stubs (pre-1.0 breaking changes OK)

- [x] **A1** — `space/journal.rs` removed; `pub mod journal;`
      declaration gone from `space/mod.rs`. Vacuum supersedes.
- [x] **A2+A3** — `ChunkKind::Data` (0x03) and `ChunkKind::Journal`
      (0x04) variants removed from the enum. Format spec marks 0x03
      and 0x04 as reserved.
- [x] **B1+B2** — `SpaceKeys::master` and `SpaceKeys::kdf` removed
      along with the `derive_subkey(master, b"hv/v1/space/kdf")`
      derivation. Saves 64 B/space + 1 BLAKE3 derivation per open.
- [x] **A4** — `crypto::ct` module (`eq_32`, `eq_slice`) removed.
      Pub functions had no callers outside own tests.
- [x] **A5** — `chunk::format::flags` module + `NONE = 0` constant
      removed. Replaced with doc comment "byte 5 reserved for
      forward-compat flags".

### Architectural (last; needs design thought)

- [x] **D3** — closed by audit pass 6 (2026-05-03) as **not needed**.
      The self-referential pattern is sound without `Pin`:
      `Space<'static>` borrows from `*container` where
      `container: Box<Container>`. The `Box`'s heap pointee has a
      stable address regardless of where `SpaceInner` itself lives;
      `Pin` is only required when the borrowed-from data is in the
      *same struct* as the borrow. Drop order is enforced by
      `ManuallyDrop` + the explicit `Drop` impl;
      `Send`/`Sync` is correctly serialized via `Mutex`. The
      `self_cell`/`ouroboros` migration is a no-op of the same
      semantics — declined.

## Refactoring backlog — pass 2 (audit re-run, 2026-05-02)

После pass 1 (D1 HIGH + 10 cleanup items) свежий аудит нашёл ещё ~75
строк removable + 1 footgun + 11K bindings. Real bugs: ноль.
Pure code-quality polish.

### Clear wins (small, mandatory)

- [x] **B5** — `impl Default for Namespace` removed. Previously
      returned `RESERVED` which Tx methods reject — footgun.
      `LeafNode::default()` / `InternalNode::default()` derives also
      removed (no callers).
- [x] **A7** — `Error::NotImplemented` variant + FFI mapping removed.
      Variant was never constructed by production code.
- [x] **A6** — `ffi-uniffi` Cargo feature placeholder + stale
      SEMVER.md line removed.

### Deduplication

- [x] **B7** — `compact_all` + `compact_all_cancellable` removed.
      Bit-identical bodies to `compact_known` / `_cancellable`. Tests
      and docs updated to use canonical `compact_known*`.

### Tightening pub surface

- [x] **B6** — `crypto::derive_subkey` → `pub(crate)`. Type-regression
      test moved inline to `crypto/derive.rs`.
- [x] **B8** — `pub mod open;` → `pub(crate) mod open;`.
- [x] **D11** — closed in pass 3. 6 of 8 `HEADER_*` constants moved
      to `pub(crate)`. `HEADER_PARAMS_OFFSET` / `HEADER_PARAMS_LEN`
      stay `pub` (used by `tests/header_params.rs` for header-tamper
      tests).

### Documentation drift

- [x] **A8** — bench module-doc `read_log_random` → `read_log` fixed.
- [x] **B9** — stale `SpaceKeys.master` / `kdf` references in
      `CT_AUDIT.md` and `MEMORY_AUDIT.md` updated with cleanup
      historical note.

### Architectural decisions (pending user ack)

- [x] **C4** — closed 2026-05-03.
      `bindings/{python,kotlin,swift,ruby}/*` generated files added
      to root `.gitignore` and `git rm --cached`'d. Tracked items
      kept: `bindings/README.md`, `bindings/python/test_smoke.py`,
      `bindings/python/.gitignore`. Regeneration recipe in
      `bindings/README.md` § Regenerating.
- [x] **D10** — CLOSED in pass 8. Consolidated via internal
      `_inner` methods + `Option<&CancelToken>`; the 12 public
      methods kept their stable surface (binary-compat preserved).
      See "Refactoring backlog — pass 8" section below.

## Refactoring backlog — pass 3 (audit re-run, 2026-05-03)

Третий проход. Ожидаемо diminishing returns после passes 1+2:
**zero real bugs**, ~20 строк cleanup + housekeeping. Pass 3 — это
финальная mini-итерация перед freeze.

### Clear wins (small, mandatory)

- [x] **B10** — `rand_core = "0.6"` direct dep removed from
      `Cargo.toml`. Pulled in transitively via `chacha20poly1305`'s
      `rand_core` feature; **0 direct import sites**.
- [x] **B11** — 6 of 8 `HEADER_*` constants → `pub(crate)`:
      `HEADER_LEN`, `HEADER_SALT_OFFSET`, `HEADER_SALT_LEN`,
      `HEADER_CONTAINER_ID_OFFSET`, `HEADER_CONTAINER_ID_LEN`,
      `FIRST_SLOT_OFFSET`. `HEADER_PARAMS_OFFSET` + `HEADER_PARAMS_LEN`
      stay `pub` (used by `tests/header_params.rs` for header-tamper
      tests).
- [x] **B12** — `AAD_LEN` → `pub(crate)`, dropped from
      `crypto::mod` re-export. External callers obtain AAD via
      `make_aad()` (still pub).
- [x] **E8** — expanded `.gitignore` with stock Rust entries
      (editor configs, swap files, OS noise, `.env*`, `dist/`,
      cargo-fuzz artifacts).

### Architectural — closed

- [x] **E5** — extract `OwnedSpace` helper. **Closed in audit pass 8**.
      Lives in [`crates/hidden-volume-rt/src/lib.rs`](crates/hidden-volume-rt/src/lib.rs)
      as the canonical home for the self-referential
      `Box<Container> + Space<'static>` pattern. Both
      `hidden-volume-async::AsyncContainer` and
      `hidden-volume-ffi::SpaceHandle` / `AsyncSpaceHandle` import
      `hidden_volume_rt::OwnedSpace` instead of duplicating the
      `unsafe { transmute }` lifetime extension. Single safety-review
      point for the `Drop`-order argument.
- [x] **E6** — generic `run_blocking` helper. **Closed in audit pass 8**.
      Lives in [`crates/hidden-volume-rt/src/lib.rs`](crates/hidden-volume-rt/src/lib.rs)
      as `hidden_volume_rt::run_blocking<F, R, E>(f, map_failure)`,
      generic over the consumer's error type. The async crate plugs
      in `hidden_volume::Error` mapping; the FFI crate plugs in
      `HvError` mapping. ~10 lines of duplication eliminated across
      both consumers.
- [x] **E7** — split `space/mod.rs`. **Reassessed 2026-05-10 as
      WONTFIX**. The original concern was 1485 lines; the file is
      now [689 lines](crates/hidden-volume/src/space/mod.rs) after
      pass-8/pass-13/pass-16 refactoring (vacuum extraction, kind-byte
      encapsulation, streaming repack moved to dedicated module). The
      remaining `impl Space<'f>` block is contiguous and well-organized;
      splitting it now would harm auditor top-to-bottom readability for
      no maintainability win. Original deferred rationale stands;
      reassessment confirms «no longer applies» — closing.

## Refactoring backlog — pass 4 (audit re-run, 2026-05-03) — CLOSED 2026-05-02

Final pre-freeze pass. **Zero real bugs.** Findings: 1 micro
re-export trim (B13), 2 test-boilerplate dedup wins (C5/C6), and 8
LOW/TRIVIAL items (F1-F8) covering perf, defensive arithmetic, CLI
hardening, and doc drift. All landed in a single execution session.

### Pre-commit blocker (operational, not code)

- [x] **GIT-1** — committed `364e9cf` "pre-1.0 cleanup: refactor
      audit passes 1-4". Bundles all four passes + .gitignore
      hygiene + binding regen.

### Closed in this pass

- [x] **F1** — `HashSet<u64>` in vacuum scrub paths. O(N²) → O(N)
      `retain` loop. `space/mod.rs:1145,1253`.
- [x] **F2** — `checked_add` + `checked_mul` in mmap expected-len.
      `open/mod.rs:348`.
- [x] **F3** — `HV_PASSWORD` env-var fallback removed. CLI tests
      rewired to `Stdio::piped()` stdin. **Breaking** for env-var
      callers; replacement is `printf 'pw\n' | hv …`.
- [x] **F4** — `hv put --value-stdin` flag added. Reads value as
      second stdin line; argv path retained but documented.
- [x] **F5** — `RepackOptions::default()` replaces explicit
      `Argon2Params::DEFAULT` field.
- [x] **F6** — `lib.rs # Status` doc rewritten for pre-1.0 reality.
- [x] **F7** — `parse_params` explicit `unreachable!` for the
      clap-rejected default arm.
- [x] **F8** — `cursor_advance_above` inlined to one line + comment.
- [x] **B13** — `MAGIC`, `PLAINTEXT_HEADER_LEN` dropped from
      `chunk::` re-export. `chunk::format::*` still public.
- [x] **C5** + **C6** — `fast_params()` and `scratch_path()`
      extracted to `tests/common/mod.rs`. ~26 stale `Argon2Params`
      imports stripped from test files.

### Threat-model status (pass 4)

Closed by passes 1-3:
- Argon2 OOM via header tamper (D1 / F1)
- Forward-format confusion via flags byte (B3 / D5)
- Recovery abort on malformed-but-AEAD-valid SB (D2)
- FFI mutex poisoning panics across boundary (D4)
- Slot-shuffle (slot in AAD), cross-space chunk move (container_id
  in AAD + per-slot key), OOM on huge `payload_len` (cap check)
- Tmp-file race in `compact_in_place` (LOCK_EX on main file)

Still open (all LOW):
- [x] **TM1** — Open-time scan timing oracle (owns vs not-owns) —
      **VERIFIED 2026-05-10**, leak quantified, mitigation deferred to
      v1.x. Ran `cargo bench --bench timing_oracle -- --quick` on
      Windows/NVMe (Argon2 MIN, 500 slots). Timings:
      `frac=0.10 → 20.3 ms`, `frac=0.50 → 48.5 ms`, `frac=0.90 → 49.6 ms`.
      Linearity test passed (~22/32/47 ms for total=100/500/1000).
      **Finding:** the leak is real but coarser-grained than the cache-
      effect hypothesis predicted: a successful per-chunk AEAD-decrypt
      runs ChaCha20 over the full body, while a failed MAC short-
      circuits before the body decrypt. So scan time grows roughly
      linearly with owned-fraction (~37 ms swing per fraction unit, or
      ~75 µs per chunk). An attacker observing one open-time can
      estimate `owned/total` to within ~10-20%. **Granularity**: this
      reveals owned-fraction, not which chunks belong to which space —
      it doesn't violate D2 (deniability of password), only adds some
      info about storage-layout sparsity. **Mitigation** (deferred,
      v1.x): replace the early-MAC-fail path with a constant-time AEAD
      that always runs ChaCha20 over the body and discards on MAC
      mismatch (~2× cost on garbage chunks but eliminates the
      timing-side-channel). Documented in
      [`docs/en/security/threat-model.md`](docs/en/security/threat-model.md)
      §F-TM1 and tracked for v1.1.
- F3 (HV_PASSWORD env leak) — see above.
- F4 (`hv put` argv leak) — see above.

Out-of-scope (documented, accepted):
- Multi-snapshot byte-diff analysis (T2', DESIGN §1)
- Rollback via file-replace (needs external anchor, MULTI_DEVICE.md)
- Plaintext leak via swap/IME/screenshot/log (host-app responsibility)
- NFS / FUSE without `flock(2)` semantics (MULTI_DEVICE.md)
- Argon2 uninterruptibility (RustCrypto crate limitation)

## Refactoring backlog — pass 16 (audit-14 follow-through, 2026-05-09) — CLOSED 2026-05-09

Pass-14 had flagged three roadmap items as "deferred / not v1.0-blocking":
streaming repack, open-time DoS budget, and FFI password hygiene. On
re-read all three were doable in a single session — the deferral was
timidity, not technical impossibility. Closed in this commit. **387
tests pass** (was 385 post-pass-15; +2 new streaming-repack regressions).

### Closed in this pass

- [x] **R-STREAMING-REPACK** — `repack_into_dest` rewritten as a
      streaming pipeline. Log namespaces are walked one
      `iter_log_after(ns, cursor, log_page_size)` page at a time,
      with `Tx::commit` per page; KV namespaces still collect (small,
      structural cap). Working-set ceiling drops from O(total
      plaintext) to O(page) ≈ 4 MiB regardless of log namespace size.
      `log_page_size = MAX_RECORDS_PER_BATCH / 2` ≈ 512 entries/page.
      Internal API change (no public surface drift). Two regression
      tests in `crates/hidden-volume/tests/repack.rs`:
      `streaming_repack_preserves_large_log_namespace` (5000 entries,
      spot-check at indices `[0, 1, 42, 1000, 2500, N-1]`) and
      `streaming_repack_multi_space_mixed_kinds` (two passwords,
      KV+Log mixed, all preserved).
- [x] **TM1 (audit-14 escalation) — open-time scan budget**.
      `crates/hidden-volume/src/open/mod.rs` now exposes
      `MAX_OPEN_SCAN_CHUNKS = 16 * 1024 * 1024` (≈ 64 GiB at 4 KiB
      chunks). All three discovery scans (sequential, parallel,
      mmap) call `check_scan_budget(total)` before iterating, so an
      adversary-inflated container header can no longer force the
      reader into a 100-GiB Argon2 / AEAD attempt loop. Returns
      `Error::Malformed("file too large for open-scan budget …")`
      with a pointer to the constant for ops who want to raise it.
- [x] **R-FFI-PWD-Z (audit-14 → audit-16)** — every FFI password
      entry point now wraps the incoming `Vec<u8>` in
      `zeroize::Zeroizing` immediately on function entry, so the
      Rust-side heap copy scrubs deterministically on return
      (including panic unwind). Sites covered:
      * `SpaceHandle::create`, `SpaceHandle::open` (sync)
      * `AsyncSpaceHandle::create`, `AsyncSpaceHandle::open`
        (Zeroizing wrapper moved into the `run_blocking` closure)
      * Top-level `compact_known(path, passwords)` —
        `Vec<Vec<u8>>` drained into `Vec<Zeroizing<Vec<u8>>>`.
      * Top-level `change_passwords(path, rotations)` — every
        `(old, new)` pair drained into a `Vec<(Zeroizing,
        Zeroizing)>`.
      Added `zeroize = "1.8"` to `crates/hidden-volume-ffi/Cargo.toml`.
      Foreign-side buffers remain the caller's hygiene responsibility
      (already documented at the crate level + on `PasswordRotation`).

### Roadmap item updates

- **R-STREAMING-REPACK** marked CLOSED above; the prior roadmap entry
  in the pass-11 section retained for archival continuity.
- **R-LOG-INDEX-3L** — kept as roadmap (caller-side option (c) in
  `docs/en/guide/integration.md` is the v1.0 recommendation; (a)/(b)
  await first integrator hitting the cap). Decision deferred is
  intentional — caller-side partitioning is structurally cheaper
  than a format v3 bump.

### Skip / document-only (justified)

- **R-DEPS** (UniFFI bump + RUSTSEC ignore review) — release-engineering
  scope, not a code task. Re-evaluate when uniffi 0.29 ships.

## Refactoring backlog — pass 11 (external audit, 2026-05-09) — CLOSED 2026-05-09

External audit pass run after pass-10 + the doc-validity sweep. **HIGH = 1**
(real lost-update race in compact / rotate; missed by passes 1–10 because
the prior threat-models focused intra-process, the race is a multi-process
TOCTOU around `rename`). **MEDIUM = 5**, **LOW = 6**, **ROADMAP = 4**
(Flutter / FFI maintenance API / release supply-chain — separate sessions).
All actionable items closed in this commit. **371 tests pass** (was 367
post-pass-10; +4 new regression tests in `tests/pass11_audit.rs`).

### Closed in this pass

- [x] **M1 HIGH** — In-place rewrite race. `compact_in_place_impl`
      and `change_passwords_impl` previously opened the source via
      `Container::open`, dropped its LOCK_EX flock between Phase 1
      read and rename, then renamed the temp over `path` — leaving a
      window where another process could LOCK_EX, commit, drop, and
      have its commits silently overwritten by our rename. Fixed by
      extracting `atomic_rewrite_under_source_lock` which holds the
      source flock for the entire critical section through `rename`;
      `repack_into_dest` is the new helper that reads from an
      already-open source. Regression tests in
      `tests/pass11_audit.rs::m1_compact_holds_source_lock_through_critical_section`
      and `m1_compact_known_smoke`.
- [x] **M2** — `rename(2)` now followed by `fsync_parent_dir(path)`
      (Unix `cfg`; no-op on Windows where `MoveFileEx` provides
      metadata durability). Closes the directory-entry-revert
      window on ext4/xfs/btrfs after a crash.
- [x] **M3** — Random temp filenames via `getrandom` (8 bytes →
      16 hex chars), placed in the same parent directory using
      `OpenOptions::create_new(true)` for atomic reservation. The
      old `path.with_extension("hv-compact-tmp")` path is no longer
      computed; sibling files with that exact name are NEVER
      deleted (regression test
      `m3_compact_does_not_blind_delete_legacy_tmp_sibling`).
- [x] **M4** — `stream_log_pages_range` now tests for cursor
      saturation BEFORE issuing the next blocking task. If the
      previous page ended at `log_id == u64::MAX`,
      `cursor.checked_add(1) = None` and the stream breaks instead
      of issuing an `iter_log_range(start=None)` call that would
      rewind to the namespace beginning. Regression test
      `m4_iter_log_range_supports_log_id_max` exercises the
      sync-side write+read of a `u64::MAX` log entry.
- [x] **M5** — `decode_batch` now uses streaming `zstd::Decoder`
      with `Read::take(cap)` enforcing a hard
      `MAX_DECODED_BATCH_LEN = 4 + 1024 × (12 + 8 KiB) ≈ 8.4 MiB`
      cap. A zstd compression bomb (key-holder / buggy-writer
      threat model) returns `Error::Malformed("batch decompressed
      size exceeds cap")` instead of unbounded allocation.
- [x] **L1** — `InternalNode::decode` rejects `num == 0` as
      `Error::Malformed("internal node has zero children")`.
      Symmetric `encode` rejection added — encoder/decoder
      symmetry. The fuzz `internal_node_roundtrip` test already
      handled the `Err` branch via skip; no test changes needed.
- [x] **L2** — `Space::commit_tx` now computes the resulting
      active root set (`prior_roots ∪ pending_kv ∪ pending_log`)
      upfront and returns `Error::TooManyNamespaces` before any
      chunk write, instead of the previous late
      `Error::Internal("commit payload exceeds...")` after orphan
      chunks were already on disk.
- [x] **L3** — `seq + 1` replaced with `checked_add(1).ok_or
      (Error::Internal("commit seq overflow"))?` in
      `space/commit.rs`.
- [x] **L4** — `DESIGN.md` §6 / `DESIGN.ru.md` §6 rewritten:
      Inv-W1 (final, v1.0) is "append-only; forward-secrecy via
      vacuum + scrub-old-on-success". The v0.1-sketch
      `Tx::update_slot` / `Tx::tombstone_slot` are explicitly
      called out as superseded.
- [x] **L5** — Two stale FFI rustdoc lines (`PaddingPreset` enum
      and `SpaceHandle::set_padding_policy`) rewritten to reflect
      pass-8 S1-full persistence. The four `PaddingPreset`
      variants are now described as the persistable subset that
      `Container::open` auto-restores; `set_padding_policy` is a
      mid-session override (and F-PAD escape hatch).
- [x] **L6** — `scripts/release.sh` bindgen loop no longer ends
      with `|| true`; failures now propagate. Kept `|| true` on
      the cosmetic `ls -la` diagnostic only.

### Roadmap items

- [x] **R-FFI-1** — CLOSED 2026-05-09. Maintenance API exposed on
      both FFI surfaces:
      * `SpaceHandle::vacuum_data_batches() -> u64` and
        `SpaceHandle::erase_namespace(u8) -> u64` (sync handle
        methods).
      * `AsyncSpaceHandle::vacuum_data_batches` /
        `erase_namespace` (async mirrors).
      * Top-level `compact_known(path, passwords)` and
        `change_passwords(path, rotations: Vec<PasswordRotation>)`
        free functions, exported via `#[uniffi::export]`. Both use
        the pass-11 `atomic_rewrite_under_source_lock` flow under
        the hood, so a `SpaceHandle` open on the same path causes
        `HvError::Busy` instead of corruption.
      * Smoke tests in `crates/hidden-volume-ffi/src/lib.rs` for
        each new API + the `Busy` symmetry.
- [x] **R-FFI-2** — CLOSED 2026-05-09. The
      `atomic_rewrite_under_source_lock` primitive was extracted in
      pass-11 M1+M2+M3 (alongside the race fix); both
      `compact_in_place_impl` and `change_passwords_impl` route
      through it. `unique_temp_path_in_parent` and
      `fsync_parent_dir` are siblings in the same module. No
      separate session needed.
- [x] **R-FLUTTER** — CLOSED 2026-05-09 (variant B). Moved
      `flutter_plugin/` under `experimental/flutter_plugin/` with an
      explicit pre-stable banner in its README and a top-level
      `experimental/README.md` explaining the gating semantics.
      The Dart facade still throws `UnimplementedError`; reachable
      only by a host-app that explicitly path-pubs the experimental
      directory, eliminating accidental "looks shipped" confusion.
      Variant A (real Dart-typed API) remains gated on uniffi-dart
      0.4 stable.
- **R-DEPS** — Bump UniFFI when 0.29+ ships; revisit
      `RUSTSEC-2025-0141 (bincode 1.3.3)` and `RUSTSEC-2024-0436
      (paste 1.0.15)` ignores; document rationale in `SECURITY.md`.
- [x] **R-STREAMING-REPACK** — CLOSED 2026-05-09 (pass 16). Log
      namespaces now stream page-by-page via `iter_log_after` with
      per-page `Tx::commit`; KV namespaces still collect (bounded
      by structural index cap). Working-set ≈ 4 MiB regardless of
      total log volume. See pass-16 section for the full closure
      record.
- **R-LOG-INDEX-3L** — The 2-level B+ tree caps a Log namespace at
      roughly 10K-20K **unique** `log_id` values before
      `Error::IndexFull`. Total messages can scale further (multiple
      `log_id`s share one DataBatch chunk via per-Tx auto-split),
      but the per-namespace KV index is the structural ceiling. The
      `Tx::append_log` rustdoc was made honest in audit pass 14;
      the limit itself remains. Plan options:
      (a) Bump to a 3-level B+ tree (≈ 1.5M unique `log_id`s) by
          adding an internal layer; format-version bump v3 because
          the on-disk encoding gains an internal-node-of-internals
          layer.
      (b) Range-page index: pack contiguous `log_id` ranges into
          `(low, high) → batch_slot` entries instead of one
          per-`log_id` pointer. Drastically reduces index entries
          for monotonic `log_id` writers (typical messenger pattern).
      (c) Caller-side namespace partitioning (per-conversation
          namespace, roll over on cap). No format change needed;
          documented in `docs/en/guide/integration.md`.
      Decision deferred to first integrator running into the cap;
      until then, (c) is the recommended pattern.
- [x] **R-NSKIND** — CLOSED 2026-05-09. Typed
      [`NamespaceKind::{Kv, Log}`](crates/hidden-volume/src/tx/commit.rs)
      enum added; every `IndexRoot` carries an explicit `kind` byte
      (format v2 — `PARAMS_VERSION` bumped from 1 to 2,
      `CommitPayload` per-root layout grew by 1 byte from 41 to 42
      bytes). Enforcement at three layers:
      * **Tx-time** — `Tx::put`/`delete` reject if namespace is in
        `pending_log`, `Tx::append_log` rejects if namespace is in
        `pending_kv` (`crates/hidden-volume/src/tx/mod.rs::check_namespace_kind`).
      * **Commit-time** — `commit_tx` reads prior `IndexRoot` and
        rejects cross-Tx kind violations: a `Put` op against an
        existing Log namespace, or a `Log` op against an existing
        Kv namespace, surfaces as `Error::WrongNamespaceKind` BEFORE
        any chunk is written.
        Pure-`Delete` op sets against a Log namespace are permitted
        (this is the path `Space::erase_namespace` uses to drop log
        entries; cannot introduce mixed-kind state).
      * **Repack** — `Container::repack` reads the persisted `kind`
        directly via `Space::list_namespaces_with_kind` and routes
        each namespace by its declared kind, no more shape heuristic.
        `RepackOptions::log_namespaces` is now an inert hint kept
        for backward-compat with v1-era integrators.
      `vacuum_data_batches` collects batch_slot pointers only from
      Log-kind namespaces, structurally closing the "8-byte KV value
      coincidentally suppresses scrub" false-negative window.
      v1 containers cannot be opened by a v2 reader (validate()
      rejects unknown `format_version`); pre-1.0 — breaking
      acceptable. 7 new regression tests in `tests/nskind.rs`.

### Skip / document-only

- Placeholder `pubspec.yaml` / `.podspec` metadata
  (`github.com/example`) — staged for fix at first publish; tracked
  in R-FLUTTER. Not a runtime issue.
- `temp.md` — already documented as durable session prompt
  (memory entry). Not a concern; kept tracked for "continue work"
  bootstrap.
- `api-surface.txt` automation TODO — pass-10 doc sweep already
  added footnotes for removed items; full automation is R-DEPS scope.

## Refactoring backlog — pass 10 (invariants re-run post-pass-8/9, 2026-05-04) — CLOSED 2026-05-03

Two parallel agents audited function invariants + state-machine
clarity, focused on pass-8/9 new code. **HIGH = 0**, **MEDIUM = 1**
(real RO-contract violation in Space::set_padding_policy), **LOW = 9**,
**INFO = 2**. The MEDIUM is a one-line fix; LOW/INFO are mostly
doc-drift and missing rustdoc on the `pub(super)` cross-submodule
helpers introduced by pass-8 E7. All actionable items closed in a
single commit. **367 tests pass** (was 358; +9 from M1 RO regression
+ I1 round-trip coverage).

### Closed in this pass

- [x] **M1** — `Space::set_padding_policy` returns `Err(ReadOnly)`
      on RO handle (`LockMode::Shared`). Closes the strict-RO
      contract violation that the async/FFI wrappers inherited via
      `space_mut().set_padding_policy(...)`. Regression test
      `tests/readonly::set_padding_policy_on_readonly_space_returns_readonly_error`.
      FFI callers updated to propagate the new `Result<()>`.
- [x] **L1** — `ContainerFile.padding_policy` doc rewritten to
      reflect S1-full: presets `None` / `BucketGrowth { 64 / 256 /
      4096 }` ARE persisted in the cleartext header (`Argon2Params.
      version` bits 16..24); custom policies (`FixedRatio`, custom
      `bucket_chunks`) are runtime-only.
- [x] **L6** — Rustdoc added to 6 `pub(super)` cross-submodule
      helpers in `space/mod.rs`: `read_owned_chunk` (with explicit
      error→meaning table), `read_index_node_at`, `append_chunk`,
      `append_superblock`, `find_root_slot`, `load_prior_roots`.
- [x] **L2** — `OwnedSpace::Drop` doc: `mem::forget` is sound
      (both Box + Space leak; preferable to use-after-free) +
      no-panic requirement on `Space::drop` (currently sound;
      future panics in Drop would leak the flock).
- [x] **L3** — `OwnedSpace::space_mut` doc: reborrow safety
      (`&'a mut Space<'a>` from `&'a mut self`) is compiler-enforced;
      `Space<'f>` is invariant in `'f` so no covariant subtyping
      can re-extend the lifetime without `unsafe`.
- [x] **L4** — F-PAD §4.1 expanded: v1-reader meets v2-writer
      forward-compat fallback case (unknown
      `padding_policy_index` ∈ 4..=255 silently degrades to None)
      now documented; multi-device-sync host-apps must call
      `set_padding_policy` explicitly rather than trust the header
      byte.
- [x] **L8** — `AsyncSpace` reentrancy/deadlock doc: closures
      passed to `run` / `stream_log_pages_*` MUST NOT re-call any
      method on the same handle clone — re-entry on the
      non-reentrant `std::sync::Mutex` deadlocks the blocking task.
      `AsyncSpaceHandle` (FFI) doc: closed-form typed methods, no
      reentry-deadlock vector through callbacks; concurrent
      foreign calls serialize on the lock, sequential awaits are
      fine.
- [x] **L9** — D10 cancellable variants doc consistency: added
      "delegates to `open_space_with_keys_inner`" pointer to
      `Container::open_space` and `open_space_with_keys` for
      grep-reachability symmetry with the cancellable variants.
- [x] **I1** — Test coverage for S1-full + B1: 5 unit tests in
      `crypto/kdf.rs` (round-trip for idx ∈ {0,1,2,3};
      `with_padding_policy_index` zeroes reserved bits 24..32;
      `format_version` low-16 extraction with noisy upper bits;
      `validate` rejects non-zero reserved bits;
      `validate` accepts all persistable indices) + 3 integration
      tests in `tests/padding.rs` (idx 0, 1, 3 preset round-trip
      across reopen; idx 2 was already covered).

### Skip / document-only (justified)

- L5 (FixedRatio reopen-degradation) — not a regression vs pre-pass-8
  (then ALL policies were runtime-only); current behaviour is
  documented in `tests/padding.rs::custom_padding_policy_not_persisted`;
  escape hatch (`set_padding_policy` runtime override) exists.
- L7 (wrap_open retry pattern) — inherent to the design;
  `derive_space_keys` cache is the documented fast-retry path.
- I2 (repack auto-detect false-positive) — astronomical probability;
  escape hatch (`RepackOptions::log_namespaces`) exists.

## Refactoring backlog — pass 9 (post-pass-8 cleanup, 2026-05-04) — CLOSED

Three parallel agents audited the pass-8 changes. **HIGH = 0,
MEDIUM = 0.** All actionable items closed in one commit.

### Closed in this pass

- [x] **Z1+Z2** — `OwnedSpace::open(path, password)` and
      `OwnedSpace::create(path, options, password)` deleted from
      `hidden-volume-rt`. Both were unused convenience wrappers.
      ~17 LOC.
- [x] **Z3** — `Space::count_leaves` demoted from `pub(super)` to
      private `fn`. Only `Space::count` in mod.rs uses it.
- [x] **Z4** — `docs/en/reference/api-surface.txt` PARAMS_VERSION
      line updated to reflect post-S1 type (`u16`); new
      `format_version` / `padding_policy_index` /
      `with_padding_policy_index` methods listed.
- [x] **Z5** — MIRROR / pass-8 E5 tombstone comments trimmed from
      `hidden-volume-async` and `hidden-volume-ffi`. The
      `hidden_volume_rt::OwnedSpace` doc is now the single canonical
      reference.
- [x] **B1** — `Argon2Params::with_padding_policy_index` doc-comment
      now explicitly states reserved bits 24..32 are zeroed by
      construction (the `& 0xFFFF` mask + `idx << 16` already does
      this — the asymmetry the audit flagged was doc-only). Doc
      clarification only; no code-flow change needed.
- [x] **D1** — `hidden-volume-ffi`'s `run_blocking` migrated to
      delegate to `hidden_volume_rt::run_blocking`, completing the
      pass-8 E6 extraction that was left half-done. ~16 LOC dedup.
- [x] **F-PAD doc** — added to `docs/en/security/threat-model.md`
      §4 (Out-of-scope mitigations) with a dedicated §4.1 explaining
      scope, what is and isn't affected, practical reachability,
      mitigation (`set_padding_policy` runtime override escape
      hatch), and rationale for not enforcing in `validate()` /
      AEAD.

## Refactoring backlog — pass 8 (architectural cleanups, 2026-05-04) — CLOSED

Group C from the post-pass-7 summary. All six items closed across
three commits:
- TM1 + E5/E6 minimal (initial pass-8 commit)
- E7 (split space/mod.rs)
- E5/E6 full (extract `hidden-volume-rt` crate)
- S1 full (persistent padding policy in header)
- D10 (consolidate cancellable API pairs — internal scope reduction
  without breaking the public API; `_inner` method + `Option<&CancelToken>`)

### Closed in this session

- [x] **TM1** — `crates/hidden-volume/benches/timing_oracle.rs`:
      criterion-based bench measuring `Container::open_space`
      wall-clock time as f(owned_fraction ∈ {10%, 50%, 90%},
      total_slots ∈ {100, 500, 1000}). Compiles + runs (registered
      in `Cargo.toml` as second bench target). Acceptance criterion
      documented in the bench header: timing distributions for
      different owned-fractions should overlap within criterion's
      noise floor; if they don't, the threat-model TM1 finding
      escalates and we add fake-AEAD-attempts to mask cache-effect
      signal.
- [x] **E5/E6 (MIRROR variant)** — `SpaceInner` + `run_blocking`
      duplicates in `hidden-volume-async` and `hidden-volume-ffi`
      gained explicit MIRROR doc-comments cross-referencing each
      other and stating "any change to one MUST be applied to the
      other". Full extraction into a shared `hidden-volume-rt`
      crate is deferred — see below.

### Closed in subsequent sessions (was "Open" at the time of pass-8)

All four items below were planned for pass-8 follow-ups; each
landed in subsequent passes. Kept here as design-rationale
context for future maintainers.

- [x] **E7** — CLOSED in pass-8. `space/mod.rs` split into
      `mod.rs + commit.rs + vacuum.rs + log_iter.rs + integrity.rs`,
      with the listed `pub(super)` cross-submodule helpers.
- [x] **E5/E6 (full extraction)** — CLOSED in pass-8.
      `hidden-volume-rt` crate created; both `-async` and `-ffi`
      depend on it. The error generic was simplified — the `rt`
      crate uses a callback (`map_err`) to map blocking failures
      into the consumer's error type.
- [x] **S1 full** — CLOSED in pass-8. Policy index packed into
      `Argon2Params.version` bits 16..24; `Container::open`
      auto-restores. Backward-compat preserved (legacy v1
      containers have upper bits = 0 → policy = `None`).
- [x] **D10** — CLOSED in pass-8. Internal `_inner` consolidation
      kept the 12 public methods stable (no breaking API change,
      contrary to the original plan); halves the internal surface
      while preserving the documented public surface.

## Refactoring backlog — pass 7 (invariants & logic audit, 2026-05-04) — CLOSED

Two parallel agents audited function invariants vs implementation
and state-machine clarity. **One HIGH-severity finding** (data-loss
in repack), **5 MEDIUM**, **6 LOW**, **4 INFO**. All actionable
items closed across two commits (pass-7 initial + pass-7
follow-up).

### Closed in this pass

- [x] **L1 HIGH** — repack auto-detects log namespaces. Added
      `Error::WrongNamespaceKind` variant; `decode_log_entries` /
      `parse_batch_slot_value` / `read_log` raise it (instead of
      `Malformed`) for "namespace is KV not log" cases. Repack
      catches `WrongNamespaceKind` and falls back to KV path.
      `RepackOptions::log_namespaces` honoured as hint, no longer
      load-bearing. Regression test
      `tests/repack::repack_auto_detects_unlisted_log_namespace`.
- [x] **C1 MEDIUM** — `commit_tx` early-returns current seq when
      both pending maps empty. Aligns with `Tx::is_empty` doc;
      saves 3 fsyncs + multi-snapshot writer-active leak per
      "no-op" commit. Test `tests/tx_multi::empty_tx_commit_is_a_no_op`.
- [x] **L2 MEDIUM** — `Error::TooManyNamespaces { limit }` variant
      added; `Tx::put`/`delete`/`append_log` reject early via
      `check_namespace_capacity` instead of surfacing the failure
      as `Error::Internal` at commit time.
- [x] **L4 LOW** — `Container::create_space` early-returns
      `Error::ReadOnly` before Argon2id. Avoids ~100ms wasted
      derivation + collision-scan + minor timing side-channel.
- [x] **C2 LOW** — `LeafNode::encode` / `InternalNode::encode`
      gain `debug_assert!` ordering checks. Catches writer-bug
      regressions in tests; release builds pay nothing.
- [x] **C5 INFO** — FFI read paths (`SpaceHandle::count`/`get`/
      `read_log`/`iter_log_range` and `AsyncSpaceHandle` mirrors)
      now reject `namespace == 0` symmetrically with write paths.

### Closed in pass-7 follow-up (2026-05-04)

- [x] **L3** — `read_log` aligned with `iter_log_*`: structural
      "KV says id is in batch but batch decodes without id" now
      returns `Err(Malformed)` from both APIs (was `Ok(None)` in
      `read_log`).
- [x] **L5** — `vacuum_orphans` / `vacuum_data_batches` strict on
      RO: return `Err(ReadOnly)` when explicitly called on a
      `LOCK_SH` handle. Auto-call from `Container::open_space*` is
      suppressed via an `is_readonly()` check in the container
      layer, so opening RO still works.
- [x] **D4** — `scan_and_recover` (sequential + parallel + mmap)
      gained `debug_assert!` on same-seq Superblock-replica
      bit-equality. Catches writer-bug regression in tests;
      release path unchanged.
- [x] **S2** — `ContainerFile` fields (`header`, `padding_policy`,
      `superblock_replicas`, `lock_mode`) tightened from `pub` to
      `pub(crate)`. No external readers; `header` is part of crypto
      identity and must not be mutated post-create.
- [x] **D1** — Documented gap: `commit_tx` doc + `vacuum_data_batches`
      doc explicitly note that DataBatch orphans from a failed
      Phase 0 persist until explicit `vacuum_data_batches`. Host-app
      should call after any `commit()` that returned an error.
- [x] **C3** — `commit_tx` doc rewritten: clarified that orphan
      IndexNode chunks survive only **within one open session** as
      in-flight-commit fallbacks; cross-launch rollback uses
      `commit_history`, not orphan preservation.
- [x] **C4** — `commit_tx` doc gained explicit "Post-failure state"
      paragraph: `owned_slots` may include orphans, `superblock`
      unchanged, next vacuum reclaims (IndexNode auto, DataBatch
      explicit).
- [x] **D2** — `make_aad` doc spells out what AAD covers
      (`container_id` ‖ `slot`) and, after the pass-12
      doc-correction, explicitly notes that format `version` is
      **not** cryptographically bound today: `derive_master_key`
      consumes only `m_cost_kib` / `t_cost` / `p_cost`, so the
      `version` field of `Argon2Params` is **not** an Argon2id
      input. Cross-version protection is policy-only — `validate()`
      strictly rejects unknown `format_version`, so a v1 reader
      cannot open a v2 container (and vice versa). The lock-down
      requirement for any future format bump (include `version` in
      the Argon2id input / a follow-up BLAKE3 derivation step, OR
      in the AAD) is documented inline in `make_aad`.
- [x] **D3** — `derive_chunk_key` doc explicitly states the
      domain-separation convention with `derive_subkey`: future
      `derive_subkey(aead_root, ...)` callers must use a context
      label whose length differs from 40 bytes (or encode a kind-
      tag at position 0) to avoid input-prefix collision with the
      40-byte chunk-key input.
- [x] **S1** (FFI exposure) — `Space::set_padding_policy` /
      `Space::padding_policy` getters added; FFI exposes
      `PaddingPreset` enum (`None`, `Bucket256Kib`, `Bucket1Mib`,
      `Bucket16Mib`) + `SpaceHandle::set_padding_policy` and
      `AsyncSpaceHandle::set_padding_policy`. Header-persisted
      policy (full S1) is a format change deferred to a separate
      design pass.

### Closed in pass-8 (was "Still open" at time of pass-7)

- [x] **S1 format-persisted padding policy** — CLOSED in pass-8 S1
      full. Policy index packed into `Argon2Params.version` bits
      16..24. The deniability concern flagged at pass-7 time
      (cleartext policy byte) was resolved by F-PAD §4.1 in
      `threat-model.md`: the byte is unauthenticated by design and
      a T2 adversary's tamper degrades to `None`, which is the
      conservative-fallback default (no padding). Host-app override
      via `set_padding_policy` remains available as the F-PAD
      escape hatch.

## Refactoring backlog — pass 5 (audit re-run, 2026-05-03) — CLOSED 2026-05-03

Hardening pass after pass-4 commit. **Zero HIGH-severity bugs.**
Two defense-in-depth bounds in B+tree decode (post-AEAD path —
attacker without key cannot reach), two production `expect(...)`
panic sites, one cargo-cult dead feature, and the long-standing
D7+D8 fragile `windows(2)` indexing. All landed in this session.

### Closed in this pass

- [x] **G1** — empty `std` feature dropped from
      `crates/hidden-volume/Cargo.toml`. Zero `cfg(feature = "std")`
      usage in workspace; cargo-cult eliminated.
- [x] **G2** — `LeafNode::decode` rejects implausibly large
      `num_entries` before allocation:
      `num * MIN_LEAF_ENTRY_BYTES > bytes.len() - HEADER_LEN` →
      `Error::Malformed("leaf count exceeds payload bound")`.
- [x] **G3** — `InternalNode::decode` same defense, with
      `MIN_INTERNAL_CHILD_BYTES = 43`.
- [x] **G4** — `cmd_put` `.expect("clap should require...")`
      replaced with `Error::Internal(...)` propagation.
- [x] **G5** — `scan_and_recover_parallel`'s rayon pool init now
      uses `OnceLock::get` + fallible build + `set` chain;
      `Error::Internal("rayon pool build failed")` on `build()`
      error instead of panic in hot scan path.
- [x] **G6** — `windows(2)` + `w[0]/w[1]` replaced with `let [a,b]
      = w else { unreachable!(...) }` slice patterns in two leaf/
      internal sort-check loops. Closes long-standing **D7+D8**.

### Threat-model status (pass 5)

Newly considered, all carry-overs:
- TM1 — open-time scan timing oracle — still LOW open (no micro-bench).
- HV-NEW1 — Argon2 uninterruptibility — RustCrypto limitation, accepted.
- HV-NEW2 — `hv put` argv leak — `--value-stdin` mitigation already
  shipped (F4); default argv path retained for ergonomics.
- HV-NEW3 — `/proc/<pid>/maps` snooping — out-of-scope (host OS).

No new attack models surfaced.

Out-of-scope (documented, accepted):
- Multi-snapshot byte-diff analysis (T2', DESIGN §1)
- Rollback via file-replace (needs external anchor, MULTI_DEVICE.md)
- Plaintext leak via swap/IME/screenshot/log (host-app responsibility)
- NFS / FUSE without `flock(2)` semantics (MULTI_DEVICE.md)
- Argon2 uninterruptibility (RustCrypto crate limitation)

---

## Cross-cutting (постоянно, не milestone)

Эти направления тянутся через все milestone'ы:

- **Документация в коде**: `#![deny(missing_docs)]` enforced на оба
  crate'а. Каждый pub item имеет rustdoc; safety-секции на любом API,
  который требует invariants от caller'а.
- **CHANGELOG.md** ведётся keepachangelog-style с каждого PR.
- **CI** ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):
  с 2026-05-09 триггеры — `push: tags: ['v*.*.*']` + manual
  `workflow_dispatch`; branch-push и PR больше не запускают CI
  (локальные `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test --workspace` — pre-tag gate). На срабатывании
  workflow прогоняются jobs:
  - `test` (Linux/macOS/Windows × stable + Linux beta)
  - `features-unix` (parallel-scan + mmap отдельно на Linux/macOS,
    плюс полный workspace `--all-features` run)
  - `locking-unix` (flock тесты — Unix-only)
  - `clippy --workspace --all-targets --all-features -D warnings`
  - `rustfmt --all --check`
  - `rustdoc --workspace --all-features` с `RUSTDOCFLAGS=-D warnings`
  - `cargo audit` (continue-on-error)
  - `cargo deny check` (license + advisory + dup + source policy)
  - `bench-check` (compile only)
  - `MSRV` job на Rust 1.89
  - `ffi-bindings-python` (Linux + macOS) — Python e2e через ctypes
  - `fuzz-smoke` (nightly, 5 min/target, continue-on-error)
  - `release-build` matrix (5 targets, push-only) с SHA256SUMS
- **MSRV policy**: 1.89 (edition 2024 floor; bumped from 1.85 to
  pick up `File::try_lock` stabilization). Bump = minor version
  bump per `docs/en/reference/semver.md`.
- **Dependency audit**: `cargo audit` + `cargo deny check` настроены.
  `deny.toml` whitelist'ит licenses, denies openssl-class deps,
  denies wildcards.
- **Reproducible builds**: `Cargo.lock` коммитится для
  бинарных артефактов; для library — пока что тоже коммитится
  (review-friendly).

---

## Открытые вопросы, которые не закрыты планом

Эти решения отложены и требуют отдельного обсуждения когда дойдём:

1. **Trained zstd dictionaries для DataBatch** (v0.2 deferred):
   полезны для текстового мессенджера, но требуют корпуса для
   тренировки и увеличивают surface формата. Скорее v0.3+.
2. **Erasure coding для медиа** (упомянуто в концепции, но не в DoD
   ни одного milestone'а): отдельный optional layer; кандидат на
   v0.3+ если будет реальный спрос.
3. **Sparse files / hole punching**: на ext4/APFS/NTFS дырки в файле
   могут утекать через `stat`/`du` различия. Если v0.6 mmap включит
   sparse — нужна отдельная проверка leakage.
4. **Hidden header**: сейчас 64 байта в clear. Альтернатива — сделать
   header тоже password-derived (первый chunk после bootstrap'а ищем
   trial-decrypt'ом). Дороже на open, но снимает один структурный
   сигнал. Кандидат на v2 формата.
