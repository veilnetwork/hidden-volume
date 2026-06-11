# Claude Code project context — `hidden-volume`

This file is auto-loaded by Claude Code when working in this
repository. It is the portable counterpart to per-machine memory:
information here travels with `git`, so a fresh checkout on a new
machine starts with the same context.

The complement to this file is `temp.md` at the repo root — that
one is **gitignored** and machine-local (hardware profile,
disk-budget thresholds, etc.). See the bottom of this file for a
template if you need to recreate it on a fresh machine.

---

## 1. Project at a glance

`hidden-volume` is a Rust workspace implementing a **deniable,
encrypted, append-only multi-space file format**. It is the
**private at-rest storage layer** for a decentralized messenger;
the network / sync / transport layer lives in a separate project.

Crates (in dependency order):

- [`crates/hidden-volume`](crates/hidden-volume/) — sync core; the
  format implementation. No tokio.
- [`crates/hidden-volume-rt`](crates/hidden-volume-rt/) — shared
  internal helpers (`OwnedSpace` self-referential pattern,
  `run_blocking` adapter). Used by both wrapper crates below.
- [`crates/hidden-volume-async`](crates/hidden-volume-async/) —
  Tokio async wrapper around the sync core via `spawn_blocking`.
- [`crates/hidden-volume-ffi`](crates/hidden-volume-ffi/) — uniffi
  0.31 FFI surface. Generates Kotlin / Swift / Python / Ruby
  bindings. Flutter integration (fully implemented typed Dart API)
  is in
  [`experimental/flutter_plugin/`](experimental/flutter_plugin/).

Authoritative sources of truth:

- [`DESIGN.md`](DESIGN.md) / [`DESIGN.ru.md`](DESIGN.ru.md) —
  format spec, invariants, threat-model framing.
- [`docs/en/security/threat-model.md`](docs/en/security/threat-model.md)
  / [`docs/ru/...`](docs/ru/security/threat-model.md) — adversary
  tiers (T1, T2, T2', T3), invariants (D1, D2, I1-3, M1, R1, C1),
  mitigation map, audit history table.
- [`docs/en/reference/format.md`](docs/en/reference/format.md) /
  [`docs/ru/...`](docs/ru/reference/format.md) — on-disk byte
  layout. The bytes are frozen by this doc, not by struct shapes
  in the Rust source.
- [`docs/en/reference/ffi.md`](docs/en/reference/ffi.md) — uniffi
  decisions, password-buffer hygiene, Mutex-per-handle threading.
- [`docs/en/guide/operations.md`](docs/en/guide/operations.md) —
  host-app recipes (backup / restore, key rotation, Argon2 param
  migration, recovery, `compact_known` triggers).
- [`docs/en/guide/integration.md`](docs/en/guide/integration.md) —
  integration guide; FAQ in §13.
- [`docs/en/guide/multi-device.md`](docs/en/guide/multi-device.md)
  — host-app sync-layer contract (commit_history anchors).
- [`docs/en/guide/flutter.md`](docs/en/guide/flutter.md) —
  Flutter status + quick-start recipe.
- [`TASKS.md`](TASKS.md) — milestone roadmap; "Status overview"
  at the top + "Refactoring backlog — pass N" sections per audit
  pass.
- [`CHANGELOG.md`](CHANGELOG.md) — keepachangelog-style; the
  `## [Unreleased]` section is the canonical "what's new in
  pre-1.0" record.
- [`SECURITY.md`](SECURITY.md) / [`SECURITY.ru.md`](SECURITY.ru.md)
  — vulnerability reporting + supply-chain advisory ignores.

When in doubt about a behavior or an invariant, consult these
documents in order, not the source code. They are kept in lockstep
with the implementation (the most recent doc-actualization pass
was 2026-05-09; see CHANGELOG).

---

## 2. Communication preferences

- **Language: Russian** for all user-facing output, conversational
  text, and end-of-session reports.
- **English** for: code, code comments, commit messages, project
  documentation under `docs/`, and the top-level `DESIGN.md` /
  `README.md` / `SECURITY.md` (both languages live side-by-side
  under `docs/{en,ru}/...` and at repo root with `.ru.md`
  suffixes).
- **End-of-session reports** are concise Russian tables:
  - Columns: «Задача», «Что сделано», «Готовность %», «Δ».
  - Followed by a one-line «Итог».
  - No prose recap of internals — the diff and CHANGELOG entry
    are the implementation story.
  - One row per task touched.

---

## 3. Versioning posture (pre-1.0 — breaking changes are fine)

The project is explicitly **pre-1.0**. The user has stated:
"Сейчас цель: создать идеальную кодовую базу и дальше
протестировать её. Можешь смело делать изменения, ломающие
обратную совместимость".

Practical rules:

- Refactor APIs in place; do NOT deprecate-then-remove.
- Change the on-disk format directly; do NOT add migration helpers
  or v1/v2 readers in parallel. `Argon2Params::validate` rejects
  unknown `format_version` — that single gate replaces all
  cross-version compat code.
- Don't preserve old field names "for backward compat" — rename.
- Don't gate cleanups behind opt-in flags "to avoid breaking
  existing callers" — pre-1.0 means there are no existing
  callers in the SemVer sense.

Breaking changes still require:

- A `CHANGELOG.md` entry under `## [Unreleased]` ⇒
  `### Breaking — audit pass N`.
- A one-line "why" in the commit message.
- Doc-actualization in the same commit (or immediate follow-up):
  any rustdoc / `docs/{en,ru}/` paragraph that referenced the
  changed surface is updated symmetrically EN ↔ RU.

The v1.0 milestone freezes both the on-disk format and the public
Rust + FFI API. Tracked in `TASKS.md` v1.0 section.

---

## 4. Workflow conventions

### Tests

- Pipe `cargo test` / `cargo bench` runs to a file in
  `/tmp/*.log`, then `grep` / `Read` from the file rather than
  tailing live output. The full workspace test suite produces
  hundreds of lines per pass; reading from a file saves context.
- Long property / proptest / fuzz sweeps can run inline (the dev
  machine is fast enough); use `run_in_background: true` only
  when there is genuinely independent foreground work.

### Build artifacts

- `cargo clean` at the end of every session (Rust leaves multi-GiB
  `target/` trees). Disk budget is tight; check `df -BG <home>` at
  session end.
- `target/` is gitignored. So is `/dist/` (release staging) and
  `bindings/` (regenerated on demand by
  [`scripts/release.sh`](scripts/release.sh)).

### OOM recovery

If a session OOMs mid-build / mid-test:

1. Check `.git/objects/` for zero-byte files — these indicate an
   interrupted git operation that left dangling objects.
2. If found, restore via `git reflog` to the last good commit:
   `git reflog` to find the SHA, `git reset --hard <sha>`.
3. Re-run the operation; the OOM was likely from `cargo` parallel
   linker invocations consuming memory beyond the available RAM.
   `cargo build -j 4` (or smaller) is the workaround on tight RAM.

### CI trigger policy (2026-05-09)

[`.github/workflows/`](.github/workflows/) has four workflows
(`ci.yml`, `ci-branch.yml`, `flutter-build.yml`, `release.yml`).
The canonical gate is **tag-time CI**; branch/PR CI is
**intentionally not wired** (resource saving — see below):

- **Branch / PR CI** ([`ci-branch.yml`](.github/workflows/ci-branch.yml)) —
  **deliberately disabled.** It is authored to fire on push to
  `master` and on PRs targeting `master`, but the project's default
  branch is `main`, so in practice it never runs. This is on
  purpose (it saves CI minutes on every push); do NOT "fix" the
  branch name to re-enable it without a deliberate decision. Its
  lightweight Ubuntu-only matrix (fmt, clippy, test, rustdoc,
  cargo-audit, cargo-deny, api-surface drift, docs-version drift)
  is covered instead by the local pre-tag gate below.
- **Tag-release CI** ([`ci.yml`](.github/workflows/ci.yml),
  [`flutter-build.yml`](.github/workflows/flutter-build.yml),
  [`release.yml`](.github/workflows/release.yml)) — the canonical
  release gate. Fires only on:
  - Push of a SemVer tag `v*.*.*` (the canonical release trigger).
  - Manual `workflow_dispatch` from the Actions UI.

  The heavy multi-OS matrix (macOS / Windows / aarch64 cross),
  Flutter artifact build, Python FFI smoke, release-build slices,
  and fuzz-smoke live here.

Because branch CI does not run, the pre-tag local gate is the
primary fast-feedback mechanism before pushing a tag:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-default-features --no-deps
cargo test --workspace --all-features --no-fail-fast
scripts/dump-public-api.sh --check
scripts/check-docs-version-drift.sh
# Android cross-compile gate (catches the `target_os = "android"`
# branch — std `try_lock` Err(Unsupported) on Android meant the v1.x
# Android-flock hardening (commit 7e4bf4a) routed through libc
# instead, and a cfg-gating regression escaped the v1.0.0 release
# push because the darwin host has no NDK. Local NDK r26d install
# (~1 GB) matches `flutter-build.yml`'s pinned version; see
# `temp.md` for ANDROID_NDK_HOME wiring on this host.
ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/26.3.11579264" \
  RUSTFLAGS="-D warnings" \
  cargo ndk -t aarch64-linux-android -- build -p hidden-volume
```

If any step fails, fix it before tagging — CI will fail
identically.

The last gate (`check-docs-version-drift.sh`, added 2026-05-28
after audit pass 19) catches the class of doc drift the v3
format-bump introduced — `docs/` describing format vN-1 while the
code already emits vN. CLAUDE.md §3 doc-actualization policy makes
this a pre-tag gate violation; the script reads `PARAMS_VERSION`
from the source and greps `docs/` for stale references to any
prior generation.

---

## 5. Snapshot of recent state (as of 2026-05-28)

Audit passes 1–19 closed. Highlights:

- **Pass 13 (R-NSKIND)**: format bumped 1 → 2 with per-`IndexRoot`
  `kind` byte.
- **Pass 16 (R-STREAMING-REPACK + TM1 + R-FFI-PWD-Z)**: `repack`
  rewritten as a streaming pipeline (≈ 4 MiB working set per
  page, was O(total plaintext)); `MAX_OPEN_SCAN_CHUNKS = 16M`
  ≈ 64 GiB cap on open-scan; FFI password buffers wrapped in
  `Zeroizing` on every entry point.
- **Pass 17**: new `Error::ContainerTooLarge` symmetric write-side
  budget gate; `open_space_verified` defers auto-vacuum until
  after `verify_integrity` succeeds; `PaddingPolicy::garbage_after_commit
  → Result<u64>`; `iter_log_after / before / range` strict on
  non-8-byte keys; async + CLI password Zeroizing; `PasswordRotation`
  no longer derives `Clone`; **MSRV 1.85 → 1.89**;
  `SpaceStats::utilization_ratio()` + `total_slot_count` field
  for host-app `compact_known` triggers; full bilingual docs
  actualization.
- **Pass 18 (second-reviewer follow-through)**: `commit_tx` no
  longer Err after durable commit; `verify_integrity` covers
  DataBatch chunks; `atomic_rewrite_under_source_lock` race
  window narrowed; Android lock-skip precondition documented;
  v3 format-binding requirement specced.
- **5-pass deep-review series (2026-05-28)**: adversarial-stance,
  primitive-level, side-channel-surface, format-fuzzing,
  threat-model-challenge. 0 critical / 0 high / 0 medium findings.
  SC-INFO2 closed by multi-variant TM1 bench (parallel-scan does
  NOT wash out the signal). F-A5 closed by `MAX_TREE_DEPTH = 3`
  cap. F-TM1 partially mitigated by opt-in
  `Container::open_space_constant_time`.
- **v3 format-bump (2026-05-28)**: format_version bumped 2 → 3.
  Three independent hardenings shipped together: #8 kind-tag bytes
  in BLAKE3 inputs, #9 cryptographic version-binding via
  post-Argon2 BLAKE3 step, #10 per-space derived `container_id`
  (closes D1-A2 fingerprint; cleartext `HEADER_LEN`: 80 → 48).
  F-PAD reclassified from silent privacy-degradation to DoS-class.
- **Pass 19 (read-only audit + follow-through, 2026-05-28)**: full
  doc-actualization (`format.md`, `threat-model.md`, audit
  dossiers, `migration.md`, both EN+RU); depth-cap operator
  unified (`>` everywhere); `derive_subkey` zero-allocation via
  blake3 incremental hasher; `tests/v3_key_schedule.rs` regression
  invariants; `scripts/check-docs-version-drift.sh` pre-tag gate;
  Python FFI smoke test updated for v3; dead `paste 1.0.15`
  advisory ignore removed.
- **Test count**: 397 passing across the workspace
  (`cargo test --workspace --all-features`); 43 integration test
  files total.

Open work (from `TASKS.md`):

1. **Flutter integration** — **implemented.** The
   `experimental/flutter_plugin/` typed Dart FFI API (~1116 + 518
   lines, 18 tests) is done; the `UnimplementedError` stubs are
   gone. Native artifact build pipeline already shipped
   (`scripts/build-android.sh`, `scripts/build-ios.sh`,
   `.github/workflows/flutter-build.yml`). Remaining work is
   native-artifact packaging on all target ABIs and graduating out
   of `experimental/`.
2. **Release engineering** (gated on external review): cosign /
   minisign for release artifacts (audit pass 17 F-1), TM1 CI
   threshold gate (pass 17 F-3), external crypto review.
3. **Architectural cleanups, post-1.0** (deferred-justified): E5
   (`OwnedSpace` re-home), E6 (`run_blocking` generic), E7
   (split `space/mod.rs`).

---

## 6. `temp.md` — machine-local bootstrap

`temp.md` at the repo root is gitignored. It contains:

- The user's standing "continue work" session prompt.
- **Machine-specific** notes: RAM, thread count, disk-budget
  threshold for the cleanup trigger.

These differ per machine, so they live OUTSIDE git. On a fresh
machine, recreate `temp.md` from the template below before
starting a session that begins with "продолжи работу" or similar.

### Template (tune to the new machine's profile)

```
Проверь, есть ли активно работающая сессия по проекту, если нет —
начни работу. Возьми задачу из TASKS.md и реализуй её. Если нужно
выбрать, то выбирай то, что лучше подойдет для hidden-volume для
приватной части децентрализованного мессенджера. Нужно учесть, что
инструмент должен работать как на дешевом (слабом) оборудовании,
так и на дорогом одинаково хорошо. Можешь смело делать изменения,
ломающие обратную совместимость, тк ещё нет устоявшейся
инфраструктуры. Сейчас цель: создать идеальную кодовую базу и
дальше протестировать её. Делай краткий отчет на русском в
табличном виде: что за задача, что сделано и подводи краткий итог
по готовности в % и дельта.

Заметки:
 - Если запускаешь тесты — записывай вывод в файл и анализируй
   вывод файла
 - Учти, что ты работаешь на машине с <RAM> ОЗУ и <THREADS> потоками
 - Все логи в /tmp/*.log, grep/Read по файлу
 - При OOM — проверять .git/objects на нулевые размеры; восстанавливать
   через reflog
 - После сессии не забывай проверять место на диске, если свободного
   меньше <THRESHOLD>, то нужно чистить артефакты (тк места на диске
   не много, а Rust оставляет много мусора)
```

Tune `<RAM>`, `<THREADS>`, `<THRESHOLD>` (e.g. on a Flutter dev
machine with 32 GB RAM and 8 threads, set those values
accordingly).

---

## 7. What is intentionally NOT in this file

- **Hardware profile** of any specific machine. Lives in `temp.md`.
- **The full project goal narrative** ("decentralized messenger
  context"). Already in `DESIGN.md` §1 and the security threat
  model — duplicating it here would just rot.
- **Detailed task breakdowns**. Live in `TASKS.md`. CLAUDE.md
  points there.
- **Historical audit findings**. Live in
  [`TASKS_ARCHIVE.md`](TASKS_ARCHIVE.md) and the per-pass sections
  of `TASKS.md`. CHANGELOG records what shipped.

This file is meant to give a fresh Claude Code session enough
context to be productive without paraphrasing the entire `docs/`
tree. When deeper specifics are needed, the doc pointers above are
the right next step.
