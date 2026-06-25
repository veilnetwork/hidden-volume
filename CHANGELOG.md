# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [SemVer](https://semver.org/). **From v1.0 onward
the on-disk format and the public Rust + FFI API are frozen**: any
subsequent breaking change requires a v2.0 major bump and a proper
migration tool (see [`docs/en/guide/migration.md`](docs/en/guide/migration.md)).
v0.x line was pre-release; v0.x → v0.y bumps were free to break the
format.

## [Unreleased]

### Security

- **FFI open paths now use the constant-time space scan (F-TM1 mitigation).**
  The constant-time open family already existed in the core
  (`Container::open_space_constant_time` and friends) but was opt-in, so the FFI
  — the surface used by the Flutter/mobile deniability app — still opened via the
  early-exit scan, leaving an unlock-timing oracle that an observer able to
  measure open latency could use to distinguish a real space, a decoy, or a wrong
  password. `SpaceHandle::open` / `open_with_keys` (sync **and** async) and
  `MultiSpaceHandle::open_space` now route through the constant-time scan. No FFI
  C-ABI / signature change (the hand-written Dart bindings are unaffected); only
  the scan's timing profile changes. Cost: the equalizer roughly doubles
  open-time on garbage-heavy containers (negligible on the small containers a
  client app holds). New helpers `OwnedSpace::wrap_open_constant_time` /
  `wrap_open_with_keys_constant_time` (rt) and `MultiSpace::open_space_constant_time`
  (core) back this; the original non-CT `wrap_open*` / `MultiSpace::open_space`
  remain for callers that want the faster early-exit scan (e.g. the standalone
  async crate).

### Performance

- **Root-payload cache in `Space::load_prior_roots`.** The read-hot namespace
  lookup path (`get` / `list_namespaces` / `find_root_slot` plus the commit and
  vacuum validation paths) re-read and re-AEAD-decrypted the *same* `Commit`
  chunk on every call, so a read sweep over N namespaces paid N redundant
  XChaCha20-Poly1305 opens of one chunk. `SpaceState` now caches that chunk's
  decrypted payload bytes keyed by `superblock.seq`; subsequent lookups in the
  same commit era decode straight from the cache (pure parsing — no crypto, no
  disk read). The `seq` equality gate plus an explicit clear in `commit_tx`
  guarantee a stale era is never served (`seq` is strictly monotonic per space),
  and the bytes are held in `Zeroizing` and scrubbed on drop / replace, so
  decrypted index data never outlives its commit era in cleartext. Transparent —
  no on-disk format or public-API change. Regression test
  `tx_multi.rs::roots_cache_transparent_across_reads_and_commits`.

### Added

- **Core `MultiSpace` — host several spaces of ONE container open at once** under
  the file's single exclusive lock. The single-space `Container::open_space`
  returns a `Space` that borrows the file for its whole lifetime (one space at a
  time); `MultiSpace` instead holds each space's recovered `SpaceState`
  *detached* and binds one to the file only for the duration of a single
  operation (`MultiSpace::with_space`), so all spaces stay open while writes are
  serialized in-core (which is what the single-writer lock requires). This is the
  storage foundation for a host that runs several identities simultaneously (one
  network node per identity) over one deniable container. New seam on `Space`:
  `from_state` / `into_state` (crate-internal). Additive — the single-space API
  is unchanged. New integration test `multi_space.rs` (two spaces coexist +
  isolate + persist; wrong-keys → AuthFailed; unknown id → Malformed).
- **FFI `MultiSpaceHandle`** — exposes `MultiSpace` over the C ABI: `open(path)`
  takes the container lock; `open_space(keys) → space_id`; then per-space
  `commit` / `get` / `read_log` / `iter_log_range` / `count` / `commit_seq` /
  `space_keys` / `vacuum_data_batches`, each addressed by `space_id`. Lets a
  host run several identities at once over one container from the FFI. Sync-only
  for now (async mirror deferred — no consumer yet). Round-trip test in
  `tests::multi_space_handle_hosts_two_spaces_at_once`.
- **FFI `SpaceHandle::open_with_keys` + `SpaceHandle::space_keys`, and core
  `Space::space_keys`** — the master-space primitive. `space_keys()` exports an
  open space's `SpaceKeys` as 64 opaque bytes (`container_id ‖ aead_root`);
  `open_with_keys(path, keys)` reopens that space from those bytes alone,
  skipping Argon2 (delegates to the existing `Container::open_space_with_keys`).
  This lets a host-app's *master* space store its children's keys (inside its
  own deniable space) and switch between identities without a per-child password
  prompt. Wrong length → `Malformed`; non-matching keys → `AuthFailed` (same
  indistinguishable path as a wrong password, so the count of spaces never
  leaks). The bytes are the per-space decryption root — sensitive, never logged,
  to be kept only inside another deniable space. Additive (no format/existing-API
  change); backed by the rt helper `OwnedSpace::wrap_open_with_keys`.
- **FFI `SpaceHandle::add_space` (+ async `AsyncSpaceHandle::add_space`)** — add a
  new parallel, deniable space to an *existing* container, keyed by a new
  password. Where `create` bootstraps a fresh container file (and fails if one
  exists), `add_space` opens the container already on disk and bootstraps an
  additional space inside it (`Container::open` + `create_space`). This is the
  FFI primitive for host-apps that hide several identities in one file; it
  returns `SpaceAlreadyExists` on password collision so the caller can fall back
  to `open`. Additive (no format/existing-API change); the sync↔async 1:1 mirror
  is preserved.

## [1.1.0] — 2026-06-11

audit pass 20 — soundness, error-fidelity, walker-consistency,
doc-actualization. No on-disk format change (format stays
`format_version = 3`). The single breaking change is confined to the
internal `hidden-volume-rt` crate (`space_mut` → `with_space_mut`),
which is documented as not-for-end-user-consumption; the frozen
`hidden-volume` + `hidden-volume-ffi` public API gains only the
additive `HvError::ContainerTooLarge` variant.

### Security — audit pass 20

- **`hidden-volume-rt::OwnedSpace::space_mut` was unsound** and is
  replaced by a higher-ranked closure accessor `with_space_mut`. The
  old signature `&'a mut self -> &'a mut Space<'a>` let region
  inference unify the inner lifetime across two `OwnedSpace` values,
  so `mem::swap(a.space_mut(), b.space_mut())` could exchange the two
  `Space`s between containers in 100% safe code — dropping one then
  freed the `Box<Container>` the other borrowed (use-after-free). The
  `for<'a> FnOnce(&mut Space<'a>) -> R` bound makes the borrow
  un-nameable and unswappable. The async/FFI wrappers (the only
  shipped consumers) were never reachable for the swap, but
  `hidden-volume-rt` is a published `1.0.0` crate with a public API.
  *Breaking* for any direct `hidden-volume-rt` consumer (an explicitly
  internal crate).
- **`derive_master_key` / `SpaceKeys` now have known-answer tests**
  (`tests/v3_key_schedule.rs::key_schedule_known_answer_vectors`). The
  v3 key schedule is the on-disk format's cryptographic identity, yet
  no test pinned the actual derived bytes — a refactor of a kind-tag,
  context label, or LE-encoding could silently brick every container
  while passing the suite. The bytes are unchanged; the format stays
  `format_version = 3`.

### Fixed — audit pass 20

- **FFI dropped `Error::ContainerTooLarge` into `Internal("unknown
  error variant")`.** Added `HvError::ContainerTooLarge { extra, cap }`
  + an explicit `From` arm + the Dart `_hvErrorKinds` entry. The
  write-side budget error is caller-actionable (shrink
  `initial_garbage_chunks` / pick a lighter padding policy) and now
  surfaces as a typed variant instead of "internal bug". *Additive*
  to the `#[non_exhaustive]` `HvError`.
- **`Space::get` accepted a Leaf one level deeper than every other
  walker.** The `MAX_TREE_DEPTH` check sat inside the `Internal` arm,
  so a forged tree presenting a `Leaf` at depth 4 returned a value
  while `list` / `count` / `iter_log_*` / `verify` rejected it. Moved
  the check to loop entry, restoring the documented "identical across
  read paths" invariant.
- **Log read paths (`iter_log_*`, `read_log`) relied on the
  8-byte-key / DataBatch-pointer shape heuristic** instead of the
  persisted `NamespaceKind` byte (R-NSKIND parity gap — vacuum/repack
  were already kind-driven). A KV namespace holding 8-byte keys *and*
  values gave an unpredictable error taxonomy; it now returns a clean
  `WrongNamespaceKind` before any leaf walk.
- **A forged tree with overlapping leaf ranges could commit an
  unsorted leaf** (per-node decode checks only intra-leaf order; the
  release `LeafNode::encode` only `debug_assert`s global sortedness),
  bricking the namespace on the next read. `flatten_tree` now rejects
  a non-globally-sorted / duplicate-key flatten.
- **Out-of-range slot pointers reported `Error::Internal`** (reserved
  for crate bugs) instead of `Error::Malformed`; a decrypted-but-
  corrupt or forged pointer is input-driven. `read_slot` /
  `read_slot_concurrent` now return `Malformed`.
- **`run_blocking` mapped runtime-shutdown cancellation to
  `Internal`** despite `HvError::Cancelled` existing; now maps to
  `Cancelled`.
- **`open` retained every distinct-seq Superblock-kind payload
  unbounded** — a key-holder could force tens of GiB of retention.
  Candidates are now length-gated to `Superblock::ENCODED_LEN`
  (behaviour-preserving; `decode` rejected the rest anyway).
- **`PasswordRotation` derived `Debug`**, which would print both
  passwords; replaced with a redacted manual impl (mirrors the
  pass-17 no-`Clone` rationale).
- **Flutter platform unit tests asserted the removed
  `getPlatformVersion` MethodChannel handler** and would fail to
  build against the no-op plugin shells; rewritten as registration
  smoke tests.
- **Doc-actualization**: `format.md` IndexNode discriminators
  corrected to the real on-disk bytes (`0x00 = Leaf`, `0x01 =
  Internal`; the doc said `0x01`/`0x02`) and the unaligned-tail
  invariant corrected to "tolerated" (EN+RU); `operations.md` Argon2
  migration recipe switched from a racy manual `repack`+`rename` to
  the in-place `change_passwords` primitive, plus empty-password-list
  data-loss-by-design and stale-temp-cleanup notes (EN+RU); stale
  `uniffi 0.28` → `0.31`, Flutter "in progress" → "implemented",
  branch-CI-intentionally-disabled, and repo-URL fixes across docs,
  comments, and plugin metadata.
- **`cargo deny` duplicate-dependency warnings** (`cpufeatures`,
  `getrandom`, `thiserror`, `winnow`) documented in `deny.toml`;
  `head -n -1` (unsupported on BSD/macOS) replaced with `sed '$d'`
  in the build scripts; dead test helper + `LD_LIBRARY_PATH` placebo
  removed.

### Fixed

- **`fuzz-smoke` CI job was silently non-functional since v1.0.0.**
  `crates/hidden-volume/fuzz/Cargo.toml` still pinned
  `hidden-volume = { version = "0.1.0" }` while the crate was bumped
  to `1.0.0` at release; the fuzz harness is workspace-`exclude`d so
  the version bump skipped it and no regular CI job builds it. Every
  `cargo fuzz` invocation failed dependency resolution
  (`candidate versions found which didn't match: 1.0.0`). Because the
  `fuzz-smoke` job is `continue-on-error: true`, the breakage never
  blocked a release — it just went red unnoticed. Bumped the pin to
  `1.0.0` (matching the other three workspace crates); all three fuzz
  targets now build and run clean (plaintext_decode 105M runs,
  decoder_family 610K, container_open 2.58M, zero crashes). The fuzz
  lockfile is now gitignored as a build byproduct.

## [1.0.0] — 2026-05-28

**Production release. On-disk format and public API are now frozen.**

Twelve months from project bootstrap through v0.1 → v0.8 → v0.1.0
(first SemVer tag, 2026-05-10) to v1.0.0 (this tag). Cumulative
audit count: **19 in-tree passes**, 0 unaddressed critical / high
findings. **397 tests** green across the workspace at the cut
(`cargo test --workspace --all-features`). The Flutter plugin
exits `experimental/` only when uniffi-dart matures (tracked as
post-1.0 packaging, not v1.0-blocking).

What "frozen" means concretely:

- **On-disk format**: `format_version = 3` is the v1.0 generation.
  Future readers must continue to read v3 containers without
  modification for at least one major-version cycle (v2.x reads
  v3; v3.x may drop v3 support). Format breaks require a major
  bump and ship a migration tool. See
  [`docs/en/reference/format.md`](docs/en/reference/format.md) §7.
- **Public Rust API**: every `pub` item in `crates/hidden-volume/src/`
  (Container, Space, Tx, CancelToken, SpaceKeys, error variants,
  feature-gated entry points) is part of the SemVer contract. The
  snapshot is locked down in
  [`docs/en/reference/api-surface.txt`](docs/en/reference/api-surface.txt);
  `scripts/dump-public-api.sh --check` is a release-blocking gate.
- **Public FFI API**: every `#[uniffi::*]`-annotated item in
  `crates/hidden-volume-ffi/src/lib.rs` is part of the contract.
  Generated bindings (Kotlin / Swift / Python / Ruby) ship from
  the same source.

### Added — TM1 CT companions for parallel-scan and mmap

The threat-model §4.4 scope previously read "Sequential-scan only"
— this v1.0 ships the missing companions:

- [`Container::open_space_parallel_constant_time`](crates/hidden-volume/src/container/mod.rs)
  + `_with_keys_parallel_constant_time` sibling. Parallel-scan
  speedup + per-chunk ChaCha20 timing equalizer.
- [`Container::open_space_mmap_constant_time`](crates/hidden-volume/src/container/mod.rs)
  + `_with_keys_mmap_constant_time` sibling. Zero-allocation mmap
  read path + the same equalizer.

Both reuse the existing `equalize_timing_via_chacha20` primitive
on every MAC-fail (introduced by audit pass 19 round 1). New tests
in `tests/parallel_scan_constant_time.rs` and
`tests/mmap_scan_constant_time.rs` lock down the equivalence of
recovered `Space` state across scan modes (2 + 2 = 4 new tests).
The dead `try_decrypt` wrapper that round-1 left feature-cfg-gated
was removed; both `scan_and_recover_parallel` and
`scan_and_recover_mmap` now call `try_decrypt_with_options` directly,
mirroring the sequential path's plumbing. Threat-model §4.4 and
`docs/{en,ru}/reference/format.md` updated to reflect the shipped
shape (no more "sequential only" caveat).

### Breaking — v3 format-bump (2026-05-28)

`format_version` bumped 2 → 3. v2 containers are not readable by v3
builds and v3 containers are not readable by v2 builds. The reject is
**doubly bound**: by `Argon2Params::validate` policy gate AND by the
v3 cryptographic version-binding step in the key chain. Pre-1.0 — no
in-place migration tool ships; cross-version transitions go through
the export-and-reimport recipe documented in
[`docs/en/guide/migration.md`](docs/en/guide/migration.md).

Three independent hardenings shipped together as a single
format-bump (saves users from a double-migration through v3a/v3b):

- **#8 — Kind-tag bytes in BLAKE3 inputs.** Every BLAKE3-keyed input
  in the key chain now starts with an explicit kind-tag byte:
  `SUBKEY_KIND_TAG = 0x01` for [`derive_subkey`](crates/hidden-volume/src/crypto/derive.rs)
  inputs, `CHUNK_KEY_KIND_TAG = 0x02` for [`derive_chunk_key`](crates/hidden-volume/src/crypto/derive.rs).
  Replaces the audit-pass-7-D3 length-distinguishes convention with
  an explicit content-based domain separator. P-LOW2 closed.
- **#9 — Cryptographic version-binding (closes pass-18 M5).** [`derive_master_key`](crates/hidden-volume/src/crypto/kdf.rs)
  now folds `params.version` into the master key through a
  post-Argon2 BLAKE3 step: `versioned_master = BLAKE3-keyed(argon_out,
  b"hv/v3/master" || u32_le(params.version))`. Cross-version key
  reuse is closed cryptographically, not only by `validate()`
  policy. As a side effect F-PAD (audit pass 9) is **reclassified
  from silent privacy-degradation to DoS-class visible failure**:
  the `padding_policy_index` byte at bits 16..24 of `params.version`
  is now part of the BLAKE3 input, so a tamper produces a different
  `master_key` ⇒ next open hits `Error::AuthFailed`. The DoS
  surface remains acceptable (any cleartext-header tamper can deny
  open); the privacy surface is closed. See
  [`docs/en/security/threat-model.md`](docs/en/security/threat-model.md) §4.1.
- **#10 — Per-space derived `container_id` (closes D1-A2
  fingerprint).** `container_id` is no longer stored in the
  cleartext header. [`SpaceKeys::from_master`](crates/hidden-volume/src/crypto/derive.rs)
  derives it per-space alongside `aead_root` from the versioned
  master key. Cross-container relocation defense is preserved
  (different salts ⇒ different master_keys ⇒ different
  container_ids), and the cleartext header no longer carries any
  per-space identifier. `HEADER_LEN`: 80 → 48.

Public API impact:

- [`Header`](crates/hidden-volume/src/container/header.rs) struct
  loses its `container_id` field; the only fields are now `salt` and
  `params`.
- [`SpaceKeys`](crates/hidden-volume/src/crypto/derive.rs) gains a
  `container_id: [u8; 32]` field; `SpaceKeys::from_master(versioned_master)`
  is now the construction entry point.
- [`HEADER_LEN`](crates/hidden-volume/src/lib.rs) = 48 (was 80);
  `HEADER_CONTAINER_ID_OFFSET` / `HEADER_CONTAINER_ID_LEN` removed.
- [`HeaderInfo` (FFI)](crates/hidden-volume-ffi/src/lib.rs) loses
  its `container_id_hex` field; `hv info` CLI no longer prints
  `container_id:`.
- All docs (`docs/en/reference/format.md`, `docs/ru/...`,
  `docs/en/security/threat-model.md`, `docs/en/security/audits/self-audit.md`,
  `docs/en/security/audits/format-fuzzing.md`, `docs/en/guide/migration.md`,
  RU mirrors) actualized for v3 layout.

### Added — TM1 timing-oracle partial mitigation (2026-05-28)

Opt-in constant-time scan path closes the dominant component of the
F-TM1 leak documented in
[`docs/en/security/threat-model.md`](docs/en/security/threat-model.md) §4.4.

- New [`Container::open_space_constant_time`](crates/hidden-volume/src/container/mod.rs)
  + `open_space_with_keys_constant_time`. On MAC-fail, runs
  `crypto::aead::equalize_timing_via_chacha20` over the AEAD body
  length to equalize the dominant per-chunk cost component.
- Honest scope (audit pass 19 follow-through): the equalizer closes
  the ChaCha20-body component (~1-3 µs) of the bench-measured
  ~40 µs/chunk swing on M5 Pro. The remaining parsing/allocation/
  `owned_slots.push` overhead is **not** equalized — host-apps
  needing full constant-time should additionally pad the post-open
  processing externally. Documented in detail in the threat-model
  honest-scope table.
- New direct dep `chacha20 = "0.9"` to drive the equalizer without
  going through the full AEAD machinery.
- Default callers should stick with `open_space`; the constant-time
  path roughly doubles open-time on garbage-heavy containers.
- New test [`tests/constant_time_scan.rs`](crates/hidden-volume/tests/constant_time_scan.rs)
  + benches in [`benches/timing_oracle.rs`](crates/hidden-volume/benches/timing_oracle.rs)
  extended with multi-variant `ScanMode` enum (sequential / parallel
  / mmap) confirming the leak shape is uniform across modes (closes
  audit pass 5 SC-INFO2 hypothesis).

### Added — B+ tree depth cap (2026-05-28, F-A5)

New `pub(crate) const MAX_TREE_DEPTH: u8 = 3` in
[`crates/hidden-volume/src/space/index.rs`](crates/hidden-volume/src/space/index.rs).
Every recursive B+ tree walker now caps its descent at this depth:

- [`Space::get`](crates/hidden-volume/src/space/mod.rs) (KV lookup);
- `collect_leaves_at` / `count_leaves_at` ([`space/mod.rs`](crates/hidden-volume/src/space/mod.rs));
- [`log_iter::*`](crates/hidden-volume/src/space/log_iter.rs) (after / before / range);
- [`integrity::*`](crates/hidden-volume/src/space/integrity.rs) walkers;
- [`vacuum::*`](crates/hidden-volume/src/space/vacuum.rs).

A pathological cyclic Internal→Internal chain (T2 file-modification
adversary scenario) trips `Error::Malformed("tree depth exceeded
MAX_TREE_DEPTH")` after at most this many descents. Writer-side
invariant continues to guarantee depth ≤ 2 in well-formed containers.

### Added — Self-audit dossier + signed-release pipeline (2026-05-28)

External paid audit (Trail of Bits / Cure53 / NCC class) is not
planned for this project (anonymity + no-budget rationale). The
substitute is a documented self-audit + community-disclosure path.

- New [`docs/en/security/audits/self-audit.md`](docs/en/security/audits/self-audit.md)
  dossier covering: dependency provenance, primitive choices, all
  security invariants (D1 / D2 / I1-3 / R1 / M1 / C1) with code
  references, open items and acknowledged gaps, "how to verify
  yourself" procedures, community bug-bounty terms.
- 5-pass deep-review series committed alongside the dossier:
  [`adversarial-stance.md`](docs/en/security/audits/adversarial-stance.md),
  [`primitive-level.md`](docs/en/security/audits/primitive-level.md),
  [`side-channel-surface.md`](docs/en/security/audits/side-channel-surface.md),
  [`format-fuzzing.md`](docs/en/security/audits/format-fuzzing.md),
  [`threat-model-challenge.md`](docs/en/security/audits/threat-model-challenge.md).
  0 critical / 0 high / 0 medium findings across the series.
- Signed-release pipeline shipped in
  [`.github/workflows/release.yml`](.github/workflows/release.yml):
  cosign keyless via GitHub Actions OIDC, GitHub Release
  auto-creation, `cargo publish` auto-skip on `publish = false`
  crates. Verification doc:
  [`docs/en/contributing/verifying-release.md`](docs/en/contributing/verifying-release.md).

### iOS packaging — xcframework closed (2026-05-28)

The last open v0.8 item (iOS `xcframework`) is closed. Built on an
Apple-silicon macOS host now that the toolchain is available.

#### Added

- **`HiddenVolumeFFI.xcframework`** produced by
  [`scripts/build-ios.sh`](scripts/build-ios.sh): `ios-arm64` device
  slice + `ios-arm64_x86_64-simulator` fat slice (arm64 + x86_64),
  staged under `experimental/flutter_plugin/hidden_volume/ios/`. Swift
  bindings regenerated against uniffi 0.31. The same Dart FFI code path
  now runs on iOS, Android, Windows desktop, and the web-free desktop
  targets.

#### Fixed

- **iOS static-lib symbols dead-stripped from the dynamic plugin
  framework.** Under Flutter's `use_frameworks!`, the Rust staticlib is
  linked into the dynamic `hidden_volume` framework via
  `-l"hidden_volume_ffi"`, but the framework's only compiled code is the
  no-op `HiddenVolumePlugin` stub — so the linker pulled in zero objects
  from the archive and the framework shipped with no Rust symbols. The
  Dart-side `DynamicLibrary.process()` lookup then failed at the first
  call with `dlsym … ffi_hidden_volume_ffi_uniffi_contract_version:
  symbol not found`. Fixed by adding
  `OTHER_LDFLAGS = -force_load "${PODS_XCFRAMEWORKS_BUILD_DIR}/hidden_volume/libhidden_volume_ffi.a"`
  to the podspec `pod_target_xcconfig`. Verified by the example app's
  `integration_test/app_test.dart` passing on an iPhone 17 simulator
  (iOS 26.5) — full Argon2 + KV + log round-trip green.

#### Notes

- On macOS the FFI cdylib is `libhidden_volume_ffi.dylib`, not the
  `.so` the `bindings/README.md` regeneration recipe hard-codes; pass
  the `.dylib` to `uniffi-bindgen --library` on this host.
- The Flutter plugin still uses CocoaPods, not Swift Package Manager;
  recent Flutter prints a (currently non-fatal) SPM-adoption warning.
  Tracked as a future packaging task, not a blocker.

## [0.1.0] — 2026-05-10

First formal SemVer tag. Snapshot of the workspace at the close of
v0.8 (FFI + Flutter integration) plus audit pass 18. Still pre-1.0:
on-disk format and public API may change in v0.x → v0.y bumps. v1.0
will freeze both pending external crypto-review (see `TASKS.md`).

Cumulative highlights since the project's start (only major themes —
per-pass detail follows below):

- **v0.1–v0.7**: foundation, multi-space deniable container, B+ tree
  indexes, log namespaces (DataBatch + zstd), crash-safe commit,
  vacuum, multi-device anchor contract, hardening passes,
  performance pass, async wrapper crate.
- **v0.8 (closed 2026-05-10)**: FFI surface (uniffi 0.31), Android
  `.so` per-ABI shipping, Windows desktop plugin packaging, hand-
  written Dart `dart:ffi` bindings (Path C) with worker-isolate async
  wrapper, end-to-end Flutter integration test passing on Windows
  desktop and Android emulator. iOS xcframework remains gated on a
  macOS host (only open v0.8 item).
- **Audit passes 1–18** (refactor + security): 378 tests pass,
  `cargo clippy --all-targets --all-features -- -D warnings` clean,
  `cargo audit` 0 vulns, `cargo deny check` clean, `cargo fmt`
  clean. TM1 timing-oracle leak verified and quantified
  (mitigation tracked for v1.1).

Released artifacts (CI matrix on `tags: [v*.*.*]` trigger): per-target
Rust binaries / Android `.so` per ABI / regenerated bindings for
Kotlin / Swift / Python / Ruby. iOS `xcframework` produced when a
macOS runner is available.

### Audit pass 18 — second-reviewer follow-through (2026-05-10)

A second independent code review (post-pass-17) found 4 medium-severity
issues my own merged audit missed plus several cleanup items. All
verified by reading the code, then fixed in this pass. **378 tests
pass** (was 377; +1 M2 regression). `cargo clippy --workspace
--all-targets --all-features -- -D warnings` clean. `cargo audit`
clean. `cargo fmt --check` clean.

#### Closed — Medium severity

- **M1 — `commit_tx` no longer returns `Err` after a durable commit.**
  Previously, the post-fsync padding step (DESIGN §8) could fail and
  surface as `Err` from `Tx::commit()` even though the superblock fsync
  had already published the commit to other processes. This violated
  the docstring invariant ("if commit_tx returns Err, state.superblock
  is unchanged") and risked host-app retries / sync-state corruption.
  Fix: catch padding errors inside `commit_tx`, stash on
  `SpaceState::last_padding_error`, return `Ok(new_seq)` regardless.
  New public read-only accessor `Space::last_padding_error()` lets
  host-apps surface a privacy-hardening warning without confusing it
  with a commit failure. Files: [`crates/hidden-volume/src/space/commit.rs:280-310`](crates/hidden-volume/src/space/commit.rs),
  [`crates/hidden-volume/src/space/mod.rs:163-175,348-360`](crates/hidden-volume/src/space/mod.rs).

- **M2 — `verify_integrity` now covers `DataBatch` chunks for log
  namespaces.** Previously the Merkle walk stopped at Leaf nodes; the
  `DataBatch` chunks pointed at by log-namespace leaf entries were
  never AEAD-decrypted or `decode_batch`-validated. A corrupted
  DataBatch would pass `verify_integrity` and only fail later at
  `read_log` time. Fix: extend the walker for Log roots to collect +
  dedup batch_slot pointers, then AEAD-decrypt + decode each.
  `IntegrityReport` gains `data_batches_verified: usize` (mirrored on
  the FFI surface as `IntegrityResult.data_batches_verified: u64`).
  New regression test [`corruption_of_databatch_chunk_surfaces_as_integrity_failure`](crates/hidden-volume/tests/integrity.rs)
  proves a corrupted DataBatch now fails the walk. Files:
  [`crates/hidden-volume/src/space/integrity.rs`](crates/hidden-volume/src/space/integrity.rs),
  [`crates/hidden-volume/src/space/mod.rs:121-138`](crates/hidden-volume/src/space/mod.rs),
  [`crates/hidden-volume-ffi/src/lib.rs:518-528,770-776,1098-1104`](crates/hidden-volume-ffi/src/lib.rs).

- **M3 — `atomic_rewrite_under_source_lock` race window narrowed.**
  Between Container's drop (end of `write` closure) and the `rename`,
  there was a window in which an attacker with directory write+read
  access could substitute the tmp-file contents (we'd then rename
  attacker content into `path`). Fix: after writer drop, re-open tmp
  with `LOCK_EX`, validate the cleartext header (Argon2 params must
  pass `validate()`), and on Unix capture the inode before rename then
  verify the post-rename inode matches. Documented `path.parent()` as
  a trusted-directory precondition in the function docstring +
  [`SECURITY.md`](SECURITY.md). Files:
  [`crates/hidden-volume/src/container/mod.rs:1004-1148`](crates/hidden-volume/src/container/mod.rs).

- **M4 — Android lock skip precondition documented as a hard
  requirement.** The 2026-05-10 `cfg(target_os = "android")` flock
  skip is safe only when the container lives in app-private storage.
  Previously this was implicit ("Android sandbox provides isolation")
  with no enumerated NOT-safe paths. Fix: explicit precondition
  comment in [`container/file.rs`](crates/hidden-volume/src/container/file.rs)
  + new "Not in scope" bullet in [`SECURITY.md`](SECURITY.md) listing
  shared/external storage, MediaStore URIs, MultiUserMode, and the
  `android:process=...` multi-process case as out-of-scope.

- **M5 — v3 format-version cryptographic-binding constraint
  documented.** v2 ships safely (gate via `Argon2Params::validate()`),
  but any v3 spec must bind `format_version` either in the Argon2id
  input or in every per-chunk AEAD AAD to close the cross-version
  replay class. Added as new question 6 in [`DESIGN.md`](DESIGN.md)
  §11 ("Open questions"). Not a v2 vulnerability.

#### Cleanup

- **Method-channel scaffolding reduced to no-op stubs** on
  Android / iOS / Windows. The "PRIMARY (Dart `dart:ffi`) /
  SECONDARY (Method Channel)" two-path narrative documented in the
  scaffolding comments was never actually wired up; the secondary
  channel was a documented placeholder that integrators would have
  had to fill in themselves. With Path C (hand-written `dart:ffi`)
  now production-ready (audit 2026-05-10), the secondary path is
  unmotivated maintenance burden. Files:
  [`HiddenVolumePlugin.kt`](experimental/flutter_plugin/hidden_volume/android/src/main/kotlin/dev/hidden_volume/hidden_volume/HiddenVolumePlugin.kt),
  [`HiddenVolumePlugin.swift`](experimental/flutter_plugin/hidden_volume/ios/Classes/HiddenVolumePlugin.swift),
  [`hidden_volume_plugin.{cpp,h}`](experimental/flutter_plugin/hidden_volume/windows/hidden_volume_plugin.cpp).
- **Broken doc link** `docs/en/security/cli.md` removed from
  [`hv.rs:351`](crates/hidden-volume/src/bin/hv.rs); replaced with an
  inline `--help`-pointer that doesn't bit-rot.
- **Stale `UnimplementedError` Flutter docs** updated. The
  experimental plugin README and the parent `experimental/README.md`
  table both claimed the Dart facade throws `UnimplementedError`;
  reality (since Path C closure 2026-05-10) is the typed `HvSpace` +
  `HvAsyncSpace` API is fully implemented. Files updated:
  [`experimental/README.md`](experimental/README.md),
  [`experimental/flutter_plugin/hidden_volume/README.md`](experimental/flutter_plugin/hidden_volume/README.md).
- **Placeholder `LICENSE` ("TODO: Add your license here.")** in the
  example Flutter plugin replaced with a dual-MIT-OR-Apache-2.0
  pointer to the parent workspace's [`LICENSE-MIT`](LICENSE-MIT) /
  [`LICENSE-APACHE`](LICENSE-APACHE).
- **Duplicate Android `MainActivity`** removed. The example app had
  two — one at `com/example/hidden_volume_example/MainActivity.kt`
  (matches namespace + applicationId, used by the `.MainActivity`
  manifest reference) and one at
  `dev/hidden_volume/hidden_volume_example/MainActivity.kt` (stray,
  never reached). The unused stray + its empty parent dirs are gone.

### Flutter integration milestone (2026-05-10)

Closed two of the three open v0.8 platform-packaging items end-to-end
on a Windows dev box (the third — iOS xcframework — remains gated on
macOS+Xcode access). Highlights:

- **Android `.so` per ABI shipped.** All four ABIs (arm64-v8a /
  armeabi-v7a / x86_64 / x86) build via
  [`scripts/build-android.sh`](scripts/build-android.sh) using
  cargo-ndk 4.1.2 and NDK r27d. Output staged in the plugin's
  `jniLibs/` so any downstream `flutter build apk` picks them up.
- **Windows packaging shipped.** Plugin pubspec now declares Windows
  as a supported platform. New `scripts/build-windows.sh` stages the
  cdylib at `experimental/flutter_plugin/hidden_volume/windows/lib/`;
  the plugin's `windows/CMakeLists.txt` bundles it via
  `<plugin>_bundled_libraries`, so `flutter build windows` copies
  `hidden_volume_ffi.dll` next to the runner `.exe` automatically.
- **Typed Dart API shipped (Path C — hand-written `dart:ffi`).**
  `uniffi-bindgen-dart` 0.1.3 had two blocking bugs (enum marshalling
  generates wrong wire-format; async constructors are stubbed
  `UnsupportedError`-throwers) and required uniffi 0.31. We bumped
  uniffi 0.28 → 0.31 in `hidden-volume-ffi` (clean drop-in, source
  unchanged) and bypassed the buggy generator. The plugin now exposes
  a hand-written, typed `HvSpace` facade ([`lib/hidden_volume.dart`](experimental/flutter_plugin/hidden_volume/lib/hidden_volume.dart))
  backed by [`lib/src/bindings.dart`](experimental/flutter_plugin/hidden_volume/lib/src/bindings.dart)
  (~700 LOC speaking the stable uniffi 0.31 C ABI). Full sync surface:
  `create / open / commit / get / iterLogRange / commitSeq /
  commitHistory / count / eraseNamespace / readLog / listNamespaces /
  setPaddingPolicy / stats / vacuumDataBatches / verifyIntegrity /
  close` plus top-level `headerInfo / changePasswords / compactKnown`.
- **Async wrapper via worker isolate.** `HvAsyncSpace` ([`lib/src/async_bindings.dart`](experimental/flutter_plugin/hidden_volume/lib/src/async_bindings.dart))
  spawns a dedicated `Isolate`, owns the `SpaceHandleBindings` there,
  and routes typed requests over `SendPort`. Frees the Flutter UI
  thread from blocking on Argon2 KDF or the open-time scan.
  `headerInfoAsync / changePasswordsAsync / compactKnownAsync` use
  `Isolate.run` for one-shot off-main execution.
- **Auto-cleanup via `Finalizer`.** `SpaceHandleBindings` attaches a
  `Finalizer<int>` to free the Rust handle on GC if the host forgets
  `close()`. Mirrors Python's `__del__` discipline.
- **Example app + integration test.** Minimal Flutter app at
  [`experimental/flutter_plugin/hidden_volume/example/`](experimental/flutter_plugin/hidden_volume/example/)
  drives the round-trip end-to-end (create → commit puts +
  append_logs → get → iter_log_range → stats → close → headerInfo)
  and renders the result. Integration test
  ([`example/integration_test/app_test.dart`](experimental/flutter_plugin/hidden_volume/example/integration_test/app_test.dart))
  passes on **Windows desktop** AND on the **Android x86_64 emulator**
  (API 36) — full vertical: Rust core → uniffi 0.31 cdylib →
  hand-written Dart bindings → async worker isolate → Flutter UI.
- **Bench Dart vs Python (Windows / NVMe / Argon2 LIGHT).**
  `dart:ffi` per-op p50: `get` 45.7 µs, `headerInfo` 84.6 µs vs
  Python ctypes 58.2 µs / 125 µs respectively (Dart ~20-30% faster on
  read-side ops; `commit` and `create` are dominated by fsync /
  Argon2 and equalize). Sources:
  [`experimental/flutter_plugin/hidden_volume/bench/`](experimental/flutter_plugin/hidden_volume/bench/).

### Fixed — Android target lacks `File::try_lock`

- **Android flock skip.** Stable Rust 1.89's `File::try_lock` is not
  implemented for `target_os = "android"` — the literal returns
  `Unsupported "try_lock() not supported"` (only `linux`, `freebsd`,
  `apple`, etc. are wired up; `android` is omitted from the cfg gate
  in `library/std/src/sys/fs/unix.rs`). Detected when running the
  Flutter integration test against the Android emulator. Added
  `cfg(target_os = "android")` branches to `try_lock_exclusive` /
  `try_lock_shared` in [`crates/hidden-volume/src/container/file.rs`](crates/hidden-volume/src/container/file.rs)
  that return `Ok(())`. Rationale: Android sandboxes each app under
  its own UID and the container file lives in the app's private
  storage, so cross-process file-lock coordination is moot. The
  in-process `Mutex` inside `SpaceHandle` already enforces single-
  writer semantics within a process. **No security regression**:
  cross-process sharing of an Android container file is not a
  supported use-case.

### Closed — architectural backlog E5/E6/E7

- **E5/E6 confirmed already closed in audit pass 8.** TASKS.md
  carried them as «deferred» but [`crates/hidden-volume-rt`](crates/hidden-volume-rt/)
  has been the canonical home for `OwnedSpace` (E5) and
  `run_blocking` (E6) since pass 8. Both `hidden-volume-async` and
  `hidden-volume-ffi` import from it. Updated TASKS.md to reflect
  reality.
- **E7 reassessed as WONTFIX 2026-05-10.** Original concern was
  `space/mod.rs` at 1485 lines; after pass-8/13/16 refactoring the
  file is now 689 lines with a contiguous, well-organized
  `impl Space<'f>` block. Splitting now would harm auditor
  top-to-bottom readability for no maintainability win. Closed.

### Verified — TM1 (open-time scan timing oracle)

- **TM1 verified, leak quantified, mitigation deferred to v1.x.**
  Ran [`crates/hidden-volume/benches/timing_oracle.rs`](crates/hidden-volume/benches/timing_oracle.rs)
  on Windows / NVMe (Argon2 MIN, 500 slots). Result:
  `frac_owned=0.10 → 20.3 ms`, `0.50 → 48.5 ms`, `0.90 → 49.6 ms` —
  open-scan time grows roughly linearly with owned-fraction, ~37 ms
  per fraction unit (~75 µs per chunk). The original cache-effect
  hypothesis was wrong; the actual mechanism is more direct: a
  successful per-chunk AEAD-decrypt runs ChaCha20 over the full
  body, while a failed MAC short-circuits before the body decrypt.
  **Granularity:** the leak reveals owned/total fraction, not which
  chunks belong to which space — D2 (deniability of password) holds.
  **Mitigation** (deferred): replace early-MAC-fail with a constant-
  time AEAD that always runs ChaCha20 over the body and discards on
  MAC mismatch (~2× cost on garbage chunks; eliminates the
  side-channel). Tracked for v1.1 in [`docs/en/security/threat-model.md`](docs/en/security/threat-model.md)
  §F-TM1. The linearity test passed (~22 / 32 / 47 ms for total =
  100 / 500 / 1000 slots), confirming Θ(N) per-chunk cost.

### Breaking — uniffi bump 0.28 → 0.31

- **`hidden-volume-ffi` now requires uniffi 0.31** (previously 0.28).
  Drop-in: no source changes were needed inside the FFI crate. The
  bump was driven by Flutter Dart-binding work — `uniffi-bindgen-dart`
  needs uniffi 0.30+ contract version. New `scaffolding-ffi-buffer-fns`
  feature added to the uniffi dep so the cdylib exports the
  `uniffi_ffibuffer_*` symbol family that the foreign-side hand-
  written bindings consume. All 14 FFI unit tests + 3 smoke tests
  still pass; Kotlin / Swift / Python / Ruby / Dart bindings all
  regenerated cleanly against the bumped contract.
- **`tests/ffi_smoke.rs`** test renamed:
  `contract_version_value_is_uniffi_028_compatible` →
  `contract_version_value_is_plausible` (the bench was already
  version-agnostic in implementation; the name stuck from the 0.28
  era).

### Breaking — audit pass 17 (security/quality follow-through)

- **New `Error::ContainerTooLarge { extra, cap }` variant.** Symmetric
  write-side / read-side budget for [`MAX_OPEN_SCAN_CHUNKS`](crates/hidden-volume/src/open/mod.rs)
  (= 16 M chunks ≈ 64 GiB). `Container::create_with_options`,
  `commit_tx` post-commit padding, and `repack` destination growth
  refuse with this error if the write would push the file past the
  cap. Previously the open-side rejected with `Error::Malformed` —
  symmetric gate avoids the create-then-can't-reopen footgun.
- **`PaddingPolicy::garbage_after_commit` returns `Result<u64>`**
  (was `u64`). Extreme-input arithmetic (`div_ceil(b) * b` overflow,
  `u128 as u64` truncation) now surfaces as `Error::Internal` instead
  of panicking in debug or wrapping in release.
- **`Space::iter_log_after / before / range` strict mode.** Non-8-byte
  keys (caller passed a KV namespace by mistake, or writer-bug
  regression) now return `Error::WrongNamespaceKind` instead of
  silently skipping. Matches the strictness of `Space::iter_log`.
- **`Container::open_space_verified` defers auto-vacuum** until after
  `verify_integrity` succeeds. Old behavior leaked observable
  mutation on verify failure; the documented "no observable mutation
  on failure" guarantee now actually holds.
- **`PasswordRotation` no longer derives `Clone`.** Defense-in-depth
  against accidental `.clone()` bypass of the pass-16 `Zeroizing`
  flow. No current callsite cloned, so this is zero behavior cost
  on the happy path.
- **CLI `hv` and `hidden-volume-async` now use `Zeroizing` for
  password buffers** — symmetric with the FFI crate's pass-16
  treatment. New `zeroize = "1.8"` dep in `hidden-volume-async`.
- **MSRV bumped 1.85 → 1.89** to pick up `File::try_lock`
  stabilization.
- **New `pub use crate::MAX_OPEN_SCAN_CHUNKS`** at crate root.
  Integrators can pre-validate `initial_garbage_chunks` /
  padding-policy growth against the cap.
- **Internal:** `unreachable!()` in `space/index.rs` decode paths
  replaced with `Err(Error::Internal)` for friendlier failure mode.
  Error-string for the open-scan-budget gate trimmed (audit-pass
  references no longer leak through FFI to foreign-side consumers).
- **389 tests pass** (was 387; +2 PaddingPolicy extreme-input
  regressions in `padding/mod.rs`).

### Breaking — audit pass 16 (R-STREAMING-REPACK + DoS budget + FFI Zeroizing)

- **Streaming repack.** `Container::repack` and the in-place
  `compact_known` / `change_passwords` flows page through log
  namespaces via `iter_log_after(ns, cursor, log_page_size)` with
  per-page `Tx::commit`. Working set ceiling drops from
  O(total plaintext) to O(page) ≈ 4 MiB regardless of total log
  volume. KV namespaces still collect once per namespace (bounded
  by the structural B+ tree cap).
- **Open-scan budget.** New constant
  [`MAX_OPEN_SCAN_CHUNKS = 16 × 1024 × 1024`](crates/hidden-volume/src/open/mod.rs)
  (≈ 64 GiB at `CHUNK_SIZE = 4096`). All three discovery scans
  (sequential, parallel, mmap) call `check_scan_budget(total)`
  before iterating, so an adversary-inflated container header
  can no longer force the reader into a 100-GiB Argon2 / AEAD
  attempt loop. Closes the TM1 escalation flagged by audit pass 14.
- **FFI password Zeroizing.** Every FFI password entry point now
  wraps the incoming `Vec<u8>` in `zeroize::Zeroizing` immediately
  on entry: `SpaceHandle::create`, `SpaceHandle::open`,
  `AsyncSpaceHandle::create`, `AsyncSpaceHandle::open`, top-level
  `compact_known(path, passwords)`, and `change_passwords(path,
  rotations)`. Foreign-side buffers remain the caller's hygiene
  responsibility (documented at the crate level + on
  `PasswordRotation`).
- **387 tests pass** (was 385; +2 streaming-repack regressions).

### Breaking — audit pass 15 (`open_space_verified` strict mode)

- **New `Container::open_space_verified` / `open_space_with_keys_verified`.**
  Strict-mode opens that run `Space::verify_integrity` before
  returning, surfacing any Merkle-chain or AEAD failure at open
  time rather than at first read. Useful for forensics / backup
  tooling and security-paranoid host-apps.
- **`ContainerFile::append_garbage_chunks` batched I/O.** Coalesces
  writes into batches of up to 64 chunks (256 KiB) per syscall,
  reducing a 1024-chunk decoy from 1024 syscalls to 16. Buffer is
  `Zeroizing`-wrapped.
- **F-PAD threat-model entry added** (`docs/en/security/threat-model.md`
  §4.1 / `docs/ru/...`). Documents the multi-snapshot adversary's
  ability to read the cleartext `padding_policy_index` byte and the
  forward-compat fallback to `None` for unknown indices.

### Breaking — format v2 (audit pass 13, R-NSKIND)

- **`PARAMS_VERSION` bumped from 1 to 2.** v1 containers cannot be
  opened by v2 readers (`Argon2Params::validate` rejects unknown
  `format_version`). Pre-1.0 — breaking is acceptable per the
  maintainer policy.
- **`CommitPayload` per-root layout grew 41 → 42 bytes.** New
  1-byte `kind` field (0 = Kv, 1 = Log) immediately after the
  per-root `namespace` byte. Closes audit pass 12 HIGH
  ("mixed-namespace data loss" via shape-heuristic in repack).
  See [`docs/en/reference/format.md`](docs/en/reference/format.md) §4.3
  for the full layout. `MAX_NAMESPACES_PER_TX` adjusted from ≈97 to
  ≈95.
- **New `pub enum NamespaceKind { Kv = 0, Log = 1 }`** in
  `hidden_volume::tx`. Re-exported from the crate root
  prelude path.
- **New `Space::list_namespaces_with_kind` API**. Returns
  `Vec<(Namespace, NamespaceKind)>` from the persisted
  `IndexRoot.kind` bytes.
- **Three-layer kind enforcement**: Tx-time check (synchronous
  `Error::WrongNamespaceKind`), commit-time cross-Tx check
  (rejects before writing any chunk), and on-disk persistence
  (every IndexRoot carries its kind). `Space::erase_namespace`
  uses a `pub(crate) Tx::delete_internal` bypass to drop log
  namespaces' KV layer; `commit_tx` allows pure-`Delete` op
  sets against Log namespaces.
- **`vacuum_data_batches` now iterates only Log-kind namespaces**
  when collecting referenced batch_slot pointers. Closes audit
  pass 12 MEDIUM ("8-byte KV value coincidentally suppresses
  scrub" false-negative window).
- **`Container::repack` routes by persisted `kind`** — the v1-era
  shape heuristic and `RepackOptions::log_namespaces` hint were
  removed. The `RepackOptions` struct lost the `log_namespaces`
  field entirely; downstream code using `..Default::default()` is
  unaffected; explicit struct-literal callers of v1-era code must
  drop the field.

### Security

- **Audit pass 14 — `Superblock` chunk-seq cross-check.** Recovery
  now rejects an SB whose decoded `Superblock.seq` disagrees with
  its chunk-level `Plaintext.seq`. Mismatch indicates writer-bug
  regression or post-AEAD tamper by a key-holder; recovery falls
  through to the next candidate instead of silently adopting an
  inconsistent state. Applies to all three scan paths
  (sequential, parallel, mmap).

- **D1 HIGH — Argon2 m_cost DoS via header tampering closed.**
  `Argon2Params::validate()` now caps `m_cost_kib ≤ 1 GiB`,
  `t_cost ≤ 100`, `p_cost ≤ 64`. Previously the cleartext header was
  unprotected and a T2 file-modification adversary could write
  `m_cost_kib = u32::MAX` (≈4 TiB) to OOM every subsequent
  `Container::open` during Argon2id derivation. New constants
  `Argon2Params::{MAX_M_COST_KIB, MAX_T_COST, MAX_P_COST}` document
  the ceilings. Coverage:
  `tests/header_params::params_above_ceiling_rejected_by_validate`
  (boundary cases at MAX, MAX+1, u32::MAX) +
  `tests/header_params::header_tamper_with_huge_m_cost_rejected_on_open`
  (real-attack reproduction: tamper a legit container's header bytes,
  re-open must fail with `Kdf` error in <1s — never trying to
  allocate). See `docs/THREAT_MODEL.md` §F1.

- **D1 HIGH — Argon2 m_cost DoS via header tampering closed.**
  `Argon2Params::validate()` now caps `m_cost_kib ≤ 1 GiB`,
  `t_cost ≤ 100`, `p_cost ≤ 64`. Previously the cleartext header was
  unprotected and a T2 file-modification adversary could write
  `m_cost_kib = u32::MAX` (≈4 TiB) to OOM every subsequent
  `Container::open` during Argon2id derivation. New constants
  `Argon2Params::{MAX_M_COST_KIB, MAX_T_COST, MAX_P_COST}` document
  the ceilings. Coverage:
  `tests/header_params::params_above_ceiling_rejected_by_validate`
  (boundary cases at MAX, MAX+1, u32::MAX) +
  `tests/header_params::header_tamper_with_huge_m_cost_rejected_on_open`
  (real-attack reproduction: tamper a legit container's header bytes,
  re-open must fail with `Kdf` error in <1s — never trying to
  allocate). See `docs/THREAT_MODEL.md` §F1.

### Added (refactor audit pass 8 — architectural cleanups, started 2026-05-04)

Group C of the post-pass-7 summary. Six architectural cleanups
planned; **TM1 + minimal-variant E5/E6** landed in this session.
The remaining three (E7 mod-split, E5/E6 full extraction, S1 full
format change, D10 cancellable-API consolidation) are scoped and
deferred to focused sessions — each is a 0.5–2 day mechanical
refactor with subtle risk that doesn't compose well with other
work.

- **TM1** — `crates/hidden-volume/benches/timing_oracle.rs` (new).
  Criterion-based open-time micro-bench measuring
  `Container::open_space` wall-clock as a function of
  (owned_fraction, total_slots). Closes a long-standing
  threat-model open question once run on real hardware:
  cache-effects from the `owned_slots` / `commit_history` /
  `sb_candidates` bookkeeping vectors during the discovery scan
  could in principle leak the owned-fraction to a same-host
  observer. Bench provides the empirical evidence base. Acceptance
  criterion is documented in the bench header — distributions for
  different fractions should overlap within criterion's noise
  floor; if not, the mitigation is to add fake-AEAD-attempts on
  non-owned slots to mask the cache signal. Registered as a
  second `[[bench]]` target in `crates/hidden-volume/Cargo.toml`.

- **E5 / E6 (MIRROR-annotation variant)** — `SpaceInner` and
  `run_blocking` are duplicated across `hidden-volume-async` and
  `hidden-volume-ffi`. Full extraction into a shared internal
  `hidden-volume-rt` crate is deferred (it requires generics over
  error types + new crate scaffolding + uniffi regeneration —
  too invasive for this session). As a minimal precaution against
  the duplicates drifting, both copies of each helper now carry an
  explicit **MIRROR** doc-comment cross-referencing the other
  copy, stating that "any change to one MUST be applied to the
  other". Pass-6 audit verified the unsafe `Box<Container>` +
  `ManuallyDrop<Space<'static>>` pattern is sound and `Pin` is
  not needed; that conclusion is now annotated in both copies.

Verify: 356 tests pass, fmt --check ✓, clippy `-D warnings` ✓,
RUSTDOCFLAGS=-D warnings cargo doc ✓, `cargo bench --bench
timing_oracle --no-run` compiles cleanly.

### Fixed (refactor audit pass 7 — follow-up, 2026-05-04)

Closes the remaining 9 actionable items from pass-7's open backlog
(L3, L5, D1, D4, S2, C3, C4, D2, D3 + the FFI-exposure half of S1).

- **L3** — `Space::read_log` aligned with `iter_log_*` for
  structural inconsistency. If KV says "log_id X is in batch B"
  but batch B decodes without X, both APIs now return
  `Err(Malformed("log_id not found in pointed batch"))` instead of
  `read_log` returning `Ok(None)`. The `Ok(None)` path is
  preserved only for "KV doesn't have the key" — a true "not
  appended" condition.

- **L5** — `Space::vacuum_orphans` and `Space::vacuum_data_batches`
  return `Err(Error::ReadOnly)` when explicitly called on a
  `LOCK_SH` handle. The previous silent `Ok(0)` masked failed
  privacy expectations. The auto-call from `Container::open_space*`
  is suppressed at the container layer via an `is_readonly()`
  check, so read-only opens still succeed without trying to scrub.

- **D4** — `scan_and_recover` (sequential), `scan_and_recover_parallel`,
  and `scan_and_recover_mmap` gained `debug_assert!`s on same-seq
  Superblock-replica bit-equality (per-thread Acc loop, cross-
  thread merge, and mmap path). Same-seq replicas are produced as
  identical bytes by `commit_tx` (one `new_sb` written N times); a
  writer-bug regression that produced same-seq-different-payload
  SBs would silently mask first-wins. Release builds keep
  first-wins semantics with no cost.

- **S2** — `ContainerFile` fields (`header`, `padding_policy`,
  `superblock_replicas`, `lock_mode`) tightened from `pub` to
  `pub(crate)`. `header` is part of the crypto identity (salt,
  container_id, Argon2 params) and must never be mutated
  post-create — `pub(crate)` removes the type-level invitation. No
  external test or user touched these fields directly; only
  `tests/header_params.rs` uses `ContainerFile` and only via
  factory methods.

- **D1, C3, C4 — commit_tx + vacuum_data_batches doc clarified.**
  - `commit_tx` doc: orphan IndexNode chunks survive **only within
    one open session** (in-flight-commit fallback); next
    `Container::open_space` runs auto-`vacuum_orphans`. Cross-launch
    rollback works through the multi-Superblock-replicas path
    (`commit_history`), NOT through orphan IndexNode preservation.
  - `commit_tx` doc gained "Post-failure state" paragraph:
    `owned_slots` may include orphans, `superblock` unchanged,
    auto-`vacuum_orphans` reclaims IndexNode but not DataBatch.
  - `vacuum_data_batches` doc: recommended call after any
    `commit()` that returned an error (D1 forward-secrecy gap).

- **D2** — `make_aad` doc explains why format version is bound via
  the key chain (`Argon2Params.version → master → aead_root → per-slot
  key`), not in the AAD itself. Locks down the convention so a
  future refactor weakening the version-to-key binding is
  highlighted as a security regression.

- **D3** — `derive_chunk_key` doc explicitly states the
  domain-separation convention with `derive_subkey`: any future
  `derive_subkey(aead_root, ...)` MUST use a context label whose
  length differs from 40 bytes, OR encode an explicit kind-tag
  byte at position 0, to avoid input-prefix collision with the
  40-byte `container_id || slot_le` chunk-key input.

- **S1 (FFI exposure half)** — `Space::set_padding_policy` /
  `Space::padding_policy` accessor methods added on the sync core.
  FFI exposes a flat `PaddingPreset` enum
  (`None`, `Bucket256Kib`, `Bucket1Mib`, `Bucket16Mib`) and
  `SpaceHandle::set_padding_policy` /
  `AsyncSpaceHandle::set_padding_policy` methods. Host-apps now
  re-apply policy on every open (still not persisted in the header
  — that's a separate format-design pass).

New `HvError` variants (FFI surface): `WrongNamespaceKind(String)`,
`TooManyNamespaces { limit: u64 }` — mapping the corresponding
sync-core variants instead of falling through to
`Internal("unknown error variant")`.

Tests updated:
- `tests/readonly::open_space_on_readonly_skips_vacuum_and_explicit_call_errors`
  (renamed) asserts `Err(ReadOnly)` from explicit `vacuum_orphans` on RO.
- `tests/vacuum_data_batches::readonly_handle_errors_on_explicit_vacuum`
  (renamed) asserts the same for `vacuum_data_batches`.

Verify: 356 tests pass, fmt --check ✓, clippy `-D warnings` ✓,
`RUSTDOCFLAGS=-D warnings cargo doc` ✓.

### Fixed (refactor audit pass 7 — invariants & logic, 2026-05-03)

Two parallel agents audited function invariants vs implementation
and state-machine clarity. **One HIGH-severity finding** (data-loss
in repack), 2 MEDIUM, 1 LOW, 1 INFO closed in this commit. 4
remaining items (doc-only / design-required) tracked in TASKS.md.

- **L1 HIGH — `Container::repack` / `compact_*` no longer silently
  corrupts custom log namespaces.** Previously, any namespace not
  enumerated in `RepackOptions::log_namespaces` was treated as KV;
  for actual log namespaces (where values are 8-byte slot pointers
  to DataBatch chunks), this copied (log_id, slot_pointer_bytes) as
  raw KV into `dest`, where the slot pointers were meaningless.
  Atomic-rename in `compact_known` then destroyed the source —
  silent data loss.

  Fix: introduced `Error::WrongNamespaceKind(&'static str)` distinct
  from `Error::Malformed`. `parse_batch_slot_value`,
  `decode_log_entries`, and `read_log` now raise
  `WrongNamespaceKind` when the namespace's KV shape doesn't match
  the `(8-byte log_id_key, 8-byte → DataBatch)` log invariant.
  `repack_inner_mapped` tries `iter_log` first; on
  `WrongNamespaceKind` it falls back to `list` for KV.
  `RepackOptions::log_namespaces` is honoured as a hint (skips the
  probe) but no longer load-bearing — host-apps with custom log
  namespaces that forget to enumerate them are now safe.

  Regression test:
  `tests/repack::repack_auto_detects_unlisted_log_namespace`.

- **C1 MEDIUM — empty Tx `commit()` is now a true no-op.**
  `Tx::is_empty` doc claimed "commit on empty Tx is a no-op (no
  commit chunk emitted)" but `commit_tx` always advanced seq, wrote
  a Commit chunk + Superblock replicas, and ran 3 fsyncs (asserted
  by the previous regression test `empty_tx_increments_seq_with_no_changes`).

  Fix: `commit_tx` early-returns `Ok(self.state.superblock.seq)`
  when both pending maps are empty. Aligns code with doc; saves 3
  fsyncs per call; removes the multi-snapshot "writer was active"
  leak from no-op commits. The old test was renamed to
  `empty_tx_commit_is_a_no_op` and now asserts the new behaviour.

- **L2 MEDIUM — `Error::TooManyNamespaces { limit }` variant** added.
  Previously, exceeding `MAX_NAMESPACES_PER_TX` surfaced as
  `Error::Internal(...)` only at commit time — and `Error::Internal`
  is documented as "bug in the crate". User-driven failures now
  surface in `Tx::put` / `Tx::delete` / `Tx::append_log` with the
  dedicated variant via `check_namespace_capacity`. The encode-time
  `Internal` check stays as defense-in-depth.

- **L4 LOW — `Container::create_space` early-returns
  `Error::ReadOnly`** before kicking off Argon2id derivation +
  collision-scan. Saves ~100ms+ on weak ARM and closes a minor
  timing side-channel (caller could observe collision-check
  completion before getting `ReadOnly`).

- **C2 LOW — encoder/decoder symmetry** in B+tree nodes.
  `LeafNode::encode` and `InternalNode::encode` previously accepted
  unsorted input; decoders strict-rejected. Added `debug_assert!`
  ordering checks in encoders — catches writer-bug regressions in
  tests; release builds pay nothing.

- **C5 INFO — FFI `namespace == 0` rejected symmetrically** in
  read paths. `SpaceHandle::count`/`get`/`read_log`/`iter_log_range`
  and the `AsyncSpaceHandle` async mirrors now return
  `HvError::Malformed("namespace 0 is reserved")` instead of
  silently `Ok(0)` / `Ok(None)`. Aligns with write-path rejection
  (`Tx::put`/`delete`/`append_log` already rejected
  `Namespace::RESERVED`).

New `Error` variants (additive, no breakage for existing match arms
that don't catch `_` exhaustively):
- `Error::WrongNamespaceKind(&'static str)`
- `Error::TooManyNamespaces { limit: usize }`

Verify: 356 tests passed (355 existing + new
`repack_auto_detects_unlisted_log_namespace` regression), fmt
--check ✓, clippy `-D warnings` ✓, RUSTDOCFLAGS=-D warnings cargo
doc ✓.

### Fixed (CI green-up, 2026-05-03)

Seven CI failures uncovered after the Flutter scaffolding commit
landed; all fixed in this commit.

- **Windows: `tests/fault_injection.rs`** previously used
  `std::os::unix::fs::FileExt` (`pread` / `pwrite`) without a
  `cfg(unix)` gate, breaking the windows-latest runner. Rewrote
  `flip_bit` to `seek` + `read_exact` + `write_all` — cross-platform,
  same semantics, no Unix-only path.
- **MSRV bump 1.85 → 1.89.** The codebase already used Rust 1.89
  features: `File::try_lock` / `File::try_lock_shared` (stable in
  1.89; `container/file.rs`), `is_multiple_of` (stable in 1.87;
  `open/mod.rs` cancel-poll guard), and `if let` chains (stable in
  1.88; `open/mod.rs`, `space/mod.rs`). The MSRV CI job pinned
  `dtolnay/rust-toolchain@1.85.0` and was correctly failing. Bumped
  the toolchain pin and added `rust-version = "1.89"` to all three
  crates' `[package]` sections.
- **`crates/*/Cargo.toml` path dependencies** were declared as
  `hidden-volume = { path = "../hidden-volume" }` — implicitly a
  wildcard. cargo-deny's `wildcards = "deny"` (correctly) failed
  on this. Added `version = "0.1.0"` next to each `path = "..."`
  in `hidden-volume-async`, `hidden-volume-ffi`, and the fuzz crate.
- **cargo-deny advisory ignores for uniffi 0.28 transitives.**
  `bincode 1.3.3` (RUSTSEC-2025-0141, unmaintained — bincode team
  archived 1.x) and `paste 1.0.15` (RUSTSEC-2024-0436, unmaintained
  — author archived) are dependencies of uniffi 0.28's proc-macro
  / bindgen crates. We don't use either at runtime; both are
  compile-time-only. No safe upgrade available — uniffi 0.29+
  drops them. Added both advisory IDs to `[advisories] ignore` in
  `deny.toml` with rationale.
- **`crates/hidden-volume/fuzz/Cargo.toml`** lacked an empty
  `[workspace]` table, which caused `cargo +nightly fuzz` to
  detect the parent workspace and fail with "current package
  believes it's in a workspace when it's not". Added the empty
  marker as the cargo error message itself recommends. The parent
  workspace already has `exclude = ["crates/hidden-volume/fuzz"]`;
  this addition is the second half of the standard fuzz-out-of-
  workspace pattern.
- **`tests/ffi_smoke.rs`** first test (`cdylib_loads_and_uniffi
  _contract_version_symbol_resolves`) hard-asserted on cdylib
  presence. `cargo test --workspace --all-features` does not
  always rebuild the cdylib (depends on cache state), causing
  spurious CI failures. Switched to skip-on-missing-cdylib (matches
  the other two tests in the file). Set `HV_REQUIRE_CDYLIB=1` to
  promote skip back to a hard panic for explicit
  `cargo build -p hidden-volume-ffi && cargo test` flows.
- **`.github/workflows/ci.yml` Python e2e step** had a `LIB=$(ls A
  B 2>/dev/null | head)` line that fails under bash strict mode
  when one path doesn't exist (`ls` exits 2 even with stderr
  redirected). Replaced with explicit `if [[ -f ... ]]` ladder —
  produces a clean error if neither cdylib variant is present and
  no spurious shell errors otherwise.
- **`deny.toml` license allowance** pruned `ISC`,
  `Unicode-DFS-2016`, `Zlib` — no current dependency uses them and
  cargo-deny's `unused-allowed-license` warning was loud about it.
  Re-add when an actual dep needs them.

Verify: 355 tests pass, fmt --check ✓, clippy `-D warnings` ✓,
RUSTDOCFLAGS=-D warnings cargo doc ✓, `cargo deny check` →
`advisories ok, bans ok, licenses ok, sources ok`.

### Added (Flutter integration scaffolding, 2026-05-03)

End-to-end build infrastructure for consuming `hidden-volume` from a
Flutter app on Android and iOS. The Rust core + FFI surface were
already in place; this commit adds everything else needed for
`flutter run` to work after a one-time toolchain install.

- **Rust Android targets** added to the toolchain expectation:
  `aarch64-linux-android`, `armv7-linux-androideabi`,
  `x86_64-linux-android`, `i686-linux-android` (4 ABIs).
- **`scripts/build-android.sh`** — `cargo-ndk` wrapper. Pre-flights
  `$ANDROID_NDK_HOME`, `cargo-ndk` install, Rust target install;
  builds `libhidden_volume_ffi.so` for all 4 ABIs and copies into
  `flutter_plugin/hidden_volume/android/src/main/jniLibs/<abi>/`.
- **`scripts/build-ios.sh`** — macOS-only. `cargo build` for
  `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`;
  `lipo`s the simulator slices into a fat staticlib; emits
  `HiddenVolumeFFI.xcframework` via `xcodebuild -create-xcframework`.
- **Flutter plugin scaffolding** at `flutter_plugin/hidden_volume/`:
  - `pubspec.yaml` — Flutter plugin manifest (Android +
    iOS platform support; depends on `ffi` 2.x for `dart:ffi`).
  - `android/build.gradle` + `settings.gradle` +
    `AndroidManifest.xml` + `HiddenVolumePlugin.kt` — AGP 8.2
    library wiring the generated uniffi Kotlin binding.
  - `ios/hidden_volume.podspec` + `Classes/HiddenVolumePlugin.swift` —
    CocoaPods spec referencing the vendored `xcframework`.
  - `lib/hidden_volume.dart` — typed Dart facade
    (`HvContainer`, `HvSpace`, `HvTx`, `Argon2Params`,
    `HvException`); methods are `UnimplementedError`-throwing
    skeletons until uniffi-dart 0.4 stabilizes or the manual
    `dart:ffi` bindings are filled in.
  - `lib/src/bindings.dart` — manual `dart:ffi` skeleton with
    cross-platform `DynamicLibrary` resolution and one wired
    probe (`uniffiContractVersion`); typed wrappers TODO.
- **CI workflow `.github/workflows/flutter-build.yml`**:
  - Android matrix job (Ubuntu, NDK r26d via
    `nttld/setup-ndk@v1`) builds 4 `.so` artifacts on each push.
  - Kotlin binding regeneration job uploads
    `bindings/kotlin/uniffi/`.
  - iOS job (macOS-14, Apple-silicon) regenerates Swift
    bindings, runs `build-ios.sh`, uploads the xcframework
    + Swift binding as artifacts.
- **`crates/hidden-volume-ffi/tests/ffi_smoke.rs`** — three new
  tests (3/3 pass) that dlopen the host-target cdylib via
  `libloading` and probe the uniffi 0.28 C ABI: contract-version
  symbol resolves, contract-version value is in the expected
  range, and a representative subset of
  `uniffi_hidden_volume_ffi_checksum_*` symbols (sync `SpaceHandle`
  ctors + methods, async `AsyncSpaceHandle` ctors + methods, free
  function `header_info`) is present. Catches FFI-surface drift
  before it reaches a slow Android-emulator run. New
  `dev-dependencies`: `libloading = "0.8"`.
- **Flutter guide updated** (`docs/en/guide/flutter.md` +
  `docs/ru/guide/flutter.md`): new "Quick start" section with
  the 4-step pipeline (install → build natives → regenerate
  bindings → `flutter pub get`), shipped-vs-pending status
  table reflects the scaffolding.

Verify: 355 tests pass (352 existing + 3 new FFI smoke), fmt
--check ✓, clippy `-D warnings` ✓, RUSTDOCFLAGS=-D warnings cargo
doc ✓. Build scripts produce a clean error message when
prerequisites are missing (verified on a Linux host without NDK
and on a non-macOS host).

### Changed (refactor audit pass 6, 2026-05-03)

Security-focused audit re-run after passes 1-5 + bilingual docs. Three
parallel audits (security/threats, dead code, bugs/perf/duplicates).
**HIGH = 0, MEDIUM = 0.** Only stale dead code, doc drift, and a few
LOW perf wins. Plus formal closure of D3 (`Pin<Box>` proposal — proven
not needed).

- **Z1-Z6 — dead B+ tree mutators removed.** `LeafNode::put`,
  `LeafNode::delete`, `LeafNode::split`, `InternalNode::update_child`,
  `InternalNode::insert_child_after`, `IndexNode::namespace()` —
  artefacts of the original B+ tree design with in-place updates.
  Zero callers in src/tests/benches/examples/FFI/async; `commit_tx`
  uses flatten-and-rebuild via `apply_op_to_sorted` +
  `pack_into_leaves` instead. ~64 LOC removed from
  `src/space/index.rs`.
- **Z7 — `ContainerFile::write_slot` removed.** Rewrite-in-place
  primitive with zero callers. The append-only architecture writes
  to fresh slots via `append_slot` and overwrites with random via
  `scrub_slot`; in-place updates were never wired up. Module-doc
  Inv-W1 simplified to match. `src/container/file.rs`.
- **Z8-Z13 — stale version-references in doc comments trimmed.**
  Phrases like "v0.1 limits…v0.2 lifts this", "Phase 3 (v0.2.x)",
  "v0.1 surface only", "v0.2 first-cut sizes" removed from
  `superblock.rs`, `error.rs`, `space/mod.rs`, `space/index.rs`.
  ~25 LOC of doc churn cleaned up; doc now reflects shipped state.
- **Perf — `vacuum_orphans` / `vacuum_data_batches` use `HashSet<u64>`**
  for `reachable` and `referenced` (was `BTreeSet`). The membership
  check is the only operation; HashSet is O(1) vs BTreeSet's O(log N).
  Symmetric with the F1 fix in pass 4 that already moved `to_drop`
  to HashSet.
- **Perf — `or_insert(pt.payload)` replaces `or_insert_with(|| pt.payload.clone())`**
  in three discovery-scan sites (`open/mod.rs:116, 264, 401`). On
  `Vacant` the Vec is moved instead of cloned; on `Occupied` it is
  dropped (which would have happened anyway). Saves a per-Superblock
  allocation in the scan hot path.
- **Perf — `checked_add(1)` guards** for the `u64` log-cursor in the
  async stream (`hidden-volume-async/src/lib.rs`). Pure
  defense-in-depth: practical log_id values are far below
  `u64::MAX`, but `cursor + 1` would panic in debug / wrap in
  release at saturation.
- **Perf — `hex()` uses `write!` instead of `format!` per byte**
  (`hidden-volume-ffi/src/lib.rs:hex`). Cold path; cosmetic. Avoids
  the per-byte intermediate `String` allocation.
- **D3 — closed as not needed.** The self-referential `SpaceInner`
  pattern (`Box<Container>` + `ManuallyDrop<Space<'static>>`) is
  sound without `Pin`. `Box`'s heap pointee has a stable address;
  `Pin` is only needed when the borrowed-from data is in the *same*
  struct as the borrow. Drop order is enforced by `ManuallyDrop` +
  the explicit `Drop` impl; `Send`/`Sync` is correctly serialized
  via `Mutex`. `self_cell` / `ouroboros` migration would be a no-op
  of the same semantics.

Verify: 352 tests passed, fmt --check ✓, clippy -D warnings ✓,
`RUSTDOCFLAGS=-D warnings` cargo doc ✓.

### Changed (housekeeping, 2026-05-03)

- **C4 — generated FFI bindings unstaged from git.**
  `bindings/{python,kotlin,swift,ruby}/*` (the ~11k lines of
  uniffi-generated source) added to root `.gitignore` and
  `git rm --cached`'d. Tracked items kept: `bindings/README.md`
  (regeneration recipe), `bindings/python/test_smoke.py`
  (hand-written), `bindings/python/.gitignore`. Avoids history
  bloat on every uniffi version bump; integrators regenerate
  locally per the README.
- **TASKS.md hygiene** — 14 line items that had been closed by
  passes 1–3 + C4 marked `[x]` with cross-references to the
  closing pass / commit. Status overview updated: code-side open
  count is 0; remaining items are all deferred-with-rationale,
  out-of-band, or organizational.

### Changed (refactor audit pass 5, 2026-05-03)

Hardening mini-pass after passes 1-4 commit. **Zero HIGH-severity
bugs.** Two defense-in-depth bounds in B+tree decode, two
production `expect(...)` panic sites converted to `Error::Internal`,
one cargo-cult dead feature removed, and the long-standing D7+D8
fragile `windows(2)` indexing fixed.

- **G1 — empty `std` feature dropped.**
  `crates/hidden-volume/Cargo.toml` previously had `default =
  ["std"]; std = []` with **zero `cfg(feature = "std")` usage** in
  the workspace. Cargo-cult artifact of a pre-`no_std` intention
  that never materialized. Both lines deleted; the implicit
  `--no-default-features` promise nobody honored is gone.
- **G2 — `LeafNode::decode` defense-in-depth bound.**
  `src/space/index.rs`: a malformed (post-AEAD) leaf payload
  declaring `num_entries = 65535` would pre-allocate ~3 MiB of
  `Vec<(Vec<u8>, Vec<u8>)>` before per-entry bounds caught the
  truncation. New check: `num * MIN_LEAF_ENTRY_BYTES > bytes.len()
  - HEADER_LEN` returns `Error::Malformed("leaf count exceeds
  payload bound")` before allocating. `MIN_LEAF_ENTRY_BYTES = 7`
  (klen u16 + min-key 1 + vlen u32). Post-AEAD path so attacker
  without key cannot reach; protects against on-disk corruption /
  buggy writer.
- **G3 — `InternalNode::decode` defense-in-depth bound.** Same
  pattern as G2 with `MIN_INTERNAL_CHILD_BYTES = 43` (klen u16 +
  min-key 1 + child_slot u64 + child_hash 32B).
- **G4 — `cmd_put` panic site converted.** The
  `.expect("clap should require...")` in
  `src/bin/hv.rs::cmd_put` (paired with `--value-stdin`'s
  `required_unless_present`) is now `.ok_or(Error::Internal(...))?`.
  A clap schema regression now surfaces as a clean
  `Error::Internal` exit code instead of a process panic.
- **G5 — `scan_and_recover_parallel` rayon pool init
  fallibility.** `rayon::ThreadPoolBuilder::build().expect(...)`
  inside `OnceLock::get_or_init` is replaced with a `OnceLock::get`
  + fallible build + `OnceLock::set` chain. On build failure
  (thread-limit-hit / OOM-during-init) the function returns
  `Err(Error::Internal("rayon pool build failed"))`; the caller
  already returns `Result`. Race between two threads building
  concurrently is benign — `set`'s loser drops their pool.
- **G6 — `windows(2)` + index ops replaced with slice patterns.**
  Long-standing **D7+D8** closed. Both leaf/internal sort-check
  loops in `src/space/index.rs` use `let [a, b] = w else
  { unreachable!("windows(2) yields 2-slices") }` instead of
  `w[0]/w[1]` indexing — same safety, no footgun for future refactors.

### Changed (refactor audit pass 4, 2026-05-02)

Eight LOW/TRIVIAL findings from a focused re-audit + two test-suite
hygiene wins (C5/C6) and one re-export trim (B13). Zero behaviour
changes for library callers; one CLI behaviour change (F3).

- **F1 — `HashSet<u64>` in vacuum scrub paths.**
  `Space::vacuum_data_batches` and `Space::scrub_data_batches`
  previously built `to_drop: Vec<u64>` and used `to_drop.contains`
  inside a `.retain()` — quadratic in the dropped-slot count. Both
  now use `HashSet<u64>`, making the retain loop O(N). For the
  expected workload (≤ thousands of slots) this is invisible; for
  pathological 100k-batch repacks it's a ~50× win.
  See `crates/hidden-volume/src/space/mod.rs:1145,1253`.
- **F2 — `checked_mul` in mmap expected-length computation.**
  `streaming_open` previously did `(1 + total) as usize *
  CHUNK_SIZE` with implicit u64→usize→multiply chain. On a 32-bit
  target (or with corrupted `total` near `usize::MAX`) this could
  silently wrap. Replaced with `checked_add(1).ok_or(...)` then
  `checked_mul(CHUNK_SIZE).ok_or(...)`. Defensive — no exploitable
  bug on 64-bit hosts. See `src/open/mod.rs:348`.
- **F3 — `HV_PASSWORD` env-var fallback removed from `hv` CLI.**
  The CLI previously read `HV_PASSWORD` if set, ahead of stdin
  prompting. Env vars leak via `/proc/<pid>/environ` to anyone with
  ptrace_scope=0 access and (worse) into shell history when set
  inline (`HV_PASSWORD=… hv …`). Stdin-only is the correct UX. CLI
  tests rewired to spawn with `Stdio::piped()` and write
  `password\n` to the child. Breaking for anyone scripting the CLI
  via env — the recommended replacement is `printf 'pw\n' | hv …`
  or `--value-stdin` (F4) for puts.
- **F4 — `hv put --value-stdin` flag.** Previously the put
  subcommand required the value on the argv (`hv put … KEY VALUE`),
  which leaks the value via `ps`/`/proc/<pid>/cmdline`. With
  `--value-stdin`, the second line of stdin (after the password) is
  consumed as the value. `value` is now `Option<String>` with
  `conflicts_with = "value_stdin"` and `required_unless_present`
  semantics — clap rejects bad combinations.
- **F5 — `RepackOptions::default()` in CLI.** The `repack`/`compact`
  subcommands constructed `RepackOptions { argon2:
  Argon2Params::DEFAULT, ..Default::default() }`. Since
  `Argon2Params::DEFAULT` *is* `Argon2Params::default()`, the
  explicit field was redundant. One line. See `src/bin/hv.rs`.
- **F6 — `lib.rs` `# Status` doc drift.** The crate-level rustdoc
  still claimed "v0.1 (current) / v0.2 (in progress)" — six
  releases stale. Updated to reflect the actual posture: pre-1.0
  freeze, v0.1–v0.7 closed in `CHANGELOG.md`, v0.8 FFI scaffold
  landed.
- **F7 — `parse_params` explicit `unreachable!`.** clap's
  `value_parser!` already constrains `--params` to one of `min`,
  `default`, `interactive`, `bench` — the previous default arm
  panicked with a generic message. Now an explicit `"default"` arm
  + `unreachable!("clap value_parser should reject {other:?}")`.
  Documents the invariant; gives a better panic message if it ever
  *is* reached. See `src/bin/hv.rs::parse_params`.
- **F8 — inline `cursor_advance_above` in async stream.** The
  helper was a 3-line function with one caller; inlined to
  `lower = Some(last.0);` with a one-line comment explaining the
  invariant. See `crates/hidden-volume-async/src/lib.rs`.
- **B13 — chunk/mod.rs re-exports trimmed.** `MAGIC` and
  `PLAINTEXT_HEADER_LEN` were re-exported from `chunk::format` but
  had **zero external usages** (in-crate or out). Dropped from the
  re-export — they remain `pub` in `chunk::format` for the rare
  caller who needs to inspect raw chunk framing. See
  `src/chunk/mod.rs`.
- **C5 + C6 — test-suite helper extraction.** `fast_params()` (alias
  for `Argon2Params::MIN` to keep tests fast) and `scratch_path()`
  (tempfile-then-drop-then-keep-path dance) were duplicated across
  ~30 integration tests. Both now live in
  `crates/hidden-volume/tests/common/mod.rs`; consumers do
  `mod common; use common::{fast_params, scratch_path};`. Reduces
  test-file boilerplate by ~10 LOC per file. The compiler's
  `unused_imports` lint caught 26 stale `Argon2Params` imports
  left behind by the helper move; all stripped.

### Changed (refactor audit pass 3, 2026-05-03)

Final mini-pass before v1.0 freeze. Diminishing returns territory
after passes 1+2: **zero real bugs**, ~20 lines cleanup +
housekeeping.

- **B10 — `rand_core` direct dep removed** from
  `crates/hidden-volume/Cargo.toml`. **0 direct import sites**;
  pulled in transitively via `chacha20poly1305`'s `rand_core`
  feature.
- **B11 — 6 wire-format constants → `pub(crate)`.** `HEADER_LEN`,
  `HEADER_SALT_OFFSET`, `HEADER_SALT_LEN`,
  `HEADER_CONTAINER_ID_OFFSET`, `HEADER_CONTAINER_ID_LEN`,
  `FIRST_SLOT_OFFSET` had `pub` visibility but **0 external
  usages**. Shrinks public API surface before v1.0 freeze.
  `HEADER_PARAMS_OFFSET` and `HEADER_PARAMS_LEN` stay `pub` (used
  by `tests/header_params.rs` for header-tamper tests).
- **B12 — `AAD_LEN` → `pub(crate)`** + dropped from
  `crypto::mod` re-export. Used internally by `seal`/`open` array
  signatures but **0 external callers** (tests obtain AAD via
  `make_aad()` which is still `pub`).
- **E8 — `.gitignore` expanded** with stock Rust entries
  (`.idea/`, `.vscode/`, `*.swp` / `*.swo`, `*.bak`, `.DS_Store`,
  `Thumbs.db`, `.env*`, `/dist/`, cargo-fuzz artifacts).
  Previously only `/target` + `/.claude/`.

**Deferred (architectural, post-1.0 candidates):**
- **E5** — extract `OwnedSpace` helper to dedupe `SpaceInner`
  self-referential pattern across async + FFI crates (~30 lines
  duplicated incl. `unsafe { transmute }` safety comments).
  Centralizes unsafe to one safety-review point but requires API
  design pass.
- **E6** — generic `run_blocking` helper. Different error types
  (`Result` vs `HvResult`) make extraction non-trivial; ~10 lines
  each is small enough to leave.
- **E7** — split `space/mod.rs` (1485 lines) into submodules.
  `impl Space<'f>` block is contiguous and well-organized; auditors
  prefer top-to-bottom read.

### Changed (refactor audit pass 2, 2026-05-02)

Second-pass cleanup after pass 1's 11-item run. Pass 2 found ~75 lines
of additional cleanup + 1 footgun (`Namespace::default()` returning
the reserved/rejected namespace). **No real bugs**; pure code-quality
polish + dead-code removal. ~9 items addressed.

- **B5 — `impl Default for Namespace` removed.** Previously returned
  `Namespace::RESERVED`, but every `Tx::put` / `Tx::delete` /
  `Tx::append_log` rejects `RESERVED` as invalid. Calling
  `Namespace::default()` produced an unusable value that always
  failed at the next call site — pure footgun. `LeafNode` and
  `InternalNode`'s `#[derive(Default)]` removed accordingly (no
  external callers; constructors `LeafNode::new(ns)` and
  `InternalNode::new(ns)` remain).
- **A7 — `Error::NotImplemented` variant removed.** Declared in the
  `Error` enum + mirrored in FFI's `HvError` but **never constructed
  by any production code**. Pure placeholder. The `_ => HvError::Internal`
  catch-all in the FFI `From<hidden_volume::Error>` impl already
  handles any future variant safely.
- **A6 — `ffi-uniffi` Cargo feature removed.** Empty `[]` placeholder
  feature in `crates/hidden-volume/Cargo.toml`; never gated any code.
  Real FFI lives in the separate `hidden-volume-ffi` crate. Stale line
  in `docs/SEMVER.md` also removed.
- **B7 — `compact_all` / `compact_all_cancellable` removed.** Both
  had bit-identical bodies to `compact_known` / `_cancellable`
  (same `compact_in_place_impl` call). The supposed semantic
  difference ("caller asserts they have all passwords") was
  documentation-only and not enforced. Now there's one canonical
  `compact_known` with destructive-drop semantics documented in its
  rustdoc + the historical-note in `docs/INTEGRATION.md`. Tests
  using `compact_all*` updated to call `compact_known*`.
- **B6 — `crypto::derive_subkey` → `pub(crate)`.** No external
  callers; only used by `SpaceKeys::from_master`. The fixed-context
  BLAKE3 schedule (`b"hv/v1/space/aead"`) is part of the on-disk
  key-schedule contract — exposing publicly invited misuse with
  arbitrary `context` bytes that would silently fork the schedule.
  Type-regression test moved into `crypto/derive.rs` as a
  `#[cfg(test)] mod tests` block.
- **B8 — `pub mod open;` → `pub(crate) mod open;`.** Every fn inside
  is `pub(crate)` already; module-level `pub` was a no-op that just
  cluttered rustdoc.
- **B9 — Stale references to removed `SpaceKeys.master` / `kdf` updated**
  in `docs/CT_AUDIT.md` and `docs/MEMORY_AUDIT.md`. Both audits now
  cite only the live `aead_root` field and historical-note the
  cleanup.
- **A8 — Bench module-doc fix.** `read_log_random` → `read_log` to
  match the actual fn name + bench label.

**Deferred:**
- **D11** — header offset/length constants → `pub(crate)`. Several
  tests in `tests/header_params.rs` use `HEADER_PARAMS_OFFSET` /
  `HEADER_PARAMS_LEN` directly; tightening would require moving
  those tests into `#[cfg(test)] mod tests` inside source files.
  Not pre-1.0 critical — these constants are wire-format documentation
  and stable.
- **C4** — `bindings/{python,kotlin,swift,ruby}/*` (~11K lines)
  remain committed. Architectural decision: gitignore + CI-regenerate
  is cleaner but loses in-repo browseable reference for integrators.
  Pending user ack.
- **D10** — `*_cancellable` API consolidation (12 methods → 6 with
  `Option<&CancelToken>`). Heavy refactor; defer post-1.0.

### Changed (refactor audit pass 1, 2026-05-02)

Pre-1.0 cleanup of dead code, vestigial features, and panic-site
hardening per a comprehensive refactor audit. **~150 lines removed,
1 dead BLAKE3 derivation eliminated per space-open, 1 production
dependency dropped (`subtle`).** Breaking format change: the v1
on-disk format now strictly rejects non-zero reserved-flags bytes
and unknown chunk-kind discriminators (which were silently accepted
before).

- **Strict-mode flags validation** — `Plaintext::decode` now rejects
  non-zero values in the reserved `flags` byte at offset 5 with
  `Error::Malformed("non-zero reserved flags")`. Prevents a v1 reader
  silently accepting a v2-format chunk under unknown semantics. The
  `flags` field is no longer exposed on the `Plaintext` struct
  (always 0 on encode, validated 0 on decode); the `chunk::format::flags`
  module with its single `NONE = 0` constant is removed. Audit B3+A5.
- **Dead `ChunkKind` variants removed** — `ChunkKind::Data` (0x03) and
  `ChunkKind::Journal` (0x04) were declared in the enum but never
  produced by any writer. `from_u8` now treats those discriminator
  bytes as unknown and rejects with `Malformed`. `space/journal.rs`
  stub deleted (never implemented; superseded by `vacuum_orphans` +
  `vacuum_data_batches`). Audit A1+A2+A3.
- **Dead `SpaceKeys` fields removed** — `SpaceKeys::master` (32 B) and
  `SpaceKeys::kdf` (32 B) were written but never read. Both removed
  along with the `derive_subkey(master, b"hv/v1/space/kdf")`
  derivation step. `SpaceKeys` now contains only `aead_root` (the
  one field actually consumed by `derive_chunk_key`). Saves 64 B/space
  + one BLAKE3-keyed-hash per space-open. `from_master` no longer
  copies the master into the struct — the master key is dropped at
  end-of-derivation. Audit B1+B2.
- **`crypto::ct` module removed** — `eq_32` and `eq_slice` constant-
  time helpers were declared `pub` but used only by their own unit
  tests (audit-confirmed: 0 production callers). Doc explicitly
  framed them as "future-proofing for hypothetical sensitive
  comparisons". `subtle` dep removed from `Cargo.toml`. Audit A4.
- **D2 — Recovery now falls back from malformed-but-AEAD-valid
  Superblock.** Previously, if the highest-seq SB AEAD-passed but
  `Superblock::decode` failed (e.g. due to format-level corruption
  AEAD missed, or a v1 reader hitting a v2-format SB), `open` would
  return `Malformed` without trying lower-seq SBs. Recovery now
  collects all distinct-seq AEAD-passing SBs into a `BTreeMap<seq,
  payload>` and decodes in descending-seq order, taking the first
  success. Applied to all three scan paths: sequential
  (`scan_and_recover`), parallel (`scan_and_recover_parallel`), and
  mmap (`scan_and_recover_mmap`).
- **D4 — FFI mutex poisoning maps to `HvError::Internal`** rather
  than panicking. ~30 sites in `hidden-volume-ffi/src/lib.rs`
  changed from `.lock().unwrap()` to `.lock().map_err(|_|
  poisoned_mutex())?`. **API change:** `SpaceHandle::commit_seq()`
  and `SpaceHandle::commit_history()` now return `HvResult<u64>` /
  `HvResult<Vec<u64>>` (were `u64` / `Vec<u64>`). Same for
  `AsyncSpaceHandle`. Mirrors `hidden-volume-async`'s pattern; a
  panic across the FFI boundary would abort the foreign-side
  process. Audit D4.
- **D7+D8 — `unwrap()` panic sites eliminated.** `page.last().unwrap()`
  in async streaming methods replaced with `let Some(last) = page.last()
  else { break }`. `try_into().unwrap()` in `space::collect_leaves_*`
  replaced with `let Ok(bytes): Result<[u8; 8], _> = ... else { continue }`.
  Safe-by-construction before, but inviting bug if loop bodies were
  refactored. Audit D7+D8.

### Added
- **Fault-injection test suite** —
  [`crates/hidden-volume/tests/fault_injection.rs`](crates/hidden-volume/tests/fault_injection.rs).
  10 scenarios beyond the truncate-at-chunk-boundary matrix in
  `crash_recovery.rs`: bit-rot in data chunks (AEAD must catch),
  bit-flip in 1-of-3 SB replicas (recover via others), bit-flip in
  ALL latest SB replicas (fall back to prior seq), unaligned
  truncation, partial-trailing-chunk, garbage-tail (1 chunk / partial
  / 10 chunks), corruption + unaligned truncation combo, wrong-password
  under corruption (deniability invariant: `AuthFailed` regardless of
  what's broken). Pure byte-munging — no production-code refactor to
  abstract `File` behind a trait. Approach documented in the test
  module's rustdoc.
- **`scripts/release.sh`** — local release-artifact build script.
  Produces `dist/` with `hv` CLI binary, FFI cdylib, regenerated
  bindings, and a `SHA256SUMS` file. Mirrors the `release-build` GHA
  job; for ad-hoc local builds. Cross-compile via `TARGET=...`
  envvar.
- **`.github/workflows/ci.yml` extensions** — three new jobs:
  - `ffi-bindings-python` (Linux + macOS): builds cdylib, regenerates
    Python bindings, runs `bindings/python/test_smoke.py` end-to-end
    through ctypes. Canary for FFI binding correctness.
  - `fuzz-smoke` (nightly): 5 min/target via `cargo fuzz run --
    -max_total_time=300` for `plaintext_decode`, `decoder_family`,
    `container_open`. `continue-on-error` so PRs don't gate on a
    fuzz finding; crashes uploaded as `fuzz-crashes` artifact for
    triage.
  - `release-build` matrix (5 targets: x86_64-linux, aarch64-linux,
    x86_64-apple, aarch64-apple, x86_64-windows). Builds release
    artifacts on push to master/main, computes SHA-256 checksums,
    uploads as `release-<target>` artifacts. Validates that release
    builds compile cleanly across every target we publish for.
- **[`docs/FLUTTER_INTEGRATION.md`](docs/FLUTTER_INTEGRATION.md)** —
  Flutter integration guide. Path A (direct via `uniffi-dart` once
  stable) + Path B (per-platform plugin wrapping Kotlin/Swift
  bindings, works today). Recommended initial method subset for an
  MVP messenger; threading model (always async on main isolate);
  storage budget table; Argon2 preset selection by device class.

### Fixed
- **`Container::open` is now lenient about trailing partial chunks**.
  Previously rejected files whose size wasn't a multiple of
  `CHUNK_SIZE` with `Error::Malformed("file size not chunk-aligned")`,
  which made crash recovery impossible when the FS committed a
  partial block before fsync. Now silently rounds down — the partial
  bytes can't represent a complete AEAD-protected chunk anyway, so
  they aren't addressable as a slot. Discovered by the new fault-
  injection suite (`unaligned_truncation_skips_partial_trailing_chunk`,
  `unaligned_truncation_with_only_partial_last_chunk_works`,
  `corruption_then_unaligned_truncation_still_recovers`,
  `garbage_tail_partial_chunk_handled`). The pre-existing
  `non_chunk_aligned_truncation_is_malformed` test was renamed to
  `non_chunk_aligned_truncation_recovers_via_lenient_open` and now
  asserts the recovery behavior end-to-end.

### Added
- **Foreign-language bindings generated and committed** under
  [`bindings/`](bindings/). uniffi auto-produces idiomatic source for
  Python (`hidden_volume_ffi.py`), Kotlin (`hidden_volume_ffi.kt`),
  Swift (`hidden_volume_ffi.swift` + `*.h` + `*.modulemap`), and
  Ruby (`hidden_volume_ffi.rb`) from a single Rust source of truth
  (`#[uniffi::*]` proc-macros in `crates/hidden-volume-ffi/src/lib.rs`).
  Generated via a new in-tree
  [`uniffi-bindgen` bin](crates/hidden-volume-ffi/src/bin/uniffi-bindgen.rs)
  (uniffi 0.25+ recommended pattern — pins bindgen to the same crate
  version we use for exports, avoiding version-skew bugs from a
  globally-installed CLI). Per-language usage examples in
  [`bindings/README.md`](bindings/README.md).
- **Python end-to-end smoke test** —
  [`bindings/python/test_smoke.py`](bindings/python/test_smoke.py).
  Loads `libhidden_volume_ffi.so` via `ctypes` (through the
  auto-generated Python module) and exercises the full FFI surface:
  sync + async constructors, get/put/delete via batched `commit`,
  log read + range query, integrity verify, stats, header inspection,
  AuthFailed deniability check, durability across reopen. **5/5
  pass on Python 3.14.** Canary for binding correctness — same uniffi
  machinery generates Kotlin / Swift / Ruby, so a Python pass is
  strong evidence for the others.
- **`AsyncSpaceHandle` in `hidden-volume-ffi`** — async sibling of
  `SpaceHandle` for Kotlin coroutines / Swift `async/await`. Every
  sync method has an `async` equivalent (constructors `create`/`open`,
  reads `get` / `count` / `list_namespaces` / `read_log` /
  `iter_log_range` / `commit_seq` / `commit_history` / `stats` /
  `verify_integrity`, write `commit`). Internally each `async fn`
  offloads the sync-core call to `tokio::task::spawn_blocking`; the
  internal mutex (shared with `SpaceHandle` via the same `SpaceInner`
  type) is held only during the offloaded work, so concurrent async
  tasks can interleave between calls. uniffi `tokio` runtime
  feature starts a Tokio multi-thread runtime inside the Rust dylib
  for Kotlin/Swift integrators automatically. Pure-Rust callers
  wrap in `#[tokio::main]`. ADR §"Decision 6" rewritten — sync and
  async are now sibling surfaces rather than sync-only. Coverage:
  5 new `#[tokio::test]` tests in
  `crates/hidden-volume-ffi/src/lib.rs` (async create/open round-trip
  with reopen + AuthFailed, async iter_log_range, async
  verify+stats, async concurrent calls serialize correctly via
  20 spawned tasks against one handle, async empty-commit no-op).
- **`AsyncSpace` in `hidden-volume-async`.** Companion to `AsyncContainer`
  that keeps an opened `Space` alive across async calls (self-referential
  `Box<Container>` + `ManuallyDrop<Space<'static>>` behind `tokio`-friendly
  `std::sync::Mutex`). Solves the lifetime mismatch where a `Stream`
  yielding paginated log entries cannot re-open the Space on every
  `poll_next` (would pay the open-time scan repeatedly — hundreds of ms
  per poll on a 50K-slot container).
  - `AsyncSpace::create(path, password, params)` — bootstrap a fresh
    container + space in one `spawn_blocking`.
  - `AsyncSpace::open(path, password)` — open existing.
  - `AsyncSpace::run(closure)` — arbitrary `&mut Space<'_>` ops on the
    blocking pool.
  - **`stream_log_pages_after(ns, after, page_size)`** — async forward
    pagination, oldest-first. Returns `impl Stream<Item = Result<Vec<(u64, Vec<u8>)>>>`.
  - **`stream_log_pages_before(ns, before, page_size)`** — async reverse
    pagination, newest-first. The canonical "scroll up to load older
    messages" primitive for chat UIs.
  - **`stream_log_pages_range(ns, start, end, page_size)`** — async
    half-open `[start, end)` range. Pair with timestamp-encoded `log_id`s
    for cheap async date-range queries.
  Each `poll_next` runs one `spawn_blocking` task that grabs the mutex,
  fetches the next page via the corresponding sync `iter_log_*` method,
  and releases the lock — so other async tasks can interleave between
  pages. New deps: `futures-core` (Stream trait, zero transitive deps) +
  `async-stream` (try_stream! macro). Coverage: 10 new tests in
  `tests/async_streaming.rs` (forward, reverse, cursor offset, range
  half-open, unbounded above/below, degenerate, empty namespace,
  durability across reopen, run+stream interplay).
- **`crates/hidden-volume/fuzz/` cargo-fuzz scaffold** (v0.5 fuzzing
  milestone follow-up). Three coverage-guided fuzz targets via
  `libfuzzer-sys`:
  - **`plaintext_decode`** — `Plaintext::decode` directly. Hot path on
    every chunk read.
  - **`decoder_family`** — every public `decode`: `Plaintext`, `Superblock`,
    `CommitPayload`, `IndexNode`, `decode_batch`, `Argon2Params::decode`.
    Catches any format-parser regression in one target.
  - **`container_open`** — end-to-end `Container::open_readonly` on
    random byte files. Exercises magic-check, header parser, file-size
    validation, discovery-scan entry.
  Fuzz package excluded from workspace (`exclude = [...]` in root
  Cargo.toml) so stable-toolchain `cargo build --workspace` does not
  pull `libfuzzer-sys`'s nightly-only `-Z` deps. Run via
  `cd crates/hidden-volume && cargo +nightly fuzz run <target>`.
  See [`crates/hidden-volume/fuzz/README.md`](crates/hidden-volume/fuzz/README.md)
  for CI integration recipe + crash-replay instructions. Stable-only
  `tests/parser_fuzz.rs` (proptest-based) remains the in-tree
  panic-freedom gate; cargo-fuzz adds coverage-guided exploration for
  v1.0 external review.
- **`hidden-volume-ffi` crate** (v0.8 milestone scaffold). uniffi 0.28
  proc-macro-based FFI bindings — generates idiomatic Kotlin/Swift/
  Python/Ruby bindings from a single Rust source of truth (no UDL
  drift). Surface: `SpaceHandle::create` / `::open` constructors,
  read methods (`get`, `count`, `list_namespaces`, `read_log`,
  `iter_log_range`, `commit_seq`, `commit_history`, `stats`,
  `verify_integrity`), batched `commit(Vec<WriteOp>)` with `Put` /
  `Delete` / `AppendLog` ops in one Tx, password-less `header_info`
  free function. Error type: flat `HvError` enum (1:1 mirror of
  `hidden_volume::Error`) → typed exceptions on the foreign side.
  Internal layout: self-referential `SpaceInner` (boxed
  `Container` + `ManuallyDrop<Space<'static>>`) pinned behind
  `Mutex` — keeps `Space` alive across FFI calls without paying the
  O(N) trial-decrypt scan per call. ADR + integration guide in
  [`docs/FFI_DESIGN.md`](docs/FFI_DESIGN.md). Build pipeline (iOS
  xcframework, Android `.aar`, Flutter sample) explicitly deferred
  to v0.8.x — Rust scaffold does not depend on them. Coverage: 5 FFI
  integration tests in `crates/hidden-volume-ffi/src/lib.rs`
  (`create_open_round_trip`, `header_info_works_no_password`,
  `iter_log_range_through_ffi`, `verify_integrity_through_ffi`,
  `empty_commit_is_noop`).
- **Public API baseline snapshot** — [`docs/PUBLIC_API_v1.txt`](docs/PUBLIC_API_v1.txt),
  297 lines covering both `hidden-volume` and `hidden-volume-async` crates.
  Generated by grep-extraction (`cargo public-api` install blocked by
  `openssl-sys` build dep in our sandbox; grep dump is stable, sortable,
  and adequate for v1.0 freeze diffing). When the OpenSSL dev headers
  are available in CI, swap to `cargo public-api --simplified` for a
  semantically richer dump.
- **`BENCH.md` § "v0.6 perf-target validation".** Compares the original
  v0.6 aspirations (scan ≥5 GiB/s x86, ≥1 GiB/s ARM; append ≥50 MB/s
  mobile; repack ≥100 MB/s x86) to measured numbers. Repack target
  **met** (~333 MiB/s); scan target **missed** by ~2.5× — the
  `parallel-scan` ceiling on the dev host is 2.0–2.2 GiB/s, bound
  inherently by per-chunk XChaCha20-Poly1305 (~1.5 GiB/s/thread × 4
  threads with the contention-cliff cap). Revised v1.0 targets in the
  doc: ≥1.5 GiB/s x86, ≥300 MiB/s Cortex-A53. ARM measurement
  deferred to v0.8 (FFI / `.aar` deployment). Append re-formulated as
  Tx-batched throughput (50 MB/s sustained at ≥100 KB Tx commits), since
  the 3-fsync floor dominates raw byte-rate.
- **`hv` CLI: `verify` and `dump-stats` subcommands.** Both are
  read-only (LOCK_SH); password from stdin or `HV_PASSWORD`. `verify`
  walks the Merkle tree under the given password and prints
  `(namespaces_verified, chunks_verified, max_depth, status: ok)` —
  surfaces `Error::IntegrityFailure { detail, slot }` as nonzero exit
  on tampering. `dump-stats` prints aggregated `SpaceStats`
  (`commit_seq`, `commit_history_len`, `owned_chunk_count`,
  `total_entries`, per-namespace counts) — the same data
  host-app's "About this profile" UI would render. Coverage: 5 new
  CLI tests in `tests/cli.rs` (fresh-space verify, post-write verify,
  wrong-password verify, fresh-space dump-stats, post-write dump-stats).
  Closes the v0.3.x CLI scope (now: info / create / create-space /
  inspect / get / put / verify / dump-stats / repack).
- **`Space::iter_log_range(namespace, start, end, limit)`** — half-open
  range query over a log namespace, returning up to `limit` entries
  with `log_id` in `[start, end)` in ascending order. `None` on either
  side means unbounded. Walks B+ tree leaves left-to-right with early
  termination as soon as either `limit` is reached or an entry past
  `end` is observed (subtrees rooted to the right of `end` are not
  visited). Memory bound: O(limit). Pair with timestamp-encoded
  `log_id`s for cheap chat date-range queries
  ("messages from yesterday to today"). Coverage: 13 new tests in
  `tests/log_pagination.rs` (R1-R13: empty namespace, zero limit,
  degenerate range, equivalence to `iter_log_after`, lower-only,
  upper-only, both-bounds half-open, off-by-one at start/end, limit
  capping, range past last entry, range across DataBatch boundaries,
  sparse ids).
- **Auto-splitting log batches at commit time.** A Tx that touches the
  message-log namespace with many or incompressible records (random /
  base64 / already-encrypted blobs) no longer fails commit with
  `Error::PayloadTooLarge` from `encode_batch`. The new
  [`log::encode_batches_split`] in `crates/hidden-volume/src/space/log.rs`
  recursively halves the record set until each batch fits under
  `PAYLOAD_CAP` (4040 bytes); `commit_tx` emits one `DataBatch` chunk
  per resulting batch and routes per-record KV pointers accordingly.
  Split is transparent on read (`read_log` / `iter_log_*` follow KV
  pointers, not batch boundaries). Validates with two new integration
  tests in `tests/log_basic.rs`: 32×2 KiB random payloads in one Tx
  produce ≥8 batches all readable; pagination works across the splits.
  Common-case cost (records compress well, ≤ ~150 short messages):
  exactly one zstd call, no behavior change.
- **`#![deny(missing_docs)]` quality gate** on both `hidden-volume`
  and `hidden-volume-async` crates. Every public item — types,
  variants, constants, struct fields, methods, free functions —
  now carries a rustdoc comment. Closes 76 missing-doc warnings
  introduced by the lint promotion. The crate now fails to build
  if a future PR adds an undocumented `pub` item.
- **`#[must_use]` markers on 40 pure accessor / constructor /
  encoder methods** across the workspace. Cuts a class of bugs
  where callers forget to consume the return value of e.g.
  `Tx::is_empty()`, `Space::commit_seq()`, `Superblock::encode()`,
  `derive_chunk_key()`. `cargo clippy -W clippy::must_use_candidate`
  now reports zero candidates.

### Changed
- **CI workflow refresh** (`.github/workflows/ci.yml`): updated for
  the v0.7 workspace split + new feature flags (`parallel-scan`,
  `mmap`). Pre-existing `--features async` references removed (no
  longer a feature; lives in `hidden-volume-async` sibling crate).
  Jobs now: `test` (Linux/macOS/Windows × stable + Linux beta) on
  default features + workspace doctests + `cli`-feature subprocess
  tests; `features-unix` (Linux + macOS) running parallel-scan and
  mmap test suites separately + an all-features full-workspace
  test on Linux; `locking-unix` for the flock tests; `clippy` /
  `fmt` / `rustdoc` workspace-wide with `-D warnings`; `audit`
  (RustSec advisory-db, continue-on-error); `deny` (cargo-deny
  policy from `deny.toml`); `bench-check` (compile only); MSRV
  pin job on Rust 1.85.
- **Rustdoc broken-intra-doc-links fixed** in
  `crates/hidden-volume/src/container/mod.rs`,
  `crates/hidden-volume/src/crypto/derive.rs`,
  `crates/hidden-volume/src/tx/commit.rs` so the rustdoc CI job
  passes with `RUSTDOCFLAGS=-D warnings`.

### Added
- **`deny.toml`** — cargo-deny supply-chain policy at the workspace
  root. License whitelist (MIT, Apache-2.0, BSD-{2,3}-Clause, ISC,
  Unicode-3.0, Zlib, MPL-2.0, CC0-1.0); advisory-db check via
  RustSec; deny multi-version dups (warn) + wildcards (deny);
  explicitly deny `openssl` / `openssl-sys` / `native-tls` (the
  crate uses RustCrypto exclusively); registry source restricted
  to crates.io. Targets cover Linux x86_64+aarch64, macOS x86_64+
  aarch64, Windows MSVC.

### Changed
- **Public API freeze prep — `#[non_exhaustive]` audit.** The
  following enums and library-constructed-only structs are now
  marked `#[non_exhaustive]`, so future minor releases may add
  variants/fields without bumping major:
  - `Error` (enum) — has grown 5 → 12 variants pre-1.0.
  - `ChunkKind` (enum) — format reserves room for new chunk kinds.
  - `PaddingPolicy` (enum) — new policies may land later.
  - `IntegrityReport` (struct) — only the library constructs it.
  - `SpaceStats` (struct) — same.
  Downstream `match` arms on these enums MUST include a `_ =>`
  catch-all from this point forward. Destructuring the structs
  (`let SpaceStats { commit_seq, .. } = stats`) continues to
  work; struct-expression construction from outside the crate is
  forbidden — but only the library constructs them anyway.

  `ContainerOptions` and `RepackOptions` are deliberately NOT
  `#[non_exhaustive]` — that would forbid the natural
  `Foo { a: …, b: … }` syntax even with FRU. We accept that
  adding a field there is a major bump post-v1.0; the budget is
  documented in `docs/SEMVER.md` §1.2.1. Other format-internal
  pub types (Header, Plaintext, Superblock, IndexNode tree types,
  CommitPayload) stay non-`#[non_exhaustive]` so tests + parser-
  fuzz can construct them; the actual stability target there is
  the *byte layout* in `FORMAT_v1.md`, not the struct shape.

  `docs/SEMVER.md` updated with the policy table.

### Added
- **`docs/FORMAT_v1.md`** — canonical byte-level wire format spec
  (12 sections / ~480 lines), foundation for v1.0 format freeze
  and external crypto review. Covers: top-level container layout
  (header 80 B cleartext + chunk grid), Argon2 params encoding,
  per-chunk wire layout (24 B nonce / 4056 B ciphertext / 16 B
  tag), AAD construction, plaintext frame (magic / kind / flags /
  seq / payload_len / payload / pad), key schedule (Argon2id →
  BLAKE3-keyed derivation chain with `hv/v1/space/*` labels), all
  six `ChunkKind` payload encodings (Superblock / IndexNode {Leaf,
  Internal} / Data / Journal / Commit / DataBatch zstd-compressed),
  Tx commit 3-fsync protocol with crash-recovery contract, discovery
  scan + deniability invariant explanation, format-constant table,
  reservation bytes for non-breaking v1.x extensions (plaintext
  `flags` byte + Argon2 `params_version`), what is NOT in the
  format (no magic / no version marker / no TOC / no timestamps —
  ruled out for parser-differential reviewers), audit checklist
  for external reviewers, format change log scaffold.
- **`docs/SEMVER.md`** — semver coverage policy (7 sections):
  what's covered (public Rust API + on-disk format + Cargo
  features), what's NOT (internal modules, dep versions, MSRV,
  bench numbers, error message strings), version-to-format mapping
  (1.x.y reads + writes v1; hypothetical 2.x.y reads v1 + writes
  v2; 3.x.y v2-only with one-major-version deprecation cadence),
  yank policy (when to yank vs not), pre-release posture
  (alpha → rc → 1.0.0 sequence), out-of-band guarantees (format
  stability, test coverage, audit traceability, breaking-change
  rationale).
- Cross-links from `DESIGN.md` §2 (now points to `FORMAT_v1.md` for
  byte-level reference), `README.md` Status section, and
  `INTEGRATION.md` "Where to read next" table.

- **mmap reader** (feature `mmap`, Unix-only). New
  `Container::open_space_mmap(password)` /
  `open_space_with_keys_mmap(keys)` use a single `mmap(2)` of the
  entire container file and slice each chunk out of the mapping
  during the discovery scan — zero allocation per chunk on the
  read path. Behaviorally identical to `open_space` / `open_space_parallel`:
  same `Space` state, same vacuum semantics. The feature opts in
  to a `memmap2` dependency (~80 KiB compiled) and an `unsafe`
  `Mmap::map(&File)` call; concurrent file mutation is excluded by
  the `LOCK_EX` / `LOCK_SH` flock acquired at `Container::open` /
  `open_readonly` time. `ContainerFile::raw_file()` is a new
  crate-internal accessor for the underlying File handle (only
  compiled under the feature). `tests/mmap_scan.rs` (7 scenarios)
  cross-checks behavioral equivalence against both sequential and
  parallel scans, plus wrong-password / empty-file / with-keys
  edge cases. Closes the v0.6 mmap-reader deliverable.

### Changed
- **Workspace split** (v0.7 closeout). Repository layout is now a
  cargo workspace with two member crates:
  - `crates/hidden-volume/` — sync core, tokio-free.
  - `crates/hidden-volume-async/` — Tokio wrapper exposing
    `AsyncContainer`. Depends on `hidden-volume` via path.
  Top-level `Cargo.toml` is the workspace manifest; profiles
  (`release`, `bench`) are workspace-shared. `Cargo.lock` lives at
  the workspace root and covers both crates.
  The `async` feature flag is **removed** from the core crate —
  async users now opt in by depending on `hidden-volume-async`
  explicitly. Sync-only consumers (mobile, single-process desktop,
  embedded) pay zero tokio cost. `tokio` is no longer a dev-
  dependency of the core crate.
  Async tests moved out of the core crate:
  `crates/hidden-volume-async/tests/async_basic.rs` (7) +
  `crates/hidden-volume-async/tests/cancellation.rs` (1, formerly
  the `#[cfg(feature = "async")]` test in
  `tests/cancellation.rs`). `cargo test --workspace` still green.
  Public sync API surface is unchanged: import paths under
  `hidden_volume::*` are identical, only `hidden_volume::async_api`
  → `hidden_volume_async` (via the new crate's name).
- README "Architecture" diagram and "Async / Tokio integration"
  section updated to reflect the new layout. `INTEGRATION.md` §6
  updated.

### Added
- **`docs/OPERATIONS.md`** — operations playbook (10 sections):
  backup / restore with anchor warning, single + multi-space key
  rotation, Argon2 parameter migration via repack, corruption
  diagnostic + recovery (4 incident classes), storage budget
  management with vacuum_data_batches vs compact_known guidance,
  multi-device deployment patterns A-D, forensic scrub before
  disposal (best-effort logical + defense-in-depth: FDE / tmpfs /
  USB-key), size monitoring with overhead bands, 12-symptom
  troubleshooting matrix. Closes the v1.0 docs deliverable for
  `OPERATIONS.md`.
- **`docs/MIGRATION.md`** — empty shell for eventual v1→v2 format
  migration. Documents intra-v1 ops cross-link, candidate v2
  reasons (none committed: hidden header, 3-level B+ tree,
  format-level Merkle root), forward-compatible migration
  mechanism plan (header version byte detection, repack-style
  copy, one-major-version compatibility window, re-anchor
  requirement, what NOT to do). Closes the v1.0 docs deliverable
  for `MIGRATION.md`.
- Cross-links added from `README.md` Status section and
  `INTEGRATION.md` "Where to read next" table.

- **`docs/THREAT_MODEL.md`** — formal threat model for v1.0 external
  crypto-review process. Sections: system model (what the library
  is and isn't, trusted components), adversary tiers (T1
  single-snapshot, T2/T2' multi-snapshot append-diff vs in-place-
  diff, T3 compelled-key), security invariants each with precise
  statement + code paths + supporting audit pass (D1
  single-snapshot indistinguishability, D2 compelled-key
  deniability, I1 per-chunk integrity, I2 tail-corruption
  tolerance, I3 cross-space isolation, R1 rollback / fork-detection
  contract, M1 memory hygiene, C1 cancellation safety),
  out-of-scope mitigations table, mitigation summary by code area,
  audit history (4 v0.5 passes), review request enumerating what
  external reviewers should confirm/deny per invariant. Cross-
  linked from `DESIGN.md` §1, `README.md`, `INTEGRATION.md`, and
  `PLAINTEXT_AUDIT.md`. Closes the v1.0 milestone's
  `THREAT_MODEL.md` deliverable.

- **Parallel-scan scaling benchmarks** (`bench_open_50k_*`,
  `bench_open_100k_*`). Confirms that the `parallel-scan` feature
  scales monotonically with container size on the 12-thread x86 dev
  host: 10 K → 2.8×, 50 K → 2.3×, **100 K → 7.4×** speedup. The
  sequential path drops from 770 MiB/s at 40 MiB to 270 MiB/s at
  400 MiB (page-cache hot-path falloff), while parallel pread-from-
  4-threads keeps prefetching at ~2 GiB/s. `BENCH.md` "Scaling"
  table added; recommended-when matrix updated.

- **`Space::vacuum_data_batches() -> Result<usize>`** — scrub owned
  DataBatch chunks that no namespace's KV index references anymore.
  Closes the forward-secrecy gap of `erase_namespace` on log
  namespaces (which leaves DataBatch chunks AEAD-decryptable until
  compact) AND reclaims orphan batches from log-entry overwrites
  (each re-append with the same `log_id` makes the prior batch
  unreachable). Cheaper than `Container::compact_known` for
  forward-secrecy alone — leaves `commit_history` and `container_id`
  intact while scrubbing the unreferenced bytes. Walk cost ≈
  Σ count(ns) tree walks + O(M) owned-chunk reads; read-only safe
  (returns 0 on `open_readonly`). `tests/vacuum_data_batches.rs`
  (8 scenarios): empty / fresh-log / post-erase reclaims / 5-round
  overwrite reclaims / multi-namespace isolation / idempotence /
  read-only zero / integrity-holds-after-vacuum. `docs/INTEGRATION.md`
  §10a updated with the cheaper "erase + vacuum_data_batches"
  recipe in place of the previous "erase + compact_known".

- **`Space::stats() -> Result<SpaceStats>`** — aggregate per-space
  statistics (commit_seq, commit_history_len, owned_chunk_count,
  per-namespace entry counts) in one call. The structured form
  host-app UIs render in a "Storage" / "About this profile" page.
  Walks each active namespace's KV-index tree once (cost ≈ sum of
  `count` calls per namespace); read-only safe. `SpaceStats`
  implements a `total_entries()` helper that sums across namespaces.
  `tests/space_stats.rs` (8 scenarios) — empty space, single
  namespace, multi-namespace KV+log with ascending-byte ordering,
  post-erase namespace disappears, multi-commit history advances,
  post-repack owned-count drops, read-only handle path,
  total_entries helper sums correctly. `docs/INTEGRATION.md` §8b
  documents the Storage-UI pattern.

- **`Space::erase_namespace(ns) -> Result<usize>`** — drop every entry
  in a namespace in a single transaction. Use case: "Clear chat
  history" / "Wipe contacts" UI buttons in a messenger. Returns the
  count removed. Idempotent on empty (returns 0, no commit). The new
  commit omits the namespace from its `IndexRoot` set (rebuilt tree
  is empty); orphan IndexNode chunks scrubbed by the next
  `vacuum_orphans` (auto-runs on `open_space`). For log namespaces,
  `DataBatch` chunks remain AEAD-decryptable until a subsequent
  `compact_known` — the recommended "Clear chat history" recipe is
  `erase_namespace(MESSAGE_LOG) + compact_known`. `tests/erase_namespace.rs`
  (10 scenarios) covering empty (no commit), full KV wipe, peer-namespace
  preservation, log KV-pointer removal, vacuum scrubs orphans on
  reopen, post-compact DataBatch elimination, commit_seq increment,
  double-erase idempotence, write-after-erase recreates, multi-space
  isolation. `docs/INTEGRATION.md` §10a documents the pattern with
  the forward-secrecy caveat for log namespaces.

- **`Container::change_passwords(path, mapping, options)`** +
  **`Container::change_passwords_cancellable(...)`** — in-place
  password rotation. Production-critical for messenger UX (user
  changes their password without losing data). The mapping is
  `&[(open_with, write_as)]`: equal pair preserves a space verbatim,
  unequal pair rotates it. Spaces not listed in the mapping are
  dropped (same destructive semantics as `compact_known` — list each
  preserved space as `(p, p)`). Internally refactors `repack_inner`
  into `repack_inner_mapped` so the existing `repack` /
  `repack_cancellable` are now thin wrappers around the same
  primitive (no behavior change for them). Atomic-rename pattern via
  `path.hv-rotate-tmp`: any failure (`AuthFailed`,
  `SpaceAlreadyExists`, `Cancelled`, I/O error) removes the temp and
  leaves `path` untouched. `tests/password_change.rs` (8 scenarios):
  single rotation, multi-space rotate-one-preserve-other, rotate-
  both-at-once, wrong old password → AuthFailed + tmp cleanup,
  `write_as` collision → SpaceAlreadyExists + tmp cleanup, drop-non-
  mapped spaces, no-op rotation identical to `compact_known`,
  cancellable pre-fired aborts cleanly.
- `docs/INTEGRATION.md` §10b documents the password-change pattern
  and its forward-secrecy caveat (FS-released blocks may be reused
  by the allocator; forensic-grade scrub is host-app concern).

- **`README.md` refreshed** to reflect the v0.4–v0.7 work that had
  shipped without README updates: capability table now lists
  paginated log, multi-device anchors (`commit_history`),
  `verify_integrity` Merkle walk, cancellation (`CancelToken`),
  read-only mode, streaming open, `parallel-scan` feature with the
  2.8× number, and the four completed audit passes. Quick-start
  expanded with pagination, cancellation, rollback-anchor, and
  integrity-self-test snippets. Architecture diagram updated to
  list `cancel.rs`, `async_api/`, `bin/hv.rs`. Cross-links to
  `docs/INTEGRATION.md` and `docs/MULTI_DEVICE.md`. Test inventory
  rewritten to match the current 30 test files.

- **`tests/crash_proptest.rs`** — property-based crash-recovery tests
  complementing the 8 hand-written scenarios in `crash_recovery.rs`
  and the exhaustive truncate-at-every-slot sweep in
  `many_chained_crashes`. Generates random op sequences (Put / Delete
  / AppendLog / Commit) and random truncation points, then asserts
  three invariants: (1) **recovery monotonicity** — recovered seq
  must be a seq we actually committed, and ≤ max committed seq;
  (2) **read APIs never panic post-recovery** — count / list / get /
  iter_log_after / iter_log_before / verify_integrity / commit_seq /
  commit_history all return Ok or documented Err on any reachable
  truncated state; (3) **recovery is idempotent** — two consecutive
  opens of the same truncated file yield the same recovered seq.
  24 cases × up to 30 ops each.

### Changed
- **`parallel-scan` is now a real win** on multi-core hosts (was
  measured ~5× slower than sequential in the previous iteration).
  Three changes together flipped the curve from ×0.2 to ×2.8 on a
  12-thread x86 host opening a 10 K-slot / 40 MiB container
  (52 ms → 18 ms):
  1. **Coarse-grained chunking.** Each parallel work item processes
     256 consecutive slots sequentially; amortizes rayon's per-task
     overhead over ~1.3 ms of real work.
  2. **Capped thread pool** at `min(4, available_parallelism)`.
     Empirical scaling on this host: 1 thread = 51 ms, 2 = 32 ms,
     4 = 47 ms (variable), 12 = 141 ms — AEAD-decrypt + small-chunk
     pread saturate L1 / memory bandwidth long before they saturate
     cores. 4-thread cap stays on the good side of the cliff.
  3. **`OnceLock`-cached pool.** A fresh `rayon::ThreadPool` per
     `open_space_parallel` call costs several ms; reusing the pool
     across opens reclaims that.
  All three were necessary; details + per-step measurements in
  `BENCH.md` "Parallel-scan tuning".

### Added
- **`BENCH.md` updated with v0.6/v0.7 measurements** on a 12-thread
  x86 dev machine: pagination (`iter_log_before_50` at 87 µs vs
  `iter_log_full` at 484 µs — 5.6× win confirms the messenger-
  pagination primitive), `verify_integrity` (125 µs over 1 100 KV
  entries — sub-ms self-test), large-container open-scan benchmark
  (`open_large_sequential` 52 ms / `open_large_parallel` 18 ms for
  a 10 K-slot / 40 MiB messenger-sized container — 2.8× speedup
  with `parallel-scan` feature). Bench harness gained
  `bench_open_large_*`, `bench_iter_log_full`, `bench_iter_log_paged_50`,
  `bench_verify_integrity`.

- **Parallel-scan feature (`parallel-scan`, Unix-only).**
  `Container::open_space_parallel(password)` /
  `open_space_with_keys_parallel(keys)` use rayon's work-stealing
  pool to parallelize AEAD-decrypts across slots during the open
  scan. Behaviorally identical to the sequential streaming path —
  same `Space` state, same vacuum semantics, same return type. The
  feature pulls in rayon (~6 MiB compiled); leave it OFF on
  single-core mobile, ON for desktop / server. New
  `ContainerFile::read_slot_concurrent(&self, i)` uses `pread(2)`
  via `std::os::unix::fs::FileExt::read_exact_at` so multiple
  threads read concurrently from the same `&File` handle without
  Rust-side locking. `tests/parallel_scan.rs` (6 scenarios) — same
  state as sequential, max-seq across 7 replicas × 10 commits,
  owned_slots sorted post-parallel, wrong-password → AuthFailed,
  empty file → AuthFailed, with-keys path bypasses Argon2.

- **`docs/INTEGRATION.md`** — narrative host-app integration guide.
  Covers: quickstart, hardware tuning (Argon2 presets), KV vs log
  namespace choice, multi-device patterns (cross-link to
  `MULTI_DEVICE.md`), message-history pagination via
  `iter_log_after` / `iter_log_before`, cooperative cancellation with
  `CancelToken` (sync + async patterns), rollback / fork detection
  via `commit_seq` + `commit_history`, key caching with
  `derive_space_keys` + `open_space_with_keys`, integrity walks via
  `verify_integrity`, padding policies, compaction trade-offs,
  13-point anti-patterns checklist, FAQ, doc index. Cross-linked
  from the crate-level rustdoc in `src/lib.rs`.

- **`Container::repack_cancellable(source, dest, passwords, options, &CancelToken)`**
  — cancellable variant of `repack`. Cancel checkpoints at every
  password boundary (read phase) and at every Tx commit boundary
  (write phase). The opened source space goes through
  `open_space_cancellable`, so the per-password scan loop also polls
  the token. On cancel, returns `Error::Cancelled` and leaves `dest`
  partial (caller cleans up — `compact_*_cancellable` does this for
  the in-place variant).
- **`Container::compact_known_cancellable`** /
  **`Container::compact_all_cancellable`** — cancellable in-place
  compactions. On cancel, the temp `path.hv-compact-tmp` is removed
  and the original `path` is untouched (atomic rename hasn't run).
- `tests/repack_cancellation.rs` (7 scenarios) — pre-fired token,
  pre-fired compact with tmp-cleanup verification, mid-flight cancel
  with 3 passwords (race-tolerant), fresh token after cancelled
  succeeds, never-cancelled `repack_cancellable` matches plain
  `repack` byte-for-byte, compact_all pre-fired with tmp cleanup,
  cancel during write phase.

- **`Space::iter_log_after(ns, after: Option<u64>, limit)`** — forward
  cursor pagination over a log namespace. Returns up to `limit`
  entries with `log_id > after` (or all entries if `after = None`),
  ascending. Memory-bounded: O(limit) decoded entries plus a few
  touched DataBatch chunks. Independent of total namespace size.
- **`Space::iter_log_before(ns, before: Option<u64>, limit)`** —
  reverse cursor pagination (newest-first). Up to `limit` entries
  with `log_id < before`, descending. The canonical chat-UI primitive
  for "scroll up to see older messages". Same memory bounds as
  `iter_log_after`.
- The B+ tree walk now early-stops on the leaf level once `limit` is
  reached — pagination cost is `O(limit + leaves_touched)` rather
  than `O(N)`.
- `tests/log_pagination.rs` (13 scenarios): empty namespace / limit=0,
  full-forward & full-reverse equivalence with `iter_log`, cursor
  walks forward and reverse over a 200-msg log, across-DataBatch-
  boundary pagination (1500-msg multi-tx log), out-of-range cursors,
  sparse log_ids, limit > total, B+ tree split case, payload integrity
  preserved end-to-end through pagination.
- Existing `Space::iter_log` is now a thin sugar over the shared
  `decode_log_entries` helper that powers all three iter APIs.

- **`hidden_volume::cancel::CancelToken`** — cooperative-cancellation
  primitive (a thin `Arc<AtomicBool>`). `cancel()` / `is_cancelled()` /
  `check()` for use as a `?`-friendly poll point inside long sync
  operations. Cheap to clone; firing from any thread short-circuits
  every existing and future clone.
- **`Container::open_space_cancellable(password, &CancelToken)`** and
  **`Container::open_space_with_keys_cancellable(keys, &CancelToken)`**
  — same semantics as `open_space` / `open_space_with_keys` but the
  O(N) scan polls the token every 64 slots and returns
  `Error::Cancelled` if fired. Argon2id derivation itself is NOT
  cancellable (RustCrypto is uninterruptible), so there is a
  post-Argon2 cancel check before the scan begins. Mid-cancel state:
  no observable file side effects.
- **`Error::Cancelled`** variant — distinguishes user-initiated abort
  from `AuthFailed` / I/O errors.
- **`AsyncContainer::run_cancellable(token, |c, t| ...)`** — bridges
  async-side cancellation into the sync core. Necessary because
  `tokio::task::spawn_blocking` does not abort a running closure;
  the threaded `CancelToken` is the workaround.
- `tests/cancellation.rs` (10 scenarios) — flag/clone/idempotency,
  pre-fired abort, mid-scan race + post-cancel file integrity check,
  reuse-after-cancel, independent fresh tokens, isolation from
  non-cancellable API, with-keys path, async `run_cancellable`.

### Changed
- **`scan_and_recover` is now streaming** (v0.6). The previous
  implementation collected every decrypted Plaintext into a `Vec<Found>`
  for the duration of the scan — ~4 KiB of heap per owned chunk. The
  refactor drops each Plaintext at the end of its iteration and
  accumulates only `owned_slots: Vec<u64>` (8 B/owned chunk),
  `commit_history: Vec<u64>` (8 B/Superblock after dedup), and the
  current best-seq Superblock's raw payload (~48 B). Asymptotic memory
  drops from `O(M · PLAINTEXT_LEN)` to `O(M · 16 B)` — ~250× smaller —
  letting weak ARM devices open multi-GiB containers without OOM.
  Public API unchanged. `tests/streaming_open.rs` (6 scenarios) covers
  many-commit roundtrip, replica dedup, max-seq across many replicas,
  owned_slots completeness, mixed KV+log workload, and large-history
  stress. **Breaking nothing observable**, just the memory profile.

### Added
- **`Space::verify_integrity() -> Result<IntegrityReport>`** — explicit
  Merkle hash-chain walk from the current Superblock down to every
  leaf. Verifies `SB.root_hash` against `BLAKE3(concat(roots[i].payload_hash))`,
  the CommitPayload's stored `tx_root_hash` for internal consistency,
  each `IndexRoot.payload_hash` against the actual hash of the
  IndexNode chunk's plaintext, and recursively each `ChildPointer.child_hash`
  for Internal-node children. Read-only safe (works on
  `Container::open_readonly` handles). Returns
  `IntegrityReport { namespaces_verified, chunks_verified, max_depth }`.
  AEAD-decrypt failures on chunks the integrity walk expected to own
  surface as `Error::IntegrityFailure { detail, slot }` instead of
  `AuthFailed`, so host-apps can distinguish "wrong password / not our
  chunk" from "owned chunk corrupted". Cost: O(N) chunks reachable
  from current Superblock, each read once and BLAKE3-hashed.
- **`Error::IntegrityFailure { detail: &'static str, slot: u64 }`** —
  raised exclusively by `verify_integrity` so the caller can localize
  corruption to a specific slot.
- `tests/integrity.rs` (10 scenarios) — empty, single-leaf, multi-namespace,
  B+ tree split (depth=2), DataBatch log namespace, multi-space
  isolation, post-compact, AEAD-corruption of IndexNode root and Commit
  chunk both surface as IntegrityFailure pointing at the corrupted slot,
  read-only handle path.
- **Plaintext-leak audit pass (`docs/PLAINTEXT_AUDIT.md`)** — fourth and
  final v0.5 audit. Wraps 7 transient plaintext buffers in `Zeroizing`
  so heap/stack regions are scrubbed at drop: `aead::ChunkAead::open`
  return value (`Zeroizing<Vec<u8>>`), `space::append_chunk` `pt_bytes`
  (`Zeroizing<[u8; PLAINTEXT_LEN]>`), `space::log::encode_batch` /
  `decode_batch` raw concat / decompress buffers, and
  `space::write_tree_for_namespace` LeafNode / InternalNode encoded
  bytes (which carry user key/value bytes). User-owned `Vec<u8>`s
  (`Tx::pending_*`, `Space::get`/`list`/`iter_log` returns, decoded
  `IndexNode` entries) explicitly deferred with rationale; cross-linked
  in `MEMORY_AUDIT.md` §C.
- `tests/plaintext_hygiene.rs` (4 tests) — type-level regression locking
  in `Zeroizing` wrap on `ChunkAead::open` and on the auto-deref chain
  callers depend on.
- **`Space::commit_history() -> &[u64]`** — sorted-ascending,
  deduplicated list of every commit-anchor seq still on disk (Superblock
  chunks that AEAD-decrypt under the space's key). For host-app rollback
  / fork triage and P2P-sync logic. O(1) accessor; populated from the
  same trial-decrypt scan that already runs at `open_space` time and
  updated in-place on every successful `commit_tx`. The initial Superblock
  written at `create_space` (seq=1) counts. Replicas at the same seq are
  deduplicated. Compaction resets the destination to a fresh history
  (host must re-anchor).
- **`docs/MULTI_DEVICE.md`** — formal contract for host-apps building
  P2P sync over `hidden-volume`. Documents the four supported patterns
  (single / sequential hand-off / read-only fan-out / replicated
  containers), what the library does and does NOT do, anchor primitives
  + rollback-detection algorithm, and the privacy contract for
  anchoring decoy / hidden spaces.
- `DESIGN.md` §11.2 updated to reference `MULTI_DEVICE.md`.
- `tests/multi_device.rs` (8 scenarios): fresh=[1], grows monotonically,
  dedups replicas at superblock_replicas=3, survives reopen, host-app
  triage of rollback/fork/clean, cross-space isolation, compaction
  resets, readonly exposes.
- **`tests/messenger_simulation.rs`** — 8 end-to-end scenarios
  modeling realistic messenger workloads: 5-day simulation with
  100 messages + contacts/settings churn; 3-week simulation with
  weekly compaction validating storage stays bounded; 22 reopen
  cycles preserving day-1 readability; delete+compact eliminates
  message bytes (forward-secrecy claim); concurrent writer/reader
  handoff (10 rounds); hidden-space-coexists-with-main; drop-decoy-
  via-compact_known; long-running session (30 rounds, mixed KV +
  log workload).
- **`hv` CLI utility** (`cli` feature). 7 subcommands: `info`,
  `create`, `create-space`, `inspect`, `get`, `put`, `repack`.
  Reads passwords from stdin or `HV_PASSWORD` env. `tests/cli.rs`
  (8 scenarios) spawning the binary via `CARGO_BIN_EXE_hv`.
- **`Container::open_readonly(path)`** + **`Container::is_readonly()`** —
  opens with shared `flock(LOCK_SH)`; multiple readers can coexist
  concurrently. Used by P2P sync agents, backup tools, forensics.
- **`Error::ReadOnly`** variant — returned by `create_space`,
  `set_padding_policy`, `set_superblock_replicas`, and any `Tx::commit`
  on a read-only handle. `vacuum_orphans` becomes a silent no-op.
- `tests/readonly.rs` (10 scenarios): basic open, multiple-readers
  coexist, writer-blocks-reader and vice-versa, all write methods
  return ReadOnly, vacuum-no-op, sequential reader/writer handoff.
- **`CONTRIBUTING.md`** — open-source workflow docs.
- **`Container::derive_space_keys(password) -> Result<SpaceKeys>`** —
  exposes Argon2id derivation as a separate step.
- **`Container::open_space_with_keys(SpaceKeys) -> Result<Space>`** —
  opens a space using pre-derived keys, skipping Argon2id (~100 ms
  saved on every relaunch).
- Cross-session caching workflow: host-app calls `derive_space_keys`
  once, persists `SpaceKeys` in OS-level secret store (Keychain /
  Secret Service / Keystore), reuses across sessions via
  `open_space_with_keys`.
- `tests/keys_cache.rs` (6 scenarios): same-keys path, byte-for-byte
  determinism, wrong-keys → AuthFailed, Clone semantics, AAD binding
  prevents cross-container key reuse, password vs cached comparison.

### Changed
- Migrated file locking from `fs2` crate to std's native `File::try_lock`
  / `try_lock_shared` (stable since Rust 1.89). Drops one external
  dependency. Same `flock(2)` / `LockFileEx` semantics as before.
- `Container::set_padding_policy` and `set_superblock_replicas` now
  return `Result<()>` instead of `()` to surface `Error::ReadOnly`
  on read-only handles. Existing callers updated.

### Documented
- Security trade-off: caching `SpaceKeys` outside the process
  bypasses Argon2id's brute-force resistance. An attacker with file
  + keyring contents recovers data without password. Use platform-
  native secure storage; document the trade-off in host-app's
  security policy.

## [v0.7] — Tokio async wrapper

### Added
- **`async` feature flag** that enables `hidden_volume::async_api`
  with `AsyncContainer` — a thin wrapper around `Container` that
  offloads sync operations onto Tokio's blocking-thread pool via
  `spawn_blocking`. Sync core unchanged.
- **`AsyncContainer::run<F>(closure)`** — generic offload of any
  `FnOnce(&mut Container) -> Result<R>`. Host-apps batch their work
  inside one `run()` call, matching the natural transactional
  granularity.
- `AsyncContainer::create` / `create_with_options` / `open` for
  lifecycle, plus `set_padding_policy` / `set_superblock_replicas`
  for runtime config.
- `Clone` impl shares the underlying `Container` via `Arc<Mutex<_>>`;
  concurrent `run()` calls from cloned handles serialize on the mutex.
- **`tests/async_basic.rs`** (7 scenarios, feature-gated): create,
  open-and-read, typed return, clone-shares-container, concurrent
  serialization via mutex, padding policy via async API, error
  propagation.
- CI now runs `cargo test --features async --tests` in addition to
  the default-feature suite.

### v0.5 closeout
- **fsync ordering audit** ([`docs/FSYNC_AUDIT.md`](docs/FSYNC_AUDIT.md)):
  traced 7 fsync sites; 3-fsync barrier protocol in `commit_tx`
  matches DESIGN §6 and tests/crash_recovery.rs. Documented macOS
  `F_FULLFSYNC` as out-of-scope (host-app concern).

## [v0.5] — Hardening + audits

### Added
- **Property tests for the full KV/log API** (`tests/property_full.rs`):
  random sequences of `Put / Delete / AppendLog / Commit / Reopen` ops
  validated against an in-memory `BTreeMap` reference model. 16 cases
  × up to 40 ops each, plus 6 deterministic regression tests.
- **Stable-Rust parser fuzzing** (`tests/parser_fuzz.rs`): 26 tests
  with proptest for decode-doesn't-panic on arbitrary bytes, encode↔
  decode roundtrip with invariant-preserving generators, and edge
  cases (empty, single-byte, exact boundaries, unknown kinds, non-zstd
  bytes). 9 decoders covered.
- **Memory hygiene audit** (`docs/MEMORY_AUDIT.md` + `tests/memory_hygiene.rs`):
  `derive_chunk_key` and `derive_subkey` tightened to return
  `Zeroizing<[u8; 32]>` (was raw `[u8; 32]` — fixed). 7 type-level
  regression tests prevent signature regression.
- **Constant-time audit** (`docs/CT_AUDIT.md` + `src/crypto/ct.rs`):
  audited 17 distinct comparisons; none on secret data. Added
  `crypto::ct::eq_32` / `eq_slice` placeholder helpers (`subtle::ConstantTimeEq`)
  for any future defense-in-depth need. 4 unit tests.

### Changed
- `derive_chunk_key` and `derive_subkey` now return `Zeroizing<[u8; 32]>`
  instead of raw `[u8; 32]`. Callers automatically adapted via
  `Deref<Target=[u8; 32]>` — no API churn at call sites.

## [v0.6] — Performance baseline

### Added
- **Criterion benchmarks** (`benches/throughput.rs`, 9 benches):
  `create_space`, `open_space`, `commit_single_kv`, `commit_100_kv`,
  `commit_1000_kv`, `commit_log_100`, `get_random_kv`, `read_log`,
  `repack_1000`. Run with `cargo bench --bench throughput`.
- **`BENCH.md`** documenting baseline numbers, the 3-fsync floor
  insight, B+ tree split cost (~5% over single put), read paths
  sub-100µs, and hardware tuning recommendations per device class.

## [v0.4] — Multi-process safety

### Added
- **Exclusive flock on container open** via `fs2` crate. POSIX `flock(2)`
  per-OFD, so two separate `Container::open` calls produce
  `Error::Busy` for the second. Lock auto-released on `Container` drop.
- **`Error::Busy`** variant distinct from `Io` / `AuthFailed`.
- **`tests/locking.rs`** (8 scenarios) covering exclusive lock
  semantics, auto-release on drop, sequential reopens, distinct
  error variant.

## [v0.3] — Compaction + integrity + resilience

### Added
- **`Container::repack(source, dest, passwords, options)`** — primary
  compaction primitive. Reads all live state under supplied passwords,
  writes a fresh container with new salt + container_id, drops anything
  not unlocked. Closes the v0.2 DataBatch leak (deleted message bytes
  physically eliminated).
- **`Container::compact_known` / `compact_all`** — in-place wrappers
  over repack with atomic temp-file rename.
- **`RepackOptions`** with `argon2`, `initial_garbage_chunks`,
  `padding_policy`, `superblock_replicas`, `log_namespaces` fields.
- **`Space::list_namespaces`** and **`Space::iter_log`** helpers
  (cached batch decoding) for enumeration.
- **`tests/repack.rs`** (12 scenarios) including param rotation and
  realistic messenger compaction.
- **Multiple Superblock replicas** (`DEFAULT_SUPERBLOCK_REPLICAS = 3`):
  each commit writes N SB chunks at the same seq. AEAD-failed replicas
  drop from the recovery scan, so corruption of any single replica
  doesn't break the space. `Container::set_superblock_replicas` for
  runtime override. 9 corruption-survival tests in `tests/sb_replicas.rs`.

## [v0.2] — Real storage stack

### Added
- **Multi-op `Tx<'s, 'f>`** with `put` / `delete` / `append_log` /
  `commit`. 3-fsync barrier protocol validated by 8 truncation
  scenarios in `tests/crash_recovery.rs`.
- **`CommitPayload`** chunk encoding (per-namespace IndexNode root
  pointers + tx_root_hash).
- **KV index with namespaces** (`Namespace(u8)` newtype with
  `SETTINGS` / `CONTACTS` / `MESSAGE_LOG` / `MEDIA` constants).
  Sorted-vector `IndexNode` payload.
- **B+ tree split for IndexNode** (`Leaf` / `Internal` enum). Single
  leaf for small namespaces, Internal+Leaves for overflow. Caps each
  namespace at ~5000-10000 entries before `Error::IndexFull` (3rd
  level deferred). 7 overflow tests in `tests/kv_btree.rs`.
- **DataBatch + zstd** for the message log namespace
  (`ChunkKind::DataBatch = 0x06`). `Tx::append_log(ns, log_id, payload)`,
  `Space::read_log(ns, log_id)`. 100-msg batches compressed to ~3-5 KB.
  11 tests in `tests/log_basic.rs` including realistic_messenger_workload.
- **`Space::vacuum_orphans`** — forward-secrecy scrub of orphan
  IndexNode chunks. Auto-called at the end of `Container::open_space`.
  Idempotent. DataBatch chunks deferred to v0.3 compaction. 7 tests
  in `tests/scrub.rs`.
- **`PaddingPolicy`** enum (`None` / `BucketGrowth` / `FixedRatio`)
  applied at end of every commit. `ContainerOptions.initial_garbage_chunks`
  for decoy initial size. 8 integration + 4 unit tests.
- **`Error::PayloadTooLarge`** distinct from generic `Internal`.

### Changed
- BREAKING: replaced raw-records storage model with KV-only. Old
  `commit_record` / `read_latest_record` / `read_latest_records`
  removed; use `Tx::put` / `Space::get` / `Space::list`.

## [v0.1] — Foundation

### Added
- **Crypto primitives** (`src/crypto/`): XChaCha20-Poly1305 AEAD per
  chunk, Argon2id KDF (`MIN` / `LIGHT` / `DEFAULT` / `HEAVY` presets),
  BLAKE3-keyed per-slot key derivation, getrandom RNG.
- **Fixed 4096-byte chunk format** (`src/chunk/`) with 5 plaintext
  fields (magic, kind, flags, seq, payload_len, payload).
- **80-byte cleartext container header** (salt + container_id + Argon2
  params) — argon2 params persisted per-container, runtime device-class
  configurable.
- **Append-only `ContainerFile`** with `append_slot` / `write_slot` /
  `read_slot` / `scrub_slot` primitives.
- **Public `Container` + `Space<'f>` API** with `create_space` /
  `open_space` / `begin_tx` / `commit_seq`.
- **Trial-decrypt scan-and-recover** (`src/open/`) — O(N) scan, picks
  highest-seq Superblock; AuthFailed unifies wrong-password and no-such-space.
- **Property tests P1/P2/P3** — chunk roundtrip, scan determinism,
  wrong-password security-critical (D2).

### Documentation
- **`DESIGN.md`** — formal threat model (D1, D2, I1, I2, I3),
  on-disk format, key schedule, invariants.
- **`README.md`** — pitch, quickstart, status table, hardware tuning,
  architecture, testing summary.
- **`TASKS.md`** — milestone roadmap from v0.1 to v1.0.
- **Crate-level rustdoc** with passing doctest quickstart.
- **`examples/messenger_lifecycle.rs`** — runnable 8-step demo.

[v0.1]: https://example.invalid/v0.1
[v0.2]: https://example.invalid/v0.2
[v0.3]: https://example.invalid/v0.3
[v0.4]: https://example.invalid/v0.4
[v0.5]: https://example.invalid/v0.5
[v0.6]: https://example.invalid/v0.6
[Unreleased]: https://example.invalid/unreleased
