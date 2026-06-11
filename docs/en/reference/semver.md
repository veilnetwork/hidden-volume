# Semver policy

🇬🇧 **English** · [🇷🇺 Русский](../../ru/reference/semver.md)

**Status.** Pre-release: the v0.x line treats every minor bump
(0.x → 0.y) as potentially breaking. After v1.0 release this policy
becomes binding.

This document spells out **what semver covers** for the
`hidden-volume` crate and its sibling `hidden-volume-async` after
v1.0. The policy is binding: if a change in a future `1.y.z`
violates it, we YANK and re-cut. The TOC of changes is in
`CHANGELOG.md`; this document explains *what counts* as a breaking
change.

## 1. What semver covers

Three surfaces, each with explicit rules:

### 1.1 Public Rust API

The `pub` surface of `hidden-volume` and `hidden-volume-async` —
types, traits, functions, modules reachable from `lib.rs` — is
covered by semver. Specifically:

- Removing or renaming a `pub` item is a major bump (`2.0.0`).
- Changing an existing `pub` function's signature in a way that
  breaks at least one realistic caller is a major bump.
- Adding a new `pub` item is a minor bump (`1.y.0`).
- Internal refactors with no `pub` impact are a patch bump
  (`1.y.z`).
- Documentation-only changes are also patch bumps.
- The `cargo public-api` baseline (planned at v1.0) is the source
  of truth.

**What "realistic caller" means.** A caller compiling against the
last released version that uses idiomatic Rust (no `..= total::pub_inner_macro!()`
magic, no fork-the-private-modules tricks). Edge cases that
required `unsafe` or path-import-of-private-via-rustdoc tricks
don't count.

**Trait impls on existing types.** Adding a new `impl Trait for
PublicType` is technically a minor bump but in practice can break
downstream code that relies on inference (e.g. the new impl is now
ambiguous with theirs). We document significant new impls in
`CHANGELOG.md`'s "Added" section so downstream can plan.

### 1.2 On-disk format

The wire format (specified in `docs/en/reference/format.md`) is **frozen at
v1.0**. After that:

- `1.x.y` libraries MUST read v1 containers correctly.
- Adding a new `ChunkKind` value, new `Namespace` constant, or
  new feature behind a reservation byte (§8 of `FORMAT_v1.md`) is
  a minor bump if it's read-tolerant by older `1.x.y` libraries
  (i.e. they reject the new feature with a documented error
  rather than silently corrupting).
- Adding a feature that older `1.x.y` libraries CAN'T tolerate
  (would silently misparse) is a v2 generation — see
  `docs/en/guide/migration.md`.
- Strengthening Argon2 parameters (raising `Argon2Params::MIN`)
  would prevent older containers from opening; it's also a major
  bump / v2.

The bias is heavy: prefer v2 over a v1.x extension that risks
downstream silent breakage.

### 1.2.1 `#[non_exhaustive]` policy

The following pub items are `#[non_exhaustive]`:

| Item | Kind | Why |
|---|---|---|
| `Error` | enum | Has grown from 5 to 16 variants pre-1.0 (audit pass 17 added `ContainerTooLarge` for the write-side scan-budget gate); further variants expected as new operations land. |
| `ChunkKind` | enum | Format-version reserves room for new chunk kinds; downstream `match` must `_ =>`. |
| `PaddingPolicy` | enum | New policies (e.g. exponential growth) may land in minor releases. |
| `IntegrityReport` | struct | Library-only construction; future fields (timing, tree statistics) may be added. |
| `SpaceStats` | struct | Same — host-apps only read these; library may add fields. |

The following pub items are deliberately NOT `#[non_exhaustive]`:

| Item | Kind | Reason |
|---|---|---|
| `ContainerOptions` | struct | Construction via struct-expression is the natural API (`ContainerOptions { argon2: …, … }`). `#[non_exhaustive]` would force a builder pattern; we accept that adding a field here is a major bump after v1.0. |
| `RepackOptions` | struct | Same as `ContainerOptions`. |
| `Argon2Params` | struct | Frozen at format level — adding fields is a v2 generation, not a v1.x extension. |
| `Namespace` | newtype | `Namespace(pub u8)` — pattern-matched as `Namespace(byte)`; non_exhaustive would silently break that. |
| Format-internal types (`Header`, `Plaintext`, `Superblock`, `LeafNode`, `InternalNode`, `IndexNode`, `IndexRoot`, `CommitPayload`) | mixed | Construction is part of the test / parser_fuzz surface; adding `#[non_exhaustive]` would force test churn for no security benefit. The format spec in `docs/en/reference/format.md` is what locks these — the *bytes* are frozen, not the in-memory struct shape. |

### 1.3 Cargo features

Features are covered with one rule: adding a new feature is a
minor bump (`1.y.0`) and the new feature MUST be additive — its
flip from absent to present cannot break existing callers.
Removing or renaming a feature is a major bump.

The library's feature set as of v1.0 is:

- `cli` — `hv` binary target + `clap` dep.
- `parallel-scan` — rayon-based parallel discovery scan
  (Unix-only, opt-in unsafe-free).
- `mmap` — memmap2-based zero-copy scan path (Unix-only,
  opt-in `unsafe`).

There is no `std` feature flag — the crate requires `std`
unconditionally (`alloc`-only / `no_std` is not a v1.0 goal; the
async wrapper, FFI surface, and Argon2id KDF all require `std`).

`hidden-volume-async` and `hidden-volume-ffi` have no Cargo features
at v1.0 — async always pulls in tokio; FFI always pulls in uniffi
0.28. The internal `hidden-volume-rt` crate is also feature-free.

## 2. What semver does NOT cover

These things may change between any patch versions without notice:

- **Internal modules.** Anything not `pub` from `lib.rs`.
- **Test-only types and helpers.** Even when in `pub` modules,
  if their docs say "for tests only" / "for benches only".
- **Dependency versions.** A `cargo update` post-`1.x.y` may
  produce a different `Cargo.lock`; only the `Cargo.toml` version
  ranges are covered.
- **Compiler MSRV.** The minimum supported Rust version is
  documented in `README.md` and may bump in any minor release.
  We aim to support the last 6 months of stable Rust at all
  times.
- **Bench numbers.** `docs/en/contributing/benchmarks.md` numbers are informational; a
  performance regression is a bug to fix but not a semver
  violation.
- **Error messages.** `Error::*` variants are stable; the
  human-readable strings in `Display` / `Debug` impls may change.
- **Log lines.** The library does not log; downstream may or may
  not.
- **Test counts.** "We have 41 test files" is documentation, not
  a contract.
- **Internal performance feature combinations.** `parallel-scan`
  may flip its 4-thread cap, change rayon's pool config, etc.
  without semver impact, as long as the public API contract holds.

## 3. Version-to-format mapping

Pre-v1.0:

- `0.x` libraries write the format documented in
  `DESIGN.md` / `FORMAT_v1.md`. Pre-1.0 format is **not** stable
  between 0.x.y bumps; do not deploy without a clear migration
  plan (per `README.md` Status section).

Post-v1.0:

| Library version | Format generation | Notes |
|---|---|---|
| `1.x.y` | v1 (frozen) | Backwards compatible reads + writes within `1.*`. |
| `2.x.y` (hypothetical) | v1 read + v2 write | One-way migration; see `docs/en/guide/migration.md`. |
| `3.x.y` (hypothetical) | v2 only | v1 read drops; users must migrate via 2.x first. |

The exact deprecation cadence (how many minor versions before a
read-drop) is one major version cycle = at minimum one calendar
year between v2 introduction and v1 read removal.

## 4. Yank policy

We will YANK a release if:

- A bug in cryptography or crash recovery is discovered that could
  cause data loss or weakened security on top of an already-
  shipped release.
- A semver violation is shipped (a breaking change in a non-major
  release).

We will NOT yank for:

- Performance regressions (will fix, not yank).
- Documentation errors (will patch).
- Cosmetic API design dissatisfaction.

Yanked releases are documented in `CHANGELOG.md` with a "Yanked"
section explaining why.

## 5. Pre-release versions

`alpha` / `beta` / `rc` pre-releases are explicitly NOT covered by
semver — they exist for downstream integration testing and may be
revoked or rebased without notice. Use only with a clear
"experimental, replaceable" stance from your downstream consumer.

The v1.0 release itself follows this sequence (planned):

```
1.0.0-alpha.1       External crypto review starts here.
1.0.0-alpha.2..N    Review findings fixes.
1.0.0-rc.1          Review complete; format frozen.
1.0.0-rc.2..N       Last-mile bugfixes.
1.0.0               Release.
```

## 6. Out-of-band guarantees

Beyond semver, we commit to:

- **Format stability.** A v1 container created by `1.0.0` MUST
  open identically on `1.x.y` for any `x`, `y`.
- **Test coverage.** `cargo test --workspace --all-features` MUST
  pass on the announced MSRV at every release.
- **Audit traceability.** Every public crypto-touching change is
  documented in `CHANGELOG.md` and in the relevant `docs/*_AUDIT.md`
  with a date stamp and reviewer line.
- **Breaking-change rationale.** A major bump is accompanied by a
  `BREAKING.md` (or `CHANGELOG.md` "Breaking" section) listing
  every break, the rationale, and a migration path.

## 7. Cross-references

- `docs/en/reference/format.md` — frozen wire format spec.
- `docs/en/guide/migration.md` — v1 → v2 migration plan (empty shell
  until v2 lands).
- `docs/en/security/threat-model.md` — invariants the format and APIs
  preserve.
- `CHANGELOG.md` — keep-a-changelog-style release notes.
- `README.md` Status section — current pre-release posture.
