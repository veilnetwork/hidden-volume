# `experimental/` — pre-stable scaffolding

Code under this directory is **NOT covered by `hidden-volume`'s SemVer
policy**. Anything here is either:

- **Gated on an upstream dependency** that has not yet shipped a
  stable release, OR
- **Gated on a platform toolchain** the maintainers don't have day-
  to-day access to (Xcode in the iOS case).

When the upstream gate is met, the work moves out of `experimental/`
and into the canonical project tree — at that point and only then it
joins the SemVer contract.

## Currently here

| Path | What it is | Gate to graduation |
|---|---|---|
| [`flutter_plugin/hidden_volume/`](flutter_plugin/hidden_volume/) | Flutter plugin: typed Dart API (`HvSpace` + `HvAsyncSpace`) over hand-written `dart:ffi` bindings to the uniffi 0.31 C ABI. **Sync + async surface fully implemented** as of 2026-05-10 (Path C). 18 tests pass; integration test passes on Windows desktop and Android emulator. Native artifacts produced by `scripts/build-{android,windows}.sh`. | iOS xcframework needs a macOS host (`scripts/build-ios.sh` + Xcode); SemVer commitment requires external crypto-review of the Rust core (TASKS.md v1.0 item). |

## Rules for adding to `experimental/`

1. New entries MUST come with a row in the table above explaining
   the gate.
2. Entries MUST NOT be referenced as "shipped" or "stable" anywhere
   in the canonical docs (`README.md`, `DESIGN.md`,
   `docs/en/reference/`, `docs/en/security/`).
3. Build / CI workflows that touch `experimental/` MUST be allowed
   to fail without blocking a release tag — they exist as
   convenience integrations, not as quality gates.
4. Once a gate is met, the migration commit moves the directory out
   of `experimental/` AND simultaneously updates
   `docs/en/reference/semver.md` to add the new public surface.
