# Changelog

## Unreleased

- `HvStatsInfo` gains `reusableSlotCount` and `hardeningFailure`, and
  `HvSpace` / `HvAsyncSpace` gain `acknowledgeHardeningError()` (report10
  HV-04). The first is the half of the `compactKnown` decision Dart did not
  have — `utilizationRatio()` alone reads a healthily recycling container as
  sparse. The second is a padding / churn / fsync round that did not run: the
  commit is durable, its MASKING is weaker than the format promises, and Dart
  had no way to be told. It is **sticky** — a later successful commit does not
  clear it, because a host polls for this and one more commit between two polls
  is ordinary — and `acknowledgeHardeningError()` is the only thing that does.
  `HvHardeningStep` says which of the three failed; the three mean different
  things and a host told only "hardening failed" cannot act on any of them.

- Add `HvSpace.addSpace({path, password})` (+ `SpaceHandleBindings.addSpace`) —
  bind the new `add_space` FFI constructor that adds a parallel, deniable space
  to an existing container. The primitive for hiding several identities in one
  file; throws `SpaceAlreadyExists` on password collision.

## 0.0.1 — 2026-05-03

Initial scaffolding (no published release):
- Plugin layout (`pubspec.yaml`, Android `build.gradle` + Kotlin glue,
  iOS `.podspec` + Swift glue, Dart facade + manual `dart:ffi`
  skeleton).
- Build scripts: `scripts/build-android.sh`, `scripts/build-ios.sh`.
- CI matrix: Android `.so` build on Ubuntu, iOS `xcframework` build
  on macOS.
- No published release yet — typed Dart API (`HvContainer`, `HvSpace`,
  `HvTx`) is `UnimplementedError`-throwing skeleton until uniffi-dart
  0.4 stabilizes or the manual `dart:ffi` bindings are filled in.
