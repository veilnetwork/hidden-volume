# Changelog

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
