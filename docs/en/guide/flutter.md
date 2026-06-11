# Flutter integration — `hidden-volume`

🇬🇧 **English** · [🇷🇺 Русский](../../ru/guide/flutter.md)

How to embed `hidden-volume` storage in a Flutter messenger app.

## Status (as of audit pass 19, 2026-05-28)

| Layer | Status | Notes |
|---|---|---|
| Rust core (`hidden-volume`) | ✅ Stable | 397 tests across the workspace; v1.0.0-frozen format v3 (cluster #8 kind-tags + #9 version-bind + #10 per-space `container_id`, 2026-05-28) |
| FFI surface (`hidden-volume-ffi`) | ✅ Stable | sync + async (Tokio), uniffi 0.31 proc-macros, password buffers wrapped in `Zeroizing` (audit pass 16 + 17) |
| Auto-generated Kotlin / Swift bindings | ✅ Generated | [`bindings/kotlin/`](../../../bindings/kotlin/), [`bindings/swift/`](../../../bindings/swift/) — gitignored, regenerate locally |
| **Flutter plugin scaffolding** | ✅ Implemented | [`experimental/flutter_plugin/hidden_volume/`](../../../experimental/flutter_plugin/hidden_volume/) — `pubspec.yaml`, Android `build.gradle` + Kotlin glue, iOS `.podspec` + Swift glue, typed Dart facade. Lives under [`experimental/`](../../../experimental/README.md) pending native-artifact packaging on all target ABIs. |
| **Build scripts** | ✅ Shipped | [`scripts/build-android.sh`](../../../scripts/build-android.sh) (cargo-ndk, all 4 ABIs), [`scripts/build-ios.sh`](../../../scripts/build-ios.sh) (xcframework, requires macOS) |
| **CI native-artifact build** | ✅ Shipped | [`.github/workflows/flutter-build.yml`](../../../.github/workflows/flutter-build.yml) — `.so` × 4 ABIs on Ubuntu + `xcframework` on macOS-14 |
| **Dart/Flutter typed API** | ✅ Implemented | [`lib/hidden_volume.dart`](../../../experimental/flutter_plugin/hidden_volume/lib/hidden_volume.dart) — hand-written `dart:ffi` typed API (~1116 + 518 lines, 18 tests); the `UnimplementedError` stubs are gone. Bindings glue in [`lib/src/bindings.dart`](../../../experimental/flutter_plugin/hidden_volume/lib/src/bindings.dart). |
| Sample Flutter app | ✅ Present | [`experimental/flutter_plugin/hidden_volume/example/`](../../../experimental/flutter_plugin/hidden_volume/example/). |

The Flutter plugin is fully implemented; running on-device requires
the native-artifact build / host setup documented below.

## Quick start

```sh
# 1. Install once (~10 min):
rustup target add aarch64-linux-android armv7-linux-androideabi \
                  x86_64-linux-android i686-linux-android \
                  aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
cargo install cargo-ndk
# Set $ANDROID_NDK_HOME to your NDK r25c+ install.

# 2. Build native artifacts:
./scripts/build-android.sh           # Linux / Windows / macOS — 4 .so files
./scripts/build-ios.sh               # macOS only — HiddenVolumeFFI.xcframework

# 3. (re)generate language bindings:
cargo build -p hidden-volume-ffi --release
for lang in kotlin swift; do
    cargo run --bin uniffi-bindgen --features bindgen-cli \
        -p hidden-volume-ffi -- generate \
        --library target/release/libhidden_volume_ffi.so \
        --language "$lang" --out-dir "bindings/$lang"
done

# 4. From your Flutter app:
flutter pub add hidden_volume \
    --path /path/to/this/repo/experimental/flutter_plugin/hidden_volume
flutter pub get
flutter run
```

CI does steps 2-3 for you on every release tag (`v*.*.*`) and on
manual workflow dispatch; download the artifacts from the Actions
run if you don't have an NDK / Mac on your dev box (e.g. a
Windows-only contributor can request a manual run, then grab the
`.so` files from it).

This document is the integration recipe **today** with the tools that
exist today. Path A (uniffi-dart direct) is the long-term goal; Path B
(per-platform plugin) works now.

## Path A — direct via `uniffi-dart` (recommended once stable)

[`uniffi-dart`](https://github.com/NiwakaDev/uniffi-dart) generates
Dart bindings from the same `#[uniffi::*]` annotations the Kotlin /
Swift / Python generators consume. When it reaches stable (track
issues [#5](https://github.com/NiwakaDev/uniffi-dart/issues/5),
[#42](https://github.com/NiwakaDev/uniffi-dart/issues/42) for known
gaps), the integration shrinks to:

```sh
# In your Flutter app's `rust/` directory.
cargo build -p hidden-volume-ffi --release \
    --target aarch64-linux-android \
    --target armv7-linux-androideabi \
    --target x86_64-linux-android

# Generate Dart bindings.
cargo install uniffi-bindgen-dart   # once stable
uniffi-bindgen-dart \
    --library target/release/libhidden_volume_ffi.so \
    --out-dir lib/src/bindings
```

Then in your Flutter code:

```dart
import 'package:my_app/src/bindings/hidden_volume_ffi.dart' as hv;

Future<void> openSpace() async {
  final space = await hv.AsyncSpaceHandle.open(
    path: '/data/data/com.example.app/files/store.bin',
    password: utf8.encode('my-password'),
  );
  final value = await space.get(namespace: 1, key: utf8.encode('username'));
  print(utf8.decode(value!));
}
```

Bundle the per-ABI `.so` files via the
[`flutter_rust_bridge`-style](https://github.com/fzyzcjy/flutter_rust_bridge)
plugin layout under `android/src/main/jniLibs/` and similar for iOS.

**Track for migration:** when uniffi-dart 1.0 ships, the Dart-side
async surface should map directly to Dart `Future<T>` without
adapter code. Until then, expect minor manual wrapping.

## Path B — per-platform plugin (works today)

Wrap the Kotlin and Swift bindings in a standard Flutter plugin
(`flutter create --template=plugin`). On each platform, the
plugin's native code calls into the generated bindings:

```
my_storage_plugin/
├── android/src/main/kotlin/com/example/MyStoragePlugin.kt
│   └── (calls into bindings/kotlin/uniffi/hidden_volume_ffi/...)
├── ios/Classes/MyStoragePlugin.swift
│   └── (calls into bindings/swift/...)
└── lib/my_storage_plugin.dart
    └── (Dart → method-channel → native)
```

This is more work — you write a method-channel passthrough on each
side — but the underlying `hidden-volume-ffi` types are stable and
the heavy lifting (FFI ABI, error mapping, async runtime) is already
done. Roughly ~200 lines of Kotlin + ~200 lines of Swift + ~100 lines
of Dart for full coverage.

The trade-off vs Path A: every API change in the Rust crate requires
updating two native wrapper files (Kotlin, Swift) and the Dart
method-channel surface. With uniffi-dart it's one regeneration
command.

## Recommended initial methods to expose

A messenger MVP needs the minimum subset; defer the rest:

1. `SpaceHandle.create(path, password, argon, ...)` — first-run setup
2. `AsyncSpaceHandle.open(path, password)` — launch path (async to
   keep UI responsive during the open-time scan)
3. `commit(ops: List<WriteOp>)` — single batched write (settings,
   contacts, messages — see DESIGN.md §11.4 namespace assignments)
4. `get(namespace, key)` — KV reads (settings, contact metadata)
5. `iter_log_range(namespace, start, end, limit)` — chat history
   pagination (pair `log_id` with timestamp-encoded u64)
6. `commit_seq()` + `commit_history()` — for rollback-detection
   anchors (see [`multi-device.md`](multi-device.md))

Skip until needed: `verify_integrity`, `stats`, `header_info`. They
are diagnostic-only and the host-app rarely surfaces them in mainline
UI flows.

## Threading model

The async surface (`AsyncSpaceHandle`) is the right default for
Flutter — every method awaits, never blocking the Dart isolate's
event loop. Internally each call offloads to Tokio's blocking pool;
uniffi starts the runtime inside the Rust dylib at first use.

The sync `SpaceHandle` is also available but **do not call from the
main isolate** — the open-time scan can take hundreds of ms on
weak hardware and would freeze the UI. Use sync only from a Dart
isolate spawned via `compute()` / `Isolate.spawn()`.

Concurrent calls on the same handle serialize on an internal mutex
(matches the sync core's "one Tx per Space at a time" invariant).
Two `await space.get(...)` calls from different async functions will
run sequentially under the hood.

## Storage budget on mobile

A messenger user's container size scales with message history. From
[`docs/en/contributing/benchmarks.md`](../contributing/benchmarks.md):

| User profile | Size | Open time (parallel-scan) |
|---|---|---|
| Light (~6 months, 1 contact) | 40 MiB | 18 ms |
| Average (~2 years, 5 contacts) | 200 MiB | 264 ms |
| Heavy (~5 years, 20 contacts) | 400 MiB | 204 ms |

For Flutter on Android: enable `parallel-scan` feature on the cdylib
build (`cargo build -p hidden-volume-ffi --release --features parallel-scan`).
On iOS the feature can be enabled too — rayon's 4-thread cap keeps
power consumption bounded. See
[`docs/en/contributing/benchmarks.md`](../contributing/benchmarks.md) §"Parallel-scan tuning" for the empirical
scaling curve.

## Argon2 preset selection

| Device class | Preset | First-launch unlock |
|---|---|---|
| Cortex-A53 (2017+) low-end Android | `ArgonPreset.LIGHT` | ~30 ms |
| Mid-range / flagship Android, A12+ iPhone | `ArgonPreset.DEFAULT` | ~100 ms |
| Desktop Linux/macOS/Windows | `ArgonPreset.HEAVY` | ~250 ms |

Pick at `create` time — the preset is baked into the container
header. Migrating to a stronger preset later is done via a no-op
`change_passwords` rotation with new Argon2 params (see
[`operations.md`](operations.md) §3).

## Backup / restore on mobile

Both Android and iOS have OS-level backup hooks (Android Auto Backup,
iCloud Keychain + Documents). The container file is a **single
opaque blob** — back up the whole thing. See
[`operations.md`](operations.md) §1 for the cold-backup procedure
(LOCK_SH + anchor warning).

## What this guide does NOT cover

- **Hot reload of Rust code in Flutter dev mode** — not supported by
  uniffi; requires app restart on Rust changes.
- **iOS xcframework packaging** — see [`TASKS.md`](../../../TASKS.md) v0.8;
  recipe deferred until first iOS integrator commits.
- **Android `.aar` packaging** — same, recipe in
  [`bindings/README.md`](../../../bindings/README.md) §Kotlin.
- **Flutter Web** — `hidden-volume` requires real flock + fsync;
  browser sandbox doesn't provide either. Use a server-side variant
  (e.g. WebSocket gateway to a backend running `hidden-volume`).

## See also

- [`docs/en/reference/ffi.md`](../reference/ffi.md) — architectural decisions
  (uniffi vs alternatives, threading, error mapping, async/sync split)
- [`bindings/README.md`](../../../bindings/README.md) — per-language usage
  examples (Python, Kotlin, Swift, Ruby)
- [`docs/en/guide/integration.md`](integration.md) — Rust-side host-app
  integration tour (anchors, rollback, sync)
- [`docs/en/guide/multi-device.md`](multi-device.md) — sync / anchor /
  rollback-detection contract
