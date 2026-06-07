# hidden_volume — Flutter plugin (experimental)

> ⚠️ **EXPERIMENTAL — pre-stable, do NOT publish.**
>
> This package lives under [`experimental/`](../../README.md) and is
> NOT covered by `hidden-volume`'s SemVer policy. The plugin
> manifest, podspec, and example LICENSE carry placeholder values
> (`github.com/example`, `noreply@example.com`) — fill them with real
> values before any publish.
>
> **What works (2026-05-10):** the Dart-side typed API in
> [`lib/hidden_volume.dart`](lib/hidden_volume.dart) and the
> hand-written `dart:ffi` bindings in
> [`lib/src/bindings.dart`](lib/src/bindings.dart) are fully
> implemented (Path C — direct binding over the stable uniffi 0.31
> C ABI). 18 plugin tests pass; the integration test
> ([`example/integration_test/app_test.dart`](example/integration_test/app_test.dart))
> passes end-to-end on Windows desktop and on the Android x86_64
> emulator. Native artifacts (Android `.so` per ABI, Windows `.dll`)
> are produced by [`scripts/build-android.sh`](../../../scripts/build-android.sh)
> and [`scripts/build-windows.sh`](../../../scripts/build-windows.sh).
>
> **What's pending:** iOS xcframework — needs a macOS host with
> Xcode (out-of-scope on Windows / Linux dev boxes). The
> `scripts/build-ios.sh` helper exists; CI's `flutter-build.yml`
> matrix includes a macOS-14 runner for this.

Flutter wrapper around the [`hidden-volume`](../../../) Rust crate.
Provides a deniable, multi-space encrypted append-only container
suitable as the local storage layer of a decentralized messenger.

## Layout

```
experimental/flutter_plugin/hidden_volume/
├── pubspec.yaml                 — Flutter plugin manifest
├── lib/
│   ├── hidden_volume.dart       — typed public Dart API (HvSpace, HvAsyncSpace)
│   └── src/
│       ├── bindings.dart        — hand-written dart:ffi over uniffi 0.31 C ABI
│       └── async_bindings.dart  — worker-isolate async wrapper
├── example/                     — runnable demo + integration_test
├── android/
│   ├── build.gradle             — AGP module
│   ├── src/main/AndroidManifest.xml
│   ├── src/main/jniLibs/<abi>/  — populated by build-android.sh
│   └── src/main/kotlin/.../HiddenVolumePlugin.kt   (no-op stub)
├── ios/
│   ├── hidden_volume.podspec    — CocoaPods manifest
│   ├── Classes/HiddenVolumePlugin.swift   (no-op stub)
│   └── HiddenVolumeFFI.xcframework/  — populated by build-ios.sh
└── windows/
    ├── CMakeLists.txt           — bundles cdylib via lib/
    ├── lib/                     — populated by scripts/build-windows.sh
    └── hidden_volume_plugin.{h,cpp}   (no-op stub)
```

## Build pipeline

### Android (works on Linux / Windows / macOS)

```sh
# 1. Install prerequisites once.
rustup target add aarch64-linux-android armv7-linux-androideabi \
                  x86_64-linux-android i686-linux-android
cargo install cargo-ndk
# Set $ANDROID_NDK_HOME to your NDK r25c+ install path.

# 2. From the repo root:
./scripts/build-android.sh
```

The script copies four `libhidden_volume_ffi.so` files into
`experimental/flutter_plugin/hidden_volume/android/src/main/jniLibs/<abi>/`.
Gradle picks them up automatically when an app depends on this
plugin.

### Windows desktop

```sh
# From the repo root:
./scripts/build-windows.sh
```

Stages `hidden_volume_ffi.dll` into the plugin's `windows/lib/`;
the plugin CMakeLists.txt bundles it next to the example app's
`.exe` automatically when `flutter build windows` runs.

### iOS (requires macOS)

```sh
# 1. Install prerequisites once.
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# 2. Regenerate Swift bindings against the latest Rust FFI surface:
cargo build -p hidden-volume-ffi --release
cargo run --bin uniffi-bindgen --features bindgen-cli \
    -p hidden-volume-ffi -- generate \
    --library target/release/libhidden_volume_ffi.dylib \
    --language swift --out-dir bindings/swift

# 3. From the repo root:
./scripts/build-ios.sh
```

Output: `experimental/flutter_plugin/hidden_volume/ios/HiddenVolumeFFI.xcframework`.
The podspec already references this path as a vendored framework.

## Usage

```dart
import 'package:hidden_volume/hidden_volume.dart';

void main() async {
  // Spawn a worker isolate so KDF + I/O don't block the UI thread.
  final space = await HvAsyncSpace.create(
    path: '/data/data/<pkg>/files/store.bin',
    password: utf8.encode('correct horse battery staple'),
    argon: ArgonPreset.defaults,
  );
  await space.commit([
    HvWriteOpPut(
      namespace: 1,
      key: utf8.encode('username'),
      value: utf8.encode('alice'),
    ),
  ]);
  final v = await space.get(1, utf8.encode('username'));
  print(utf8.decode(v!));  // alice
  await space.close();
}
```

For one-shot top-level operations (header inspection, password rotation,
container compaction), use `headerInfoAsync` / `changePasswordsAsync` /
`compactKnownAsync`.

See the parent project's [Integration guide](../../docs/en/guide/integration.md)
for the conceptual model (spaces, transactions, deniability invariants)
and [Flutter guide](../../docs/en/guide/flutter.md) for messenger
integration patterns.
