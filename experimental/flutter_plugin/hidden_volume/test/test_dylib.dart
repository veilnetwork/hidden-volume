// Shared dylib resolver for the plugin's Dart tests.
//
// The previous per-test resolvers only searched for `hidden_volume_ffi.dll`
// (Windows extension), which made `flutter test` fail in `setUpAll`
// on macOS (`.dylib`) and Linux (`.so`). This helper picks the right
// extension for the running platform — and tries every probable
// search root — so the tests work uniformly across host OS.
//
// Naming convention: no `_test.dart` suffix so Dart's test runner
// does not auto-discover this as a test file.

import 'dart:ffi' show DynamicLibrary;
import 'dart:io';

/// Find the freshly-built `hidden-volume-ffi` cdylib for the current
/// host platform. Tries debug first because `cargo test` / `cargo build` refresh
/// it during local development; a stale release artifact must not silently make
/// the binding tests exercise an older ABI. Searches both
/// "test runs from plugin dir" and "test runs from repo root"
/// layouts. Throws [StateError] with the full candidate list if no
/// file is found.
String resolveDylibPath() {
  // Pick the host's native shared-library extension. macOS uses
  // `.dylib`, Linux uses `.so`, Windows uses `.dll`. `cdylib` outputs
  // in `target/{release,debug}/` use the platform-default prefix /
  // extension.
  final triplets = <List<String>>[
    if (Platform.isMacOS) ['lib', 'hidden_volume_ffi', '.dylib'],
    if (Platform.isLinux) ['lib', 'hidden_volume_ffi', '.so'],
    if (Platform.isWindows) ['', 'hidden_volume_ffi', '.dll'],
  ];
  if (triplets.isEmpty) {
    throw StateError('unsupported host OS: ${Platform.operatingSystem}');
  }
  final root = Directory.current.path;
  final searchRoots = <String>[
    // `flutter test` invoked from the plugin dir
    // (`experimental/flutter_plugin/hidden_volume/`) — ascend three
    // levels to find the workspace `target/`.
    '$root/../../../target',
    // `flutter test` invoked from the repo root.
    '$root/target',
  ];
  final candidates = <String>[];
  for (final base in searchRoots) {
    for (final profile in ['debug', 'release']) {
      for (final triple in triplets) {
        candidates.add('$base/$profile/${triple[0]}${triple[1]}${triple[2]}');
      }
    }
  }
  for (final p in candidates) {
    if (File(p).existsSync()) return p;
  }
  throw StateError('cdylib not found, searched: ${candidates.join(", ")}');
}

/// Convenience wrapper: resolve, open, return the [DynamicLibrary].
DynamicLibrary openTestDylib() => DynamicLibrary.open(resolveDylibPath());
