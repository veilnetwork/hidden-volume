// ignore_for_file: avoid_print
// Micro-benchmark for the dart:ffi overhead of the hidden_volume sync
// bindings. Compares against the same operations driven from Python
// (`bench/ffi_overhead_bench.py`) — the workload is identical down to
// the chunk count.
//
// Run from repo root:
//   dart run experimental/flutter_plugin/hidden_volume/bench/ffi_overhead_bench.dart
// (Use a host with the cdylib already built at target/release.)
//
// What this measures:
//   1. SpaceHandle.create — dominated by Argon2 KDF (~30 ms light)
//   2. commit  — 1 KV put per call, includes one chunk write + fsync
//   3. get     — read one KV value
//   4. headerInfo — password-less header read (LOCK_SH)
//
// We deliberately use small payloads so per-call FFI overhead, not
// payload serialization, dominates the time budget.

import 'dart:io';
import 'dart:typed_data';

import 'package:hidden_volume/src/bindings.dart';

const int _opsPerSample = 200;
const int _samples = 5;

void main() {
  final dllPath = _resolveDylibPath();
  overrideDylib(DynamicLibrary.open(dllPath));
  print('cdylib: $dllPath');
  print('uniffi contract version: ${contractVersion()}');
  print('');

  final tmp = Directory.systemTemp.createTempSync('hv_bench_');
  try {
    _benchmarkCreate(tmp);
    _benchmarkGetCommit(tmp);
    _benchmarkHeaderInfo(tmp);
  } finally {
    tmp.deleteSync(recursive: true);
  }
}

void _benchmarkCreate(Directory tmp) {
  // 5 cold creates, each with ArgonPreset.light. Don't measure single
  // calls — Argon2 dominates and that's a Rust cost, not an FFI cost.
  // But report it anyway so the user has the absolute number.
  final samples = <int>[];
  for (var i = 0; i < _samples; i++) {
    final path = '${tmp.path}/create_$i.bin';
    final sw = Stopwatch()..start();
    final s = SpaceHandleBindings.create(
      path: path,
      password: Uint8List.fromList('bench'.codeUnits),
      argon: ArgonPreset.light,
    );
    sw.stop();
    s.close();
    samples.add(sw.elapsedMicroseconds);
  }
  _report('create (Argon2 light + 1 init commit)', samples, 1);
}

void _benchmarkGetCommit(Directory tmp) {
  final path = '${tmp.path}/getcommit.bin';
  final space = SpaceHandleBindings.create(
    path: path,
    password: Uint8List.fromList('bench'.codeUnits),
    argon: ArgonPreset.light,
  );

  // Pre-populate keys so the get() loop has something to read.
  final keys = <Uint8List>[
    for (var i = 0; i < _opsPerSample; i++)
      Uint8List.fromList('k$i'.codeUnits),
  ];
  space.commit([
    for (var i = 0; i < _opsPerSample; i++)
      HvWriteOpPut(
        namespace: 1,
        key: keys[i],
        value: Uint8List.fromList('v$i'.codeUnits),
      ),
  ]);

  // get() — 200 reads per sample
  final getSamples = <int>[];
  for (var s = 0; s < _samples; s++) {
    final sw = Stopwatch()..start();
    for (var i = 0; i < _opsPerSample; i++) {
      space.get(1, keys[i]);
    }
    sw.stop();
    getSamples.add(sw.elapsedMicroseconds);
  }
  _report('get  (200 reads/sample)', getSamples, _opsPerSample);

  // commit() — 200 single-put commits per sample. Each includes a
  // chunk write + fsync, so this is upper-bounded by disk speed.
  final commitSamples = <int>[];
  for (var s = 0; s < _samples; s++) {
    final sw = Stopwatch()..start();
    for (var i = 0; i < _opsPerSample; i++) {
      space.commit([
        HvWriteOpPut(
          namespace: 2,
          key: Uint8List.fromList('c${s}_$i'.codeUnits),
          value: Uint8List.fromList('v'.codeUnits),
        ),
      ]);
    }
    sw.stop();
    commitSamples.add(sw.elapsedMicroseconds);
  }
  _report('commit (1 KV + fsync per call)', commitSamples, _opsPerSample);

  space.close();
}

void _benchmarkHeaderInfo(Directory tmp) {
  final path = '${tmp.path}/header.bin';
  final s = SpaceHandleBindings.create(
    path: path,
    password: Uint8List.fromList('bench'.codeUnits),
    argon: ArgonPreset.light,
  );
  s.close();

  final samples = <int>[];
  for (var sample = 0; sample < _samples; sample++) {
    final sw = Stopwatch()..start();
    for (var i = 0; i < _opsPerSample; i++) {
      headerInfo(path);
    }
    sw.stop();
    samples.add(sw.elapsedMicroseconds);
  }
  _report('headerInfo (200 reads/sample)', samples, _opsPerSample);
}

void _report(String label, List<int> sampleMicros, int opsPerSample) {
  final perOpUs = sampleMicros.map((m) => m / opsPerSample).toList()..sort();
  final min = perOpUs.first;
  final p50 = perOpUs[perOpUs.length ~/ 2];
  final max = perOpUs.last;
  print('${label.padRight(36)}'
      '  per-op: min=${min.toStringAsFixed(2)}µs  '
      'p50=${p50.toStringAsFixed(2)}µs  '
      'max=${max.toStringAsFixed(2)}µs  '
      '($_samples samples × $opsPerSample ops)');
}

String _resolveDylibPath() {
  final root = Directory.current.path;
  // From repo root OR from the plugin dir — try both depths.
  final candidates = <String>[
    '$root/target/release/hidden_volume_ffi.dll',
    '$root/target/debug/hidden_volume_ffi.dll',
    '$root/../../../target/release/hidden_volume_ffi.dll',
    '$root/../../../target/debug/hidden_volume_ffi.dll',
  ];
  for (final p in candidates) {
    if (File(p).existsSync()) return p;
  }
  throw StateError('cdylib not found, searched: ${candidates.join(", ")}');
}
