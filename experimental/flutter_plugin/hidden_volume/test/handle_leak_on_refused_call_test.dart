// A call refused by a Dart-side validator must leave nothing behind.
//
// The bindings clone the native handle (uniffi 0.31 methods CONSUME the handle
// they are passed) and allocate Rust-owned buffers BEFORE the call, while some
// scalar validators run inside the call expression — after both. A validator
// that throws there leaks the clone, and the clone is an `Arc` on the
// container: its `flock` is then held until the process ends, so `close` frees
// nothing and the next `open` answers `Busy`.
//
// Proven against a REAL container, because the leak is at the FFI boundary.
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/src/bindings.dart';

import 'test_dylib.dart';

void main() {
  setUpAll(() => overrideDylib(openTestDylib()));

  ({String path, void Function() cleanup}) scratch(String tag) {
    final tmp = Directory.systemTemp.createTempSync('hv_leak_$tag');
    return (
      path: '${tmp.path}/store.bin',
      cleanup: () => tmp.deleteSync(recursive: true),
    );
  }

  final pwd = Uint8List.fromList('pwd'.codeUnits);

  /// Every refusal is driven the same way: make the call, close, and see
  /// whether the container can be opened again.
  void reopensAfter(String tag, void Function(SpaceHandleBindings) refused) {
    final s = scratch(tag);
    addTearDown(s.cleanup);

    final space = SpaceHandleBindings.create(
      path: s.path,
      password: pwd,
      argon: ArgonPreset.light,
    );
    expect(() => refused(space), throwsA(anything),
        reason: 'the fixture must actually be refused');
    space.close();

    final again = SpaceHandleBindings.open(path: s.path, password: pwd);
    again.close();
  }

  test('a refused iterLogRange does not strand the container', () {
    reopensAfter(
      'iter',
      (space) => space.iterLogRange(namespace: 2, limit: -1),
    );
  });

  test('a refused readLog does not strand the container', () {
    reopensAfter('read', (space) => space.readLog(2, -1));
  });

  test('a refused kvKeysPage does not strand the container', () {
    reopensAfter(
      'page',
      (space) => space.kvKeysPage(0, null, -1),
    );
  });

  test('a refused get does not strand the container', () {
    reopensAfter(
      'get',
      (space) => space.get(999, Uint8List.fromList([1])),
    );
  });
}
