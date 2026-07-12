// Smoke test for the hand-written dart:ffi bindings.
//
// Loads the cdylib, exercises the MVP surface (create / commit / get /
// iter_log_range / commit_seq / commit_history / close + top-level
// headerInfo). The cdylib resolver lives in `test/test_dylib.dart` so
// the lookup picks the right extension for the host
// (`.dylib`/`.so`/`.dll`); previously this test hard-coded `.dll`
// and broke `flutter test` on macOS/Linux.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/src/bindings.dart';

import 'test_dylib.dart';

void main() {
  setUpAll(() {
    overrideDylib(openTestDylib());
  });

  test('uniffi contract version is 30', () {
    expect(contractVersion(), 30);
  });

  test('empty commit is no-op', () {
    final tmp = Directory.systemTemp.createTempSync('hv_dart_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final space = SpaceHandleBindings.create(
      path: path,
      password: Uint8List.fromList('pwd'.codeUnits),
      argon: ArgonPreset.light,
    );
    final s0 = space.commitSeq();
    final s1 = space.commit([]);
    expect(s1, s0, reason: 'empty commit returns current seq unchanged');
    space.close();
  });

  test('round-trip: create / put / get / commitSeq / headerInfo', () {
    final tmp = Directory.systemTemp.createTempSync('hv_dart_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final pwd = Uint8List.fromList('correct horse battery staple'.codeUnits);
    final space = SpaceHandleBindings.create(
      path: path,
      password: pwd,
      argon: ArgonPreset.light,
    );

    final initialSeq = space.commitSeq();
    expect(initialSeq, isNonNegative);

    final newSeq = space.commit([
      HvWriteOpPut(
        namespace: 1,
        key: Uint8List.fromList('username'.codeUnits),
        value: Uint8List.fromList('alice'.codeUnits),
      ),
      HvWriteOpPut(
        namespace: 1,
        key: Uint8List.fromList('email'.codeUnits),
        value: Uint8List.fromList('alice@example.com'.codeUnits),
      ),
    ]);
    expect(newSeq, greaterThan(initialSeq),
        reason: 'commit advances commit_seq');

    final got = space.get(1, Uint8List.fromList('username'.codeUnits));
    expect(got, isNotNull);
    expect(String.fromCharCodes(got!), 'alice');

    final missing = space.get(1, Uint8List.fromList('nope'.codeUnits));
    expect(missing, isNull);

    final history = space.commitHistory();
    expect(history.length, greaterThanOrEqualTo(1));

    space.close();

    final hi = headerInfo(path);
    expect(hi.saltHex.length, 64);
    // v3 (2026-05-28): `container_id` is no longer in the cleartext
    // header. `HvHeaderInfo` correspondingly dropped `containerIdHex`.
    // The toString() output must reflect the new shape — assert
    // there is no `container=` substring (lock-down against a
    // future regression that re-introduces the field).
    expect(hi.toString(), isNot(contains('container=')));
    expect(hi.fileSizeBytes, greaterThan(0));
    // light preset: m=16384, t=3, p=1
    expect(hi.argonMCostKib, 16 * 1024);
    expect(hi.argonTCost, 3);
    expect(hi.argonPCost, 1);
  });

  test('append_log + iter_log_range round-trip', () {
    final tmp = Directory.systemTemp.createTempSync('hv_dart_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final space = SpaceHandleBindings.create(
      path: path,
      password: Uint8List.fromList('pwd'.codeUnits),
      argon: ArgonPreset.light,
    );
    space.commit([
      for (var i = 0; i < 5; i++)
        HvWriteOpAppendLog(
          namespace: 3,
          logId: i,
          payload: Uint8List.fromList('msg-$i'.codeUnits),
        ),
    ]);

    final entries = space.iterLogRange(namespace: 3, limit: 100);
    expect(entries, hasLength(5));
    for (var i = 0; i < 5; i++) {
      expect(entries[i].logId, i);
      expect(String.fromCharCodes(entries[i].payload), 'msg-$i');
    }

    final tail = space.iterLogRange(namespace: 3, start: 2, limit: 100);
    expect(tail.map((e) => e.logId), [2, 3, 4]);

    space.close();
  });

  test('delete_log removes a logical record', () {
    final tmp = Directory.systemTemp.createTempSync('hv_dart_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));
    final space = SpaceHandleBindings.create(
      path: path,
      password: Uint8List.fromList('pw'.codeUnits),
      argon: ArgonPreset.light,
    );
    space.commit([
      HvWriteOpAppendLog(
        namespace: 3,
        logId: 9,
        payload: Uint8List.fromList('record'.codeUnits),
      ),
    ]);
    expect(space.readLog(3, 9), isNotNull);

    space.commit([const HvWriteOpDeleteLog(namespace: 3, logId: 9)]);

    expect(space.readLog(3, 9), isNull);
    expect(space.count(3), 0);
    space.close();
  });

  test('wrong password → HvException.AuthFailed', () {
    final tmp = Directory.systemTemp.createTempSync('hv_dart_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final s1 = SpaceHandleBindings.create(
      path: path,
      password: Uint8List.fromList('right'.codeUnits),
      argon: ArgonPreset.light,
    );
    s1.close();

    expect(
      () => SpaceHandleBindings.open(
        path: path,
        password: Uint8List.fromList('wrong'.codeUnits),
      ),
      throwsA(isA<HvException>().having((e) => e.kind, 'kind', 'AuthFailed')),
    );
  });

  test('count / eraseNamespace / readLog / listNamespaces', () {
    final tmp = Directory.systemTemp.createTempSync('hv_dart_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final space = SpaceHandleBindings.create(
      path: path,
      password: Uint8List.fromList('pwd'.codeUnits),
      argon: ArgonPreset.light,
    );
    addTearDown(space.close);

    space.commit([
      HvWriteOpPut(
        namespace: 1,
        key: Uint8List.fromList('a'.codeUnits),
        value: Uint8List.fromList('1'.codeUnits),
      ),
      HvWriteOpPut(
        namespace: 1,
        key: Uint8List.fromList('b'.codeUnits),
        value: Uint8List.fromList('2'.codeUnits),
      ),
      HvWriteOpAppendLog(
        namespace: 3,
        logId: 42,
        payload: Uint8List.fromList('hello'.codeUnits),
      ),
    ]);

    expect(space.count(1), 2);

    final logEntry = space.readLog(3, 42);
    expect(logEntry, isNotNull);
    expect(String.fromCharCodes(logEntry!), 'hello');
    expect(space.readLog(3, 999), isNull);

    final namespaces = space.listNamespaces();
    expect(namespaces, contains(1));
    expect(namespaces, contains(3));

    space.eraseNamespace(1);
    expect(space.count(1), 0);
  });

  test('stats / vacuumDataBatches / verifyIntegrity', () {
    final tmp = Directory.systemTemp.createTempSync('hv_dart_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final space = SpaceHandleBindings.create(
      path: path,
      password: Uint8List.fromList('pwd'.codeUnits),
      argon: ArgonPreset.light,
    );
    addTearDown(space.close);

    space.commit([
      for (var i = 0; i < 10; i++)
        HvWriteOpPut(
          namespace: 1,
          key: Uint8List.fromList('k$i'.codeUnits),
          value: Uint8List.fromList('v$i'.codeUnits),
        ),
    ]);

    final stats = space.stats();
    expect(stats.commitSeq, greaterThan(0));
    expect(stats.totalEntries, greaterThanOrEqualTo(10));
    expect(stats.namespaceCounts.any((c) => c.namespace == 1 && c.count == 10),
        isTrue);
    expect(stats.utilizationRatio(), inInclusiveRange(0.0, 1.0));

    final scrubbed = space.vacuumDataBatches();
    expect(scrubbed, greaterThanOrEqualTo(0));

    final integrity = space.verifyIntegrity();
    expect(integrity.namespacesVerified, greaterThan(0));
    expect(integrity.chunksVerified, greaterThan(0));
    // dataBatchesVerified is wired through audit pass 18 M2 (2026-05-10).
    // No DataBatch chunks in this test (no log namespace touched), so
    // the count must be exactly 0. A non-zero value here is a sign the
    // wire decoder misread the field offsets.
    expect(integrity.dataBatchesVerified, 0);
  });

  test('utilizationRatio matches Rust semantics for empty container', () {
    final tmp = Directory.systemTemp.createTempSync('hv_dart_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final space = SpaceHandleBindings.create(
      path: path,
      password: Uint8List.fromList('pwd'.codeUnits),
      argon: ArgonPreset.light,
    );
    addTearDown(space.close);

    final stats = space.stats();
    // A freshly-created container has zero owned chunks AND zero total
    // slots. Rust [`SpaceStats::utilization_ratio`] returns 0.0 in
    // that case; the Dart helper used to disagree (returned 1.0),
    // which would have mis-driven host-app compact triggers.
    if (stats.totalSlotCount == 0) {
      expect(stats.utilizationRatio(), 0.0);
    } else {
      expect(stats.utilizationRatio(), inInclusiveRange(0.0, 1.0));
    }
  });

  test('setPaddingPolicy round-trip', () {
    final tmp = Directory.systemTemp.createTempSync('hv_dart_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final space = SpaceHandleBindings.create(
      path: path,
      password: Uint8List.fromList('pwd'.codeUnits),
      argon: ArgonPreset.light,
    );
    addTearDown(space.close);

    // Each preset is accepted without error. Padding effect is verified
    // by the Rust workspace tests; here we just exercise the FFI path.
    for (final preset in PaddingPreset.values) {
      space.setPaddingPolicy(preset);
    }
  });

  test('changePasswords keeps named space, drops unlisted', () {
    final tmp = Directory.systemTemp.createTempSync('hv_dart_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final s1 = SpaceHandleBindings.create(
      path: path,
      password: Uint8List.fromList('first'.codeUnits),
      argon: ArgonPreset.light,
    );
    s1.commit([
      HvWriteOpPut(
        namespace: 1,
        key: Uint8List.fromList('k'.codeUnits),
        value: Uint8List.fromList('v'.codeUnits),
      ),
    ]);
    s1.close();

    // Rotate: first → second. Old password is dropped.
    changePasswords(path, [
      HvPasswordRotation(
        oldPwd: Uint8List.fromList('first'.codeUnits),
        newPwd: Uint8List.fromList('second'.codeUnits),
      ),
    ]);

    // Old password no longer opens.
    expect(
      () => SpaceHandleBindings.open(
        path: path,
        password: Uint8List.fromList('first'.codeUnits),
      ),
      throwsA(isA<HvException>().having((e) => e.kind, 'kind', 'AuthFailed')),
    );

    // New password opens, data preserved.
    final s2 = SpaceHandleBindings.open(
      path: path,
      password: Uint8List.fromList('second'.codeUnits),
    );
    addTearDown(s2.close);
    final v = s2.get(1, Uint8List.fromList('k'.codeUnits));
    expect(v, isNotNull);
    expect(String.fromCharCodes(v!), 'v');
  });
}
