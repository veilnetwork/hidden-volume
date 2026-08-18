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

  test('an out-of-range namespace is refused, not silently narrowed', () {
    // `dart:ffi` narrows without complaint: the uniffi signature is `u8`, so
    // namespace 257 arrives in Rust as 1. The write path narrows too, because
    // `addByte` masks. Either way the caller is told the operation succeeded
    // while it touched a namespace they never named (audit HV-04).
    //
    // Proven against a REAL container, not a mock — the whole finding is that
    // the truncation happens at the FFI boundary itself.
    final tmp = Directory.systemTemp.createTempSync('hv_dart_ns_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final space = SpaceHandleBindings.create(
      path: path,
      password: Uint8List.fromList('pwd'.codeUnits),
      argon: ArgonPreset.light,
    );
    addTearDown(space.close);

    final key = Uint8List.fromList('k'.codeUnits);
    final value = Uint8List.fromList('v'.codeUnits);

    // Read side.
    expect(
      () => space.get(257, key),
      throwsA(isA<ArgumentError>()),
      reason: '257 would have read namespace 1',
    );
    expect(() => space.count(-1), throwsA(isA<ArgumentError>()));

    // Write side — the damaging one: a commit that lands in the wrong
    // namespace is a silent cross-namespace write.
    expect(
      () => space.commit([
        HvWriteOpPut(namespace: 257, key: key, value: value),
      ]),
      throwsA(isA<ArgumentError>()),
    );

    // Nothing leaked into namespace 1 on the way.
    expect(space.get(1, key), isNull,
        reason: 'the rejected write must not have landed anywhere');

    // Control: a legal namespace still works, so the guard is rejecting the
    // out-of-range value and not the operation.
    space.commit([HvWriteOpPut(namespace: 1, key: key, value: value)]);
    expect(space.get(1, key), value);
  });

  test('create counts that would narrow are refused, not degraded', () {
    // report7 P2. Two bare numbers reached the FFI unchecked, and the
    // consequence is not an overrun — the core clamps both to what the
    // container can hold. It is quieter than that, and worse for a format
    // whose point is deniability: the caller asked for something and got
    // LESS, silently.
    //
    //   superblockReplicas: 256 narrows to 0, and 0 means "the minimum" —
    //   ONE replica, fewer than the default 3, for a caller who asked for
    //   more. Replicas are what a torn write is recovered from.
    //
    //   initialGarbageChunks: Dart's int is 64-bit and SIGNED, and it wraps.
    //   `1 << 64` is 0 in Dart. A decoy size that wraps to zero turns off
    //   the padding the caller explicitly requested.
    final tmp = Directory.systemTemp.createTempSync('hv_dart_counts_');
    addTearDown(() => tmp.deleteSync(recursive: true));
    final pwd = Uint8List.fromList('pwd'.codeUnits);

    expect(
      () => SpaceHandleBindings.create(
        path: '${tmp.path}/replicas.bin',
        password: pwd,
        argon: ArgonPreset.light,
        superblockReplicas: 256,
      ),
      throwsA(isA<ArgumentError>()),
      reason: '256 would have narrowed to 0 and produced ONE replica',
    );
    expect(
      () => SpaceHandleBindings.create(
        path: '${tmp.path}/garbage.bin',
        password: pwd,
        argon: ArgonPreset.light,
        initialGarbageChunks: -1,
      ),
      throwsA(isA<ArgumentError>()),
      reason: 'a negative Dart int reinterprets as an enormous u64',
    );

    // Neither rejected call may leave a container behind: the guard has to
    // fire BEFORE the FFI, not after a file exists.
    expect(File('${tmp.path}/replicas.bin').existsSync(), isFalse);
    expect(File('${tmp.path}/garbage.bin').existsSync(), isFalse);

    // Control: in-range values on both still create a working container, so
    // the guard rejects the value and not the operation.
    final ok = SpaceHandleBindings.create(
      path: '${tmp.path}/ok.bin',
      password: pwd,
      argon: ArgonPreset.light,
      initialGarbageChunks: 4,
      superblockReplicas: 2,
    );
    addTearDown(ok.close);
    expect(ok.commitSeq(), isNotNull);
  });

  test('a range limit that would narrow is refused, not silently emptied', () {
    // report7 P2, third bare number. `limit` crosses as u32, so 2^32 narrows
    // to 0 — and a zero limit is a LEGAL request for an empty page. The
    // caller reads "no entries" from a namespace that has them, which is
    // indistinguishable from the end of the log.
    //
    // `kvKeysPage` took its limit bare through the same door and is guarded
    // with it: it is the same defect one method along, and nothing would
    // have caught it there either.
    final tmp = Directory.systemTemp.createTempSync('hv_dart_limit_');
    addTearDown(() => tmp.deleteSync(recursive: true));

    final space = SpaceHandleBindings.create(
      path: '${tmp.path}/store.bin',
      password: Uint8List.fromList('pwd'.codeUnits),
      argon: ArgonPreset.light,
    );
    addTearDown(space.close);
    space.commit([
      HvWriteOpAppendLog(
          namespace: 3,
          logId: 1,
          payload: Uint8List.fromList('entry'.codeUnits)),
    ]);

    const tooWide = 0x100000000; // 2^32
    expect(
      () => space.iterLogRange(namespace: 3, start: null, end: null, limit: tooWide),
      throwsA(isA<ArgumentError>()),
      reason: '2^32 would have narrowed to 0 and returned an empty range',
    );
    expect(
      () => space.kvKeysPage(1, null, tooWide),
      throwsA(isA<ArgumentError>()),
    );
    expect(
      () => space.iterLogRange(namespace: 3, start: null, end: null, limit: -1),
      throwsA(isA<ArgumentError>()),
    );

    // Control: an in-range limit still returns the entry, so the guard is
    // rejecting the value rather than breaking the call.
    final got =
        space.iterLogRange(namespace: 3, start: null, end: null, limit: 10);
    expect(got, isNotEmpty);
  });

  test('a negative log id is refused, not reinterpreted as 2^64-1', () {
    // Dart's `int` is signed and the FFI parameter is `u64`, so -1 crosses
    // as 18446744073709551615. Unlike the narrowing above, the width is
    // right and nothing is lost — the value simply means something else,
    // and log ids are an ORDERED domain: -1 does not land near zero, it
    // lands at the top. A read misses an entry that exists, a range query
    // asking for "from the beginning" covers only the last id there is,
    // and a delete names a record no writer will ever produce, so it
    // silently does nothing (audit HV13-M3). Log ids are frequently
    // timestamps, and an unset clock is the ordinary way a caller comes to
    // hold a negative one.
    final tmp = Directory.systemTemp.createTempSync('hv_dart_logid_');
    addTearDown(() => tmp.deleteSync(recursive: true));

    final space = SpaceHandleBindings.create(
      path: '${tmp.path}/store.bin',
      password: Uint8List.fromList('pwd'.codeUnits),
      argon: ArgonPreset.light,
    );
    addTearDown(space.close);

    final payload = Uint8List.fromList('entry'.codeUnits);
    // The boundary, on both ends of what a Dart int can carry.
    const maxDartInt = 0x7fffffffffffffff;
    space.commit([
      HvWriteOpAppendLog(namespace: 3, logId: 0, payload: payload),
      HvWriteOpAppendLog(namespace: 3, logId: maxDartInt, payload: payload),
    ]);
    expect(space.readLog(3, 0), isNotNull, reason: '0 is an ordinary id');
    expect(space.readLog(3, maxDartInt), isNotNull);

    // Read side.
    expect(() => space.readLog(3, -1), throwsA(isA<ArgumentError>()));
    expect(
      () => space.iterLogRange(namespace: 3, start: -1, end: null, limit: 10),
      throwsA(isA<ArgumentError>()),
      reason: 'a start of -1 asks for the very END of the domain',
    );
    expect(
      () => space.iterLogRange(namespace: 3, start: null, end: -1, limit: 10),
      throwsA(isA<ArgumentError>()),
    );

    // Write side, both ops that carry an id.
    expect(
      () => space.commit(
          [HvWriteOpAppendLog(namespace: 3, logId: -1, payload: payload)]),
      throwsA(isA<ArgumentError>()),
    );
    expect(
      () => space.commit([const HvWriteOpDeleteLog(namespace: 3, logId: -1)]),
      throwsA(isA<ArgumentError>()),
    );

    // Control: the guard rejects the value, not the operation, and the
    // rejected writes landed nowhere.
    final got =
        space.iterLogRange(namespace: 3, start: 0, end: null, limit: 10);
    expect(got.length, 2);
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
