// End-to-end test of the public facade in `lib/hidden_volume.dart`.
// Mirrors the FFI smoke test but exercises the typed `HvSpace` API
// (the surface a host-app actually consumes). The dylib resolver
// lives in `test/test_dylib.dart` so it picks the right extension
// for the host (`.dylib`/`.so`/`.dll`).

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/hidden_volume.dart';
import 'package:hidden_volume/src/bindings.dart' show overrideDylib;

import 'test_dylib.dart';

void main() {
  setUpAll(() {
    overrideDylib(openTestDylib());
  });

  test('HvSpace.create → put → get → headerInfo', () {
    final tmp = Directory.systemTemp.createTempSync('hv_facade_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final space = HvSpace.create(
      path: path,
      password: Uint8List.fromList('passphrase'.codeUnits),
      argon: ArgonPreset.light,
    );

    space.commit([
      HvWriteOpPut(
        namespace: 1,
        key: Uint8List.fromList('username'.codeUnits),
        value: Uint8List.fromList('alice'.codeUnits),
      ),
    ]);

    final got = space.get(1, Uint8List.fromList('username'.codeUnits));
    expect(got, isNotNull);
    expect(String.fromCharCodes(got!), 'alice');

    // headerInfo takes LOCK_SH; release the writer's LOCK_EX first.
    space.close();
    final hi = headerInfo(path);
    expect(hi.fileSizeBytes, greaterThan(0));
  });

  test('HvSpace.open after create round-trip', () {
    final tmp = Directory.systemTemp.createTempSync('hv_facade_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final s1 = HvSpace.create(
      path: path,
      password: Uint8List.fromList('pw'.codeUnits),
      argon: ArgonPreset.light,
    );
    s1.commit([
      HvWriteOpPut(
        namespace: 2,
        key: Uint8List.fromList('contact'.codeUnits),
        value: Uint8List.fromList('bob'.codeUnits),
      ),
    ]);
    s1.close();

    final s2 = HvSpace.open(
      path: path,
      password: Uint8List.fromList('pw'.codeUnits),
    );
    addTearDown(s2.close);

    final v = s2.get(2, Uint8List.fromList('contact'.codeUnits));
    expect(String.fromCharCodes(v!), 'bob');
    expect(s2.commitSeq(), greaterThan(0));
  });

  test('typed HvException.AuthFailed propagates through facade', () {
    final tmp = Directory.systemTemp.createTempSync('hv_facade_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final s = HvSpace.create(
      path: path,
      password: Uint8List.fromList('right'.codeUnits),
      argon: ArgonPreset.light,
    );
    s.close();

    expect(
      () => HvSpace.open(
        path: path,
        password: Uint8List.fromList('wrong'.codeUnits),
      ),
      throwsA(isA<HvException>()
          .having((e) => e.kind, 'kind', 'AuthFailed')),
    );
  });

  test('spaceKeys export → openWithKeys reopens without a password', () {
    final tmp = Directory.systemTemp.createTempSync('hv_facade_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    // A "child identity" space; write data, export its keys.
    final child = HvSpace.create(
      path: path,
      password: Uint8List.fromList('childpw'.codeUnits),
      argon: ArgonPreset.light,
    );
    child.commit([
      HvWriteOpPut(
        namespace: 1,
        key: Uint8List.fromList('who'.codeUnits),
        value: Uint8List.fromList('carol'.codeUnits),
      ),
    ]);
    final keys = child.spaceKeys();
    expect(keys.length, 64, reason: 'SpaceKeys is container_id ‖ aead_root');
    child.close(); // release the exclusive flock

    // A "master" reopens the child by keys alone — no password.
    final reopened = HvSpace.openWithKeys(path: path, keys: keys);
    final got = reopened.get(1, Uint8List.fromList('who'.codeUnits));
    expect(got, isNotNull);
    expect(String.fromCharCodes(got!), 'carol');
    reopened.close();

    // Wrong length → Malformed.
    expect(
      () => HvSpace.openWithKeys(path: path, keys: Uint8List(10)),
      throwsA(isA<HvException>().having((e) => e.kind, 'kind', 'Malformed')),
    );

    // Well-formed but bogus keys → AuthFailed (indistinguishable from a wrong
    // password — the count of spaces never leaks).
    expect(
      () => HvSpace.openWithKeys(
        path: path,
        keys: Uint8List.fromList(List.filled(64, 7)),
      ),
      throwsA(isA<HvException>().having((e) => e.kind, 'kind', 'AuthFailed')),
    );
  });
}
