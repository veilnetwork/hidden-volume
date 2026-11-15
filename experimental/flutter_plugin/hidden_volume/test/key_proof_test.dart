import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/hidden_volume.dart';
import 'package:hidden_volume/src/bindings.dart' show overrideDylib;

import 'test_dylib.dart';

void main() {
  setUpAll(() => overrideDylib(openTestDylib()));

  test('known-key proof preserves ciphertext for matching and absent keys', () {
    final fixture = Directory.systemTemp.createTempSync('hv_key_proof_');
    addTearDown(() => fixture.deleteSync(recursive: true));
    final path = '${fixture.path}/fixture.hv';
    final space = HvSpace.create(
      path: path,
      password: Uint8List.fromList('fixture'.codeUnits),
      argon: ArgonPreset.min,
      padding: PaddingPreset.none,
    );
    late Uint8List keys;
    try {
      space.commit([
        HvWriteOpPut(
            namespace: 1,
            key: Uint8List.fromList([1]),
            value: Uint8List.fromList([2])),
      ]);
      keys = space.spaceKeys();
    } finally {
      space.close();
    }
    final snapshot = File(path).readAsBytesSync();
    expect(verifySpaceKeys(path: path, keys: keys), isTrue);
    expect(File(path).readAsBytesSync(), snapshot);
    expect(verifySpaceKeys(path: path, keys: Uint8List(64)), isFalse);
    expect(File(path).readAsBytesSync(), snapshot);
    expect(verifySpaceKeys(path: path, keys: keys), isTrue);
    expect(File(path).readAsBytesSync(), snapshot);
  });

  test('invalid key shape refuses before a native path open', () {
    final fixture = Directory.systemTemp.createTempSync('hv_key_proof_shape_');
    addTearDown(() => fixture.deleteSync(recursive: true));
    final path = '${fixture.path}/missing.hv';
    for (final size in [0, 63, 65]) {
      expect(() => verifySpaceKeys(path: path, keys: Uint8List(size)),
          throwsArgumentError);
    }
    expect(File(path).existsSync(), isFalse);
  });

  test('missing file is an error, not an absent-space proof', () {
    final fixture =
        Directory.systemTemp.createTempSync('hv_key_proof_missing_');
    addTearDown(() => fixture.deleteSync(recursive: true));
    final path = '${fixture.path}/missing.hv';
    expect(() => verifySpaceKeys(path: path, keys: Uint8List(64)),
        throwsA(isA<HvException>()));
    expect(File(path).existsSync(), isFalse);
  });

  test('authenticated tree corruption remains an error without a scrub', () {
    final fixture =
        Directory.systemTemp.createTempSync('hv_key_proof_integrity_');
    addTearDown(() => fixture.deleteSync(recursive: true));
    final path = '${fixture.path}/fixture.hv';
    final space = HvSpace.create(
      path: path,
      password: Uint8List.fromList('fixture'.codeUnits),
      argon: ArgonPreset.min,
      padding: PaddingPreset.none,
    );
    late Uint8List keys;
    try {
      space.commit([
        HvWriteOpPut(
            namespace: 1, key: Uint8List.fromList([1]), value: Uint8List(800)),
      ]);
      keys = space.spaceKeys();
    } finally {
      space.close();
    }
    final snapshot = File(path).readAsBytesSync();
    expect(verifySpaceKeys(path: path, keys: keys), isTrue);
    var witnessedIntegrityFailure = false;
    // Inspect actual fixture slots, rather than assuming a root-slot number.
    for (var offset = 4096 + 24; offset < snapshot.length; offset += 4096) {
      final corrupted = Uint8List.fromList(snapshot)..[offset] ^= 1;
      File(path).writeAsBytesSync(corrupted, flush: true);
      try {
        verifySpaceKeys(path: path, keys: keys);
      } on HvException catch (error) {
        expect(error.kind, 'IntegrityFailure');
        witnessedIntegrityFailure = true;
      }
      expect(File(path).readAsBytesSync(), corrupted);
      if (witnessedIntegrityFailure) break;
    }
    expect(witnessedIntegrityFailure, isTrue);
  });
}
