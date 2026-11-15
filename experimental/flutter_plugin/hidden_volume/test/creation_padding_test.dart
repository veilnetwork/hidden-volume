import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/hidden_volume.dart';
import 'package:hidden_volume/src/bindings.dart' as ffi;
import 'test_dylib.dart';

void main() {
  setUpAll(() => ffi.overrideDylib(openTestDylib()));
  late Directory fixture;
  setUp(() =>
      fixture = Directory.systemTemp.createTempSync('hv-create-padding-'));
  tearDown(() => fixture.deleteSync(recursive: true));
  Uint8List password() =>
      Uint8List.fromList(utf8.encode('synthetic padding fixture'));
  final write = HvWriteOpPut(
      namespace: 1,
      key: Uint8List.fromList([1]),
      value: Uint8List.fromList([2]));

  test('explicit no-padding survives cold reopen without a session override',
      () {
    final path = '${fixture.path}/plain-posture.hv';
    final created = HvSpace.create(
        path: path,
        password: password(),
        argon: ArgonPreset.min,
        padding: PaddingPreset.none);
    created.commit([write]);
    created.close();
    final before = File(path).lengthSync();
    expect(before, lessThan(128 * 1024));
    final reopened = HvSpace.open(path: path, password: password());
    reopened.cancelDeferredVacuum();
    try {
      reopened.commit([write]);
      expect(reopened.get(1, Uint8List.fromList([1])), [2]);
    } finally {
      reopened.close();
    }
    expect(File(path).lengthSync() - before, lessThanOrEqualTo(64 * 1024));
  });

  test('omitting padding retains the hidden-storage default', () {
    final path = '${fixture.path}/hidden-posture.hv';
    final created = HvSpace.create(
        path: path, password: password(), argon: ArgonPreset.min);
    try {
      created.commit([write]);
    } finally {
      created.close();
    }
    expect(File(path).lengthSync(), greaterThanOrEqualTo(1024 * 1024));
  });

  test('explicit creation rejects invalid scalars before native allocations',
      () {
    final path = '${fixture.path}/refused.hv';
    expect(
        () => HvSpace.create(
            path: path,
            password: password(),
            padding: PaddingPreset.none,
            initialGarbageChunks: -1),
        throwsArgumentError);
    expect(
        () => HvSpace.create(
            path: path,
            password: password(),
            padding: PaddingPreset.none,
            superblockReplicas: 256),
        throwsArgumentError);
    expect(File(path).existsSync(), isFalse);
    final valid = HvSpace.create(
        path: path,
        password: password(),
        argon: ArgonPreset.min,
        padding: PaddingPreset.none);
    valid.close();
  });
}
