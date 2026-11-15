import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/hidden_volume.dart';
import 'package:hidden_volume/src/bindings.dart' show overrideDylib;

import 'test_dylib.dart';

Uint8List _bytes(String value) => Uint8List.fromList(value.codeUnits);

void main() {
  late Directory directory;
  late String path;
  late Uint8List oldKeys;
  final payload = Uint8List.fromList(List.generate(2048, (i) => i % 251));
  List<Uint8List> passwords() =>
      [_bytes('child-fixture'), _bytes('master-fixture')];

  Uint8List repair(String staged) {
    final child = HvSpace.open(path: staged, password: _bytes('child-fixture'));
    late Uint8List keys;
    try {
      keys = child.spaceKeys();
      expect(child.get(1, _bytes('body')), payload);
    } finally {
      child.close();
    }
    final master =
        HvSpace.open(path: staged, password: _bytes('master-fixture'));
    try {
      master.commit(
          [HvWriteOpPut(namespace: 1, key: _bytes('child'), value: keys)]);
    } finally {
      master.close();
    }
    return keys;
  }

  Uint8List verify() {
    final master = HvSpace.open(path: path, password: _bytes('master-fixture'));
    late Uint8List keys;
    try {
      keys = master.get(1, _bytes('child'))!;
    } finally {
      master.close();
    }
    final child = HvSpace.openWithKeys(path: path, keys: keys);
    try {
      expect(child.get(1, _bytes('body')), payload);
    } finally {
      child.close();
    }
    return keys;
  }

  setUpAll(() => overrideDylib(openTestDylib()));
  setUp(() {
    directory = Directory.systemTemp.createTempSync('hv_worker_prepared_');
    path = '${directory.path}/fixture.hv';
    final child = HvSpace.create(
        path: path, password: _bytes('child-fixture'), argon: ArgonPreset.min);
    try {
      oldKeys = child.spaceKeys();
      child.commit(
          [HvWriteOpPut(namespace: 1, key: _bytes('body'), value: payload)]);
    } finally {
      child.close();
    }
    final master =
        HvSpace.addSpace(path: path, password: _bytes('master-fixture'));
    try {
      master.commit(
          [HvWriteOpPut(namespace: 1, key: _bytes('child'), value: oldKeys)]);
    } finally {
      master.close();
    }
  });
  tearDown(() => directory.deleteSync(recursive: true));

  test('worker-local publication retains source until repaired commit', () {
    final before = File(path).readAsBytesSync();
    final credentials = passwords();
    final plan = HvPreparedCompaction.prepare(path, credentials);
    late Uint8List next;
    try {
      expect(File(path).readAsBytesSync(), before);
      expect(() => HvSpace.open(path: path, password: _bytes('child-fixture')),
          throwsA(isA<HvException>()));
      next = repair(plan.stagedPath);
      expect(next, isNot(oldKeys));
      expect(File(path).readAsBytesSync(), before);
      plan.commit();
      expect(plan.commit, throwsStateError);
    } finally {
      plan.close();
    }
    plan.close();
    expect(verify(), next);
    expect(credentials, passwords(), reason: 'caller buffers are not consumed');
    expect(directory.listSync(), hasLength(1));
  });

  test('closing an unpublished repaired plan restores no new source bytes', () {
    final before = File(path).readAsBytesSync();
    final plan = HvPreparedCompaction.prepare(path, passwords());
    try {
      repair(plan.stagedPath);
    } finally {
      plan.close();
    }
    plan.close();
    expect(plan.commit, throwsStateError);
    expect(File(path).readAsBytesSync(), before);
    expect(verify(), oldKeys);
    expect(directory.listSync(), hasLength(1));
  });

  test('failed preparation releases its capability and preserves credentials',
      () {
    final before = File(path).readAsBytesSync();
    final credentials = [_bytes('wrong-fixture')];
    expect(() => HvPreparedCompaction.prepare(path, credentials),
        throwsA(isA<HvException>()));
    expect(credentials.single, _bytes('wrong-fixture'));
    expect(File(path).readAsBytesSync(), before);
    expect(verify(), oldKeys);
    expect(directory.listSync(), hasLength(1));
  });

  test(
      'an open staged handle refuses commit and the consumed plan cannot retry',
      () {
    final before = File(path).readAsBytesSync();
    final plan = HvPreparedCompaction.prepare(path, passwords());
    final held =
        HvSpace.open(path: plan.stagedPath, password: _bytes('master-fixture'));
    try {
      expect(plan.commit, throwsA(isA<HvException>()));
      expect(plan.commit, throwsStateError);
    } finally {
      held.close();
      plan.close();
    }
    plan.close();
    expect(File(path).readAsBytesSync(), before);
    expect(verify(), oldKeys);
    expect(directory.listSync(), hasLength(1));
  });

  test('the owner cannot be copied into another isolate message', () {
    final port = ReceivePort();
    final plan = HvPreparedCompaction.prepare(path, passwords());
    try {
      expect(() => port.sendPort.send(plan), throwsArgumentError);
    } finally {
      plan.close();
      port.close();
    }
    expect(verify(), oldKeys);
  });
}
