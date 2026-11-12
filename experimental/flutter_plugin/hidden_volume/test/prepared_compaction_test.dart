import 'dart:async';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/hidden_volume.dart';
import 'package:hidden_volume/src/bindings.dart' show overrideDylib;

import 'test_dylib.dart';

Uint8List bytes(String value) => Uint8List.fromList(value.codeUnits);

void main() {
  late String dylib;
  late Directory directory;
  late String path;
  late Uint8List oldKeys;
  final payload =
      Uint8List.fromList(List.generate(1024, (index) => index % 251));
  List<Uint8List> passwords() =>
      [bytes('child-fixture'), bytes('master-fixture')];

  Future<HvSpace> open(String target, String password) async => HvSpace.open(
        path: target,
        password: bytes(password),
      );

  Future<void> put(HvSpace space, String key, Uint8List value) async {
    space.commit([HvWriteOpPut(namespace: 1, key: bytes(key), value: value)]);
  }

  Future<Uint8List> repair(String staged) async {
    final child = await open(staged, 'child-fixture');
    late Uint8List keys;
    try {
      keys = child.spaceKeys();
      expect(child.get(1, bytes('body')), payload);
    } finally {
      child.close();
    }
    final master = await open(staged, 'master-fixture');
    try {
      await put(master, 'child', keys);
    } finally {
      master.close();
    }
    return keys;
  }

  Future<Uint8List> verify() async {
    final master = await open(path, 'master-fixture');
    late Uint8List reference;
    try {
      reference = (master.get(1, bytes('child')))!;
    } finally {
      master.close();
    }
    final child = HvSpace.openWithKeys(
      path: path,
      keys: reference,
    );
    try {
      expect(child.get(1, bytes('body')), payload);
    } finally {
      child.close();
    }
    return reference;
  }

  setUpAll(() {
    dylib = resolveDylibPath();
    overrideDylib(openTestDylib());
  });

  setUp(() async {
    directory = Directory.systemTemp.createTempSync('hv_prepared_');
    path = '${directory.path}/fixture.hv';
    final child = HvSpace.create(
      path: path,
      password: bytes('child-fixture'),
      argon: ArgonPreset.min,
    );
    try {
      oldKeys = child.spaceKeys();
      await put(child, 'body', payload);
    } finally {
      child.close();
    }
    final master = HvSpace.addSpace(
      path: path,
      password: bytes('master-fixture'),
    );
    try {
      await put(master, 'child', oldKeys);
    } finally {
      master.close();
    }
  });

  tearDown(() => directory.deleteSync(recursive: true));

  test('publication waits for authenticated repair and rotates references',
      () async {
    final before = File(path).readAsBytesSync();
    final entered = Completer<void>();
    final release = Completer<void>();
    // A callback may own isolate-unsendable application state. It must never
    // be captured by the worker closure along with its native owner.
    final port = ReceivePort();
    addTearDown(port.close);
    final credentials = passwords();
    final operation = compactKnownPreparedAsync(
      path,
      credentials,
      dylibPath: dylib,
      repairMetadata: (staged) async {
        expect(port.sendPort, isA<SendPort>());
        await repair(staged);
        entered.complete();
        await release.future;
      },
    );
    try {
      await entered.future;
      expect(File(path).readAsBytesSync(), before);
      await expectLater(
          open(path, 'master-fixture'), throwsA(isA<HvException>()));
    } finally {
      release.complete();
      await operation;
    }
    expect(await verify(), isNot(oldKeys));
    expect(credentials, passwords(), reason: 'caller-owned passwords survive');
    expect(directory.listSync().length, 1);
  });

  test('repair failure after metadata writes aborts and drains source lock',
      () async {
    final before = File(path).readAsBytesSync();
    await expectLater(
      compactKnownPreparedAsync(path, passwords(), dylibPath: dylib,
          repairMetadata: (staged) async {
        await repair(staged);
        throw StateError('fixture repair interrupted');
      }),
      throwsStateError,
    );
    expect(File(path).readAsBytesSync(), before);
    expect(await verify(), oldKeys);
    expect(directory.listSync().length, 1);
  });

  test('failed native preparation never enters host repair', () async {
    final before = File(path).readAsBytesSync();
    var repairs = 0;
    await expectLater(
      compactKnownPreparedAsync(path, [bytes('wrong-fixture')],
          dylibPath: dylib, repairMetadata: (_) async {
        repairs++;
      }),
      throwsA(isA<HvException>()),
    );
    expect(repairs, 0);
    expect(File(path).readAsBytesSync(), before);
    expect(await verify(), oldKeys);
    expect(directory.listSync().length, 1);
  });

  test('a staged handle still open at commit refuses publication', () async {
    final before = File(path).readAsBytesSync();
    HvSpace? held;
    try {
      await expectLater(
        compactKnownPreparedAsync(path, passwords(), dylibPath: dylib,
            repairMetadata: (staged) async {
          await repair(staged);
          held = await open(staged, 'master-fixture');
        }),
        throwsA(isA<HvException>()),
      );
    } finally {
      held?.close();
    }
    expect(File(path).readAsBytesSync(), before);
    expect(await verify(), oldKeys);
    expect(directory.listSync().length, 1);
  });
}
