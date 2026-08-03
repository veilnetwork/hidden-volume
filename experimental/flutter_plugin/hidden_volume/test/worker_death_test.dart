import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/src/async_bindings.dart';
import 'package:hidden_volume/src/bindings.dart';

import 'test_dylib.dart';

/// The async API runs the container in its own isolate, and every RPC used to
/// `await reply.first` with nothing watching that isolate. A worker that died
/// — an FFI fault, an uncaught error, an OOM kill — therefore left the
/// caller's future pending FOREVER, and every later call joined it.
/// `errorsAreFatal: true` makes the isolate die QUIETLY, so nothing surfaced
/// (audit HV-09).
void main() {
  late Directory tmp;

  setUpAll(() => overrideDylib(openTestDylib()));

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('hv09_');
  });
  tearDown(() async {
    if (tmp.existsSync()) await tmp.delete(recursive: true);
  });

  test('a worker that DIES is reported, not waited on forever', () async {
    // A real death, not an error reply. The worker loads its dylib before the
    // bootstrap `try`, so an unopenable path throws where nothing catches it
    // and `errorsAreFatal: true` takes the isolate down SILENTLY — which is
    // the case the old code could not see: `bootReply.first` simply never
    // completed (audit HV-09).
    //
    // A container that merely fails to open is NOT this case: the worker
    // catches that and replies with an error, which always worked.
    await expectLater(
      HvAsyncSpace.open(
        path: '${tmp.path}/store.bin',
        password: Uint8List.fromList('pw'.codeUnits),
        dylibPath: '${tmp.path}/no-such-library.dylib',
      ).timeout(const Duration(seconds: 15)),
      throwsA(anything),
      reason: 'a dead worker must surface, not leave the future pending',
    );
  });

  test('an ordinary open failure still replies with an error', () async {
    // The path that always worked, kept so the fix cannot be mistaken for it.
    final dir = Directory('${tmp.path}/not-a-file')..createSync();
    await expectLater(
      HvAsyncSpace.open(
        path: dir.path,
        password: Uint8List.fromList('pw'.codeUnits),
      ).timeout(const Duration(seconds: 15)),
      throwsA(anything),
    );
  });

  test('a healthy worker is unaffected by the watch', () async {
    // The race must not turn a working RPC into a failure — a supervisor that
    // breaks the happy path is worse than none.
    final space = await HvAsyncSpace.create(
      path: '${tmp.path}/store.bin',
      password: Uint8List.fromList('pw'.codeUnits),
      argon: ArgonPreset.light,
    );
    addTearDown(space.close);

    final key = Uint8List.fromList('k'.codeUnits);
    final value = Uint8List.fromList('v'.codeUnits);
    await space.commit([HvWriteOpPut(namespace: 1, key: key, value: value)]);
    expect(await space.get(1, key), value);
  });

  test('close is idempotent and leaves the space unusable', () async {
    final space = await HvAsyncSpace.create(
      path: '${tmp.path}/store2.bin',
      password: Uint8List.fromList('pw'.codeUnits),
      argon: ArgonPreset.light,
    );
    await space.close();
    await space.close(); // must not throw, must not hang
    expect(
      () => space.get(1, Uint8List.fromList('k'.codeUnits)),
      throwsA(isA<StateError>()),
    );
  });
}
