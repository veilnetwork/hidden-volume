// Tests for the async wrapper in `lib/src/async_bindings.dart`.
//
// Worker isolates need an explicit dylib path to find the cdylib outside
// the OS standard search path during host testing — pass it via the
// `dylibPath:` arg on every async constructor. The resolver lives in
// `test/test_dylib.dart` so it picks the right extension for the host
// (`.dylib`/`.so`/`.dll`).

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/hidden_volume.dart';

import 'test_dylib.dart';

void main() {
  late String dylibPath;
  setUpAll(() {
    dylibPath = resolveDylibPath();
  });

  test('HvAsyncSpace.create → commit → get → close', () async {
    final tmp = Directory.systemTemp.createTempSync('hv_async_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final space = await HvAsyncSpace.create(
      path: path,
      password: Uint8List.fromList('async-pwd'.codeUnits),
      argon: ArgonPreset.light,
      dylibPath: dylibPath,
    );

    final seq = await space.commit([
      HvWriteOpPut(
        namespace: 1,
        key: Uint8List.fromList('k'.codeUnits),
        value: Uint8List.fromList('v'.codeUnits),
      ),
    ]);
    expect(seq, greaterThan(0));

    final v = await space.get(1, Uint8List.fromList('k'.codeUnits));
    expect(v, isNotNull);
    expect(String.fromCharCodes(v!), 'v');

    await space.close();
  });

  test('HvAsyncSpace serializes concurrent calls (no interleaving)',
      () async {
    final tmp = Directory.systemTemp.createTempSync('hv_async_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final space = await HvAsyncSpace.create(
      path: path,
      password: Uint8List.fromList('pw'.codeUnits),
      argon: ArgonPreset.light,
      dylibPath: dylibPath,
    );
    addTearDown(space.close);

    // Fire 20 concurrent commits + 20 concurrent reads. The worker
    // serializes via its receive-port queue; Rust mutex enforces the
    // single-Tx-per-Space invariant. All ops must succeed.
    final futures = <Future<void>>[];
    for (var i = 0; i < 20; i++) {
      futures.add(space.commit([
        HvWriteOpPut(
          namespace: 1,
          key: Uint8List.fromList('k$i'.codeUnits),
          value: Uint8List.fromList('v$i'.codeUnits),
        ),
      ]));
      futures.add(space
          .get(1, Uint8List.fromList('k$i'.codeUnits))
          .then((_) {}));
    }
    await Future.wait(futures);

    expect(await space.count(1), 20);
  });

  test('typed HvException propagates from worker', () async {
    final tmp = Directory.systemTemp.createTempSync('hv_async_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final s = await HvAsyncSpace.create(
      path: path,
      password: Uint8List.fromList('right'.codeUnits),
      argon: ArgonPreset.light,
      dylibPath: dylibPath,
    );
    await s.close();

    await expectLater(
      HvAsyncSpace.open(
        path: path,
        password: Uint8List.fromList('wrong'.codeUnits),
        dylibPath: dylibPath,
      ),
      throwsA(isA<HvException>()
          .having((e) => e.kind, 'kind', 'AuthFailed')),
    );
  });

  test('headerInfoAsync runs in a one-shot isolate', () async {
    final tmp = Directory.systemTemp.createTempSync('hv_async_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final s = await HvAsyncSpace.create(
      path: path,
      password: Uint8List.fromList('pwd'.codeUnits),
      argon: ArgonPreset.light,
      dylibPath: dylibPath,
    );
    await s.close();

    final hi = await headerInfoAsync(path, dylibPath: dylibPath);
    expect(hi.fileSizeBytes, greaterThan(0));
    expect(hi.argonMCostKib, 16 * 1024);
  });

  test('changePasswordsAsync rotates from one-shot isolate', () async {
    final tmp = Directory.systemTemp.createTempSync('hv_async_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final s1 = await HvAsyncSpace.create(
      path: path,
      password: Uint8List.fromList('first'.codeUnits),
      argon: ArgonPreset.light,
      dylibPath: dylibPath,
    );
    await s1.commit([
      HvWriteOpPut(
        namespace: 1,
        key: Uint8List.fromList('k'.codeUnits),
        value: Uint8List.fromList('v'.codeUnits),
      ),
    ]);
    await s1.close();

    await changePasswordsAsync(
      path,
      [
        HvPasswordRotation(
          oldPwd: Uint8List.fromList('first'.codeUnits),
          newPwd: Uint8List.fromList('second'.codeUnits),
        ),
      ],
      dylibPath: dylibPath,
    );

    await expectLater(
      HvAsyncSpace.open(
        path: path,
        password: Uint8List.fromList('first'.codeUnits),
        dylibPath: dylibPath,
      ),
      throwsA(isA<HvException>()),
    );

    final s2 = await HvAsyncSpace.open(
      path: path,
      password: Uint8List.fromList('second'.codeUnits),
      dylibPath: dylibPath,
    );
    addTearDown(s2.close);
    final v = await s2.get(1, Uint8List.fromList('k'.codeUnits));
    expect(String.fromCharCodes(v!), 'v');
  });

  test('post-close calls throw StateError', () async {
    final tmp = Directory.systemTemp.createTempSync('hv_async_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final s = await HvAsyncSpace.create(
      path: path,
      password: Uint8List.fromList('pwd'.codeUnits),
      argon: ArgonPreset.light,
      dylibPath: dylibPath,
    );
    await s.close();

    await expectLater(
      s.commit([]),
      throwsA(isA<StateError>()),
    );
  });
}
