// The transport's own copies of a secret must be wiped (report9 HV-16).
//
// Rust owns its side: `decode_space_keys` takes the buffer by value and wraps
// it in `Zeroizing`, and every FFI entry point does the same for incoming
// passwords. None of that reaches the copies THIS side makes on the way in —
// a `calloc` buffer handed to `_rustbufferFromBytes`, and the framed
// `Uint8List` that `_bufferFromByteVec` builds first. Both used to be released
// as they were: one to the C allocator, one to the garbage collector.
//
// The same leak runs INBOUND: `_bufferToBytes` copies a Rust-owned buffer out
// and hands it straight back to the Rust allocator, and `spaceKeys()` decodes
// 64 raw key bytes out of a framed temporary it then drops on the floor.
//
// A source check, and the reason is the same one the memory audit gives for
// its own guards: proving a released buffer was scrubbed means reading it
// after release, which is undefined behaviour rather than a test. What can rot
// is the wiring, and that is a fact about the file.
//
// The ORDER assertion is the one worth having. A wipe that drifts below the
// `free` is not a weaker version of this fix — it is a write into memory the
// allocator has taken back. Inbound, the other edge is just as real: a wipe
// that drifts ABOVE the copy hands the caller zeros.
//
// The source checks cannot tell a wipe of OUR copy from a wipe of the caller's
// buffer — both are a `fillRange`. So the runtime tests below assert the
// inverse: the caller's password survives, and the round-trip still opens.
// Those cannot pass vacuously, and no "the buffer reads as zero" test could
// promise either one.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/hidden_volume.dart';
// `overrideDylib` is a test seam, deliberately not on the public surface.
import 'package:hidden_volume/src/bindings.dart' show overrideDylib;

import 'test_dylib.dart';

/// Same resolution the checksum test uses: the suite is run from either the
/// plugin directory or the repository root.
File _bindingsSource() => _pluginSource('lib/src/bindings.dart');

File _asyncSource() => _pluginSource('lib/src/async_bindings.dart');

File _pluginSource(String relative) {
  final candidates = <String>[
    '${Directory.current.path}/$relative',
    '${Directory.current.path}/experimental/flutter_plugin/hidden_volume/'
        '$relative',
  ];
  for (final path in candidates) {
    final file = File(path);
    if (file.existsSync()) return file;
  }
  fail('$relative not found relative to ${Directory.current.path}');
}

/// The body of `name`, from its signature to the start of the next top-level
/// declaration.
String _body(String source, String name) {
  final start = source.indexOf(name);
  expect(start, isNot(-1), reason: '$name is gone — this guard watches it');
  final rest = source.substring(start + name.length);
  final end = rest.indexOf('\n}\n');
  return rest.substring(0, end == -1 ? rest.length : end);
}

void main() {
  final source = _bindingsSource().readAsStringSync();
  final asyncSource = _asyncSource().readAsStringSync();

  // ----------------------------------------------------------------
  // Outbound: Dart's own copies on the way into Rust
  // ----------------------------------------------------------------

  test('the calloc buffer is wiped, and before it is freed', () {
    final body = _body(source, 'RustBuffer _bufferFromBytes(');
    final wipe =
        body.indexOf('tmp.asTypedList(src.length).fillRange(0, src.length, 0)');
    final free = body.indexOf('calloc.free(tmp)');
    expect(
      wipe,
      isNot(-1),
      reason: 'the buffer carrying passwords and raw SpaceKeys into Rust is '
          'returned to the C allocator unwiped',
    );
    expect(free, isNot(-1), reason: 'the buffer is no longer freed at all');
    expect(
      wipe,
      lessThan(free),
      reason: 'the wipe sits below the free — that is a write into memory the '
          'allocator has already taken back, not a late scrub',
    );
  });

  test('the framed copy is wiped too, by the one owning helper', () {
    final helper = _body(source, 'RustBuffer _bufferFromOwnedSecret(');
    final handoff = helper.indexOf('_bufferFromBytes(owned)');
    final wipe = helper.indexOf('owned.fillRange(0, owned.length, 0)');
    expect(
      wipe,
      isNot(-1),
      reason: 'the encoded copy this builds is a second copy of the secret, '
          'handed to the garbage collector as it is',
    );
    expect(handoff, isNot(-1), reason: 'the helper no longer reaches Rust');
    expect(
      handoff,
      lessThan(wipe),
      reason: 'the wipe runs before Rust has copied the bytes — Rust would '
          'receive zeros',
    );
    expect(
      helper.contains('finally'),
      isTrue,
      reason: 'a throw on the way into Rust would skip the wipe',
    );
  });

  test('every outbound secret encoder goes through the owning helper', () {
    for (final fn in const <String>[
      'RustBuffer _bufferFromByteVec(',
      'RustBuffer _writeRotations(',
      'RustBuffer _writeBytesSequence(',
    ]) {
      expect(
        _body(source, fn).contains('_bufferFromOwnedSecret('),
        isTrue,
        reason: '$fn builds a blob of passwords and frees it unwiped',
      );
    }
  });

  // The single most dangerous line in this fix. `_Writer` builds on
  // `BytesBuilder(copy: false)`; `takeBytes()` on a single-chunk builder
  // returns that chunk BY REFERENCE, so `_bufferFromOwnedSecret` would wipe
  // the host app's live password instead of a copy of it. `toBytes()` always
  // copies. Nothing else in the file states this, and the swap is a one-word
  // edit that reads like a performance win.
  test('_Writer.toBytes copies — the owning helper depends on it', () {
    final writer = _body(source, 'class _Writer {');
    expect(
      writer.contains('Uint8List toBytes() => _b.toBytes();'),
      isTrue,
      reason: 'if this became `takeBytes()` the "owned" buffer would be the '
          "caller's own password, and _bufferFromOwnedSecret would wipe it",
    );
    expect(
      writer.contains('takeBytes'),
      isFalse,
      reason: 'takeBytes on BytesBuilder(copy: false) aliases the caller',
    );
  });

  // ----------------------------------------------------------------
  // Inbound: Rust's buffer and the framed temporary on the way out
  // ----------------------------------------------------------------

  test('the Rust buffer is wiped between the copy and the free', () {
    final body = _body(source, 'Uint8List _bufferToBytes(');
    final copy = body.indexOf('Uint8List.fromList(buf.data.asTypedList(');
    final wipe =
        body.indexOf('buf.data.asTypedList(buf.len).fillRange(0, buf.len, 0)');
    final free = body.indexOf('_freeBuffer(buf)');
    expect(copy, isNot(-1), reason: 'the copy out is gone');
    expect(
      wipe,
      isNot(-1),
      reason: 'plaintext and raw SpaceKeys go back to the Rust allocator '
          'unwiped',
    );
    expect(free, isNot(-1), reason: 'the buffer is no longer freed at all');
    expect(
      copy,
      lessThan(wipe),
      reason: 'the wipe runs before the copy — the caller receives zeros',
    );
    expect(
      wipe,
      lessThan(free),
      reason: 'the wipe sits below the free — a write into memory the '
          'allocator has already taken back',
    );
  });

  test('the framed SpaceKeys temporary is wiped after it is decoded', () {
    final body = _body(source, 'Uint8List _secretByteVecFrom(');
    final decode = body.indexOf('_Reader(framed).readByteVec()');
    final wipe = body.indexOf('framed.fillRange(0, framed.length, 0)');
    expect(decode, isNot(-1), reason: 'the decode is gone');
    expect(wipe, isNot(-1), reason: 'the frame goes to the GC holding the key');
    expect(
      decode,
      lessThan(wipe),
      reason: 'the wipe runs before the decode — the caller gets 64 zeros, '
          'which no source check would catch on its own',
    );
  });

  test('both spaceKeys exports use the wiping decoder', () {
    // The single-space export and the multi-space one. Neither may go back to
    // the raw two-step `_Reader(_bufferToBytes(out)).readByteVec()`, which
    // leaves the frame to the GC.
    for (final fn in const <String>[
      'Uint8List spaceKeys() {',
      'Uint8List spaceKeys(int id) {',
    ]) {
      final body = _body(source, fn);
      expect(
        body.contains('_secretByteVecFrom(out)'),
        isTrue,
        reason: '$fn decodes 64 raw key bytes out of a framed temporary and '
            'drops the frame unwiped',
      );
    }
  });

  // ----------------------------------------------------------------
  // Async: the worker's and the one-shot isolate's private clones
  // ----------------------------------------------------------------

  test('the one-shot isolates wipe their own password clones', () {
    for (final fn in const <String>[
      'void _changePasswordsEntry(',
      'void _compactKnownEntry(',
    ]) {
      final body = _body(asyncSource, fn);
      expect(
        body.contains('finally'),
        isTrue,
        reason: '$fn drops its private copy of every password on the floor',
      );
      expect(
        body.contains('fillRange(0,'),
        isTrue,
        reason: '$fn never wipes the clone Isolate.run handed it',
      );
    }
  });

  test('the worker isolate wipes its bootstrap password clone', () {
    final body = _body(asyncSource, 'void _workerEntry(');
    expect(
      body.contains('_wipeBootstrapPassword(config.bootstrap)'),
      isTrue,
      reason: 'the worker holds its clone of the unlock password for the '
          'whole life of the isolate',
    );
    expect(
      body.contains('finally'),
      isTrue,
      reason: 'a failed open would leave the clone behind — the case where a '
          'password is most likely to be retried and re-entered',
    );
    final helper = _body(asyncSource, 'void _wipeBootstrapPassword(');
    expect(
      helper.contains('pwd.fillRange(0, pwd.length, 0)'),
      isTrue,
      reason: 'the helper no longer wipes anything',
    );
  });

  // ----------------------------------------------------------------
  // Runtime: what the source checks cannot say
  // ----------------------------------------------------------------

  group('runtime', () {
    late String dylibPath;
    setUpAll(() {
      dylibPath = resolveDylibPath();
      // The async tests pass `dylibPath` to their worker; the sync one runs
      // in this isolate and needs the override here.
      overrideDylib(openTestDylib());
    });

    test("changePasswordsAsync leaves the CALLER's passwords intact", () async {
      final tmp = Directory.systemTemp.createTempSync('hv_wipe_');
      final path = '${tmp.path}/store.bin';
      addTearDown(() => tmp.deleteSync(recursive: true));

      final first = Uint8List.fromList('first-pwd'.codeUnits);
      final second = Uint8List.fromList('second-pwd'.codeUnits);
      final firstBefore = Uint8List.fromList(first);
      final secondBefore = Uint8List.fromList(second);

      final s = await HvAsyncSpace.create(
        path: path,
        password: first,
        argon: ArgonPreset.light,
        dylibPath: dylibPath,
      );
      await s.close();

      await changePasswordsAsync(
        path,
        [HvPasswordRotation(oldPwd: first, newPwd: second)],
        dylibPath: dylibPath,
      );

      // The wipes live in the CHILD isolate, on ITS deep copies. If one of
      // them ever moves into the synchronous `changePasswords` — or if Dart
      // stops copying the closure state — this is where it shows up, and the
      // host app finds its password zeroed under it.
      expect(first, firstBefore,
          reason: "the old password was wiped in the caller's isolate");
      expect(second, secondBefore,
          reason: "the new password was wiped in the caller's isolate");

      // ...and the rotation still took effect, so nothing was zeroed on the
      // way IN either.
      final reopened = await HvAsyncSpace.open(
        path: path,
        password: second,
        dylibPath: dylibPath,
      );
      addTearDown(reopened.close);
    });

    test("HvAsyncSpace.create leaves the CALLER's password intact", () async {
      final tmp = Directory.systemTemp.createTempSync('hv_wipe_');
      final path = '${tmp.path}/store.bin';
      addTearDown(() => tmp.deleteSync(recursive: true));

      final pwd = Uint8List.fromList('worker-pwd'.codeUnits);
      final before = Uint8List.fromList(pwd);

      final s = await HvAsyncSpace.create(
        path: path,
        password: pwd,
        argon: ArgonPreset.light,
        dylibPath: dylibPath,
      );
      await s.close();

      expect(pwd, before,
          reason: 'the worker wiped the spawn message it shares with the '
              'caller instead of its own copy');

      // The same buffer still unlocks the space it just created.
      final reopened = await HvAsyncSpace.open(
        path: path,
        password: pwd,
        dylibPath: dylibPath,
      );
      addTearDown(reopened.close);
    });

    test('spaceKeys survives the framed wipe and still opens the space', () {
      final tmp = Directory.systemTemp.createTempSync('hv_wipe_');
      final path = '${tmp.path}/store.bin';
      addTearDown(() => tmp.deleteSync(recursive: true));

      final space = HvSpace.create(
        path: path,
        password: Uint8List.fromList('keys-pwd'.codeUnits),
        argon: ArgonPreset.light,
      );
      space.commit([
        HvWriteOpPut(
          namespace: 1,
          key: Uint8List.fromList('k'.codeUnits),
          value: Uint8List.fromList('v'.codeUnits),
        ),
      ]);

      final keys = space.spaceKeys();
      final again = space.spaceKeys();
      space.close();

      expect(keys.length, 64);
      // A wipe that ran before the decode returns the right LENGTH and the
      // wrong bytes — the shape assertion alone would pass.
      expect(keys.any((b) => b != 0), isTrue,
          reason: 'the framed temporary was wiped before it was decoded');
      expect(again, keys, reason: 'two exports of one space disagree');

      // The one assertion that cannot be satisfied by a zeroed buffer.
      final reopened = HvSpace.openWithKeys(path: path, keys: keys);
      addTearDown(reopened.close);
      final v = reopened.get(1, Uint8List.fromList('k'.codeUnits));
      expect(String.fromCharCodes(v!), 'v');
    });
  });

  group('the dylib load is inside the wipe', () {
    late String source;

    setUpAll(() {
      source = File('lib/src/async_bindings.dart').readAsStringSync();
    });

    test('worker entry', () {
      _loaderIsUnderTheWipe(source, 'void _workerEntry(');
    });

    test('change-passwords entry', () {
      _loaderIsUnderTheWipe(source, 'void _changePasswordsEntry(');
    });

    test('compact-known entry', () {
      _loaderIsUnderTheWipe(source, 'void _compactKnownEntry(');
    });

    test('and each still HAS a wipe under it', () {
      // Vacuity guard: moving the loader below a try that wipes nothing
      // satisfies the order check and fixes nothing.
      for (final signature in const [
        'void _workerEntry(',
        'void _changePasswordsEntry(',
        'void _compactKnownEntry(',
      ]) {
        final body = _entryBody(source, signature);
        expect(
          body,
          anyOf(contains('fillRange('), contains('_wipeBootstrapPassword(')),
          reason: '$signature no longer wipes anything',
        );
      }
    });
  });
}

// ── report15 HV15-L1 — the wipe must cover the loader, not start after it ───
//
// Every one of the three isolate entry-points took an optional dylib path and
// opened it BEFORE its try/finally. `DynamicLibrary.open` throws on a path
// that is not a loadable library, and from above the try that took the isolate
// down with the password copies still in its heap — and, in the worker's case,
// with nothing sent back, so the parent learned of it as a death rather than
// as an answer.
//
// A source check for the reason the file's header gives: proving a dead
// isolate's heap was scrubbed means reading memory that no longer belongs to
// anybody. What can rot is the ORDER, and that is a fact about the file.

/// One entry-point's body, from its signature to the closing brace of its
/// `finally`.
String _entryBody(String source, String signature) {
  final at = source.indexOf(signature);
  expect(at, isNot(-1),
      reason: '$signature moved — this guard watches nothing');
  // To the function's own closing brace, which is the only `}` at column zero.
  // A fixed-size window was the first version: too small to reach one entry's
  // `finally`, and past the end of the file for the last one.
  final end = source.indexOf('\n}\n', at);
  expect(end, isNot(-1), reason: '$signature has no closing brace');
  return source.substring(at, end);
}

void _loaderIsUnderTheWipe(String source, String signature) {
  final body = _entryBody(source, signature);
  final tryAt = body.indexOf('try {');
  final openAt = body.indexOf('DynamicLibrary.open(');
  expect(tryAt, isNot(-1), reason: '$signature has no try block');
  expect(openAt, isNot(-1), reason: '$signature no longer loads a dylib');
  expect(
    tryAt,
    lessThan(openAt),
    reason:
        '$signature opens the dylib above its try/finally: a path that does '
        'not load throws past the wipe and leaves the passwords in the '
        "isolate's heap",
  );
}
