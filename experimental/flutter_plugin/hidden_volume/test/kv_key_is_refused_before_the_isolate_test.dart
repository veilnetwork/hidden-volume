import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
// The guard lives beside the other request validators, which are package-
// internal — the test reaches them the same way the plugin's own code does.
import 'package:hidden_volume/src/bindings.dart';

/// A worker takes its requests through a `SendPort`, and a `SendPort` COPIES
/// what it is given. The key of a `get` was never checked on this side, and it
/// weighs nothing against the in-flight byte budget — that budget weighs commit
/// payloads, and a read carries none. So a caller could hand over megabytes per
/// request and have as many of them copied into the worker as the in-flight
/// ceiling allows, every one to be refused by the core afterwards for being too
/// long (report14 HV14-M3).
///
/// Refusing on this side costs nothing and says the same thing.
void main() {
  Uint8List key(int n) => Uint8List(n)..fillRange(0, n, 0x41);

  test('an ordinary key passes', () {
    final k = key(32);
    expect(requireKvKey(k, 'key'), same(k));
    // The boundary itself is usable: the core accepts it, so this must too.
    expect(() => requireKvKey(key(maxKeyLen), 'key'), returnsNormally);
  });

  test('a key past what the core accepts is refused here', () {
    expect(
      () => requireKvKey(key(maxKeyLen + 1), 'key'),
      throwsA(isA<ArgumentError>()),
      reason: 'one byte past the limit is still a request that cannot succeed',
    );
    expect(
      () => requireKvKey(key(4 * 1024 * 1024), 'key'),
      throwsA(isA<ArgumentError>()),
      reason: 'and this is the size that made it a memory amplifier',
    );
  });

  test('an empty key is refused, as the core refuses it', () {
    expect(
        () => requireKvKey(Uint8List(0), 'key'), throwsA(isA<ArgumentError>()));
  });

  test('the error names the parameter and the limit', () {
    try {
      requireKvKey(key(maxKeyLen + 1), 'key');
      fail('expected a refusal');
    } on ArgumentError catch (e) {
      expect('$e', contains('key'));
      expect('$e', contains('$maxKeyLen'));
    }
  });

  test('the limit mirrors the core', () {
    // `MAX_KEY_LEN` in space/index.rs. If the core moves, this must move with
    // it — a preflight that refuses what the core accepts is a bug of its own.
    expect(maxKeyLen, 256);
  });
}
