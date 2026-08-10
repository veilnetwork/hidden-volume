// The transport's own copies of a secret must be wiped (report9 HV-16).
//
// Rust owns its side: `decode_space_keys` takes the buffer by value and wraps
// it in `Zeroizing`, and every FFI entry point does the same for incoming
// passwords. None of that reaches the copies THIS side makes on the way in —
// a `calloc` buffer handed to `_rustbufferFromBytes`, and the framed
// `Uint8List` that `_bufferFromByteVec` builds first. Both used to be released
// as they were: one to the C allocator, one to the garbage collector.
//
// A source check, and the reason is the same one the memory audit gives for
// its own guards: proving a released buffer was scrubbed means reading it
// after release, which is undefined behaviour rather than a test. What can rot
// is the wiring, and that is a fact about the file.
//
// The ORDER assertion is the one worth having. A wipe that drifts below the
// `free` is not a weaker version of this fix — it is a write into memory the
// allocator has taken back.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Same resolution the checksum test uses: the suite is run from either the
/// plugin directory or the repository root.
File _bindingsSource() {
  final candidates = <String>[
    '${Directory.current.path}/lib/src/bindings.dart',
    '${Directory.current.path}/experimental/flutter_plugin/hidden_volume/lib/src/bindings.dart',
  ];
  for (final path in candidates) {
    final file = File(path);
    if (file.existsSync()) return file;
  }
  fail('bindings.dart not found relative to ${Directory.current.path}');
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

  test('the framed copy is wiped too', () {
    final body = _body(source, 'RustBuffer _bufferFromByteVec(');
    expect(
      body.contains('framed.fillRange(0, framed.length, 0)'),
      isTrue,
      reason: 'the length-prefixed copy this builds is a second copy of the '
          'secret, handed to the garbage collector as it is',
    );
  });
}
