import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/src/bindings.dart';

/// `_optU64` ALLOCATES: the `RustBuffer` it returns is native memory, and
/// native frees it only by consuming it in the call it was made for. Two
/// bounds in a row therefore meant the first buffer existed while the second
/// was still being validated — and a refusal there threw past the call, with
/// nobody left to free what had already been allocated (report14 HV14-L1).
///
/// The leak is native, so Dart cannot observe it: there is no counter to read
/// and no finalizer to catch. What CAN be checked is that the order is no
/// longer something a call site decides — both bounds are judged inside one
/// function, and the call sites use it.
void main() {
  test('both bounds are judged, whichever one is bad', () {
    expect(
      () => requireOptU64PairForTest(1, 'start', -1, 'end'),
      throwsA(isA<ArgumentError>()),
      reason: 'the SECOND bound is the one that used to be judged too late',
    );
    expect(
      () => requireOptU64PairForTest(-1, 'start', 1, 'end'),
      throwsA(isA<ArgumentError>()),
    );
    expect(
      () => requireOptU64PairForTest(null, 'start', null, 'end'),
      returnsNormally,
      reason: 'absent bounds are the ordinary case and must not be refused',
    );
    expect(
      () => requireOptU64PairForTest(0, 'start', 9, 'end'),
      returnsNormally,
    );
  });

  test('no call site allocates a bound buffer before judging the other', () {
    // A STRUCTURAL guard, because the leak it prevents is invisible from here.
    // What regresses is the SHAPE: two `_optU64` calls in a row, with a
    // validation between them that can throw.
    final src = File('lib/src/bindings.dart').readAsStringSync();
    final pairs = RegExp(r'_optU64\([^)]*\);\s*\n\s*final \w+ = _optU64\(')
        .allMatches(src);
    expect(
      pairs,
      isEmpty,
      reason: 'two bound buffers built one after the other is the window: the '
          'first is native memory nobody frees if the second refuses',
    );
    expect(
      src.contains('_optU64Pair('),
      isTrue,
      reason: 'the assertion above is vacuous if the bounds stopped being '
          'passed to native at all',
    );
  });
}
