import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/hidden_volume.dart';

/// `outcomeOf` answers "what became of operation N" for the last 128 finished
/// operations. It used to answer with the operation's whole RESULT — so for a
/// read, the plaintext, kept alive for 128 more operations after the caller
/// was done with it (report14 HV14-M1). A count bound is not a bound on how
/// long a secret stays in memory, and `toString` interpolated the bytes on top
/// of that, so any diagnostic dump printed what had been read.
///
/// What is kept now is the SHAPE of the answer. The small scalars that
/// `outcomeOf` exists for — a commit sequence number, a bool — pass through
/// unchanged, because they are the answer and they are not secret.
void main() {
  test('a scalar answer is remembered as itself', () {
    // A commit_seq is what a caller who lost their reply comes back for.
    expect(const HvOpSucceeded(4711).value, 4711);
    expect(const HvOpSucceeded(true).value, isTrue);
    expect(const HvOpSucceeded(null).value, isNull);
  });

  test('a payload is described, never held', () {
    final read = Uint8List.fromList('the quiet part'.codeUnits);
    final kept = rememberableForTest(read);

    expect(
      kept,
      isNot(same(read)),
      reason: 'holding the very buffer is what kept plaintext alive',
    );
    expect(kept, isA<HvOpPayload>());
    final payload = kept! as HvOpPayload;
    expect(payload.length, read.length, reason: 'the shape is still useful');
    expect(
      '$payload',
      isNot(contains('quiet')),
      reason: 'a diagnostic dump of the ledger must not print what was read',
    );
    expect('$payload', isNot(contains('${read.first}')));
  });

  test('a string answer is described too', () {
    final kept = rememberableForTest('a record name nobody else should see');
    expect(kept, isA<HvOpPayload>());
    expect('$kept', isNot(contains('nobody')));
  });

  test('a list of results is described by its length', () {
    final kept = rememberableForTest(['one', 'two', 'three']);
    expect(kept, isA<HvOpPayload>());
    expect((kept! as HvOpPayload).length, 3);
    expect('$kept', isNot(contains('two')));
  });

  test('the outcome prints its stand-in, not its content', () {
    final outcome = HvOpSucceeded(
      rememberableForTest(Uint8List.fromList([1, 2, 3, 4])),
    );
    expect('$outcome', contains('HvOpPayload'));
    expect('$outcome', isNot(contains('[1, 2, 3, 4]')));
  });
}
