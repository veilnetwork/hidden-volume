// A caller that stops waiting must still be able to learn what
// happened (audit HV-07).
//
// Dart futures do not cancel. `space.commit(ops).timeout(...)` stops
// the CALLER waiting and nothing else: the worker finishes the call and
// answers into a reply port nobody reads. Before HV-07 that answer was
// dropped, so a host whose write timed out could not tell a landed
// commit from a lost one — on a deniable store, where the alternative
// to knowing is to guess and possibly apply the write twice.
//
// The Rust FFI has a ledger for exactly this
// (`AsyncSpaceHandle::abandoned_operations`), but it hangs off the
// ASYNC handle and these hand-written bindings bind only the sync
// symbols; the worker isolate holds a `SpaceHandleBindings`. So it was
// unreachable from Dart, and `outcomeOf` is its Dart-side counterpart.
//
// Worker isolates need an explicit dylib path during host testing —
// see `test/test_dylib.dart`.

import 'dart:async';
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

  Future<HvAsyncSpace> makeSpace() async {
    final tmp = Directory.systemTemp.createTempSync('hv_opid_');
    addTearDown(() => tmp.deleteSync(recursive: true));
    return HvAsyncSpace.create(
      path: '${tmp.path}/store.bin',
      password: Uint8List.fromList('op-id-pw'.codeUnits),
      argon: ArgonPreset.light,
      dylibPath: dylibPath,
    );
  }

  HvWriteOp put(String k, String v) => HvWriteOpPut(
        namespace: 1,
        key: Uint8List.fromList(k.codeUnits),
        value: Uint8List.fromList(v.codeUnits),
      );

  test('an abandoned commit still files its outcome', () async {
    final space = await makeSpace();
    addTearDown(space.close);

    final op = space.commitOperation([put('k', 'v')]);

    // Walk away from the future the way a `.timeout` would: never await
    // it. `unawaited` is not enough on its own — the outcome has to be
    // recorded by the call itself, not by whoever is listening, which
    // is the whole of the fix.
    unawaited(op.result);

    // Give the worker room to finish. Polling rather than a fixed
    // sleep so the test is not a race on a slow host.
    HvOpOutcome outcome = space.outcomeOf(op.id);
    for (var i = 0; i < 200 && outcome is HvOpPending; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 10));
      outcome = space.outcomeOf(op.id);
    }

    expect(outcome, isA<HvOpSucceeded>(),
        reason: 'the abandoned commit left no record of what it did');
    expect((outcome as HvOpSucceeded).value, isA<int>(),
        reason: 'the recorded value is not the commit_seq the call returns');

    // And the write really did land, so the record is not merely
    // optimistic.
    final v = await space.get(1, Uint8List.fromList('k'.codeUnits));
    expect(v, isNotNull);
    expect(String.fromCharCodes(v!), 'v');
  });

  test('a timed-out commit is answerable afterwards', () async {
    final space = await makeSpace();
    addTearDown(space.close);

    final op = space.commitOperation([put('t', 'timeout')]);

    // A zero-length timeout always fires before the worker can answer,
    // which is the caller-side shape of the finding without depending
    // on how fast the host is.
    await expectLater(
      op.result.timeout(Duration.zero),
      throwsA(isA<TimeoutException>()),
    );

    HvOpOutcome outcome = space.outcomeOf(op.id);
    for (var i = 0; i < 200 && outcome is HvOpPending; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 10));
      outcome = space.outcomeOf(op.id);
    }
    expect(outcome, isA<HvOpSucceeded>(),
        reason: 'after a timeout the caller still cannot tell what happened');
  });

  test('a rejected operation is recorded as failed, not as succeeded',
      () async {
    final space = await makeSpace();
    addTearDown(space.close);

    // Namespace 0 is reserved; the Rust side rejects this before it
    // writes anything.
    final op = space.commitOperation([
      HvWriteOpPut(
        namespace: 0,
        key: Uint8List.fromList('k'.codeUnits),
        value: Uint8List.fromList('v'.codeUnits),
      ),
    ]);
    await expectLater(op.result, throwsA(isA<HvException>()));

    final outcome = space.outcomeOf(op.id);
    expect(outcome, isA<HvOpFailed>(),
        reason: 'a rejection has to be distinguishable from a success');
  });

  test('a worker that DIES under a call is indeterminate, not failed',
      () async {
    // report7 P2. Both a refusal and a death end with the caller's future
    // throwing an HvException, and until now both filed HvOpFailed —
    // whose contract said "nothing was committed; safe to retry". For a
    // dead worker that is an assertion nobody is in a position to make:
    // the isolate can die AFTER the native commit reaches the disk and
    // BEFORE its reply is sent, and from Dart the two are
    // indistinguishable, because what would tell them apart is the reply
    // that never came.
    final space = await makeSpace();
    // This test deliberately leaves a DEAD worker behind, and closing over
    // one now throws (report8): the isolate was killed where an FFI frame
    // may still have been open, so nothing here can claim the native handle
    // was released. That report is the point of the change; swallowing it is
    // right for a teardown and wrong for anywhere else.
    addTearDown(() async {
      try {
        await space.close();
      } on HvException catch (_) {
        // Expected: the worker is already gone.
      }
    });

    // A real kill, not `close()`. `close()` drains the in-flight call
    // first, so a call cannot be caught mid-flight through it — the first
    // draft of this test used it and watched the commit SUCCEED, which is
    // the opposite of the situation under test.
    final op = space.commitOperation([put('k', 'v')]);
    space.debugKillWorker();

    await expectLater(op.result, throwsA(isA<HvException>()));

    final outcome = space.outcomeOf(op.id);
    expect(
      outcome,
      isA<HvOpIndeterminate>(),
      reason: 'the worker died under this call, so whether the commit '
          'landed is unknown — filing it as HvOpFailed tells the caller '
          '"nothing was committed", which nobody here can know. Got: $outcome',
    );
    // And explicitly NOT the variant whose contract promises no effect.
    expect(outcome, isNot(isA<HvOpFailed>()));
  });

  test('a REFUSAL is still HvOpFailed, so the split is a split', () async {
    // The control for the test above. If both a refusal and a death came
    // back indeterminate, the new variant would have replaced the old one
    // rather than divided it, and every ordinary rejection would have lost
    // its "nothing was committed" guarantee — a strictly worse answer than
    // the one being fixed.
    final space = await makeSpace();
    addTearDown(space.close);

    // Namespace 0 is reserved; the worker is alive, runs the call, and the
    // core refuses before writing anything.
    final op = space.commitOperation([
      HvWriteOpPut(
        namespace: 0,
        key: Uint8List.fromList('k'.codeUnits),
        value: Uint8List.fromList('v'.codeUnits),
      ),
    ]);
    await expectLater(op.result, throwsA(isA<HvException>()));

    final outcome = space.outcomeOf(op.id);
    expect(outcome, isA<HvOpFailed>());
    expect(outcome, isNot(isA<HvOpIndeterminate>()),
        reason: 'a worker that answered is not a worker that vanished');
  });

  test('a refusal that MAY have applied does not claim it did not', () {
    // report8 H-09. `HvOpFailed` used to promise, of every kind, that
    // "nothing was committed, so the operation is safe to retry" — while
    // `docs/{en,ru}/security/audits/fsync.md` said a caller "should NOT
    // retry the same Tx without first re-opening the container". The core
    // settles it: a commit whose Superblock publish fails answers
    // `PublishUncertain`, which exists to say a replica may already be on
    // the disk. That arrives as an error reply from a LIVE worker, so it
    // is an `HvOpFailed` — the one variant that promised the opposite.
    final publishUncertain = HvOpFailed(
      HvException('PublishUncertain', 'reopen before committing'),
    );
    expect(publishUncertain.mayHaveApplied, isTrue,
        reason: 'a burnt seq with a replica possibly on disk was reported '
            'as "nothing was committed"');

    // The rewrite kinds are the other half: the rename HAPPENED, so the
    // new passwords are already in effect and retrying with the old one
    // is wrong.
    for (final kind in const [
      'RenameVisibleDurabilityUncertain',
      'RenameVisibleContentUnverified',
      // report16 HV16-M3. The rewrite applied at the name it was given; what
      // is qualified is that another name still resolves to the old file. A
      // caller reading it as "nothing happened" retries with the old
      // password, which no longer opens the name it just rotated.
      'RenameVisibleAliasesNotRevoked',
    ]) {
      expect(HvOpFailed(HvException(kind, '')).mayHaveApplied, isTrue,
          reason: '$kind means the rewrite applied');
    }

    // ...and the split has to stay a split. If every refusal answered
    // "may have applied", the flag would be a constant and every
    // ordinary rejection would lose the guarantee it really does carry.
    for (final kind in const [
      'WrongNamespaceKind',
      'AuthFailed',
      'ReadOnly',
      'PayloadTooLarge',
      'UnreadableNewerState',
      // report16 HV16-H2. The one kind that looks like its neighbours and is
      // not: the path is a symlink or otherwise not a plain file, and the
      // rewrite is refused before anything is opened.
      'SourceIsNotARegularFile',
    ]) {
      expect(HvOpFailed(HvException(kind, '')).mayHaveApplied, isFalse,
          reason: '$kind is refused before a byte is written');
    }
  });

  test('every kind that may have applied is a kind that can actually arrive',
      () {
    // The predicate matches on a STRING. A kind that is misspelled, or
    // one the Rust side renamed, makes `mayHaveApplied` silently
    // always-false for it — the flag is still there, still read, and
    // never true again. Pin it against the ordinal table the lifter
    // actually produces names from.
    //
    // Read the REAL set, not a list of the same names written out here.
    // The first draft of this test did the latter and a deliberately
    // misspelled entry sailed through it: all that proved was that the
    // test's own copy was spelled correctly.
    final unliftable =
        debugKindsThatMayHaveApplied().difference(debugKnownErrorKinds());
    expect(unliftable, isEmpty,
        reason: 'no error can ever be lifted with these kinds, so naming '
            'them is dead code that reads as a live guarantee: $unliftable');
    // And the set is not empty, or the check above passes vacuously.
    expect(debugKindsThatMayHaveApplied(), contains('PublishUncertain'));
  });

  test('a live refusal from the core is answerable through mayHaveApplied',
      () async {
    // The decision at the CALL SITE, not the predicate next to it: an
    // outcome taken off a real worker, through the real reply path, must
    // carry the flag — a getter that only works on hand-built values is
    // a getter no caller can use.
    final space = await makeSpace();
    addTearDown(space.close);

    // Namespace 0 is reserved; the core refuses before writing anything.
    final op = space.commitOperation([
      HvWriteOpPut(
        namespace: 0,
        key: Uint8List.fromList('k'.codeUnits),
        value: Uint8List.fromList('v'.codeUnits),
      ),
    ]);
    await expectLater(op.result, throwsA(isA<HvException>()));

    final outcome = space.outcomeOf(op.id);
    expect(outcome, isA<HvOpFailed>());
    expect((outcome as HvOpFailed).mayHaveApplied, isFalse,
        reason: 'a pre-write rejection really did nothing, and saying '
            'otherwise would make the flag useless in the other direction');
  });

  test('ids are monotonic and an unissued id is unknown, not pending',
      () async {
    final space = await makeSpace();
    addTearDown(space.close);

    final a = space.commitOperation([put('a', '1')]);
    final b = space.commitOperation([put('b', '2')]);
    expect(b.id, greaterThan(a.id),
        reason: 'ids must order, or a caller cannot tell two calls apart');
    await a.result;
    await b.result;

    // "Never issued" must not read as "still running": a caller that
    // cannot tell those apart is back to guessing, which is the state
    // this getter exists to end.
    expect(space.outcomeOf(b.id + 1000), isA<HvOpUnknown>());
    expect(space.outcomeOf(0), isA<HvOpUnknown>(),
        reason: '0 is never issued, so it must not resolve to an outcome');
  });

  test('a LIVE operation is not evicted by the ones submitted after it',
      () async {
    final space = await makeSpace();
    addTearDown(space.close);

    // Submitted in one turn, so the worker — which serves one call at a time
    // — has answered none of them: 200 genuinely in-flight operations, past
    // the 128 the outcome map holds.
    //
    // One map for both states meant the 129th submission dropped the first
    // one WHILE IT WAS RUNNING, and `outcomeOf` then answered Unknown — "an
    // id this handle never issued" — for a commit the worker was in the
    // middle of. A caller reading that is back to guessing whether the write
    // landed, which is the one question this getter exists to answer
    // (report13 HV13-L7).
    final ops = [
      for (var i = 0; i < 200; i++) space.commitOperation([put('k$i', 'v$i')])
    ];
    for (final op in ops) {
      expect(space.outcomeOf(op.id), isA<HvOpPending>(),
          reason: 'operation ${op.id} is still running and reads as evicted');
    }

    for (final op in ops) {
      await op.result;
    }

    // And the finished half is still bounded — the fix separates the two, it
    // does not make either unbounded.
    expect(space.outcomeOf(ops.last.id), isA<HvOpSucceeded>());
    expect(space.outcomeOf(ops.first.id), isA<HvOpUnknown>(),
        reason: 'the terminal history keeps 128, so the oldest of 200 '
            'completions must have aged out');
  });

  test('an outcome is filed before the worker answers, as pending', () async {
    final space = await makeSpace();
    addTearDown(space.close);

    // Read the outcome synchronously, in the same turn as the submit —
    // the worker cannot possibly have answered yet. The id has to be
    // usable from this moment, because a caller that only learns it
    // after awaiting has learnt it in the one case that never needed
    // it.
    final op = space.commitOperation([put('p', '1')]);
    expect(space.outcomeOf(op.id), isA<HvOpPending>());

    await op.result;
    expect(space.outcomeOf(op.id), isA<HvOpSucceeded>());
  });
}
