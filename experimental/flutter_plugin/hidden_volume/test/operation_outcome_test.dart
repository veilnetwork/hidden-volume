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

  test('an outcome is filed before the worker answers, as pending',
      () async {
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
