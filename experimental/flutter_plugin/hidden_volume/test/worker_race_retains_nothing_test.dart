// Every RPC races the worker's death, and the race used to keep the answer.
//
// `Future.any([reply, death.future])` attaches a listener to BOTH futures and
// cancels neither. The reply wins and the caller gets its value — but the
// listener left on the shared, never-completed death future holds the closure
// over the completer that carries that value. For a read, the value is the
// plaintext. `dispose` deliberately leaves the death future uncompleted (a
// caller already holding it must still see a real death), so the pile was
// released only when a worker genuinely exited. Measured at roughly +46 MiB of
// RSS over 16k reads of 8 KiB (report14 HV14-H1).
//
// Retention is not directly observable from a Dart test — there is no forced
// GC, and a test that allocates until the collector notices is the kind of
// flaky the project has been bitten by before. So it is pinned from two sides
// instead:
//
//   * the mechanism, at the seam: a waiting operation IS registered, and the
//     registration goes away when it answers. Under the old racing helper
//     there is no registry at all, so "one waiting" reads zero and these fail;
//   * the shape, structurally: no race in this file may be built out of the
//     helper that cannot cancel.
//
// Neither alone would do. The first proves the new mechanism drains; the
// second proves nobody quietly went back to the old one.

import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/hidden_volume.dart';

void main() {
  test('an operation still waiting is registered, and answering removes it',
      () async {
    final death = HvWorkerDeath();
    addTearDown(death.dispose);

    expect(death.debugWaitingCount, 0, reason: 'nothing has been raced yet');

    final op = Completer<Object?>();
    final raced = death.race(op.future);
    expect(
      death.debugWaitingCount,
      1,
      reason: 'the race must hold its OWN registration — a helper that only '
          'listens on the death future leaves nothing here to remove, which '
          'is the whole of the leak',
    );

    op.complete('the answer');
    expect(await raced, 'the answer');
    expect(
      death.debugWaitingCount,
      0,
      reason: 'the answer was delivered, so nothing about this call may '
          'outlive it',
    );
  });

  test('an operation that fails is deregistered too', () async {
    final death = HvWorkerDeath();
    addTearDown(death.dispose);

    final op = Completer<Object?>();
    final raced = death.race(op.future);
    op.completeError(StateError('the core refused'));
    await expectLater(raced, throwsA(isA<StateError>()));
    expect(death.debugWaitingCount, 0);
  });

  test('a long run of answered operations accumulates nothing', () async {
    final death = HvWorkerDeath();
    addTearDown(death.dispose);

    // Sequential, the way a worker actually answers: one op in flight at a
    // time. What is under test is whether the finished ones let go.
    for (var i = 0; i < 2000; i++) {
      final op = Completer<Object?>();
      final raced = death.race(op.future);
      op.complete(List<int>.filled(1024, i & 0xff));
      await raced;
    }

    expect(
      death.debugWaitingCount,
      0,
      reason: '2000 answered reads left 2000 payloads reachable — this is the '
          'unbounded growth the finding is about',
    );
  });

  test('death answers everything still waiting, and clears the registry',
      () async {
    final death = HvWorkerDeath();
    addTearDown(death.dispose);

    final stuck = [for (var i = 0; i < 3; i++) Completer<Object?>()];
    final raced = [for (final c in stuck) death.race(c.future)];
    expect(death.debugWaitingCount, 3);

    // The worker exits. Its exit port is the real trigger, so the death runs
    // the way production reaches it rather than through a back door.
    death.exitPort.sendPort.send(null);

    for (final r in raced) {
      await expectLater(r, throwsA(isA<HvException>()));
    }
    expect(
      death.debugWaitingCount,
      0,
      reason: 'the registry is drained by the death, not left holding gates '
          'nobody will ever complete',
    );
  });

  test('racing after the worker is already dead does not register anything',
      () async {
    final death = HvWorkerDeath();
    addTearDown(death.dispose);
    death.exitPort.sendPort.send(null);
    // The death is delivered through a port listener, so let it land.
    await Future<void>.delayed(const Duration(milliseconds: 20));

    final raced = death.race(Completer<Object?>().future);
    await expectLater(raced, throwsA(isA<HvException>()));
    expect(
      death.debugWaitingCount,
      0,
      reason: 'an operation that can never be answered must not be filed as '
          'though it might be',
    );
  });

  test('no race in the bindings is built from the helper that cannot cancel',
      () {
    // A STRUCTURAL guard. The retention it prevents is invisible to a Dart
    // test, and the defect was not a wrong value but a listener nobody could
    // take back — so what is asserted is the construct itself. Comments are
    // stripped first: this file's own explanation names the helper.
    final source = File('lib/src/async_bindings.dart')
        .readAsStringSync()
        .split('\n')
        .where((l) => !l.trimLeft().startsWith('///'))
        .where((l) => !l.trimLeft().startsWith('//'))
        .join('\n');

    expect(
      source.contains('Future.any'),
      isFalse,
      reason: 'it attaches a listener to the shared death future and cancels '
          'none of them; each one holds the completer that carries the reply, '
          'and for a read that reply is the plaintext',
    );
    expect(
      source.contains('.race('),
      isTrue,
      reason: 'the assertion above is vacuous if nothing races the death at '
          'all — a dead worker would then hang its caller forever',
    );
  });
}
