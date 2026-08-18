// A close races the worker's death and kills it anyway (report8).
//
// `HvAsyncSpace.close` swallowed both the timeout and the worker's death,
// killed the isolate unconditionally and returned normally — so a container
// that had NOT closed reported a clean close, and lost its handle in the deal.
//
// The kill is the worse half. A worker that has not answered is almost
// certainly parked inside a synchronous FFI call, and **an isolate kill cannot
// unwind an FFI frame**: the native Drop never runs, the container's exclusive
// flock stays held by this process, and every later open fails Busy until the
// app restarts. That is the "correct password but won't unlock" trap.
//
// What is pinned here is the report and the survival, not the internals: after
// a close the worker never answers, the caller must be TOLD, and the worker
// must still be alive to finish releasing the container.
//
// A stub worker rather than a real one on purpose. A real worker cannot be
// parked inside an FFI frame on demand, and `close()` drains the in-flight call
// first, so there is no way to catch one mid-flight through the public API.

import 'dart:isolate';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/hidden_volume.dart';

/// The stub's isolate + serving port, kept aside so a test can prove the worker
/// outlived a timed-out close. Production holds no such handle by design.
({Isolate isolate, SendPort port, HvWorkerDeath watch})? _lastStub;

Future<void> _pumpUntil(bool Function() ready, String what) async {
  for (var i = 0; i < 400 && !ready(); i++) {
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
  expect(ready(), isTrue, reason: 'never reached: $what');
}

void main() {
  setUp(() {
    // The wait is what is under test; five real seconds per case is not.
    HvAsyncSpace.closeTimeout = const Duration(milliseconds: 150);
  });
  tearDown(() {
    HvAsyncSpace.closeTimeout = const Duration(seconds: 5);
    // A stub deliberately left running must not outlive its test. Stop
    // watching BEFORE the kill, or its exit is reported as a death nobody is
    // listening for, after the test has already finished.
    _lastStub?.watch.dispose();
    _lastStub?.isolate.kill(priority: Isolate.immediate);
    _lastStub = null;
  });

  test('a close the worker never answers is reported to the caller, and the '
      'worker is left ALIVE to finish releasing the container', () async {
    final events = ReceivePort();
    final seen = <String>[];
    events.listen((dynamic m) => seen.add('$m'));
    addTearDown(events.close);

    // A worker stuck the way a real one gets stuck: inside a long synchronous
    // FFI op, with our close queued behind it. It never answers.
    final live = await _spawnStubWorker(events.sendPort, answerClose: false);
    final space = HvAsyncSpace.debugOverWorker(
      isolate: live.isolate,
      toWorker: live.port,
      watch: live.watch,
    );

    await expectLater(
      space.close(),
      throwsA(isA<HvException>()),
      reason: 'the close timed out with the container lock still held, and '
          'the caller was handed a clean-close success anyway',
    );
    expect(seen, contains('close-requested'));

    // ...and the worker is STILL THERE. Killing it here is what strands the
    // native handle: the flock stays held by this process until it exits.
    seen.clear();
    _lastStub!.port.send(_Ping(events.sendPort));
    await _pumpUntil(
      () => seen.contains('call'),
      'the worker answering after the timeout (it was killed instead)',
    );
  });

  test('a worker that DIES mid-close is reported at once, not after the whole '
      'timeout', () async {
    // The wait used to swallow the death and return normally. `errorsAreFatal`
    // makes a crashed worker die QUIETLY, so watching the reply alone burns
    // the full timeout for an answer that can never arrive.
    HvAsyncSpace.closeTimeout = const Duration(seconds: 30);
    final events = ReceivePort();
    addTearDown(events.close);

    final live = await _spawnStubWorker(
      events.sendPort,
      answerClose: false,
      dieOnClose: true,
    );
    final space = HvAsyncSpace.debugOverWorker(
      isolate: live.isolate,
      toWorker: live.port,
      watch: live.watch,
    );

    final sw = Stopwatch()..start();
    await expectLater(space.close(), throwsA(isA<HvException>()));
    sw.stop();
    expect(
      sw.elapsed,
      lessThan(const Duration(seconds: 10)),
      reason:
          'the close sat on the reply alone while the worker was already dead',
    );
  });

  test('CONTROL: a worker that DOES answer its close is shut down cleanly, '
      'without throwing', () async {
    // If close threw on the happy path too, the report above would be noise
    // and every caller would learn to ignore it.
    final events = ReceivePort();
    final seen = <String>[];
    events.listen((dynamic m) => seen.add('$m'));
    addTearDown(events.close);

    final live = await _spawnStubWorker(events.sendPort, answerClose: true);
    final space = HvAsyncSpace.debugOverWorker(
      isolate: live.isolate,
      toWorker: live.port,
      watch: live.watch,
    );
    await space.close(); // must NOT throw
    expect(seen, contains('close-requested'));
  });

  test('a worker that ANSWERS its close with a failure is reported as a '
      'failure, not as a clean close', () async {
    // The reply is there, it is an object, and it says the container was not
    // released — the native `close` threw, the Rust handle was never dropped,
    // and the worker killed itself anyway so no finalizer will ever drop it.
    // `if (r != null)` read that as success and returned normally, which is
    // the "correct password but won't unlock" trap reported as a clean
    // teardown (report13 HV13-L2).
    final events = ReceivePort();
    final seen = <String>[];
    events.listen((dynamic m) => seen.add('$m'));
    addTearDown(events.close);

    final live = await _spawnStubWorker(
      events.sendPort,
      answerClose: true,
      failClose: true,
    );
    final space = HvAsyncSpace.debugOverWorker(
      isolate: live.isolate,
      toWorker: live.port,
      watch: live.watch,
    );

    await expectLater(
      space.close(),
      throwsA(isA<HvException>().having(
          (e) => e.message, 'message', contains('native close threw'))),
      reason: 'a close the worker refused was reported as a clean close',
    );
    expect(seen, contains('close-requested'));
    // Still idempotent, and the handle is still shut: a failure to release the
    // container is not a reason to keep accepting calls on it.
    await space.close();
    expect(() => space.commitSeq(), throwsA(isA<StateError>()));
  });

  test('close stays idempotent, and a failed close still closes the handle',
      () async {
    // The second call must not re-send, re-wait or re-throw: a caller that
    // retries a teardown is not asking to be told twice.
    final events = ReceivePort();
    addTearDown(events.close);

    final live = await _spawnStubWorker(events.sendPort, answerClose: false);
    final space = HvAsyncSpace.debugOverWorker(
      isolate: live.isolate,
      toWorker: live.port,
      watch: live.watch,
    );
    await expectLater(space.close(), throwsA(isA<HvException>()));
    await space.close(); // must not throw, must not hang
    expect(
      () => space.commitSeq(),
      throwsA(isA<StateError>()),
      reason: 'a close that reported a failure still closed the handle',
    );
  });
}

class _Ping {
  const _Ping(this.reply);
  final SendPort reply;
}

Future<({Isolate isolate, SendPort port, HvWorkerDeath watch})>
    _spawnStubWorker(
  SendPort events, {
  required bool answerClose,
  bool dieOnClose = false,
  bool failClose = false,
}) async {
  final boot = ReceivePort();
  final death = HvWorkerDeath();
  final isolate = await Isolate.spawn<List<Object>>(
    _stubWorkerEntry,
    [boot.sendPort, events, answerClose, dieOnClose, failClose],
    errorsAreFatal: true,
    onExit: death.exitPort.sendPort,
    onError: death.errorPort.sendPort,
  );
  final port = await boot.first as SendPort;
  boot.close();
  _lastStub = (isolate: isolate, port: port, watch: death);
  return (isolate: isolate, port: port, watch: death);
}

void _stubWorkerEntry(List<Object> args) {
  final boot = args[0] as SendPort;
  final events = args[1] as SendPort;
  final answerClose = args[2] as bool;
  final dieOnClose = args[3] as bool;
  final failClose = args[4] as bool;
  final rx = ReceivePort();
  boot.send(rx.sendPort);
  rx.listen((dynamic msg) {
    // `reply` is a public field on the (library-private) request classes, so
    // it is reachable dynamically without importing them.
    final reply = (msg as dynamic).reply as SendPort;
    if (msg.runtimeType.toString().contains('Close')) {
      events.send('close-requested');
      if (dieOnClose) {
        // A worker that faults on the way out: quietly gone, no reply ever.
        rx.close();
        Isolate.current.kill(priority: Isolate.immediate);
        return;
      }
      if (!answerClose) return; // still inside the FFI, like the real thing
      // The reply the REAL worker sends, not a convenient truthy stand-in:
      // `close` matches on the type now, and the whole point of the match is
      // that the failure reply below is a different one.
      reply.send(failClose
          ? HvAsyncSpace.debugCloseError('Internal', 'native close threw')
          : HvAsyncSpace.debugCloseOk());
      rx.close();
      Isolate.current.kill(priority: Isolate.immediate);
      return;
    }
    events.send('call');
    reply.send(HvAsyncSpace.debugCloseOk());
  });
}
