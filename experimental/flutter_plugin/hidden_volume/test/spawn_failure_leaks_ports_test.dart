import 'dart:isolate';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/src/async_bindings.dart';

/// `Isolate.spawn` is the one step of an open that happens before anything is
/// watchable: the watcher's two ports and the bootstrap port already exist,
/// and the worker that would eventually close them was never started. Every
/// path BELOW the spawn cleans them up; the spawn's own failure did not.
///
/// A `ReceivePort` is a root — it keeps the event loop alive and is never
/// collected while open. So a caller retrying a failing open (a phone under
/// memory pressure, which is exactly when a spawn fails) accumulated three
/// live ports per attempt for the life of the process.
void main() {
  tearDown(() {
    HvAsyncSpace.debugSpawnFailure = null;
    HvAsyncSpace.debugOnSpawnStart = null;
  });

  test('a spawn that fails closes what it already opened', () async {
    HvWorkerDeath? death;
    ReceivePort? bootReply;
    HvAsyncSpace.debugOnSpawnStart = (d, b) {
      death = d;
      bootReply = b;
    };
    HvAsyncSpace.debugSpawnFailure = StateError('no isolate for you');

    await expectLater(
      HvAsyncSpace.open(
        path: '/definitely/not/used',
        password: Uint8List.fromList('pw'.codeUnits),
      ),
      throwsA(isA<StateError>()),
      reason: 'the failure itself must still reach the caller',
    );

    expect(death, isNotNull, reason: 'the seam never fired');

    // Nothing has listened to the bootstrap port on this path — the spawn
    // threw before the `first` that would have. A closed, empty port reports
    // empty; an open one never answers, hence the timeout.
    final bootClosed = await bootReply!.isEmpty
        .timeout(const Duration(seconds: 1), onTimeout: () => false);
    expect(bootClosed, isTrue, reason: 'the bootstrap port was left open');

    // The watcher's ports carry a listener from its constructor, so ask it
    // the way the runtime would: a closed port drops what is sent to it, an
    // open one still runs the listener and reports a death.
    death!.exitPort.sendPort.send('a late exit notice');
    final stillWatching = await death!.future
        .then<bool>((_) => true)
        .catchError((Object _) => true)
        .timeout(const Duration(seconds: 1), onTimeout: () => false);
    expect(
      stillWatching,
      isFalse,
      reason: "the watcher's ports were left open and it is still listening",
    );
  });
}
