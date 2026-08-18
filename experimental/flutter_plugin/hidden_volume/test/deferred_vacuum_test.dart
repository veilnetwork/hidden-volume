// The post-open scrub the constant-time unlock defers, and the plugin's
// scheduling of it (audit HV-01).
//
// `HvSpace.open` goes through `SpaceHandle::open`, which takes the
// constant-time scan — the FFI is the deniability app's surface, so every
// app unlock lands there. That scan equalizes so its duration cannot say
// whether a password matched, and it used to vacuum inline right
// afterwards: milliseconds and disk writes proportional to the space's
// history, on the success path only. Rust moved the scrub out; this side
// has to actually run it, and to run it somewhere other than immediately
// after the unlock, or the same duration just moves right and stays
// correlated with success.
//
// So both halves are pinned:
//
//   1. the unlock itself does not reclaim, and
//   2. the armed timer does — and it is armed at a random offset rather
//      than at zero.

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/hidden_volume.dart';
import 'package:hidden_volume/src/bindings.dart';

import 'test_dylib.dart';

/// A window that fires almost immediately, so a test does not wait out the
/// production delay. The point under test is that the delay exists and is
/// drawn from the window, not its magnitude.
const _fast = DeferredVacuumWindow(
  Duration(milliseconds: 30),
  Duration(milliseconds: 60),
);

/// Never fires within a test: used to prove the unlock left the scrub
/// undone rather than having quietly done it.
const _never =
    DeferredVacuumWindow(Duration(minutes: 10), Duration(minutes: 10));

/// Wider than the sampler can draw from: `Random.nextInt` takes a bound of
/// at most 2^32, so a 50-day span is one it refuses (audit HV13-M2).
const _tooWide = DeferredVacuumWindow(Duration.zero, Duration(days: 50));

/// A window in the past. `Timer` treats a negative delay as zero and fires
/// on the next turn of the event loop, which puts the scrub back on the
/// unlock — the correlation the deferral exists to break.
const _inThePast =
    DeferredVacuumWindow(Duration(seconds: -5), Duration(seconds: -1));

Uint8List _pw(String s) => Uint8List.fromList(s.codeUnits);

/// A container that owes a scrub: 20 entries written, then deleted. The
/// delete only unlinks; the index chunks holding the old values stay on
/// disk and stay decryptable with the password.
String _containerOwingAScrub(Directory tmp) {
  final path = '${tmp.path}/store.bin';
  final space = SpaceHandleBindings.create(
    path: path,
    password: _pw('pwd'),
    argon: ArgonPreset.light,
  );
  space.commit([
    for (var i = 0; i < 20; i++)
      HvWriteOpPut(
        namespace: 1,
        key: _pw('k$i'),
        value: _pw('v$i'),
      ),
  ]);
  space.commit([
    for (var i = 0; i < 20; i++) HvWriteOpDelete(namespace: 1, key: _pw('k$i')),
  ]);
  space.close();
  return path;
}

void main() {
  setUpAll(() {
    overrideDylib(openTestDylib());
  });

  test('the unlock leaves the scrub undone; the armed timer performs it',
      () async {
    final tmp = Directory.systemTemp.createTempSync('hv_dart_defer_');
    addTearDown(() => tmp.deleteSync(recursive: true));
    final path = _containerOwingAScrub(tmp);

    // Half one. Nothing may have been reclaimed by the open itself, so an
    // explicit scrub right now still finds work. If the open had vacuumed
    // inline — the finding — this would be 0.
    final probe = HvSpace.open(path: path, password: _pw('pwd'),
        vacuumWindow: _never);
    final owed = probe.vacuumAfterOpen();
    probe.close();
    expect(
      owed,
      greaterThan(0),
      reason: 'the constant-time unlock reclaimed the orphans inline, which '
          'is the leak: the work only happens when the password was right, '
          'and its duration tracks how much history the space has',
    );

    // Half two, stated positively: with a real (short) window armed, the
    // scrub happens on its own. Without this, "the open does not vacuum"
    // would be satisfied by never vacuuming at all.
    final tmp2 = Directory.systemTemp.createTempSync('hv_dart_defer2_');
    addTearDown(() => tmp2.deleteSync(recursive: true));
    final path2 = _containerOwingAScrub(tmp2);
    final space =
        HvSpace.open(path: path2, password: _pw('pwd'), vacuumWindow: _fast);
    expect(space.pendingVacuumDelay, isNotNull,
        reason: 'open must arm the deferred scrub');

    // Counted in owned chunks rather than in the return value, so a
    // `vacuum_after_open` that answered 0 without doing anything would
    // fail here too.
    final ownedBefore = space.stats().ownedChunkCount;
    await Future<void>.delayed(const Duration(milliseconds: 400));
    expect(space.pendingVacuumDelay, isNull, reason: 'the timer must have run');
    expect(
      space.stats().ownedChunkCount,
      lessThan(ownedBefore),
      reason: 'the armed scrub never reclaimed anything: forward secrecy '
          'after a constant-time unlock is now simply gone rather than '
          'deferred, and every deleted value stays readable to whoever '
          'later obtains the password',
    );
    expect(space.vacuumAfterOpen(), 0, reason: 'nothing should be left owed');
    space.close();
  });

  test('the delay is drawn from the window, and is never zero', () {
    final tmp = Directory.systemTemp.createTempSync('hv_dart_window_');
    addTearDown(() => tmp.deleteSync(recursive: true));
    final path = _containerOwingAScrub(tmp);

    final space =
        HvSpace.open(path: path, password: _pw('pwd'), vacuumWindow: _never);
    addTearDown(space.close);

    // A fixed seed makes the assertion about the WINDOW, not about luck.
    for (var seed = 0; seed < 25; seed++) {
      final d = space.scheduleDeferredVacuum(
        window: const DeferredVacuumWindow(
          Duration(seconds: 30),
          Duration(minutes: 5),
        ),
        random: Random(seed),
      );
      expect(d, greaterThanOrEqualTo(const Duration(seconds: 30)),
          reason: 'a scrub adjacent to the unlock is the finding, not the fix');
      expect(d, lessThanOrEqualTo(const Duration(minutes: 5)));
    }

    // The default window the plugin arms is the same shape.
    expect(DeferredVacuumWindow.standard.min, const Duration(seconds: 30));
    expect(DeferredVacuumWindow.standard.max, const Duration(minutes: 5));
  });

  test('re-arming replaces the pending scrub and close cancels it', () async {
    final tmp = Directory.systemTemp.createTempSync('hv_dart_cancel_');
    addTearDown(() => tmp.deleteSync(recursive: true));
    final path = _containerOwingAScrub(tmp);

    final space =
        HvSpace.open(path: path, password: _pw('pwd'), vacuumWindow: _never);
    expect(space.pendingVacuumDelay, const Duration(minutes: 10));

    space.scheduleDeferredVacuum(window: _fast);
    expect(space.pendingVacuumDelay, lessThan(const Duration(seconds: 1)),
        reason: 're-arming must replace the pending timer, not add one');

    space.cancelDeferredVacuum();
    expect(space.pendingVacuumDelay, isNull);

    // A timer surviving close would fire against a freed handle.
    space.scheduleDeferredVacuum(window: _fast);
    space.close();
    expect(space.pendingVacuumDelay, isNull);
    await Future<void>.delayed(const Duration(milliseconds: 200));
  });

  test('a window the sampler cannot serve is refused with nothing held',
      () async {
    // The finding is not the throw, it is WHEN it happened: the arming ran
    // after the container was open, so a window `pick` could not draw from
    // threw with the handle holding the file's `flock` and no longer
    // reachable by the caller. Every later open then answered `Busy` for
    // the life of the process — the "correct password but won't unlock"
    // trap (audit HV13-M2).
    final tmp = Directory.systemTemp.createTempSync('hv_dart_window_');
    addTearDown(() => tmp.deleteSync(recursive: true));
    final path = _containerOwingAScrub(tmp);

    expect(
      () =>
          HvSpace.open(path: path, password: _pw('pwd'), vacuumWindow: _tooWide),
      throwsA(isA<ArgumentError>()),
      reason: 'a 50-day span is wider than the sampler will draw from',
    );
    expect(
      () => HvSpace.open(
          path: path, password: _pw('pwd'), vacuumWindow: _inThePast),
      throwsA(isA<ArgumentError>()),
      reason: 'a negative delay fires at once, next to the unlock',
    );

    // The half that matters: neither refusal took the container with it.
    final ok =
        HvSpace.open(path: path, password: _pw('pwd'), vacuumWindow: _never);
    addTearDown(ok.close);
    expect(ok.pendingVacuumDelay, const Duration(minutes: 10));

    // And the same window is refused on a handle the caller already holds,
    // where there is nothing to strand and everything to say.
    expect(() => ok.scheduleDeferredVacuum(window: _tooWide),
        throwsA(isA<ArgumentError>()));
    expect(ok.pendingVacuumDelay, const Duration(minutes: 10),
        reason: 'a refused re-arm must leave the armed one alone');
  });

  test('the sampler is total: every window yields a delay', () {
    // `pick` runs with a container open, so it does not get to throw —
    // `validate` is where a bad window is reported. What `pick` owes is a
    // usable answer for one that got this far.
    final wide = _tooWide.pick(Random(7));
    expect(wide, greaterThanOrEqualTo(Duration.zero));
    expect(wide.inMilliseconds, lessThan(DeferredVacuumWindow.maxSpanMs));

    final past = _inThePast.pick(Random(7));
    expect(past, greaterThanOrEqualTo(Duration.zero),
        reason: 'a delay in the past arms a timer that fires immediately');

    // The exact boundary: the widest span the sampler serves is served,
    // and one millisecond more is refused.
    const widest = DeferredVacuumWindow(Duration.zero,
        Duration(milliseconds: DeferredVacuumWindow.maxSpanMs - 1));
    widest.validate();
    expect(widest.pick(Random(7)).inMilliseconds,
        inInclusiveRange(0, DeferredVacuumWindow.maxSpanMs - 1));
    const justOver = DeferredVacuumWindow(
        Duration.zero, Duration(milliseconds: DeferredVacuumWindow.maxSpanMs));
    expect(justOver.validate, throwsA(isA<ArgumentError>()));
  });

  test('a degenerate window means exactly its lower bound', () {
    const w = DeferredVacuumWindow(Duration(seconds: 7), Duration(seconds: 7));
    expect(w.pick(Random(1)), const Duration(seconds: 7));
    // max below min is clamped rather than throwing — callers pinning an
    // exact delay should get one.
    const inverted =
        DeferredVacuumWindow(Duration(seconds: 9), Duration(seconds: 2));
    expect(inverted.pick(Random(1)), const Duration(seconds: 9));
  });
}
