/// Scheduling for the post-open scrub the constant-time open defers
/// (audit HV-01).
///
/// `Container::open_space*_constant_time` equalizes the discovery scan so
/// unlock latency cannot say whether a password matched. It used to vacuum
/// orphan index chunks inline right afterwards — milliseconds and disk
/// writes proportional to how much history the space has, on the success
/// path only, since a wrong password never reaches that line. An observer
/// watching the process or the filesystem at the moment a password is
/// typed could read the answer straight off it.
///
/// Rust moved the scrub out of the open. Somebody still has to run it, and
/// **running it in the line after the open fixes nothing**: the same work
/// a few milliseconds later is still the unlock's work, still absent when
/// the password was wrong. It has to happen at a moment the unlock did not
/// cause.
///
/// This module is that moment for the plugin's callers. A window, a
/// cryptographically-random delay inside it, and a timer.
///
/// ## What this does and does not buy
///
/// It buys: the unlock call itself no longer contains the scrub, and the
/// writes land at a time an observer cannot attribute to the unlock —
/// during a stretch in which a messenger is doing its own network and
/// storage work anyway.
///
/// It does not buy: an absolute guarantee that the scrub happens. If the
/// process dies before the timer fires, nothing is reclaimed and the next
/// session owes it again. That is the honest cost of the split against a
/// pre-fix inline vacuum that always ran — and against the leak it always
/// ran into. Hosts that know a better moment (screen off, app backgrounded,
/// first user-initiated write) should call `vacuumAfterOpen` there instead.
library;

import 'dart:async';
import 'dart:math';

/// How long after an unlock the deferred scrub may be run.
///
/// The delay is drawn uniformly from `[min, max]`. Wider is better for
/// decorrelation and worse for the odds that the process is still alive
/// when it fires; [DeferredVacuumWindow.standard] is the compromise the
/// plugin arms by default.
class DeferredVacuumWindow {
  /// A window running from [min] to [max]. `max` is clamped up to `min`,
  /// so a degenerate window means "exactly `min`" rather than an error —
  /// callers pinning an exact delay in tests want that, not a throw.
  const DeferredVacuumWindow(this.min, this.max);

  /// 30 s to 5 min.
  ///
  /// The lower end is far enough out that the write burst is not adjacent
  /// to the unlock in any log an observer keeps at second resolution; the
  /// upper end is short enough that an ordinary session reaches it. Both
  /// ends are a judgement call rather than a derived number, and a host
  /// with a real threat model should pick its own.
  static const DeferredVacuumWindow standard =
      DeferredVacuumWindow(Duration(seconds: 30), Duration(minutes: 5));

  /// Earliest the scrub may run.
  final Duration min;

  /// Latest the scrub may run.
  final Duration max;

  /// Draw a delay from this window.
  ///
  /// [random] defaults to [Random.secure]. That is not paranoia about the
  /// value: a delay drawn from a PRNG an observer can seed or predict is a
  /// delay they can subtract, which puts the write burst back next to the
  /// unlock.
  Duration pick([Random? random]) {
    final lo = min.inMilliseconds;
    final hi = max.inMilliseconds < lo ? lo : max.inMilliseconds;
    if (hi == lo) return Duration(milliseconds: lo);
    return Duration(
      milliseconds: lo + (random ?? Random.secure()).nextInt(hi - lo + 1),
    );
  }
}

/// One armed deferred scrub. Owns a single [Timer]; re-arming cancels the
/// previous one, so a handle never has two in flight.
class DeferredVacuum {
  Timer? _timer;

  /// The delay the currently armed scrub will wait, or `null` if none is
  /// armed. Exposed so a host can log it and a test can assert on it.
  Duration? get pendingDelay => _timer == null ? null : _pending;
  Duration? _pending;

  /// Arm `run` to fire once, after a delay drawn from [window]. Returns
  /// the delay chosen.
  ///
  /// `run` is invoked from a timer callback, where nothing can catch what
  /// it throws — so it must not. The caller wraps it.
  Duration arm(DeferredVacuumWindow window, void Function() run,
      {Random? random}) {
    final delay = window.pick(random);
    _timer?.cancel();
    _pending = delay;
    _timer = Timer(delay, () {
      _timer = null;
      _pending = null;
      run();
    });
    return delay;
  }

  /// Disarm without running. Idempotent; called from every `close`, since
  /// a timer that fires against a freed handle is a use-after-free at the
  /// FFI boundary.
  void cancel() {
    _timer?.cancel();
    _timer = null;
    _pending = null;
  }
}
