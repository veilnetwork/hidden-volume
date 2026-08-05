/// Async wrapper around the sync [SpaceHandleBindings].
///
/// Sync FFI calls block the calling isolate. In Flutter that means the
/// UI thread freezes for the duration of every call — unacceptable for
/// open-time scans (hundreds of ms on weak hardware) or Argon2 KDF
/// (~30-250 ms depending on preset).
///
/// [HvAsyncSpace] solves this by spawning a dedicated worker isolate
/// that owns the [SpaceHandleBindings]. Every method on the public API
/// sends a typed request over a [SendPort], the worker executes it
/// against the held handle, and ships the result back. The Dart UI
/// isolate stays free.
///
/// One [HvAsyncSpace] = one worker isolate = one container handle.
/// Concurrent method calls on the same instance serialize on the
/// worker's `ReceivePort.listen` queue (matches the Rust-side mutex
/// inside `SpaceHandle`).
///
/// For top-level one-shot functions (headerInfo, changePasswords,
/// compactKnown) prefer [headerInfoAsync] / [changePasswordsAsync] /
/// [compactKnownAsync] — they use [Isolate.run] for a single-shot
/// background execution without keeping a worker around.
library;

import 'dart:async';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'bindings.dart';
import 'deferred_vacuum.dart';

// ------------------------------------------------------------------
// Worker entry-point + spawn config
// ------------------------------------------------------------------

class _SpawnConfig {
  const _SpawnConfig({this.dylibPath, required this.bootstrap});

  /// Optional override for the dylib path. Production use leaves this
  /// null; tests pass an explicit path so the worker isolate finds the
  /// build-output cdylib.
  final String? dylibPath;

  /// Either `_BootstrapCreate` or `_BootstrapOpen`. Sent in the spawn
  /// message so the worker constructs the SpaceHandle as the very first
  /// thing it does — failure here exits the isolate cleanly.
  final _Bootstrap bootstrap;
}

sealed class _Bootstrap {
  const _Bootstrap(this.reply);
  final SendPort reply;
}

class _BootstrapCreate extends _Bootstrap {
  const _BootstrapCreate({
    required this.path,
    required this.password,
    required this.argon,
    required this.initialGarbageChunks,
    required this.superblockReplicas,
    required SendPort reply,
  }) : super(reply);
  final String path;
  final Uint8List password;
  final ArgonPreset argon;
  final int initialGarbageChunks;
  final int superblockReplicas;
}

class _BootstrapOpen extends _Bootstrap {
  const _BootstrapOpen({
    required this.path,
    required this.password,
    required SendPort reply,
  }) : super(reply);
  final String path;
  final Uint8List password;
}

// ------------------------------------------------------------------
// Per-call requests + replies
// ------------------------------------------------------------------

sealed class _Request {
  const _Request(this.reply);
  final SendPort reply;
}

class _CommitRequest extends _Request {
  const _CommitRequest({required this.ops, required SendPort reply})
      : super(reply);
  final List<HvWriteOp> ops;
}

class _GetRequest extends _Request {
  const _GetRequest(
      {required this.namespace, required this.key, required SendPort reply})
      : super(reply);
  final int namespace;
  final Uint8List key;
}

class _IterLogRangeRequest extends _Request {
  const _IterLogRangeRequest({
    required this.namespace,
    required this.start,
    required this.end,
    required this.limit,
    required SendPort reply,
  }) : super(reply);
  final int namespace;
  final int? start;
  final int? end;
  final int limit;
}

class _CommitSeqRequest extends _Request {
  const _CommitSeqRequest({required SendPort reply}) : super(reply);
}

class _CommitHistoryRequest extends _Request {
  const _CommitHistoryRequest({required SendPort reply}) : super(reply);
}

class _CountRequest extends _Request {
  const _CountRequest({required this.namespace, required SendPort reply})
      : super(reply);
  final int namespace;
}

class _EraseNamespaceRequest extends _Request {
  const _EraseNamespaceRequest(
      {required this.namespace, required SendPort reply})
      : super(reply);
  final int namespace;
}

class _ReadLogRequest extends _Request {
  const _ReadLogRequest({
    required this.namespace,
    required this.logId,
    required SendPort reply,
  }) : super(reply);
  final int namespace;
  final int logId;
}

class _ListNamespacesRequest extends _Request {
  const _ListNamespacesRequest({required SendPort reply}) : super(reply);
}

class _SetPaddingPolicyRequest extends _Request {
  const _SetPaddingPolicyRequest(
      {required this.preset, required SendPort reply})
      : super(reply);
  final PaddingPreset preset;
}

class _StatsRequest extends _Request {
  const _StatsRequest({required SendPort reply}) : super(reply);
}

class _VacuumAfterOpenRequest extends _Request {
  const _VacuumAfterOpenRequest({required SendPort reply}) : super(reply);
}

class _VacuumDataBatchesRequest extends _Request {
  const _VacuumDataBatchesRequest({required SendPort reply}) : super(reply);
}

class _VerifyIntegrityRequest extends _Request {
  const _VerifyIntegrityRequest({required SendPort reply}) : super(reply);
}

class _CloseRequest extends _Request {
  const _CloseRequest({required SendPort reply}) : super(reply);
}

sealed class _Reply {
  const _Reply();
}

class _OkReply extends _Reply {
  const _OkReply(this.value);
  final Object? value;
}

class _ErrorReply extends _Reply {
  const _ErrorReply(this.kind, this.message);
  final String kind;
  final String message;
}

// ------------------------------------------------------------------
// Operation identity and outcomes (audit HV-07)
// ------------------------------------------------------------------

/// What became of an operation submitted to the worker.
///
/// A Dart `Future` cannot be cancelled. Wrapping one of the calls below
/// in `.timeout(...)` therefore stops the CALLER waiting; it does not
/// stop the worker, which finishes the call and answers into a reply
/// port nobody reads. Before audit HV-07 that answer was simply lost,
/// and a host whose commit timed out had no way to find out whether its
/// write had landed — on a deniable store, where the alternative to
/// knowing is to guess and possibly re-apply.
///
/// The Rust FFI does have a ledger for exactly this
/// (`AsyncSpaceHandle::abandoned_operations`), but it hangs off the
/// ASYNC handle, and the hand-written Dart bindings bind only the sync
/// symbols — the worker isolate holds a `SpaceHandleBindings`. So the
/// ledger was unreachable from Dart, and this is its Dart-side
/// counterpart rather than a binding of it. Nothing needed porting: the
/// worker already serialises calls, which is the hard half.
sealed class HvOpOutcome {
  const HvOpOutcome();
}

/// The worker has not answered yet. A caller that timed out may still
/// see this — the operation is genuinely still running.
class HvOpPending extends HvOpOutcome {
  const HvOpPending();

  @override
  String toString() => 'HvOpPending()';
}

/// The worker completed the operation. [value] is what the matching
/// method would have returned.
class HvOpSucceeded extends HvOpOutcome {
  const HvOpSucceeded(this.value);
  final Object? value;

  @override
  String toString() => 'HvOpSucceeded($value)';
}

/// The worker answered, and the answer was a refusal by the core.
///
/// This is a claim about the CORE's answer, and it is only sound because
/// there is one: the worker was alive, it ran the call, and the call
/// returned an error. A worker that died under the call answers
/// [HvOpIndeterminate] instead — it used to answer this, which said
/// "nothing happened" about an operation nobody watched finish
/// (report7 P2).
///
/// **A refusal is not by itself a proof that nothing happened**
/// (report8 H-09). This variant used to say "nothing was committed, so
/// the operation is safe to retry" flatly, of every kind — and
/// `docs/en/security/audits/fsync.md` said the opposite in the same
/// breath, that a caller "should NOT retry the same Tx without first
/// re-opening the container". The core is the arbiter and the core sides
/// with the audit doc: a commit whose Superblock publish fails answers
/// `PublishUncertain`, which exists precisely to say a replica may
/// already be on the disk.
///
/// Ask [error] rather than the variant: [HvException.mayHaveApplied] is
/// `true` for `PublishUncertain` and the two `RenameVisible*` kinds, and
/// `false` for the ordinary refusals that were rejected before anything
/// was written. Reopen on the first group; the second is safe to retry.
class HvOpFailed extends HvOpOutcome {
  const HvOpFailed(this.error);
  final HvException error;

  /// Whether the refused operation may still have taken effect — see
  /// [HvException.mayHaveApplied]. `true` means reopen and look; do not
  /// retry.
  bool get mayHaveApplied => error.mayHaveApplied;

  @override
  String toString() => 'HvOpFailed(${error.kind}: ${error.message})';
}

/// The worker **died under this operation**, so whether it took effect
/// is unknown.
///
/// Not a failure. The isolate can die *after* the native commit has
/// reached the disk and *before* its reply is sent — an FFI fault, an
/// OOM kill and an uncaught error all land in that window — and from
/// Dart the two are indistinguishable, because the thing that would have
/// told them apart is the answer that never came.
///
/// The Rust core models this honestly: a lost operation **may have
/// changed state**, and only `Cancelled` carries a proof of no effect.
/// This variant is the same boundary on the Dart side.
///
/// **What a caller should do.** Reopen the container and look, rather
/// than retry blindly or report failure to the user. Every mutating call
/// in this API is currently idempotent by key, so a blind retry happens
/// to be harmless today — that is a property of today's call set, not a
/// guarantee of this type, and it is exactly the kind of thing that stops
/// being true quietly.
class HvOpIndeterminate extends HvOpOutcome {
  const HvOpIndeterminate(this.error);

  /// Why the worker is gone. Diagnostic only — it describes the death,
  /// not the fate of the operation, which is the whole point.
  final HvException error;

  @override
  String toString() => 'HvOpIndeterminate(${error.kind}: ${error.message})';
}

/// No such id was ever issued by this handle, or its record has aged
/// out of the bounded history.
///
/// Distinct from [HvOpPending] on purpose: "I do not know" and "not
/// finished yet" call for different things from a caller, and
/// collapsing them would make the getter a source of the same guesswork
/// it exists to remove.
class HvOpUnknown extends HvOpOutcome {
  const HvOpUnknown();

  @override
  String toString() => 'HvOpUnknown()';
}

/// A submitted operation: the id to ask about it by, and the future of
/// its result.
///
/// Take the id BEFORE awaiting — that is the whole point. Awaiting
/// first and reading the id after works only when the await succeeded,
/// which is the case that never needed an id.
class HvOperation<T> {
  const HvOperation(this.id, this.result);

  /// Monotonic within one [HvAsyncSpace], starting at 1.
  final int id;

  /// The same future the non-`Operation` method would have returned.
  final Future<T> result;
}

/// Watches the worker isolate and turns its death into a failed future.
///
/// Every RPC used to `await reply.first` with nothing watching the isolate, so
/// a worker that died — an FFI fault, an uncaught error, an OOM kill — left
/// that future pending FOREVER, and every later call joined it.
/// `errorsAreFatal: true` makes the isolate die QUIETLY, so nothing surfaced
/// (audit HV-09).
///
/// `onExit` fires for any termination; `onError` fires first when the isolate
/// died from an uncaught error and carries the message. Both are wired, so a
/// silent exit is reported too and not only the errors Dart can describe.
///
/// Public (rather than library-private) only so a test can watch a stub worker
/// of its own — see [HvAsyncSpace.debugOverWorker]. Not part of the supported
/// API.
class HvWorkerDeath {
  HvWorkerDeath() {
    errorPort.listen((message) {
      final detail =
          message is List && message.isNotEmpty ? '${message.first}' : '$message';
      _die('hidden-volume worker isolate error: $detail');
    });
    exitPort.listen((_) => _die('hidden-volume worker isolate exited'));
  }

  final exitPort = ReceivePort();
  final errorPort = ReceivePort();
  final _completer = Completer<Never>();

  Future<Never> get future => _completer.future;

  void _die(String why) {
    if (_completer.isCompleted) return;
    _completer.completeError(HvException('Internal', why), StackTrace.current);
  }

  /// Stop watching. The future is left as it is: a caller already holding it
  /// must still see the death, and completing it here would invent one.
  void dispose() {
    exitPort.close();
    errorPort.close();
    // An uncompleted error future with no listener is an unhandled-error
    // report at GC time; give it a handler that does nothing.
    _completer.future.ignore();
  }
}

// ------------------------------------------------------------------
// Worker isolate entry-point
// ------------------------------------------------------------------

void _workerEntry(_SpawnConfig config) {
  if (config.dylibPath != null) {
    overrideDylib(DynamicLibrary.open(config.dylibPath!));
  }

  // Bootstrap: construct the handle. On failure, send error and exit.
  final SpaceHandleBindings space;
  try {
    space = switch (config.bootstrap) {
      _BootstrapCreate(:final path, :final password, :final argon, :final initialGarbageChunks, :final superblockReplicas) =>
        SpaceHandleBindings.create(
          path: path,
          password: password,
          argon: argon,
          initialGarbageChunks: initialGarbageChunks,
          superblockReplicas: superblockReplicas,
        ),
      _BootstrapOpen(:final path, :final password) =>
        SpaceHandleBindings.open(path: path, password: password),
    };
  } on HvException catch (e) {
    config.bootstrap.reply.send(_ErrorReply(e.kind, e.message));
    return;
  } catch (e) {
    config.bootstrap.reply.send(_ErrorReply('Internal', e.toString()));
    return;
  }

  // Bootstrap succeeded — open the request port and signal readiness
  // by sending its SendPort back.
  final rx = ReceivePort();
  config.bootstrap.reply.send(_OkReply(rx.sendPort));

  rx.listen((dynamic msg) {
    if (msg is! _Request) return;
    _dispatch(space, msg, rx);
  });
}

void _dispatch(SpaceHandleBindings space, _Request msg, ReceivePort rx) {
  void run<T>(T Function() body) {
    try {
      msg.reply.send(_OkReply(body()));
    } on HvException catch (e) {
      msg.reply.send(_ErrorReply(e.kind, e.message));
    } catch (e) {
      msg.reply.send(_ErrorReply('Internal', e.toString()));
    }
  }

  switch (msg) {
    case _CommitRequest(:final ops):
      run(() => space.commit(ops));
    case _GetRequest(:final namespace, :final key):
      run(() => space.get(namespace, key));
    case _IterLogRangeRequest(:final namespace, :final start, :final end, :final limit):
      run(() => space.iterLogRange(
          namespace: namespace, start: start, end: end, limit: limit));
    case _CommitSeqRequest():
      run(() => space.commitSeq());
    case _CommitHistoryRequest():
      run(() => space.commitHistory());
    case _CountRequest(:final namespace):
      run(() => space.count(namespace));
    case _EraseNamespaceRequest(:final namespace):
      run(() => space.eraseNamespace(namespace));
    case _ReadLogRequest(:final namespace, :final logId):
      run(() => space.readLog(namespace, logId));
    case _ListNamespacesRequest():
      run(() => space.listNamespaces());
    case _SetPaddingPolicyRequest(:final preset):
      run<Object?>(() {
        space.setPaddingPolicy(preset);
        return null;
      });
    case _StatsRequest():
      run(() => space.stats());
    case _VacuumDataBatchesRequest():
      run(() => space.vacuumDataBatches());
    case _VacuumAfterOpenRequest():
      run(() => space.vacuumAfterOpen());
    case _VerifyIntegrityRequest():
      run(() => space.verifyIntegrity());
    case _CloseRequest():
      try {
        space.close();
        msg.reply.send(const _OkReply(null));
      } catch (e) {
        msg.reply.send(_ErrorReply('Internal', e.toString()));
      } finally {
        rx.close();
        Isolate.current.kill(priority: Isolate.immediate);
      }
  }
}

// ------------------------------------------------------------------
// Public async API
// ------------------------------------------------------------------

/// Async equivalent of [HvSpace] (in `lib/hidden_volume.dart`). Backed
/// by a dedicated worker isolate that owns the underlying Rust handle.
/// Every method offloads work — the calling isolate (Flutter UI) stays
/// responsive.
///
/// One [HvAsyncSpace] == one worker isolate. Drop with [close] when
/// done — that frees the Rust-side handle AND terminates the worker.
/// [close] can throw; read its doc before ignoring the result.
class HvAsyncSpace {
  HvAsyncSpace._(this._isolate, this._toWorker, this._death);

  /// Assemble a handle over a worker that is ALREADY up.
  ///
  /// TEST SEAM ONLY. [close]'s contract turns on what happens when a worker
  /// does NOT answer — which in production means it is parked inside a
  /// synchronous FFI call, and there is no way to park a real worker there on
  /// demand. A stub that simply declines to answer is the only way to exercise
  /// it at all.
  ///
  /// Not part of the supported API. Production builds its worker through
  /// [create] / [open].
  static HvAsyncSpace debugOverWorker({
    required Isolate isolate,
    required SendPort toWorker,
    required HvWorkerDeath watch,
  }) =>
      HvAsyncSpace._(isolate, toWorker, watch);

  /// How long [close] waits for the worker before giving up on the wait.
  /// Settable for TESTS ONLY — the wait is what is under test, and five real
  /// seconds per case is not a thing to spend.
  static Duration closeTimeout = const Duration(seconds: 5);

  final Isolate _isolate;
  final SendPort _toWorker;

  /// Completes with an error when the worker isolate dies. Every RPC races it
  /// so a dead worker surfaces as a failure rather than a future that never
  /// completes (audit HV-09).
  final HvWorkerDeath _death;
  bool _closed = false;
  final DeferredVacuum _deferredVacuum = DeferredVacuum();

  /// Next operation id. Monotonic, starts at 1 so that 0 is never a
  /// valid id and an uninitialised field cannot be mistaken for one
  /// (audit HV-07).
  int _nextOpId = 1;

  /// Outcome per submitted operation, oldest evicted first.
  ///
  /// A `LinkedHashMap` (Dart's default) keeps insertion order, and ids
  /// are issued in order, so evicting `keys.first` evicts the oldest.
  final Map<int, HvOpOutcome> _outcomes = <int, HvOpOutcome>{};

  /// How many operations' outcomes are kept. Bounded on purpose: an
  /// unbounded map would be a leak on a long-lived handle, and an
  /// outcome nobody asked about within the last [_outcomeHistory]
  /// operations is one nobody is going to. Past that the getter says
  /// [HvOpUnknown] rather than inventing an answer.
  static const int _outcomeHistory = 128;

  /// What became of the operation [opId] (audit HV-07).
  ///
  /// The one thing a `.timeout(...)` on any of the calls below leaves
  /// you without. Dart futures do not cancel, so a timeout stops the
  /// caller waiting and nothing else: the worker finishes the call and
  /// answers into a port the caller has stopped reading. Submit through
  /// the `*Operation` variant, keep the id, and ask here afterwards.
  ///
  /// Returns [HvOpPending] while the worker is still on it,
  /// [HvOpSucceeded] / [HvOpFailed] once it has answered, and
  /// [HvOpUnknown] for an id this handle never issued or has since
  /// evicted.
  HvOpOutcome outcomeOf(int opId) => _outcomes[opId] ?? const HvOpUnknown();

  void _record(int opId, HvOpOutcome outcome) {
    _outcomes[opId] = outcome;
    while (_outcomes.length > _outcomeHistory) {
      _outcomes.remove(_outcomes.keys.first);
    }
  }

  /// Spawn a worker, create a fresh container at [path], bootstrap a
  /// space inside it under [password]. See [HvSpace.create] for argument
  /// semantics.
  ///
  /// [dylibPath] is for tests only — production builds leave it null
  /// and the worker resolves the cdylib via the standard OS path
  /// (Android: `libhidden_volume_ffi.so`, iOS: process-scope, etc.).
  static Future<HvAsyncSpace> create({
    required String path,
    required Uint8List password,
    ArgonPreset argon = ArgonPreset.defaults,
    int initialGarbageChunks = 0,
    int superblockReplicas = 3,
    String? dylibPath,
  }) async {
    final bootReply = ReceivePort();
    final boot = _BootstrapCreate(
      path: path,
      password: password,
      argon: argon,
      initialGarbageChunks: initialGarbageChunks,
      superblockReplicas: superblockReplicas,
      reply: bootReply.sendPort,
    );
    return _spawn(boot, bootReply, dylibPath);
  }

  /// Spawn a worker, open the container at [path], unlock the space
  /// matching [password]. See [HvSpace.open] for semantics (especially
  /// the deniability invariant: do NOT distinguish wrong-password from
  /// no-such-space in your UI).
  ///
  /// The unlock takes the constant-time scan, which no longer scrubs
  /// inline (audit HV-01) — so this arms the deferred scrub on the worker
  /// before returning, at a random offset from now. See
  /// [scheduleDeferredVacuum] to choose your own window and
  /// [cancelDeferredVacuum] to take the job over.
  static Future<HvAsyncSpace> open({
    required String path,
    required Uint8List password,
    String? dylibPath,
    DeferredVacuumWindow vacuumWindow = DeferredVacuumWindow.standard,
  }) async {
    final bootReply = ReceivePort();
    final boot = _BootstrapOpen(
      path: path,
      password: password,
      reply: bootReply.sendPort,
    );
    final space = await _spawn(boot, bootReply, dylibPath);
    space.scheduleDeferredVacuum(window: vacuumWindow);
    return space;
  }

  static Future<HvAsyncSpace> _spawn(
      _Bootstrap boot, ReceivePort bootReply, String? dylibPath) async {
    // Watch it BEFORE it can die (audit HV-09): a worker that fails while
    // opening the container fails FAST — usually on its very first FFI call —
    // and a watcher attached afterwards would miss exactly that case.
    final death = HvWorkerDeath();
    final isolate = await Isolate.spawn<_SpawnConfig>(
      _workerEntry,
      _SpawnConfig(dylibPath: dylibPath, bootstrap: boot),
      errorsAreFatal: true,
      onExit: death.exitPort.sendPort,
      onError: death.errorPort.sendPort,
    );
    Object? firstReply;
    try {
      firstReply = await Future.any<Object?>([bootReply.first, death.future]);
    } catch (e) {
      bootReply.close();
      death.dispose();
      isolate.kill(priority: Isolate.immediate);
      throw HvException('Internal', 'worker died while opening: $e');
    }
    bootReply.close();
    if (firstReply is _ErrorReply) {
      death.dispose();
      isolate.kill(priority: Isolate.immediate);
      throw HvException(firstReply.kind, firstReply.message);
    }
    final ok = firstReply as _OkReply;
    final toWorker = ok.value as SendPort;
    return HvAsyncSpace._(isolate, toWorker, death);
  }

  Future<T> _call<T>(_Request Function(SendPort reply) build) =>
      _submit<T>(build).result;

  /// Send one request and return its id alongside the future of its
  /// result.
  ///
  /// The id is allocated and filed as [HvOpPending] **before** the
  /// send, and the outcome is recorded by the `then`/`catchError` on
  /// the future rather than by whoever awaits it — so a caller who
  /// walks away (a `.timeout(...)`, a widget disposed mid-flight) still
  /// leaves a record behind (audit HV-07).
  HvOperation<T> _submit<T>(_Request Function(SendPort reply) build) {
    if (_closed) {
      throw StateError('HvAsyncSpace is closed');
    }
    final opId = _nextOpId++;
    _record(opId, const HvOpPending());
    final result = _run<T>(opId, build);
    return HvOperation<T>(opId, result);
  }

  Future<T> _run<T>(int opId, _Request Function(SendPort reply) build) async {
    final reply = ReceivePort();
    _toWorker.send(build(reply.sendPort));
    // Raced against the worker's death, not awaited alone (audit HV-09).
    final Object? r;
    try {
      r = await Future.any<Object?>([reply.first, _death.future]);
    } on HvException catch (e) {
      // The worker died under this call, and that is an answer worth
      // filing rather than dropping. It is NOT the answer "nothing was
      // committed" (report7 P2): the only thing that reaches here is
      // `_death.future`, and the isolate can die after the native commit
      // has landed on disk and before its reply is sent. From here the
      // two are indistinguishable, because what would have told them
      // apart is the reply that never arrived.
      //
      // A reply that carries an error is the other case entirely and is
      // filed as `HvOpFailed` below — there the worker was alive, ran
      // the call, and the core refused. That distinction is the one Rust
      // already draws, and this is the same line on the Dart side.
      _record(opId, HvOpIndeterminate(e));
      rethrow;
    } finally {
      reply.close();
    }
    if (r is _ErrorReply) {
      final e = HvException(r.kind, r.message);
      _record(opId, HvOpFailed(e));
      throw e;
    }
    final value = (r as _OkReply).value;
    _record(opId, HvOpSucceeded(value));
    return value as T;
  }

  /// Apply a batch of writes atomically. Returns the new commit_seq.
  ///
  /// Wrapping this in `.timeout(...)` leaves you without an answer —
  /// see [commitOperation] and [outcomeOf] (audit HV-07).
  Future<int> commit(List<HvWriteOp> ops) async => commitOperation(ops).result;

  /// [commit], submitted with an id you can ask [outcomeOf] about.
  ///
  /// ```dart
  /// final op = space.commitOperation(ops);
  /// try {
  ///   await op.result.timeout(const Duration(seconds: 2));
  /// } on TimeoutException {
  ///   // The worker is still on it. Ask again later; do NOT re-submit
  ///   // blindly, and do not assume it failed.
  ///   final what = space.outcomeOf(op.id);
  /// }
  /// ```
  HvOperation<int> commitOperation(List<HvWriteOp> ops) =>
      _submit<int>((reply) => _CommitRequest(ops: ops, reply: reply));

  /// Read a KV value, or null if absent.
  Future<Uint8List?> get(int namespace, Uint8List key) =>
      _call<Uint8List?>(
          (reply) => _GetRequest(namespace: namespace, key: key, reply: reply));

  /// Read a contiguous range of log entries.
  Future<List<HvLogEntry>> iterLogRange({
    required int namespace,
    int? start,
    int? end,
    required int limit,
  }) =>
      _call<List<HvLogEntry>>((reply) => _IterLogRangeRequest(
            namespace: namespace,
            start: start,
            end: end,
            limit: limit,
            reply: reply,
          ));

  /// Current commit sequence.
  Future<int> commitSeq() =>
      _call<int>((reply) => _CommitSeqRequest(reply: reply));

  /// Recoverable commit-anchor history.
  Future<List<int>> commitHistory() =>
      _call<List<int>>((reply) => _CommitHistoryRequest(reply: reply));

  /// Number of KV entries in [namespace].
  Future<int> count(int namespace) =>
      _call<int>((reply) => _CountRequest(namespace: namespace, reply: reply));

  /// Drop all entries in [namespace]. Returns the new commit_seq.
  ///
  /// See [eraseNamespaceOperation] if you intend to time this out.
  Future<int> eraseNamespace(int namespace) async =>
      eraseNamespaceOperation(namespace).result;

  /// [eraseNamespace], submitted with an id for [outcomeOf].
  HvOperation<int> eraseNamespaceOperation(int namespace) => _submit<int>(
      (reply) => _EraseNamespaceRequest(namespace: namespace, reply: reply));

  /// Read one log entry by `(namespace, logId)`. Null if absent.
  Future<Uint8List?> readLog(int namespace, int logId) =>
      _call<Uint8List?>((reply) =>
          _ReadLogRequest(namespace: namespace, logId: logId, reply: reply));

  /// All namespace tags currently in use.
  Future<Uint8List> listNamespaces() =>
      _call<Uint8List>((reply) => _ListNamespacesRequest(reply: reply));

  /// Override the post-commit padding policy.
  ///
  /// See [setPaddingPolicyOperation] if you intend to time this out.
  Future<void> setPaddingPolicy(PaddingPreset preset) async =>
      setPaddingPolicyOperation(preset).result;

  /// [setPaddingPolicy], submitted with an id for [outcomeOf].
  HvOperation<void> setPaddingPolicyOperation(PaddingPreset preset) =>
      _submit<void>(
          (reply) => _SetPaddingPolicyRequest(preset: preset, reply: reply));

  /// Aggregated per-space stats.
  Future<HvStatsInfo> stats() =>
      _call<HvStatsInfo>((reply) => _StatsRequest(reply: reply));

  /// Reclaim DataBatch chunk slots that no longer hold live log
  /// entries. Returns the count of slots scrubbed.
  ///
  /// See [vacuumDataBatchesOperation] if you intend to time this out.
  Future<int> vacuumDataBatches() async => vacuumDataBatchesOperation().result;

  /// [vacuumDataBatches], submitted with an id for [outcomeOf].
  HvOperation<int> vacuumDataBatchesOperation() =>
      _submit<int>((reply) => _VacuumDataBatchesRequest(reply: reply));

  /// Run the post-open forward-secrecy scrub **now** (audit HV-01).
  /// Returns the number of orphan index chunks reclaimed.
  ///
  /// Already armed on a random delay by [HvAsyncSpace.open] — this is the
  /// escape hatch for a host that has a better moment of its own. Awaiting
  /// it in the line after `open` re-creates the finding in the caller: the
  /// scrub costs time and disk writes in proportion to the space's
  /// history, only ever happens when the password was right, and an
  /// observer who can see either at the moment of unlock learns that.
  Future<int> vacuumAfterOpen() async => vacuumAfterOpenOperation().result;

  /// [vacuumAfterOpen], submitted with an id for [outcomeOf].
  HvOperation<int> vacuumAfterOpenOperation() =>
      _submit<int>((reply) => _VacuumAfterOpenRequest(reply: reply));

  /// Arm [vacuumAfterOpen] to run once, after a delay drawn uniformly at
  /// random from [window]. Returns the delay chosen. Re-arming cancels
  /// the pending one; [close] cancels it for good.
  ///
  /// The scrub runs on the worker isolate like every other call here, so
  /// arming it costs the calling isolate nothing.
  ///
  /// Failures are swallowed — there is nobody to report them to from a
  /// timer callback, and a scrub that could not run leaves the container
  /// in the state it was already in.
  Duration scheduleDeferredVacuum({
    DeferredVacuumWindow window = DeferredVacuumWindow.standard,
    Random? random,
  }) {
    return _deferredVacuum.arm(window, () {
      if (_closed) return;
      unawaited(vacuumAfterOpen().catchError((Object _) => 0));
    }, random: random);
  }

  /// The delay the armed deferred scrub is waiting, or `null` if none is
  /// armed.
  Duration? get pendingVacuumDelay => _deferredVacuum.pendingDelay;

  /// Disarm the deferred scrub without running it — for a host taking the
  /// job over, not for skipping it. Until something runs it, the values a
  /// previous session deleted stay recoverable by anyone who later obtains
  /// the password and an old snapshot of the file.
  void cancelDeferredVacuum() => _deferredVacuum.cancel();

  /// Walk every chunk owned by this space, AEAD-decrypting and
  /// re-checking Merkle nodes.
  Future<HvIntegrityResult> verifyIntegrity() => _call<HvIntegrityResult>(
      (reply) => _VerifyIntegrityRequest(reply: reply));

  /// **Test-only.** Kill the worker isolate outright, without the
  /// orderly shutdown [close] performs.
  ///
  /// This is what an FFI fault, an uncaught error or an OOM kill does to
  /// the worker, and it is the only way to produce that from a test:
  /// [close] drains the in-flight call first, so a call cannot be caught
  /// mid-flight through it. Exists so
  /// `outcomeOf`'s [HvOpIndeterminate] branch is covered by an actual
  /// death rather than by a simulation of one (report7 P2).
  ///
  /// Not part of the supported API. Production code wants [close].
  void debugKillWorker() => _isolate.kill(priority: Isolate.immediate);

  /// Release the Rust handle and terminate the worker isolate.
  ///
  /// Idempotent; subsequent method calls throw [StateError].
  ///
  /// **Throws when the container was NOT closed** — `Busy` if the worker did
  /// not answer within [closeTimeout], `Internal` if it died on the way out.
  /// Both are teardown failures a caller can log and carry on from, but the
  /// container's exclusive lock is still held when they are raised, so a flow
  /// that closes one space and immediately opens another must expect `Busy`
  /// on the open and not treat it as a wrong password.
  ///
  /// **A worker that has not answered is NOT killed** (report8). It used to
  /// be: the wait swallowed both the timeout and the worker's death, killed
  /// the isolate unconditionally and returned normally, i.e. reported a clean
  /// close of a container that was still open. And the kill was the worse
  /// half. A worker that has not answered is almost certainly parked inside a
  /// synchronous FFI call, and **an isolate kill cannot interrupt or unwind an
  /// FFI frame**: the native `Drop` never runs, the container's flock stays
  /// held by THIS PROCESS, and every later open fails `Busy` until the app
  /// restarts — the "correct password but won't unlock" trap. So the worker is
  /// left running to finish releasing the container on its own terms; it kills
  /// itself once it has served the close.
  ///
  /// Killing is still the last resort, on the two paths where it is safe:
  /// after the worker has answered (it is already tearing itself down), and
  /// after it has died (there is no frame left to unwind).
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    // Before anything else: a timer that fires against a torn-down worker
    // would send into a dead port.
    _deferredVacuum.cancel();
    final reply = ReceivePort();
    // Single-subscription port: capture the one future it can hand out, so
    // the background drain below can wait on the same reply this did.
    final done = reply.first;
    _toWorker.send(_CloseRequest(reply: reply.sendPort));
    Object? r;
    try {
      // Raced against the worker's death as well as the timeout: a worker that
      // has already died will never answer, and `errorsAreFatal` makes it die
      // QUIETLY, so watching the reply alone burns the whole timeout and then
      // queues a drain for an answer that cannot come.
      //
      // The worker never replies a bare null (`_OkReply` / `_ErrorReply` are
      // objects), so null unambiguously means the timeout fired.
      r = await Future.any<Object?>([done, _death.future])
          .timeout(closeTimeout, onTimeout: () => null);
    } catch (e) {
      // The worker died mid-close. Nothing is left to wait for, and whether
      // the container handle was released with it is not something this is in
      // a position to claim.
      reply.close();
      _death.dispose();
      _isolate.kill(priority: Isolate.immediate);
      throw HvException(
          'Internal', 'hidden-volume worker died during close: $e');
    }
    if (r != null) {
      reply.close();
      // Stop watching BEFORE the kill: an expected shutdown is not a death to
      // report, and leaving the watcher armed turns every clean close into an
      // error future with nobody listening (audit HV-09).
      _death.dispose();
      _isolate.kill(priority: Isolate.immediate);
      return;
    }
    // Timed out. Leave the worker alive (see the doc above) and drain its
    // answer in the background, so the watcher and the port are released when
    // it finally lands rather than never.
    unawaited(done.catchError((Object _) => null).whenComplete(() {
      reply.close();
      // The worker is finally gone, on its own terms. Stop watching now rather
      // than at the timeout: until this lands the isolate is still live and a
      // real crash in the meantime is still worth reporting.
      _death.dispose();
    }));
    throw HvException(
        'Busy',
        'hidden-volume worker did not close within '
            '${closeTimeout.inMilliseconds}ms; the container lock is still '
            'held');
  }
}

// ------------------------------------------------------------------
// Top-level async (one-shot) functions via Isolate.run
// ------------------------------------------------------------------

HvHeaderInfo _headerInfoEntry((String, String?) args) {
  final (path, dylibPath) = args;
  if (dylibPath != null) {
    overrideDylib(DynamicLibrary.open(dylibPath));
  }
  return headerInfo(path);
}

/// Async equivalent of [headerInfo]. Spawns a one-shot isolate so the
/// `LOCK_SH` acquire and read don't block the caller.
Future<HvHeaderInfo> headerInfoAsync(String path, {String? dylibPath}) {
  return Isolate.run(() => _headerInfoEntry((path, dylibPath)));
}

void _changePasswordsEntry(
    (String, List<HvPasswordRotation>, String?) args) {
  final (path, rotations, dylibPath) = args;
  if (dylibPath != null) {
    overrideDylib(DynamicLibrary.open(dylibPath));
  }
  changePasswords(path, rotations);
}

/// Async equivalent of [changePasswords]. Spawns a one-shot isolate so
/// the `LOCK_EX` rewrite (Argon2 KDF + repack) doesn't block the caller.
Future<void> changePasswordsAsync(
    String path, List<HvPasswordRotation> rotations,
    {String? dylibPath}) {
  return Isolate.run(
      () => _changePasswordsEntry((path, rotations, dylibPath)));
}

void _compactKnownEntry((String, List<Uint8List>, String?) args) {
  final (path, passwords, dylibPath) = args;
  if (dylibPath != null) {
    overrideDylib(DynamicLibrary.open(dylibPath));
  }
  compactKnown(path, passwords);
}

/// Async equivalent of [compactKnown]. Spawns a one-shot isolate so the
/// `LOCK_EX` rewrite doesn't block the caller.
Future<void> compactKnownAsync(String path, List<Uint8List> passwords,
    {String? dylibPath}) {
  return Isolate.run(() => _compactKnownEntry((path, passwords, dylibPath)));
}
