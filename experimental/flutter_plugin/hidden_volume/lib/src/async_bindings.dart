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
import 'dart:typed_data';

import 'bindings.dart';

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
class HvAsyncSpace {
  HvAsyncSpace._(this._isolate, this._toWorker);

  final Isolate _isolate;
  final SendPort _toWorker;
  bool _closed = false;

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
  static Future<HvAsyncSpace> open({
    required String path,
    required Uint8List password,
    String? dylibPath,
  }) async {
    final bootReply = ReceivePort();
    final boot = _BootstrapOpen(
      path: path,
      password: password,
      reply: bootReply.sendPort,
    );
    return _spawn(boot, bootReply, dylibPath);
  }

  static Future<HvAsyncSpace> _spawn(
      _Bootstrap boot, ReceivePort bootReply, String? dylibPath) async {
    final isolate = await Isolate.spawn<_SpawnConfig>(
      _workerEntry,
      _SpawnConfig(dylibPath: dylibPath, bootstrap: boot),
      errorsAreFatal: true,
    );
    final firstReply = await bootReply.first;
    bootReply.close();
    if (firstReply is _ErrorReply) {
      isolate.kill(priority: Isolate.immediate);
      throw HvException(firstReply.kind, firstReply.message);
    }
    final ok = firstReply as _OkReply;
    final toWorker = ok.value as SendPort;
    return HvAsyncSpace._(isolate, toWorker);
  }

  Future<T> _call<T>(_Request Function(SendPort reply) build) async {
    if (_closed) {
      throw StateError('HvAsyncSpace is closed');
    }
    final reply = ReceivePort();
    _toWorker.send(build(reply.sendPort));
    final r = await reply.first;
    reply.close();
    if (r is _ErrorReply) {
      throw HvException(r.kind, r.message);
    }
    return (r as _OkReply).value as T;
  }

  /// Apply a batch of writes atomically. Returns the new commit_seq.
  Future<int> commit(List<HvWriteOp> ops) =>
      _call<int>((reply) => _CommitRequest(ops: ops, reply: reply));

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
  Future<int> eraseNamespace(int namespace) => _call<int>(
      (reply) => _EraseNamespaceRequest(namespace: namespace, reply: reply));

  /// Read one log entry by `(namespace, logId)`. Null if absent.
  Future<Uint8List?> readLog(int namespace, int logId) =>
      _call<Uint8List?>((reply) =>
          _ReadLogRequest(namespace: namespace, logId: logId, reply: reply));

  /// All namespace tags currently in use.
  Future<Uint8List> listNamespaces() =>
      _call<Uint8List>((reply) => _ListNamespacesRequest(reply: reply));

  /// Override the post-commit padding policy.
  Future<void> setPaddingPolicy(PaddingPreset preset) => _call<void>(
      (reply) => _SetPaddingPolicyRequest(preset: preset, reply: reply));

  /// Aggregated per-space stats.
  Future<HvStatsInfo> stats() =>
      _call<HvStatsInfo>((reply) => _StatsRequest(reply: reply));

  /// Reclaim DataBatch chunk slots that no longer hold live log
  /// entries. Returns the count of slots scrubbed.
  Future<int> vacuumDataBatches() =>
      _call<int>((reply) => _VacuumDataBatchesRequest(reply: reply));

  /// Walk every chunk owned by this space, AEAD-decrypting and
  /// re-checking Merkle nodes.
  Future<HvIntegrityResult> verifyIntegrity() => _call<HvIntegrityResult>(
      (reply) => _VerifyIntegrityRequest(reply: reply));

  /// Release the Rust handle and terminate the worker isolate.
  /// Idempotent; subsequent method calls throw [StateError].
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    final reply = ReceivePort();
    try {
      _toWorker.send(_CloseRequest(reply: reply.sendPort));
      await reply.first.timeout(const Duration(seconds: 5),
          onTimeout: () => const _OkReply(null));
    } finally {
      reply.close();
      // Worker exits itself in the close handler; this is a belt-and-
      // suspenders kill in case the worker is wedged.
      _isolate.kill(priority: Isolate.immediate);
    }
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
