/// Dart facade for the `hidden-volume` Rust crate.
///
/// Thin re-export of the typed API in [`src/bindings.dart`](src/bindings.dart),
/// which speaks `dart:ffi` to the uniffi 0.31 C ABI exported by the
/// `hidden-volume-ffi` cdylib (Android `.so` / Windows `.dll`) or
/// statically-linked iOS xcframework.
///
/// ## Quick reference
///
/// ```dart
/// import 'package:hidden_volume/hidden_volume.dart';
///
/// final space = HvSpace.create(
///   path: '/data/data/.../store.bin',
///   password: utf8.encode('correct horse battery staple'),
///   argon: ArgonPreset.defaults,
/// );
/// space.commit([
///   HvWriteOpPut(namespace: 1, key: utf8.encode('username'),
///       value: utf8.encode('alice')),
/// ]);
/// final v = space.get(1, utf8.encode('username'));  // → 'alice' bytes
/// space.close();
/// ```
///
/// ## Threading
///
/// All methods are sync. Run them off the main isolate (via
/// `Isolate.spawn` / `compute`) for I/O-bound calls — the open-time
/// scan can take hundreds of ms on weak hardware. Concurrent calls on
/// the same handle serialize on an internal Rust mutex.
///
/// See [`docs/en/guide/flutter.md`](../../../docs/en/guide/flutter.md)
/// for messenger integration patterns.
library;

import 'dart:typed_data';

import 'src/bindings.dart' as ffi;

// Re-export typed FFI types so callers don't import `src/`.
export 'src/bindings.dart'
    show
        ArgonPreset,
        HvException,
        HvHeaderInfo,
        HvIntegrityResult,
        HvLogEntry,
        HvNamespaceCount,
        HvPasswordRotation,
        HvStatsInfo,
        HvWriteOp,
        HvWriteOpPut,
        HvWriteOpDelete,
        HvWriteOpAppendLog,
        PaddingPreset;

// Async wrapper + Future-returning top-level helpers.
export 'src/async_bindings.dart'
    show
        HvAsyncSpace,
        headerInfoAsync,
        changePasswordsAsync,
        compactKnownAsync;

/// A handle to one open space inside a `hidden-volume` container file.
///
/// One [HvSpace] == one (container_file, password) pair. Multiple
/// passwords on the same file create deniable parallel spaces — open
/// each via a separate [HvSpace] handle.
///
/// Acquire via [HvSpace.create] (first run) or [HvSpace.open]
/// (subsequent launches). Always [close] when done — the underlying
/// file lock + memory release only when [close] runs (or when the Dart
/// object is GC'd).
class HvSpace {
  HvSpace._(this._inner);

  final ffi.SpaceHandleBindings _inner;

  /// Create a fresh container at [path] and bootstrap a space inside it
  /// keyed by [password]. [argon] picks the KDF cost preset baked into
  /// the container header (cannot be changed in-place later — needs a
  /// `repack` to migrate).
  ///
  /// Throws [HvException] with `kind == "Busy"` if another process holds
  /// the file lock; `kind == "SpaceAlreadyExists"` if [path] already has
  /// a space matching [password] (re-running create on an existing
  /// container).
  factory HvSpace.create({
    required String path,
    required Uint8List password,
    ffi.ArgonPreset argon = ffi.ArgonPreset.defaults,
    int initialGarbageChunks = 0,
    int superblockReplicas = 3,
  }) {
    return HvSpace._(ffi.SpaceHandleBindings.create(
      path: path,
      password: password,
      argon: argon,
      initialGarbageChunks: initialGarbageChunks,
      superblockReplicas: superblockReplicas,
    ));
  }

  /// Open an existing container at [path] and unlock the space matching
  /// [password]. Throws [HvException] with `kind == "AuthFailed"` if no
  /// space matches — deniability invariant: do NOT distinguish "wrong
  /// password" from "no such space" in your UI.
  factory HvSpace.open({
    required String path,
    required Uint8List password,
  }) {
    return HvSpace._(ffi.SpaceHandleBindings.open(
      path: path,
      password: password,
    ));
  }

  /// Apply a batch of writes atomically as one commit. Returns the new
  /// `commit_seq`. Empty [ops] returns the current seq unchanged.
  int commit(List<ffi.HvWriteOp> ops) => _inner.commit(ops);

  /// Read a KV value from [namespace], or `null` if absent.
  Uint8List? get(int namespace, Uint8List key) => _inner.get(namespace, key);

  /// Read a contiguous range of log entries. Pass `start`/`end` as `null`
  /// for open-ended range; cap with [limit].
  List<ffi.HvLogEntry> iterLogRange({
    required int namespace,
    int? start,
    int? end,
    required int limit,
  }) =>
      _inner.iterLogRange(
        namespace: namespace,
        start: start,
        end: end,
        limit: limit,
      );

  /// Current commit sequence (advances by 1 per non-empty [commit]).
  int commitSeq() => _inner.commitSeq();

  /// Recoverable commit-anchor history. Used by host-app sync layer to
  /// detect rollback (see [`docs/en/guide/multi-device.md`](../../../docs/en/guide/multi-device.md)).
  List<int> commitHistory() => _inner.commitHistory();

  /// Number of KV entries in [namespace]. O(N) — walks the index.
  int count(int namespace) => _inner.count(namespace);

  /// Drop all entries in [namespace]. Returns the **number of
  /// entries that were erased** (matches Rust
  /// [`Space::erase_namespace`] semantics — see
  /// `crates/hidden-volume-ffi/src/lib.rs::erase_namespace`).
  /// Earlier Dart drafts documented this as returning `commit_seq`;
  /// that was incorrect.
  int eraseNamespace(int namespace) => _inner.eraseNamespace(namespace);

  /// Read one log entry by `(namespace, logId)`. Null if absent.
  Uint8List? readLog(int namespace, int logId) =>
      _inner.readLog(namespace, logId);

  /// All namespace tags currently in use. One `u8` per namespace.
  Uint8List listNamespaces() => _inner.listNamespaces();

  /// Override the post-commit padding policy. Auto-restored from header
  /// on each open — manual override is rarely needed.
  void setPaddingPolicy(ffi.PaddingPreset preset) =>
      _inner.setPaddingPolicy(preset);

  /// Aggregated stats: commit_seq, history depth, slot utilization,
  /// per-namespace entry counts. Drives host-app `compact_known`
  /// triggers.
  ffi.HvStatsInfo stats() => _inner.stats();

  /// Reclaim DataBatch chunk slots that no longer hold live log entries.
  /// Returns the count of slots scrubbed.
  int vacuumDataBatches() => _inner.vacuumDataBatches();

  /// Walk every chunk owned by this space, AEAD-decrypting and
  /// re-checking Merkle nodes. Throws [HvException] with
  /// `kind == "IntegrityFailure"` on mismatch.
  ffi.HvIntegrityResult verifyIntegrity() => _inner.verifyIntegrity();

  /// Release the file lock and Rust-side resources. Idempotent.
  void close() => _inner.close();
}

/// Inspect the plaintext header (salt, Argon cost, file size).
/// Readable without a password; useful for password-less header
/// integrity checks.
///
/// **v3 (2026-05-28).** `container_id` is no longer in the
/// cleartext header — it is per-space derived from the versioned
/// master key. Earlier docstrings listed `container_id` here.
ffi.HvHeaderInfo headerInfo(String path) => ffi.headerInfo(path);

/// In-place password rotation for the container at [path]. Each entry
/// in [rotations] is an `(old → new)` pair; `oldPwd == newPwd` preserves
/// the space verbatim. Spaces NOT mentioned are **dropped** by the
/// rewrite — to keep a hidden space, include it as a no-op rotation.
///
/// Holds `LOCK_EX` on [path] for the entire rewrite. Throws
/// [HvException] with `kind == "Busy"` if any other process / handle
/// has the file open.
void changePasswords(String path, List<ffi.HvPasswordRotation> rotations) =>
    ffi.changePasswords(path, rotations);

/// In-place compact, keeping only spaces unlocked by [passwords].
/// Anything not unlocked is permanently destroyed by the rewrite —
/// including hidden spaces whose passwords aren't listed. Use
/// [changePasswords] (with `oldPwd == newPwd` per kept space) to
/// preserve hidden spaces without naming them.
void compactKnown(String path, List<Uint8List> passwords) =>
    ffi.compactKnown(path, passwords);
