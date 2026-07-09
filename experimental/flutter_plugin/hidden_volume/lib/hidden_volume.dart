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
    show HvAsyncSpace, headerInfoAsync, changePasswordsAsync, compactKnownAsync;

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

  /// Add a **new parallel space** to an **existing** container at [path],
  /// keyed by [password] — the primitive for hiding several identities in
  /// one file. Unlike [HvSpace.create] (which bootstraps a fresh container
  /// and fails if one exists), this opens the container already on disk and
  /// creates an additional, deniable space inside it.
  ///
  /// Throws [HvException] with `kind == "SpaceAlreadyExists"` if [password]
  /// already maps to a space here (caller may fall back to [HvSpace.open]);
  /// `kind == "Io"` / `"Malformed"` if [path] is not an existing container.
  factory HvSpace.addSpace({
    required String path,
    required Uint8List password,
  }) {
    return HvSpace._(ffi.SpaceHandleBindings.addSpace(
      path: path,
      password: password,
    ));
  }

  /// Open a space from pre-derived [keys] (64 opaque bytes from [spaceKeys])
  /// instead of a password — the **master-space** path: a master holds its
  /// children's keys inside its own deniable space and opens any child without
  /// a per-child password prompt.
  ///
  /// Throws [HvException] with `kind == "Malformed"` if [keys] is not 64 bytes,
  /// `kind == "AuthFailed"` if the keys match no space here (same
  /// indistinguishable path as a wrong password).
  factory HvSpace.openWithKeys({
    required String path,
    required Uint8List keys,
  }) {
    return HvSpace._(ffi.SpaceHandleBindings.openWithKeys(
      path: path,
      keys: keys,
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

  /// Keys of every KV entry in [namespace] (sorted ascending, values not
  /// transferred) — see SpaceHandleBindings.kvKeys.
  List<Uint8List> kvKeys(int namespace) => _inner.kvKeys(namespace);

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

  /// Export this space's `SpaceKeys` as 64 opaque bytes, for a master roster to
  /// store and later reopen this space via [HvSpace.openWithKeys] without its
  /// password. **Sensitive** key material — keep only inside another deniable
  /// space; never log or persist it in the clear.
  Uint8List spaceKeys() => _inner.spaceKeys();

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

/// Hosts SEVERAL spaces of one container file open at once, under that file's
/// single exclusive lock. The storage handle for running several identities
/// simultaneously (one network node per identity) over a single deniable
/// container — the single-handle [HvSpace] only opens one space at a time.
///
/// Spaces are addressed by a small [int] id from [openSpace]. Every call
/// serializes internally, so writes to different spaces never overlap (which is
/// exactly what the single-writer lock requires). Always [close] when done.
class HvMultiSpace {
  HvMultiSpace._(this._inner);

  final ffi.MultiSpaceHandleBindings _inner;

  /// Open the container at [path] for multi-space hosting (takes its lock).
  factory HvMultiSpace.open({required String path}) =>
      HvMultiSpace._(ffi.MultiSpaceHandleBindings.open(path: path));

  /// Host an existing space by its 64-byte `SpaceKeys` (from [HvSpace.spaceKeys]);
  /// returns its space id. Throws [HvException] `AuthFailed` if no space matches,
  /// `Malformed` if [keys] is not 64 bytes.
  int openSpace(Uint8List keys) => _inner.openSpace(keys);

  /// Number of hosted spaces.
  int spaceCount() => _inner.spaceCount();

  /// Override the shared container's post-commit padding policy.
  void setPaddingPolicy(ffi.PaddingPreset preset) =>
      _inner.setPaddingPolicy(preset);

  /// Export hosted space [id]'s 64-byte `SpaceKeys`. **Sensitive** — never log.
  Uint8List spaceKeys(int id) => _inner.spaceKeys(id);

  /// Apply a write batch to space [id]; returns its new commit seq.
  int commit(int id, List<ffi.HvWriteOp> ops) => _inner.commit(id, ops);

  /// Read a KV value from space [id], or null if absent.
  Uint8List? get(int id, int namespace, Uint8List key) =>
      _inner.get(id, namespace, key);

  /// Read one log entry from space [id] by [logId], or null if absent.
  Uint8List? readLog(int id, int namespace, int logId) =>
      _inner.readLog(id, namespace, logId);

  /// Half-open range query over a log namespace of space [id].
  List<ffi.HvLogEntry> iterLogRange({
    required int id,
    required int namespace,
    int? start,
    int? end,
    required int limit,
  }) =>
      _inner.iterLogRange(
          id: id, namespace: namespace, start: start, end: end, limit: limit);

  /// Number of KV entries in [namespace] of space [id].
  int count(int id, int namespace) => _inner.count(id, namespace);

  /// Keys of every KV entry in [namespace] of space [id].
  List<Uint8List> kvKeys(int id, int namespace) => _inner.kvKeys(id, namespace);

  /// Current commit sequence of space [id].
  int commitSeq(int id) => _inner.commitSeq(id);

  /// Reclaim chunks orphaned by edit/delete in space [id] (deniable scrub).
  int vacuumDataBatches(int id) => _inner.vacuumDataBatches(id);

  /// Release the container lock and free the handle.
  void close() => _inner.close();
}
