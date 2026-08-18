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

import 'dart:math';
import 'dart:typed_data';

import 'src/bindings.dart' as ffi;
import 'src/deferred_vacuum.dart';

export 'src/deferred_vacuum.dart' show DeferredVacuumWindow;

// Re-export typed FFI types so callers don't import `src/`.
export 'src/bindings.dart'
    show
        ArgonPreset,
        HvException,
        HvHardeningFailure,
        HvHardeningStep,
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
        HvWriteOpDeleteLog,
        PaddingPreset,
        // Test seams for the `mayHaveApplied` drift check (report8 H-09):
        // a kind that matches nothing makes the predicate silently
        // always-false, and only the ordinal table can say what can arrive.
        debugKnownErrorKinds,
        debugKindsThatMayHaveApplied;

// Async wrapper + Future-returning top-level helpers.
export 'src/async_bindings.dart'
    show
        HvAsyncSpace,
        HvOperation,
        HvOpOutcome,
        HvOpPending,
        HvOpSucceeded,
        HvOpFailed,
        HvOpIndeterminate,
        HvOpUnknown,
        HvWorkerDeath,
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
  final DeferredVacuum _deferredVacuum = DeferredVacuum();

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
  ///
  /// The unlock takes the constant-time scan, which no longer scrubs
  /// inline (audit HV-01) — so this arms the deferred scrub before
  /// returning, at a random offset from now. See
  /// [scheduleDeferredVacuum] to choose your own moment, and
  /// [cancelDeferredVacuum] to take the job over entirely.
  factory HvSpace.open({
    required String path,
    required Uint8List password,
    DeferredVacuumWindow vacuumWindow = DeferredVacuumWindow.standard,
  }) {
    // Before the open, not after it: see `_armOrRelease`.
    vacuumWindow.validate();
    final s = HvSpace._(ffi.SpaceHandleBindings.open(
      path: path,
      password: password,
    ));
    return _armOrRelease(s, vacuumWindow);
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
  ///
  /// Constant-time like [HvSpace.open], and arms the deferred scrub the
  /// same way.
  factory HvSpace.openWithKeys({
    required String path,
    required Uint8List keys,
    DeferredVacuumWindow vacuumWindow = DeferredVacuumWindow.standard,
  }) {
    vacuumWindow.validate();
    final s = HvSpace._(ffi.SpaceHandleBindings.openWithKeys(
      path: path,
      keys: keys,
    ));
    return _armOrRelease(s, vacuumWindow);
  }

  /// Arm [space]'s deferred scrub, closing it if the arming throws.
  ///
  /// Between the open and the `return` the handle holds the container's
  /// `flock` and the caller has no reference to it: anything thrown in
  /// that gap leaks the lock for the life of the process, and every later
  /// open answers `Busy` — the "correct password but won't unlock" trap.
  /// The GC finalizer on `SpaceHandleBindings` would eventually free it,
  /// on no schedule anybody can wait for.
  ///
  /// The window is validated before the open as well, which is what
  /// actually removed the known way to get here (audit HV13-M2); this is
  /// the structural half, so the next thing that learns to throw in this
  /// gap does not re-open the finding.
  static HvSpace _armOrRelease(HvSpace space, DeferredVacuumWindow window) {
    try {
      space.scheduleDeferredVacuum(window: window);
    } catch (_) {
      space.close();
      rethrow;
    }
    return space;
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
  /// transferred) — see SpaceHandleBindings.kvKeys. The result is
  /// proportional to the namespace; prefer [kvKeysPage] when its size is
  /// not bounded by this app.
  List<Uint8List> kvKeys(int namespace) => _inner.kvKeys(namespace);

  /// One page of [kvKeys]: up to [limit] keys strictly greater than
  /// [after] (`null` = start from the first key), ascending.
  List<Uint8List> kvKeysPage(int namespace, Uint8List? after, int limit) =>
      _inner.kvKeysPage(namespace, after, limit);

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

  /// Acknowledge the sticky [ffi.HvStatsInfo.hardeningFailure] — "I have shown
  /// this to the person". Clears it; nothing else does (report10 HV-04).
  void acknowledgeHardeningError() => _inner.acknowledgeHardeningError();

  /// Reclaim DataBatch chunk slots that no longer hold live log entries.
  /// Returns the count of slots scrubbed.
  int vacuumDataBatches() => _inner.vacuumDataBatches();

  /// Run the post-open forward-secrecy scrub **now**, synchronously.
  /// Returns the number of orphan index chunks reclaimed (`0` if there
  /// was nothing owed, or the container is read-only).
  ///
  /// Prefer [scheduleDeferredVacuum] unless you have a moment of your own
  /// that the unlock did not cause — the screen going off, the app being
  /// backgrounded, the first message the user sends. Calling this right
  /// after [HvSpace.open] re-creates audit HV-01 in the caller: the scrub
  /// costs time and disk writes in proportion to the space's history, it
  /// only happens when the password was right, and an observer who can see
  /// either at the moment of unlock learns that.
  int vacuumAfterOpen() => _inner.vacuumAfterOpen();

  /// Arm [vacuumAfterOpen] to run once, after a delay drawn uniformly at
  /// random from [window]. Returns the delay chosen.
  ///
  /// Already armed by [HvSpace.open] / [HvSpace.openWithKeys]; call this
  /// only to re-arm with a different window. Re-arming cancels the
  /// pending one — there is never more than one in flight — and [close]
  /// cancels it for good.
  ///
  /// The timer fires on the isolate that armed it and the scrub is a
  /// blocking FFI call, like every other method on this class; run
  /// [HvSpace] off the UI isolate, or use [HvAsyncSpace], which owns a
  /// worker.
  ///
  /// Failures are swallowed. There is nobody to report them to from a
  /// timer callback, and a scrub that could not run is the state the
  /// container was already in — the next open owes it again.
  Duration scheduleDeferredVacuum({
    DeferredVacuumWindow window = DeferredVacuumWindow.standard,
    Random? random,
  }) {
    // A window `pick` would have to clamp is the caller's error, and this
    // is a handle they hold — so it is safe to say so here.
    window.validate();
    return _deferredVacuum.arm(window, () {
      try {
        _inner.vacuumAfterOpen();
      } catch (_) {
        // Closed under us, read-only, I/O — see the doc comment.
      }
    }, random: random);
  }

  /// The delay the armed deferred scrub is waiting, or `null` if none is
  /// armed.
  Duration? get pendingVacuumDelay => _deferredVacuum.pendingDelay;

  /// Disarm the deferred scrub without running it. Use when the host is
  /// taking the job over and will call [vacuumAfterOpen] at its own
  /// moment — **not** as a way to skip it, since until something runs it
  /// the values a previous session deleted stay recoverable by anyone who
  /// later obtains the password and an old snapshot of the file.
  void cancelDeferredVacuum() => _deferredVacuum.cancel();

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
  ///
  /// Cancels any pending deferred scrub first — a timer that fires
  /// against a freed handle is a use-after-free at the FFI boundary.
  void close() {
    _deferredVacuum.cancel();
    _inner.close();
  }
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

  /// One page of [kvKeys] for space [id]: up to [limit] keys strictly
  /// greater than [after] (`null` = start from the first key).
  List<Uint8List> kvKeysPage(
          int id, int namespace, Uint8List? after, int limit) =>
      _inner.kvKeysPage(id, namespace, after, limit);

  /// Current commit sequence of space [id].
  int commitSeq(int id) => _inner.commitSeq(id);

  /// Reclaim chunks orphaned by edit/delete in space [id] (deniable scrub).
  int vacuumDataBatches(int id) => _inner.vacuumDataBatches(id);

  /// Run the post-open scrub for hosted space [id].
  ///
  /// The constant-time open deliberately leaves this undone: the scrub's
  /// duration depends on the space's history, so doing it inline made a
  /// successful open measurably longer than a failed one and undid the
  /// equalized scan (audit HV-02). Call it once unlock is complete.
  void vacuumSpace(int id) => _inner.vacuumSpace(id);

  /// Release the container lock and free the handle.
  void close() => _inner.close();
}
