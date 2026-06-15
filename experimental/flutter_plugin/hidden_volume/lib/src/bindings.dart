/// Hand-written `dart:ffi` bindings against the uniffi 0.31 C ABI
/// exported by `libhidden_volume_ffi.so` (Android), `hidden_volume_ffi.dll`
/// (Windows desktop), and the `HiddenVolumeFFI` static lib (iOS, linked
/// into the app process).
///
/// ## Why hand-written
///
/// `uniffi-bindgen-dart` 0.1.3 has runtime bugs (enum marshalling, async
/// constructor stubs). Until it stabilizes, this file binds a focused
/// MVP subset directly to the stable uniffi 0.31 C ABI. Reference for
/// the wire format: [`bindings/python/hidden_volume_ffi.py`](../../../../bindings/python/hidden_volume_ffi.py).
///
/// ## Layout
///
/// 1. uniffi runtime (RustBuffer / ForeignBytes / RustCallStatus structs +
///    rustbuffer_alloc/free/reserve/from_bytes wrappers)
/// 2. Big-endian binary reader/writer for record/sequence/optional decoding
///    (uniffi serializes everything BE on the wire)
/// 3. Function lookups + `rustCall<T>(callable)` helper that handles the
///    out-status arg and decodes typed `HvException` on CALL_ERROR
/// 4. Lift/lower for our types: ArgonPreset, WriteOp, HeaderInfo,
///    LogEntry, HvException
/// 5. Top-level `headerInfoRaw(path)` and `SpaceHandleBindings` —
///    consumed by the typed facade in [`../hidden_volume.dart`].
library;

import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

DynamicLibrary _open() {
  if (Platform.isAndroid) {
    return ffi.DynamicLibrary.open('libhidden_volume_ffi.so');
  } else if (Platform.isIOS || Platform.isMacOS) {
    return ffi.DynamicLibrary.process();
  } else if (Platform.isLinux) {
    return ffi.DynamicLibrary.open('libhidden_volume_ffi.so');
  } else if (Platform.isWindows) {
    return ffi.DynamicLibrary.open('hidden_volume_ffi.dll');
  } else {
    throw UnsupportedError(
        'hidden_volume: unsupported platform ${Platform.operatingSystem}');
  }
}

ffi.DynamicLibrary _dylib = _open();

/// Override the dylib lookup. Must be called before any FFI use.
/// Used by the smoke test and by host-app integration tests that bundle
/// the cdylib at a non-standard path.
void overrideDylib(ffi.DynamicLibrary lib) {
  _dylib = lib;
}

typedef DynamicLibrary = ffi.DynamicLibrary;

// ------------------------------------------------------------------
// 1. uniffi runtime structs (matches uniffi_core::ffi layout)
// ------------------------------------------------------------------

/// Owned-by-Rust byte buffer. Returned/consumed by every uniffi call
/// that exchanges variable-width data. Memory lives in Rust's allocator;
/// always free via `_rustbufferFree` after consuming.
final class RustBuffer extends ffi.Struct {
  @ffi.Uint64()
  external int capacity;
  @ffi.Uint64()
  external int len;
  external ffi.Pointer<ffi.Uint8> data;
}

/// Foreign (Dart-owned) byte view passed into Rust for `rustbuffer_from_bytes`.
final class ForeignBytes extends ffi.Struct {
  @ffi.Int32()
  external int len;
  external ffi.Pointer<ffi.Uint8> data;
}

/// Rust→foreign call status. uniffi convention: every fallible function
/// takes a trailing `*mut RustCallStatus` out-arg. Status code is i8:
///   0 = CALL_SUCCESS
///   1 = CALL_ERROR (typed exception; payload in error_buf)
///   2 = CALL_UNEXPECTED_ERROR (Rust panic; error_buf may have a string)
final class RustCallStatus extends ffi.Struct {
  @ffi.Int8()
  external int code;
  external RustBuffer errorBuf;
}

const int _callSuccess = 0;
const int _callError = 1;
const int _callUnexpectedError = 2;

// ------------------------------------------------------------------
// 2. uniffi runtime function lookups
// ------------------------------------------------------------------

final _rustbufferFromBytes = _dylib.lookupFunction<
    RustBuffer Function(ForeignBytes, ffi.Pointer<RustCallStatus>),
    RustBuffer Function(ForeignBytes, ffi.Pointer<RustCallStatus>)>(
    'ffi_hidden_volume_ffi_rustbuffer_from_bytes');

final _rustbufferFree = _dylib.lookupFunction<
    ffi.Void Function(RustBuffer, ffi.Pointer<RustCallStatus>),
    void Function(RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'ffi_hidden_volume_ffi_rustbuffer_free');

final _contractVersion = _dylib.lookupFunction<ffi.Uint32 Function(),
    int Function()>('ffi_hidden_volume_ffi_uniffi_contract_version');

/// Reads the contract version baked into the cdylib at compile time.
/// uniffi 0.31 = 30. Mismatch with our hardcoded expectation would mean
/// the cdylib was built with a different uniffi minor and the wire
/// format may have shifted.
int contractVersion() => _contractVersion();

const int _expectedContractVersion = 30;

void _ensureAbiCompatible() {
  final v = _contractVersion();
  if (v != _expectedContractVersion) {
    throw StateError(
        'uniffi contract version mismatch: cdylib reports $v, bindings expect $_expectedContractVersion. '
        'Rebuild hidden-volume-ffi against uniffi 0.31.');
  }
}

bool _abiChecked = false;
void _ensureChecked() {
  if (!_abiChecked) {
    _ensureAbiCompatible();
    _abiChecked = true;
  }
}

// ------------------------------------------------------------------
// 3. Call helper: handles status + lifts typed errors
// ------------------------------------------------------------------

T rustCall<T>(T Function(ffi.Pointer<RustCallStatus>) body) {
  _ensureChecked();
  final statusPtr = calloc<RustCallStatus>();
  try {
    statusPtr.ref.code = _callSuccess;
    statusPtr.ref.errorBuf
      ..capacity = 0
      ..len = 0
      ..data = ffi.nullptr;
    final result = body(statusPtr);
    final code = statusPtr.ref.code;
    if (code == _callSuccess) {
      return result;
    }
    final errBuf = statusPtr.ref.errorBuf;
    try {
      if (code == _callError) {
        throw _liftHvException(errBuf);
      } else if (code == _callUnexpectedError) {
        // Rust panic. Buffer holds a String (i32 BE len + utf8) describing
        // the panic.
        final msg = _decodeErrorString(errBuf);
        throw HvException(
            'InternalPanic', msg.isEmpty ? 'rust panic (no message)' : msg);
      } else {
        throw StateError('unknown uniffi call status code: $code');
      }
    } finally {
      _freeBuffer(errBuf);
    }
  } finally {
    calloc.free(statusPtr);
  }
}

void _freeBuffer(RustBuffer buf) {
  if (buf.data == ffi.nullptr && buf.len == 0 && buf.capacity == 0) {
    return;
  }
  final s = calloc<RustCallStatus>();
  try {
    s.ref.code = _callSuccess;
    s.ref.errorBuf
      ..capacity = 0
      ..len = 0
      ..data = ffi.nullptr;
    _rustbufferFree(buf, s);
  } finally {
    calloc.free(s);
  }
}

String _decodeErrorString(RustBuffer buf) {
  if (buf.len == 0 || buf.data == ffi.nullptr) return '';
  // CALL_UNEXPECTED_ERROR payload: just utf8 (no length prefix).
  return utf8.decode(buf.data.asTypedList(buf.len));
}

// ------------------------------------------------------------------
// 4. Big-endian binary reader/writer
// ------------------------------------------------------------------

/// Streaming reader over a borrowed byte view. Caller owns the underlying
/// buffer; this just holds a ByteData view + offset. uniffi serializes
/// multi-byte ints as **big-endian**.
class _Reader {
  _Reader(this._bytes) : _data = ByteData.sublistView(_bytes);
  final Uint8List _bytes;
  final ByteData _data;
  int _pos = 0;
  int get remaining => _bytes.length - _pos;

  int readU8() => _data.getUint8(_pos++);
  int readI32() {
    final v = _data.getInt32(_pos, Endian.big);
    _pos += 4;
    return v;
  }

  int readU32() {
    final v = _data.getUint32(_pos, Endian.big);
    _pos += 4;
    return v;
  }

  int readU64() {
    final v = _data.getUint64(_pos, Endian.big);
    _pos += 8;
    return v;
  }

  Uint8List readBytes(int n) {
    final out = Uint8List.sublistView(_bytes, _pos, _pos + n);
    _pos += n;
    return out;
  }

  String readString() {
    final len = readI32();
    if (len < 0) {
      throw StateError('negative string length');
    }
    return utf8.decode(readBytes(len));
  }

  Uint8List readByteVec() {
    final len = readI32();
    if (len < 0) {
      throw StateError('negative byte-vec length');
    }
    return Uint8List.fromList(readBytes(len));
  }
}

/// Streaming writer that appends BE-encoded primitives to a growing
/// `BytesBuilder`. Caller calls `.toBytes()` once and then
/// `_bufferFromBytes(...)` to hand it to Rust.
class _Writer {
  final BytesBuilder _b = BytesBuilder(copy: false);
  Uint8List toBytes() => _b.toBytes();

  void writeU8(int v) => _b.addByte(v & 0xff);

  void writeI32(int v) {
    final bd = ByteData(4)..setInt32(0, v, Endian.big);
    _b.add(bd.buffer.asUint8List());
  }

  void writeU32(int v) {
    final bd = ByteData(4)..setUint32(0, v, Endian.big);
    _b.add(bd.buffer.asUint8List());
  }

  void writeU64(int v) {
    final bd = ByteData(8)..setUint64(0, v, Endian.big);
    _b.add(bd.buffer.asUint8List());
  }

  void writeRaw(Uint8List bytes) => _b.add(bytes);

  void writeString(String s) {
    final bytes = utf8.encode(s);
    writeI32(bytes.length);
    writeRaw(bytes);
  }

  void writeByteVec(Uint8List bytes) {
    writeI32(bytes.length);
    writeRaw(bytes);
  }
}

// ------------------------------------------------------------------
// 5. RustBuffer ↔ Dart Uint8List
// ------------------------------------------------------------------

/// Move a Dart byte buffer into a Rust-owned [RustBuffer] verbatim
/// (no framing). Use this for:
///   * `String` arguments — uniffi reads them as `&str` from the
///     buffer's full extent (no internal length prefix)
///   * Pre-encoded payloads from a [_Writer] (records, enums,
///     sequences — already self-framed via internal `i32` lengths).
///
/// For `Vec<u8>` arguments use [_bufferFromByteVec] which prepends the
/// uniffi-required `i32` BE length prefix that the Rust deserializer
/// reads before consuming the bytes.
RustBuffer _bufferFromBytes(Uint8List src) {
  return rustCall<RustBuffer>((status) {
    final tmp = src.isEmpty
        ? calloc<ffi.Uint8>(1) // calloc(0) UB on some libcs
        : calloc<ffi.Uint8>(src.length);
    try {
      if (src.isNotEmpty) {
        tmp.asTypedList(src.length).setAll(0, src);
      }
      final fb = calloc<ForeignBytes>();
      try {
        fb.ref
          ..len = src.length
          ..data = tmp;
        return _rustbufferFromBytes(fb.ref, status);
      } finally {
        calloc.free(fb);
      }
    } finally {
      calloc.free(tmp);
    }
  });
}

/// Wrap a `Vec<u8>` argument in the framing the uniffi Rust-side
/// deserializer expects: `i32` BE length + raw bytes. Use for any FFI
/// arg whose Rust type is `Vec<u8>` (passwords, KV keys/values).
RustBuffer _bufferFromByteVec(Uint8List src) {
  final w = _Writer()..writeByteVec(src);
  return _bufferFromBytes(w.toBytes());
}

/// Copy a Rust-owned buffer's contents into a fresh Dart byte list, then
/// free the Rust buffer. Safe to call regardless of buf.len / data state.
Uint8List _bufferToBytes(RustBuffer buf) {
  try {
    if (buf.len == 0 || buf.data == ffi.nullptr) return Uint8List(0);
    return Uint8List.fromList(buf.data.asTypedList(buf.len));
  } finally {
    _freeBuffer(buf);
  }
}

// ------------------------------------------------------------------
// 6. Typed Dart enums / records (mirrors of FFI types)
// ------------------------------------------------------------------

/// Argon2id cost preset. Maps to the uniffi enum tags 1..=4. Pick one
/// at `SpaceHandle.create` time — baked into the container header.
enum ArgonPreset {
  /// Test-only minimum — DO NOT use in production.
  min(1),

  /// Cortex-A53 class low-end ARM (~30 ms unlock).
  light(2),

  /// Mid-range / flagship phones (~100 ms unlock).
  defaults(3),

  /// Desktop / server-class (~250 ms unlock).
  heavy(4);

  const ArgonPreset(this.tag);
  final int tag;

  RustBuffer _toRustBuffer() {
    final w = _Writer()..writeI32(tag);
    return _bufferFromBytes(w.toBytes());
  }
}

/// Post-commit padding policy preset. Maps to uniffi enum tags 1..=4.
/// Auto-restored from header on each open — manual override only needed
/// when host wants to differ from the create-time choice or to recover
/// from a tampered (unauthenticated by design) cleartext byte.
enum PaddingPreset {
  /// No post-commit padding. Privacy degrades vs multi-snapshot.
  none(1),

  /// 256 KiB buckets — embedded / very weak phones.
  bucket256KiB(2),

  /// 1 MiB buckets — recommended default for typical mobile.
  bucket1MiB(3),

  /// 16 MiB buckets — desktop / unconstrained storage.
  bucket16MiB(4);

  const PaddingPreset(this.tag);
  final int tag;

  RustBuffer _toRustBuffer() {
    final w = _Writer()..writeI32(tag);
    return _bufferFromBytes(w.toBytes());
  }
}

/// One mutation in a [SpaceHandleBindings.commit] batch. Mirror of the
/// Rust `WriteOp` enum (variant tags 1=Put, 2=Delete, 3=AppendLog).
sealed class HvWriteOp {
  const HvWriteOp();
  void _write(_Writer w);
}

/// Insert or replace a KV entry in `namespace`.
final class HvWriteOpPut extends HvWriteOp {
  const HvWriteOpPut(
      {required this.namespace, required this.key, required this.value});
  final int namespace;
  final Uint8List key;
  final Uint8List value;

  @override
  void _write(_Writer w) {
    w
      ..writeI32(1)
      ..writeU8(namespace)
      ..writeByteVec(key)
      ..writeByteVec(value);
  }
}

/// Delete a KV entry. No-op if absent.
final class HvWriteOpDelete extends HvWriteOp {
  const HvWriteOpDelete({required this.namespace, required this.key});
  final int namespace;
  final Uint8List key;

  @override
  void _write(_Writer w) {
    w
      ..writeI32(2)
      ..writeU8(namespace)
      ..writeByteVec(key);
  }
}

/// Append one log entry into a DataBatch chunk.
final class HvWriteOpAppendLog extends HvWriteOp {
  const HvWriteOpAppendLog(
      {required this.namespace,
      required this.logId,
      required this.payload});
  final int namespace;
  final int logId;
  final Uint8List payload;

  @override
  void _write(_Writer w) {
    w
      ..writeI32(3)
      ..writeU8(namespace)
      ..writeU64(logId)
      ..writeByteVec(payload);
  }
}

RustBuffer _writeOpsToBuffer(List<HvWriteOp> ops) {
  final w = _Writer()..writeI32(ops.length);
  for (final op in ops) {
    op._write(w);
  }
  return _bufferFromBytes(w.toBytes());
}

/// Plaintext header info. Readable without a password.
///
/// **v3 layout (2026-05-28).** The 32-byte `containerIdHex` field
/// that existed in v2 is gone. v3 derives `container_id` per-space
/// from the versioned master key (see Rust [`SpaceKeys::from_master`])
/// — no per-space identifier sits in the cleartext header any more.
/// The wire format here mirrors `HeaderInfo` in [`crates/hidden-volume-ffi/src/lib.rs`].
class HvHeaderInfo {
  const HvHeaderInfo({
    required this.saltHex,
    required this.argonMCostKib,
    required this.argonTCost,
    required this.argonPCost,
    required this.fileSizeBytes,
  });
  final String saltHex;
  final int argonMCostKib;
  final int argonTCost;
  final int argonPCost;
  final int fileSizeBytes;

  @override
  String toString() =>
      'HvHeaderInfo(salt=${saltHex.substring(0, 16)}…, '
      'argon(m=$argonMCostKib t=$argonTCost p=$argonPCost), size=${fileSizeBytes}B)';
}

HvHeaderInfo _readHeaderInfo(Uint8List bytes) {
  final r = _Reader(bytes);
  return HvHeaderInfo(
    saltHex: r.readString(),
    argonMCostKib: r.readU32(),
    argonTCost: r.readU32(),
    argonPCost: r.readU32(),
    fileSizeBytes: r.readU64(),
  );
}

/// One log entry returned by [SpaceHandleBindings.iterLogRange].
class HvLogEntry {
  const HvLogEntry({required this.logId, required this.payload});
  final int logId;
  final Uint8List payload;
}

List<HvLogEntry> _readLogEntries(Uint8List bytes) {
  final r = _Reader(bytes);
  final n = r.readI32();
  if (n < 0) throw StateError('negative sequence length');
  return [
    for (var i = 0; i < n; i++)
      HvLogEntry(logId: r.readU64(), payload: r.readByteVec()),
  ];
}

List<int> _readU64Sequence(Uint8List bytes) {
  final r = _Reader(bytes);
  final n = r.readI32();
  if (n < 0) throw StateError('negative sequence length');
  return [for (var i = 0; i < n; i++) r.readU64()];
}

/// Result of [SpaceHandleBindings.verifyIntegrity] — counts the
/// namespaces/chunks walked plus the deepest B+ tree level reached.
///
/// **Wire layout** mirrors `IntegrityResult` in
/// [`crates/hidden-volume-ffi/src/lib.rs`]:
/// `namespaces_verified (u64) ‖ chunks_verified (u64) ‖
/// max_depth (u32) ‖ data_batches_verified (u64)`. The
/// `dataBatchesVerified` field was added in audit pass 18 M2
/// (2026-05-10) — it counts the `DataBatch` chunks that were
/// AEAD-decrypted and `decode_batch`-validated as part of the
/// Merkle walk; prior to M2, those chunks were silently skipped.
class HvIntegrityResult {
  const HvIntegrityResult({
    required this.namespacesVerified,
    required this.chunksVerified,
    required this.maxDepth,
    required this.dataBatchesVerified,
  });
  final int namespacesVerified;
  final int chunksVerified;
  final int maxDepth;
  final int dataBatchesVerified;

  @override
  String toString() =>
      'HvIntegrityResult(namespaces=$namespacesVerified, chunks=$chunksVerified, '
      'depth=$maxDepth, batches=$dataBatchesVerified)';
}

HvIntegrityResult _readIntegrity(Uint8List bytes) {
  final r = _Reader(bytes);
  return HvIntegrityResult(
    namespacesVerified: r.readU64(),
    chunksVerified: r.readU64(),
    maxDepth: r.readU32(),
    dataBatchesVerified: r.readU64(),
  );
}

/// One row of [HvStatsInfo.namespaceCounts].
class HvNamespaceCount {
  const HvNamespaceCount({required this.namespace, required this.count});
  final int namespace;
  final int count;
}

/// Aggregated per-space stats. Mirror of `SpaceStats` flattened for FFI.
class HvStatsInfo {
  const HvStatsInfo({
    required this.commitSeq,
    required this.commitHistoryLen,
    required this.ownedChunkCount,
    required this.totalSlotCount,
    required this.totalEntries,
    required this.namespaceCounts,
  });
  final int commitSeq;
  final int commitHistoryLen;
  final int ownedChunkCount;
  final int totalSlotCount;
  final int totalEntries;
  final List<HvNamespaceCount> namespaceCounts;

  /// Convenience: fraction of allocated slots that hold owned (live)
  /// chunks. Drives host-app `compact_known` triggers.
  ///
  /// Returns `0.0` for an empty container (no slots), matching the
  /// Rust-side semantics of `SpaceStats::utilization_ratio` —
  /// see [`crates/hidden-volume/src/space/mod.rs`]. Earlier Dart
  /// drafts returned `1.0` here; that disagreed with the FFI/Rust
  /// contract and could mislead compact-trigger heuristics.
  double utilizationRatio() =>
      totalSlotCount == 0 ? 0.0 : ownedChunkCount / totalSlotCount;
}

HvStatsInfo _readStats(Uint8List bytes) {
  final r = _Reader(bytes);
  final commitSeq = r.readU64();
  final commitHistoryLen = r.readU64();
  final ownedChunkCount = r.readU64();
  final totalSlotCount = r.readU64();
  final totalEntries = r.readU64();
  final n = r.readI32();
  if (n < 0) throw StateError('negative sequence length');
  final counts = <HvNamespaceCount>[
    for (var i = 0; i < n; i++)
      HvNamespaceCount(namespace: r.readU8(), count: r.readU64()),
  ];
  return HvStatsInfo(
    commitSeq: commitSeq,
    commitHistoryLen: commitHistoryLen,
    ownedChunkCount: ownedChunkCount,
    totalSlotCount: totalSlotCount,
    totalEntries: totalEntries,
    namespaceCounts: counts,
  );
}

/// One mapping for [changePasswords]. `oldPwd == newPwd` preserves the
/// space verbatim. Spaces NOT mentioned are **dropped** by the rewrite —
/// list every space you want to keep (use `oldPwd == newPwd` for a
/// no-op rotation when keeping a hidden space).
class HvPasswordRotation {
  const HvPasswordRotation({required this.oldPwd, required this.newPwd});
  final Uint8List oldPwd;
  final Uint8List newPwd;
}

RustBuffer _writeRotations(List<HvPasswordRotation> rotations) {
  final w = _Writer()..writeI32(rotations.length);
  for (final r in rotations) {
    w
      ..writeByteVec(r.oldPwd)
      ..writeByteVec(r.newPwd);
  }
  return _bufferFromBytes(w.toBytes());
}

RustBuffer _writeBytesSequence(List<Uint8List> items) {
  final w = _Writer()..writeI32(items.length);
  for (final b in items) {
    w.writeByteVec(b);
  }
  return _bufferFromBytes(w.toBytes());
}

/// Decode `Option<Vec<u8>>`: 1 byte tag + (Some) i32 BE len + bytes.
Uint8List? _readOptByteVec(Uint8List bytes) {
  if (bytes.isEmpty) {
    throw StateError('uniffi: empty Option<Bytes> buffer');
  }
  final r = _Reader(bytes);
  final tag = r.readU8();
  if (tag == 0) return null;
  if (tag != 1) {
    throw StateError('uniffi: unexpected Option tag $tag');
  }
  return r.readByteVec();
}

/// FFI exception. `kind` is the discriminant from `hidden_volume::Error`
/// (one of "Io", "AuthFailed", "SpaceAlreadyExists", "Busy", "ReadOnly",
/// "Malformed", "Kdf", "Internal", "PayloadTooLarge", "IndexFull",
/// "Compression", "Cancelled", "WrongNamespaceKind", "TooManyNamespaces",
/// "IntegrityFailure", or "InternalPanic" for an unexpected Rust panic).
class HvException implements Exception {
  HvException(this.kind, this.message);
  final String kind;
  final String message;

  @override
  String toString() => 'HvException.$kind: $message';
}

const _hvErrorKinds = <String>[
  '<reserved-zero>', // variant 0 unused; uniffi tags start at 1
  'Io',
  'AuthFailed',
  'SpaceAlreadyExists',
  'Busy',
  'ReadOnly',
  'Malformed',
  'Kdf',
  'Internal',
  'PayloadTooLarge',
  'IndexFull',
  'Compression',
  'Cancelled',
  'WrongNamespaceKind',
  'TooManyNamespaces',
  'IntegrityFailure',
  'ContainerTooLarge',
];

HvException _liftHvException(RustBuffer buf) {
  final bytes = buf.len == 0 || buf.data == ffi.nullptr
      ? Uint8List(0)
      : Uint8List.fromList(buf.data.asTypedList(buf.len));
  if (bytes.isEmpty) {
    return HvException('Unknown', 'empty error buffer');
  }
  final r = _Reader(bytes);
  final variant = r.readI32();
  final msg = r.remaining > 0 ? r.readString() : '';
  final kind = (variant >= 1 && variant < _hvErrorKinds.length)
      ? _hvErrorKinds[variant]
      : 'Unknown($variant)';
  return HvException(kind, msg);
}

// ------------------------------------------------------------------
// 7. Top-level functions
// ------------------------------------------------------------------

final _fnHeaderInfo = _dylib.lookupFunction<
    RustBuffer Function(RustBuffer, ffi.Pointer<RustCallStatus>),
    RustBuffer Function(RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_func_header_info');

final _fnChangePasswords = _dylib.lookupFunction<
    ffi.Void Function(
        RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>),
    void Function(
        RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_func_change_passwords');

final _fnCompactKnown = _dylib.lookupFunction<
    ffi.Void Function(
        RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>),
    void Function(
        RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_func_compact_known');

/// Inspect plaintext header (salt, Argon params, size). v3
/// (2026-05-28) removed `container_id` from the cleartext header —
/// it is now per-space derived from the versioned master key.
/// Throws [HvException.Io] / [HvException.Malformed] on bad files.
HvHeaderInfo headerInfo(String path) {
  final pathBuf = _bufferFromBytes(utf8.encode(path));
  final out = rustCall<RustBuffer>((s) => _fnHeaderInfo(pathBuf, s));
  return _readHeaderInfo(_bufferToBytes(out));
}

/// In-place password rotation. Each entry maps `old → new`. Spaces NOT
/// listed are **dropped** by the rewrite — to keep a hidden space pass
/// `oldPwd == newPwd` for it.
///
/// Holds `LOCK_EX` on [path] for the entire rewrite. Throws
/// [HvException] with `kind == "Busy"` if any other process / handle
/// has the file open.
void changePasswords(String path, List<HvPasswordRotation> rotations) {
  final pathBuf = _bufferFromBytes(utf8.encode(path));
  final rotBuf = _writeRotations(rotations);
  rustCall<void>((s) {
    _fnChangePasswords(pathBuf, rotBuf, s);
  });
}

/// In-place compact, keeping only spaces unlocked by [passwords].
/// Anything not unlocked is permanently destroyed by the rewrite —
/// including hidden spaces whose passwords aren't listed. Use
/// [changePasswords] (with `oldPwd == newPwd` per kept space) when the
/// caller wants to preserve hidden spaces without naming them.
void compactKnown(String path, List<Uint8List> passwords) {
  final pathBuf = _bufferFromBytes(utf8.encode(path));
  final pwdsBuf = _writeBytesSequence(passwords);
  rustCall<void>((s) {
    _fnCompactKnown(pathBuf, pwdsBuf, s);
  });
}

// ------------------------------------------------------------------
// 8. SpaceHandle (sync)
// ------------------------------------------------------------------

final _spCreate = _dylib.lookupFunction<
    ffi.Uint64 Function(RustBuffer, RustBuffer, RustBuffer, ffi.Uint64,
        ffi.Uint8, ffi.Pointer<RustCallStatus>),
    int Function(RustBuffer, RustBuffer, RustBuffer, int, int,
        ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_constructor_spacehandle_create');

final _spOpen = _dylib.lookupFunction<
    ffi.Uint64 Function(
        RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>),
    int Function(RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_constructor_spacehandle_open');

// Same wire shape as `open` (path, password) -> handle; adds a new parallel
// space to an existing container instead of opening one.
final _spAddSpace = _dylib.lookupFunction<
    ffi.Uint64 Function(
        RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>),
    int Function(RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_constructor_spacehandle_add_space');

// Same wire shape as `open` (path, keys) -> handle; opens a space from
// pre-derived SpaceKeys (64 opaque bytes) instead of a password — the
// master-space path.
final _spOpenWithKeys = _dylib.lookupFunction<
    ffi.Uint64 Function(
        RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>),
    int Function(RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_constructor_spacehandle_open_with_keys');

final _spFree = _dylib.lookupFunction<
    ffi.Void Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
    void Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_free_spacehandle');

final _spClone = _dylib.lookupFunction<
    ffi.Uint64 Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
    int Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_clone_spacehandle');

final _spCommit = _dylib.lookupFunction<
    ffi.Uint64 Function(
        ffi.Uint64, RustBuffer, ffi.Pointer<RustCallStatus>),
    int Function(int, RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_commit');

final _spGet = _dylib.lookupFunction<
    RustBuffer Function(
        ffi.Uint64, ffi.Uint8, RustBuffer, ffi.Pointer<RustCallStatus>),
    RustBuffer Function(
        int, int, RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_get');

final _spIterLogRange = _dylib.lookupFunction<
    RustBuffer Function(ffi.Uint64, ffi.Uint8, RustBuffer, RustBuffer,
        ffi.Uint32, ffi.Pointer<RustCallStatus>),
    RustBuffer Function(int, int, RustBuffer, RustBuffer, int,
        ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_iter_log_range');

final _spCommitSeq = _dylib.lookupFunction<
    ffi.Uint64 Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
    int Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_commit_seq');

final _spCommitHistory = _dylib.lookupFunction<
    RustBuffer Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
    RustBuffer Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_commit_history');

final _spCount = _dylib.lookupFunction<
    ffi.Uint64 Function(
        ffi.Uint64, ffi.Uint8, ffi.Pointer<RustCallStatus>),
    int Function(int, int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_count');

final _spEraseNs = _dylib.lookupFunction<
    ffi.Uint64 Function(
        ffi.Uint64, ffi.Uint8, ffi.Pointer<RustCallStatus>),
    int Function(int, int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_erase_namespace');

final _spReadLog = _dylib.lookupFunction<
    RustBuffer Function(
        ffi.Uint64, ffi.Uint8, ffi.Uint64, ffi.Pointer<RustCallStatus>),
    RustBuffer Function(
        int, int, int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_read_log');

final _spListNamespaces = _dylib.lookupFunction<
    RustBuffer Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
    RustBuffer Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_list_namespaces');

final _spSetPaddingPolicy = _dylib.lookupFunction<
    ffi.Void Function(
        ffi.Uint64, RustBuffer, ffi.Pointer<RustCallStatus>),
    void Function(int, RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_set_padding_policy');

final _spStats = _dylib.lookupFunction<
    RustBuffer Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
    RustBuffer Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_stats');

final _spVacuumDataBatches = _dylib.lookupFunction<
    ffi.Uint64 Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
    int Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_vacuum_data_batches');

// (handle) -> Vec<u8> (the 64-byte SpaceKeys export). Same wire shape as
// list_namespaces / commit_history (u64 -> RustBuffer).
final _spSpaceKeys = _dylib.lookupFunction<
    RustBuffer Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
    RustBuffer Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_space_keys');

final _spVerifyIntegrity = _dylib.lookupFunction<
    RustBuffer Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
    RustBuffer Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_verify_integrity');

/// Encode an `Option<u64>` as: 1 byte tag (0=None, 1=Some) + (if Some) u64 BE.
RustBuffer _optU64(int? v) {
  final w = _Writer();
  if (v == null) {
    w.writeU8(0);
  } else {
    w.writeU8(1);
    w.writeU64(v);
  }
  return _bufferFromBytes(w.toBytes());
}

/// Low-level wrapper over the uniffi-exported `SpaceHandle` symbols.
/// The typed facade in [`../hidden_volume.dart`] adds resource-management
/// (close-on-finalize) and idiomatic naming on top.
class SpaceHandleBindings {
  SpaceHandleBindings._(this._handle) {
    _finalizer.attach(this, _handle, detach: this);
  }

  final int _handle;
  bool _closed = false;

  static SpaceHandleBindings create({
    required String path,
    required Uint8List password,
    required ArgonPreset argon,
    int initialGarbageChunks = 0,
    int superblockReplicas = 3,
  }) {
    final pathBuf = _bufferFromBytes(utf8.encode(path));
    final pwdBuf = _bufferFromByteVec(password);
    final argonBuf = argon._toRustBuffer();
    final h = rustCall<int>((s) => _spCreate(
        pathBuf, pwdBuf, argonBuf, initialGarbageChunks, superblockReplicas, s));
    return SpaceHandleBindings._(h);
  }

  static SpaceHandleBindings open({
    required String path,
    required Uint8List password,
  }) {
    final pathBuf = _bufferFromBytes(utf8.encode(path));
    final pwdBuf = _bufferFromByteVec(password);
    final h = rustCall<int>((s) => _spOpen(pathBuf, pwdBuf, s));
    return SpaceHandleBindings._(h);
  }

  /// Add a new parallel, deniable space to an existing container (the
  /// multi-identity primitive). Throws `SpaceAlreadyExists` if [password]
  /// already maps to a space here.
  static SpaceHandleBindings addSpace({
    required String path,
    required Uint8List password,
  }) {
    final pathBuf = _bufferFromBytes(utf8.encode(path));
    final pwdBuf = _bufferFromByteVec(password);
    final h = rustCall<int>((s) => _spAddSpace(pathBuf, pwdBuf, s));
    return SpaceHandleBindings._(h);
  }

  /// Open a space from pre-derived [keys] (64 opaque bytes from [spaceKeys])
  /// instead of a password — the master-space path. Throws `Malformed` if
  /// [keys] is not 64 bytes, `AuthFailed` if they match no space.
  static SpaceHandleBindings openWithKeys({
    required String path,
    required Uint8List keys,
  }) {
    final pathBuf = _bufferFromBytes(utf8.encode(path));
    final keysBuf = _bufferFromByteVec(keys);
    final h = rustCall<int>((s) => _spOpenWithKeys(pathBuf, keysBuf, s));
    return SpaceHandleBindings._(h);
  }

  void _ensureOpen() {
    if (_closed) {
      throw StateError('SpaceHandle is closed');
    }
  }

  /// uniffi 0.31 method-call convention: methods CONSUME the passed
  /// handle (drop the underlying `Arc`). Clone before every call so
  /// the wrapper retains a live reference for subsequent calls and
  /// for the eventual `close()` → `_spFree`.
  int _cloneHandle() {
    return rustCall<int>((s) => _spClone(_handle, s));
  }

  /// Apply a batch of writes atomically. Returns the new commit_seq.
  int commit(List<HvWriteOp> ops) {
    _ensureOpen();
    final buf = _writeOpsToBuffer(ops);
    final h = _cloneHandle();
    return rustCall<int>((s) => _spCommit(h, buf, s));
  }

  /// Read a value, or null if absent. Throws on AuthFailed / Io / etc.
  Uint8List? get(int namespace, Uint8List key) {
    _ensureOpen();
    final keyBuf = _bufferFromByteVec(key);
    final h = _cloneHandle();
    final out = rustCall<RustBuffer>((s) => _spGet(h, namespace, keyBuf, s));
    final bytes = _bufferToBytes(out);
    if (bytes.isEmpty) {
      // uniffi encodes Option<Vec<u8>> as: u8 tag + (Some) bytes.
      // Empty buffer would be a protocol error; an absent value gets a
      // non-empty buffer with leading 0x00 tag.
      throw StateError('uniffi: empty Option<Bytes> buffer');
    }
    final r = _Reader(bytes);
    final tag = r.readU8();
    if (tag == 0) return null;
    if (tag != 1) {
      throw StateError('uniffi: unexpected Option tag $tag');
    }
    return r.readByteVec();
  }

  /// Read a contiguous range of log entries, capped at `limit`.
  /// `start`/`end` are u64 log_ids; null means open-ended.
  List<HvLogEntry> iterLogRange({
    required int namespace,
    int? start,
    int? end,
    required int limit,
  }) {
    _ensureOpen();
    final startBuf = _optU64(start);
    final endBuf = _optU64(end);
    final h = _cloneHandle();
    final out = rustCall<RustBuffer>(
        (s) => _spIterLogRange(h, namespace, startBuf, endBuf, limit, s));
    return _readLogEntries(_bufferToBytes(out));
  }

  /// Current commit sequence (incremented per successful commit chunk).
  int commitSeq() {
    _ensureOpen();
    final h = _cloneHandle();
    return rustCall<int>((s) => _spCommitSeq(h, s));
  }

  /// Recoverable commit-anchor history. Used by host-app sync layer to
  /// detect rollback (see `MULTI_DEVICE.md`).
  List<int> commitHistory() {
    _ensureOpen();
    final h = _cloneHandle();
    final out = rustCall<RustBuffer>((s) => _spCommitHistory(h, s));
    return _readU64Sequence(_bufferToBytes(out));
  }

  /// Number of KV entries in [namespace]. O(N) — walks the index.
  int count(int namespace) {
    _ensureOpen();
    final h = _cloneHandle();
    return rustCall<int>((s) => _spCount(h, namespace, s));
  }

  /// Drop all entries in [namespace] and zero the index root. Returns
  /// the new commit_seq.
  int eraseNamespace(int namespace) {
    _ensureOpen();
    final h = _cloneHandle();
    return rustCall<int>((s) => _spEraseNs(h, namespace, s));
  }

  /// Read one log entry by `(namespace, logId)`. Returns null if absent.
  Uint8List? readLog(int namespace, int logId) {
    _ensureOpen();
    final h = _cloneHandle();
    final out = rustCall<RustBuffer>(
        (s) => _spReadLog(h, namespace, logId, s));
    return _readOptByteVec(_bufferToBytes(out));
  }

  /// All namespace tags currently in use. Returned as raw bytes (one
  /// `u8` per namespace) — small footprint, no per-element framing.
  Uint8List listNamespaces() {
    _ensureOpen();
    final h = _cloneHandle();
    final out = rustCall<RustBuffer>((s) => _spListNamespaces(h, s));
    final bytes = _bufferToBytes(out);
    // The wire format is `i32 BE len + bytes` (Vec<u8>).
    final r = _Reader(bytes);
    return r.readByteVec();
  }

  /// Override the post-commit padding policy. Auto-restored from header
  /// on each open — manual override only needed when host wants to
  /// differ from the create-time choice or to recover from tampered
  /// (unauthenticated) header byte.
  void setPaddingPolicy(PaddingPreset preset) {
    _ensureOpen();
    final buf = preset._toRustBuffer();
    final h = _cloneHandle();
    rustCall<void>((s) {
      _spSetPaddingPolicy(h, buf, s);
    });
  }

  /// Aggregated stats: commit_seq, history depth, slot utilization,
  /// per-namespace entry counts. Drives host-app `compact_known`
  /// triggers.
  HvStatsInfo stats() {
    _ensureOpen();
    final h = _cloneHandle();
    final out = rustCall<RustBuffer>((s) => _spStats(h, s));
    return _readStats(_bufferToBytes(out));
  }

  /// Reclaim DataBatch chunk slots that no longer have any live
  /// log entries. Returns the count of slots scrubbed.
  int vacuumDataBatches() {
    _ensureOpen();
    final h = _cloneHandle();
    return rustCall<int>((s) => _spVacuumDataBatches(h, s));
  }

  /// Export this space's `SpaceKeys` as 64 opaque bytes for a master roster.
  /// **Sensitive** — keep only inside another deniable space, never log.
  Uint8List spaceKeys() {
    _ensureOpen();
    final h = _cloneHandle();
    final out = rustCall<RustBuffer>((s) => _spSpaceKeys(h, s));
    // Wire format `i32 BE len + bytes` (Vec<u8>), same as listNamespaces.
    return _Reader(_bufferToBytes(out)).readByteVec();
  }

  /// Walk every chunk owned by this space, AEAD-decrypting and
  /// re-checking Merkle nodes. Returns counts on success; throws
  /// [HvException] with `kind == "IntegrityFailure"` on any mismatch.
  HvIntegrityResult verifyIntegrity() {
    _ensureOpen();
    final h = _cloneHandle();
    final out = rustCall<RustBuffer>((s) => _spVerifyIntegrity(h, s));
    return _readIntegrity(_bufferToBytes(out));
  }

  /// Release the file lock and Rust-side resources. Idempotent.
  void close() {
    if (_closed) return;
    _closed = true;
    _finalizer.detach(this);
    rustCall<void>((s) {
      _spFree(_handle, s);
    });
  }

  /// Auto-cleanup on GC: if the wrapper is collected without [close],
  /// free the handle from the finalizer thread. Best-effort — host-apps
  /// SHOULD call [close] explicitly to release the file lock promptly.
  static final Finalizer<int> _finalizer = Finalizer<int>((handle) {
    final s = calloc<RustCallStatus>();
    try {
      s.ref.code = _callSuccess;
      s.ref.errorBuf
        ..capacity = 0
        ..len = 0
        ..data = ffi.nullptr;
      _spFree(handle, s);
    } finally {
      calloc.free(s);
    }
  });
}
