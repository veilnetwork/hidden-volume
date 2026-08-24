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
import 'dart:io' show File, Platform;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

/// Refuse an out-of-range namespace before it reaches the FFI.
///
/// The uniffi signature is `u8`, and `dart:ffi` NARROWS silently: passing 257
/// arrives in Rust as 1. The call then reads or writes a namespace the caller
/// never named — no error, no log, just another namespace's data (audit HV-04).
int _ns(int v) {
  if (v < 0 || v > 0xFF) {
    throw ArgumentError.value(v, 'namespace', 'must be 0..255 (FFI is u8)');
  }
  return v;
}

/// Refuse an out-of-range space id before it reaches the FFI.
///
/// Same narrowing, `u32` wide: 2^32 arrives as 0, which is a VALID id — the
/// first hosted space, i.e. in a multi-identity container somebody else's.
int _sid(int v) {
  if (v < 0 || v > 0xFFFFFFFF) {
    throw ArgumentError.value(v, 'spaceId', 'must be 0..2^32-1 (FFI is u32)');
  }
  return v;
}

/// Refuse a count that will not survive the trip as a `u8` (report7 P2).
///
/// `superblockReplicas` was passed bare. The interesting consequence is not
/// the one you might expect — the core clamps the count to what the container
/// can hold, so nothing overruns. It is quieter: 256 narrows to 0, and the
/// core reads 0 as "give me the minimum" and writes **one** replica. A caller
/// asking for 256 got fewer than the default 3, and got them silently. The
/// replicas are what a torn write is recovered from, so the request was for
/// durability and the answer was less of it.
int _u8(int v, String name) {
  if (v < 0 || v > 0xFF) {
    throw ArgumentError.value(v, name, 'must be 0..255 (FFI is u8)');
  }
  return v;
}

/// Refuse a `limit` that will not survive the trip as a `u32`.
///
/// A page size of 2^32 narrows to 0, and a zero limit is a legal request for
/// an empty page. The caller then reads "no entries" from a namespace that
/// has them, which is indistinguishable from the end of the log.
int _u32(int v, String name) {
  if (v < 0 || v > 0xFFFFFFFF) {
    throw ArgumentError.value(v, name, 'must be 0..2^32-1 (FFI is u32)');
  }
  return v;
}

/// Refuse a value that will not survive the trip as a `u64`.
///
/// Dart's `int` is exactly 64 bits, so the width matches — but it is
/// **signed**, and it wraps. `1 << 64` evaluates to `0` in Dart, and a
/// negative value reinterprets as an enormous unsigned one: `-1` arrives in
/// Rust as 18446744073709551615.
///
/// Every u64 that crosses this boundary is one of two things, and the
/// reinterpretation ruins both:
///
///   - **A count.** `initialGarbageChunks` is the decoy size, so a request
///     that wraps turns off the deniability padding the caller explicitly
///     asked for, and says nothing about it.
///   - **A point in an ORDERED domain** — a `logId`, or a `start` / `end`
///     bound over one. `-1` does not land near zero, it lands at the top of
///     the domain: a read misses an entry that exists, a range query that
///     should have covered the earliest records covers only the last
///     possible one, and a `DeleteLog` names a record no writer will ever
///     produce, so the delete silently does nothing (audit HV13-M3). Log ids
///     are frequently timestamps, and a clock that has not been set yet is
///     the ordinary way a caller ends up holding a negative one.
///
/// Failing loudly is the only way such a request can be seen to have failed.
/// Public within the package so [`async_bindings.dart`](async_bindings.dart)
/// applies the same guard at the same width: without it a negative id is
/// caught only inside the worker isolate, and comes back as a generic
/// `HvException('Internal', ...)` instead of an `ArgumentError` naming the
/// parameter.
int requireU64(int v, String name) {
  if (v < 0) {
    throw ArgumentError.value(
        v,
        name,
        'must be >= 0 (FFI is u64; a negative Dart int reinterprets '
        'as an enormous unsigned value)');
  }
  return v;
}

DynamicLibrary _open() {
  // Standalone/headless hosts cannot preload symbols through a Flutter runner.
  // Honour the same explicit path the xVeil desktop integration already uses.
  // The file check keeps a typo from silently falling through to an unrelated
  // soname on the system loader path.
  final overridePath = Platform.environment['XVEIL_HV_DYLIB'];
  if (overridePath != null &&
      overridePath.isNotEmpty &&
      File(overridePath).existsSync()) {
    return ffi.DynamicLibrary.open(overridePath);
  }
  final bundled = File(Platform.resolvedExecutable)
      .parent
      .parent
      .uri
      .resolve('lib/${_libraryFileName()}')
      .toFilePath();
  if (File(bundled).existsSync()) return ffi.DynamicLibrary.open(bundled);
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

String _libraryFileName() {
  if (Platform.isWindows) return 'hidden_volume_ffi.dll';
  if (Platform.isMacOS || Platform.isIOS) {
    return 'libhidden_volume_ffi.dylib';
  }
  return 'libhidden_volume_ffi.so';
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
    void Function(RustBuffer,
        ffi.Pointer<RustCallStatus>)>('ffi_hidden_volume_ffi_rustbuffer_free');

final _contractVersion =
    _dylib.lookupFunction<ffi.Uint32 Function(), int Function()>(
        'ffi_hidden_volume_ffi_uniffi_contract_version');

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

/// Per-method UniFFI checksums, one per function / method / constructor these
/// bindings call (audit HV-05).
///
/// The contract version above answers "was this cdylib built by the same
/// uniffi minor". It says nothing about whether any individual METHOD still
/// takes the arguments this file passes. A generated binding compares a
/// per-method checksum for exactly that reason and refuses to run when one
/// differs; hand-written bindings had nothing to compare, so an older or
/// swapped library with the same contract version was accepted, and the first
/// call decoded the wrong bytes — a native crash if we were lucky, silently
/// wrong arguments against the user's real container if we were not.
///
/// Regenerate after ANY change to a Rust FFI signature:
///
///     cargo build -p hidden-volume-ffi --release
///     scripts/regen-dart-checksums.py
///
/// and `scripts/regen-dart-checksums.py --check` fails on a stale table. Do
/// not hand-edit the block below: the script derives its key set from the
/// symbol lookups in this same file, so a newly bound method is picked up
/// automatically and a removed one disappears.
// BEGIN GENERATED CHECKSUMS — scripts/regen-dart-checksums.py
const Map<String, int> _methodChecksums = <String, int>{
  'uniffi_hidden_volume_ffi_checksum_constructor_multispacehandle_open': 55952,
  'uniffi_hidden_volume_ffi_checksum_constructor_spacehandle_add_space': 26649,
  'uniffi_hidden_volume_ffi_checksum_constructor_spacehandle_create': 32815,
  'uniffi_hidden_volume_ffi_checksum_constructor_spacehandle_open': 49007,
  'uniffi_hidden_volume_ffi_checksum_constructor_spacehandle_open_with_keys':
      38449,
  'uniffi_hidden_volume_ffi_checksum_func_change_passwords': 12821,
  'uniffi_hidden_volume_ffi_checksum_func_compact_known': 9495,
  'uniffi_hidden_volume_ffi_checksum_func_header_info': 40142,
  'uniffi_hidden_volume_ffi_checksum_method_multispacehandle_commit': 27479,
  'uniffi_hidden_volume_ffi_checksum_method_multispacehandle_commit_seq': 20495,
  'uniffi_hidden_volume_ffi_checksum_method_multispacehandle_count': 7841,
  'uniffi_hidden_volume_ffi_checksum_method_multispacehandle_get': 65186,
  'uniffi_hidden_volume_ffi_checksum_method_multispacehandle_iter_log_range':
      14894,
  'uniffi_hidden_volume_ffi_checksum_method_multispacehandle_kv_keys': 32138,
  'uniffi_hidden_volume_ffi_checksum_method_multispacehandle_kv_keys_page':
      65359,
  'uniffi_hidden_volume_ffi_checksum_method_multispacehandle_open_space': 38306,
  'uniffi_hidden_volume_ffi_checksum_method_multispacehandle_read_log': 27036,
  'uniffi_hidden_volume_ffi_checksum_method_multispacehandle_set_padding_policy':
      49029,
  'uniffi_hidden_volume_ffi_checksum_method_multispacehandle_space_count':
      64423,
  'uniffi_hidden_volume_ffi_checksum_method_multispacehandle_space_keys': 15090,
  'uniffi_hidden_volume_ffi_checksum_method_multispacehandle_vacuum_data_batches':
      40066,
  'uniffi_hidden_volume_ffi_checksum_method_multispacehandle_vacuum_space':
      35449,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_acknowledge_hardening_error':
      23895,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_commit': 59696,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_commit_history': 53412,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_commit_seq': 53179,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_count': 3982,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_erase_namespace': 7530,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_get': 28461,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_iter_log_range': 24184,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_kv_keys': 32483,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_kv_keys_page': 45476,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_list_namespaces': 63954,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_read_log': 59826,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_set_padding_policy':
      6532,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_space_keys': 38453,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_stats': 53120,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_vacuum_after_open':
      23213,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_vacuum_data_batches':
      48307,
  'uniffi_hidden_volume_ffi_checksum_method_spacehandle_verify_integrity':
      55085,
};
// END GENERATED CHECKSUMS

/// Compare every entry of [table] against the loaded cdylib.
///
/// Fails closed and names every offender at once: whoever is staring at a
/// mismatch wants the whole list, not the first entry in map order.
///
/// Takes the table as an argument so a test can drive THIS code — the real
/// comparison and the real report — against a deliberately wrong value. A
/// verifier that is only ever handed a matching table is a verifier nobody
/// has seen refuse anything.
void _verifyChecksums(Map<String, int> table) {
  if (table.isEmpty) {
    // An empty table would make this function a no-op that still reads like a
    // check — the failure mode of every guard nobody regenerated.
    throw StateError('hidden_volume: the UniFFI checksum table is empty. Run '
        'scripts/regen-dart-checksums.py against the built cdylib.');
  }
  final missing = <String>[];
  final mismatched = <String>[];
  table.forEach((symbol, expected) {
    final int actual;
    try {
      actual = _dylib
          .lookupFunction<ffi.Uint16 Function(), int Function()>(symbol)();
    } on ArgumentError {
      // dart:ffi throws ArgumentError when the symbol is absent — the method
      // this file calls does not exist in the loaded library at all.
      missing.add(symbol);
      return;
    }
    if (actual != expected) {
      mismatched.add('$symbol (cdylib $actual, bindings $expected)');
    }
  });
  if (missing.isEmpty && mismatched.isEmpty) return;
  final report = StringBuffer(
      'hidden_volume: the loaded native library does not match these bindings.\n'
      'The uniffi contract version agrees, so this is a per-method signature '
      'drift — calling through would corrupt arguments, not fail cleanly.\n');
  if (missing.isNotEmpty) {
    report.writeln('Absent from the library:');
    for (final s in missing) {
      report.writeln('  $s');
    }
  }
  if (mismatched.isNotEmpty) {
    report.writeln('Checksum mismatch:');
    for (final s in mismatched) {
      report.writeln('  $s');
    }
  }
  report.write(
      'Rebuild hidden-volume-ffi and run scripts/regen-dart-checksums.py.');
  throw StateError(report.toString());
}

/// Force the ABI checks that otherwise run before the first FFI call.
///
/// Exposed so a host app can fail at a moment of its choosing — a launch
/// screen rather than the middle of an unlock.
void verifyAbiCompatibility() {
  _ensureAbiCompatible();
  _verifyChecksums(_methodChecksums);
  abiVerificationRuns++;
  _abiChecked = true;
}

/// The checksum table, for tests and tooling. Unmodifiable.
Map<String, int> get expectedMethodChecksums =>
    Map<String, int>.unmodifiable(_methodChecksums);

/// Run the real verifier against a caller-supplied table. Test-only, in the
/// same spirit as [overrideDylib]: the shipped table matches by construction,
/// so this is the only way to watch the check actually refuse something.
void verifyChecksumsAgainst(Map<String, int> table) => _verifyChecksums(table);

/// How many times [verifyAbiCompatibility] has run. Test-only.
///
/// "The check is wired into the call path" is otherwise unobservable, and an
/// uncalled check is indistinguishable from no check at all — which is the
/// state this whole mechanism was added to leave (audit HV-05).
int abiVerificationRuns = 0;

/// Test-only: forget that the ABI was already verified, so the next FFI call
/// verifies again.
void resetAbiVerificationForTest() {
  _abiChecked = false;
}

bool _abiChecked = false;
void _ensureChecked() {
  if (!_abiChecked) {
    verifyAbiCompatibility();
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

  // Masks, like `addByte` demands. Every namespace reaching here goes through
  // `_ns` first — without that, a commit with namespace 257 lands in namespace
  // 1 and the caller is told the write succeeded (audit HV-04).
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
      // Wiped before the free, because this buffer carries passwords and raw
      // SpaceKeys on their way into Rust. `free` returns the bytes to the C
      // allocator as they are, so a copy of the secret outlived every
      // `Zeroizing` the Rust side puts around its own (report9 HV-16). The
      // cost is a memset of at most a few dozen bytes on a call that has just
      // crossed an FFI boundary.
      if (src.isNotEmpty) {
        tmp.asTypedList(src.length).fillRange(0, src.length, 0);
      }
      calloc.free(tmp);
    }
  });
}

/// Wrap a `Vec<u8>` argument in the framing the uniffi Rust-side
/// deserializer expects: `i32` BE length + raw bytes. Use for any FFI
/// arg whose Rust type is `Vec<u8>` (passwords, KV keys/values).
RustBuffer _bufferFromByteVec(Uint8List src) {
  return _bufferFromOwnedSecret((_Writer()..writeByteVec(src)).toBytes());
}

/// Hand an OWNED Dart byte list to Rust, then wipe it.
///
/// The encoded copy is a SECOND copy of the secret, in the Dart heap this
/// time, and handing it to the garbage collector unwiped is the same leak the
/// `calloc` buffer had one layer down (report9 HV-16). Rust has copied it by
/// the time [_bufferFromBytes] returns, so wiping here is safe.
///
/// **`owned` is the whole contract.** Every caller passes the result of
/// `_Writer.toBytes()`, which is a fresh concatenation — never a buffer the
/// caller of the caller still holds. `BytesBuilder.takeBytes()` would NOT
/// satisfy that: `_Writer` builds on `BytesBuilder(copy: false)`, so for a
/// single-chunk payload `takeBytes` returns that chunk BY REFERENCE, and the
/// "owned" buffer would be the host app's live password. `toBytes()` always
/// copies. `test/secret_buffers_wiped_test.dart` pins that choice.
RustBuffer _bufferFromOwnedSecret(Uint8List owned) {
  try {
    return _bufferFromBytes(owned);
  } finally {
    owned.fillRange(0, owned.length, 0);
  }
}

/// Copy a Rust-owned buffer's contents into a fresh Dart byte list, then
/// free the Rust buffer. Safe to call regardless of buf.len / data state.
/// Decode the `kv_keys` inner frame: `[count u32 LE] ( [len u32 LE][key] )*`.
List<Uint8List> _decodeFramedKeys(Uint8List buf) {
  final bd = ByteData.sublistView(buf);
  var off = 0;
  final count = bd.getUint32(off, Endian.little);
  off += 4;
  final keys = <Uint8List>[];
  for (var i = 0; i < count; i++) {
    final len = bd.getUint32(off, Endian.little);
    off += 4;
    keys.add(Uint8List.fromList(Uint8List.sublistView(buf, off, off + len)));
    off += len;
  }
  return keys;
}

Uint8List _bufferToBytes(RustBuffer buf) {
  try {
    if (buf.len == 0 || buf.data == ffi.nullptr) return Uint8List(0);
    final copy = Uint8List.fromList(buf.data.asTypedList(buf.len));
    // The INBOUND leg of the same leak (report9 HV-16). Everything Rust hands
    // back through here is plaintext this app asked for — KV values, log
    // payloads, and the raw `SpaceKeys` — and `_freeBuffer` returns the bytes
    // to the Rust allocator exactly as they are. The wipe sits between the
    // copy and the free, and both edges are load-bearing: above the copy it
    // returns zeros to the caller, below the free it writes into memory the
    // allocator has already taken back. Dropping a `Vec<u8>` never reads its
    // contents, so zeroing first is safe.
    buf.data.asTypedList(buf.len).fillRange(0, buf.len, 0);
    return copy;
  } finally {
    _freeBuffer(buf);
  }
}

/// Decode a `Vec<u8>` reply whose CONTENT is a secret, wiping the framed
/// intermediate.
///
/// `_Reader(_bufferToBytes(out)).readByteVec()` leaves the framed list — the
/// `i32` BE length plus the secret itself — as an anonymous temporary for the
/// garbage collector. `readByteVec` wraps its slice in `Uint8List.fromList`, a
/// real copy, so the frame is dead the moment it returns and wiping it costs
/// the caller nothing.
Uint8List _secretByteVecFrom(RustBuffer out) {
  final framed = _bufferToBytes(out);
  try {
    return _Reader(framed).readByteVec();
  } finally {
    framed.fillRange(0, framed.length, 0);
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
/// Rust `WriteOp` enum (variant tags 1=Put, 2=Delete, 3=AppendLog,
/// 4=DeleteLog).
sealed class HvWriteOp {
  const HvWriteOp();
  void _write(_Writer w);

  /// Roughly what this op costs in bytes when the batch is sent to the worker.
  ///
  /// `SendPort.send` copies the whole message into the receiving isolate's
  /// heap SYNCHRONOUSLY, before the caller awaits anything, so a batch's
  /// payload is spent the moment it is submitted. The async handle's
  /// in-flight ceiling counts operations, which says nothing about that: 4096
  /// batches of two megabytes is eight gigabytes of copies, admitted one at a
  /// time by a limit that saw only the number 4096.
  ///
  /// The keys and values, not the framing — a few bytes of tag and length per
  /// op are noise beside the payloads this exists to bound.
  int get byteSize;
}

/// Insert or replace a KV entry in `namespace`.
final class HvWriteOpPut extends HvWriteOp {
  const HvWriteOpPut(
      {required this.namespace, required this.key, required this.value});
  final int namespace;
  final Uint8List key;
  final Uint8List value;

  @override
  int get byteSize => key.length + value.length;

  @override
  void _write(_Writer w) {
    w
      ..writeI32(1)
      ..writeU8(_ns(namespace))
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
  int get byteSize => key.length;

  @override
  void _write(_Writer w) {
    w
      ..writeI32(2)
      ..writeU8(_ns(namespace))
      ..writeByteVec(key);
  }
}

/// Append one log entry into a DataBatch chunk.
final class HvWriteOpAppendLog extends HvWriteOp {
  const HvWriteOpAppendLog(
      {required this.namespace, required this.logId, required this.payload});
  final int namespace;
  final int logId;
  final Uint8List payload;

  @override
  int get byteSize => payload.length;

  @override
  void _write(_Writer w) {
    w
      ..writeI32(3)
      ..writeU8(_ns(namespace))
      ..writeU64(requireU64(logId, 'logId'))
      ..writeByteVec(payload);
  }
}

/// Delete one logical record from a Log namespace. No-op if absent.
final class HvWriteOpDeleteLog extends HvWriteOp {
  const HvWriteOpDeleteLog({required this.namespace, required this.logId});
  final int namespace;
  final int logId;

  @override
  int get byteSize => 0;

  @override
  void _write(_Writer w) {
    w
      ..writeI32(4)
      ..writeU8(_ns(namespace))
      ..writeU64(requireU64(logId, 'logId'));
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
  String toString() => 'HvHeaderInfo(salt=${saltHex.substring(0, 16)}…, '
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

/// Which post-commit hardening step failed. Mirror of the Rust
/// `HardeningStepKind`; the ordinals are uniffi's, 1-based in declaration
/// order.
///
/// The step is why this is an enum and not a flag. The three protect different
/// things, and a host told only "hardening failed" cannot act on any of them.
enum HvHardeningStep {
  /// The commit's SIZE is readable by an adversary who diffs two snapshots of
  /// the container file.
  padding,

  /// The slots this commit REUSED stand alone in that diff, with no decoy
  /// moved beside them — the deniability the reuse depends on.
  churn,

  /// The masking writes are not on the platter yet. The COMMIT is durable
  /// regardless; this is about the padding and churn around it.
  sync,
}

/// A post-commit hardening failure the space has recorded and the host has not
/// acknowledged. See [HvStatsInfo.hardeningFailure].
class HvHardeningFailure {
  const HvHardeningFailure({required this.step, required this.message});

  /// Which of the three steps failed — the part a host acts on.
  final HvHardeningStep step;

  /// Why, rendered by Rust. Diagnostic text for a log or a bug report; do not
  /// branch on it.
  final String message;

  @override
  String toString() => 'HvHardeningFailure(${step.name}: $message)';
}

/// Aggregated per-space stats. Mirror of `SpaceStats` flattened for FFI.
class HvStatsInfo {
  const HvStatsInfo({
    required this.commitSeq,
    required this.commitHistoryLen,
    required this.ownedChunkCount,
    required this.totalSlotCount,
    required this.reusableSlotCount,
    required this.totalEntries,
    required this.namespaceCounts,
    required this.hardeningFailure,
  });
  final int commitSeq;
  final int commitHistoryLen;
  final int ownedChunkCount;
  final int totalSlotCount;

  /// Slots this space has retired and will reuse before it grows the file
  /// again — the decoy pool.
  ///
  /// **Read it together with [utilizationRatio], never instead of it.** The
  /// ratio on its own gets the `compact_known` decision wrong both ways: a low
  /// ratio with a large pool is a container recycling healthily, and compacting
  /// it rewrites the whole file and rotates the `container_id` for nothing; a
  /// low ratio with a pool near zero is the shape that actually needs it. Until
  /// report10 HV-04 this number did not cross the FFI at all, so a host had
  /// only the half that cannot decide alone.
  final int reusableSlotCount;

  final int totalEntries;
  final List<HvNamespaceCount> namespaceCounts;

  /// A post-commit hardening failure this space recorded and nobody has
  /// acknowledged yet, or `null` (report10 HV-04).
  ///
  /// **Sticky.** This is NOT "the last commit's outcome". A commit that
  /// succeeds completely leaves it exactly as it was, poll after poll, until
  /// [SpaceHandleBindings.acknowledgeHardeningError] clears it — which is the only
  /// thing that clears it. It used to reflect only the newest commit and never
  /// crossed the boundary at all: a host polling for it would have found a
  /// clean record because an ordinary second commit had landed in between, and
  /// the person was never told that one of their writes is sized, unchurned or
  /// unsynced on the disk.
  ///
  /// Non-null does NOT mean a commit failed. The commit is durable; what is
  /// weaker than promised is the masking around it.
  ///
  /// In-memory: a reopened handle starts with `null`.
  final HvHardeningFailure? hardeningFailure;

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

/// uniffi lowers an enum as an i32 of its 1-based declaration index. Ordered to
/// match `HardeningStepKind` in `crates/hidden-volume-ffi/src/lib.rs`.
const List<HvHardeningStep> _hardeningSteps = <HvHardeningStep>[
  HvHardeningStep.padding,
  HvHardeningStep.churn,
  HvHardeningStep.sync,
];

HvStatsInfo _readStats(Uint8List bytes) {
  final r = _Reader(bytes);
  final commitSeq = r.readU64();
  final commitHistoryLen = r.readU64();
  final ownedChunkCount = r.readU64();
  final totalSlotCount = r.readU64();
  final reusableSlotCount = r.readU64();
  final totalEntries = r.readU64();
  final n = r.readI32();
  if (n < 0) throw StateError('negative sequence length');
  final counts = <HvNamespaceCount>[
    for (var i = 0; i < n; i++)
      HvNamespaceCount(namespace: r.readU8(), count: r.readU64()),
  ];
  // `Option<HardeningFailureInfo>`: 1 byte tag, then (Some) the record — i32
  // enum ordinal, i32 string length, utf8 bytes.
  final tag = r.readU8();
  HvHardeningFailure? hardening;
  if (tag == 1) {
    final ordinal = r.readI32();
    if (ordinal < 1 || ordinal > _hardeningSteps.length) {
      // A step this build does not know about is a library newer than these
      // bindings. Refusing beats guessing: the whole value of the field is
      // WHICH thing is no longer true, and a wrong step is worse advice than
      // none.
      throw StateError('uniffi: unknown hardening step ordinal $ordinal');
    }
    hardening = HvHardeningFailure(
      step: _hardeningSteps[ordinal - 1],
      message: r.readString(),
    );
  } else if (tag != 0) {
    throw StateError('uniffi: unexpected Option tag $tag');
  }
  return HvStatsInfo(
    commitSeq: commitSeq,
    commitHistoryLen: commitHistoryLen,
    ownedChunkCount: ownedChunkCount,
    totalSlotCount: totalSlotCount,
    reusableSlotCount: reusableSlotCount,
    totalEntries: totalEntries,
    namespaceCounts: counts,
    hardeningFailure: hardening,
  );
}

/// Test seam for the `StatsInfo` wire decode.
///
/// The hardening record only becomes non-null when a padding, churn or fsync
/// round actually fails, and the hooks that force one live inside the Rust
/// core's own test build — unreachable from here. So the `Some(_)` leg of this
/// decoder cannot be exercised through a real call, and without a seam it would
/// ship untested while everything around it looks green.
HvStatsInfo debugReadStats(Uint8List bytes) => _readStats(bytes);

/// One mapping for [changePasswords]. `oldPwd == newPwd` preserves the
/// space verbatim. Spaces NOT mentioned are **dropped** by the rewrite —
/// list every space you want to keep (use `oldPwd == newPwd` for a
/// no-op rotation when keeping a hidden space).
class HvPasswordRotation {
  const HvPasswordRotation({required this.oldPwd, required this.newPwd});
  final Uint8List oldPwd;
  final Uint8List newPwd;
}

/// Every password in the rotation, old and new, concatenated into one blob —
/// the densest secret this plugin ever builds. It goes out through
/// [_bufferFromOwnedSecret], not [_bufferFromBytes], because the caller's
/// buffers are untouched by `toBytes()` and this blob belongs to nobody else.
RustBuffer _writeRotations(List<HvPasswordRotation> rotations) {
  final w = _Writer()..writeI32(rotations.length);
  for (final r in rotations) {
    w
      ..writeByteVec(r.oldPwd)
      ..writeByteVec(r.newPwd);
  }
  return _bufferFromOwnedSecret(w.toBytes());
}

/// Same shape as [_writeRotations], same reason: `compact_known` carries every
/// password that unlocks a kept space.
RustBuffer _writeBytesSequence(List<Uint8List> items) {
  final w = _Writer()..writeI32(items.length);
  for (final b in items) {
    w.writeByteVec(b);
  }
  return _bufferFromOwnedSecret(w.toBytes());
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
/// "IntegrityFailure", "ContainerTooLarge", "UnreadableNewerState",
/// "RenameVisibleDurabilityUncertain", "RenameVisibleContentUnverified",
/// "PublishUncertain", or "InternalPanic" for an unexpected Rust panic).
///
/// "ContainerTooLarge" now also covers OPENING a container past the
/// open-scan budget; it used to arrive as "Malformed", which said the
/// container was corrupt when it was merely large (audit HV-13).
///
/// The last four kinds used to arrive as "Internal" (report7 P1), which
/// documents itself as a library bug. Each is a normal outcome:
/// "UnreadableNewerState" and "PublishUncertain" both mean **reopen the
/// container**, and both are raised by orphan cleanup — which this
/// plugin arms on every open. The two rename kinds mean the rewrite
/// **applied**: after a password change the new passwords are already in
/// effect, so retrying with the old one is wrong.
class HvException implements Exception {
  HvException(this.kind, this.message);
  final String kind;
  final String message;

  /// Whether the refused operation **may still have taken effect**
  /// (report8 H-09).
  ///
  /// Most core refusals happen before a single byte is written, and for
  /// those an error is a proof of no effect. Three are not:
  ///
  ///  * `PublishUncertain` — the commit burnt its `seq` and a Superblock
  ///    replica may already be on the disk, so the file may hold an era
  ///    this handle does not know about;
  ///  * the two `RenameVisible*` kinds — the rewrite **applied**; the old
  ///    container is gone and the new passwords are already in effect.
  ///
  /// For all three the remedy is to reopen and look. Retrying is what a
  /// caller does when it believes nothing happened, and on a deniable
  /// store a blind re-apply is not a free move.
  ///
  /// `false` is NOT "retry away". `UnreadableNewerState` and `Busy` are
  /// effect-free and still want a reopen or a wait; this getter answers
  /// what happened, not what to do next.
  bool get mayHaveApplied => _kindsThatMayHaveApplied.contains(kind);

  @override
  String toString() => 'HvException.$kind: $message';
}

/// The kinds [HvException.mayHaveApplied] answers `true` for.
///
/// Every entry must also appear in [_hvErrorKinds] — a name that matches
/// nothing is a predicate that is silently always-`false`, which is the
/// failure mode this whole distinction exists to prevent. Pinned by
/// `operation_outcome_test.dart`.
const _kindsThatMayHaveApplied = <String>{
  'PublishUncertain',
  'RenameVisibleDurabilityUncertain',
  'RenameVisibleContentUnverified',
};

/// The names an [HvException.kind] can carry, for the drift check above.
/// Test-only reader — production code compares `kind` directly.
Set<String> debugKnownErrorKinds() => _hvErrorKinds.skip(1).toSet();

/// The real contents of [_kindsThatMayHaveApplied], for the same check.
///
/// Test-only, and it must be THIS set rather than a copy written out in the
/// test: a test that lists the names again only proves its own list is
/// spelled right. The first version of that check let a misspelled entry
/// straight through.
Set<String> debugKindsThatMayHaveApplied() => _kindsThatMayHaveApplied;

/// Positional map from the uniffi `flat_error` ordinal to a name. The
/// order MUST match `enum HvError` in `crates/hidden-volume-ffi/src/lib.rs`
/// exactly: a variant inserted in the middle there renames every kind
/// after it here, silently and at runtime. Both sides are append-only.
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
  // report7 P1 — four core outcomes that used to arrive as
  // `Internal("unknown error variant")`, i.e. as "the library has a bug"
  // when each is a normal outcome with its own remedy.
  'UnreadableNewerState',
  'RenameVisibleDurabilityUncertain',
  'RenameVisibleContentUnverified',
  'PublishUncertain',
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
        ffi.Void Function(RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>),
        void Function(RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_func_change_passwords');

final _fnCompactKnown = _dylib.lookupFunction<
        ffi.Void Function(RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>),
        void Function(RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>)>(
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

final _spOpen =
    _dylib.lookupFunction<
            ffi.Uint64 Function(
                RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>),
            int Function(RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>)>(
        'uniffi_hidden_volume_ffi_fn_constructor_spacehandle_open');

// Same wire shape as `open` (path, password) -> handle; adds a new parallel
// space to an existing container instead of opening one.
final _spAddSpace =
    _dylib.lookupFunction<
            ffi.Uint64 Function(
                RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>),
            int Function(RustBuffer, RustBuffer, ffi.Pointer<RustCallStatus>)>(
        'uniffi_hidden_volume_ffi_fn_constructor_spacehandle_add_space');

// Same wire shape as `open` (path, keys) -> handle; opens a space from
// pre-derived SpaceKeys (64 opaque bytes) instead of a password — the
// master-space path.
final _spOpenWithKeys =
    _dylib.lookupFunction<
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

final _spCommit =
    _dylib.lookupFunction<
            ffi.Uint64 Function(
                ffi.Uint64, RustBuffer, ffi.Pointer<RustCallStatus>),
            int Function(int, RustBuffer, ffi.Pointer<RustCallStatus>)>(
        'uniffi_hidden_volume_ffi_fn_method_spacehandle_commit');

final _spGet = _dylib.lookupFunction<
        RustBuffer Function(
            ffi.Uint64, ffi.Uint8, RustBuffer, ffi.Pointer<RustCallStatus>),
        RustBuffer Function(int, int, RustBuffer, ffi.Pointer<RustCallStatus>)>(
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
        ffi.Uint64 Function(ffi.Uint64, ffi.Uint8, ffi.Pointer<RustCallStatus>),
        int Function(int, int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_count');

final _spKvKeys = _dylib.lookupFunction<
        RustBuffer Function(ffi.Uint64, ffi.Uint8, ffi.Pointer<RustCallStatus>),
        RustBuffer Function(int, int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_kv_keys');

// (handle, namespace, Option<Vec<u8>> after, u32 limit) -> framed keys.
// Same argument shape as iter_log_range's cursor, keyed on a byte string
// instead of a log_id.
final _spKvKeysPage = _dylib.lookupFunction<
        RustBuffer Function(ffi.Uint64, ffi.Uint8, RustBuffer, ffi.Uint32,
            ffi.Pointer<RustCallStatus>),
        RustBuffer Function(
            int, int, RustBuffer, int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_kv_keys_page');

final _spEraseNs = _dylib.lookupFunction<
        ffi.Uint64 Function(ffi.Uint64, ffi.Uint8, ffi.Pointer<RustCallStatus>),
        int Function(int, int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_erase_namespace');

final _spReadLog = _dylib.lookupFunction<
        RustBuffer Function(
            ffi.Uint64, ffi.Uint8, ffi.Uint64, ffi.Pointer<RustCallStatus>),
        RustBuffer Function(int, int, int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_read_log');

final _spListNamespaces = _dylib.lookupFunction<
        RustBuffer Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
        RustBuffer Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_list_namespaces');

final _spSetPaddingPolicy = _dylib.lookupFunction<
        ffi.Void Function(ffi.Uint64, RustBuffer, ffi.Pointer<RustCallStatus>),
        void Function(int, RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_set_padding_policy');

final _spStats = _dylib.lookupFunction<
        RustBuffer Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
        RustBuffer Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_stats');

final _spAcknowledgeHardeningError = _dylib.lookupFunction<
        ffi.Void Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
        void Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_acknowledge_hardening_error');

final _spVacuumDataBatches = _dylib.lookupFunction<
        ffi.Uint64 Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
        int Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_vacuum_data_batches');

final _spVacuumAfterOpen = _dylib.lookupFunction<
        ffi.Uint64 Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
        int Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_spacehandle_vacuum_after_open');

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

/// Encode an `Option<Vec<u8>>` as: 1 byte tag (0=None, 1=Some) + (if Some)
/// the i32-BE-length-prefixed bytes uniffi expects for a `Vec<u8>`.
RustBuffer _optByteVec(Uint8List? v) {
  final w = _Writer();
  if (v == null) {
    w.writeU8(0);
  } else {
    w.writeU8(1);
    w.writeByteVec(v);
  }
  return _bufferFromBytes(w.toBytes());
}

/// Encode an `Option<u64>` as: 1 byte tag (0=None, 1=Some) + (if Some) u64 BE.
///
/// `name` is required rather than optional so that a bound cannot be lowered
/// without saying which one it is — the guard is then part of the signature
/// instead of something a later call site can forget (audit HV13-M3).
RustBuffer _optU64(int? v, String name) {
  final w = _Writer();
  if (v == null) {
    w.writeU8(0);
  } else {
    w.writeU8(1);
    w.writeU64(requireU64(v, name));
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
        pathBuf,
        pwdBuf,
        argonBuf,
        requireU64(initialGarbageChunks, 'initialGarbageChunks'),
        _u8(superblockReplicas, 'superblockReplicas'),
        s));
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
    final out =
        rustCall<RustBuffer>((s) => _spGet(h, _ns(namespace), keyBuf, s));
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
    final startBuf = _optU64(start, 'start');
    final endBuf = _optU64(end, 'end');
    final h = _cloneHandle();
    final out = rustCall<RustBuffer>((s) => _spIterLogRange(
        h, _ns(namespace), startBuf, endBuf, _u32(limit, 'limit'), s));
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
    return rustCall<int>((s) => _spCount(h, _ns(namespace), s));
  }

  /// Keys of every KV entry in [namespace], sorted ascending. Host apps use
  /// this to garbage-collect stale bookkeeping keys (a namespace's 2-level
  /// B+ tree has a hard entry budget — `IndexFull` — so orphans must be
  /// enumerable to be deletable).
  ///
  /// The walk peaks at one decoded index node, like [count] — values are
  /// neither transferred nor held. The RESULT, though, is every key: one
  /// allocation on each side of the FFI boundary, proportional to the
  /// namespace. On anything whose size this app does not control, use
  /// [kvKeysPage].
  List<Uint8List> kvKeys(int namespace) {
    _ensureOpen();
    final h = _cloneHandle();
    final out = rustCall<RustBuffer>((s) => _spKvKeys(h, _ns(namespace), s));
    return _decodeFramedKeys(_Reader(_bufferToBytes(out)).readByteVec());
  }

  /// One page of [kvKeys]: up to [limit] keys strictly greater than
  /// [after], ascending. Pass `after: null` for the first page and the
  /// last key of the previous page thereafter; a page shorter than
  /// [limit] is the end.
  List<Uint8List> kvKeysPage(int namespace, Uint8List? after, int limit) {
    _ensureOpen();
    final h = _cloneHandle();
    final out = rustCall<RustBuffer>((s) => _spKvKeysPage(
        h, _ns(namespace), _optByteVec(after), _u32(limit, 'limit'), s));
    return _decodeFramedKeys(_Reader(_bufferToBytes(out)).readByteVec());
  }

  /// Drop all entries in [namespace] and zero the index root. Returns
  /// the new commit_seq.
  int eraseNamespace(int namespace) {
    _ensureOpen();
    final h = _cloneHandle();
    return rustCall<int>((s) => _spEraseNs(h, _ns(namespace), s));
  }

  /// Read one log entry by `(namespace, logId)`. Returns null if absent.
  Uint8List? readLog(int namespace, int logId) {
    _ensureOpen();
    final h = _cloneHandle();
    final out = rustCall<RustBuffer>(
        (s) => _spReadLog(h, _ns(namespace), requireU64(logId, 'logId'), s));
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

  /// Acknowledge the sticky [HvStatsInfo.hardeningFailure] — "I have shown this
  /// to the person". Clears it; nothing else does (report10 HV-04).
  ///
  /// Idempotent, and safe when there is nothing recorded. Call it once the
  /// warning has actually been surfaced, not on the way past: the record
  /// survives commits precisely so it cannot fall between two polls, and
  /// acknowledging it unread throws the same warning away by hand.
  void acknowledgeHardeningError() {
    _ensureOpen();
    final h = _cloneHandle();
    rustCall<void>((s) {
      _spAcknowledgeHardeningError(h, s);
    });
  }

  /// Reclaim DataBatch chunk slots that no longer have any live
  /// log entries. Returns the count of slots scrubbed.
  int vacuumDataBatches() {
    _ensureOpen();
    final h = _cloneHandle();
    return rustCall<int>((s) => _spVacuumDataBatches(h, s));
  }

  /// Run the post-open forward-secrecy scrub the constant-time [open]
  /// deliberately left undone (audit HV-01). Returns the number of orphan
  /// index chunks scrubbed; `0` on a read-only container.
  ///
  /// **Call it away from the unlock** — see `HvSpace.scheduleDeferredVacuum`
  /// in `lib/hidden_volume.dart`, which is what a host should normally use.
  /// Running it in the line after [open] moves the same history-proportional
  /// milliseconds and disk writes a moment to the right and leaves them
  /// correlated with the unlock having succeeded, which is the whole thing
  /// the equalized scan removes.
  int vacuumAfterOpen() {
    _ensureOpen();
    final h = _cloneHandle();
    return rustCall<int>((s) => _spVacuumAfterOpen(h, s));
  }

  /// Export this space's `SpaceKeys` as 64 opaque bytes for a master roster.
  /// **Sensitive** — keep only inside another deniable space, never log.
  Uint8List spaceKeys() {
    _ensureOpen();
    final h = _cloneHandle();
    final out = rustCall<RustBuffer>((s) => _spSpaceKeys(h, s));
    // Wire format `i32 BE len + bytes` (Vec<u8>), same as listNamespaces —
    // but the payload is 64 raw key bytes, so the frame gets wiped too.
    return _secretByteVecFrom(out);
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

// ------------------------------------------------------------------
// MultiSpaceHandle — several spaces of one container open at once.
// ------------------------------------------------------------------

final _msOpen = _dylib.lookupFunction<
        ffi.Uint64 Function(RustBuffer, ffi.Pointer<RustCallStatus>),
        int Function(RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_constructor_multispacehandle_open');

final _msFree = _dylib.lookupFunction<
        ffi.Void Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
        void Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_free_multispacehandle');

final _msClone = _dylib.lookupFunction<
        ffi.Uint64 Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
        int Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_clone_multispacehandle');

final _msOpenSpace =
    _dylib.lookupFunction<
            ffi.Uint32 Function(
                ffi.Uint64, RustBuffer, ffi.Pointer<RustCallStatus>),
            int Function(int, RustBuffer, ffi.Pointer<RustCallStatus>)>(
        'uniffi_hidden_volume_ffi_fn_method_multispacehandle_open_space');

final _msVacuumSpace = _dylib.lookupFunction<
        ffi.Void Function(ffi.Uint64, ffi.Uint32, ffi.Pointer<RustCallStatus>),
        void Function(int, int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_multispacehandle_vacuum_space');

final _msSpaceCount = _dylib.lookupFunction<
        ffi.Uint32 Function(ffi.Uint64, ffi.Pointer<RustCallStatus>),
        int Function(int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_multispacehandle_space_count');

final _msSetPaddingPolicy = _dylib.lookupFunction<
        ffi.Void Function(ffi.Uint64, RustBuffer, ffi.Pointer<RustCallStatus>),
        void Function(int, RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_multispacehandle_set_padding_policy');

final _msSpaceKeys =
    _dylib.lookupFunction<
            RustBuffer Function(
                ffi.Uint64, ffi.Uint32, ffi.Pointer<RustCallStatus>),
            RustBuffer Function(int, int, ffi.Pointer<RustCallStatus>)>(
        'uniffi_hidden_volume_ffi_fn_method_multispacehandle_space_keys');

final _msCommit = _dylib.lookupFunction<
        ffi.Uint64 Function(
            ffi.Uint64, ffi.Uint32, RustBuffer, ffi.Pointer<RustCallStatus>),
        int Function(int, int, RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_multispacehandle_commit');

final _msGet = _dylib.lookupFunction<
        RustBuffer Function(ffi.Uint64, ffi.Uint32, ffi.Uint8, RustBuffer,
            ffi.Pointer<RustCallStatus>),
        RustBuffer Function(
            int, int, int, RustBuffer, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_multispacehandle_get');

final _msReadLog = _dylib.lookupFunction<
        RustBuffer Function(ffi.Uint64, ffi.Uint32, ffi.Uint8, ffi.Uint64,
            ffi.Pointer<RustCallStatus>),
        RustBuffer Function(int, int, int, int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_multispacehandle_read_log');

final _msIterLogRange = _dylib.lookupFunction<
        RustBuffer Function(ffi.Uint64, ffi.Uint32, ffi.Uint8, RustBuffer,
            RustBuffer, ffi.Uint32, ffi.Pointer<RustCallStatus>),
        RustBuffer Function(int, int, int, RustBuffer, RustBuffer, int,
            ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_multispacehandle_iter_log_range');

final _msCount = _dylib.lookupFunction<
        ffi.Uint64 Function(
            ffi.Uint64, ffi.Uint32, ffi.Uint8, ffi.Pointer<RustCallStatus>),
        int Function(int, int, int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_multispacehandle_count');

final _msKvKeys = _dylib.lookupFunction<
        RustBuffer Function(
            ffi.Uint64, ffi.Uint32, ffi.Uint8, ffi.Pointer<RustCallStatus>),
        RustBuffer Function(int, int, int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_multispacehandle_kv_keys');

final _msKvKeysPage = _dylib.lookupFunction<
        RustBuffer Function(ffi.Uint64, ffi.Uint32, ffi.Uint8, RustBuffer,
            ffi.Uint32, ffi.Pointer<RustCallStatus>),
        RustBuffer Function(
            int, int, int, RustBuffer, int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_multispacehandle_kv_keys_page');

final _msCommitSeq =
    _dylib.lookupFunction<
            ffi.Uint64 Function(
                ffi.Uint64, ffi.Uint32, ffi.Pointer<RustCallStatus>),
            int Function(int, int, ffi.Pointer<RustCallStatus>)>(
        'uniffi_hidden_volume_ffi_fn_method_multispacehandle_commit_seq');

final _msVacuum = _dylib.lookupFunction<
        ffi.Uint64 Function(ffi.Uint64, ffi.Uint32, ffi.Pointer<RustCallStatus>),
        int Function(int, int, ffi.Pointer<RustCallStatus>)>(
    'uniffi_hidden_volume_ffi_fn_method_multispacehandle_vacuum_data_batches');

/// Low-level wrapper over the uniffi-exported `MultiSpaceHandle` symbols.
/// Hosts several spaces of one container open at once under a single lock;
/// per-space methods take a `spaceId` from [openSpace].
class MultiSpaceHandleBindings {
  MultiSpaceHandleBindings._(this._handle) {
    _msFinalizer.attach(this, _handle, detach: this);
  }

  final int _handle;
  bool _closed = false;

  /// Open a container at [path] for multi-space hosting (takes its lock).
  static MultiSpaceHandleBindings open({required String path}) {
    final pathBuf = _bufferFromBytes(utf8.encode(path));
    final h = rustCall<int>((s) => _msOpen(pathBuf, s));
    return MultiSpaceHandleBindings._(h);
  }

  void _ensureOpen() {
    if (_closed) throw StateError('MultiSpaceHandle is closed');
  }

  // uniffi method calls CONSUME the passed handle; clone before each so the
  // wrapper keeps a live reference for later calls and for close().
  int _clone() => rustCall<int>((s) => _msClone(_handle, s));

  /// Host a space by its 64-byte SpaceKeys; returns its spaceId.
  int openSpace(Uint8List keys) {
    _ensureOpen();
    final keysBuf = _bufferFromByteVec(keys);
    final h = _clone();
    return rustCall<int>((s) => _msOpenSpace(h, keysBuf, s));
  }

  /// Run the post-open scrub for a hosted space.
  ///
  /// [openSpace] deliberately does NOT do this inline: the scrub's duration
  /// depends on the space's history, so running it as part of the
  /// constant-time unlock made a successful open measurably longer than a
  /// failed one and undid the equalized scan (audit HV-02).
  ///
  /// Call it once unlock is complete. The work still has to happen — without
  /// it, values a previous session deleted stay decryptable to anyone who
  /// later obtains the password and an old snapshot of the file.
  void vacuumSpace(int spaceId) {
    _ensureOpen();
    final h = _clone();
    rustCall<void>((s) => _msVacuumSpace(h, _sid(spaceId), s));
  }

  /// Number of hosted spaces.
  int spaceCount() {
    _ensureOpen();
    final h = _clone();
    return rustCall<int>((s) => _msSpaceCount(h, s));
  }

  /// Override the shared container's post-commit padding policy.
  void setPaddingPolicy(PaddingPreset preset) {
    _ensureOpen();
    final buf = preset._toRustBuffer();
    final h = _clone();
    rustCall<void>((s) {
      _msSetPaddingPolicy(h, buf, s);
    });
  }

  /// Export hosted space [id]'s 64-byte SpaceKeys (sensitive — never log).
  Uint8List spaceKeys(int id) {
    _ensureOpen();
    final h = _clone();
    final out = rustCall<RustBuffer>((s) => _msSpaceKeys(h, _sid(id), s));
    return _secretByteVecFrom(out);
  }

  /// Apply a write batch to space [id]; returns its new commit_seq.
  int commit(int id, List<HvWriteOp> ops) {
    _ensureOpen();
    final buf = _writeOpsToBuffer(ops);
    final h = _clone();
    return rustCall<int>((s) => _msCommit(h, _sid(id), buf, s));
  }

  /// Read a KV value from space [id], or null if absent.
  Uint8List? get(int id, int namespace, Uint8List key) {
    _ensureOpen();
    final keyBuf = _bufferFromByteVec(key);
    final h = _clone();
    final out = rustCall<RustBuffer>(
        (s) => _msGet(h, _sid(id), _ns(namespace), keyBuf, s));
    return _decodeOptionBytes(out);
  }

  /// Read one log entry from space [id], or null if not found.
  Uint8List? readLog(int id, int namespace, int logId) {
    _ensureOpen();
    final h = _clone();
    final out = rustCall<RustBuffer>((s) => _msReadLog(
        h, _sid(id), _ns(namespace), requireU64(logId, 'logId'), s));
    return _decodeOptionBytes(out);
  }

  /// Half-open range query over a log namespace of space [id].
  List<HvLogEntry> iterLogRange({
    required int id,
    required int namespace,
    int? start,
    int? end,
    required int limit,
  }) {
    _ensureOpen();
    final startBuf = _optU64(start, 'start');
    final endBuf = _optU64(end, 'end');
    final h = _clone();
    final out = rustCall<RustBuffer>((s) => _msIterLogRange(h, _sid(id),
        _ns(namespace), startBuf, endBuf, _u32(limit, 'limit'), s));
    return _readLogEntries(_bufferToBytes(out));
  }

  /// Number of KV entries in [namespace] of space [id].
  int count(int id, int namespace) {
    _ensureOpen();
    final h = _clone();
    return rustCall<int>((s) => _msCount(h, _sid(id), _ns(namespace), s));
  }

  /// Keys of every KV entry in [namespace] of space [id] — the multi-space
  /// twin of [SpaceHandleBindings.kvKeys].
  List<Uint8List> kvKeys(int id, int namespace) {
    _ensureOpen();
    final h = _clone();
    final out =
        rustCall<RustBuffer>((s) => _msKvKeys(h, _sid(id), _ns(namespace), s));
    return _decodeFramedKeys(_Reader(_bufferToBytes(out)).readByteVec());
  }

  /// One page of [kvKeys] for space [id] — the multi-space twin of
  /// [SpaceHandleBindings.kvKeysPage].
  List<Uint8List> kvKeysPage(
      int id, int namespace, Uint8List? after, int limit) {
    _ensureOpen();
    final afterBuf = _optByteVec(after);
    final h = _clone();
    final out = rustCall<RustBuffer>((s) => _msKvKeysPage(
        h, _sid(id), _ns(namespace), afterBuf, _u32(limit, 'limit'), s));
    return _decodeFramedKeys(_Reader(_bufferToBytes(out)).readByteVec());
  }

  /// Current commit sequence of space [id].
  int commitSeq(int id) {
    _ensureOpen();
    final h = _clone();
    return rustCall<int>((s) => _msCommitSeq(h, _sid(id), s));
  }

  /// Reclaim DataBatch slots orphaned by edit/delete in space [id].
  int vacuumDataBatches(int id) {
    _ensureOpen();
    final h = _clone();
    return rustCall<int>((s) => _msVacuum(h, _sid(id), s));
  }

  /// Release the container lock and free the handle.
  void close() {
    if (_closed) return;
    _closed = true;
    _msFinalizer.detach(this);
    rustCall<void>((s) {
      _msFree(_handle, s);
    });
  }

  static final Finalizer<int> _msFinalizer = Finalizer<int>((handle) {
    final s = calloc<RustCallStatus>();
    try {
      s.ref.code = _callSuccess;
      s.ref.errorBuf
        ..capacity = 0
        ..len = 0
        ..data = ffi.nullptr;
      _msFree(handle, s);
    } finally {
      calloc.free(s);
    }
  });
}

/// Decode a uniffi `Option<Vec<u8>>`: `u8 tag (0=None,1=Some) + (if Some) bytes`.
Uint8List? _decodeOptionBytes(RustBuffer out) {
  final bytes = _bufferToBytes(out);
  if (bytes.isEmpty) {
    throw StateError('uniffi: empty Option<Bytes> buffer');
  }
  final r = _Reader(bytes);
  final tag = r.readU8();
  if (tag == 0) return null;
  if (tag != 1) throw StateError('uniffi: unexpected Option tag $tag');
  return r.readByteVec();
}
