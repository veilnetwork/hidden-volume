// What `StatsInfo` carries across the boundary, and what it used to drop
// (report10 HV-04).
//
// Two numbers the Rust core has always held never reached Dart: the decoy pool
// (`reusableSlotCount`) and the post-commit hardening record. Without the first
// a host deciding whether to `compactKnown` has only `utilizationRatio`, which
// answers wrongly in both directions. Without the second the host gets a
// successful commit and cannot warn anybody that this write's masking is
// weaker than promised.
//
// ## Why half of this is decoded from bytes the test writes
//
// The hardening record only becomes non-null when a padding, churn or fsync
// round actually FAILS, and the hooks that force one are `#[cfg(test)]` inside
// the Rust core — they do not exist in the shipped cdylib and cannot be reached
// from Dart at all. The stickiness itself is therefore proved where it lives,
// in `crates/hidden-volume/src/space/reuse_tests.rs`. What is left for this
// side, and what nothing else covers, is the WIRE DECODE: `bindings.dart` is
// hand-written against the uniffi C ABI, and adding fields to a `Record`
// changes the bytes it returns while changing NO per-method checksum — uniffi
// checksums a method's signature, and `stats` still returns a thing called
// `StatsInfo`. `checksum_test.dart` stays green through exactly the drift that
// makes this decoder read the wrong offsets. So the buffers below are written
// by hand to the layout Rust emits, and a reader that loses its place fails
// here or nowhere.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/hidden_volume.dart';
import 'package:hidden_volume/src/bindings.dart';

import 'test_dylib.dart';

/// Build the uniffi wire form of a `StatsInfo`, big-endian, in the field order
/// `crates/hidden-volume-ffi/src/lib.rs` declares. Spelled out rather than
/// produced by `_Writer` so that a change to the shipped writer cannot quietly
/// change what this test considers correct.
Uint8List _statsBytes({
  required int commitSeq,
  required int commitHistoryLen,
  required int ownedChunkCount,
  required int totalSlotCount,
  required int reusableSlotCount,
  required int totalEntries,
  List<(int, int)> namespaceCounts = const <(int, int)>[],
  ({int ordinal, String message})? hardening,
}) {
  final out = BytesBuilder();
  void u64(int v) {
    final b = ByteData(8)..setUint64(0, v, Endian.big);
    out.add(b.buffer.asUint8List());
  }

  void i32(int v) {
    final b = ByteData(4)..setInt32(0, v, Endian.big);
    out.add(b.buffer.asUint8List());
  }

  u64(commitSeq);
  u64(commitHistoryLen);
  u64(ownedChunkCount);
  u64(totalSlotCount);
  u64(reusableSlotCount);
  u64(totalEntries);
  i32(namespaceCounts.length);
  for (final (ns, count) in namespaceCounts) {
    out.addByte(ns);
    u64(count);
  }
  if (hardening == null) {
    out.addByte(0);
  } else {
    out.addByte(1);
    i32(hardening.ordinal);
    final msg = utf8.encode(hardening.message);
    i32(msg.length);
    out.add(msg);
  }
  return out.toBytes();
}

void main() {
  setUpAll(() {
    overrideDylib(openTestDylib());
  });

  test('every scalar lands in its own field', () {
    // Six distinct values, so a decoder that is off by one field puts a
    // recognisably wrong number somewhere rather than reading a plausible one.
    // `reusableSlotCount` sits between `totalSlotCount` and `totalEntries`;
    // before this change it was not read at all, and appending it at the end
    // instead would have made every field after it wrong.
    final stats = debugReadStats(_statsBytes(
      commitSeq: 11,
      commitHistoryLen: 22,
      ownedChunkCount: 33,
      totalSlotCount: 44,
      reusableSlotCount: 55,
      totalEntries: 66,
      namespaceCounts: const <(int, int)>[(1, 7), (2, 9)],
    ));

    expect(stats.commitSeq, 11);
    expect(stats.commitHistoryLen, 22);
    expect(stats.ownedChunkCount, 33);
    expect(stats.totalSlotCount, 44);
    expect(stats.reusableSlotCount, 55);
    expect(stats.totalEntries, 66);
    expect(stats.namespaceCounts.length, 2);
    expect(stats.namespaceCounts[0].namespace, 1);
    expect(stats.namespaceCounts[0].count, 7);
    expect(stats.namespaceCounts[1].namespace, 2);
    expect(stats.namespaceCounts[1].count, 9);
    // The namespace list is variable-length, so the Option tag after it is the
    // offset most easily lost. Reading `null` here means the reader arrived at
    // the right byte.
    expect(stats.hardeningFailure, isNull);
  });

  test('each hardening step decodes as itself', () {
    // The step is the entire value of the field: padding failing means the
    // commit's SIZE is readable, churn failing means the slots it reused stand
    // alone in a snapshot diff, sync failing means neither masking write is on
    // the platter. Reporting one as another is worse advice than reporting
    // nothing, so the ordinals are pinned one by one rather than "some step
    // came back".
    const expected = <int, HvHardeningStep>{
      1: HvHardeningStep.padding,
      2: HvHardeningStep.churn,
      3: HvHardeningStep.sync,
    };
    expected.forEach((ordinal, step) {
      final stats = debugReadStats(_statsBytes(
        commitSeq: 5,
        commitHistoryLen: 1,
        ownedChunkCount: 2,
        totalSlotCount: 3,
        reusableSlotCount: 4,
        totalEntries: 6,
        hardening: (ordinal: ordinal, message: 'disk full'),
      ));
      expect(stats.hardeningFailure, isNotNull,
          reason: 'ordinal $ordinal decoded as no failure at all');
      expect(stats.hardeningFailure!.step, step);
      expect(stats.hardeningFailure!.message, 'disk full');
      // The record sits after the namespace list; a reader that mis-sized it
      // would still have got the scalars right, so check one of those too.
      expect(stats.reusableSlotCount, 4);
    });
  });

  test('a step this build does not know is refused, not guessed', () {
    // A newer cdylib with a fourth step. Mapping it onto one of the three we
    // have would tell a host the wrong thing is no longer true.
    expect(
      () => debugReadStats(_statsBytes(
        commitSeq: 1,
        commitHistoryLen: 1,
        ownedChunkCount: 1,
        totalSlotCount: 1,
        reusableSlotCount: 1,
        totalEntries: 1,
        hardening: (ordinal: 4, message: 'from the future'),
      )),
      throwsA(isA<StateError>()),
    );
  });

  test('reusableSlotCount tracks the pool the library actually built', () {
    // End-to-end, against a real container, and asserted as an EQUATION rather
    // than "greater than zero": a constant, or a field wired to the wrong
    // number, satisfies a non-zero check.
    //
    // `open` uses the constant-time path, which defers the orphan vacuum (audit
    // HV-01) — so the pool starts empty and `vacuumAfterOpen` is what fills it,
    // with exactly the slots it reports reclaiming.
    final tmp = Directory.systemTemp.createTempSync('hv_dart_pool_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final creating = SpaceHandleBindings.create(
      path: path,
      password: Uint8List.fromList('pwd'.codeUnits),
      argon: ArgonPreset.light,
    );
    // One commit per key, so each supersedes the previous KV index and leaves
    // the orphan index chunks the vacuum will retire.
    for (var i = 0; i < 40; i++) {
      creating.commit([
        HvWriteOpPut(
          namespace: 1,
          key: Uint8List.fromList('k$i'.codeUnits),
          value: Uint8List.fromList('v'.codeUnits),
        ),
      ]);
    }
    creating.close();

    final space = SpaceHandleBindings.open(
      path: path,
      password: Uint8List.fromList('pwd'.codeUnits),
    );
    addTearDown(space.close);

    final before = space.stats().reusableSlotCount;
    final reclaimed = space.vacuumAfterOpen();
    expect(reclaimed, greaterThan(0),
        reason: 'the fixture left no orphans, so the pool cannot move and this '
            'test proves nothing');

    expect(space.stats().reusableSlotCount, before + reclaimed,
        reason: 'the pool did not grow by what the vacuum said it reclaimed');
  });

  test(
      'a healthy space reports no hardening failure, and the acknowledgement '
      'reaches the library', () {
    final tmp = Directory.systemTemp.createTempSync('hv_dart_ack_');
    final path = '${tmp.path}/store.bin';
    addTearDown(() => tmp.deleteSync(recursive: true));

    final space = SpaceHandleBindings.create(
      path: path,
      password: Uint8List.fromList('pwd'.codeUnits),
      argon: ArgonPreset.light,
    );
    addTearDown(space.close);

    space.commit([
      HvWriteOpPut(
        namespace: 1,
        key: Uint8List.fromList('k'.codeUnits),
        value: Uint8List.fromList('v'.codeUnits),
      ),
    ]);

    final before = space.stats();
    expect(before.hardeningFailure, isNull,
        reason: 'a commit whose padding, churn and fsync all ran reported '
            '${before.hardeningFailure}');

    // The call has to reach Rust: a Dart-side no-op would pass an
    // "it is still null" assertion just as well. What proves the crossing is
    // that it goes through `rustCall` — a symbol the library did not export
    // would have failed at lookup, and a Rust-side error would arrive as an
    // `HvException` here.
    space.acknowledgeHardeningError();
    space.acknowledgeHardeningError();

    final after = space.stats();
    expect(after.hardeningFailure, isNull);
    // It dismisses a warning; it must not disturb anything else.
    expect(after.commitSeq, before.commitSeq);
    expect(after.totalEntries, before.totalEntries);
    expect(after.reusableSlotCount, before.reusableSlotCount);
    expect(after.totalSlotCount, before.totalSlotCount);
  });

  test('the worker isolate carries both ends of it too', () async {
    // `HvAsyncSpace` is what a Flutter host actually holds — the sync bindings
    // block the UI isolate. Its request/reply plumbing is a separate hop with
    // its own way to go wrong: a message type that nothing dispatches, or a
    // reply the caller decodes as the wrong shape. The analyzer catches a
    // missing `case` on the sealed request type; it cannot catch a round trip
    // that dispatches and then answers with nothing usable.
    final space = await HvAsyncSpace.create(
      path:
          '${Directory.systemTemp.createTempSync('hv_async_ack_').path}/s.bin',
      password: Uint8List.fromList('pwd'.codeUnits),
      argon: ArgonPreset.light,
      dylibPath: resolveDylibPath(),
    );
    addTearDown(space.close);

    await space.commit([
      HvWriteOpPut(
        namespace: 1,
        key: Uint8List.fromList('k'.codeUnits),
        value: Uint8List.fromList('v'.codeUnits),
      ),
    ]);

    final stats = await space.stats();
    expect(stats.hardeningFailure, isNull);
    // Decoded across the isolate boundary, not defaulted: `totalEntries` sits
    // AFTER `reusableSlotCount` on the wire, so a reply that lost its place
    // would have to get both wrong together to satisfy these two.
    expect(stats.reusableSlotCount, isNonNegative);
    expect(stats.totalEntries, greaterThanOrEqualTo(1));

    await space.acknowledgeHardeningError();
    expect((await space.stats()).hardeningFailure, isNull);
  });
}
