import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/hidden_volume.dart' as hv;
import 'package:hidden_volume/src/bindings.dart' show overrideDylib;
import 'test_dylib.dart';

Uint8List bytes(String value) => Uint8List.fromList(value.codeUnits);
void main() {
  setUpAll(() {
    final explicit = Platform.environment['XVEIL_HV_DYLIB'];
    if (explicit != null && explicit.isNotEmpty) {
      expect(File(resolveDylibPath()).resolveSymbolicLinksSync(),
          File(explicit).resolveSymbolicLinksSync(),
          reason: 'the host resolver must execute the artifact under qualification');
    }
    overrideDylib(openTestDylib());
  });
  test('sync exact native groups preserve order, byte caps and fresh data', () {
    final dir = Directory.systemTemp.createTempSync('hv-groups-sync-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final space = hv.HvSpace.create(
        path: '${dir.path}/fixture.hv',
        password: bytes('fixture'),
        argon: hv.ArgonPreset.light);
    addTearDown(space.close);
    space.commit([
      hv.HvWriteOpAppendLog(namespace: 3, logId: 1, payload: bytes('a')),
      hv.HvWriteOpAppendLog(namespace: 3, logId: 2, payload: bytes('bc'))
    ]);
    final groups = [
      const hv.HvLogReadGroup(logIds: [2, 1, 2], maxBytes: 5),
      const hv.HvLogReadGroup(logIds: [], maxBytes: 0)
    ];
    expect(space.readLogGroups(3, groups), [bytes('bcabc'), <int>[]]);
    expect(
        space.readLogGroups(3, [
          const hv.HvLogReadGroup(logIds: [1, 2], maxBytes: 1)
        ]),
        isNull);
    expect(
        space.readLogGroups(3, [
          const hv.HvLogReadGroup(logIds: [99], maxBytes: 5)
        ]),
        isNull);
    expect(
        () => space.readLogGroups(
            3, [hv.HvLogReadGroup(logIds: List.filled(65, 1), maxBytes: 99)]),
        throwsArgumentError);
    space.commit([const hv.HvWriteOpDeleteLog(namespace: 3, logId: 2)]);
    expect(space.readLogGroups(3, groups), isNull);
    space.commit(
        [hv.HvWriteOpAppendLog(namespace: 3, logId: 2, payload: bytes('de'))]);
    expect(space.readLogGroups(3, groups), [bytes('deade'), <int>[]]);
  });
  test('async exact groups snapshot descriptors before isolate dispatch',
      () async {
    final dir = Directory.systemTemp.createTempSync('hv-groups-async-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final space = await hv.HvAsyncSpace.create(
        path: '${dir.path}/fixture.hv',
        password: bytes('fixture'),
        argon: hv.ArgonPreset.light,
        dylibPath: resolveDylibPath());
    addTearDown(space.close);
    await space.commit([
      hv.HvWriteOpAppendLog(namespace: 3, logId: 1, payload: bytes('a')),
      hv.HvWriteOpAppendLog(namespace: 3, logId: 2, payload: bytes('bc'))
    ]);
    final ids = [2, 1, 2],
        groups = [hv.HvLogReadGroup(logIds: ids, maxBytes: 5)];
    final result = space.readLogGroups(3, groups);
    ids[0] = 99;
    groups.clear();
    expect(await result, [bytes('bcabc')]);
    expect(
        await space.readLogGroups(3, [
          const hv.HvLogReadGroup(logIds: [1, 2], maxBytes: 1)
        ]),
        isNull);
  });
  test('multi-space exact groups keep same ids isolated by space', () {
    final dir = Directory.systemTemp.createTempSync('hv-groups-multi-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final path = '${dir.path}/fixture.hv';
    final first = hv.HvSpace.create(
        path: path, password: bytes('first'), argon: hv.ArgonPreset.light);
    final a = first.spaceKeys();
    first.close();
    final second = hv.HvSpace.addSpace(path: path, password: bytes('second'));
    final b = second.spaceKeys();
    second.close();
    final multi = hv.HvMultiSpace.open(path: path);
    addTearDown(multi.close);
    final ia = multi.openSpace(a), ib = multi.openSpace(b);
    final groups = [
      const hv.HvLogReadGroup(logIds: [1, 1], maxBytes: 12)
    ];
    for (final entry in [(ia, 'alice'), (ib, 'bob')]) {
      multi.commit(entry.$1, [
        hv.HvWriteOpAppendLog(namespace: 3, logId: 1, payload: bytes(entry.$2))
      ]);
    }
    expect(multi.readLogGroups(ia, 3, groups), [bytes('alicealice')]);
    expect(multi.readLogGroups(ib, 3, groups), [bytes('bobbob')]);
    expect(() => multi.readLogGroups(99, 3, groups),
        throwsA(isA<hv.HvException>()));
  });
}
