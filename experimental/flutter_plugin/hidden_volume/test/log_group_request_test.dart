import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume/src/bindings.dart';

void main() {
  test('bounded log descriptors own nested ids before async dispatch', () {
    final first = [3, 1, 3], second = [2];
    final request = [
      HvLogReadGroup(logIds: first, maxBytes: 3),
      HvLogReadGroup(logIds: second, maxBytes: 1),
    ];
    final frozen = snapshotLogReadGroups(request);
    first[0] = 9;
    second.clear();
    request.clear();
    expect(frozen.map((group) => group.logIds), [
      [3, 1, 3],
      [2],
    ]);
    expect(frozen.map((group) => group.maxBytes), [3, 1]);
    expect(() => frozen.first.logIds[0] = 5, throwsUnsupportedError);
  });
  test('bounded log descriptors reject invalid bounds before dispatch', () {
    expect(
      () => snapshotLogReadGroups(
        List.filled(9, const HvLogReadGroup(logIds: [], maxBytes: 0)),
      ),
      throwsArgumentError,
    );
    expect(
      () => snapshotLogReadGroups([
        HvLogReadGroup(logIds: List.filled(65, 1), maxBytes: 99),
      ]),
      throwsArgumentError,
    );
    expect(
      () => snapshotLogReadGroups([
        const HvLogReadGroup(logIds: [1], maxBytes: -1),
      ]),
      throwsArgumentError,
    );
    expect(
      () => snapshotLogReadGroups([
        const HvLogReadGroup(logIds: [-1], maxBytes: 1),
      ]),
      throwsArgumentError,
    );
    expect(snapshotLogReadGroups([]), isEmpty);
  });
}
