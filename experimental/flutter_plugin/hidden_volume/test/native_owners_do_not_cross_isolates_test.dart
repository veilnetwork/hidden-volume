import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// A native handle has ONE owner, and an isolate boundary makes two.
///
/// The wrappers here are plain Dart objects holding a raw `int` handle and a
/// `_closed` flag of their own. Sending one deep-copies both, and the copy
/// takes no new Rust `Arc` — so two objects believe they own one handle, and
/// either can free it. The other then clones or frees a pointer that is gone:
/// use-after-free, double-free, an allocator abort, or a container lock left
/// stranded, with nothing in Dart saying a word (report18 HV18-H1).
///
/// `@pragma('vm:isolate-unsendable')` turns that into a synchronous throw at
/// the send. Asserted structurally rather than by sending a real handle: an
/// instance needs an open container and the built cdylib, and the failure this
/// guards against is undefined behaviour — not something to demonstrate.
///
/// DERIVED, not listed: the classes it demands the pragma on are the ones that
/// hold a raw handle, so a wrapper added later is covered without anyone
/// remembering to add it here.
void main() {
  test('every owner of a native handle refuses to be sent', () {
    final sources = {
      'lib/src/bindings.dart': File('lib/src/bindings.dart').readAsStringSync(),
      'lib/hidden_volume.dart': File(
        'lib/hidden_volume.dart',
      ).readAsStringSync(),
    };

    // Owners, found by what makes them owners: a raw `int _handle`, or a field
    // holding one of the low-level wrappers.
    final owners = <String, String>{};
    final classPattern = RegExp(
      r'((?:@pragma\([^)]*\)\s*)*)class\s+(\w+)\s*\{([^]*?)\n\}',
      multiLine: true,
    );
    for (final entry in sources.entries) {
      for (final match in classPattern.allMatches(entry.value)) {
        final pragmas = match.group(1) ?? '';
        final name = match.group(2)!;
        final body = match.group(3)!;
        final ownsHandle = RegExp(r'\bint\s+_handle\b').hasMatch(body) ||
            RegExp(r'\b(SpaceHandleBindings|MultiSpaceHandleBindings)\s+_\w+')
                .hasMatch(body);
        if (ownsHandle) owners[name] = pragmas;
      }
    }

    // Vacuity guard: the check below passes on an empty map.
    expect(
      owners.keys,
      containsAll(<String>[
        'SpaceHandleBindings',
        'MultiSpaceHandleBindings',
        'HvSpace',
        'HvMultiSpace',
      ]),
      reason:
          'the owners were not recognised — found ${owners.keys.toList()}, so '
          'this guard is checking almost nothing',
    );

    final unmarked = [
      for (final owner in owners.entries)
        if (!owner.value.contains("vm:isolate-unsendable")) owner.key,
    ];
    expect(
      unmarked,
      isEmpty,
      reason:
          'these own a native handle and can be copied into another isolate, '
          'where a second owner frees what the first still uses: $unmarked',
    );
  });
}
