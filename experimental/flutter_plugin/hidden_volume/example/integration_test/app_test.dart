// End-to-end Flutter integration test. Runs the example app and taps
// the demo button; asserts the round-trip status text appears.
//
// Run on Windows desktop:
//   flutter test integration_test/app_test.dart -d windows
//
// Or on a connected Android device once the per-ABI .so files are
// bundled into the plugin's android/src/main/jniLibs/:
//   flutter test integration_test/app_test.dart -d <android-device-id>

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hidden_volume_example/main.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('demo round-trip succeeds', (tester) async {
    await tester.pumpWidget(const HvDemoApp());
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('run-demo')), findsOneWidget);

    await tester.tap(find.byKey(const Key('run-demo')));
    // The demo runs Argon2-light + several FFI roundtrips. Pump until
    // settled with a generous timeout so the worker isolate has time to
    // bootstrap, run KDF, and ship results back.
    await tester.pumpAndSettle(const Duration(seconds: 10));

    final status = tester.widget<SelectableText>(
      find.byKey(const Key('status')),
    );
    expect(status.data, startsWith('OK'));
    expect(status.data, contains('username = alice'));
    expect(status.data, contains('log entries = 5'));
  });
}
