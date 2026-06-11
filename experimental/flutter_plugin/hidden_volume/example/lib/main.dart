// Minimal example app exercising the `hidden_volume` plugin
// end-to-end. Drives [HvAsyncSpace.create] / commit / get on a press
// and renders the round-trip result on screen.
//
// Runs on Windows desktop today (`flutter run -d windows`); the same
// code targets Android once the per-ABI `.so` files in the plugin's
// `android/src/main/jniLibs/` are built (see
// `scripts/build-android.sh`).

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:hidden_volume/hidden_volume.dart';

void main() {
  runApp(const HvDemoApp());
}

class HvDemoApp extends StatelessWidget {
  const HvDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'hidden_volume demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const HvDemoPage(),
    );
  }
}

class HvDemoPage extends StatefulWidget {
  const HvDemoPage({super.key});

  @override
  State<HvDemoPage> createState() => _HvDemoPageState();
}

class _HvDemoPageState extends State<HvDemoPage> {
  String _status = 'Press the button to run a round-trip.';
  bool _busy = false;

  Future<void> _runDemo() async {
    setState(() {
      _busy = true;
      _status = 'Running…';
    });

    final tmp = await Directory.systemTemp.createTemp('hv_demo_');
    final path = '${tmp.path}/store.bin';
    final pwd = Uint8List.fromList('demo-passphrase'.codeUnits);

    try {
      final space = await HvAsyncSpace.create(
        path: path,
        password: pwd,
        argon: ArgonPreset.light,
      );
      await space.commit([
        HvWriteOpPut(
          namespace: 1,
          key: Uint8List.fromList('username'.codeUnits),
          value: Uint8List.fromList('alice'.codeUnits),
        ),
        for (var i = 0; i < 5; i++)
          HvWriteOpAppendLog(
            namespace: 3,
            logId: i,
            payload: Uint8List.fromList('msg-$i'.codeUnits),
          ),
      ]);

      final username = await space.get(
          1, Uint8List.fromList('username'.codeUnits));
      final entries =
          await space.iterLogRange(namespace: 3, limit: 100);
      final stats = await space.stats();
      await space.close();

      final hi = await headerInfoAsync(path);

      setState(() {
        _status = 'OK\n'
            'username = ${String.fromCharCodes(username!)}\n'
            'log entries = ${entries.length}\n'
            'commit_seq = ${stats.commitSeq}\n'
            'file_size = ${hi.fileSizeBytes} bytes\n'
            'salt = ${hi.saltHex.substring(0, 16)}…';
      });
    } on HvException catch (e) {
      setState(() => _status = 'HvException.${e.kind}: ${e.message}');
    } catch (e) {
      setState(() => _status = 'unexpected: $e');
    } finally {
      try {
        await tmp.delete(recursive: true);
      } catch (_) {/* best-effort */}
      setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: const Text('hidden_volume demo'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            FilledButton.icon(
              key: const Key('run-demo'),
              onPressed: _busy ? null : _runDemo,
              icon: const Icon(Icons.play_arrow),
              label: const Text('Run round-trip'),
            ),
            const SizedBox(height: 16),
            Expanded(
              child: SingleChildScrollView(
                child: SelectableText(
                  _status,
                  key: const Key('status'),
                  style: const TextStyle(fontFamily: 'monospace'),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
