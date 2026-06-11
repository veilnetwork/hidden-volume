package dev.hidden_volume.hidden_volume

import io.flutter.embedding.engine.plugins.FlutterPlugin
import org.mockito.Mockito
import kotlin.test.Test
import kotlin.test.assertTrue

/*
 * Smoke test for the Kotlin plugin shell.
 *
 * `HiddenVolumePlugin` is a deliberate no-op: the Dart layer talks to
 * the Rust cdylib directly via `dart:ffi` (`lib/src/bindings.dart`),
 * so there is no MethodChannel handler to exercise. The old
 * `getPlatformVersion` MethodChannel ping was removed in the
 * 2026-05-10 audit cleanup. These tests therefore only assert that the
 * plugin instantiates and attaches/detaches without throwing.
 *
 * Run from the command line via `./gradlew testDebugUnitTest` in the
 * `example/android/` directory, or directly from a JUnit-aware IDE.
 */

internal class HiddenVolumePluginTest {
    @Test
    fun instantiates_asFlutterPlugin() {
        val plugin = HiddenVolumePlugin()
        assertTrue(plugin is FlutterPlugin)
    }

    @Test
    fun attachAndDetach_areNoOp() {
        val plugin = HiddenVolumePlugin()
        val binding = Mockito.mock(FlutterPlugin.FlutterPluginBinding::class.java)

        // No-op shell: neither call touches the binding or throws.
        plugin.onAttachedToEngine(binding)
        plugin.onDetachedFromEngine(binding)
    }
}
