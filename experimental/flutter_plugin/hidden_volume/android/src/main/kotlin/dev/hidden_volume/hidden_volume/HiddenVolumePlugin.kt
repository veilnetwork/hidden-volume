package dev.hidden_volume.hidden_volume

import androidx.annotation.NonNull
import io.flutter.embedding.engine.plugins.FlutterPlugin

/**
 * Flutter plugin entry point — **no-op stub**.
 *
 * `hidden_volume` uses Dart `dart:ffi` (`lib/src/bindings.dart`) to
 * load the cdylib directly via `DynamicLibrary.open`; there is no
 * Kotlin code in the call path. This class exists solely to satisfy
 * the Flutter plugin contract (the manifest registers a plugin class
 * per platform).
 *
 * Audit cleanup 2026-05-10: previously contained a `MethodChannel`
 * "ping" stub that was a documented "secondary integration path".
 * That path was never wired up; integrators preferring a Method
 * Channel layer can write a thin app-side handler atop the
 * auto-generated Kotlin bindings in `bindings/kotlin/` (regenerate
 * via `cargo run --bin uniffi-bindgen --features bindgen-cli ...`).
 */
class HiddenVolumePlugin : FlutterPlugin {
    override fun onAttachedToEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        // No-op: Dart side loads the cdylib directly via dart:ffi.
    }

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        // No-op.
    }
}
