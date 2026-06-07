import Flutter
import UIKit

/**
 iOS plugin entry point — **no-op stub**.

 `hidden_volume` uses Dart `dart:ffi` (`lib/src/bindings.dart`) to
 resolve symbols at process scope (`DynamicLibrary.process()`), since
 the iOS xcframework is statically linked into the app. There is no
 Swift code in the call path. This class exists solely to satisfy the
 Flutter plugin contract.

 Audit cleanup 2026-05-10: previously contained a `MethodChannel`
 "ping" stub that was a documented "secondary integration path".
 That path was never wired up; integrators preferring a Method
 Channel layer can write a thin app-side handler atop the
 auto-generated Swift bindings in `bindings/swift/` (regenerate via
 `cargo run --bin uniffi-bindgen --features bindgen-cli ...`).
 */
public class HiddenVolumePlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        // No-op: Dart side resolves symbols via DynamicLibrary.process().
    }
}
