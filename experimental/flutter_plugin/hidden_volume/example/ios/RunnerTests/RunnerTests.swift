import Flutter
import UIKit
import XCTest

@testable import hidden_volume

// Smoke test for the iOS plugin shell.
//
// `HiddenVolumePlugin` is a deliberate no-op: the Dart layer resolves
// the Rust FFI symbols at process scope via `DynamicLibrary.process()`,
// so there is no MethodChannel handler to exercise. The old
// `getPlatformVersion` MethodChannel ping was removed in the
// 2026-05-10 audit cleanup, so there is nothing channel-shaped left to
// assert. This test simply confirms the type is present and linkable.
//
// See https://developer.apple.com/documentation/xctest for more info.

class RunnerTests: XCTestCase {

  func testPluginTypeIsLinkable() {
    // The plugin registers via a static `register(with:)` entry point
    // and carries no instance state. Referencing the metatype proves
    // the no-op shell compiled and linked into the test target; there
    // is no MethodChannel behavior to exercise.
    let pluginType: AnyClass = HiddenVolumePlugin.self
    XCTAssertTrue(pluginType is FlutterPlugin.Type)
  }

}
