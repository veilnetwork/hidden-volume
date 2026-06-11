#include <gtest/gtest.h>

#include <memory>

#include <flutter/plugin_registrar_windows.h>

#include "hidden_volume_plugin.h"

// Smoke test for the Windows plugin shell.
//
// `HiddenVolumePlugin` is a deliberate no-op: the Dart layer loads the
// Rust cdylib directly via `dart:ffi`, so there is no MethodChannel
// handler to exercise. The old `getPlatformVersion` handler (copied
// from `flutter create -t plugin` scaffolding) was removed in the
// 2026-05-10 audit cleanup. This test only verifies that the plugin
// constructs and destructs without error.

namespace hidden_volume {
namespace test {

TEST(HiddenVolumePlugin, ConstructsAndDestructs) {
  auto plugin = std::make_unique<HiddenVolumePlugin>();
  EXPECT_NE(plugin, nullptr);
  // Destruction at scope exit must not throw (no-op shell).
}

}  // namespace test
}  // namespace hidden_volume
