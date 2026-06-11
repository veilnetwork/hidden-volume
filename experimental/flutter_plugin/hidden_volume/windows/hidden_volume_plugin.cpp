// Flutter plugin entry point — no-op stub.
//
// `hidden_volume` uses Dart `dart:ffi` (`lib/src/bindings.dart`) to
// load `hidden_volume_ffi.dll` directly via `DynamicLibrary.open`;
// there is no C++ code in the call path. This file exists solely to
// satisfy the Flutter Windows plugin contract — `RegisterWithRegistrar`
// must exist and be exported via the `_c_api` header so the runner's
// generated_plugin_registrant.cc can call it.
//
// Audit cleanup 2026-05-10: previously contained a "getPlatformVersion"
// MethodChannel handler copied verbatim from `flutter create -t plugin`
// scaffolding. That handler had nothing to do with hidden-volume and
// was inconsistent with the Android/iOS "ping" stubs (since-removed
// in the same cleanup). The Dart FFI bindings make the channel
// unnecessary for any real call; integrators preferring a Method
// Channel layer can write a thin app-side handler atop the
// auto-generated bindings (run `cargo run --bin uniffi-bindgen ...`).

#include "hidden_volume_plugin.h"

#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace hidden_volume {

// static
void HiddenVolumePlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows *registrar) {
  // Register an empty plugin instance. The Dart side bypasses any
  // method channel and loads the cdylib directly.
  registrar->AddPlugin(std::make_unique<HiddenVolumePlugin>());
}

HiddenVolumePlugin::HiddenVolumePlugin() {}

HiddenVolumePlugin::~HiddenVolumePlugin() {}

}  // namespace hidden_volume
