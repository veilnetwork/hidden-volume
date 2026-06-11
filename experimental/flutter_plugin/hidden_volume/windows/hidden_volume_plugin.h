#ifndef FLUTTER_PLUGIN_HIDDEN_VOLUME_PLUGIN_H_
#define FLUTTER_PLUGIN_HIDDEN_VOLUME_PLUGIN_H_

#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace hidden_volume {

// No-op plugin shell — see hidden_volume_plugin.cpp for rationale.
// Production call path uses Dart `dart:ffi` directly; this exists
// only to satisfy the Flutter Windows plugin contract.
class HiddenVolumePlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  HiddenVolumePlugin();

  virtual ~HiddenVolumePlugin();

  // Disallow copy and assign.
  HiddenVolumePlugin(const HiddenVolumePlugin&) = delete;
  HiddenVolumePlugin& operator=(const HiddenVolumePlugin&) = delete;
};

}  // namespace hidden_volume

#endif  // FLUTTER_PLUGIN_HIDDEN_VOLUME_PLUGIN_H_
