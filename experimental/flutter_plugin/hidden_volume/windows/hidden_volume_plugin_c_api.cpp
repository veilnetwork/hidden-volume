#include "include/hidden_volume/hidden_volume_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "hidden_volume_plugin.h"

void HiddenVolumePluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  hidden_volume::HiddenVolumePlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
