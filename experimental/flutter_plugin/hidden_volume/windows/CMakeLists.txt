# The Flutter tooling requires that developers have a version of Visual Studio
# installed that includes CMake 3.14 or later. You should not increase this
# version, as doing so will cause the plugin to fail to compile for some
# customers of the plugin.
cmake_minimum_required(VERSION 3.14)

# Project-level configuration.
set(PROJECT_NAME "hidden_volume")
project(${PROJECT_NAME} LANGUAGES CXX)

# Explicitly opt in to modern CMake behaviors to avoid warnings with recent
# versions of CMake.
cmake_policy(VERSION 3.14...3.25)

# This value is used when generating builds using this plugin, so it must
# not be changed
set(PLUGIN_NAME "hidden_volume_plugin")

# Any new source files that you add to the plugin should be added here.
list(APPEND PLUGIN_SOURCES
  "hidden_volume_plugin.cpp"
  "hidden_volume_plugin.h"
)

# Define the plugin library target. Its name must not be changed (see comment
# on PLUGIN_NAME above).
add_library(${PLUGIN_NAME} SHARED
  "include/hidden_volume/hidden_volume_plugin_c_api.h"
  "hidden_volume_plugin_c_api.cpp"
  ${PLUGIN_SOURCES}
)

# Apply a standard set of build settings that are configured in the
# application-level CMakeLists.txt. This can be removed for plugins that want
# full control over build settings.
apply_standard_settings(${PLUGIN_NAME})

# Symbols are hidden by default to reduce the chance of accidental conflicts
# between plugins. This should not be removed; any symbols that should be
# exported should be explicitly exported with the FLUTTER_PLUGIN_EXPORT macro.
set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)

# Source include directories and library dependencies. Add any plugin-specific
# dependencies here.
target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter flutter_wrapper_plugin)

# List of absolute paths to libraries that should be bundled with the plugin.
# Flutter's bundle pipeline copies every entry into the runner output dir
# alongside the .exe, so `DynamicLibrary.open('hidden_volume_ffi.dll')`
# from `lib/src/bindings.dart` resolves at runtime.
#
# `hidden_volume_ffi.dll` is the uniffi 0.31 cdylib produced by
# `cargo build -p hidden-volume-ffi --release` at the repo root. We
# prefer the release artifact and fall back to debug if release is
# missing — the FFI surface and ABI are identical between profiles.
# Flutter consumes the plugin via a Windows junction at
# `example/windows/flutter/ephemeral/.plugin_symlinks/hidden_volume`,
# so navigating "up" from CMAKE_CURRENT_SOURCE_DIR lands in the example
# tree, not the real plugin. We avoid the issue entirely by requiring
# the cdylib to live INSIDE the plugin's windows tree (`windows/lib/`).
# `scripts/build-windows.sh` (or the manual copy documented in
# `bindings/README.md` § Windows) places it there.
set(_HV_DLL_BUNDLED "${CMAKE_CURRENT_SOURCE_DIR}/lib/hidden_volume_ffi.dll")

if(EXISTS "${_HV_DLL_BUNDLED}")
  set(_HV_DLL "${_HV_DLL_BUNDLED}")
else()
  message(FATAL_ERROR
    "hidden_volume_ffi.dll not found at:\n"
    "  ${_HV_DLL_BUNDLED}\n"
    "Build + stage it first:\n"
    "  cargo build -p hidden-volume-ffi --release\n"
    "  cp target/release/hidden_volume_ffi.dll experimental/flutter_plugin/hidden_volume/windows/lib/\n"
    "Or run scripts/build-windows.sh from the repo root.")
endif()

set(hidden_volume_bundled_libraries
  "${_HV_DLL}"
  PARENT_SCOPE
)

# === Tests ===
# These unit tests can be run from a terminal after building the example, or
# from Visual Studio after opening the generated solution file.

# Only enable test builds when building the example (which sets this variable)
# so that plugin clients aren't building the tests.
if (${include_${PROJECT_NAME}_tests})
set(TEST_RUNNER "${PROJECT_NAME}_test")
enable_testing()

# Add the Google Test dependency.
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/release-1.11.0.zip
)
# Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
# Disable install commands for gtest so it doesn't end up in the bundle.
set(INSTALL_GTEST OFF CACHE BOOL "Disable installation of googletest" FORCE)
FetchContent_MakeAvailable(googletest)

# The plugin's C API is not very useful for unit testing, so build the sources
# directly into the test binary rather than using the DLL.
add_executable(${TEST_RUNNER}
  test/hidden_volume_plugin_test.cpp
  ${PLUGIN_SOURCES}
)
apply_standard_settings(${TEST_RUNNER})
target_include_directories(${TEST_RUNNER} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(${TEST_RUNNER} PRIVATE flutter_wrapper_plugin)
target_link_libraries(${TEST_RUNNER} PRIVATE gtest_main gmock)
# flutter_wrapper_plugin has link dependencies on the Flutter DLL.
add_custom_command(TARGET ${TEST_RUNNER} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
  "${FLUTTER_LIBRARY}" $<TARGET_FILE_DIR:${TEST_RUNNER}>
)

# Enable automatic test discovery.
include(GoogleTest)
gtest_discover_tests(${TEST_RUNNER})
endif()
