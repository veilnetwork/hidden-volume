#!/usr/bin/env bash
# Build the `hidden-volume-ffi` cdylib for Windows (x86_64-pc-windows-msvc)
# and copy `hidden_volume_ffi.dll` into the Flutter plugin's
# `windows/lib/` so a downstream `flutter build windows` picks it up
# via the bundled-libraries hook in `windows/CMakeLists.txt`.
#
# Why a dedicated copy step (vs reading from `target/release/` directly):
#   The Flutter Windows plugin pipeline mounts the plugin under a
#   junction at `example/windows/flutter/ephemeral/.plugin_symlinks/`,
#   so `${CMAKE_CURRENT_SOURCE_DIR}/../..` from the plugin's
#   `windows/CMakeLists.txt` traverses the symlink hierarchy and never
#   reaches `target/`. Staging the .dll inside the plugin tree makes
#   the CMake reference path-independent.
#
# Usage:
#   ./scripts/build-windows.sh           # release
#   ./scripts/build-windows.sh --debug   # debug

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

PROFILE="${PROFILE:-release}"
case "${1:-}" in
    --debug) PROFILE=debug ;;
    --help|-h)
        sed -n '2,/^set -euo/p' "$0" | sed 's/^# \?//' | head -n -1
        exit 0
        ;;
esac

build_flag=""
if [[ "$PROFILE" == "release" ]]; then
    build_flag="--release"
fi

echo "==> building hidden-volume-ffi for windows (profile: $PROFILE)"
cargo build -p hidden-volume-ffi $build_flag

src="target/$PROFILE/hidden_volume_ffi.dll"
out_dir="experimental/flutter_plugin/hidden_volume/windows/lib"
mkdir -p "$out_dir"
cp "$src" "$out_dir/"

echo
echo "==> staged:"
ls -lh "$out_dir/hidden_volume_ffi.dll"
echo
echo "next step: cd experimental/flutter_plugin/hidden_volume/example && flutter run -d windows"
