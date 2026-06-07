#!/usr/bin/env bash
# Build the `hidden-volume-ffi` staticlib for the 3 iOS-relevant
# Apple targets and bundle them into an `xcframework` consumable by
# CocoaPods + Flutter.
#
# REQUIRES MACOS WITH XCODE INSTALLED. This script is a no-op
# (early exit) on any other platform.
#
# Prerequisites:
#   - macOS host with Xcode + Command Line Tools
#   - Rust targets: aarch64-apple-ios (device), aarch64-apple-ios-sim
#                   (Apple-silicon simulator), x86_64-apple-ios (Intel
#                   simulator)
#
# Output:
#   experimental/flutter_plugin/hidden_volume/ios/HiddenVolumeFFI.xcframework/
#
# Usage:
#   ./scripts/build-ios.sh             # release
#   ./scripts/build-ios.sh --debug

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

# Minimum iOS deployment target. Must match
# `experimental/flutter_plugin/hidden_volume/ios/hidden_volume.podspec` `s.platform`.
# Rust's default for aarch64-apple-ios is iOS 10.0, but cc-rs (used to
# build zstd-sys / blake3 C code) defaults to the host SDK version
# (currently 17.5 on macos-14 runners). The mismatch produces an
# undefined-symbol link error for `___chkstk_darwin` (a stack-check
# intrinsic added in newer SDKs and only available when the
# deployment target is high enough). Setting this env var here makes
# both rustc and cc-rs target the SAME minimum, eliminating the
# warning ladder + the link error. iOS 13 is the practical minimum
# for a 2026 deployment (covers ~99% of active iPhones).
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-13.0}"

PROFILE="${PROFILE:-release}"

case "${1:-}" in
    --debug)  PROFILE=debug; shift ;;
    --help|-h)
        sed -n '2,/^set -euo/p' "$0" | sed 's/^# \?//' | head -n -1
        exit 0
        ;;
esac

# Pre-flight: macOS
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: build-ios.sh requires macOS with Xcode." >&2
    echo "       current host: $(uname -s)" >&2
    exit 1
fi

# Pre-flight: xcodebuild
if ! command -v xcodebuild >/dev/null 2>&1; then
    echo "error: xcodebuild not found. install Xcode + Command Line Tools." >&2
    exit 1
fi

# Pre-flight: Rust iOS targets
required_targets=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
installed=$(rustup target list --installed)
missing=()
for t in "${required_targets[@]}"; do
    if ! grep -q "^${t}$" <<< "$installed"; then
        missing+=("$t")
    fi
done
if (( ${#missing[@]} > 0 )); then
    echo "error: missing Rust targets: ${missing[*]}" >&2
    echo "       install with: rustup target add ${missing[*]}" >&2
    exit 1
fi

build_flag=""
if [[ "$PROFILE" == "release" ]]; then
    build_flag="--release"
fi

echo "==> building hidden-volume-ffi staticlib for iOS targets (profile: $PROFILE)"

for target in "${required_targets[@]}"; do
    echo "    → $target"
    cargo build $build_flag --target "$target" -p hidden-volume-ffi
done

# Locate per-target staticlibs.
profile_dir="release"
if [[ "$PROFILE" != "release" ]]; then
    profile_dir="debug"
fi
device_lib="target/aarch64-apple-ios/${profile_dir}/libhidden_volume_ffi.a"
sim_arm_lib="target/aarch64-apple-ios-sim/${profile_dir}/libhidden_volume_ffi.a"
sim_x86_lib="target/x86_64-apple-ios/${profile_dir}/libhidden_volume_ffi.a"

# Make a fat staticlib for the simulator slice (arm64 + x86_64).
sim_fat_lib="target/ios-sim-fat/${profile_dir}/libhidden_volume_ffi.a"
mkdir -p "$(dirname "$sim_fat_lib")"
lipo -create "$sim_arm_lib" "$sim_x86_lib" -output "$sim_fat_lib"

# Output xcframework.
out_dir="experimental/flutter_plugin/hidden_volume/ios"
xcfw="$out_dir/HiddenVolumeFFI.xcframework"
mkdir -p "$out_dir"
rm -rf "$xcfw"

# Headers come from uniffi-bindgen; the Swift binding regenerates the
# matching `*FFI.h` and `*FFI.modulemap`. We assume `bindings/swift/`
# has been regenerated *after* a release build of the cdylib has run.
headers_dir="bindings/swift"
if [[ ! -f "$headers_dir/hidden_volume_ffiFFI.h" ]]; then
    echo "error: $headers_dir/hidden_volume_ffiFFI.h missing." >&2
    echo "       regenerate Swift bindings first — see bindings/README.md § Regenerating" >&2
    exit 1
fi

xcodebuild -create-xcframework \
    -library "$device_lib"  -headers "$headers_dir" \
    -library "$sim_fat_lib" -headers "$headers_dir" \
    -output "$xcfw"

echo
echo "==> output: $xcfw"
echo "next step: in experimental/flutter_plugin/hidden_volume/ios/hidden_volume.podspec the"
echo "           xcframework is referenced as a vendored framework; run"
echo "           'flutter pub get' from the example app and 'pod install' from"
echo "           example/ios/."
