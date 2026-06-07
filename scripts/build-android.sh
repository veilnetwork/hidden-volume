#!/usr/bin/env bash
# Build the `hidden-volume-ffi` cdylib for all 4 supported Android ABIs
# via cargo-ndk, then copy the resulting `.so` files into the Flutter
# plugin's `jniLibs/<abi>/` directory so a downstream Flutter build
# picks them up automatically.
#
# Prerequisites:
#   - rustup target add aarch64-linux-android armv7-linux-androideabi \
#                       x86_64-linux-android i686-linux-android
#   - cargo install cargo-ndk
#   - $ANDROID_NDK_HOME set to a v25+ NDK install (e.g. r25c or newer)
#
# Output:
#   experimental/flutter_plugin/hidden_volume/android/src/main/jniLibs/arm64-v8a/libhidden_volume_ffi.so
#   experimental/flutter_plugin/hidden_volume/android/src/main/jniLibs/armeabi-v7a/libhidden_volume_ffi.so
#   experimental/flutter_plugin/hidden_volume/android/src/main/jniLibs/x86_64/libhidden_volume_ffi.so
#   experimental/flutter_plugin/hidden_volume/android/src/main/jniLibs/x86/libhidden_volume_ffi.so
#
# Usage:
#   ./scripts/build-android.sh             # release build, all 4 ABIs
#   ./scripts/build-android.sh --debug     # debug build (faster, larger)
#   PROFILE=release ABIS="arm64-v8a x86_64" ./scripts/build-android.sh

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

PROFILE="${PROFILE:-release}"
ABIS_DEFAULT="arm64-v8a armeabi-v7a x86_64 x86"
ABIS="${ABIS:-$ABIS_DEFAULT}"

case "${1:-}" in
    --debug)  PROFILE=debug; shift ;;
    --help|-h)
        sed -n '2,/^set -euo/p' "$0" | sed 's/^# \?//' | head -n -1
        exit 0
        ;;
esac

# Pre-flight: NDK
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    echo "error: \$ANDROID_NDK_HOME is not set." >&2
    echo "       install Android NDK r25c or newer and export the path." >&2
    echo "       on Linux, e.g. via the Android Studio SDK Manager or the standalone" >&2
    echo "       NDK package: https://developer.android.com/ndk/downloads" >&2
    exit 1
fi
if [[ ! -d "$ANDROID_NDK_HOME" ]]; then
    echo "error: \$ANDROID_NDK_HOME=$ANDROID_NDK_HOME is not a directory." >&2
    exit 1
fi

# Pre-flight: cargo-ndk
if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo "error: cargo-ndk is not installed." >&2
    echo "       install with: cargo install cargo-ndk" >&2
    exit 1
fi

# Pre-flight: Rust targets
required_targets=(aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android)
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

# Build flag
build_flag=""
if [[ "$PROFILE" == "release" ]]; then
    build_flag="--release"
fi

# Map ABI → cargo-ndk -t arg (cargo-ndk understands Android ABI names directly).
abi_args=()
for abi in $ABIS; do
    abi_args+=(-t "$abi")
done

echo "==> building hidden-volume-ffi for ABIs: $ABIS (profile: $PROFILE)"
echo "    NDK: $ANDROID_NDK_HOME"

# cargo-ndk produces target/<rust-target>/<profile>/libhidden_volume_ffi.so per ABI
# and (with -o) copies into a jniLibs-shaped output dir.
out_dir="experimental/flutter_plugin/hidden_volume/android/src/main/jniLibs"
mkdir -p "$out_dir"

cargo ndk "${abi_args[@]}" \
    -o "$out_dir" \
    build $build_flag -p hidden-volume-ffi

echo
echo "==> output:"
find "$out_dir" -name "libhidden_volume_ffi.so" -exec ls -lh {} \;
echo
echo "next step: regenerate Kotlin bindings (see bindings/README.md § Regenerating)"
echo "           then run 'flutter pub get' inside experimental/flutter_plugin/hidden_volume/"
