#!/usr/bin/env bash
#
# scripts/release.sh — local release-artifact build script.
#
# Produces a `dist/` directory with:
#   - The `hv` CLI binary (release, with `cli` feature)
#   - The `libhidden_volume_ffi.{so,dylib,dll}` cdylib
#   - The auto-generated foreign-language bindings (Python, Kotlin,
#     Swift, Ruby) regenerated against this exact cdylib
#   - A `SHA256SUMS` file with checksums of every artifact
#
# Usage:
#   ./scripts/release.sh                         # native target
#   TARGET=aarch64-unknown-linux-gnu \
#       ./scripts/release.sh                     # cross-compile (needs toolchain)
#
# Cross-compile prerequisites (Linux host):
#   sudo apt-get install gcc-aarch64-linux-gnu
#   rustup target add aarch64-unknown-linux-gnu
#
# This script mirrors the `release-build` GHA job in
# `.github/workflows/ci.yml`. CI is the source of truth for the
# canonical published artifacts; this is for ad-hoc local builds.
#
# Exit codes:
#   0 — success, artifacts in dist/
#   1 — build failed
#   2 — sha256sum / shasum not available

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)"
cd "$REPO_ROOT"

# Default to native target if not specified.
TARGET="${TARGET:-}"
DIST="$REPO_ROOT/dist${TARGET:+/$TARGET}"

# Pick a sha256 tool that exists on the host.
if command -v sha256sum >/dev/null 2>&1; then
    SHA="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA="shasum -a 256"
else
    echo "error: neither sha256sum nor shasum available" >&2
    exit 2
fi

CARGO_TARGET_FLAG=()
RELEASE_DIR="$REPO_ROOT/target/release"
if [ -n "$TARGET" ]; then
    CARGO_TARGET_FLAG=(--target "$TARGET")
    RELEASE_DIR="$REPO_ROOT/target/$TARGET/release"
fi

echo "==> building hv CLI (release)"
cargo build -p hidden-volume --release --features cli "${CARGO_TARGET_FLAG[@]}"

echo "==> building hidden-volume-ffi cdylib (release)"
cargo build -p hidden-volume-ffi --release "${CARGO_TARGET_FLAG[@]}"

# Locate the cdylib (varies by OS).
CDYLIB=""
for candidate in libhidden_volume_ffi.so libhidden_volume_ffi.dylib hidden_volume_ffi.dll; do
    if [ -f "$RELEASE_DIR/$candidate" ]; then
        CDYLIB="$RELEASE_DIR/$candidate"
        break
    fi
done
if [ -z "$CDYLIB" ]; then
    echo "error: cdylib not found in $RELEASE_DIR" >&2
    ls -la "$RELEASE_DIR" >&2 || true
    exit 1
fi
echo "    cdylib: $CDYLIB"

echo "==> regenerating bindings against the freshly-built cdylib"
# Bindgen runs on the host toolchain regardless of target; the bin
# was built earlier as part of the workspace build above.
# Audit pass 11 (L6): fail-loud on any bindgen error so we never
# package stale or missing bindings. Previously trailing `|| true`
# silently swallowed failures, letting the release ship with
# pre-existing bindings that may not match the just-built cdylib.
for lang in kotlin swift python ruby; do
    cargo run --bin uniffi-bindgen --features bindgen-cli -p hidden-volume-ffi -- \
        generate \
        --library "$CDYLIB" \
        --language "$lang" \
        --out-dir "bindings/$lang" >/dev/null
done

echo "==> staging artifacts in $DIST"
rm -rf "$DIST"
mkdir -p "$DIST"

# CLI binary (Windows variant has .exe).
if [ -f "$RELEASE_DIR/hv" ]; then
    cp "$RELEASE_DIR/hv" "$DIST/"
elif [ -f "$RELEASE_DIR/hv.exe" ]; then
    cp "$RELEASE_DIR/hv.exe" "$DIST/"
fi

# cdylib.
cp "$CDYLIB" "$DIST/"

# Bindings — copy the entire generated tree.
cp -r bindings "$DIST/bindings"

# Compute SHA256SUMS over every file in dist/, sorted for reproducibility.
echo "==> computing SHA256SUMS"
( cd "$DIST" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 $SHA ) > "$DIST/SHA256SUMS"

echo
echo "==> release artifacts in $DIST"
ls -la "$DIST"
echo
echo "==> SHA256SUMS:"
cat "$DIST/SHA256SUMS"
