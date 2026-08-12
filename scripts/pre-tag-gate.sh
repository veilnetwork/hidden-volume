#!/usr/bin/env bash
# scripts/pre-tag-gate.sh — the gate that runs before a release tag.
#
# Branch/PR CI is deliberately not wired (the local release checklist §4), so this list IS the
# fast-feedback mechanism. It lived as fifteen commands in a code block that a
# person copied by hand, which has two failure modes: a step gets skipped
# because the block is long, and the block drifts from what the workflows
# actually run.
#
# So the list lives here now and the local release checklist points at it. One source, one
# command.
#
# ## What a SKIP means here
#
# Two gates need a toolchain that is not on every host — the Android NDK and
# mingw-w64. A skipped gate is NOT a passed gate: it is a question nobody
# asked, and this prints them under NOT CHECKED at the end where they cannot
# be mistaken for green. The Android one exists because a cfg-gating
# regression escaped the v1.0.0 push on a darwin host that had no NDK, which
# is exactly what a silent skip looks like from the outside.
#
# Exit code: 0 only if every gate that RAN passed. Skips do not fail the run —
# they are reported, and it is the reader's job to decide whether a release
# may go out without them.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FAILED=()
SKIPPED=()

# Run one gate. `name` is what the summary prints; the rest is the command.
gate() {
  local name="$1"; shift
  printf '\n=== %s\n' "$name"
  if "$@"; then
    printf '    ok   %s\n' "$name"
  else
    printf '    FAIL %s\n' "$name"
    FAILED+=("$name")
  fi
}

skip() {
  printf '\n=== %s\n    SKIP %s\n' "$1" "$2"
  SKIPPED+=("$1 — $2")
}

gate "fmt" cargo fmt --all -- --check
gate "clippy (all features, warnings deny)" \
  cargo clippy --workspace --all-targets --all-features -- -D warnings
gate "rustdoc (all features)" \
  env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
gate "rustdoc (no default features)" \
  env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-default-features --no-deps
gate "tests (all features)" cargo test --workspace --all-features --no-fail-fast
gate "public API surface" ./scripts/dump-public-api.sh --check
gate "docs version drift" ./scripts/check-docs-version-drift.sh

# In-repo dependency constraints. Sibling crates are depended on by path AND
# version; cargo uses the path locally and the version when published, so a
# stale `version =` costs nothing until the number stops matching. The fuzz
# crate's said `^1.1.0` through three releases — caret semantics resolved it
# every time — and the v2.0.0 bump is what finally broke it, in CI, on the
# release tag. This gate is cheap and would have said so before the push.
gate "in-repo version constraints" ./scripts/check-intra-repo-versions.sh

# The checksum table is read out of the cdylib, so it has to exist first.
# A stale table fails the app CLOSED at launch (audit HV-05), and it drifts
# more easily than it sounds: uniffi hashes the metadata with the DOCSTRING in
# it, so editing a doc comment on an exported method moves its checksum.
gate "build cdylib (release)" cargo build -p hidden-volume-ffi --release
gate "UniFFI checksum table" python3 scripts/regen-dart-checksums.py --check

# Android cross-compile: catches the `target_os = "android"` branches, which
# no darwin check sees. std's `try_lock` returns Err(Unsupported) there, which
# is why the Android flock hardening routes through libc — and why a cfg
# regression escaped the v1.0.0 push.
NDK="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/26.3.11579264}"
if command -v cargo-ndk >/dev/null 2>&1 && [ -d "$NDK" ]; then
  gate "android cross-compile (aarch64)" \
    env ANDROID_NDK_HOME="$NDK" RUSTFLAGS="-D warnings" \
    cargo ndk -t aarch64-linux-android -- build -p hidden-volume
else
  skip "android cross-compile (aarch64)" \
    "needs cargo-ndk and an NDK at \$ANDROID_NDK_HOME ($NDK)"
fi

# Windows cross-compile: `hv.exe` ships in every release and its `cfg(windows)`
# arms are invisible to every check above. This type-checks them on a darwin
# host in seconds; `windows-release-gate.yml` covers the running half.
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 \
  && rustup target list --installed 2>/dev/null | grep -q x86_64-pc-windows-gnu; then
  gate "windows cross-compile (type check)" \
    env CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
    cargo check --target x86_64-pc-windows-gnu -p hidden-volume --features cli --all-targets
else
  skip "windows cross-compile (type check)" \
    "needs mingw-w64 and the x86_64-pc-windows-gnu target"
fi

printf '\n========================================\n'
if [ ${#SKIPPED[@]} -gt 0 ]; then
  printf 'NOT CHECKED (%d) — these are questions nobody asked:\n' "${#SKIPPED[@]}"
  printf '  - %s\n' "${SKIPPED[@]}"
fi
if [ ${#FAILED[@]} -gt 0 ]; then
  printf 'FAILED (%d):\n' "${#FAILED[@]}"
  printf '  - %s\n' "${FAILED[@]}"
  exit 1
fi
printf 'every gate that ran passed\n'
exit 0
