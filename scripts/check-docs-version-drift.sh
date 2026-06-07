#!/usr/bin/env bash
#
# scripts/check-docs-version-drift.sh — pre-tag doc-actualization gate.
#
# Run this **before** tagging a new release; it catches the
# class of doc drift the 2026-05-28 v3 format-bump introduced —
# `docs/` describing format vN-1 (or earlier) while the code already
# emits vN. CLAUDE.md §3 doc-actualization policy makes this a
# pre-tag gate violation.
#
# How it works:
#   1. Reads `PARAMS_VERSION` from `crates/hidden-volume/src/crypto/kdf.rs`
#      (canonical source of truth).
#   2. Greps `docs/` AND the top-level narrative docs (`DESIGN.md`,
#      `DESIGN.ru.md`, `README.md`, `README.ru.md`, `SECURITY.md`,
#      `SECURITY.ru.md`, `CLAUDE.md`) for tell-tale stale patterns of
#      any *prior* generation: `format_version = N` for
#      `N < PARAMS_VERSION`, and the legacy `80-byte cleartext`
#      phrasing (v2-only).
#   3. Exits non-zero with a per-finding report if anything matched.
#
# What is INTENTIONALLY excluded:
#   - `CHANGELOG.md`, `TASKS.md`, `TASKS_ARCHIVE.md` — these are
#     historical record by design; mentions of older versions in their
#     past entries are correct.
#
# To update on the next format bump (vN → vN+1): no edits needed
# here — `PARAMS_VERSION` lives in code; the script enumerates all
# prior generations automatically.
#
# Usage:
#   ./scripts/check-docs-version-drift.sh
#
# Exit codes:
#   0 — docs look consistent with current code-side PARAMS_VERSION
#   1 — drift found; see report
#   2 — could not read PARAMS_VERSION from the source

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)"
cd "$REPO_ROOT"

KDF_RS="$REPO_ROOT/crates/hidden-volume/src/crypto/kdf.rs"

if [ ! -f "$KDF_RS" ]; then
    echo "error: cannot locate $KDF_RS — wrong repo root?" >&2
    exit 2
fi

# Extract the integer value of `pub const PARAMS_VERSION: u16 = N;`.
PARAMS_VERSION=$(grep -E '^pub const PARAMS_VERSION: u16 = [0-9]+;' "$KDF_RS" \
    | sed -E 's/^pub const PARAMS_VERSION: u16 = ([0-9]+);.*/\1/' \
    | head -n1)

if [ -z "$PARAMS_VERSION" ]; then
    echo "error: PARAMS_VERSION not parseable from $KDF_RS" >&2
    exit 2
fi

# Files in scope. `docs/` is the directory; the rest are
# individual top-level narrative docs that also describe the
# format. CHANGELOG.md / TASKS.md are excluded by design — they
# are append-only historical record.
SEARCH_PATHS=(docs/)
TOP_LEVEL=(DESIGN.md DESIGN.ru.md README.md README.ru.md SECURITY.md SECURITY.ru.md CLAUDE.md)
for f in "${TOP_LEVEL[@]}"; do
    if [ -f "$f" ]; then
        SEARCH_PATHS+=("$f")
    fi
done

echo "==> current PARAMS_VERSION = $PARAMS_VERSION (from $KDF_RS)"
echo "==> checking ${#SEARCH_PATHS[@]} path(s) for stale references to v1..v$((PARAMS_VERSION - 1))"

FOUND=0
REPORT=$(mktemp)
trap 'rm -f "$REPORT"' EXIT

# Pattern 1: `format_version = N` or `format_version=N` where N < current.
# Anchored as a *literal text* assertion (the doc says "currently N");
# we tolerate the same number appearing inside a v3-current explanation
# like "v2 readers refuse v3 files" by excluding lines that also
# mention the current version.
for V in $(seq 1 $((PARAMS_VERSION - 1))); do
    while IFS=: read -r FILE LINE TEXT; do
        # Skip if the same line also mentions the current version
        # (e.g. "v3 readers refuse v2 files" — that's a v3-correct
        # cross-reference, not stale).
        if echo "$TEXT" | grep -qE "v$PARAMS_VERSION|format_version\s*=\s*$PARAMS_VERSION|format-version $PARAMS_VERSION|currently \`$PARAMS_VERSION\`"; then
            continue
        fi
        echo "  [STALE] $FILE:$LINE — claims format_version = $V" >> "$REPORT"
        FOUND=$((FOUND + 1))
    done < <(grep -rnE "format_version\s*=\s*$V\b|currently \`$V\`" "${SEARCH_PATHS[@]}" 2>/dev/null || true)
done

# Pattern 2: "80-byte cleartext header" — only correct for v2; v3 is
# 48 bytes. If a future bump changes the header size again, append
# its size to this exclusion list (or refactor to read from
# `HEADER_LEN` in the source).
while IFS=: read -r FILE LINE TEXT; do
    # Allow lines that *contrast* old vs new (the changelog and
    # threat-model legitimately reference "80-byte" in the v2 vs v3
    # context). Skip any line that also mentions "48-byte" or "v3".
    if echo "$TEXT" | grep -qE "48-byte|48 байт|v3|→ 48|: 80 → 48"; then
        continue
    fi
    echo "  [STALE] $FILE:$LINE — \"80-byte cleartext header\" (v2-only phrasing)" >> "$REPORT"
    FOUND=$((FOUND + 1))
done < <(grep -rnE "80-byte cleartext header|80-байтный cleartext" "${SEARCH_PATHS[@]}" 2>/dev/null || true)

# Pattern 4: experimental Flutter plugin's hand-written Dart FFI
# must not carry the v2-era `containerIdHex` field. The Rust FFI
# `HeaderInfo` dropped it in v3 (#10); a stale Dart binding would
# misalign the binary FFI buffer on the first `headerInfo()` call.
# Pre-tag gate catches this class of cross-language drift.
DART_BINDINGS="$REPO_ROOT/experimental/flutter_plugin/hidden_volume/lib/src/bindings.dart"
if [ -f "$DART_BINDINGS" ]; then
    # Only flag active code references — skip Dart doc-comment lines
    # (`///`) and inline block-comment lines, which may legitimately
    # explain "what v2 had and v3 removed".
    while IFS=: read -r LINE TEXT; do
        case "${TEXT// /}" in
            ///*|/\**) continue ;;  # docstring or block comment — not code
        esac
        echo "  [STALE] $DART_BINDINGS:$LINE — Dart bindings reference v2 \"containerIdHex\"" >> "$REPORT"
        FOUND=$((FOUND + 1))
    done < <(grep -nE "containerIdHex" "$DART_BINDINGS" 2>/dev/null || true)
fi

# Pattern 3: stale `uniffi 0.X` references where X is older than the
# version pinned in `crates/hidden-volume-ffi/Cargo.toml`. The FFI
# crate is the source of truth; older versions referenced in narrative
# docs are doc drift.
FFI_TOML="$REPO_ROOT/crates/hidden-volume-ffi/Cargo.toml"
if [ -f "$FFI_TOML" ]; then
    # macOS sed has no `\s`; use `[[:space:]]*` for portability.
    UNIFFI_VERSION=$(grep -E '^uniffi[[:space:]]*=[[:space:]]*\{' "$FFI_TOML" \
        | head -n1 \
        | sed -E 's/.*version[[:space:]]*=[[:space:]]*"([0-9]+\.[0-9]+)".*/\1/')
    if [ -n "$UNIFFI_VERSION" ] && [[ "$UNIFFI_VERSION" =~ ^[0-9]+\.[0-9]+$ ]]; then
        while IFS=: read -r FILE LINE TEXT; do
            # `uniffi 0.X+` is a legitimate MSRV-style note ("requires
            # 0.25+ for proc-macro support") — not drift. Only flag
            # exact-version refs that aren't the current one.
            if echo "$TEXT" | grep -qE "uniffi 0\.[0-9]+\+"; then
                continue
            fi
            echo "  [STALE] $FILE:$LINE — references older \"uniffi 0.X\" (workspace pins $UNIFFI_VERSION)" >> "$REPORT"
            FOUND=$((FOUND + 1))
        done < <(grep -rnE "uniffi 0\.[0-9]+" "${SEARCH_PATHS[@]}" 2>/dev/null \
            | grep -vE "uniffi ${UNIFFI_VERSION//./\\.}([^0-9]|$)" \
            || true)
    fi
fi

if [ "$FOUND" -gt 0 ]; then
    echo
    echo "==> $FOUND stale doc reference(s) found:"
    cat "$REPORT"
    echo
    echo "Fix the docs to match PARAMS_VERSION = $PARAMS_VERSION before tagging."
    echo "See CLAUDE.md §3 (doc-actualization policy) and"
    echo "docs/en/reference/format.md §7 (cross-version policy)."
    exit 1
fi

echo "==> docs are consistent with current PARAMS_VERSION"
exit 0
