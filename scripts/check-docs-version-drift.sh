#!/usr/bin/env bash
#
# scripts/check-docs-version-drift.sh — pre-tag doc-actualization gate.
#
# Run this **before** tagging a new release; it catches the
# class of doc drift the 2026-05-28 v3 format-bump introduced —
# `docs/` describing format vN-1 (or earlier) while the code already
# emits vN. the local release checklist §3 doc-actualization policy makes this a
# pre-tag gate violation.
#
# How it works:
#   1. Reads `PARAMS_VERSION` from `crates/hidden-volume/src/crypto/kdf.rs`
#      (canonical source of truth).
#   2. Greps `docs/` AND the top-level narrative docs (`DESIGN.md`,
#      `DESIGN.ru.md`, `README.md`, `README.ru.md`, `SECURITY.md`,
#      `SECURITY.ru.md`, `the local release checklist`) for tell-tale stale patterns of
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
TOP_LEVEL=(DESIGN.md DESIGN.ru.md README.md README.ru.md SECURITY.md SECURITY.ru.md the local release checklist)
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

# Pattern 5: Argon2 cost ceilings. `MAX_M_COST_KIB` / `MAX_T_COST` /
# `MAX_P_COST` live in `crypto/kdf.rs`; the narrative docs restate
# their values in prose and in constant tables. Commit ff9ec00
# tightened all three (1 GiB / 100 / 64 -> 512 MiB / 8 / 16) and
# touched only the changelog, the source and the generated API
# snapshot — EIGHT doc sites went on asserting the old numbers, and
# this gate answered "docs are consistent", because patterns 1-4 know
# about format versions, header size, and binding staleness, and
# nothing at all about cost constants. That is what this pattern is
# for: the next edit to these three values must not drift silently
# the way the last one did.
#
# It reads the three values from the source and fails on any line in
# `docs/` or the top-level narrative docs that states a DIFFERENT
# value next to one of the ceiling names. Three doc idioms are
# recognised, which is every idiom in use:
#
#   triple    `512 MiB / 8 / 16`            (format.md prose + table)
#   claim     `MAX_T_COST` = 8 | 8 <= 8     (DESIGN.md, audit tables)
#   interval  `t_cost ∈ [2, 8]`             (adversarial-stance)
#
# A line is only examined when it carries ceiling context — one of the
# constant names, the word "ceiling"/"потолк", a `≤`, or an interval.
# That is what keeps the `Argon2Params::MIN` rows sitting right above
# the MAX rows in the audit tables from being read as ceiling claims.
# Values may wrap onto the following line (markdown docs here are
# hard-wrapped at ~68 columns), so each check reads a two-line window
# but only fires when the claim STARTS on the current line — which
# also dedupes a finding seen from both of its windows.
#
# `docs/en/reference/api-surface.txt` is excluded: it is generated
# verbatim from the source by `scripts/dump-public-api.sh`, which has
# its own `--check` mode in the same pre-tag gate.
CEIL_SRC="$REPO_ROOT/crates/hidden-volume/src/crypto/kdf.rs"

read_ceiling() {
    # $1 = constant name. Accepts `N`, `N * M`, `N * M * K`.
    grep -E "^[[:space:]]*pub const $1: u32 = [0-9 *]+;" "$CEIL_SRC" \
        | head -n1 \
        | sed -E "s/^[[:space:]]*pub const $1: u32 = ([0-9 *]+);.*/\1/" \
        | tr -d ' ' \
        | awk -F'*' '{v=1; for (i=1; i<=NF; i++) v*=$i; print v}'
}

CEIL_M=$(read_ceiling MAX_M_COST_KIB)
CEIL_T=$(read_ceiling MAX_T_COST)
CEIL_P=$(read_ceiling MAX_P_COST)

if [ -z "$CEIL_M" ] || [ -z "$CEIL_T" ] || [ -z "$CEIL_P" ]; then
    echo "error: Argon2 cost ceilings not parseable from $CEIL_SRC" >&2
    exit 2
fi

echo "==> Argon2 ceilings from source: m_cost_kib <= $CEIL_M KiB, t_cost <= $CEIL_T, p_cost <= $CEIL_P"

CEIL_REPORT=$(mktemp)
trap 'rm -f "$REPORT" "$CEIL_REPORT"' EXIT

CEIL_FILES=()
while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
        docs/en/reference/api-surface.txt) continue ;;
    esac
    CEIL_FILES+=("$f")
done < <(
    find docs -type f \( -name '*.md' -o -name '*.txt' \) 2>/dev/null || true
    for f in "${TOP_LEVEL[@]}"; do [ -f "$f" ] && echo "$f"; done
)

for f in "${CEIL_FILES[@]}"; do
    # Normalize the non-ASCII spellings to ASCII before awk sees them.
    # The awk patterns below use bracket expressions, and a multi-byte
    # character inside `[...]` is a set of its BYTES, not one
    # character. Substitutions are one-line-in / one-line-out, so line
    # numbers and the `length()`-based line boundary both still hold.
    sed -e 's/≤/<=/g' -e 's/≥/>=/g' -e 's/ *∈ */ in /g' \
        -e 's/ГиБ/GiB/g' -e 's/МиБ/MiB/g' -e 's/КиБ/KiB/g' "$f" \
    | awk -v FNAME="$f" -v M="$CEIL_M" -v T="$CEIL_T" -v P="$CEIL_P" '
        { line[NR] = $0 }

        # Does this line make a claim about the CEILINGS, as opposed to
        # the MIN floor, a preset, or the raw header field layout?
        function ceiling_ctx(s) {
            return index(s, "MAX_M_COST_KIB") || index(s, "MAX_T_COST") \
                || index(s, "MAX_P_COST")    || index(s, "MAX.m_cost")  \
                || index(s, "MAX.t_cost")    || index(s, "MAX.p_cost")  \
                || index(s, "ceiling")       || index(s, "Ceiling")     \
                || index(s, "потолк")        || index(s, "Потолк")      \
                || index(s, "<=")            || index(s, " in [")
        }

        # `NAME` = V, or a table cell `| NAME | V |`. Returns the value
        # in the constant own units, or -1 when the name carries no
        # numeric claim here (`p_cost <= MAX_P_COST`, prose mentions).
        # Sets ANCHOR to where the name was found.
        function claim(s, anchor, is_mem,    rest, num) {
            if (!match(s, anchor)) return -1
            ANCHOR = RSTART
            rest = substr(s, RSTART + RLENGTH)
            # An assertion delimiter must come before any digit.
            if (!match(rest, /^[^0-9|=<]*[|=<]+/)) return -1
            rest = substr(rest, RSTART + RLENGTH)
            if (!match(rest, /^[^0-9A-Za-z]*[0-9]+/)) return -1
            num = substr(rest, RSTART, RLENGTH) + 0
            rest = substr(rest, RSTART + RLENGTH)
            if (is_mem && match(rest, /^[ ]*(KiB|MiB|GiB)/)) {
                if (index(substr(rest, RSTART, RLENGTH), "MiB")) return num * 1024
                if (index(substr(rest, RSTART, RLENGTH), "GiB")) return num * 1024 * 1024
            }
            return num
        }

        # `NAME ∈ [lo, hi]` — the upper end is the ceiling. `∈` has
        # already been rewritten to ` in ` by the sed above.
        function interval_hi(s, anchor,    rest) {
            if (!match(s, anchor)) return -1
            ANCHOR = RSTART
            rest = substr(s, RSTART + RLENGTH)
            if (!match(rest, /^[^0-9]*in[ ]*\[[ ]*[0-9]+[ ]*,[ ]*/)) return -1
            rest = substr(rest, RSTART + RLENGTH)
            if (!match(rest, /^[0-9]+/)) return -1
            return substr(rest, RSTART, RLENGTH) + 0
        }

        function report(n, what) {
            printf "  [STALE] %s:%d — %s\n", FNAME, n, what
        }

        function check(win, cut, i, anchor, is_mem, want, label,    v) {
            v = interval_hi(win, anchor)
            if (v < 0) v = claim(win, anchor, is_mem)
            if (v < 0 || ANCHOR > cut || v == want) return
            report(i, label " ceiling stated as " v ", source says " want)
        }

        END {
            for (i = 1; i <= NR; i++) {
                if (!ceiling_ctx(line[i])) continue
                cut = length(line[i])
                win = (i < NR) ? line[i] " " line[i + 1] : line[i]

                # The `<mem> / <t> / <p>` triple states all three at
                # once; where it appears it supersedes the per-name
                # checks, whose delimiter scan cannot tell the three
                # slash-separated values apart.
                if (match(win, /[0-9]+[ ]*(KiB|MiB|GiB)[ ]*\/[ ]*[0-9]+[ ]*\/[ ]*[0-9]+/)) {
                    if (RSTART > cut) continue
                    trip = substr(win, RSTART, RLENGTH)
                    split(trip, a, "/")
                    mem = a[1] + 0
                    if (index(a[1], "MiB")) mem *= 1024
                    else if (index(a[1], "GiB")) mem *= 1024 * 1024
                    if (mem != M || (a[2] + 0) != T || (a[3] + 0) != P)
                        report(i, "ceiling triple \"" trip "\", source says " \
                            (M / 1024) " MiB / " T " / " P)
                    continue
                }

                # Anchors are passed as STRINGS, not `/…/` literals: a
                # regex literal in an argument position is evaluated as
                # `$0 ~ /…/` and reaches the callee as 0 or 1.
                check(win, cut, i, "(MAX_M_COST_KIB|MAX\\.m_cost_kib|m_cost_kib)", 1, M, "m_cost_kib (KiB)")
                check(win, cut, i, "(MAX_T_COST|MAX\\.t_cost|t_cost)",             0, T, "t_cost")
                check(win, cut, i, "(MAX_P_COST|MAX\\.p_cost|p_cost)",             0, P, "p_cost")
            }
        }
    ' >> "$CEIL_REPORT"
done

if [ -s "$CEIL_REPORT" ]; then
    CEIL_FOUND=$(wc -l < "$CEIL_REPORT" | tr -d ' ')
    FOUND=$((FOUND + CEIL_FOUND))
    cat "$CEIL_REPORT" >> "$REPORT"
fi

if [ "$FOUND" -gt 0 ]; then
    echo
    echo "==> $FOUND stale doc reference(s) found:"
    cat "$REPORT"
    echo
    echo "Fix the docs to match PARAMS_VERSION = $PARAMS_VERSION before tagging."
    echo "See the local release checklist §3 (doc-actualization policy) and"
    echo "docs/en/reference/format.md §7 (cross-version policy)."
    exit 1
fi

echo "==> docs are consistent with current PARAMS_VERSION"
exit 0
