#!/usr/bin/env bash
# dump-public-api.sh — regenerate `docs/en/reference/api-surface.txt`.
#
# Strategy: grep-extract `pub` items from each crate's `src/`. Matches
# the heuristic the original 2026-05-02 snapshot was built with —
# `cargo public-api` would be more rigorous but its `rustdoc-json`
# dependency requires nightly Rust, which the project's MSRV (1.89
# stable, see `crates/*/Cargo.toml::rust-version`) does not allow as
# a CI gate. The grep-based snapshot is good enough for "did anything
# user-visible change" diff checks.
#
# Captures:
#   - top-level pub fn / struct / enum / trait / const / static / type
#     / mod / use lines
#   - pub fn / pub async fn methods inside impl blocks
#   - the union of all four workspace crates: hidden-volume,
#     hidden-volume-rt, hidden-volume-async, hidden-volume-ffi
#
# Skips:
#   - tests/ benches/ examples/ (not user-visible API)
#   - re-export expansion to canonical paths (the "use" lines are
#     listed verbatim; consumers who care can resolve themselves)
#   - generic-bound details past the line wrap
#   - private items (intentional — drift check is for the public
#     contract, not internal refactors)
#
# Usage:
#   scripts/dump-public-api.sh           # writes the canonical path
#   scripts/dump-public-api.sh --check   # diff against committed
#                                          snapshot, exit non-zero on
#                                          drift (CI mode)
#
# Audit pass 11 follow-up — replaces the old "Regenerate with: TODO"
# placeholder in the snapshot's header.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${HV_API_OUT:-$ROOT/docs/en/reference/api-surface.txt}"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

CRATES=(
    "hidden-volume"
    "hidden-volume-rt"
    "hidden-volume-async"
    "hidden-volume-ffi"
)

NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat >"$TMP" <<HEADER
# hidden-volume — public API baseline snapshot
#
# This file is language-neutral: it is a verbatim listing of Rust public-API
# identifiers and signatures. There is no separate Russian version because
# the content is code, not prose. Canonical path: this file.
#
# Этот файл нейтрален по языку: это дословный листинг идентификаторов и
# сигнатур публичного Rust API. Отдельной русской версии нет — содержимое
# является кодом, а не прозой. Канонический путь: этот файл.
#
# Captured: $NOW
# Method:   scripts/dump-public-api.sh — grep-extracted from each crate's
#           src/. cargo public-api would be more rigorous but its rustdoc-
#           json dependency requires nightly Rust; this project's MSRV is
#           1.89 stable. The grep snapshot is sufficient for drift-detection
#           in CI.
# Format:   <crate>: <module-path> :: <pub item declaration>
#
# Regenerate with: scripts/dump-public-api.sh
# Drift-check (CI):  scripts/dump-public-api.sh --check
#
# This snapshot includes:
#   - top-level items (pub fn/struct/enum/trait/const/static/type/mod/use)
#   - methods inside impl blocks (pub fn within impl)
# It does NOT include:
#   - re-exports expanded to canonical paths
#   - generic-bound details beyond the line
#   - private items (we only care about pub surface)
#

HEADER

# Extract pub-item lines per crate, preserving file order.
for crate in "${CRATES[@]}"; do
    echo "==========================================" >>"$TMP"
    echo "crate: $crate" >>"$TMP"
    echo "==========================================" >>"$TMP"
    echo >>"$TMP"

    src_dir="$ROOT/crates/$crate/src"
    if [[ ! -d "$src_dir" ]]; then
        echo "# (crate not present)" >>"$TMP"
        echo >>"$TMP"
        continue
    fi

    # Walk every .rs file under src/. We deliberately scan the file
    # tree top-down with `find ... | LC_ALL=C sort` so the snapshot
    # is deterministic across machines:
    #   - Bare `find` order is filesystem-dependent on some OSes.
    #   - Bare `sort` uses the host's `LC_COLLATE`. UTF-8 locales
    #     order `log_iter.rs` BEFORE `log.rs` (word-aware: underscore
    #     treated as a separator); the C locale orders them byte-by-
    #     byte (`.` 0x2E < `_` 0x5F → `log.rs` first). The CI runner
    #     and dev machines disagreed on this prior to 2026-05-09 and
    #     produced spurious "snapshot is stale" failures.
    #   - Pinning `LC_ALL=C` gives byte-order on every host. Same
    #     trick used in `release.sh` for the SHA256SUMS sort.
    while IFS= read -r file; do
        rel="${file#$src_dir/}"
        # Match lines that introduce public surface. Indentation-tolerant
        # so we catch `pub fn` inside `impl` blocks.
        # Patterns:
        #   ^pub                 — top-level pub items (fn/struct/enum/...)
        #   ^\s+pub\s+(async\s+)?fn  — methods inside impl blocks
        #   ^\s+pub\s+const      — associated consts
        #   ^pub use             — re-exports
        # Strip trailing `{` from struct/enum/impl headers for cleanliness.
        awk -v fname="$rel" '
            # NO LINE NUMBER. It used to be part of every entry, which made a
            # COMMENT a public-API change: adding three lines of prose shifted
            # every signature below it and the gate reported eighty-eight
            # changed items. The snapshot was then regenerated mechanically to
            # get back to green, and a real signature change would have arrived
            # inside that noise looking exactly like the rest of it. The file
            # and the declaration are what the gate is about.
            #
            # Indentation-tolerant on BOTH patterns now: a `pub struct` inside
            # an inline `mod` block never appeared at all, so adding, renaming
            # or removing one passed silently. Nothing in the tree is declared
            # that way today, which is why this cost nothing to fix and would
            # have cost the whole gate to discover later.
            /^[[:space:]]*pub (fn|async fn|struct|enum|trait|const|static|type|mod|use)/ {
                sub(/^[[:space:]]+/, "  ")
                print fname ": " $0
                next
            }
        ' "$file" >>"$TMP"
    done < <(find "$src_dir" -name '*.rs' | LC_ALL=C sort)

    echo >>"$TMP"
done

# The Flutter plugin's Dart surface.
#
# Not Rust and therefore not in the loop above, and it is what the app
# actually compiles against: xVeil imports this package directly. A rename
# here breaks that build, and until now the API gate could not see it — the
# snapshot described four Rust crates and called itself the public API.
# Overridable so the self-test can point the SAME extractor at fixtures —
# a check on a copy of the rules is a check on a copy of the rules.
DART_LIB="${HV_API_DART_LIB:-$ROOT/experimental/flutter_plugin/hidden_volume/lib}"
echo "==========================================" >>"$TMP"
echo "dart: hidden_volume (flutter plugin)" >>"$TMP"
echo "==========================================" >>"$TMP"
echo >>"$TMP"
if [[ -d "$DART_LIB" ]]; then
    while IFS= read -r file; do
        rel="${file#$DART_LIB/}"
        # Public means "not underscore-prefixed", which is the whole of Dart's
        # visibility rule — but only half of what makes a line API. The other
        # half is WHERE it sits, and the first version of this extractor had
        # no idea: it took any `final Type name;` at any indentation, so the
        # snapshot filled up with private classes' fields, statements lifted
        # out of function bodies and method locals. 257 lines, most of them
        # not surface at all — a baseline that noisy reddens on refactors
        # while staying blind to real additions.
        #
        # Brace depth is the discriminator, not indentation: a type sits at
        # depth 0, its members at depth 1, anything inside a body at 2 or
        # more. Members of a private type are skipped whole.
        awk -v fname="$rel" '
            # COMMENTS FIRST, before the braces are counted.
            #
            # They used to be skipped after, so every `{` in a doc comment —
            # and this package documents with code examples — pushed the depth
            # up and never brought it down. Whole classes then sat at an
            # apparent depth of 2 or more and were dropped as "inside a body":
            # 28 public methods of `HvSpace` and friends were simply not in the
            # snapshot, so renaming one passed the gate with exit 0. Reproduced
            # against this script before it was touched (report14 HV14-M6).
            /^[[:space:]]*\/\// { next }
            {
                start_depth = depth
                t = $0; ob = gsub(/\{/, "{", t)
                u = $0; cb = gsub(/\}/, "}", u)
                depth += ob - cb
                if (depth <= 0) { depth = 0; private_type = 0 }
            }
            start_depth == 0 && /^[[:space:]]*(abstract |final |sealed |base )*(class|enum|mixin|extension|typedef) [A-Za-z_]/ {
                match($0, /(class|enum|mixin|extension|typedef)[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)
                decl = substr($0, RSTART, RLENGTH)
                sub(/^[a-z]+[[:space:]]+/, "", decl)
                private_type = (substr(decl, 1, 1) == "_")
                if (private_type) next
                sub(/^[[:space:]]+/, "  ")
                print fname ": " $0
                next
            }
            start_depth > 1 || private_type { next }
            # Methods and top-level functions: a return type, a public name,
            # then a parameter list or type arguments.
            /^[[:space:]]*(static |external )*[A-Za-z0-9_<>?, ]+ [a-z][A-Za-z0-9_]*[(<]/ {
                # Judge the DECLARED NAME, not the whole line.
                #
                # The guard here used to skip any line carrying a space
                # followed by an underscore ANYWHERE on it. An
                # expression-bodied member that delegates to a private one —
                # `Uint8List? get(int ns, Uint8List k) => _inner.get(ns, k);`
                # — matches that, so `HvSpace.get` was never in the snapshot at
                # all and renaming it passed the gate with exit 0. Reproduced
                # against this script before it was touched (report14 HV14-M6).
                #
                # The class above carries DIGITS. Without them `Uint8List`
                # was unmatchable, so every method returning one — `get`,
                # `kvKeys`, `kvKeysPage`, the whole read surface — was absent
                # from a snapshot that called itself the public API.
                #
                # An `=` BEFORE the first `(` means the line is an assignment,
                # not a declaration: `final bytes = _bufferToBytes(out);` is a
                # local, and the old heuristic was catching those by accident.
                # Declarations put their `=` after the parameter list, if at
                # all.
                paren = index($0, "(")
                eq = index($0, "=")
                if (eq > 0 && eq < paren) next
                if (match($0, /[a-z][A-Za-z0-9_]*\(/)) {
                    if (substr($0, RSTART, 1) == "_") next
                } else if ($0 ~ /[[:space:]]_[a-zA-Z]/) {
                    next
                }
                sub(/^[[:space:]]+/, "  ")
                print fname ": " $0
                next
            }
            # Getters. `int get byteSize => ...` has no parameter list, so the
            # rule above walked straight past it — and a getter is API in
            # exactly the way a method is. Found by checking the extractor
            # against three members added the same day: it saw one of them.
            /^[[:space:]]*(static |external )*[A-Za-z0-9_<>?, ]+ get [a-z][A-Za-z0-9_]*/ {
                sub(/^[[:space:]]+/, "  ")
                print fname ": " $0
                next
            }
            # Fields and constants, which carry values callers depend on —
            # `static const int defaultMaxConcurrentServes = 8` is a promise
            # about behaviour, not an implementation detail. `const|final` is
            # NOT required: a settable `static Object? debugSpawnFailure;` is
            # just as reachable, and demanding it hid every seam of that kind.
            /^[[:space:]]*(static )*(const |final |late |covariant )*[A-Za-z_][A-Za-z0-9_<>?, ]* [a-z][A-Za-z0-9_]*[[:space:]]*[=;]/ {
                if ($0 ~ /[[:space:]]_[a-zA-Z]/) next
                if ($0 ~ /^[[:space:]]*(return|await|throw|yield|assert|if|for|while|case)[[:space:]]/) next
                sub(/^[[:space:]]+/, "  ")
                print fname ": " $0
                next
            }
        ' "$file" >>"$TMP"
    done < <(find "$DART_LIB" -name '*.dart' | LC_ALL=C sort)
else
    echo "# (plugin not present)" >>"$TMP"
fi
echo >>"$TMP"

if [[ "${1:-}" == "--check" ]]; then
    # Strip the volatile `Captured:` line before comparing — every
    # invocation re-stamps it and would otherwise show as drift.
    if ! diff -u \
        <(grep -v '^# Captured:' "$OUT") \
        <(grep -v '^# Captured:' "$TMP") \
        >/dev/null 2>&1; then
        echo "ERROR: docs/en/reference/api-surface.txt is stale." >&2
        echo "       Run: scripts/dump-public-api.sh" >&2
        echo "       Diff:" >&2
        diff -u \
            <(grep -v '^# Captured:' "$OUT") \
            <(grep -v '^# Captured:' "$TMP") \
            >&2 || true
        exit 1
    fi
    echo "api-surface.txt is up to date."
    exit 0
fi

mv "$TMP" "$OUT"
trap - EXIT
echo "wrote $OUT"
