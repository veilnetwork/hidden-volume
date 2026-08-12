#!/usr/bin/env bash
# scripts/check-intra-repo-versions.sh — every in-repo dependency constraint
# names the version the workspace actually publishes.
#
# A crate here depends on its sibling by BOTH path and version:
#
#     hidden-volume = { path = "..", version = "2.0.0" }
#
# cargo uses the path for local builds and the version for a published one, so
# a stale `version =` is invisible until the number stops matching. Caret
# semantics are what hide it: `^1.1.0` happily resolved 1.2.0, 1.2.1, 1.2.2 and
# 1.2.3, so the fuzz crate's constraint sat three releases out of date and
# nothing anywhere said so. The v2.0.0 bump is what finally broke the match,
# and it broke it in CI on a release tag — the worst place to learn it.
#
# The fuzz crate is the one that was wrong, and it is worth knowing WHY it was
# missed: it is not a workspace member. `cargo metadata` on the workspace does
# not see it, so a check written against the workspace would have agreed that
# everything was fine. This walks Cargo.toml files on disk instead.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# The version the workspace publishes, taken from the core crate rather than
# passed in: a gate whose expected value is supplied by its caller checks that
# the caller can type.
want="$(sed -n 's/^version = "\(.*\)"/\1/p' crates/hidden-volume/Cargo.toml | head -1)"
[ -n "$want" ] || { echo "error: no version in crates/hidden-volume/Cargo.toml" >&2; exit 2; }
echo "==> workspace version = $want"

manifests=()
while IFS= read -r m; do manifests+=("$m"); done < <(
  find crates -name Cargo.toml -not -path '*/target/*' | sort
)
# A floor, not a non-empty test: a find that stops matching would otherwise
# report a clean sweep of nothing at all.
if [ "${#manifests[@]}" -lt 4 ]; then
  echo "error: found only ${#manifests[@]} manifests — discovery is broken, not the tree" >&2
  exit 2
fi
echo "==> scanning ${#manifests[@]} manifest(s)"

bad=0
checked=0
for m in "${manifests[@]}"; do
  # Lines of the shape `<our-crate> = { ... version = "X" ... }`.
  while IFS= read -r line; do
    dep="${line%% *}"
    got="$(printf '%s' "$line" | sed -n 's/.*version *= *"\([^"]*\)".*/\1/p')"
    [ -n "$got" ] || continue
    checked=$((checked + 1))
    if [ "$got" != "$want" ]; then
      echo "::error::$m: $dep is pinned at $got, workspace is at $want" >&2
      bad=$((bad + 1))
    fi
  done < <(grep -E '^(hidden-volume(-[a-z]+)?) *= *\{.*version *= *"' "$m" || true)
done

if [ "$checked" -eq 0 ]; then
  echo "error: no in-repo version constraints found — the pattern stopped matching" >&2
  exit 2
fi
echo "==> $checked in-repo constraint(s) checked"

if [ "$bad" -gt 0 ]; then
  echo "$bad constraint(s) name a version this workspace does not publish" >&2
  exit 1
fi
echo "==> every in-repo constraint names $want"
