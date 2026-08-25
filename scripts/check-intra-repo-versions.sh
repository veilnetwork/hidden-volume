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
#
# The work itself moved to `check_intra_repo_versions.py`, which PARSES the
# manifests. This shell version matched one line of one shape, and Cargo
# accepts several others that mean the same thing — a dependency table, a
# per-target section, a renamed dependency, a bare version string. A wrong
# version in any of those passed the gate, which is the failure the check
# exists to prevent (report14 HV14-L5). The self-test carries one fixture per
# shape and runs first, so a check that has stopped seeing them says so before
# it reports a clean tree.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/check_intra_repo_versions.py --self-test
python3 scripts/check_intra_repo_versions.py
