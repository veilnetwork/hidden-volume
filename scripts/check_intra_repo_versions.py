#!/usr/bin/env python3
"""Every in-repo dependency constraint names the version the workspace publishes.

Parses the manifests instead of grepping them. The shell version this replaced
matched one line of one shape —

    hidden-volume = { path = "..", version = "2.0.0" }

— and Cargo accepts several others that mean exactly the same thing:

  * a dependency TABLE (`[dependencies.hidden-volume]` with `version =` under
    it), which is what a manifest turns into as soon as the inline form gets
    long;
  * an inline table spread over several lines;
  * `[target.'cfg(unix)'.dependencies]` and `[workspace.dependencies]`;
  * a RENAMED dependency (`hv = { package = "hidden-volume", version = "1.0" }`),
    where the key is not the crate's name at all.

A wrong version in any of those passed the gate, which is the failure this
whole check exists to prevent (report14 HV14-L5).
"""

from __future__ import annotations

import pathlib
import sys
import tomllib

# The kinds of dependency table Cargo reads. Order is only for stable output.
KINDS = ("dependencies", "dev-dependencies", "build-dependencies")


def in_repo(name: str) -> bool:
    """Crates this workspace publishes."""
    return name == "hidden-volume" or name.startswith("hidden-volume-")


def dep_tables(manifest: dict) -> list[tuple[str, dict]]:
    """Every dependency table in the manifest, including per-target ones."""
    out: list[tuple[str, dict]] = []
    for kind in KINDS:
        table = manifest.get(kind)
        if isinstance(table, dict):
            out.append((kind, table))
    workspace = manifest.get("workspace")
    if isinstance(workspace, dict):
        for kind in KINDS:
            table = workspace.get(kind)
            if isinstance(table, dict):
                out.append((f"workspace.{kind}", table))
    targets = manifest.get("target")
    if isinstance(targets, dict):
        for triple, spec in targets.items():
            if not isinstance(spec, dict):
                continue
            for kind in KINDS:
                table = spec.get(kind)
                if isinstance(table, dict):
                    out.append((f"target.{triple}.{kind}", table))
    return out


def constraints(path: pathlib.Path) -> list[tuple[str, str, str]]:
    """`(where, crate, version)` for every in-repo constraint that names one."""
    manifest = tomllib.loads(path.read_text(encoding="utf-8"))
    found: list[tuple[str, str, str]] = []
    for where, table in dep_tables(manifest):
        for key, spec in table.items():
            if not isinstance(spec, dict):
                # `hidden-volume = "2.0.0"` — a bare version string.
                if isinstance(spec, str) and in_repo(key):
                    found.append((where, key, spec))
                continue
            # A rename names the real crate in `package`.
            crate = spec.get("package", key)
            if not isinstance(crate, str) or not in_repo(crate):
                continue
            version = spec.get("version")
            if isinstance(version, str):
                label = crate if crate == key else f"{key} (package = {crate})"
                found.append((where, label, version))
    return found


def self_test() -> int:
    """Prove the parser sees the shapes the regex missed.

    Each fixture is a manifest that names a WRONG version in a form Cargo
    accepts. The old check passed every one of them, which is how a breaking
    version could reach a release unnoticed.
    """
    import tempfile

    fixtures: list[tuple[str, str]] = [
        (
            "inline table (the one shape the regex did see)",
            '[dependencies]\nhidden-volume = { path = "..", version = "9.9.9" }\n',
        ),
        (
            "dependency table",
            '[dependencies.hidden-volume]\npath = ".."\nversion = "9.9.9"\n',
        ),
        (
            # Not a multi-line inline table: TOML 1.0 forbids those and Cargo
            # rejects them too, so a fixture built that way would be testing
            # the parser rather than the check.
            "workspace dependency table",
            '[workspace.dependencies]\nhidden-volume = { path = ".", version = "9.9.9" }\n',
        ),
        (
            "per-target dependency",
            '[target.\'cfg(unix)\'.dependencies]\n'
            'hidden-volume = { path = "..", version = "9.9.9" }\n',
        ),
        (
            "dev-dependency",
            '[dev-dependencies]\nhidden-volume-ffi = { path = "..", version = "9.9.9" }\n',
        ),
        (
            "renamed dependency",
            '[dependencies]\nhv = { package = "hidden-volume", path = "..", version = "9.9.9" }\n',
        ),
        (
            "bare version string",
            '[dependencies]\nhidden-volume = "9.9.9"\n',
        ),
    ]

    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for label, body in fixtures:
            path = pathlib.Path(tmp) / "Cargo.toml"
            path.write_text(body, encoding="utf-8")
            found = constraints(path)
            if not any(v == "9.9.9" for _, _, v in found):
                print(f"::error::self-test: {label} was not seen", file=sys.stderr)
                failures += 1
            else:
                print(f"    ok: {label}")

        # And the other way: a manifest that names nothing of ours must
        # produce nothing, or the checker would report constraints it invented.
        path = pathlib.Path(tmp) / "Cargo.toml"
        path.write_text(
            '[dependencies]\nserde = { version = "1.0" }\n', encoding="utf-8"
        )
        if constraints(path):
            print("::error::self-test: an unrelated crate was claimed", file=sys.stderr)
            failures += 1
        else:
            print("    ok: unrelated crates are left alone")

    if failures:
        print(f"{failures} self-test fixture(s) slipped through", file=sys.stderr)
        return 1
    print("==> self-test: every dependency shape is seen")
    return 0


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    core = tomllib.loads((root / "crates" / "hidden-volume" / "Cargo.toml").read_text())
    want = core.get("package", {}).get("version")
    if not isinstance(want, str) or not want:
        print("error: no version in crates/hidden-volume/Cargo.toml", file=sys.stderr)
        return 2
    print(f"==> workspace version = {want}")

    manifests = sorted(
        p for p in (root / "crates").rglob("Cargo.toml") if "target" not in p.parts
    )
    # A floor, not a non-empty test: discovery that stops matching would
    # otherwise report a clean sweep of nothing at all.
    if len(manifests) < 4:
        print(
            f"error: found only {len(manifests)} manifests — discovery is broken, "
            "not the tree",
            file=sys.stderr,
        )
        return 2
    print(f"==> scanning {len(manifests)} manifest(s)")

    checked = 0
    bad = 0
    for m in manifests:
        rel = m.relative_to(root)
        for where, crate, version in constraints(m):
            checked += 1
            if version != want:
                print(
                    f"::error::{rel}: [{where}] {crate} is pinned at {version}, "
                    f"workspace is at {want}",
                    file=sys.stderr,
                )
                bad += 1

    if checked == 0:
        print(
            "error: no in-repo version constraints found — the parse stopped "
            "matching",
            file=sys.stderr,
        )
        return 2
    print(f"==> {checked} in-repo constraint(s) checked")
    if bad:
        print(
            f"{bad} constraint(s) name a version this workspace does not publish",
            file=sys.stderr,
        )
        return 1
    print(f"==> every in-repo constraint names {want}")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    sys.exit(main())
