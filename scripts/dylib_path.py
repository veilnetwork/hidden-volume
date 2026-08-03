"""dylib_path.py — one place that decides WHICH built cdylib the dev tooling
uses, and the cross-language guard that keeps it one place.

Why this module exists
----------------------
Two tools have to agree on a single file:

* `scripts/regen-dart-checksums.py` bakes the UniFFI per-method checksums of a
  cdylib into `experimental/flutter_plugin/hidden_volume/lib/src/bindings.dart`
  and, in `--check` mode, certifies that the table still matches.
* `flutter test` dlopens a cdylib through
  `experimental/flutter_plugin/hidden_volume/test/test_dylib.dart` and asserts
  the table matches THAT one.

They used to search `target/` in opposite orders — the script `release` first,
the Dart tests `debug` first. With both profiles built and only one refreshed,
`--check` passed against `target/release` while `flutter test` failed against
`target/debug`, quoting the checksums the script had just called sound. The
integrity gate was certifying a library the tests never executed, which is the
split audit HV-05 was raised to close.

Order
-----
`release` leads. It is what this script's own instructions tell you to build
(`cargo build -p hidden-volume-ffi --release`), what `scripts/release.sh`
stages, and what CI ships — so it is the artifact the baked table describes,
and therefore the one the tests must load.

Keeping it one place
--------------------
Python cannot import Dart. So the order is declared once per language and
`assert_dart_order_matches()` compares them, wired into
`regen-dart-checksums.py` on every invocation — including the `--check` that
the local release checklist §4 lists in the pre-tag gate. Editing one side alone fails the gate
with a diff instead of surfacing later as two green checks about two different
files.
"""

from __future__ import annotations

import pathlib
import re
import sys

# Most-preferred first. Mirrored by `dylibProfileOrder` in
# `experimental/flutter_plugin/hidden_volume/test/test_dylib.dart`;
# `assert_dart_order_matches()` enforces that they stay equal.
PROFILE_ORDER = ("release", "debug")

# All three host spellings of the `cdylib`. Probing every name on every host is
# harmless — only the native one can exist in a given `target/<profile>/` — and
# it keeps this list free of a `sys.platform` branch that would then need its
# own agreement with the Dart side.
LIBRARY_NAMES = (
    "libhidden_volume_ffi.dylib",
    "libhidden_volume_ffi.so",
    "hidden_volume_ffi.dll",
)

DART_RESOLVER = pathlib.Path(
    "experimental/flutter_plugin/hidden_volume/test/test_dylib.dart"
)

_DART_ORDER_RE = re.compile(
    r"const\s+dylibProfileOrder\s*=\s*<String>\[(?P<body>[^\]]*)\]",
    re.MULTILINE,
)


def profile_dir(root: pathlib.Path, profile: str) -> pathlib.Path:
    """`target/<profile>` under `root`, for callers that pin one profile.

    `bench/ffi_overhead_bench.py` deliberately pins `release` — benchmarking an
    unoptimized build would be a measurement error, not a stale artifact — but
    it routes through here so the pin is spelled against `PROFILE_ORDER`
    instead of a fourth hand-written `"target" / "..."`.
    """
    if profile not in PROFILE_ORDER:
        raise ValueError(f"unknown cargo profile {profile!r}; expected one of {PROFILE_ORDER}")
    return root / "target" / profile


def candidates(root: pathlib.Path) -> list[pathlib.Path]:
    """Every path `resolve()` will try, in the order it tries them."""
    return [
        profile_dir(root, profile) / name
        for profile in PROFILE_ORDER
        for name in LIBRARY_NAMES
    ]


def resolve(root: pathlib.Path, explicit: str | None = None) -> pathlib.Path:
    """The cdylib to read checksums from, or exit with how to build one."""
    if explicit:
        p = pathlib.Path(explicit)
        if not p.exists():
            sys.exit(f"error: no such library: {p}")
        return p
    for c in candidates(root):
        if c.exists():
            return c
    sys.exit(
        "error: cdylib not found. Build it first:\n"
        "    cargo build -p hidden-volume-ffi --release\n"
        "Searched:\n  " + "\n  ".join(str(c) for c in candidates(root))
    )


def dart_profile_order(root: pathlib.Path) -> tuple[str, ...]:
    """`dylibProfileOrder` as the Dart resolver declares it."""
    path = root / DART_RESOLVER
    try:
        source = path.read_text()
    except OSError as exc:
        sys.exit(f"error: cannot read the Dart cdylib resolver at {path}: {exc}")
    m = _DART_ORDER_RE.search(source)
    if not m:
        sys.exit(
            f"error: no `const dylibProfileOrder = <String>[...]` in {path}.\n"
            "That constant is half of the cross-language agreement on which\n"
            "built cdylib the tooling uses; without it this check cannot tell\n"
            "whether the Dart tests load the library this script checksums."
        )
    return tuple(re.findall(r"'([^']+)'", m.group("body")))


def assert_dart_order_matches(root: pathlib.Path) -> None:
    """Fail unless both languages search build profiles in the same order.

    The failure this prevents is not hypothetical: it is the state the two
    resolvers were actually in, where one tool verified `target/release` and
    the other executed `target/debug`.
    """
    dart = dart_profile_order(root)
    if dart == PROFILE_ORDER:
        return
    sys.exit(
        "error: the Dart tests and this script disagree about which built\n"
        "cdylib to use.\n"
        f"  {DART_RESOLVER}\n"
        f"    dylibProfileOrder = {list(dart)}\n"
        "  scripts/dylib_path.py\n"
        f"    PROFILE_ORDER     = {list(PROFILE_ORDER)}\n"
        "\n"
        "Left as is, `--check` would certify one library while `flutter test`\n"
        "executes another, and both could be green about different files.\n"
        "Make the two lists equal."
    )
