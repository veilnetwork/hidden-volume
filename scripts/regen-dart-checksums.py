#!/usr/bin/env python3
"""regen-dart-checksums.py — refresh the UniFFI per-method checksum table in
`experimental/flutter_plugin/hidden_volume/lib/src/bindings.dart`.

Why this exists
---------------
The Dart bindings are hand-written against the uniffi 0.31 C ABI (see the
header of `bindings.dart` for why). uniffi exports one
`uniffi_hidden_volume_ffi_checksum_<kind>_<name>` symbol per function,
method, and constructor; a generated binding compares each against a value
baked in at generation time and refuses to run on a mismatch. Hand-written
bindings had nothing to compare, so a cdylib whose METHOD signatures had
changed — but whose overall contract version had not — was accepted, and the
first call decoded the wrong bytes: a native crash if lucky, silently wrong
arguments if not (audit HV-05).

The table in `bindings.dart` closes that. This script is what keeps the table
honest: without it the values go stale the first time a Rust signature moves,
and a stale table fails closed on every launch, which is its own outage.

Usage
-----
    scripts/regen-dart-checksums.py            # rewrite the table in place
    scripts/regen-dart-checksums.py --check    # exit 1 if the table is stale
    scripts/regen-dart-checksums.py --lib PATH # explicit cdylib

The cdylib must be built first:

    cargo build -p hidden-volume-ffi --release

Symbols are not read out of the binary with `nm` / `strings`: the checksum
values are the RETURN of those symbols, not their names, so the script dlopens
the library and calls each one. That also means it works identically on
macOS (`.dylib`), Linux (`.so`), and Windows (`.dll`) — where `nm` reads
neither of the other two's formats.
"""

from __future__ import annotations

import argparse
import ctypes
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BINDINGS = ROOT / "experimental/flutter_plugin/hidden_volume/lib/src/bindings.dart"

BEGIN = "// BEGIN GENERATED CHECKSUMS — scripts/regen-dart-checksums.py"
END = "// END GENERATED CHECKSUMS"

# `_fn_clone_*` / `_fn_free_*` are object-lifecycle entry points, not
# signatures, and uniffi emits no checksum for them. Everything else the
# bindings bind must have one.
NO_CHECKSUM_PREFIXES = ("clone_", "free_")

FN_PREFIX = "uniffi_hidden_volume_ffi_fn_"
CHECKSUM_PREFIX = "uniffi_hidden_volume_ffi_checksum_"


def library_candidates() -> list[pathlib.Path]:
    names = [
        "libhidden_volume_ffi.dylib",
        "libhidden_volume_ffi.so",
        "hidden_volume_ffi.dll",
    ]
    out = []
    for profile in ("release", "debug"):
        for name in names:
            out.append(ROOT / "target" / profile / name)
    return out


def resolve_library(explicit: str | None) -> pathlib.Path:
    if explicit:
        p = pathlib.Path(explicit)
        if not p.exists():
            sys.exit(f"error: no such library: {p}")
        return p
    for c in library_candidates():
        if c.exists():
            return c
    sys.exit(
        "error: cdylib not found. Build it first:\n"
        "    cargo build -p hidden-volume-ffi --release\n"
        "Searched:\n  " + "\n  ".join(str(c) for c in library_candidates())
    )


def bound_symbols(source: str) -> list[str]:
    """Every `uniffi_hidden_volume_ffi_fn_*` symbol the bindings look up.

    Derived from the source rather than kept as a second hand-maintained
    list, so a newly bound method cannot be left out of the table by
    forgetting to edit two places.
    """
    found = sorted(set(re.findall(r"'(" + FN_PREFIX + r"[a-z0-9_]+)'", source)))
    if not found:
        sys.exit("error: no FFI symbol lookups found in bindings.dart — wrong file?")
    return found


def checksum_symbol(fn_symbol: str) -> str | None:
    tail = fn_symbol[len(FN_PREFIX) :]
    if tail.startswith(NO_CHECKSUM_PREFIXES):
        return None
    return CHECKSUM_PREFIX + tail


def read_checksums(lib_path: pathlib.Path, symbols: list[str]) -> dict[str, int]:
    lib = ctypes.CDLL(str(lib_path))
    out: dict[str, int] = {}
    missing: list[str] = []
    for sym in symbols:
        try:
            fn = getattr(lib, sym)
        except AttributeError:
            missing.append(sym)
            continue
        fn.restype = ctypes.c_uint16
        fn.argtypes = []
        out[sym] = int(fn())
    if missing:
        sys.exit(
            "error: the cdylib does not export these checksum symbols:\n  "
            + "\n  ".join(missing)
            + "\nThe bindings call methods this library does not have. Rebuild it, "
            "or drop the binding."
        )
    return out


def render_table(checksums: dict[str, int]) -> str:
    lines = [BEGIN]
    if checksums:
        lines.append("const Map<String, int> _methodChecksums = <String, int>{")
        for sym in sorted(checksums):
            lines.append(f"  '{sym}': {checksums[sym]},")
        lines.append("};")
    else:
        lines.append("const Map<String, int> _methodChecksums = <String, int>{};")
    lines.append(END)
    return "\n".join(lines)


def splice(source: str, table: str) -> str:
    start = source.find(BEGIN)
    end = source.find(END)
    if start < 0 or end < 0:
        sys.exit(
            f"error: markers not found in {BINDINGS}.\n"
            f"Expected a block delimited by:\n{BEGIN}\n{END}"
        )
    return source[:start] + table + source[end + len(END) :]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="fail if the table is stale")
    ap.add_argument("--lib", help="path to the built cdylib")
    args = ap.parse_args()

    source = BINDINGS.read_text()
    fn_symbols = bound_symbols(source)
    wanted = [s for s in (checksum_symbol(f) for f in fn_symbols) if s]

    lib_path = resolve_library(args.lib)
    checksums = read_checksums(lib_path, wanted)
    updated = splice(source, render_table(checksums))

    if args.check:
        if updated != source:
            print(
                "ERROR: the UniFFI checksum table in bindings.dart is stale.\n"
                "Regenerate it with: scripts/regen-dart-checksums.py",
                file=sys.stderr,
            )
            return 1
        print(f"checksum table is up to date ({len(checksums)} entries)")
        return 0

    if updated == source:
        print(f"checksum table already current ({len(checksums)} entries)")
        return 0
    BINDINGS.write_text(updated)
    print(f"wrote {len(checksums)} checksums from {lib_path} into {BINDINGS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
