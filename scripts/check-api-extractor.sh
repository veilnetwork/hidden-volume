#!/usr/bin/env bash
# scripts/check-api-extractor.sh — the API extractor sees the declarations it
# claims to.
#
# A snapshot gate is only as good as what it looks at, and this one looked at
# less than it said. `HvSpace.get`, `kvKeys`, `kvKeysPage` — the whole read
# surface of the Dart plugin — were never in the snapshot at all, because the
# return-type character class carried no DIGITS and `Uint8List` was therefore
# unmatchable. Renaming any of them passed with exit 0, which is the one thing
# an API gate exists to prevent (report14 HV14-M6).
#
# So the rules get their own fixtures: one declaration per shape, run through
# the REAL extractor rather than a copy of it, and every one of them has to
# come out the other side.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/lib"

cat >"$work/lib/fixture.dart" <<'DART'
class PublicThing {
  int plainMethod(int a) => 1;
  Uint8List? digitInTheType(int ns, Uint8List key) => null;
  List<Uint8List> genericWithDigits(int ns) => const [];
  Future<Uint8List?> asyncWithDigits(int ns) async => null;
  void delegatesToPrivate() => _inner.thing();
  int get aGetter => 1;
  static const int aConstant = 7;
  static Object? aSettableSeam;
  int _privateMethod(int a) => a;
  Uint8List? _privateWithDigits(int a) => null;
}

class _PrivateThing {
  int notSurface(int a) => a;
}
DART

out="$work/surface.txt"
HV_API_DART_LIB="$work/lib" HV_API_OUT="$out" ./scripts/dump-public-api.sh >/dev/null

fail=0
must_see=(
  "plainMethod"
  "digitInTheType"
  "genericWithDigits"
  "asyncWithDigits"
  "delegatesToPrivate"
  "aGetter"
  "aConstant"
  "aSettableSeam"
)
for name in "${must_see[@]}"; do
  if grep -q "$name" "$out"; then
    echo "    ok: $name"
  else
    echo "::error::the extractor does not see $name" >&2
    fail=1
  fi
done

must_not_see=("_privateMethod" "_privateWithDigits" "notSurface")
for name in "${must_not_see[@]}"; do
  if grep -q "$name" "$out"; then
    echo "::error::the extractor claims $name is public API" >&2
    fail=1
  else
    echo "    ok: $name stays out"
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "the API extractor has a blind spot — a rename there would pass the gate" >&2
  exit 1
fi
echo "==> the API extractor sees every declaration shape"
