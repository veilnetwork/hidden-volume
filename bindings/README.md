# Foreign-language bindings — `hidden-volume-ffi`

Auto-generated bindings against the
[`hidden-volume-ffi`](../crates/hidden-volume-ffi/) cdylib via uniffi.

> **Generated artifacts are not committed** (audit C4, 2026-05-03).
> The per-language source files (`hidden_volume_ffi.py`, `*.kt`,
> `*.swift`, `*.rb`, plus the Swift `*.h` / `*.modulemap`) are
> listed in the root `.gitignore` to avoid bloating git history with
> ~11k lines of auto-generated code on every uniffi version bump.
> Regenerate them locally before browsing — see § Regenerating
> below. The hand-written `python/test_smoke.py` and this README
> stay tracked.

## Status

| Language | File(s) | Tested in CI |
|---|---|---|
| **Python 3.8+** | [`python/hidden_volume_ffi.py`](python/hidden_volume_ffi.py) | ✓ via [`test_smoke.py`](python/test_smoke.py) — 5/5 pass |
| **Kotlin** (JVM / Android) | [`kotlin/uniffi/hidden_volume_ffi/hidden_volume_ffi.kt`](kotlin/uniffi/hidden_volume_ffi/hidden_volume_ffi.kt) | Reference only — needs JVM toolchain to test |
| **Swift** (iOS / macOS) | [`swift/hidden_volume_ffi.swift`](swift/) + `*.h` + `*.modulemap` | Reference only — needs Xcode to test |
| **Ruby** | [`ruby/hidden_volume_ffi.rb`](ruby/hidden_volume_ffi.rb) | Reference only |

The Python smoke test exercises the **same uniffi machinery** that
generates Kotlin / Swift / Ruby. A passing Python run is strong
evidence the other bindings are correct, since:

- The FFI ABI between Rust and the foreign side is identical for
  all four languages (C ABI under the hood).
- uniffi's per-language code generators share a common AST extracted
  from the Rust crate. A bug in the FFI surface (wrong type, missing
  method, error not exposed) would surface in the Python output too.
- We exercise sync constructors, async constructors, opaque handles,
  byte arrays, optional values, vector returns, error-variant typed
  exceptions — every cross-FFI primitive uniffi handles.

## Regenerating

The bindings are regenerated from a single source of truth — the
`#[uniffi::*]` proc-macro annotations in
[`crates/hidden-volume-ffi/src/lib.rs`](../crates/hidden-volume-ffi/src/lib.rs).
Whenever the FFI surface changes, regenerate:

```sh
# From the repo root.
cargo build -p hidden-volume-ffi --release
for lang in kotlin swift python ruby; do
    cargo run --bin uniffi-bindgen --features bindgen-cli -p hidden-volume-ffi -- \
        generate \
        --library target/release/libhidden_volume_ffi.so \
        --language "$lang" \
        --out-dir "bindings/$lang"
done
# Refresh the .so next to the Python module so test_smoke.py finds it.
cp target/release/libhidden_volume_ffi.so bindings/python/
```

Auto-format warnings (`ktlint`, `swiftformat`, `yapf`, `rubocop`) are
benign — install the relevant formatter on your dev box to silence,
or ignore in CI. The generated source is valid without formatting.

## Per-language integration

### Python

```python
import hidden_volume_ffi as hv

space = hv.SpaceHandle.create(
    path="/tmp/store.bin",
    password=b"my-password",
    argon=hv.ArgonPreset.DEFAULT,
    initial_garbage_chunks=0,
    superblock_replicas=3,
)
space.commit([
    hv.WriteOp.PUT(namespace=1, key=b"username", value=b"alice"),
    hv.WriteOp.APPEND_LOG(namespace=3, log_id=1, payload=b"hello"),
])
print(space.get(namespace=1, key=b"username"))  # b"alice"
```

Async with `asyncio`:

```python
import asyncio, hidden_volume_ffi as hv

async def main():
    space = await hv.AsyncSpaceHandle.open(path="/tmp/store.bin", password=b"my-password")
    print(await space.get(1, b"username"))

asyncio.run(main())
```

The Python module loads `libhidden_volume_ffi.so` via `ctypes`. Make
sure the `.so` is in the same directory as the `.py` file (this repo
ships it that way) or set `LD_LIBRARY_PATH` to a directory containing
it.

### Kotlin (Android)

The generated `.kt` file uses [JNA](https://github.com/java-native-access/jna)
under the hood (JNA is uniffi's default for Kotlin; no JNI hand-coding
required).

```kotlin
import uniffi.hidden_volume_ffi.*

val space = SpaceHandle.create(
    path = "/data/data/com.example.app/files/store.bin",
    password = "my-password".toByteArray(),
    argon = ArgonPreset.DEFAULT,
    initialGarbageChunks = 0u,
    superblockReplicas = 3.toUByte(),
)
space.commit(listOf(
    WriteOp.Put(namespace = 1u, key = "username".toByteArray(), value = "alice".toByteArray()),
))
```

For Android packaging, you'll cross-compile the cdylib for each ABI:

```sh
cargo install cargo-ndk
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
    build -p hidden-volume-ffi --release
```

…then bundle the resulting `.so` files alongside the `.kt` source in
your `.aar`. See `TASKS.md` v0.8 build pipeline for the full recipe;
that work is deferred until an Android integrator commits.

### Swift (iOS / macOS)

```swift
import Foundation
// (Build the xcframework as documented in TASKS.md v0.8.)

let space = try SpaceHandle.create(
    path: "/Users/me/Library/store.bin",
    password: Data("my-password".utf8),
    argon: .default,
    initialGarbageChunks: 0,
    superblockReplicas: 3
)
try space.commit(ops: [
    .put(namespace: 1, key: Data("username".utf8), value: Data("alice".utf8))
])
```

`xcframework` packaging requires Xcode + macOS host (cargo cross-
compile to `aarch64-apple-ios` etc.). Recipe in `TASKS.md` v0.8.

### Ruby

```ruby
require_relative 'hidden_volume_ffi'

space = HiddenVolumeFfi::SpaceHandle.create(
    path: '/tmp/store.bin',
    password: 'my-password'.b,
    argon: HiddenVolumeFfi::ArgonPreset::DEFAULT,
    initial_garbage_chunks: 0,
    superblock_replicas: 3
)
```

## See also

- [`docs/en/reference/ffi.md`](../docs/en/reference/ffi.md) — architectural
  decisions (why uniffi, why this API shape, threading model)
- [`crates/hidden-volume-ffi/src/lib.rs`](../crates/hidden-volume-ffi/src/lib.rs)
  — the Rust source these bindings are generated from
- [`docs/en/guide/integration.md`](../docs/en/guide/integration.md) — semantic
  integration guide (host-app concerns: rollback anchors,
  multi-device sync, key rotation)
