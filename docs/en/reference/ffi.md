# FFI design — `hidden-volume-ffi`

🇬🇧 **English** · [🇷🇺 Русский](../../ru/reference/ffi.md)

This document records the architectural decisions for the v0.8 FFI
milestone. It is the integrator-facing reference for anyone embedding
`hidden-volume` into a non-Rust codebase (Kotlin, Swift, Python, Ruby).

## Status

- v0.8.0 (this commit): **Rust-side scaffold + sync API surface
  complete**. Builds clean, passes 5 FFI-level integration tests.
- v0.8.x: iOS `xcframework`, Android `.aar` / `.so`, Flutter sample
  app, CI matrix — **deferred** until at least one host-app team is
  ready to integrate (no point building toolchain wiring nobody will
  exercise).

## Decision 1 — Bindings tool: **uniffi** (over `flutter_rust_bridge`, `cbindgen`, `cxx`)

| Tool | Languages | Memory safety | Maintenance burden | Flutter | Verdict |
|---|---|---|---|---|---|
| **uniffi-rs** | Kotlin, Swift, Python, Ruby (+ community ports for Go, C#, Dart) | High — generated bindings own memory, errors map to typed exceptions | Low — single Rust source of truth, optional UDL | via Dart port | **Chosen** |
| flutter_rust_bridge | Dart only | High — but Dart-specific | Medium — separate `.dart` glue | Native | Single-target; would need a parallel JNI layer for Android Kotlin |
| cbindgen | C ABI → any | Hand-rolled; manual memory ownership rules | High — every binding language needs its own wrapper | Via FFI plugin | Too low-level; reinvents what uniffi does |
| cxx | Rust ↔ C++ | Excellent for C++ | High — needs C++ wrapper for every method | Indirect | C++-specific; Kotlin/Swift would still need JNI/ObjC wrapping |

**uniffi rationale.** A messenger that ships on Android (Kotlin), iOS
(Swift), and a desktop port (Python or .NET) needs at least three host
languages. uniffi gives us all three from one Rust source of truth.
The Dart port (`uniffi-dart`) covers Flutter without a separate
wrapper. Memory ownership is generated correctly by default — host-app
developers who integrate it never write `unsafe` JNI code or
`@_implementationOnly` Swift glue.

The cost: one extra build step (`uniffi-bindgen generate ...`) per
target language. This runs once per `cargo build`, not at runtime.

**Why not flutter_rust_bridge despite Flutter being a major messenger
target?** It's Dart-only — we'd still need a parallel JNI/Kotlin layer
for native Android UIs (e.g. notification handlers, tile widgets) that
don't go through Dart. Two FFI surfaces is worse than one.

## Decision 2 — proc-macro mode (over UDL)

uniffi 0.31 supports two authoring styles:

1. **UDL file** (`hidden_volume.udl`): WebIDL-like schema, separate
   from Rust source. Older style.
2. **Proc-macro attributes** (`#[derive(uniffi::Object)]`,
   `#[uniffi::export]`): annotate the Rust source directly.

We use **proc-macros** because:

- **No drift.** The UDL approach requires keeping `.udl` and `.rs` in
  sync; mismatches surface only at bindgen time.
- **Better diagnostics.** `cargo build` catches type errors at the
  Rust call site.
- **Lower file count.** One `lib.rs` instead of `lib.rs + .udl + build.rs`
  scaffolding.

The trade-off: proc-macro mode requires uniffi 0.25+, which is fine
since we're building a fresh crate.

## Decision 3 — combined `Container + Space` handle (over two-step)

The natural Rust API is two-step:

```rust
let mut c = Container::open(path)?;
let mut s = c.open_space(password)?;
s.put(...);
```

`Space<'f>` borrows mutably from `Container`. This is great in Rust
(the borrow checker prevents holding two open spaces against the same
container) but **does not translate to FFI** because:

- uniffi-exported objects must be `Send + Sync + 'static`.
- The borrow `&'f mut Container` is not `'static`.
- A two-step API would require uniffi callback-interfaces (host calls
  back into Rust with the open space) — awkward in Kotlin/Swift.

Our shape: one combined `SpaceHandle` constructor opens the file,
opens the space, and holds both:

```kotlin
// Kotlin
val space = SpaceHandle.open("/storage/store.bin", "password".toByteArray())
space.commit(listOf(WriteOp.Put(/*ns*/1u, "username".encodeToByteArray(), "alice".encodeToByteArray())))
```

```swift
// Swift
let space = try SpaceHandle.open(path: "/storage/store.bin", password: Data("password".utf8))
try space.commit(ops: [.put(namespace: 1, key: Data("username".utf8), value: Data("alice".utf8))])
```

For multi-space deniability flows (rare in practice — one user, one
password, one space), the pattern is: drop the existing handle,
re-open with a different password. The file flock prevents concurrent
multi-handle use anyway.

### Self-referential implementation

Internally `SpaceHandle` holds:

```rust
struct SpaceInner {
    container: Box<Container>,           // stable address
    space: ManuallyDrop<Space<'static>>, // borrow with lifetime extended
}
```

The `'static` is a lie — the `Space` is only valid while `container`
lives at its current heap address. Safety:

1. `container` is `Box`-allocated; address is stable for the lifetime
   of `SpaceInner`.
2. After `transmute`-ing the lifetime, we never move `container`.
3. `Drop for SpaceInner` drops `space` first (it borrows from
   `container`), then `container`. Without `ManuallyDrop`, Rust's
   automatic field-drop order would drop `container` first — UB.

This is the standard self-referential FFI pattern; `self_cell` and
`ouroboros` crates exist to abstract it but we use the direct form
to avoid an extra dep for ~30 lines of code. The unsafe block is
documented in `src/lib.rs:SpaceInner::new`.

## Decision 4 — batch `commit(Vec<WriteOp>)` over per-op auto-commit

A naive FFI shape would expose `put` / `delete` / `append_log` directly
on `SpaceHandle`, each auto-wrapping in a one-op Tx. This is wasteful
because:

- Every Tx costs **3 fsync barriers** (~5 ms on SSD, hundreds of ms on
  cheap eMMC).
- A messenger that puts a contact, updates its avatar URL, and logs a
  "contact added" message would pay 3× this floor.

Instead we expose a single `commit(ops: Vec<WriteOp>)`. The host-app
batches at the call site:

```kotlin
space.commit(listOf(
    WriteOp.Put(namespace = 2u, key = "alice".encodeToByteArray(), value = avatarUrl),
    WriteOp.Put(namespace = 2u, key = "alice.tag", value = tagBytes),
    WriteOp.AppendLog(namespace = 3u, logId = msgIdGen.next(), payload = "Added Alice".encodeToByteArray()),
))
```

This makes the 3-fsync cost amortize naturally over each logical
"action" the host-app performs, matching the underlying transactional
model exactly. Empty `commit(emptyList())` is a no-op (returns the
unchanged `commit_seq`).

## Decision 5 — flat error enum

Rust's `Error` is a typed enum with 14 variants. uniffi supports
mapping this to typed exceptions on the foreign side, but each variant
needs to be FFI-friendly (no `&'static str`, no opaque data).

Our [`HvError`] is a 1:1 mirror with all `&'static str` payloads
converted to `String`. The `#[uniffi(flat_error)]` attribute makes
uniffi generate idiomatic Kotlin sealed classes / Swift enums:

```kotlin
sealed class HvException : Exception() {
    object AuthFailed : HvException()
    object Busy : HvException()
    data class Malformed(val message: String) : HvException()
    data class IntegrityFailure(val detail: String, val slot: ULong) : HvException()
    // ...
}
```

```swift
public enum HvError: Error {
    case AuthFailed
    case Busy
    case Malformed(String)
    case IntegrityFailure(detail: String, slot: UInt64)
    // ...
}
```

The mapping preserves the **deniability invariant**: `AuthFailed`
fires for both wrong-password AND no-such-space; foreign callers
cannot distinguish (and MUST NOT branch on the difference).

## Decision 6 — both sync and async API surfaces (v0.8.1+)

We ship **two sibling handle types**:

- [`SpaceHandle`] — the synchronous workhorse. Methods take `&self`,
  block the calling thread on the underlying mutex + sync-core call.
- [`AsyncSpaceHandle`] — the async sibling. Methods are `async fn` and
  offload the underlying sync work to `tokio::task::spawn_blocking`.

### Why both, not just one

A messenger's storage layer faces two distinct integrator profiles:

| Profile | Native idiom | Best surface |
|---|---|---|
| Android / Kotlin coroutines | `suspend fun` | **Async** — `AsyncSpaceHandle` maps to a `suspend fun` |
| iOS / Swift `async/await` | `async throws` | **Async** — `AsyncSpaceHandle` maps to `async throws` |
| iOS / GCD-only legacy code | `DispatchQueue.global` | **Sync** — caller already wraps in their scheduler |
| Pure-Rust desktop / server | tokio runtime | **Async** for non-blocking storage |
| Server-side single-threaded scripts (Python, Ruby) | sync calls | **Sync** — async overhead unjustified |
| Embedded ARM with no Tokio | sync calls | **Sync** — async pulls Tokio (~700 KB binary) |

Shipping both lets each integrator pick the right tool. The two
handles **share the same internal `SpaceInner`** (boxed Container +
ManuallyDrop'd Space behind Mutex) — code duplication is only the
method shells, not the storage logic. There is no "async vs sync"
runtime split in the format or in the sync core; the async surface is
a pure offload wrapper, identical to what `hidden-volume-async` does
for pure-Rust callers.

### What async actually buys

The sync core's wall-clock is dominated by the 3-fsync floor (~5 ms on
SSD, hundreds of ms on cheap eMMC) and Argon2id (tens to hundreds of
ms depending on preset). Async does NOT make any single call faster.
What it buys:

1. **Doesn't block the UI thread.** A messenger that calls
   `space.get()` from the main coroutine on Android stays responsive
   to scrolling / animations because the actual work runs on a
   blocking-pool thread.
2. **Concurrent calls overlap.** Two `tokio::spawn`-ed tasks can each
   await `AsyncSpaceHandle.get(...)` and the runtime interleaves them
   between page-cache misses. The internal mutex still serializes
   actual storage access (only one Tx per Space), but the pre/post
   work outside the lock can interleave.
3. **Cancellation hooks.** A future iteration can plumb
   `CancelToken` through the FFI boundary as a Kotlin `Job` /
   Swift `Task` cancel — the async surface is the natural place.

### Runtime requirement

The host process must be running a Tokio multi-thread runtime when
async methods are awaited. uniffi's `tokio` feature handles this
automatically for Kotlin / Swift integrators by starting a runtime
inside the Rust dylib at first use.

For pure-Rust callers, wrap in `#[tokio::main]` or construct the
runtime yourself. The async-only `hidden-volume-async` crate exists
for pure-Rust async use cases without the FFI overhead.

### Method coverage

`AsyncSpaceHandle` mirrors **every** method of `SpaceHandle` 1:1:
constructors (`create`, `open`), reads (`get`, `count`,
`list_namespaces`, `read_log`, `iter_log_range`, `commit_seq`,
`commit_history`, `stats`, `verify_integrity`), and write
(`commit`). Same arguments, same error shapes, same semantics — just
`async fn` everywhere.

### What we still don't ship

- **Streaming `iter_log_*`**. uniffi async returns single futures, not
  streams. For unbounded scrollback, host-app pages via
  `iter_log_range` in a loop (same as sync). A `Stream`-based FFI
  would need uniffi callback-interfaces or a foreign-side `Flow` /
  `AsyncSequence` adapter.
- **Cancellation tokens through the FFI boundary**. Would need uniffi
  callback-interface support; defer to actual demand.
- **`async-stream`-based pagination helpers** like the pure-Rust
  `hidden-volume-async::AsyncSpace::stream_log_pages_*` methods.
  Pure-Rust callers should use `hidden-volume-async` directly for
  Stream-style APIs.

## Bindings generation (v0.8.1+)

We ship an **in-tree** `uniffi-bindgen` driver:
[`crates/hidden-volume-ffi/src/bin/uniffi-bindgen.rs`](../../../crates/hidden-volume-ffi/src/bin/uniffi-bindgen.rs).
Recommended pattern from uniffi 0.25+: instead of `cargo install
uniffi-bindgen-cli` (which can drift out of sync with the runtime
crate version), each FFI crate ships its own bindgen bin pinned to
the same uniffi version it uses for exports.

Regenerate all four supported languages:

```sh
cargo build -p hidden-volume-ffi --release
for lang in kotlin swift python ruby; do
    cargo run --bin uniffi-bindgen --features bindgen-cli -p hidden-volume-ffi -- \
        generate \
        --library target/release/libhidden_volume_ffi.so \
        --language "$lang" \
        --out-dir "bindings/$lang"
done
```

Output is committed as reference under `bindings/` so integrators can
browse the surface they'll consume without needing to build the
project. Bindings are deterministic — re-running the command on an
unchanged FFI crate produces byte-identical output (modulo the
formatter warnings, which only fire if `ktlint` / `swiftformat` /
`yapf` / `rubocop` are installed).

### Python end-to-end test

`bindings/python/test_smoke.py` is the canary test for binding
correctness. It loads `libhidden_volume_ffi.so` via `ctypes` (through
the auto-generated Python module) and exercises the full sync + async
FFI surface: constructors, opaque handles, byte arrays, optional
values, vector returns, error-variant typed exceptions. A passing
Python run is strong evidence Kotlin / Swift / Ruby bindings are also
correct, since uniffi's per-language code generators share a common
AST extracted from the Rust crate.

```sh
cd bindings/python
python3 test_smoke.py
# all 5 tests passed
```

The test should be added to CI for any PR touching
`crates/hidden-volume-ffi/src/lib.rs`.

## Deferred for v0.8.x

The Rust side is done; what remains is **platform packaging**:

| Item | Why deferred | Trigger to start |
|---|---|---|
| **iOS xcframework** | Needs Xcode + iOS SDK on a macOS build host; not available in Linux sandbox. | First iOS integrator request OR macOS GitHub Actions runner allocated. |
| **Android `.aar` / `.so` per ABI** | Needs Android NDK; cargo-ndk + uniffi-bindgen-kotlin scripts in CI. | First Android integrator request. |
| **Linux/macOS/Windows desktop binaries** | Cross-compile via `cargo` is straightforward but no consumer yet. | First desktop messenger fork that wants to embed. |
| **CI matrix for all targets** | Costs CI minutes; skip until binaries are actually published. | Same trigger as the binary tasks above. |
| **Flutter sample app** | Needs Dart-side generator (`uniffi-dart` 0.4+, currently in beta). Real Flutter integration work has just begun (2026-05-09); the `experimental/flutter_plugin/` scaffold under [`experimental/`](../../../experimental/) is being filled in. | Track progress in `experimental/flutter_plugin/`; graduates out of `experimental/` once the Dart-side typed API replaces the `UnimplementedError` stubs. |
| **`docs/en/guide/flutter.md`** | Currently documents the experimental scaffold + uniffi-dart gate. Will be expanded as the Flutter integration ships. | After the typed Dart API graduates from `experimental/`. |

The Rust-side scaffolding does NOT depend on any of these — they are
pure deployment / packaging work. An integrator who wants Kotlin
bindings today can run:

```sh
cargo install uniffi-bindgen-kotlin    # community CLI
uniffi-bindgen-kotlin --library target/debug/libhidden_volume_ffi.so --out-dir bindings/kotlin
```

…and get a working `.kt` file. Same for Swift via
`uniffi-bindgen-swift`. The bindgen tools are not vendored into this
repo because they evolve independently of the FFI surface.

## Threading model — Mutex per handle

uniffi generates `Arc<SpaceHandle>` — multiple foreign-side references
share one Rust object. We wrap the inner state in `Mutex<SpaceInner>`
to satisfy `Sync`. Concurrent FFI calls from foreign threads serialize
on the lock.

This is the same pattern as `hidden-volume-async`'s `AsyncContainer`.
Per the sync core's design, only one `Tx` may be active per `Space` at
a time — the mutex enforces this at the FFI boundary, matching the
borrow-checker's enforcement for native Rust callers.

## Memory ownership

uniffi handles object lifecycle via reference-counted handles:

- Foreign caller receives `Arc<SpaceHandle>` (Rust-side) wrapped in a
  language-native ref-counted handle (`AutoCloseable` in Kotlin,
  ARC-managed class in Swift).
- When the foreign-side handle drops to zero refs, uniffi calls the
  Rust `Drop`. Our `Drop for SpaceInner` releases the `LOCK_EX` on the
  underlying file.
- Bytes (`Vec<u8>`) cross the FFI boundary by **copying** in both
  directions. This is the only safe choice — the foreign side may
  outlive any single Rust call. For typical messenger payloads
  (≤8 KiB log entries, ≤2 KiB KV values) the copy cost is negligible
  compared to AEAD seal/open.

### Password buffer hygiene (audit pass 16 + 17)

Every password entry point on this crate AND on `hidden-volume-async`
wraps the incoming `Vec<u8>` in `zeroize::Zeroizing` immediately on
function entry:

- Sync: `SpaceHandle::create`, `SpaceHandle::open`.
- Async: `AsyncSpaceHandle::create`, `AsyncSpaceHandle::open`. The
  Zeroizing wrapper is moved INTO the `run_blocking` closure so the
  scrub runs in the closure's drop on the normal-return path. Under
  `panic = "abort"` (workspace `[profile.release]`) destructors do
  not run on panic, so the panic-path "scrub" is the OS process
  teardown — Zeroizing still buys deterministic zeroing before the
  allocator could reuse the bytes on the success path.
- Top-level: `compact_known(path, passwords)` drains
  `Vec<Vec<u8>>` into `Vec<Zeroizing<Vec<u8>>>`;
  `change_passwords(path, rotations)` drains every
  `PasswordRotation` into a pair of `Zeroizing` buffers.

`PasswordRotation` deliberately does NOT derive `Clone` (audit pass
17 F-2). A derived `Clone` would let an internal `.clone()` silently
spawn a non-`Zeroizing` copy outside the wrapper flow.

Foreign-side ownership stays the host-app's hygiene problem: the
Kotlin `ByteArray` / Swift `Data` / Python `bytes` you passed in is
copied across the FFI boundary, but the source buffer remains under
your control on the foreign side. Zero it out yourself once the call
resolves (Kotlin: `pw.fill(0)`; Swift: `pw.resetBytes(in: 0..<count)`).

## Versioning

The FFI crate is versioned independently from `hidden-volume` core,
following the same SemVer policy (`docs/en/reference/semver.md`). Breaking changes
to `HvError` variants, `WriteOp` shape, or `SpaceHandle` method
signatures bump the major. Adding new variants / methods is a minor.

## See also

- [`crates/hidden-volume-ffi/src/lib.rs`](../../../crates/hidden-volume-ffi/src/lib.rs) — the implementation
- [`docs/en/guide/integration.md`](../guide/integration.md) — Rust-side host-app integration tour
- [`docs/en/guide/multi-device.md`](../guide/multi-device.md) — anchor / rollback contract (same on all FFI sides)
- [`docs/en/reference/semver.md`](semver.md) — versioning policy
