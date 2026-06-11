# hidden-volume

🇬🇧 **English** · [🇷🇺 Русский](README.ru.md)

Deniable multi-space encrypted append-only container — a storage primitive
for messengers and other apps that need plausible-deniability against
compelled-key disclosure.

A single file holds an arbitrary number of independent encrypted spaces.
An adversary with the file plus one password cannot prove that other
spaces exist. Each space has its own per-chunk AEAD keys derived from
its password; chunks of different spaces are mutually indistinguishable
from random bytes.

```text
messenger.store
└── 48-byte cleartext header (salt + Argon2 params)
    └── slot grid of fixed 4096-byte chunks
         ├── space A's encrypted IndexNode chunks
         ├── space B's encrypted IndexNode chunks  (hidden)
         ├── space A's encrypted DataBatch chunks
         ├── garbage padding chunks
         └── ...
```

Format version 3 (since 2026-05-28). Per-space `container_id` is
derived from the versioned master key — no per-space identifier
sits in the cleartext header. See [`docs/en/reference/format.md`](docs/en/reference/format.md)
for the canonical byte layout.

## Status

**v1.0.0 released (2026-05-28).** On-disk format and public API
are now frozen — any subsequent breaking change requires a v2.0
major bump and a proper migration tool. See [`TASKS.md`](TASKS.md)
for the milestone roadmap, [`DESIGN.md`](DESIGN.md) for design
rationale, and [`docs/en/reference/format.md`](docs/en/reference/format.md) for the
canonical byte-level wire format spec (frozen as of v1.0).
Host-app integration guide:
[`docs/en/guide/integration.md`](docs/en/guide/integration.md). Formal threat model:
[`docs/en/security/threat-model.md`](docs/en/security/threat-model.md). Operations playbook
(backup, restore, key rotation, recovery, scrub):
[`docs/en/guide/operations.md`](docs/en/guide/operations.md). Semver policy:
[`docs/en/reference/semver.md`](docs/en/reference/semver.md).

| Capability | Status |
|---|---|
| Multi-space deniability (D1, D2 invariants) | ✓ shipped |
| KV index with namespaces (2-level B+ tree) | ✓ shipped |
| Append-log via DataBatch + zstd | ✓ shipped |
| **Paginated log** (`iter_log_after` / `iter_log_before`) | ✓ shipped |
| Crash recovery (3-fsync protocol) | ✓ shipped + property-based crash proptest |
| Forward-secrecy (vacuum_orphans on open) | ✓ shipped |
| Compaction / repack with batch scrub | ✓ shipped |
| Multi-Superblock replicas (corruption resilience) | ✓ shipped |
| Padding policy + initial garbage | ✓ shipped |
| Exclusive / shared file lock (multi-process safety) | ✓ shipped |
| **Read-only mode** (`open_readonly`, `LOCK_SH`) | ✓ shipped |
| **Cooperative cancellation** (`CancelToken`) | ✓ shipped (open + repack) |
| **Multi-device anchors** (`commit_seq` + `commit_history`) | ✓ shipped, see [`multi-device.md`](docs/en/guide/multi-device.md) |
| **Merkle integrity walk** (`verify_integrity`) | ✓ shipped |
| **Streaming open** (O(M·16 B) memory regardless of container size) | ✓ shipped |
| **Parallel scan** (`parallel-scan` feature, Unix, 2.8× at 40 MiB → 7.4× at 400 MiB) | ✓ shipped |
| **mmap reader** (`mmap` feature, Unix, zero-copy scan path) | ✓ shipped |
| Property tests + parser fuzzing | ✓ shipped (proptest + 26 parser fuzz cases) |
| Audit passes (CT / memory / fsync / plaintext-leak) | ✓ all four shipped |
| Performance benchmarks | ✓ shipped (see [`docs/en/contributing/benchmarks.md`](docs/en/contributing/benchmarks.md)) |
| Tokio-based async wrapper (`hidden-volume-async` crate) | ✓ shipped |
| Pre-derived key cache (skip Argon2id on relaunch) | ✓ shipped |
| `hv` CLI utility (`cli` feature) | ✓ shipped |
| FFI bindings (Kotlin / Swift / Python / Ruby via uniffi 0.31) | ✓ shipped (v0.8 scaffold + generated bindings) |
| External security review | ✗ not planned — [self-audit dossier](docs/en/security/audits/self-audit.md) §1 documents the rationale (anonymity + no-budget) and the substitute process (18 in-tree audit passes + property-level review + bug bounty + reproducible signed builds) |

## Quick start

```rust
use hidden_volume::{Container, crypto::kdf::Argon2Params};
use hidden_volume::space::index::Namespace;

# fn run() -> hidden_volume::Result<()> {
// Create a container. Pick Argon2 params for your target hardware:
//   Argon2Params::LIGHT   — low-end ARM (Cortex-A53)
//   Argon2Params::DEFAULT — typical mobile (last 5y phones)
//   Argon2Params::HEAVY   — desktop / server-class
let mut container = Container::create(
    "/path/to/messenger.store",
    Argon2Params::DEFAULT,
)?;

// First space — the user's main profile.
{
    let mut space = container.create_space(b"main-password")?;
    let mut tx = space.begin_tx();
    tx.put(Namespace::SETTINGS, b"username", b"alice")?;
    tx.put(Namespace::CONTACTS, b"bob",      b"bob@example.com")?;
    tx.append_log(Namespace::MESSAGE_LOG, 1, b"first message")?;
    tx.commit()?;
}

// Hidden second space, completely independent.
{
    let mut hidden = container.create_space(b"hidden-password")?;
    let mut tx = hidden.begin_tx();
    tx.put(Namespace::SETTINGS, b"username", b"actual-identity")?;
    tx.commit()?;
}

// Reopen and read back.
let mut container = Container::open("/path/to/messenger.store")?;
let mut main = container.open_space(b"main-password")?;
assert_eq!(
    main.get(Namespace::SETTINGS, b"username")?.as_deref(),
    Some(&b"alice"[..])
);
# Ok(()) }
```

A complete runnable example lives at
[`crates/hidden-volume/examples/messenger_lifecycle.rs`](crates/hidden-volume/examples/messenger_lifecycle.rs):

```sh
cargo run --example messenger_lifecycle
```

For the full guided tour of every API a messenger needs (pagination,
cancellation, multi-device anchors, key caching, integrity audits,
anti-patterns), read [`docs/en/guide/integration.md`](docs/en/guide/integration.md).

### Message-history pagination

Don't materialize a 100 K-message log into memory; use cursor-based
pagination. `iter_log_before` is the canonical chat-UI primitive
("scroll up to see older messages"):

```rust,ignore
use hidden_volume::space::index::Namespace;

// First page: 50 newest messages.
let page1 = space.iter_log_before(Namespace::MESSAGE_LOG, None, 50)?;

// Subsequent pages: pass the oldest log_id from the previous page.
let cursor = page1.last().map(|(id, _)| *id);
let page2 = space.iter_log_before(Namespace::MESSAGE_LOG, cursor, 50)?;
```

Memory bound: O(limit) decoded entries plus a few touched DataBatch
chunks — independent of total namespace size. **5.6× faster** than
the legacy `iter_log` on a 1 000-message log (87 µs vs 484 µs;
[`docs/en/contributing/benchmarks.md`](docs/en/contributing/benchmarks.md)).

### Cancellation (mobile UX)

Long operations (`open_space` scan, `repack`) accept a
[`CancelToken`](crates/hidden-volume/src/cancel.rs) for cooperative abort. Necessary
because `tokio::task::spawn_blocking` cannot abort a running closure
on its own:

```rust,ignore
use hidden_volume::cancel::CancelToken;

let token = CancelToken::new();
let arm = token.clone();
std::thread::spawn(move || {
    std::thread::sleep(std::time::Duration::from_secs(5));
    arm.cancel();
});

match container.open_space_cancellable(b"password", &token) {
    Ok(_) => { /* unlocked in time */ }
    Err(hidden_volume::Error::Cancelled) => { /* user pressed cancel */ }
    Err(e) => return Err(e),
}
```

### Rollback / fork detection

After every commit, persist `space.commit_seq()` to TPM /
Secure Enclave / a server counter. On reopen verify the file's
state hasn't been swapped:

```rust,ignore
let cur = space.commit_seq();
let history = space.commit_history();
if cur < anchor_seq || !history.contains(&anchor_seq) {
    panic!("rollback or fork detected — file replaced with older version");
}
```

Full algorithm + anchor-storage tradeoffs in
[`docs/en/guide/multi-device.md`](docs/en/guide/multi-device.md).

### Integrity self-test

Walk the full Merkle hash chain in 125 µs (sub-millisecond on tested
hardware) — recommended after sync from a peer or as a periodic
defense-in-depth audit:

```rust,ignore
let report = space.verify_integrity()?;
println!(
    "verified {} chunks across {} namespaces, max depth {}",
    report.chunks_verified, report.namespaces_verified, report.max_depth,
);
```

### CLI utility (`hv`)

The `cli` feature builds an `hv` binary for debugging, scripting, and
migration:

```sh
cargo install --path . --features cli
```

Subcommands:

```sh
hv info <path>                                   # public header info, no password
hv create <path> [--params LIGHT|DEFAULT|HEAVY|MIN]
hv create-space <path>                           # password read from first stdin line
hv inspect <path>                                # list namespaces with counts
hv get <path> <namespace_id> <key>
hv put <path> <namespace_id> <key> <value>       # value via argv (visible in /proc/<pid>/cmdline)
hv put <path> <namespace_id> <key> --value-stdin # value as second stdin line (private)
hv repack <source> <dest>                        # passwords from stdin, one per line
```

Passwords are always read from stdin — there is no env-var fallback (env
vars leak via `/proc/<pid>/environ` and shell history). For non-interactive
use, pipe the password in:

```sh
printf 'secret\n' | hv create-space messenger.store
printf 'secret\n' | hv put messenger.store 1 username alice
printf 'secret\n' | hv get messenger.store 1 username
printf 'secret\n' | hv inspect messenger.store
# To avoid argv leak of the value as well:
printf 'secret\nbob@example.com\n' | hv put messenger.store 2 bob --value-stdin
```

Namespace IDs follow the `Namespace` constants:
- `1` SETTINGS
- `2` CONTACTS
- `3` MESSAGE_LOG
- `4` MEDIA
- `5+` host-app custom namespaces

### Async / Tokio integration

The separate **[`hidden-volume-async`](crates/hidden-volume-async)
crate** exposes `AsyncContainer`, which offloads sync operations onto
Tokio's blocking-thread pool via `spawn_blocking`. The sync core stays
tokio-free — async users opt into tokio explicitly by depending on
the wrapper crate; sync-only users (mobile / single-process desktop)
pay zero dep cost for tokio.

```toml
[dependencies]
hidden-volume = { version = "..." }
hidden-volume-async = { version = "..." }
tokio = { version = "1", features = ["rt-multi-thread"] }
```

```rust,ignore
use hidden_volume::space::index::Namespace;
use hidden_volume_async::AsyncContainer;

let container = AsyncContainer::open("/path/to/store").await?;
container.run(|c| {
    let mut s = c.open_space(b"password")?;
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"theme", b"dark")?;
    tx.commit()?;
    Ok(())
}).await?;
```

The `run()` method accepts any `FnOnce(&mut Container) -> Result<R>`,
so transactional batches stay together inside one blocking-pool
dispatch. For cancellable async work use `run_cancellable(token, |c, t| …)`
which threads a `CancelToken` into the closure (necessary because
`spawn_blocking` cannot abort a running closure on its own — the
token is the workaround).

### Parallel scan (`parallel-scan` feature, Unix-only)

For multi-core hosts opening multi-MiB containers,
`Container::open_space_parallel` parallelizes the discovery scan via
rayon's work-stealing pool (capped to 4 threads, lazily-cached). The
speedup grows with container size — on the 12-thread x86 dev host:

| Container | Sequential | Parallel | Speedup |
|---|---:|---:|---:|
| 40 MiB / 10 K slots | 52 ms | 18 ms | 2.8× |
| 200 MiB / 50 K slots | 608 ms | 264 ms | 2.3× |
| 400 MiB / 100 K slots | 1499 ms | 204 ms | **7.4×** |

**TL;DR for messenger devs.** Enable `parallel-scan` for any
multi-core host with messenger-realistic history (≥ 40 MiB). At
400 MiB of history (a heavy user) the unlock drops from 1.5 s to
200 ms — directly visible in UX. Leave the feature OFF on
single-core mobile (it collapses to 1 thread and you pay rayon's
~6 MiB binary-size cost for no speedup). See
[`docs/en/contributing/benchmarks.md`](docs/en/contributing/benchmarks.md) "Parallel-scan tuning" + "Scaling" for the
full analysis.

### mmap reader (`mmap` feature, Unix-only)

Zero-copy alternative scan path. Maps the entire container file via
`mmap(2)` and slices each chunk out of the mapping —
`Container::open_space_mmap` instead of the streaming `pread` path.

When to use: cold-cache opens of multi-GiB containers, where
avoiding per-chunk syscall overhead produces a measurable
wall-clock win. On warm-cache repeat opens the difference is small;
the kernel page cache dominates either way. The feature trades a
`memmap2` dependency (~80 KiB compiled) and an `unsafe` Mmap
construction for that win — `LOCK_EX` / `LOCK_SH` flock excludes
concurrent writers, which is what makes the unsafe call safe.

Behavioral guarantee: identical `Space` state to sequential and
parallel paths. `tests/mmap_scan.rs` (7 scenarios) cross-checks
against both — see "Architecture" for which crate hosts which path.

## What this protects

- **Confidentiality** of every space against any party without its
  password (XChaCha20-Poly1305 per chunk, Argon2id KDF).
- **Cross-space isolation** — opening space A neither reveals nor can
  accidentally corrupt space B (per-space keys + append-only file).
- **Single-snapshot deniability** (D1) — the file is statistically
  indistinguishable from a uniform-random blob with one 48-byte
  cleartext header (salt + Argon2 params). v3 (2026-05-28) removed
  the per-space `container_id` from the cleartext header, closing
  the D1-A2 fingerprint.
- **Compelled-key deniability** (D2) — predicating a password yields
  one space; the holder of that password cannot prove the existence
  of others.
- **Per-chunk integrity** — byte modification produces an AEAD failure
  on the affected chunk.
- **Forward-secrecy after reopen** — `Container::open_space`
  automatically scrubs orphan IndexNode chunks; `Container::compact`
  does the same for DataBatch.
- **Crash safety** — three-fsync commit protocol with multi-replica
  Superblock fallback. Validated by 8 hand-written truncation
  scenarios + property-based crash-recovery (random-ops × random-
  truncate, asserts recovered seq is a previously-committed seq) +
  exhaustive truncate-at-every-slot sweep.
- **Multi-process safety** — exclusive `flock(LOCK_EX)` on open
  prevents two writers; `LOCK_SH` lets multiple readers coexist with
  one writer (`open_readonly`). Useful for sync agents or backup
  tools running alongside the app.
- **Tamper-evident integrity** — `verify_integrity()` walks the
  Merkle chain (Superblock → Commit → IndexNode tree) and surfaces
  any hash mismatch as `Error::IntegrityFailure { detail, slot }`.
- **Cooperative cancellation** — long operations (open scan, repack)
  poll a `CancelToken` at periodic checkpoints. Mobile UX can abort
  unlock attempts mid-flight without leaving the file in a partial
  state.
- **Streaming-bounded memory on open** — the discovery scan retains
  ~16 bytes per owned chunk regardless of file size; multi-GiB
  containers open without OOM on weak ARM.

## What this does NOT protect against

Read this list carefully — a hidden-volume file is only as deniable as
the host application's behavior around it.

- **Side-channel leaks at the application layer** — recently-opened
  files, IME caches, screenshot thumbnails, swap, system logs. The
  library can't see those; the host-app must.
- **Multi-snapshot byte-diff analysis** (T2') — in-place rewrite or
  tombstone of an existing slot leaves a "this byte changed" signal
  that distinguishes active slots from genuine garbage. See
  [`DESIGN.md`](DESIGN.md) §1.
- **Rollback attacks (out of the box)** — if the adversary captures
  the file at time T₁ and restores it after the user has committed
  at T₂, the user loses recent state and the library on its own
  cannot detect it. The library DOES expose `Space::commit_seq()`
  + `Space::commit_history()` so the host-app can implement
  rollback / fork detection against an external anchor (TPM, server
  counter, signed log) — see [`docs/en/guide/multi-device.md`](docs/en/guide/multi-device.md).
- **The fact that the file is encrypted** — high-entropy files are
  visible to any forensic scan. Deniability is about *which* and
  *how many* secrets are inside, not about hiding that the file is
  a ciphertext.

## Hardware tuning

The Argon2id cost is per-container, set at creation time, persisted in
the cleartext header. Pick a preset that matches the target device:

| Preset | m | t | p | Open time | Use case |
|---|---|---|---|---|---|
| `Argon2Params::LIGHT` | 16 MiB | 3 | 1 | ~30 ms | Low-end ARM (Cortex-A53) |
| `Argon2Params::DEFAULT` | 64 MiB | 3 | 1 | ~100 ms | Mid-range mobile |
| `Argon2Params::HEAVY` | 256 MiB | 4 | 4 | ~250 ms | Desktop / server |

`Argon2Params::MIN` (m=8 MiB, t=2, p=1) is the floor — the library
refuses to open or create a container with weaker params (defense
against a malicious-host attack).

## Architecture

Cargo workspace with four crates:

```
crates/hidden-volume/        — sync core (no tokio dependency)
└── src/
    ├── crypto/              — primitives: Argon2id KDF, XChaCha20-Poly1305 AEAD,
    │                          BLAKE3 keyed derivation, getrandom RNG
    ├── chunk/               — fixed 4096-byte chunk format + ChunkKind enum
    │                          (Superblock=0x01, IndexNode=0x02, Commit=0x05,
    │                          DataBatch=0x06; 0x03/0x04 reserved)
    ├── container/           — file-level append-only ops, header, PaddingPolicy,
    │                          ContainerOptions, RepackOptions, LOCK_EX / LOCK_SH
    │                          lock modes, repack + compact_known + change_passwords APIs
    ├── space/               — per-space superblock + commit_history; mod.rs split
    │                          into commit / vacuum / log_iter / integrity submodules
    │                          (pass-8 E7); B+ tree IndexNode (Leaf/Internal),
    │                          DataBatch log encoding (zstd), pagination via
    │                          iter_log_after / _before, vacuum_orphans +
    │                          vacuum_data_batches, verify_integrity Merkle walk,
    │                          erase_namespace, stats
    ├── tx/                  — Tx<'s, 'f> with put/delete/append_log/commit;
    │                          CommitPayload encoding (Merkle root over IndexRoots)
    ├── padding/             — None | BucketGrowth | FixedRatio policies; presets
    │                          0..=3 persisted via Argon2Params.version bits 16..24
    ├── open/                — discovery scan + recovery (sequential streaming;
    │                          optional rayon-parallel via `parallel-scan` feature,
    │                          optional mmap via `mmap` feature)
    ├── cancel.rs            — CancelToken (Arc<AtomicBool>) for cooperative abort
    ├── bin/hv.rs            — `hv` CLI (feature `cli`): info, create, inspect, …
    └── error.rs             — single Error enum; AuthFailed unifies wrong-password
                               and no-such-space (deniability invariant D2)

crates/hidden-volume-rt/     — internal runtime helpers (pass-8 E5/E6 extraction)
└── src/lib.rs               — OwnedSpace (self-referential Box<Container> +
                               Space<'static>) and run_blocking adapter shared
                               between the async + ffi crates. Not for end-users.

crates/hidden-volume-async/  — Tokio wrapper crate (depends on hidden-volume + -rt)
└── src/lib.rs               — AsyncContainer (run / run_cancellable) and
                               AsyncSpace (run / stream_log_pages_*); spawn_blocking
                               offload; mutex-serialized handle.

crates/hidden-volume-ffi/    — uniffi 0.31 bindings (depends on hidden-volume + -rt)
└── src/lib.rs               — SpaceHandle (sync) + AsyncSpaceHandle (Tokio);
                               typed surface for Kotlin / Swift / Python / Ruby
                               via uniffi-generated bindings under `bindings/`.
```

See [`DESIGN.md`](DESIGN.md) for the full on-disk format specification,
threat model, and invariant catalog.

## Testing

```sh
cargo test --all-features
cargo test --doc                  # crate-level doctest
cargo bench                       # see docs/en/contributing/benchmarks.md for baselines
cargo clippy --all-targets --all-features -- -D warnings
```

43 integration test files (39 in `hidden-volume`, 3 in
`hidden-volume-async`, 1 in `hidden-volume-ffi`) plus unit tests;
**397 tests** green on the dev machine. Highlights:

- **Crash recovery**: 8 hand-written truncate scenarios + property-
  based crash proptest (24 random workloads × 3 invariants:
  monotonicity, no-panic, idempotence) + exhaustive
  truncate-at-every-slot sweep.
- **Parser fuzzing**: 26 stable-Rust proptest cases — `decode_doesnt_panic`
  + roundtrip + edge cases for every wire format.
- **Property test against reference model** (BTreeMap) for random
  Put/Delete/AppendLog/Commit/Reopen sequences.
- **Pagination correctness**: 13 scenarios for `iter_log_after` /
  `iter_log_before` covering empty / sparse / B+ split / cross-batch.
- **Multi-device contract**: 8 scenarios for `commit_history` (dedup,
  reopen survival, isolation, post-compact reset).
- **Integrity Merkle walk**: 10 scenarios for `verify_integrity`
  including AEAD-corruption localized to specific slots.
- **Cancellation**: 10 scenarios for open + repack cancellation,
  including async `run_cancellable` smoke.
- **Multi-process safety**: locking + readonly + sequential hand-off.
- **Memory + plaintext-leak hygiene**: type-level regression tests
  locking in `Zeroizing` wraps for keys and transient plaintext.

## License

Dual-licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
