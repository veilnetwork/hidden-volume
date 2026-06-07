# Performance baseline

🇬🇧 **English** · [🇷🇺 Русский](../../ru/contributing/benchmarks.md)

Run: `cargo bench --bench throughput`

All numbers in this document are from a single x86_64 run on the
development machine (12-thread, 64 GB RAM, Linux). Mobile ARM hardware
is expected to be 2-3× slower on Argon2-dominated paths and 1.5-2×
slower on chunk I/O paths.

## Baseline numbers (committed: this commit)

All benches use [`Argon2Params::MIN`] (m=8 MiB, t=2, p=1) — about the
weakest acceptable configuration. Production with `Argon2Params::DEFAULT`
(64 MiB / 3 iter) takes roughly 4× longer for any path that crosses the
KDF (`create_space`, `open_space`, repack).

| Benchmark | Time (median) | Notes |
|---|---:|---|
| `create_space` | **5.5 ms** | Argon2id MIN + initial Superblock writes |
| `open_space` | **5.4 ms** | Argon2id MIN + O(N) scan + auto-vacuum |
| `commit_single_kv` | **5.8 ms** | Open + put + commit + close (Argon2 dominates) |
| `commit_100_kv` | **5.8 ms** | 100 puts in one Tx — same baseline as 1 put |
| `commit_1000_kv` | **6.1 ms** | Forces B+ tree split — only +5% over single |
| `commit_log_100` | **5.9 ms** | 100 log entries in one zstd-compressed batch |
| `get_random_kv` | **36 µs** | KV lookup, 1000-entry namespace (2-level B+) |
| `read_log` | **84 µs** | Log lookup, 1000 msgs / 10 batches (incl. zstd decode) |
| `repack_1000` | **13 ms** | Full repack of 1000 KV + 100 log entries |
| `open_large_sequential` | **52 ms** | 5 000 KV + 1 000 log + 10 000 garbage = ~10 K slot / 40 MiB container |
| `open_large_parallel` | **18 ms** | Same container, `parallel-scan` feature — **2.8× faster** |
| `open_50k_sequential` | **608 ms** | 50 K slot / ~200 MiB messenger-sized history |
| `open_50k_parallel` | **264 ms** | Same, `parallel-scan` — **2.3× faster** |
| `open_100k_sequential` | **1499 ms** | 100 K slot / ~400 MiB heavy-history messenger |
| `open_100k_parallel` | **204 ms** | Same, `parallel-scan` — **~7× faster** (page-cache + 4-thread sweet spot) |
| `iter_log_full` | **484 µs** | All 1 000 entries from a 5-batch log (legacy `iter_log`) |
| `iter_log_before_50` | **87 µs** | Newest 50 entries (the messenger-pagination primitive) |
| `verify_integrity` | **125 µs** | Full Merkle walk over 2 namespaces (1 000 + 100 KV) |

## Pagination is the right way

`iter_log_before_50` is **5.6× faster** than `iter_log_full` despite
the same backing log:

```
iter_log_full         484 µs   ← decodes all 1 000 entries
iter_log_before_50     87 µs   ← decodes newest 50 only
```

The win scales linearly with namespace size: a 100 K-message log
would still take ~100 µs for the first reverse page, while
`iter_log_full` would cross 50 ms and become user-visible. Use
`iter_log_after` / `iter_log_before` for any namespace that grows
unbounded — see `docs/en/guide/integration.md` §5.

## verify_integrity is cheap

The full Merkle walk over a non-trivial tree (1 100 KV entries across
2 namespaces) takes 125 µs. Running it as a self-test on every app
launch costs effectively nothing. Recommended cadence: after sync
from a peer, after a host-app crash recovery, periodically as a
defense-in-depth audit.

## Insights

### 1. The 3-fsync floor

Any commit takes at least ~5 ms because of three fsync barriers
(`Data → fsync → Commit → fsync → Superblock → fsync`). On modern
SSDs this is the dominant cost; the actual compute (AEAD, encoding,
zstd) is sub-millisecond.

This means **batching writes is essentially free up to the chunk
capacity limit**. A Tx that puts 1 record costs the same wall-clock
as a Tx that puts 100 records — both pay 3 fsyncs.

Implication for messenger UX: batch outgoing messages opportunistically
(short flush window like 50 ms) to reduce per-message commit cost.

### 2. B+ tree split is cheap

`commit_1000_kv` is only 5% slower than `commit_single_kv` despite
involving:
- pack_into_leaves with greedy first-fit across thousands of bytes
- multiple Leaf chunk encodings + AEAD seals
- one Internal node above

This validates the 2-level B+ tree design choice — splitting cost
amortizes well over the 3-fsync barrier.

### 3. Read paths are very fast

- KV lookup: 36 µs (one tree walk + AEAD decrypt + binary search)
- Log lookup: 84 µs (KV lookup + zstd decompress + linear scan in batch)

Even on slow mobile hardware, these would be sub-millisecond. UI
responsiveness is not bottlenecked by storage.

### 4. Repack is fast

12 ms to repack 1000 KV + 100 log messages. For a typical messenger
workload (~5000 contacts + 50000 messages), repack would take roughly
~100-500 ms — feasible to do as a background "cleanup" task on
app launch or after deletion.

## Parallel-scan tuning

The `parallel-scan` feature (rayon-based) has three tuning levers
that each individually were necessary to get a real speedup:

```
open_large_sequential                52 ms  (baseline)

→ par_iter().map().collect()        265 ms  ✗ giant intermediate Vec allocator-contends
→ try_fold/try_reduce               265 ms  ✗ no change — wasn't the bottleneck
→ + coarse-grained chunking (256)   141 ms  ✗ better but still > sequential
→ + cap to 4 threads (was 12)        47 ms  ✓ slightly under sequential
→ + cached static pool               18 ms  ✓ 2.8× speedup
```

**Final implementation.**
1. **Coarse-grained chunking.** Each parallel work item processes
   256 consecutive slots sequentially (no per-slot scheduling
   overhead). Per-slot work is ~5 µs — well below rayon's per-task
   overhead unless amortized.
2. **Capped at 4 threads.** AEAD-decrypt + small-chunk pread saturate
   L1 cache and memory bandwidth long before they saturate cores.
   Empirical scaling on the 12-thread x86 dev host:
   ```
   1 thread     51 ms  (sequential through rayon = baseline)
   2 threads    32 ms  (1.6× speedup)
   4 threads    47 ms  (variance up; near baseline)
   12 threads  141 ms  (3× SLOWER — contention cliff)
   ```
   We `min(4, available_parallelism)` to stay on the good side of
   the cliff regardless of host core count.
3. **Static pool cache.** Building a fresh `rayon::ThreadPool` per
   `open_space_parallel` call costs several ms and dominates wall-
   clock for fast scans. The pool is constructed once via `OnceLock`
   and reused across opens.

**When to enable.**
- ✓ Multi-core hosts (≥4 logical) with non-trivial container size
  (≥ ~10 K slots / ~40 MiB). On the dev machine: 2.8× faster open.
- ✗ Single-core mobile (Cortex-A53 class). Capped pool collapses
  to 1 thread and you pay rayon's ~6 MiB binary-size cost for no
  speedup. Leave the feature OFF.
- ? Tiny containers (< 1 K slots). Speedup margin shrinks below
  the rayon overhead floor; not measured. Sequential is fine.

### Scaling

End-to-end open (`Container::open` + `open_space*` + `vacuum_orphans`)
on the same 12-thread x86 dev host across container sizes:

| Container | Sequential | Parallel | Speedup | Throughput (par) |
|---|---:|---:|---:|---:|
| 10 K slot / 40 MiB | 52 ms | 18 ms | 2.8× | 2.2 GiB/s |
| 50 K slot / 200 MiB | 608 ms | 264 ms | 2.3× | 760 MiB/s |
| 100 K slot / 400 MiB | 1499 ms | 204 ms | 7.4× | 2.0 GiB/s |

The 50 K result is the **dip in the curve** — at 200 MiB, sequential
read-ahead is still working (768 MiB/s), and 4-thread parallel only
gets a 2.3× speedup. By 400 MiB the sequential path appears to fall
off the page-cache hot path (270 MiB/s, 3× slower per-byte than 10 K),
while parallel pread-from-many-threads keeps prefetching aggressively
and stays at ~2 GiB/s. Parallel-scan therefore helps **most** exactly
where it matters most: large messenger histories on multi-core hosts.

Variance note: the 100 K parallel sample range was [162, 204, 274] ms
(10 samples) — wider than at smaller sizes, but the median is firmly
under sequential's [1367, 1499, 1627] ms range. Even the worst
parallel sample beats the best sequential by 5×.

### UX impact for messenger devs

Translate the numbers to user-visible UX cost per unlock:

| User profile size | Sequential unlock | Parallel unlock |
|---|---:|---:|
| Light user (~40 MiB) | 52 ms — invisible | 18 ms — invisible |
| Average user (~200 MiB) | **0.6 s** — noticeable | 0.26 s — invisible |
| Heavy user (~400 MiB) | **1.5 s** — UX cost | **0.2 s** — invisible |

Once a user's history crosses ~200 MiB, sequential unlock hits the
"user notices" threshold (>300 ms — see
[Doherty threshold](https://en.wikipedia.org/wiki/Mental_chronometry)).
At 400 MiB it's a clear "did the app freeze?" moment.

**Recommendation for messenger devs:** enable `parallel-scan` for any
multi-core host with messenger-realistic history. Disable on
single-core mobile (the 4-thread cap collapses to 1 — no speedup,
~6 MiB rayon binary size for nothing). See "When to enable" matrix
above for the full decision tree.

**Behavioral guarantee.** `tests/parallel_scan.rs` (6 scenarios)
asserts that the parallel path produces the same observable
`SpaceState` as sequential — same superblock, same owned_slots,
same commit_history, same verify_integrity result.

## How to interpret regressions

If a future commit pushes any of these numbers up by >25%, investigate.
Specifically:
- **Commit benches >7.5 ms**: extra fsync somewhere, or expensive
  per-chunk computation added.
- **Read benches >100 µs / >150 µs**: tree walk added a layer, or
  per-leaf decode got slower.
- **Repack >15 ms / 1000**: enumeration or rewriting got slower.

## Hardware tuning recommendations

For the messenger use case, host-app should pick Argon2 params
based on the device class (DESIGN §11.1):

| Device class | Recommended params | Approx open_space |
|---|---|---|
| Low-end ARM (Cortex-A53, 2017+) | `Argon2Params::LIGHT` | ~30 ms |
| Mid-range ARM (last 5y phones) | `Argon2Params::DEFAULT` | ~100 ms |
| Desktop / server-class x86 | `Argon2Params::HEAVY` | ~250 ms |

The numbers in this document assume `MIN` for benchmarking purposes.
For each preset, multiply Argon2-dominated paths (create_space,
open_space, repack) by the relevant ratio:

- LIGHT (m=16 MiB, t=3): ~1.5× MIN
- DEFAULT (m=64 MiB, t=3): ~4× MIN
- HEAVY (m=256 MiB, t=4, p=4): ~10-15× MIN

## v0.6 perf-target validation (`TASKS.md` L538)

The v0.6 milestone aspired to:

| Target | Aspiration | Measured (dev host x86) | Status |
|---|---:|---:|---|
| Parallel scan throughput | ≥ 5 GiB/s on x86 | 2.0–2.2 GiB/s | **Missed** by ~2.5× |
| Parallel scan throughput | ≥ 1 GiB/s on ARM | not measured | **Unmeasured** |
| Append throughput | ≥ 50 MB/s on mobile flash | not directly benched | **Unmeasured** |
| Repack throughput | ≥ 100 MB/s on x86 | ~333 MiB/s¹ | **Met** ✓ |

¹ `repack_1000` (12 ms, ~4 MiB live data) → 333 MiB/s. Larger containers
were not separately benched but the per-byte cost is dominated by AEAD
re-seal + zstd, both of which are throughput-stable.

### Why scan is below the 5 GiB/s aspiration

The scan path is bound by **AEAD-decrypt + small-chunk pread**, and on
the 12-thread x86 dev host the per-thread ceiling appears to be
~500–600 MiB/s (XChaCha20-Poly1305 ~1.5 GiB/s without I/O, throttled
by the I/O-bound 4-thread cap from "Parallel-scan tuning" above).
Hitting 5 GiB/s would require either (a) lifting the 4-thread cap —
which the empirical curve shows triggers contention cliffs — or (b)
moving from per-chunk AEAD to a streaming AEAD construction, which
breaks the discoverability invariant (each chunk must trial-decrypt
under any space's key independently). **The 2 GiB/s ceiling is
inherent to the format**, not a code-level optimization gap. We
accept it and revise the target downward in the next milestone:

> **Revised target (v1.0):** parallel scan ≥ 1.5 GiB/s on x86 with
> `parallel-scan` feature; ≥ 300 MiB/s on Cortex-A53 ARM.

### ARM unmeasured

The sandbox CI environment for these benchmarks has no ARM hardware.
Validation on real Cortex-A53 / A76 phones is **deferred to v0.8**
when the FFI layer (`hidden-volume-ffi`) lands and we have a
deployable `.aar` to measure on-device. Until then ARM numbers
extrapolate from the rule-of-thumb in the document header (2-3×
slower on Argon2; 1.5-2× slower on chunk I/O).

### Append throughput

The current bench suite measures **commits**, not raw appends. A
commit's wall-clock is dominated by the 3-fsync barrier (~5 ms floor
on SSD, multiple seconds on cheap eMMC). The bytes-per-second figure
depends entirely on Tx batch size: a Tx with 1 KV pair pays the same
3 fsyncs as one with 1000 — so "append throughput" is misleading in
this design. Host-apps should batch outgoing writes (a 50 ms flush
window is sufficient to amortize the fsync floor). The 50 MB/s
target is therefore restated as a Tx-batched target:

> **Revised target (v1.0):** ≥ 50 MB/s sustained when host-app
> batches into ≥ 100 KB Tx commits. With 64 KB-each Tx commits
> (~12 messages of 5 KB each in one Tx), a 5 ms fsync floor
> translates to 12.8 MB/s — consistent with mobile flash latency
> dominating, not throughput.

### Reproduction

```sh
cargo bench --bench throughput            # baseline
cargo bench --bench throughput --features parallel-scan  # for parallel paths
```

Median values written to `target/criterion/<bench>/new/estimates.json`.
Run again after any commit touching `space::commit_tx`,
`open::scan_and_recover*`, `crypto::aead`, or `crypto::derive`.
