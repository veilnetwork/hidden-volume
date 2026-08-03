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

## Write amplification of a one-key edit (audit HV-14)

Measured on macOS/APFS SSD (aarch64), `PaddingPolicy::None` so file
growth is exactly the chunks the commit wrote, `Argon2Params::MIN`,
one Superblock replica. "chunks" counts 4 KiB slots appended by a
single `put` + `commit`; the floor is 2 (the Commit chunk and its
Superblock replica).

`commit_tx` materialises a namespace's whole tree, applies the ops and
rebuilds. The rebuild used to reach the disk as well, so a one-key edit
re-appended the entire namespace. Because index chunks are immutable
and Merkle-addressed, the ones a rebuild reproduces byte-for-byte are
now pointed at instead of written again.

**One key overwritten in a KV namespace of N entries, 64-byte values:**

| N | before | after | wall before | wall after |
|---:|---:|---:|---:|---:|
| 10 | 3 chunks | 3 chunks | 21.0 ms | 12.2 ms |
| 100 | 5 | 4 | 17.4 ms | 11.8 ms |
| 500 | 13 | 4 | 17.1 ms | 11.2 ms |
| 1 000 | 23 | 4 | 17.3 ms | 12.1 ms |
| 2 000 | 43 | 4 | 16.8 ms | 12.3 ms |
| 4 000 | 82 (336 KiB) | 4 (16 KiB) | 22.6 ms | 12.9 ms |

**One 200-byte message appended to a log namespace holding N:**

| N | before | after |
|---:|---:|---:|
| 0 | 4 chunks | 4 chunks |
| 100 | 4 | 4 |
| 500 | 7 | 5 |
| 1 000 | 10 | 5 |
| 2 000 | 15.3 | 5 |
| 4 000 | 26 | 5 |
| 8 000 | 48 (196 KiB) | 5 (20 KiB) |

The cost is now flat in N. It cannot be worse than before: an edit
where every leaf genuinely differs writes every leaf, as it always did.

### Why the in-memory flatten-and-repack was kept

The audit filed this as "O(N) CPU, RAM and write amplification". Only
the last of the three is real here, and the measurements are the
reason:

- **CPU / latency is flat** — 11–22 ms from N = 10 to N = 8 000, both
  before and after. A commit is fsync-bound; the tree work does not
  show above the 3-fsync barrier.
- **RAM is bounded by the format, not by N.** The writer emits at most
  one internal root over its children, and an internal node caps at
  `(PAYLOAD_CAP - 4) / (2 + key_len + 8 + 32)` children — 79 with
  9-byte keys. The flattened working set therefore cannot exceed about
  `79 × PAYLOAD_CAP ≈ 320 KiB` before `Error::IndexFull` stops the
  commit outright. Measured ceilings: 64-byte values reach ≥ 4 000
  entries; 512-byte values fail between 500 and 1 000; 2 048-byte
  values fail between 10 and 100.

Replacing the repack with incremental descent plus split/merge would
buy nothing measurable against those numbers, and would cost the
greedy repack's self-compaction — the property that keeps repeated
delete/insert cycles from fragmenting a namespace into the `IndexFull`
ceiling.

### What was still open — and is closed below

The `IndexFull` ceiling above was a real capacity limit: a namespace
could not hold more than one root's worth of leaves. That is what the
next section removes.

### Reproducing these numbers

`crates/hidden-volume/tests/hv14_write_amplification.rs` asserts the
flatness (the same edit against namespaces of very different sizes must
cost the same number of chunks). The absolute numbers above came from
ad-hoc harnesses over the public API: seed N entries, record
`metadata(path).len()`, commit one `put`, record it again.

## The namespace capacity ceiling (audit HV-15)

Same rig as above: macOS/APFS SSD (aarch64), `PaddingPolicy::None`,
`Argon2Params::MIN`, one Superblock replica, 9-byte keys, release
build.

The writer used to emit exactly two levels — a row of Leaves and one
Internal node above them — so a namespace held no more entries than
fit under a single root. Binary-searching the largest N that commits:

| value size | last N that committed | first N that failed |
|---:|---:|---:|
| 64 B | 4 029 | 4 030 → `Error::IndexFull` |
| 512 B | 553 | 554 → `Error::IndexFull` |
| 2 048 B | **79** | 80 → `Error::IndexFull` |

Past those, the data could not be stored at all. Adding a third level
would only have moved the wall (79 → ~6 200 for 2 KiB values), so
instead the writer grows a level whenever the level below outgrows one
chunk. The same sizes now:

| value size | N stored, read back and `verify_integrity`-clean | levels | container | vs. before |
|---:|---:|---:|---:|---:|
| 64 B | 1 000 000 | 4 | 19 866 chunks (77.6 MiB) | 248× |
| 512 B | 250 000 | 4 | 36 885 chunks (144.1 MiB) | 452× |
| 2 048 B | 100 000 | 4 | 101 530 chunks (396.6 MiB) | 1 266× |

Those are not ceilings — nothing in the writer stops there. The only
remaining limit is the container's own `MAX_OPEN_SCAN_CHUNKS`
(16 M chunks / 64 GiB), which refuses with `Error::ContainerTooLarge`
rather than `IndexFull`.

### The readers' depth bound

Removing the writer's ceiling means the readers can no longer assume a
depth. Their cap is not a new constant but the inverse of the same
arithmetic: each level of a well-formed tree is at least
`MIN_FULL_INTERNAL_FANOUT` (12) times wider than the one above it, so a
tree of depth *d* costs at least this many chunks:

| depth | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---:|---:|---:|---:|---:|---:|---:|
| minimum chunks | 3 | 16 | 161 | 1 890 | 22 627 | 271 460 | 3 257 445 |

A walk may descend as deep as the chunks the space owns could be
arranged into — no deeper. Honest data is never refused (its chunks are
on the disk by definition), and at the largest container the format
permits the bound is 7, so a hostile chain costs 7 chunk reads and 8
stack frames instead of the 16 M the budget alone would have allowed.

### Write amplification at depth (HV-14 still holds)

A one-key overwrite appends the Commit chunk, one Superblock replica,
and exactly one index node per level — the path, not the namespace:

| N | value size | levels | chunks appended |
|---:|---:|---:|---:|
| 1 000 | 64 B | 2 | 4 |
| 4 000 | 64 B | 2 | 4 |
| 100 000 | 64 B | 3 | 5 |
| 79 | 2 048 B | 2 | 4 |
| 20 000 | 2 048 B | 4 | 6 |

This needs the HV-14 reuse map to cover *every* level of the previous
tree, not just the row under the root; it does, because it is now
collected during the flatten walk the commit already performs (so it
also costs one chunk read less than the HV-14 version did).

### What HV-15 left open: per-commit cost was O(namespace)

`commit_tx` materialised the whole namespace, applied the ops and
rebuilt. HV-14 measured that and kept it, on the grounds that the
format's own ceiling capped the working set at ~320 KiB. **That
argument went with the ceiling** — the disk cost of an edit stayed flat
(the table above), but its CPU and RAM scaled with the namespace. Audit
HV-16 below closes it.

### Reproducing these numbers

`crates/hidden-volume/tests/hv15_unbounded_depth.rs` pins the
properties: the exact N that used to fail now commits, a four-level
tree is built and read back, deleting collapses the levels again, and a
one-key edit costs `2 + levels` chunks at any depth. The absolute
numbers above came from an ad-hoc harness over the public API — binary
search on N for the ceilings, `metadata(path).len()` for the chunk
counts, `/usr/bin/time -l` for peak RSS.

## A commit costs the change, not the namespace (audit HV-16)

Same rig throughout: macOS/APFS SSD (aarch64), release build,
`PaddingPolicy::None`, `Argon2Params::MIN`, one Superblock replica,
9-byte keys. "Before" is commit `41fe226` (HV-15), "after" is HV-16.

### Seeding

Writing the same data in more transactions used to cost more, because
each commit re-flattened everything it already held.

| workload | wall before | wall after | RSS before | RSS after |
|---|---:|---:|---:|---:|
| 10⁶ × 64 B, **1 Tx** | 0.64 s | 0.91 s | 395 MiB | 316 MiB |
| 10⁶ × 64 B, **500 Txs** | **96.2 s** | **7.0 s** | **2.60 GiB** | **12.7 MiB** |
| 10⁵ × 64 B, 1 Tx | 0.14 s | 0.14 s | 50 MiB | 42 MiB |
| 10⁵ × 64 B, 50 Txs | 1.49 s | 0.69 s | 79 MiB | 12 MiB |
| 10⁵ × 2 KiB, 1 Tx | 2.26 s | 2.31 s | 648 MiB | 423 MiB |
| 10⁵ × 2 KiB, 50 Txs | **31.9 s** | **2.8 s** | 557 MiB | 21 MiB |

13.8× the wall time and 210× the memory on the headline row. The
one-Tx row is the one that got *slower* — 0.64 s → 0.91 s — and that is
the price of the change: every key is now BLAKE3-hashed to decide
whether it ends a node, and there are ~16 % more nodes to encrypt.

### One key edited

| N | value | wall before | wall after | chunks before | chunks after |
|---:|---:|---:|---:|---:|---:|
| 1 000 | 64 B | 10.7 ms | 10.5 ms | 4 | 4 |
| 10 000 | 64 B | 13.3 ms | 11.0 ms | 5 | 5 |
| 100 000 | 64 B | 46.8 ms | 10.1 ms | 5 | 5 |
| 1 000 000 | 64 B | **361.6 ms** | **11.2 ms** | 6 | 6 |
| 1 000 | 2 KiB | 22.5 ms | 11.5 ms | 5 | 5 |
| 20 000 | 2 KiB | **242.2 ms** | **11.6 ms** | 6 | 6 |

Wall time is now flat at the 3-fsync floor (~11 ms) instead of rising
with N. **The chunk counts are unchanged** — that matters beyond
performance: the number of chunks a commit appends is what a
multi-snapshot observer can count, and HV-14 deliberately made it track
how localised a change was rather than how big the namespace is. It
still does, at exactly the same values.

Appending one message to a log namespace holding N behaves the same:
12.7 / 14.0 / 45.5 ms before at N = 2 000 / 20 000 / 200 000, against
12.0 / 11.4 / 10.5 ms after, with peak RSS at the largest dropping from
566 MiB to 12.4 MiB.

### Why greedy packing could not have been made incremental

The obvious cheap fix — keep the greedy left-to-right packing and
descend to the affected leaf — does not work, and the amount by which
it does not work is measurable. Chunk reads for one `put` into the
middle of a namespace of N (`space::tree`'s own test counts them):

| N | greedy packing | content-defined boundaries |
|---:|---:|---:|
| 2 000 | 23 | 4 |
| 20 000 | 202 | 4 |
| 100 000 | 996 | 4 |

Greedy boundaries are a function of *fill*, so an edit that changes any
entry's size shifts every boundary to its right and the rewrite never
re-synchronises with the old tree; it runs to the end of the namespace.
(It is worse than it looks: a greedy packer cannot even seal a node
without seeing the next item, so it never resynchronises at all.)
Boundaries chosen from each key's own hash re-synchronise within a node
or two, which is what makes the descent worth doing.

### What it costs: fill

Nodes are no longer packed to the brim. The sealed-fill distribution is
`P(fill > f) = ((PAYLOAD_CAP - f)/PAYLOAD_CAP)^(1/K)`, so mean
utilisation is `K/(K+1)` — 6/7 ≈ 86 % at the chosen `K = 6`, against
~98 % greedy. Measured on the whole container:

| workload | chunks before | chunks after | growth |
|---|---:|---:|---:|
| 10⁵ × 64 B | 1 991 | 2 292 | +15.1 % |
| 10⁶ × 64 B | 19 866 (77.6 MiB) | 23 144 (90.4 MiB) | +16.5 % |
| 2·10⁴ × 2 KiB | 20 307 | 20 351 | +0.2 % |
| 10⁵ × 2 KiB | 101 288 | 101 487 | +0.2 % |

Large values are unaffected because only one 2 KiB entry fits in a
chunk either way. The ~16 % on small values is the standing price of a
shape that does not record its own history; `K` is the single knob if a
future workload wants to trade it back.

### The readers' depth bound, recomputed

The bound is derived from the narrowest a level of a well-formed tree
can be, so changing how nodes are sealed changes it. Greedy packing
guaranteed 12 children per non-final internal node (one more would not
have fit). Content-defined boundaries guarantee nothing on their own —
that is the point — so the writer refuses to honour a boundary before
`MIN_INTERNAL_CHILDREN` = 4 children, and 4 is what the arithmetic now
uses:

| depth | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| minimum chunks | 3 | 8 | 25 | 90 | 347 | 1 372 | 5 469 | 21 854 | 87 391 | 349 536 | 1 398 113 | 5 592 418 |

At the largest container the format permits the bound is 12 descents,
against 7 before. Honest data is still never refused — a tree of depth
*d* owns at least that many chunks by construction — and a hostile
chain still costs its own chunks. Actual fanout is far above the floor
(~40–70 children per internal node at 9-byte keys), so honest trees are
the same height they were: 3 levels at 10⁵ entries, 4 at 10⁶.

### What is still open

A commit costs the *span* of keys it touches, not the number of keys.
Operations scattered from one end of a namespace to the other still
walk everything between them — the same O(namespace) the previous
implementation always paid, so nothing regresses, but nothing improves
either. Batching by key locality (which a monotonic `log_id` writer
gets for free) is what keeps a commit cheap.

### Reproducing these numbers

`crates/hidden-volume/src/space/tree.rs` holds the two property tests —
one shape per key set whatever order it was written in, and chunk reads
per edit that do not grow with N. `crates/hidden-volume/tests/
hv16_incremental_commit.rs` holds the host-app-visible half. The
absolute numbers came from an ad-hoc harness over the public API:
`metadata(path).len()` for chunk counts, `std::time::Instant` for wall,
`/usr/bin/time -l` for peak RSS.
