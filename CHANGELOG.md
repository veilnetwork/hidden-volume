# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [SemVer](https://semver.org/). **From v1.0 onward
the on-disk format and the public Rust + FFI API are frozen**: any
subsequent breaking change requires a v2.0 major bump and a proper
migration tool (see [`docs/en/guide/migration.md`](docs/en/guide/migration.md)).
v0.x line was pre-release; v0.x → v0.y bumps were free to break the
format.

## [Unreleased]

### Fixed — report10 HV-04: a commit could be masked worse than promised and nobody downstream was told

The three post-commit hardening steps — padding, decoy churn, fsync — run
after the superblock is durable, and they are deliberately not allowed to
downgrade a commit that has already happened. Their failure was recorded on
`SpaceState::last_hardening_error` instead, which is the right answer. Two
things then threw that record away.

- **A successful commit erased it.** The field held the LAST commit's outcome
  and was replaced unconditionally, with a comment saying so. A host learns
  about this by polling `stats`, and one more commit between two polls is not
  an edge case — it is what a messenger does per message. So the ordinary
  sequence "the padding that should have hidden this write's size failed; the
  next write went fine" left nothing to poll for. The commit is durable either
  way; what was gone was the only signal that its masking is not what the
  format promises.

  It is **sticky** now. The first unacknowledged failure stays readable until
  the host says otherwise: no commit, successful or not, replaces it. A later
  failure does not displace it either, which extends the rule `commit_tx`
  already applies inside one commit — the first step to fail is the one
  reported — to keep the news the host is least likely to have seen.

- **It never crossed the FFI at all.** `StatsInfo` had no field for it, so
  Kotlin / Swift / Dart got a successful commit and no way to warn the person.
  It crosses now as `Option<HardeningFailureInfo>`, carrying WHICH step failed
  (`Padding` / `Churn` / `Sync`) — a size leak, a broken deniability and a
  missing fsync are three different pieces of news, and flattening them to a
  bool here would have re-created report9 HV-06 one layer out.

- **`Space::acknowledge_hardening_error()`**, exported on both handles, is the
  only thing that clears it. Sticky with no way to dismiss is a warning that is
  always on screen, which teaches whoever reads it to stop reading it.

- **`reusable_slot_count` crosses too**, in the same record. It was the half of
  the compaction decision the host did not have: `utilization_ratio` alone
  reads a healthily recycling container as sparse, so a host acting on it
  compacts destructively when it need not — rewriting the whole file and
  rotating the `container_id` — and cannot tell that case from the one that
  genuinely needs it.

- **The checksum table did not and could not catch this.** uniffi checksums a
  method's SIGNATURE, and `stats` still returns a thing called `StatsInfo`, so
  adding two fields to the record moved no existing checksum — the new
  acknowledge method is the only new entry. The hand-written Dart decoder would
  have read the wrong offsets with `checksum_test.dart` green throughout. Its
  wire layout is now pinned byte for byte in `test/stats_hardening_test.dart`,
  against buffers the test writes itself.

### Fixed — report9 HV-01 / HV-02: the copies the first pass did not reach

The HV-16 entry below wiped the two buffers on the argument path of a single
`Vec<u8>`. It stopped there. Everything else this plugin copies a secret into
was still released as it was — and the inbound direction had never been looked
at at all.

- **Outbound: every password at once.** `_writeRotations` encodes the whole
  rotation — every OLD and every NEW password, concatenated — into one blob,
  and `_writeBytesSequence` does the same for `compact_known`. Both went out
  through `_bufferFromBytes`, which wipes its own `calloc` buffer and leaves
  the Dart-side blob to the collector. The densest secret the plugin ever
  builds was the one copy nobody wiped. The wipe tail is now one owning helper,
  `_bufferFromOwnedSecret`, and `_bufferFromByteVec` shares it.

- **`owned` is the whole contract of that helper**, and it rests on a fact
  nothing else in the file states: `_Writer` builds on `BytesBuilder(copy:
  false)`, where `takeBytes()` returns a single-chunk payload BY REFERENCE.
  Under `takeBytes` the "owned" buffer would be the host app's live password
  and the helper would wipe it. `toBytes()` always copies. A test pins that
  one word; nothing else can, because every writer in this file happens to be
  multi-chunk today, so the swap is invisible at runtime until the day it
  isn't.

- **Inbound: nothing was wiped at all.** `_bufferToBytes` copied a Rust-owned
  buffer out and handed it straight back to the Rust allocator — KV values,
  log payloads, and the raw `SpaceKeys` alike. `spaceKeys()` then decoded 64
  key bytes out of a framed temporary and dropped the frame on the floor. Both
  are wiped now, through `_secretByteVecFrom` at the two export sites.

- **Async: three private clones, none of them the caller's.** `Isolate.spawn`
  and `Isolate.run` deep-copy their message, so the worker's bootstrap
  password and the one-shot isolates' rotation lists are the isolate's OWN
  buffers. The worker's clone lived as long as the isolate, which for an open
  space is the whole session. They are wiped in a `finally` — including the
  failed-open path, which is exactly when a password is about to be typed
  again. The synchronous `changePasswords` / `compactKnown` deliberately do
  NOT mirror this: there the list belongs to the caller, and `oldPwd ==
  newPwd` is a documented no-op that legitimately passes one instance twice.

- **The source checks cannot tell our copy from the caller's** — both are a
  `fillRange` — so the tests assert the inverse and cannot pass vacuously:
  after `changePasswordsAsync` the caller's passwords must be byte-identical,
  and `spaceKeys()` must still open the space through `openWithKeys`. A
  break-check that moved either wipe to the caller's isolate returns the
  password as ten zeros; one that moved a wipe above its copy returns 64
  zeros of the right length, which a "the buffer reads as zero" test would
  have called a pass.

- **Deferred, deliberately.** Rust still hands back a 64-byte `Vec<u8>` from
  `space_keys` (`crates/hidden-volume-ffi/src/lib.rs`, the sync, async and
  multi-space exports) that uniffi's `Lower` takes by move. A `Zeroizing`
  wrapper there would add a THIRD copy and scrub the wrong one. Recorded here
  rather than papered over.

### Breaking — a space now keeps a bounded window of commit anchors

- **The growth this removes.** Every commit left two chunks nothing later
  reaches: the Superblock of that era and the Commit chunk it points at. Old
  IndexNodes were already collected — the orphan vacuum walks from the CURRENT
  root — but those two were kept forever, one as a decode fallback (audit D2)
  and one as what that fallback points at. Measured: a container rewriting a
  single eight-byte value grew ~17 KB per commit with no plateau, 21 MB for one
  key after 1200 rewrites and rising. That is the shape of the reference case
  this project already carried in its own comments, 7.0 GB of file against
  4.8 MB of content.

- **`ANCHOR_HORIZON = 1024`.** `vacuum_orphans` now retires the pair for every
  era below `current_seq - ANCHOR_HORIZON`, so the steady cost is
  `2 * ANCHOR_HORIZON * CHUNK_SIZE` — 8 MiB — instead of growing with the
  number of commits a container has ever taken. Measured on the same fixture:
  the owned set plateaus and per-commit growth falls from ~17 KB to ~0.5 KB.
  The superblock and its Commit chunk travel as a PAIR: a fallback superblock
  whose Commit chunk is gone is worse than no fallback at all.

- **The decode fallback is unchanged.** An open picks the highest-seq
  superblock that decodes and falls back down a list the scan caps at
  `MAX_SB_CANDIDATES = 64`. Any horizon at or above 64 leaves that depth
  exactly as it was; 1024 is chosen for the anchors, not for the fallback.

- **BREAKING for host apps: the rollback procedure gains a third answer.**
  `docs/{en,ru}/guide/multi-device.md` used to say that an anchor absent from
  `commit_history()` means **fork — treat as adversarial**. With a bounded
  window that is wrong for any device that has been offline longer than the
  horizon. The range test now comes FIRST: an anchor further back than
  `ANCHOR_HORIZON` is **out of range** — its absence says nothing either way,
  and the host must re-anchor rather than accuse. A host that keeps the old
  order will read every long-offline device as an attacker.

- **The in-memory anchor list is pruned with the retirement**, so a session
  does not keep answering `commit_history()` with eras it has just scrubbed
  while the next open answers differently.

- **Tested by the plateau, across two consecutive session boundaries**, plus a
  data-survival pass (every key readable, `verify_integrity` clean, after the
  retirement and again after a reopen) and both edges of the window. A
  break-check that disabled the retirement first PASSED the anchor test,
  because it read the list from the session that had just pruned it in memory;
  the test reads read-only now, which is what the disk actually holds.

### Fixed — report9 HV-13: opening a large container cost 440 MiB

- **Measured, not estimated.** The audit put the open scan's peak at "256+ MiB
  at the 64 GiB cap" from an assumed per-slot cost. `tests/open_peak_memory.rs`
  measured it at **27.5 bytes of peak heap per owned slot** — 440 MiB at the
  cap, worse than the estimate. A device that could hold a 64 GiB container
  could not open one. It is **0.16 bytes per owned slot** now, ≈2.5 MiB at the
  cap.

- **`owned_slots` is a bitmap** (`space::slots::OwnedSet`), one bit per slot in
  the file rather than eight bytes per owned chunk, and retained for the life
  of the handle either way. It is smaller than the vector at any density above
  one owned slot in sixty-four; an open that found almost nothing owned had
  almost nothing to hold either. Deliberately NOT vacuum's `SlotSet`, which
  refuses a slot beyond the file it was sized to: `place_chunk` writes to this
  one as the file grows, and refusing there would forget a live chunk — the
  failure mode that ends in a vacuum scrubbing data. Vacuum walks it one
  bitmap word at a time, so the whole-list copy audit HV-03 removed does not
  come back.

- **Commit anchors collapse before the list doubles.** The list takes a push
  per owned Superblock CHUNK and a commit publishes several replicas, so it
  inflated several-fold over the distinct anchors it ends up holding: 4096
  entries of capacity for 801 anchors on a fixture.

- **The backward superblock hunt was the actual peak.** It kept every
  distinct-seq candidate in its window — up to `REVERSE_SCAN_BUDGET` payloads
  — while the three other candidate loops route through the capped helper.
  This is the gap its own neighbouring comment warns about ("that duplication
  is what let the audit's candidate cap ship in one backend only"), with a
  fourth loop nobody counted. It runs on EVERY open, before the fast path
  decides it cannot proceed, so every open paid it.

- **The measurement now proves it can see.** An upper bound is satisfied by a
  measurement that sees nothing, and an earlier version of this test reported
  "0.0 bytes per slot" because Argon2's working buffer dominated it. The test
  runs a second pass that deliberately holds eight bytes per owned slot — the
  representation this removes — and requires the harness to report it.

- **A gap closed on the way.** Replacing the anchor collapse with one that
  DROPS anchors passed the entire workspace suite: every other fixture is too
  small to reach the threshold. `tests/commit_history_reach.rs` now crosses it
  and requires every commit on disk to leave an anchor — the host-app's
  rollback evidence (DESIGN §11.2).

### Fixed — report9 HV-14: a checkpoint refresh recorded an empty decoy pool over the accumulated one

- **The pool exists in one place only.** Nothing on disk but the checkpoint
  chain says which retired slots may be rewritten. A session that never read
  the chain therefore holds no pool — and used to record that emptiness as
  truth on its next self-heal. The loss is permanent, not per-session: every
  later open starts append-only and there is nothing left to rebuild from.

- **The session that does this is the constant-time open.** It takes the full
  scan BY DESIGN — a fast path's chunk count is exactly the signal that
  distinguishes a right password from a wrong one — so the mode chosen for its
  resistance to timing was the one that wiped the pool. Measured on a fixture:
  39 recorded slots became 1.

- **The fix carries the previous record forward.** `write_self_heal_checkpoint`
  now reads the chain it is about to supersede BEFORE scrubbing it, and merges
  that pool with the live one whenever this session never loaded a record.
  Merged rather than substituted: a pool-less session still frees slots of its
  own (every commit's garbage padding lands there), and those are as real as
  the carried ones. Both halves are filtered against this era's owned set and
  high-water, so the record stays true on its own terms rather than only after
  a reader repairs it.

- **The condition is "never loaded a record", not "the pool is empty".** New
  `SpaceState::pool_recovered`, set by the scan that actually read the chain.
  Emptiness is indistinguishable one instruction after the open and wrong one
  commit later: with it, a session's handful of padding slots is recorded over
  the accumulated forty. A break-check confirms — the narrower condition passes
  a fixture that refreshes immediately and fails one that commits first.

- **Tested by identity, not by count.** The first version of the container-level
  test asserted the recorded pool had not shrunk, and a break-check that removed
  the carry-forward passed it: the session's own padding refilled the count with
  forty different slots. The test now names the slots the previous record
  offered and requires each to be in the new record still.

### Fixed — report9 HV-16: the transport's own copies of a secret

- **The Rust half was already done** (audit H-03): `decode_space_keys` takes
  the buffer by value and wraps it in `Zeroizing`, and the neighbouring entry
  points treat incoming passwords the same way. None of that reaches the copies
  the DART side makes on the way in.

- **Two copies, both released as they were.** `_bufferFromBytes` fills a
  `calloc` buffer with the secret, hands it to `_rustbufferFromBytes` and frees
  it — returning the bytes to the C allocator intact. `_bufferFromByteVec`
  builds a length-prefixed copy first and hands that to the garbage collector.
  Both are wiped now; Rust has copied by the time either returns, so wiping is
  safe.

- The guard is a source check for the reason the memory audit gives for its
  own: proving a released buffer was scrubbed means reading it after release.
  Its ORDER assertion is the one worth having — a wipe that drifts below the
  `free` is not a weaker fix but a write into memory the allocator has taken
  back, and moving it there turns the test red.

### Fixed — report9 HV-15: the key survived its own erasure

- **Argon2's working memory was freed as-is.** m_cost KiB — 64 MiB at the
  default parameters — holding the password's expansion. The `argon2` crate
  has a `zeroize` feature for exactly this and it was not enabled.

- **Every keyed BLAKE3 hash here IS a key, and none was wiped.**
  `derive_master_key`, `derive_subkey` and `derive_chunk_key` each build a
  `Zeroizing<[u8; 32]>` by copying OUT of a `blake3::Hash`, and that source
  copy was dropped untouched; `derive_subkey`'s keyed `Hasher` holds
  key-equivalent state for the same reason. `derive_chunk_key` runs once per
  chunk read or written, so this was the highest-traffic key site in the crate.
  The `blake3` crate's `zeroize` feature is enabled now and each transient is
  wiped explicitly.

- `docs/{en,ru}/security/audits/memory.md` said "key material — zeroized ✓"
  and meant it about the RETURNED value. The buffer the key was derived in and
  the hash it was copied out of were not in the table at all. Both are now,
  in both languages, with what was actually true before.

- The guard is a source and manifest check, and says why: proving a freed
  buffer was scrubbed means reading memory after it is released, which is
  undefined behaviour rather than a test. What can rot is the wiring — a
  feature dropped in a dependency bump, a `.zeroize()` lost in a refactor.
  Break-checked both ways. Its first version counted its own assertions
  (`include_str!` reads the file the test lives in) and read 4 where it wanted
  2; it now cuts the source at its own module.

### Fixed — report9 HV-12: a fast open could not be interrupted while it ran

- **Neither fast-open phase polled the cancel token.** `try_fast_scan_inner`
  takes one and passed it to neither the reverse superblock scan nor the
  checkpoint-chain walk, so a caller who cancelled waited out up to
  `REVERSE_SCAN_BUDGET` reads plus a `MAX_CHECKPOINT_CHAIN` walk — each a read
  and a trial-decrypt — before the selective scan's own poll surfaced it. The
  full scan's documentation promises a check every `CANCEL_POLL_PERIOD` slots;
  the fast path quietly did not keep it.

  The reverse scan now polls at the same cadence. The chain walk polls every
  hop rather than every 64: a hop is far more expensive than a slot read and
  the chain is short, so the check costs nothing.

- The guard is a SOURCE check and says why. Cancelling produced the same
  outcome either way — only the wait changed — and on the machine that runs
  this suite that wait is milliseconds, so a timing assertion would measure
  nothing and be flaky when it did. What can rot is the wiring: a phase that
  stops taking the token, or takes it and never looks.

### Measured — report9 HV-13: what the open-scan cap costs in memory

- **27.5 bytes of peak heap per owned slot**, so ≈ 440 MiB at
  `MAX_OPEN_SCAN_CHUNKS`. The audit estimated "256+ MiB" from an assumed
  per-slot cost; measured, it is worse than that, and well above the 8 bytes
  per owned chunk the streaming-scan note says is retained. The extra is
  transient — the parallel reduce holds a second copy of an `owned_slots` half
  while it merges, and `commit_history` adds 8 per commit.

  Read with its fixture: that measurement commits once per iteration, close to
  a worst case for slots-per-commit. A container that reached the cap by
  holding DATA rather than history has more slots per commit and a lower
  figure. What it establishes is the order — tens of bytes per slot, hundreds
  of megabytes at the cap — so a device that can hold a 64 GiB container
  cannot necessarily open one. Recorded on the constant.

- `tests/open_peak_memory.rs` keeps it honest, with an upper bound of 128
  bytes per slot (an order below retaining one payload per chunk) and a
  non-vacuity floor of 4. The floor is the part worth having: measured through
  `open_space`, Argon2's eight-mebibyte buffer dominates both fixtures and the
  slope comes out at 0.0 bytes per slot — a green proving only that the KDF is
  bigger than the thing under test. The first version of this test did exactly
  that. Keys are now derived outside the measured region, and the floor fails
  if anything masks the per-slot term again.

- Not changed: lowering it means replacing `SpaceState::owned_slots`
  (`Vec<u64>`) with the bitmap the crate already has for the vacuum
  (`SlotSet`, one bit per slot). That touches commit, vacuum and reuse
  together, and it is its own pass rather than a rider on a measurement.

### Fixed — report9 HV-09 / HV-10: the destructive flows now refuse an era they cannot read

A superblock NEWER than the one an open settled on can decrypt under our key
and still fail to parse — a writer we do not understand published after us. The
rule is old and the refusals were only in some of the places that need them.

- **`vacuum_data_batches` had the read-only and publish-uncertain refusals and
  not this one** (HV-09). It scrubs every owned DataBatch chunk that is not
  referenced from OUR namespaces, and the batches the newer era's entries point
  at are precisely the ones our tree does not reference. `vacuum_orphans` has
  refused this state since the 1.1.0 incident; the batch pass, which is the
  destructive half for log data, did not.

- **Repack — and therefore compaction and password rotation — did not refuse
  at all** (HV-10). Repack copies what THIS build can read into a fresh
  container and the in-place flows rename that over the source. With a newer
  writer having published, the projection is missing everything they wrote, and
  the rename makes that permanent. Vacuum refusing while the whole-file rewrite
  proceeded was the gap: the rewrite is the same act with no undo.

  `Space::unreadable_newer_state()` is `pub(crate)` for this: the container
  flows live in another module and could not see the state they had to check.

- Both are covered, and the container case needed a test seam. The state cannot
  be staged honestly — it takes a superblock that AEAD-passes and then fails to
  parse, which means writing a future format this build does not know how to
  write. Setting the field on an open handle (what the vacuum tests do) reaches
  nothing that opens the space ITSELF, which is where these flows live. So
  `ForcedUnreadableNewerState` arms the single place the rule is decided
  (`newer_unreadable_sb`), following the `ForcedRngFailure` idiom: thread-local,
  disarmed on drop. The refusal test also asserts the source is left
  byte-identical, and a second test asserts compaction still runs — and still
  carries entries over — without the state.

### Fixed — report9 HV-07: the reentrancy warning pointed at an exit that was not there, and named the wrong lock

- **`AsyncSpace::run`'s deadlock warning told the reader to "use the typed
  `&self` methods (`space.get(...)`, `space.put(...)`, `space.commit(...)`)
  which serialize on their own outside the closure".** `AsyncSpace` has no such
  methods — `create`, `open`, `run`, the abandonment accessors and the log-page
  streams are the whole surface. The one escape route the warning offered did
  not exist, so a reader who took it seriously went looking, found nothing, and
  came back with the warning's weight spent. (The uniffi `Space` object does
  have `get` / `commit`; a different type in a different crate is the likely
  source of the mix-up.) It now says the true fix: do the whole job in one
  closure — `f` already holds `&mut Space`.

- **The same block claimed the mutex is what serializes concurrent calls, and
  it is not.** `OpLedger::default()` is a ONE-permit semaphore acquired before
  `spawn_blocking`, shared across clones; the non-reentrant mutex inside the
  closure is a second layer that in practice is never contended. This matters
  to a reader, not only to a pedant: a nested call hangs on the permit and
  never reaches the mutex, so the mechanism the warning describes is not the
  one that traps them.

- **The recorded reason for rejecting a `try_lock` guard was never measured,
  and does not hold.** Audit pass 19 round 6 wrote that `try_lock` "would
  regress `concurrent_runs_serialize_via_mutex` — 10 concurrent legit `run`
  calls would fail-fast instead of serializing". Measured now: with the mutex
  swapped for a fail-fast `try_lock`, every test in `async_basic.rs` still
  passes, because those ten calls never contend for the mutex. The decision
  stands on a reason that survives — `try_lock` would not detect reentrancy
  either, since the nested call hangs one layer earlier — and the false
  reasoning is corrected in place rather than dropped.

- **`concurrent_runs_serialize_via_mutex` did not check what its name said.**
  It counted that ten calls returned and ten keys landed, both of which a
  fully parallel implementation also satisfies. Renamed
  `concurrent_container_runs_never_overlap` and given the measurement:
  peak concurrency observed inside the closure, asserted to be one. Its new
  `AsyncSpace` twin `concurrent_space_runs_never_overlap` does the same for
  the handle whose warning is the loud one, and
  `the_overlap_detector_sees_overlap_when_it_is_there` is the positive control
  — two unsynchronized blocking tasks that must register as concurrent, so a
  green peak reading means "serialized" and not "the instrument is blind".

### Fixed — report9 HV-08: the format reference described a checkpoint nobody writes

- **`docs/{en,ru}/reference/format.md` carried the pre-pool 28-byte checkpoint
  header**, with one `count` and one `owned[]` list, long after `pool_count`
  and the pool list arrived with slot reuse. The real header is 32 bytes and
  the chunk carries two lists sharing one budget. Nothing was wrong with the
  code; the format reference is the contract an independent implementation is
  written against, and one written from it mis-parsed every checkpoint this
  writer produces.

  Also documented there now: the pool-drift refresh trigger (the tail alone
  cannot carry the pool — the better reuse works, the less the tail grows),
  and that a Checkpoint chunk never comes from the pool.

- **The threat model still opened with "append-only"**, in both languages,
  which DESIGN §9.1 lifted. Restated as `Inv-W1` says it: the writer touches
  only a slot unreachable from any superblock a reopen could select — not
  only the end of the file. The same wording in the superblock-recovery
  section is gone with it; last-wins within a seq holds on slot order, not on
  slots being append-only.

- `format_doc_agreement_tests` reads both references and fails if either
  stops describing the header that is written. A comment beside the constant
  is exactly what was already there while the reference said something else.


### Measured — report9 HV-05: what a pool draw costs, and why the scan stays

- `DecoyPool::select` is a linear scan from word zero, so a draw costs
  O(capacity in words) — set by how WIDE the file is, not by how much is in
  the pool. Measured, release build:

  | slots (file size) | per draw | 64 draws |
  |---|---|---|
  | 100 K (≈400 MiB) | 2.6 µs | 0.17 ms |
  | 1 M (≈4 GiB) | 6.8 µs | 0.43 ms |
  | 16 M (64 GiB, `MAX_OPEN_SCAN_CHUNKS`) | 84 µs | 5.4 ms |

  Sixty-four draws is a commit reusing thirty-two slots and churning
  thirty-two. The worst case the format can be pushed to therefore costs a
  commit about five milliseconds, on a container at the hard cap.

  A hierarchical popcount index would cut that by roughly sixty, and would
  put a second, derived copy of the membership beside the bitmap. This is the
  structure where a wrong answer means the allocator hands out a LIVE slot —
  silent data loss on the next commit. Five milliseconds on a 64 GiB
  container does not buy that trade. The measurement is kept runnable as an
  `#[ignore]`d `measure_select_cost` rather than only written down; timings
  make bad gates, so it is not one.


### Fixed — report9 HV-04: a failed draw no longer costs the pool its decoys

- **`DecoyPool::sample_distinct` restores what it drew on the error path too.**
  It clears each drawn bit as its sampling device and puts every one back at
  the end, because churn retires nothing — but a `?` on the CSPRNG returned
  between those halves, so the slots drawn before the failure stayed cleared.
  Gone from `len`, never allocated, never churned again: decoys that stop
  existing because a draw failed. The pool is also what the reuse budget is
  sized from. Covered by `a_failed_draw_leaves_the_pool_whole`, which reaches
  the path through a new thread-local CSPRNG fault (`ForcedRngFailure`) —
  eight slots in, one drawn, and the broken version comes back with seven.

### Changed — report9 HV-06: the hardening record names the step that failed

- **`SpaceState::last_padding_error` is now `last_hardening_error:
  Option<HardeningFailure>`**, carrying a `HardeningStep` of `Padding`,
  `Churn` or `Sync`. `Space::last_padding_error()` becomes
  `Space::last_hardening_error()`.

  All three steps reported through one field named for the first of them, so
  a host was told "padding" whichever broke. They are not the same news:
  padding failing means the commit's SIZE is readable by a multi-snapshot
  adversary; churn failing means the slots it reused stand alone in a
  snapshot diff with no decoy moved beside them, which is the oracle DESIGN
  §9.1 exists to deny; the fsync failing means neither is on the platter yet.
  One of those is a warning and one is worth stopping for.

  `a_churn_failure_is_not_filed_as_a_padding_failure` provokes a churn
  failure while padding succeeds beside it (new thread-local
  `ForcedChurnFailure` — the CSPRNG hook cannot reach churn by count, because
  every chunk the commit sealed drew a nonce first).


### Fixed — report9 #1: reuse is budgeted so the churn can always be funded

- **A write episode reuses at most the share of the pool whose churn the
  rest can fund**, `pool - pool / (1 + CHURN_PER_REUSE)` (`reuse_floor_for`),
  declared per episode in `SpaceState::reuse_floor`. Reuse and churn draw
  from the same pool and reuse goes first: `take` removes, then
  `sample_distinct` samples what is left — and it returns `n.min(len)`, so
  it truncates in silence. A commit that reused the pool down to nothing
  churned nothing, returned `Ok`, and `churn_count` simply stopped tracking
  `reuse_count`. A small pool is not exotic; it is what a container has
  right after its first `vacuum_orphans`.

- **The budget is checked where a slot leaves the pool, not in
  `reuse_permitted`.** That predicate answers a question about the ERA, which
  is why `publish_superblock` reads it once before it burns the seq and hands
  one answer to every replica. The budget is a resource the placements spend
  as they go, and the same snapshot spent it once too often — measured at
  five reuses against four churns on a pool of nine. `reuse_budget_available`
  is therefore separate and lives in `place_chunk_with`.

- **`write_self_heal_checkpoint` declares its own budget: none.** `commit_tx`
  is the only caller of `churn_decoys`, so the pool slots that path took for
  its Superblock replicas were reuse no churn ever covered — three of them in
  one round of the new guard. It now leaves the pool alone and pays an append
  per replica. Not in report9; found while fixing #1.

- New `every_write_path_churns_what_it_reuses` guards the invariant behind
  all three — and behind report9 #2 — structurally: it drives commits,
  `vacuum_orphans` and checkpoints, and checks `churn_count == reuse_count`
  after every step, so a future path that reuses without churning fails
  whether or not anyone writes a test for it.

### Fixed — report9 #2: a padding failure no longer costs a commit its churn

- **`commit_tx` attempts padding and churn on independent error paths.**
  They were one `and_then` chain — padding first, churn nested inside
  it — so any padding failure skipped the churn entirely. `commit_tx`
  deliberately does not fail after the superblock is durable (audit
  pass 18), so the caller saw `Ok`, only `last_padding_error` recorded
  anything, and nothing said the churn had not run.

  Why it matters beyond tidiness: that state is exactly the snapshot
  pair DESIGN §9.1 exists to deny. The commit's real writes landed in
  reused slots and no decoy moved, so every offset that changed below
  the tail holds live data — the "live data is here" oracle the
  slot-reuse prohibition used to prevent, back for one commit. And
  padding fails on a full disk, so an adversary who can fill one can
  ask for that commit rather than wait for it.

  Both steps now run whatever the other did, one `fsync` still covers
  them (the shared snapshot interval was the reason they were chained),
  and the first failure is the one reported. Covered by
  `a_padding_failure_does_not_cost_the_commit_its_churn`, which
  provokes the failure through a new thread-local
  `GARBAGE_APPEND_FAILS` — on the chained code it reports 5 slots
  reused against 0 decoys churned.

### Breaking — slot reuse and decoy churn

- **Retired slots are reused; the slot-reuse prohibition is gone.**
  `Space::append_chunk` is now `Space::place_chunk`, and it allocates
  from a **decoy pool** — slots this space retired (`vacuum_orphans` /
  `vacuum_data_batches` orphans, superseded checkpoint chains) plus the
  post-commit padding this space itself appended — before it grows the
  file. `ContainerFile::rewrite_slot` is the single in-place writer;
  `scrub_slot` is now one of its callers. `Inv-W1` is restated from "the
  writer only appends" to "the writer only writes to a slot unreachable
  from any superblock a reopen could select". DESIGN §9.1 replaces the
  old "Slot-reuse prohibition" section in both languages.

  Why the prohibition existed: a decoy chunk was written once and never
  touched, so a **second** overwrite at one offset had no decoy
  explanation and was a reliable "live data is here" oracle for a T2'
  multi-snapshot adversary. Why it can go: the oracle is really "an
  offset was rewritten AND no decoy is ever rewritten", and the second
  half is now false. Decoys are re-randomized — **churn** — from the
  same pool, drawn the same way, in the same commit.

  Churn is deliberately **not on a timer**. A fixed-interval churn moves
  the distinguisher from *whether* an offset is rewritten to *how often*,
  which is no improvement at all. Instead: same event (inside
  `commit_tx`, under the padding's `fsync`), same rate
  (`CHURN_PER_REUSE` victims per slot the commit reused), same
  distribution (uniform draws from one pool, without replacement within
  a commit — `DecoyPool::take` for allocation, `sample_distinct` for
  churn). Uniform draws also matter for a second reason: a FIFO
  allocator would have given real writes an index-locality signature the
  churn does not share.

  **What is honestly not bought**, spelled out in DESIGN §9.1 rather
  than only here: the anonymity set for a reused slot is the pool, not
  the file — an offset that never changed is provably not in any pool;
  write *volume* still leaks, at `k · (1 + CHURN_PER_REUSE)` dirty
  offsets per commit, exactly as file growth leaked it before; and the
  file still grows, because reuse recycles `IndexNode` / `DataBatch`
  chunks and **not** the superseded `Commit` / `Superblock` chunks that
  are the crash-recovery fallbacks and `commit_history` anchors.
  Steady-state growth is `1 + superblock_replicas` per commit — measured
  at one replica, 24 commits append 48 slots where append-only appended
  72. `compact_known` is still the only thing that shrinks a container.

  Crash safety adds no new argument: reuse rests on `vacuum_orphans`'
  proof that a pool slot is unreachable from the era this handle names,
  and therefore inherits vacuum's guards at the point of decision
  (`Space::reuse_permitted` refuses under `PublishUncertain`-shaped
  state and under `unreadable_newer_superblock`). The 3-fsync barrier is
  untouched. Keys needed no change either, and the reason is in §9.1:
  `derive_chunk_key` and the AAD bind to the slot **index**, while every
  `ChunkAead::seal` draws a fresh random 192-bit nonce, so two seals into
  one slot share a key and no keystream — the property XChaCha20-Poly1305
  was chosen for in §10.

- **`CheckpointChunk` carries a second slot list.** The chain that
  records the owned set now records the decoy pool beside it: header
  grows by a `pool_count: u32` (`CP_HEADER_LEN` 28 → 32).
  `CP_ENTRIES_PER_CHUNK` stays 501 — the four extra header bytes came
  out of the slack the integer division was already discarding — and the
  two lists now share that budget rather than the owned list having it
  all. One chain, one superblock pointer, published atomically with an
  era. The decode-time capacity check is on the **sum** of the two
  counts, since a pair that each pass a per-list bound can still describe
  twice a chunk's worth of entries. Existing
  containers decode as "no usable checkpoint" and fall back to a full
  scan, which is the checkpoint's standing contract; the format version
  is unchanged because a checkpoint has never been correctness-bearing
  in either direction.

  The recorded pool is a **hint**: the open path computes
  `pool_effective = pool_recorded \ owned_slots`, so a slot a later
  commit reused comes back as owned and leaves the pool whatever the
  checkpoint said. Under-reporting leaks disk and never loses data,
  which is what makes lazy refresh safe. Two consequences: the fast-open
  scan must now trial-decrypt the recorded pool slots (they are the only
  sub-high-water slots reuse can make newly owned — without this the
  checkpoint's completeness induction is false), and a third refresh
  trigger `CHECKPOINT_MIN_POOL_DRIFT = 256` exists because the existing
  trigger measures tail growth, which is precisely what reuse suppresses.

  `Checkpoint` chunks are the one kind that never allocates from the
  pool. The self-heal retires the chain it supersedes into the pool and
  only then publishes the superblock naming the new chain; a `Checkpoint`
  landing on the old head would let a crash leave a chain that reads as
  valid and is a suffix of the new one — a silently incomplete owned set.
  Any other kind there decodes as the wrong kind and the reader falls
  back to a full scan.

- **`SpaceStats` gains `reusable_slot_count`.** How much writing costs
  no disk right now, and equally the anonymity set a reused slot hides
  in. `utilization_ratio()`'s documentation changed with it: a low ratio
  no longer implies the file will keep growing, and must be read
  together with this field.

  The decoy pool is a bitmap over slot indices, not a `Vec<u64>`, for
  the reason audit HV-03 gave for `SlotSet`: at
  `MAX_OPEN_SCAN_CHUNKS` a `Vec` pool would be 128 MiB held for the
  whole session on a phone, and a pool that cannot be allocated is a
  container that cannot be opened. The `vacuum_peak_memory` regression
  test caught the `Vec` version of this during development.

### Breaking — report8 H-09

- **A publish that may have landed answers `PublishUncertain`, not `Io`.**
  Both publishers — `commit_tx` and the checkpoint self-heal — burn the
  new `seq` one instruction before the first Superblock replica can
  reach the disk, and adopt the new superblock only after the final
  `fsync`. Any failure in between left the disk holding a `seq` HIGHER
  than the one in memory, and the caller was handed the raw
  `Error::Io(_)` of whichever syscall broke.

  That named the syscall and misnamed the situation. An I/O error reads
  as "the write did not happen", and a caller who believes it retries
  the same Tx or runs maintenance on a root the file has already moved
  past — the exact HV-01 sequence where a vacuum erases an era that was
  already visible. The remedy is neither retry nor abort: it is to
  **reopen**, because only the open scan can settle which era landed.
  `Error::PublishUncertain` has said precisely that since HV-01, was
  already carried across the FFI, and was already raised by the vacuum
  gate; the publishers themselves simply never raised it. The comment
  above the burn already claimed this semantics ("if one lands and a
  later replica (or the fsync) fails") — the code did not.

  The window is exactly the burn-to-`fsync` span, and its lower edge is
  load-bearing: the Commit chunk and its fsync sit ABOVE it and keep
  their own error, because nothing they write is reachable until a
  superblock names it. Widening the variant to cover them would tell
  every caller to reopen after any full disk.

  Both publishers now route through one `Space::publish_superblock`,
  so the window has a single definition rather than two copies to
  drift apart.

- **New: `Space::last_publish_error()`.** `PublishUncertain` names the
  remedy, not the cause, and deliberately so — the remedy is the same
  whichever step broke. The cause is parked here instead of discarded,
  the same way `last_padding_error` parks a skipped padding round: a
  device that is out of space and one that is failing want different
  things from an operator. Diagnostic only; it says nothing about
  whether the era reached the disk, and nothing on this side of a
  reopen can. Cleared by the next successful publish.

- **Unchanged, on purpose: committing is not blocked afterwards.**
  `commit_tx` derives the next `seq` from `attempted_seq`, so it skips
  the burnt number instead of publishing a second payload under it
  (audit HV-01). Only the destructive maintenance is refused.

### Breaking — report8 (Dart worker lifecycle)

- **`HvAsyncSpace.close` no longer kills a worker that has not
  answered, and no longer reports a close that did not happen.** It
  used to swallow both the timeout and the worker's death, kill the
  isolate unconditionally in a `finally`, and return normally — so a
  container that was still open reported a clean close.

  The kill was the worse half. A worker that has not answered is
  almost certainly parked inside a synchronous FFI call, and **an
  isolate kill cannot interrupt or unwind an FFI frame**: the native
  `Drop` never runs, the container's exclusive flock stays held by the
  process, and every later open fails `Busy` until the app restarts —
  the "correct password but won't unlock" trap. The worker is now left
  running to finish releasing the container on its own terms; it kills
  itself once it has served the close. Its answer is drained in the
  background so the watcher and the reply port are released when it
  lands rather than never.

  Killing remains the last resort on the two paths where it is safe:
  after the worker has answered (it is already tearing itself down) and
  after it has died (there is no frame left to unwind).

  `close()` now **throws** when the container did not close — `Busy`
  past `closeTimeout` (5 s, settable for tests), `Internal` on a worker
  that died mid-close. Both are teardown failures a caller can log and
  carry on from, but a flow that closes one space and opens another
  must expect `Busy` on the open and not present it as a wrong
  password. `debugKillWorker()` therefore leaves a handle whose
  `close()` throws — by design; nothing on that path can claim the
  native handle was released.

  This is the third of three worker lifecycles in the project to be
  brought to the same contract; `WorkerKvLogStore` in the host app was
  the one that already had it right.

- `_WorkerDeath` → `HvWorkerDeath` (public), plus
  `HvAsyncSpace.debugOverWorker` and `HvAsyncSpace.closeTimeout`. Test
  seams: a real worker cannot be parked inside an FFI frame on demand,
  and `close()` drains the in-flight call first, so the contract above
  has no other way to be exercised.

### Breaking — report8 H-09 (Dart)

- **`HvOpFailed` no longer promises that nothing happened.** Its doc
  said, of every kind, "**Nothing was committed**, so the operation is
  safe to retry" — while `docs/{en,ru}/security/audits/fsync.md` said in
  the same repository that a caller "should NOT retry the same Tx
  without first re-opening the container". Two documents, opposite
  advice, and `docs/{en,ru}/guide/flutter.md` had copied the wrong one
  into its worked example.

  The core is the arbiter and it sides with the audit doc: a commit
  whose Superblock publish fails answers `PublishUncertain`, and that
  arrives from a **live** worker as an error reply — i.e. as an
  `HvOpFailed`, the one outcome that promised the opposite. The two
  `RenameVisible*` kinds are the same shape: the rewrite applied.

- **New: `HvException.mayHaveApplied` / `HvOpFailed.mayHaveApplied`.**
  The distinction now lives where it can be acted on instead of in a
  paragraph. `true` for `PublishUncertain` and the two `RenameVisible*`
  kinds — reopen and look; `false` for refusals raised before a byte was
  written. `false` is not "retry away": `UnreadableNewerState` and
  `Busy` are effect-free and still want a reopen or a wait. The getter
  answers what happened, not what to do next.

  The names are checked against the `_hvErrorKinds` ordinal table by a
  test, because a misspelled kind makes the predicate silently
  always-`false` for it — a guarantee that reads live and is dead.

### Breaking — report7 P2 (Dart)

- **A worker that died under a call is `HvOpIndeterminate`, not
  `HvOpFailed`.** `HvOpFailed` documented itself as "the worker rejected
  the operation, or the worker died under it. Nothing was committed" —
  and `7e973f9` wrote that claim into the public API *and* into
  `docs/{en,ru}/guide/flutter.md`, which advised retrying on it.

  Nobody is in a position to make that claim about a dead worker. An
  isolate can die **after** the native commit reaches the disk and
  **before** its reply is sent — an FFI fault, an OOM kill and an
  uncaught error all land in that window — and from Dart the two cases
  are indistinguishable, because the thing that would tell them apart is
  the reply that never came. The Rust core already models this honestly:
  a lost operation *may have changed state*, and only `Cancelled` carries
  a proof of no effect.

  The remedy is a fifth outcome, not a flag, and the two sources are now
  split along exactly the line Rust already draws: **worker alive and the
  core refused** is a failure, **worker dead** is indeterminate. The
  guidance changes with it — reopen the container and look, rather than
  retry.

  **Latent, correctly.** No mutating call in this API carries a timeout
  today and all four are idempotent by key, so nothing observable was
  wrong. But the shape was, and it had already spread into two guides.

  `debugKillWorker()` is added for the test: `close()` drains the
  in-flight call first, so a call cannot be caught mid-flight through it,
  and the first draft of the test watched the commit succeed instead.

### Fixed — report7 P2 (Dart)

- **Three counts crossed the Dart FFI boundary unchecked.** `_ns` and
  `_sid` guard the two parameters that were audited; `initialGarbageChunks`,
  `superblockReplicas` and the range iterator's `limit` were passed bare,
  and `dart:ffi` narrows silently.

  The consequence the report predicted does not happen — the core clamps
  both capacity and the replica minimum, so nothing overruns. The real one
  is quieter and worse for a format whose point is deniability: **the
  caller asks for something and gets less, with nothing said.**
  `superblockReplicas: 256` narrows to 0, and 0 means "the minimum", so a
  request for 256 replicas produces **one** — fewer than the default 3, on
  the copies a torn write is recovered from. `initialGarbageChunks` is
  worse still: Dart's `int` is 64-bit and *signed*, `1 << 64` evaluates to
  `0`, and a decoy size that wraps to zero switches off the padding the
  caller explicitly requested. A `limit` of 2^32 narrows to 0, which is a
  legal request for an empty page, so the caller reads "no entries" from a
  namespace that has them.

  Guarded by `_u8` / `_u32` / `_u64`, in the shape of the two that already
  existed. `kvKeysPage` took its limit through the same door and is
  guarded with it — the same defect one method along, which nothing would
  have caught either.

### Hygiene — report7 P3

- **The collapsed key-ops map wears `Redacted` now.** `space::tree`'s
  `KeyOps` is a full copy of one transaction's plaintext — every key and
  every value it writes — assembled by `space::commit` from `KvOp`s that
  are themselves `Redacted`. As a bare `BTreeMap` the copy printed under
  `{:?}` and outlived its source's scrub, which is precisely the shape of
  leak the `redact` module exists to close: the wrapper on the original
  said nothing about the collection derived from it. `LeafRun::entries`
  gets the same treatment — `LeafNode` already wore the wrapper on the
  identical field; the buffer that feeds it did not.

  `Secret` is implemented for the map shape. Its scrub drains rather
  than iterating, because a `BTreeMap`'s keys are not reachable as
  `&mut` and an in-place pass would have zeroized the values and left
  every key intact.

- **`unsafe impl Send for OwnedSpace` removed.** Every field is `Send`,
  so the compiler derives it — the `unsafe impl` asserted something
  nobody had to be told. Worse than redundant: it would have gone on
  holding if a future field stopped being `Send`, turning a compile
  error into a data race. Replaced by a static assertion that fails to
  **compile** in exactly that case, which is the outcome the `unsafe
  impl` was suppressing. Verified by pointing the assertion at a
  `*const u8`, which does not build.

- **`hex-literal` dropped** from dev-dependencies. Zero uses in the tree.

### Fixed — report7 P2

- **A custom padding policy inherited the previous container's preset
  index.** `Container::create_with_options` derives the header's
  padding bits (16..24 of the Argon2 version word) from the requested
  policy — except for a custom one, where it passed `options.argon2`
  through untouched. That word *is* where the index lives, so "untouched"
  meant "keep whatever index the caller's params already carried".

  Not only reachable by a host passing something odd. `repack` builds
  the destination's params from the **source header**, which carries the
  source's index by construction; ask that repack for a custom policy and
  the new container's header claimed a preset nothing at runtime was
  applying. The next open read the index back and applied a policy its
  owner had explicitly asked to replace. The comment at the site said the
  custom case is "runtime-only" — true of the policy, false of the header.

  The custom arm now zeroes the index, so a runtime-only policy reads
  back as `None`: a host that forgets `set_padding_policy` gets no
  padding rather than the wrong padding.

### Security — report7 P1

- **`hv repack` echoed every password in the container, and the Windows
  binary echoed all of them.** report6 P2 closed `read_password`, the
  single-password prompt. It did not touch `read_all_passwords`, which
  `repack` uses — and `repack` is the worse of the two: it prints
  "Reading passwords from stdin (one per line, EOF to end)" and waits,
  which *invites* interactive use, and what it collects is the password
  to every space in the container. All of them went into the terminal
  scrollback together. The existing pty test could not see it: every
  case in it drives `create-space`, which goes through the other
  function.

  `read_all_passwords` now holds the same `EchoOff` guard across the
  whole list, and restores the terminal before every early return.

- **The Windows arm of `EchoOff` is written.** It was left out on the
  stated grounds that this host could not compile or run it, so shipping
  it would mean shipping unexecuted code. The premise did not hold:
  `hv.exe` is built and published by `release.yml` and `ci.yml`, and
  `windows-release-gate.yml` already ran this crate's tests on a Windows
  runner. There was a place to compile and execute it. Meanwhile the
  shipped binary printed passwords on screen.

  `GetConsoleMode` / `SetConsoleMode` clearing `ENABLE_ECHO_INPUT`, with
  `ENABLE_LINE_INPUT` deliberately left on so the prompt keeps its line
  editing. Two things make it executed code rather than a claim: the
  `hv` binary's unit tests now run on the Windows runner
  (`cargo test -p hidden-volume --features cli --bins`, added to the
  gate — `--test cli` selected one integration target and never built
  them), and `the local release checklist` §4 gains a Windows cross-compile check via the
  `-gnu` target and mingw-w64, which type-checks every `cfg(windows)`
  arm on a darwin host in seconds.

  `windows-sys` joins as a `cfg(windows)` dependency. It is already in
  the tree there via getrandom / tempfile / zstd; this adds two feature
  modules and no new crates.

- **Stdin is bounded.** `MAX_PASSWORD_LINE` (1 KiB) and `MAX_PASSWORDS`
  (256). Both were unbounded, so `hv repack < /dev/zero` grew a single
  line until the machine gave out. Not a policy on password length — a
  bound on what one process will allocate for input it has not validated.

### Fixed — report7 P1

- **Four typed errors were erased at the FFI boundary.** The core has
  twenty variants; `From<hidden_volume::Error> for HvError` had sixteen
  arms. `UnreadableNewerState`, `PublishUncertain`,
  `RenameVisibleDurabilityUncertain` and `RenameVisibleContentUnverified`
  all fell through to `Internal("unknown error variant")` — an error
  whose own doc comment says it indicates a bug in the library. The last
  of them was added to the core by `df50507`, which touched the core and
  not the boundary, so it was born already erased.

  **Reachable from the main path, not from a fault-injection harness.**
  Orphan cleanup raises `PublishUncertain` and `UnreadableNewerState`,
  and the Dart plugin arms deferred cleanup on **every open**. So a
  container that lost a publish answered "library bug" on every single
  open, and the one thing that fixes it — *reopen the container* — never
  reached the host at all. The two rename cases come from the rewrite
  under source lock, which the exported compaction and password-change
  entry points both reach; there, "the rename applied and your old
  password is dead" arrived as "internal error", which a caller
  reasonably reads as *nothing happened* and acts on by retrying with a
  password that no longer opens the file.

  All four now have their own `HvError` variant, carrying the remedy in
  the rustdoc. They are **appended** to the enum, not inserted: uniffi
  transports a `flat_error` as its ordinal and the hand-written Dart
  bindings decode it positionally, so a middle insert would silently
  rename every error after it on the Dart side. `_hvErrorKinds` gains
  the four names, and both sides now say in a comment that they are
  append-only.

  The catch-all's comment claimed `from_maps_*` unit tests guarded the
  actionable variants. No such test existed — there was one, on
  `ContainerTooLarge`, under a different name — and the four had
  collected behind that claim. The false reference is replaced by the
  test it promised: `every_core_variant_maps_to_something_other_than_unknown`
  names all twenty core variants and fails on any that reaches the
  catch-all, plus one test per rescued variant asserting on `HvError`,
  the type a foreign caller actually receives.

  `docs/{en,ru}/reference/ffi.md` said "14 variants" and called the
  mapping a 1:1 mirror; both are corrected, and the ordinal coupling is
  now written down.

### Documentation — report7 P0

- **The Argon2 ceiling values in the docs had not moved with the
  code, and the gate that exists to catch exactly that said they
  had.** `ff9ec00` tightened `MAX_M_COST_KIB` / `MAX_T_COST` /
  `MAX_P_COST` to 512 MiB / 8 / 16 and touched three files: the
  changelog, the source, and the generated API snapshot. Twelve
  claim sites across eight documents went on asserting 1 GiB / 100 /
  64 — `format.md` (EN+RU, prose and constant table), the
  `adversarial-stance` and `primitive-level` audit dossiers (EN+RU),
  and `DESIGN.md` / `DESIGN.ru.md`. A reader checking what a
  tampered header can cost would have read a number four to twelve
  times too large in every document that answers the question.

  All twelve are corrected. Three things were wrong beyond the
  values themselves and are fixed with them: the `primitive-level`
  tables cited `Argon2Params::MAX.m_cost_kib`, a **constant that
  does not exist** (the real names are `MAX_M_COST_KIB` /
  `MAX_T_COST` / `MAX_P_COST`); `adversarial-stance` F-A1 still
  described the reject as `format_version == 2`, two generations
  stale; and the ceilings are now stated as multiples of `HEAVY`,
  which is the invariant the code's own test pins, rather than as
  bare numbers with no stated relation to anything.

- **`check-docs-version-drift.sh` gained the pattern that would have
  caught it.** The gate knew four patterns — format generation,
  header size, Dart binding staleness, uniffi version — and nothing
  about cost constants, so it answered "docs are consistent" on a
  tree where they were not. Pattern 5 reads the three ceilings from
  `crypto/kdf.rs` and fails on any line in `docs/` or the top-level
  narrative docs that states a different value next to one of the
  names. It recognises all three idioms the docs use — the
  `512 MiB / 8 / 16` triple, `NAME = V` / table-cell claims, and
  `t_cost ∈ [2, 8]` intervals — over a two-line window, because
  these files are hard-wrapped and a claim can straddle the wrap.

  Values are compared as *numbers*, not as text: writing
  `524288 KiB` where the table says `512 MiB` passes, and changing
  the source constant lights up all twelve sites at once.
  `api-surface.txt` is excluded — it is generated from the source
  and gated by `dump-public-api.sh --check` in the same pre-tag run.

### Breaking — report6 follow-through

- **A delete now has to be addressed the way its namespace is kept
  (HV-04).** The single-kind-per-namespace contract was enforced for
  every operation except the two that delete.

  `Tx::delete` on a namespace recorded `Log` went through. The Tx-side
  check only asks whether the *other* kind is pending in the same
  transaction, which for a lone delete it is not; the commit-side check
  then looked for a `Put` among the ops, because pure-`Delete` op sets
  had been exempted so `Space::erase_namespace` could clear a log
  namespace. The exemption was written for erase and granted to
  everything shaped like erase.

  `Tx::delete_log` on a namespace recorded `Kv` went through for the
  opposite reason: a log delete is stored as a KV `Delete` on the
  `log_id_key`, so the log-side gate never saw it, and it reached the
  index through the same internal helper erase uses — which skipped the
  KV-side gate outright. It was the only operation in the crate that met
  no kind check at all.

  Neither needs an attacker; both need the password and a mistake in the
  host app. The first unlinks a message from its `DataBatch` through an
  API documented to refuse. The second removes a real KV entry whenever
  its key happens to be the eight big-endian bytes of the id.

  Ops now carry a `KvOrigin` — `ByKey`, `ByLog` or `Erase` — and
  `commit_tx` weighs that against the recorded kind instead of guessing
  from op shape. Only `Erase` may disagree with what is on disk, because
  the namespace it leaves behind is empty and so cannot end up half of
  one kind and half of another.

  **Breaking for callers who deleted log records with
  `Tx::delete(ns, log_id_key(id))` or the FFI `WriteOp::Delete` on a log
  namespace** — that now fails the commit with `WrongNamespaceKind`.
  `Tx::delete_log` / `WriteOp::DeleteLog` is the call. Four of this
  crate's own tests were written that way and are migrated in the same
  commit, which is the best evidence available that the mistake is an
  easy one to make.

### Security — report6 P2

- **The Argon2 parameter ceilings bound time, not only memory.** They
  existed to stop a tampered cleartext header from OOM-ing every open —
  but 1 GiB × 100 iterations × 64 lanes was still admissible, and that
  worst case measures **43 seconds** on an Apple-Silicon desktop
  (against 416 ms for `HEAVY` on the same machine). A header edit that
  needs no key turned every open of that container into a minute-long
  freeze, on a file whose owner cannot tell it was tampered with until
  the derivation finishes and fails.

  `MAX_M_COST_KIB` 1 GiB → 512 MiB (2× `HEAVY`), `MAX_T_COST` 100 → 8
  (2× `HEAVY`), `MAX_P_COST` 64 → 16 (4× `HEAVY`). Worst admissible
  header now measures **1.7 s** on the same machine. Every shipped
  preset stays admissible.

  The audit proposed a caller-supplied budget at open time instead.
  Rejected: it would create containers that open on a desktop and refuse
  on a phone, which is a worse failure for a format meant to be carried
  between them.


- **`hv` no longer echoes a password typed at a terminal.**
  `read_password` was a bare `read_line`, so at an interactive prompt
  the tty printed every character back and the password stayed in the
  scrollback of whoever was looking at the screen — on a tool whose
  whole point is that a container's contents cannot be compelled out of
  you.

  The branch is on `IsTerminal` and nothing else, so a piped or
  redirected password — `echo pw | hv …`, the documented scripting
  idiom and the one every test uses — takes byte-for-byte the same path
  it always did. Echo is cleared through a guard, so a read error or a
  panic still restores the caller's shell; `TCSAFLUSH` discards
  type-ahead so characters entered before the prompt are not silently
  taken as part of the password.

  **Unix only.** Windows needs `SetConsoleMode`, which this host cannot
  compile or run — shipping it would mean shipping code nobody has
  executed. On Windows the read behaves as before; `EchoOff` says so.

  The audit also reported a command-line-argument leak here. That half
  is **not correct**: there is no `--password` flag and never was, and
  the CLI spawns no child processes.

  `libc` moves from a `cfg(target_os = "android")` dependency to
  `cfg(unix)` for `tcgetattr`/`tcsetattr`. Free in dependency terms —
  it is already in the tree on every Unix via getrandom / zstd /
  memmap2 / rayon.

### Testing — report6 P2

- **`Checkpoint` was the chunk kind the property tests skipped.**
  `tests/properties.rs` built its generator by naming variants one by
  one; a fifth kind was added to the format and nothing connected the
  two, so `p1_chunk_plaintext_roundtrip` exercised four of five and
  neither file said so.

  The generator is now built from one list, and a new test sweeps all
  256 bytes through `ChunkKind::from_u8` to assert that list is exactly
  the set the decoder accepts — so a kind added to the format fails the
  suite instead of quietly dropping out again.

### Documentation — report6 follow-through

- **An interrupted `create_space` leaves a complete, empty space, and
  the rustdoc now says so.** The call writes N Superblock replicas and
  fsyncs; a crash partway through leaves some replicas and no return
  value, but the space on disk owns no namespaces, no Commit chunk and
  no data — there is nothing yet for a partial write to make
  inconsistent. Reconciliation is therefore just opening it again with
  the same password, and a repeated `create_space` answering
  `SpaceAlreadyExists` is the truth rather than a symptom.

  Deliberately **no third outcome** on the constructor: a caller cannot
  act differently on "created-but-unconfirmed" than on either of the
  two that exist, and every space this API can leave behind is openable.

- **`v1` where the format is `v3`.** `docs/{en,ru}/reference/README.md`
  called `format.md` "the spec for v1"; `docs/{en,ru}/guide/README.md`
  called `migration.md` "an empty shell for the eventual v1 → v2
  migration" (the format has bumped twice since, and that file now
  documents the policy); and `docs/{en,ru}/reference/semver.md` pinned
  the whole post-1.0 freeze policy to v1 — "`1.x.y` libraries MUST read
  v1 containers", "a v1 container created by `1.0.0`" — both of which
  `1.0.0` contradicts by shipping and requiring v3. The
  hypothetical-future generation table moved up with them, and four
  dead references to a `FORMAT_v1.md` that has been `format.md` for
  some time now point at the real file.

### Fixed — report6 follow-through

- **The post-rename inode check reported a post-rename failure as an
  internal bug (P2).** `compact_known` / `change_passwords` pin the temp
  file's inode, `rename(2)` it over the target, then re-read the path's
  inode to catch a substitution. On mismatch that check returned
  `Error::Internal` — documented as a crate bug, which a caller reads as
  "nothing was done" — while the rename had already happened and the
  previous inode was already unlinked. Same shape audit HV-03 fixed one
  branch below it for the parent-directory fsync, left unfixed here.

  New `Error::RenameVisibleContentUnverified`, sibling of
  `RenameVisibleDurabilityUncertain`, and reported ahead of it: "the file
  at this path is not the one we wrote" is worse news than "it is, and
  might not survive a crash".

  The `compact_known` / `change_passwords` contract said "on any failure
  `path` is left BYTE-IDENTICAL", which the two post-rename outcomes
  contradict. It now says "on any failure **before the rename**" and
  names both, in the rustdoc and in `docs/{en,ru}/guide/operations.md`.

### Removed — report6 follow-through

- **`crates/hidden-volume-ffi/build.rs` and its build-dependency.** The
  script did nothing but print two `rerun-if-changed` lines, and its own
  comment justified its existence falsely: it claimed
  `uniffi::setup_scaffolding!` needs "a build-script marker", which is a
  UDL-mode requirement — proc-macro mode, which this crate uses and
  which `docs/{en,ru}/reference/ffi.md` §"Decision 2" names as the
  reason there is no `build.rs`, has no such dependency. The
  `[build-dependencies] uniffi` entry it implied was likewise unused,
  and building it on every host is the only thing it cost.

  Verified by the `ffi_smoke` test, which dlopens the built cdylib and
  resolves the uniffi contract-version and per-method checksum symbols
  the foreign bindings depend on — 242 exported symbols before and
  after.

### Added — report6 follow-through

- **`HvAsyncSpace` answers what became of an operation you stopped
  waiting for (HV-07).** A Dart `Future` cannot be cancelled, so
  `space.commit(ops).timeout(...)` stops the caller waiting and nothing
  else: the worker isolate finishes the call and answers into a reply
  port nobody reads. The answer was dropped, leaving a host that timed
  out unable to tell a landed commit from a lost one — on a deniable
  store, where the alternative to knowing is to guess and possibly
  apply the write twice.

  The Rust FFI has a ledger for exactly this
  (`AsyncSpaceHandle::abandoned_operations`), but it hangs off the
  **async** handle while the hand-written Dart bindings bind only the
  sync symbols — the worker holds a `SpaceHandleBindings` — so it was
  unreachable from Dart. Nothing needed porting: the worker already
  serialises calls, which is the hard half.

  New: `HvOperation<T>` (a monotonic `id` plus the same future), the
  `commitOperation` / `eraseNamespaceOperation` /
  `setPaddingPolicyOperation` / `vacuumDataBatchesOperation` /
  `vacuumAfterOpenOperation` submit twins, and
  `HvAsyncSpace.outcomeOf(id)` returning
  `HvOpPending` / `HvOpSucceeded` / `HvOpFailed` / `HvOpUnknown`. The id
  is issued and filed as pending **before** the send, and the outcome is
  recorded by the call itself rather than by whoever awaits it, so a
  caller who walks away still leaves a record. `HvOpUnknown` is kept
  distinct from `HvOpPending` on purpose — collapsing "I do not know"
  into "not finished yet" would reintroduce the guesswork.

  Additive: the existing `Future`-returning methods keep their
  signatures and semantics (including rejecting rather than throwing
  synchronously on a closed handle) and delegate to the new twins.
  Outcomes are bounded to the last 128 operations per handle.

  **Latent, not live**: no mutating call in the app carries a timeout
  today, and all four write operations are idempotent by key.

### Performance — report6 follow-through

- **The constant-time scan's timing equalizer reuses its scratch buffer
  (HV-12).** `equalize_timing_via_chacha20` ran `vec![0u8; body_len]` on
  every chunk whose tag did not verify, and its one call site passes the
  compile-time constant `PLAINTEXT_LEN` — so every rejected chunk
  allocated and freed the same ~4 KiB. Near the format's 16 M-chunk
  ceiling that is tens of GB of allocator traffic for a single unlock,
  on the path the FFI takes by default. The buffer is now thread-local
  and grown once (thread-local rather than shared: the parallel scan
  runs this on every rayon worker, and a lock would serialise the scan
  and add contention timing of its own).

  **Reclassified from side channel to cost.** The audit filed it as the
  former; it is not. `body_len` is constant at the only call site, so
  the allocation's size — and therefore its cost — carries nothing about
  the chunk, the key, or whether the tag matched. The reuse is if
  anything *better* for the property the equalizer protects: it removes
  the allocator, whose timing depends on heap state, and leaves the
  ChaCha20 pass, which is constant-time by construction and one to two
  orders of magnitude larger.

- **Maintenance stops materialising whole namespaces (HV-02, HV-03).**
  Three paths held plaintext, or slot bookkeeping, proportional to the
  container rather than to the work in front of them. All three were
  written under the two-level B+ tree cap of ~10 K entries per namespace,
  which audit HV-15 removed without revisiting the callers that leaned on
  it — comments in `repack` still cited the cap as the reason its KV leg
  was safe.

  - `Container::repack`'s KV leg did `src_space.list(ns)` — every key and
    every value of the namespace in one `Vec` — and then handed each pair
    to `Tx::put`, which copies. Peak was **twice the namespace's
    plaintext**. It now pages through the new `Space::list_after(ns,
    after, limit)`, the pair-carrying twin of `list_keys_after`, and
    drains each page into the destination transaction: ≈ 1 MiB per page,
    flat in namespace size. Splitting a namespace's copy across several
    destination transactions is sound because the destination is a file
    the call created; a failure between pages leaves a partial `dest` the
    caller discards. This is not a general licence to split transactions.
  - `Space::vacuum_orphans` built a `HashSet<u64>` of reachable slots
    beside the traversal guard's own visited set — the same set, twice —
    cloned `owned_slots` whole, and built a second `HashSet<u64>` of
    slots to drop. It now reads the guard's set through
    `TreeWalk::has_visited`, indexes `owned_slots` in place, and keys the
    drop set on a **slot bitmap**: one bit per slot, 2 MiB at the format's
    16 M-chunk ceiling against hundreds of MiB of hashed `u64`s. This one
    is not merely an allocation win — `vacuum_orphans` runs automatically
    on every writable open, so a container grown past where the vacuum can
    allocate stops opening **at all**.
  - `Space::vacuum_data_batches` reached its referenced-slot set through
    `collect_leaves`, materialising every `(log_id_key, batch_slot)` pair
    of every log namespace before reading one. Paged scan, same bitmap.
  - `Space::verify_integrity` pooled every log namespace's DataBatch
    pointers and verified the lot after the last root; it now flushes per
    namespace. Per-namespace is as fine as this can safely go: the batch
    pass admits each slot to the shared traversal guard, and log_ids in
    one batch need not be contiguous, so a boundary inside a namespace
    could split one batch's pointers across two flushes and report a
    healthy container as corrupt.
  - `Space::erase_namespace` moves each key into its `Delete` op instead
    of copying it, so the key list and the op list are never both live.

  Additive at every level; `Space::list_after` is the only new public
  item. Coverage: `tests/repack_peak_memory.rs`,
  `tests/vacuum_peak_memory.rs` and `tests/integrity_peak_memory.rs`
  measure peak allocation under a counting global allocator, because none
  of this is visible in any return value — every correctness test in
  `tests/repack.rs`, `tests/scrub.rs` and `tests/integrity.rs` passed
  against the old code and passes against the new.

### Security — report6 follow-through

- **The constant-time open no longer performs maintenance (HV-01).**
  `Container::open_space_constant_time` and its parallel / mmap companions
  exist to make unlock latency independent of whether a password matched —
  the F-TM1 mitigation for a coercion setting. Each of them then ran
  `vacuum_orphans` before returning: a tree walk, a read of every
  non-visible chunk among the reachable ones, an overwrite of each orphan
  and an fsync. **Milliseconds and disk writes, both proportional to the
  space's accumulated history, and reached only when the password was
  right** — a wrong one returns from the scan before that line. The
  equalizer's microseconds were followed by a signal orders of magnitude
  larger, so the very measurement it removes was handed back by the
  maintenance behind it.

  Reachability was maximal and not opt-in: the FFI opens constant-time by
  **default** (`SpaceHandle::open` / `open_with_keys`, sync and async), so
  every app unlock went through it. `MultiSpace` had the same defect and
  closed it one audit earlier; the container path had no test at all.

  The three constant-time entry points now do no maintenance, and the new
  `Space::vacuum_after_open` is that maintenance as its own operation —
  read-only-tolerant (`Ok(0)`) the way `MultiSpace::vacuum_hosted` is,
  because a host calls it unconditionally after every open. `SpaceHandle`
  and `AsyncSpaceHandle` expose it across UniFFI.

  **The scrub is deferred, not cancelled**, and simply deleting the call
  would have quietly ended forward secrecy for every caller. So the Flutter
  plugin runs it — and deliberately not on the heels of the unlock, which
  would move the same duration a few milliseconds right and leave it
  correlated with success. `HvSpace.open` / `openWithKeys` and
  `HvAsyncSpace.open` arm it on a delay drawn with `Random.secure` from a
  `DeferredVacuumWindow` (30 s – 5 min by default); `scheduleDeferredVacuum`
  re-arms with another window, `cancelDeferredVacuum` hands the job to the
  host, and `close` disarms. A host that knows a better moment — screen
  off, app backgrounded, first user-initiated write — should call
  `vacuumAfterOpen` there instead.

  Honest cost of the split: the scrub is no longer guaranteed by the open.
  If the process dies before the timer fires nothing is reclaimed and the
  next session owes it again — against a pre-fix inline vacuum that always
  ran, into the leak it always ran into. Both halves are pinned:
  `tests/constant_time_defers_scrub.rs` asserts the open reclaims nothing
  **and** that the explicit call does, plus the same for the keys variant,
  the contrast that the ordinary open still scrubs inline, and the
  read-only `Ok(0)`. `test/deferred_vacuum_test.dart` does the same across
  the FFI and pins that the armed delay is drawn from the window rather
  than being zero.

### Breaking — report6 follow-through

- **Maintenance no longer re-parameterises the container it maintains
  (HV-09).** `RepackOptions::default()` meant `Argon2Params::DEFAULT` and
  `PaddingPolicy::None` for the destination, and all three production
  callers passed exactly that — the FFI `compact_known` and
  `change_passwords`, and the `hv repack` CLI. A container created at
  256 MiB / t4 / p4 therefore came out of a password rotation at
  64 MiB / t3 / p1: **four times cheaper to brute-force offline**, written
  into the header permanently, with nothing said to the user. The KDF half
  needed no user action at all, since a host app calls compaction itself on
  a size threshold. Padding went the same way, from a persisted preset to
  none, un-masking per-commit growth for a multi-snapshot observer.

  Breaking, in the public Rust API: `RepackOptions::argon2` is
  `Option<Argon2Params>` and `RepackOptions::padding_policy` is
  `Option<PaddingPolicy>`. `None` — the new default for both — copies the
  source's; `Some(..)` rotates, which is what a deliberate
  re-parameterisation now has to say. The three production callers are
  unchanged in code and now preserve; the FFI surface has no way to ask
  for a rotation, which is the correct posture for it.

  Both fields had to move together. `Container::create_with_options`
  re-derives the destination header's padding bits from `padding_policy`,
  so preserving `Argon2Params` alone would carry the cost across and zero
  the padding index of the very header it had just copied.
  `tests/repack_preserves_posture.rs` asserts the two halves separately
  for `compact_known`, `change_passwords` and out-of-place `repack`, plus
  a fourth test that an explicit `Some(..)` still reaches the destination
  — preserving unconditionally would otherwise pass the first three.

### Performance — report6 follow-through

- **A page of pagination costs the page, not the history (HV-05).** None of
  the four paged walkers pruned by the separating key: each one descended
  from child 0 and filtered in the leaf, so every page re-read the entire
  prefix it had already returned. At N = 20 000, one page from the tail
  cost **94** chunk reads for `list_keys_after` and **130** for each of
  `iter_log_after` / `iter_log_before` / `iter_log_range`, against **4**
  and **5** for the first page — and paging all the way through was
  therefore O(N) per page, O(N²) overall. It is now **4 and 5 at both ends**:
  every internal node starts its loop at `InternalNode::child_index_for`
  (the binary search point-reads already used) instead of at zero.

  The audit named the KV walker and the forward log walker. The other two
  were found by reading the file: `iter_log_before` had the mirror-image
  defect, and `iter_log_range` — the one an app actually calls for chat
  scrollback — stopped early on its UPPER bound and ignored its lower one
  entirely, which is the worst combination, since scrollback is exactly the
  caller that moves the lower bound one page at a time.

  Correct results were never in question: the leaf filter was right before
  and is right now. So the regression test is `space::pagination_cost_tests`,
  which counts chunk reads through the `CHUNK_READS` probe — a test that
  only checked the page contents passes against the defect.

### Breaking — audit follow-through

- **`Debug` printed decrypted keys, values and log payloads (HV-01,
  HV-07).** The previous pass redacted the four types that *hold* a
  secret — `KvOp`, `WriteOp`, `LogEntry`, `Plaintext` — and left the
  structs that hold *those* deriving `Debug`. `format!("{tx:?}")`, a
  `tracing::debug!` on an index node, or an `assert_eq!` failure message
  still printed a contact record or a message body verbatim, in release
  builds, with no key and no container file needed. `Zeroizing` does not
  help: the upstream crate derives `Debug` on it, so
  `SpaceState::roots_payload_cache` printed a decrypted commit payload
  byte for byte.

  Fixed structurally rather than by extending the list that was already
  incomplete once. New `redact` module, and two rules:

  - A plaintext-bearing field is typed `Redacted<T>` — `Deref`s to `T`,
    prints `{ items, bytes }` and never content, scrubs on drop. Safe
    even under `#[derive(Debug)]`.
  - Its carrier's `Debug` comes from the `redacted_debug!` allow-list
    macro and ends in `finish_non_exhaustive()`, so a field added later
    prints nothing until someone names it. Forgetting is the safe
    direction.

  The scrub half is HV-07, and the honest scope is that the crate's
  **internal** copies no longer outlive the operation that built them —
  not that a plaintext is gone from the process. What the API returns is
  the caller's, and across UniFFI it is copied into a foreign heap.

  Breaking, in the public Rust API:

  - `LeafNode::entries` is `Redacted<Vec<(Vec<u8>, Vec<u8>)>>` and
    `ChildPointer::first_key` is `Redacted<Vec<u8>>`. Reads and mutations
    are unchanged via `Deref`/`DerefMut`; taking the value out by move is
    now `.into_inner()`.
  - New public `hidden_volume::redact` module (`Redacted`, `Secret`,
    `SecretShape`).

  `tests/debug_redaction.rs` is the sentinel: it formats every reachable
  carrier and searches for the markers in text, byte-array and
  truncated-tail form.

- **A commit costs the change, not the namespace (HV-16).** `commit_tx`
  read a namespace's whole tree, applied the ops in memory and rebuilt
  it. The *disk* cost of an edit was already the path to it (HV-14),
  but the CPU and RAM were the namespace: writing 10⁶ 64-byte entries
  as 500 transactions cost **96 s and 2.60 GiB**, against 0.64 s and
  395 MiB for the same data in one. A one-key edit cost 362 ms at
  N = 10⁶. `commit_tx` now descends to the affected leaf and rewrites
  only the nodes the change reaches: **7.0 s and 12.7 MiB** for the
  same 500 transactions (13.8× the wall, 210× the memory), and a
  one-key edit is 11 ms at every size measured — flat at the 3-fsync
  floor. The number of chunks a commit *appends* is unchanged at every
  point in the table, which matters beyond speed: that number is what a
  multi-snapshot observer counts, and HV-14 deliberately made it track
  how localised a change was rather than how big the namespace is.

  **Node boundaries are now content-defined, and that is the breaking
  part.** Descending to a leaf is only worth anything if the rest of
  the tree stays put, and under the previous greedy left-to-right
  packing it does not: boundaries are a function of fill, so changing
  one entry's size shifts every boundary to its right. Measured, a
  greedy packer plus incremental descent reads 23 / 202 / 996 chunks
  for one edit at N = 2 000 / 20 000 / 100 000 — still O(N). A node now
  ends where one of its items' BLAKE3 says it does, with probability
  `cost / (K × bytes still free)`, so an edit perturbs only the run it
  lands in and the packing re-synchronises with the old tree a node or
  two later: **4 chunk reads at all three sizes**.

  This also makes the tree's shape a function of its key-value set and
  of nothing else — the same entries always produce the same tree,
  whether they were written in one transaction, one at a time, or
  churned through deletes and re-inserts. That is a deniability
  property, not a tidiness one: a B+ tree that splits a full node in
  half in place records its own insertion order, so a key-holder could
  tell a namespace that was written at once from one that was edited
  into the same state. It is also what HV-14's content-keyed node reuse
  has always assumed.

  Breaking, and on disk:

  - **Trees are shaped differently.** Node encodings, Merkle links, the
    3-fsync protocol and the format version are all untouched — a
    container written by the previous version reads correctly — but a
    namespace rewritten by this version comes out cut at different
    places. Nothing migrates; nothing needs to.
  - **Containers are ~16 % larger for small values.** Mean node
    utilisation is `K/(K+1)` = 6/7 ≈ 86 % against ~98 % greedy: 10⁶ ×
    64 B goes from 19 866 to 23 144 chunks (77.6 → 90.4 MiB). Values of
    2 KiB are unaffected (+0.2 %) — one fits in a chunk either way.
    This is the standing price of a history-free shape.
  - **`MIN_FULL_INTERNAL_FANOUT` is 4, not 12**, so the readers' depth
    bound is 12 descents at the largest container the format permits
    rather than 7. The bound is derived from the narrowest a level can
    be, and content-defined boundaries guarantee nothing on their own —
    a key-holder choosing keys whose hashes all fire would get
    one-child nodes and unbounded depth. So the writer refuses to
    honour a boundary before `MIN_INTERNAL_CHILDREN` = 4 children, and
    4 is what the arithmetic uses. Honest fanout is 40–70, so honest
    trees are the same height they were.
  - `IntegrityReport::max_depth` can therefore reach 13.

  What is **not** fixed: a commit costs the *span* of keys it touches,
  not their number. Operations scattered across a whole namespace still
  walk everything between the outermost two — the same O(namespace) the
  previous implementation always paid, so nothing regresses. Numbers,
  method and the greedy-packing comparison are in
  `docs/en/contributing/benchmarks.md` (and the RU mirror).

  Covered by `crates/hidden-volume/src/space/tree.rs` (one shape per key
  set across eight different ways of writing it, at two and at three
  levels; chunk reads per edit flat in N; a level grown and collapsed
  again landing back on the shape it started with) and
  `crates/hidden-volume/tests/hv16_incremental_commit.rs` (the same
  content in 1 / 16 / 200 transactions producing byte-identical index
  chunk counts and depths; a one-key edit at `2 + levels` chunks from
  500 to 50 000 entries; a 24-round churn of inserts below, above and
  through the middle checked entry by entry). Five break-check probes,
  all caught: the level tag off by one in the incremental path (9
  tests), boundaries disabled back to greedy packing (the read-count
  test, at 23 / 202 / 996 chunks), the guaranteed-fanout floor dropped
  (the writer refused the commit with `IndexFull` rather than writing an
  unreadable namespace), the level prefix primed from the advanced
  cursor instead of the descent (4 tests), and re-synchronising before
  the operations were exhausted (16 tests). Two control probes — the
  emitted-slot guard and the writer's own level-width check, both
  documented as defence-in-depth — left the suite green.

- **A namespace's capacity is no longer a property of one chunk
  (HV-15).** The writer emitted exactly two levels — a row of Leaves
  and one Internal node above them — so a namespace could hold no more
  entries than fit under a single root. Measured (`PaddingPolicy::None`,
  9-byte keys), that ceiling was **4 029 entries with 64-byte values,
  553 with 512-byte values and 79 with 2 048-byte values**; one more
  and `Tx::commit` returned `Error::IndexFull`, with no way for a
  host-app to store the data at all. A message log stopped at roughly
  15 K unique `log_id`s.

  Teaching the writer a third level would only have moved the wall
  (79 → ~6 200 for 2 KiB values), so it now grows a level whenever the
  level below outgrows one chunk. There is no depth limit: a namespace
  is bounded by the container, and a full container says
  `Error::ContainerTooLarge` as it always did. Verified by writing,
  reopening, reading back and `verify_integrity`-ing **1 000 000
  entries at 64 B (77.6 MiB, 4 levels), 250 000 at 512 B, 100 000 at
  2 KiB (396.6 MiB)** — 248×, 452× and 1 266× the old ceilings, with
  nothing in the writer stopping there.

  **`MAX_TREE_DEPTH = 3` is gone.** It was the same ceiling seen from
  the reader's end, and no constant can bound a tree whose shape is not
  fixed. Every walker (`Space::get`, `list`, `count`, the `log_iter`
  family, `verify_integrity`, `vacuum_orphans`) now takes its depth
  bound from the traversal budget `TreeWalk` already held: since each
  level of a well-formed tree is at least `MIN_FULL_INTERNAL_FANOUT`
  (12) times wider than the one above it, a tree of depth *d* costs at
  least 3, 16, 161, 1 890, 22 627, 271 460, 3 257 445 chunks for
  *d* = 1..7, and a walk may descend only as deep as the chunks the
  space owns could be arranged into. Honest data is never refused — its
  chunks are on the disk by definition — while a hostile chain is
  bounded harder than before: 7 descents at a 64 GiB container, and
  three descents are already refused in a near-empty one, where the
  constant would have allowed them. `Space::get` gained the visited-set
  and budget halves of the guard too; it previously relied on the depth
  constant alone.

  Breaking, though nothing on disk changes: `Error::IndexFull` no longer
  means "namespace full" (it is now the structural guard against a tree
  level that would not narrow, unreachable via `MAX_KEY_LEN`) and its
  `Display` string changed; `IntegrityReport::max_depth` can exceed 2.
  Node encodings, Merkle links, the 3-fsync protocol and the format
  version are untouched — an Internal node's children were always
  permitted to be Internal nodes; the writer simply never emitted them.
  HV-14's node reuse is preserved and extended: the reuse map now covers
  every level of the previous tree (and is collected during the flatten
  walk the commit already performs, so it costs one chunk read *less*
  than before), which keeps a one-key edit at 2 + one chunk per level —
  4 chunks at two levels, 6 at four — instead of one per leaf.

  The writer refuses to publish a tree its own readers would reject, so
  a future change that weakened the packing would fail the commit rather
  than leave a namespace unreadable.

  **What this does not fix, and now matters more.** `commit_tx` still
  materialises the whole namespace per write. HV-14 measured that and
  kept it because the format's own ceiling capped the working set at
  ~320 KiB — that argument died with the ceiling. The disk cost of an
  edit stays flat, but CPU and RAM now scale with the namespace: 10⁶
  64-byte entries cost 1.6 s and 414 MiB in one `Tx`, or 97 s and
  2.9 GiB when written as 500 `Tx`es (each re-flattens everything).
  `Container::repack` inherits it for KV namespaces. Host-apps writing
  very large namespaces should prefer fewer, larger transactions and may
  still want to partition — now a performance choice rather than a hard
  limit. Numbers and method in
  `docs/en/contributing/benchmarks.md` (and the RU mirror).

  **Amended by HV-16 (above), which shipped in the same release.** The
  per-commit cost this entry leaves open is closed: `commit_tx` no
  longer materialises a namespace, so the RAM and CPU of a write track
  the change rather than the namespace, and partitioning a large
  namespace is no longer even a performance recommendation. The
  reader-side depth bound below is recomputed there (7 descents → 12),
  because the packing it is derived from changed.

  Covered by `crates/hidden-volume/tests/hv15_unbounded_depth.rs` (the
  exact entry counts that used to fail, a four-level tree built and read
  back entry by entry, 20 K log ids paginated forward and backward,
  levels collapsing again on delete, and the one-key edit cost at each
  depth) plus two forged-container tests in `space::integrity`: a chain
  deeper than the container could hold is refused by every walker at
  exactly one descent past the bound, and *the same chain verifies* in a
  container big enough for it — which is what makes the bound a budget
  and not a magic number.

### Security — audit follow-through

- **Changing one key no longer rewrites the whole namespace (HV-14).**
  `commit_tx` materialised a namespace's entire tree, applied the ops and
  rebuilt — and the rebuild reached the disk as well, so a one-key edit
  re-appended every leaf. Measured, `PaddingPolicy::None`, one Superblock
  replica: overwriting one key in a 4 000-entry namespace appended 82 chunks
  (336 KiB, a 4 601× amplification over the 73 bytes actually changed);
  appending one 200-byte message to an 8 000-message log appended 48 chunks
  (196 KiB). Those chunks are only reclaimed by the next `vacuum_orphans` at
  open, so a long-running session grew the container by that much per write.
  Index chunks are immutable and Merkle-addressed, and `pack_into_leaves` is
  deterministic, so a rebuild reproduces most leaves byte for byte: those are
  now pointed at instead of written again, keyed by the BLAKE3 the parent
  already stores as its Merkle link. Both cases drop to 4–5 chunks and stay
  there — flat in N. The fallback is the old behaviour: an edit where every
  leaf genuinely differs (a value-length change early in the key space) writes
  every leaf, exactly as before, so this cannot do worse.

  The in-memory flatten-and-repack stays, deliberately. The audit filed the
  finding as "O(N) CPU, RAM and write amplification"; measurement says only the
  third is real. Wall time is flat at 11–22 ms from N = 10 to N = 8 000 both
  before and after — a commit is fsync-bound and the tree work does not surface
  above the 3-fsync barrier. RAM is bounded by the format rather than by N:
  the writer emits one internal root over at most ~79 children, so the
  flattened working set cannot exceed roughly 320 KiB before `Error::IndexFull`
  stops the commit outright. Replacing the repack with incremental descent and
  split/merge would buy nothing measurable and would cost the greedy repack's
  self-compaction, which is what keeps delete/insert churn from fragmenting a
  namespace into that ceiling. Numbers, method and the still-open capacity
  ceiling are in `docs/en/contributing/benchmarks.md` (and the RU mirror).

  **Amended by HV-15 (above), which shipped in the same release.** The
  capacity ceiling this entry leaves open is gone, and with it the
  "RAM is bounded by the format" half of the argument for keeping the
  flatten-and-repack — a namespace can now be as large as the container,
  so the working set is too. The write-amplification finding and its fix
  are unaffected: node reuse still makes a one-key edit cost the path to
  it, at any depth.

  Forward secrecy is unchanged or better: a reused chunk is the live node, not
  a stale copy, so each commit leaves *fewer* superseded plaintexts for
  `vacuum_orphans` to scrub. Against a multi-snapshot observer the appended
  chunk count now tracks how localised a change was rather than how large the
  namespace is, and `PaddingPolicy::DEFAULT` still quantises the observable
  file size to 1 MiB buckets. No format change: the bytes, the node encodings
  and the Merkle links are identical — only which slot a `ChildPointer` names.

- **An abandoned async call no longer disappears without a verdict (HV-11).**
  Dropping the future of `AsyncContainer::run` / `AsyncSpace::run` detached the
  `spawn_blocking` task: the closure ran to completion, its commit landed, and
  the caller — who saw only `Elapsed` — had no way to find out. Rust cannot
  interrupt a running blocking closure, so the contract is now split along the
  line where cancellation stops being possible, instead of pretending it never
  ends. Before dispatch, abandonment is real: the new `OpLedger` admits one
  operation at a time per handle, so a caller that walks away while queued is
  never dispatched, and a closure that does reach a pool thread re-checks its
  cancel token as its first act — either way it reports `NeverStarted`, which
  is a proof of no effect. After dispatch, the drop fires the caller's
  `CancelToken` (the sync core's open-scan / repack / integrity checkpoints
  honour it) but the operation is reported as `Running` until it settles, then
  as `Succeeded` / `Failed` / `Lost`. New `abandoned_operations()`,
  `clear_settled_operations()` and `forgotten_abandonments()` on both async
  handles expose the ledger, which is capped at 128 records with the eviction
  count surfaced rather than swallowed. The blocking pool stops filling with
  work nobody awaits: queued callers wait as async tasks, not as parked pool
  threads.

  **Breaking:** `hidden-volume-async` — `AsyncContainer` and `AsyncSpace` carry
  a new private field, so struct-literal construction outside the crate is gone
  (there was none); calls that used to be dispatched-and-forgotten after a drop
  may now not run at all, which is the point. `hidden-volume-rt` —
  `BlockingFailure` gains a `NotStarted` variant, so exhaustive matches on it
  must be extended; it maps to `Error::Cancelled` / `HvError::Cancelled`, never
  to `Internal`. No on-disk format change; no FFI ABI change.

- **The `iter_log_*` decoded-batch cache is bounded in bytes and entries.**
  `MAX_DECODED_BATCH_LEN` caps **one** batch at ≈ 8.4 MiB; the cache kept one
  decoded batch per distinct `batch_slot` on the page, with no aggregate bound.
  A page of N entries naming N crafted batches held `N × 8.4 MiB` at once — and
  N is the caller's `limit`, with `iter_log` having no limit at all, so 512
  entries is ~4.3 GiB out of a container that fits in a couple of MiB of
  ciphertext. A per-item cap is not a budget. New `MAX_CACHED_BATCH_BYTES`
  (8 MiB) and `MAX_CACHED_BATCHES` (64) bound the cache; the entry cap is there
  because a near-empty batch weighs almost nothing yet still costs a map entry,
  which would move the cost into eviction bookkeeping. Eviction is
  least-recently-used and never fails a call: re-reading and re-decoding a
  batch is always possible, so no result depends on what stayed resident. Peak
  decoded bytes per call is now the budget plus the single batch being decoded
  — under ~16.4 MiB at any `limit`. New `log::batch_footprint` charges payload
  bytes plus per-record `Vec` overhead, so many-record tiny-payload batches are
  not counted as free.

- **Every B+ tree walker now shares a traversal guard.** `MAX_TREE_DEPTH`
  bounds how *deep* a walk goes and says nothing about how *wide*. Nothing in
  the encoding forces an `InternalNode`'s `child_slot` pointers to be distinct,
  so a node whose ~90 children all name the same next node is AEAD-valid,
  Merkle-consistent (the same child hash is correct under every parent that
  names it) and passed every check: at the depth cap that is `90³ ≈ 7.3 × 10⁵`
  chunk reads — an AEAD-decrypt and a BLAKE3 each — out of four distinct
  chunks, from a container of a few KiB. The prior finding reasoned about
  *cycles*, which the hash chain does rule out; a DAG costs the attacker
  nothing. `space/walk.rs` adds a visited set (a chunk reachable twice is a
  structural failure, not work to repeat — this also covers two children of one
  node sharing a slot, and two namespaces claiming one chunk) plus a budget
  equal to the space's owned-chunk count, and `verify_integrity`, `list`,
  `count`, `iter_log_after/before/range` and `vacuum_orphans` all go through
  it. `iter_log_*`'s `limit` was never a defence here: it bounds the output,
  not the chunk reads.
- **`verify_integrity` checks sibling key ranges.** Every key under
  `children[i]` must fall in `[children[i].first_key, children[i+1].first_key)`,
  the last child inheriting its parent's upper bound. `LeafNode::decode`
  enforces order only *within* one leaf, so sibling leaves could overlap or sit
  out of order with every hash still matching — and the entries in the overlap
  are unreachable through `Space::get`, which binary-searches `first_key` on
  the way down. `flatten_tree` would then reject the namespace at the next
  commit. That is the verified-but-unreadable state `verify_integrity` exists
  to rule out, and it reported healthy.
- **The integrity walk reads a log namespace once, not twice.** The hash
  descent and the `DataBatch`-pointer collection were separate full walks of
  the same tree; they are one walk now, and the batch pass shares the tree
  walk's guard, so a log pointer naming a chunk of its own index tree is
  reported as aliasing. Batch pointers from all log namespaces are pooled
  before deduplication, so a slot is read once per call rather than once per
  namespace.

- **`verify_integrity` checks that a log's DataBatch holds the record the index
  promised.** The walk collected every leaf's batch_slot, deduplicated the
  slots, and confirmed each chunk decoded — never that the `log_id` the leaf
  pointed at was inside it. A state where the index maps `log_id -> slot` and
  that batch never contained `log_id` is AEAD-valid, decodes cleanly, passed
  the walk, and then failed at `read_log`: the integrity check reported healthy
  about the one thing the reader could not do. Each `(log_id, batch_slot)` pair
  is now verified.
- **New `log::parse_log_id_key`.** Log keys are big-endian (so byte order
  matches numeric order in the B+ tree) and log values are little-endian.
  Neither decoder rejects the other's bytes — it returns a different, plausible
  number — so the pair now exists explicitly, with a test that pins it.

- **The open scan holds a bounded number of Superblock candidates.** Audit pass
  20 capped each candidate's payload to a canonical superblock length, but not
  how many there could be: a key-holder could forge one distinct-seq Superblock
  per scanned chunk and have `ScanAcc` hold every one of them at once, up to
  `MAX_OPEN_SCAN_CHUNKS`. Only the highest `MAX_SB_CANDIDATES` (64) are kept.
  The audit-D2 fall-through is unaffected — reaching the 64th candidate would
  mean 64 consecutive superblocks were forged or corrupt.
- **`open_with_keys` wipes the key buffer it is handed.** The `Vec<u8>` carrying
  a space's `aead_root` — the value that opens the space without its password —
  becomes ours when uniffi passes it in, and was dropped without zeroing,
  leaving it in a freed heap block for the life of the process. Both the sync
  and async constructors now wrap it in `Zeroizing`. The copy on the foreign
  side is the caller's to clear, and `space_keys` now says so instead of leaving
  it implied.

### Added — report5 follow-through

- **`AsyncSpaceHandle` reports its abandoned calls (HV-02).** A foreign
  caller that wraps `commit` in a timeout and walks away could not learn
  whether the transaction landed, and retrying a non-idempotent
  `append_log` on a guess corrupts the log. The mechanism for answering
  that shipped with HV-11 and was wired into `hidden-volume-async`; this
  crate kept calling the plain `hidden_volume_rt::run_blocking`, which
  builds a fresh **unbounded** ledger per call and destroys it on return,
  so every verdict was filed into an object that immediately ceased to
  exist. All eighteen async methods now run through the handle's own
  `Arc<OpLedger>`, via `run_cancellable` so the cancel token is the
  caller's rather than one the closure cannot see.

  New on `AsyncSpaceHandle`, all synchronous so they can be called from a
  `finally` / `catch` / `defer` path: `abandoned_operations()`,
  `clear_settled_operations()`, `forgotten_abandonments()`. New
  `AbandonedOperation` record and `OperationOutcome` enum across UniFFI.
  Branch on `may_have_mutated` — `false` only for `NeverStarted`, which is
  backed by a proof and is the one state where a blind retry is safe.

  The ledger's single admission permit is the availability half: a fan-out
  of abandoned calls now queues as cheap async tasks instead of occupying
  `spawn_blocking` threads that all end up waiting on one mutex.
  Constructors stay on the plain path — an abandoned constructor has no
  handle to report to.

- **Keys can be enumerated without materialising the namespace (HV-04).**
  The FFI `kv_keys` went through `Space::list`, which builds a
  `Vec<(Vec<u8>, Vec<u8>)>` of every entry, and then dropped the values
  while framing the keys. Its rustdoc meanwhile promised "the same O(N)
  index walk as `count`" with "values not decoded" — `count` peaks at one
  decoded node. On a namespace of message bodies that is the difference
  between holding the keys and holding the whole plaintext, on the device
  class this library exists for. Measured on 1500 × 2 KiB values: peak
  3.21 MB → 108 KB.

  - New `Space::list_keys` — the keys-only twin of `Space::list`. Each
    leaf's values are dropped as the leaf is consumed, so the walk really
    does peak at one node.
  - New `Space::list_keys_after(namespace, after, limit)` — a key cursor,
    the KV counterpart of `iter_log_after` and modelled on it. Bounded
    result; as there, `limit` bounds the output and not the chunk reads.
  - New FFI `SpaceHandle::kv_keys_page` / `MultiSpaceHandle::kv_keys_page`
    and their Dart bindings, for namespaces whose size the host app does
    not control. `kv_keys` keeps its signature and its meaning ("every
    key") — what changed is that it no longer reads the values to get
    there. Its doc now says what the call actually costs.
  - `Space::erase_namespace` enumerates by key too. A delete is addressed
    by key; the values it used to materialise alongside them were held for
    the length of the whole transaction and never looked at.

  Not breaking: `kv_keys` is unchanged on the wire, and the additions are
  additive. The remaining HV-04 sites (`repack`, `vacuum`) still walk
  whole namespaces and are untouched.

### Fixed — report5 follow-through

- **The third `flock` site is taken on Android too (HV-09).** The tmp-file
  pin `atomic_rewrite_under_source_lock` holds through the rename — the
  guard against someone substituting the tmp between the writer finishing
  and the rename landing — sat behind `#[cfg(not(target_os = "android"))]`
  with an inline `File::try_lock`. On Android the pin was therefore not
  taken at all, and the comment beside it recorded the gap as a follow-up
  rather than closing it. The reason for the `cfg` was real (std's
  `try_lock` answers `Err(Unsupported)` there), and it was solved back in
  v1.0 for the two *container* locks by routing them through `flock(2)` via
  libc; this site was simply never wired to the same helper. It now calls
  `container::file::try_lock_exclusive`, which is the crate's one exclusive
  lock dispatcher, so Android gets the same real `flock(LOCK_EX | LOCK_NB)`
  as every other Unix and the "filesystem does not honour flock" degradation
  is identical on all of them.

- **`derive_master_key` validates its own parameters (HV-05).** The public
  function's whole job is to burn CPU and RAM in proportion to its
  arguments, and it delegated the bounds check to its callers — the rustdoc
  said `params` "MUST have already passed `Argon2Params::validate`". Every
  container path did; nothing made a direct caller. `m_cost_kib` one KiB
  above the ceiling is a gibibyte of Argon2 working set with no error in
  sight, and `t_cost` has no upper bound in the `argon2` crate at all. It
  now calls `validate()` first. A hostile container was never able to reach
  this (header params are validated on open, before any derivation), so
  what is closed is misuse by this crate's own callers.

  `crypto::kdf`'s new `master_key_derivation_validates_params` picks every
  fixture so that *this crate's policy is the only thing that rejects it*
  and asserts the `argon2` crate accepts each one — a `u32::MAX` fixture
  would have tested the dependency's bounds and passed with the gate
  removed. `tests/v3_key_schedule.rs`'s cross-generation assertion moved
  into the module as `version_word_changes_the_master_key`, since a
  synthesised `format_version = 2` / `4` is exactly what the new gate
  refuses; what the integration test checks from outside is the gate.

- **A container can be addressed by a bare file name again.** `Path::parent()`
  answers `Some("")` — not `None` — for `"store.hv"`, so the
  `parent().unwrap_or(Path::new("."))` in both parent-directory fsyncs never
  fired and the fsync opened `""`, i.e. ENOENT. `"./store.hv"` worked;
  `"store.hv"` did not. The damage was not a skipped fsync:
  `Container::create` returned `Err(Io(NotFound))` **and** its `UnlinkOnDrop`
  guard then removed the container it had already written, so the caller was
  left with neither a handle nor a file; `change_passwords` and
  `compact_known` returned `RenameVisibleDurabilityUncertain`, which on a
  rotation reads as a durability caveat but meant the password had not been
  changed at all — the caller who had just rotated a leaked password was told
  something far milder than the truth. Regression from the HV-16 hardening
  that introduced the strict create-side fsync. The empty-parent case now
  lives in one `parent_dir_for` helper that all three call sites share, rather
  than in a condition each of them has to remember.

## [1.2.3] — 2026-07-29

Security and correctness release from a read-only audit pass. The on-disk
format and the public Rust + FFI API are unchanged; `PARAMS_VERSION` stays
at 3.

### Fixed

- **A failed `create` left the path occupied.** The header is written first and
  the file is opened with `create_new`, so a create that then failed — an
  over-large `initial_garbage_chunks`, ENOSPC — returned Err and left a
  4096-byte stub. The retry a caller obviously makes next hit AlreadyExists, and
  the path stayed unusable until someone deleted a file they never knowingly
  made. The partial file is now removed before the error is returned.
- **The constant-time open modes silently took the checkpoint fast path.**
  `open_space_constant_time` publishes one property — the host's wall-clock does
  not leak which space, or none, matched — and the fast path visits a working
  set instead of every slot, so a correct password finished early while a wrong
  one paid the full sweep. Per-chunk equalisation cannot hide a signal carried
  by the NUMBER of chunks visited. The CT modes now always take the full scan;
  the default path keeps the fast open unchanged, so nobody who did not ask for
  equal timing pays for it. Its callers already accept roughly double the open
  time, which is what they were buying.
- **`repack` rewrote the container it was only supposed to read.** An
  out-of-place repack documents the source as untouched, but opened it writable
  and `open_space` runs the post-open vacuum — so taking a backup altered the
  original, and it no longer hashed to what it was taken from. The source is now
  opened read-only; a shared lock still excludes writers, so the consistency the
  exclusive open gave is unchanged.
- **`hv inspect` mutated the container it was inspecting**, for the same reason:
  a writable open runs the vacuum and the checkpoint self-heal. Read-only now.
- **`vacuum_orphans` kept re-reading slots it had already scrubbed.** The
  `owned_slots` retain was gated on `scrubbed > 0`, so a pass that only found
  already-scrubbed slots (the `AuthFailed` arm) dropped none of them: every
  later open re-read and re-failed on the same dead slots and the checkpoint
  kept carrying them. The fsync stays conditional; the retain no longer is.
- **`MultiSpace` never scrubbed the values a previous session deleted.** A
  writable `Container::open_space*` runs `vacuum_orphans` as part of the open —
  the index nodes an update or delete retires stay valid AEAD, so anyone who
  later obtains the password and an old snapshot of the file can decrypt them
  back. `MultiSpace::open_space` and `open_space_constant_time` went straight
  from the recovery scan to a stored `SpaceState` and skipped it, so a host that
  keeps every identity open at once — the reason `MultiSpace` exists — never
  scrubbed anything at all. Both now run the same finaliser. Read-only hosts are
  left alone: `vacuum_orphans` answers `Err(ReadOnly)` under a shared lock, and
  refusing to open a container mounted read-only would be the worse bug.
- **A new container was created at the process umask** (0644 on a typical
  desktop) rather than owner-only. The contents are encrypted either way; a
  deniable container whose existence and size any other local account can stat
  defeats the point, and a readable one can be copied for an unhurried offline
  attack. Now `0o600`, set through the open flags so there is no window in which
  the file exists at the looser mode.

## [1.2.2] — 2026-07-28

Bug-fix release. The on-disk format and the public Rust + FFI API are
unchanged; `PARAMS_VERSION` stays at 3.

### Fixed

- **A confirmed commit could be lost silently.** Both Superblock publishers
  append N replicas and adopt the new superblock only after the final `fsync`.
  A failure in between — ENOSPC on the second replica on a nearly-full disk, a
  failed `fsync` — left a replica of seq N+1 on disk while `superblock.seq`
  still named the previous era. The next commit derived its seq from that stale
  value and published a DIFFERENT payload under the same N+1, and the open scan
  resolved a same-seq collision by taking the LOWER slot, i.e. the older of the
  two. A commit that had already returned `Ok` therefore disappeared, and
  nothing detected it: the surviving superblock is self-consistent so
  `verify_integrity` passes, and N+1 is present in `commit_history` so the
  multi-device triage in the sync guide sees no fork. The bit-equality
  invariant the scan relied on was held only by a `debug_assert`, compiled out
  of release builds.

  `SpaceState` now tracks the highest seq that may already be on disk. Both
  publishers burn that number before their first append and derive the next seq
  from it, so a partially-published seq is never handed out again. It is seeded
  on open from the highest seq seen anywhere in the scan rather than from the
  winning superblock, so a seq burnt by a crash is skipped across restarts too.
  Publishing a self-heal checkpoint bumps and publishes the superblock seq, so
  that path carries the same rule despite being documented as an optimisation
  hint.

- **Same-seq collision resolution is now explicit and last-writer-wins.** Slots
  are append-only, so the higher slot is the later commit; first-wins silently
  reverted to the older one. This also makes the two scan paths agree —
  `find_latest_superblock_reverse` scans backward and so already kept the
  highest slot. Containers written by older builds that already hold a
  divergence now recover the newer commit instead of the older.

- A parser-fuzz test passed for the wrong reason: `header_decode_short_input`
  looped to a literal 80, the v2 header length, while a v3 header is 48 — sizes
  48..79 had stopped exercising the length gate and were failing later, on
  zeroed Argon2 params. The boundary is now derived from a real encoded header,
  with an explicit one-byte-short case.

### Documentation

- Threat model §3: the same-seq rule is documented (I2 specified max-seq but
  was silent *within* a seq — exactly the underspecification the defect above
  exploited), and two stale code references are corrected —
  `ContainerFile::write_slot` does not exist, and `Space::owned_slots` is a
  private field whose accessor is `audit_owned_chunk_count`.

## [1.2.1] — 2026-07-16

Corrective release that restores three signed commits accidentally omitted
from the `v1.2.0` tag while its changelog and host integrations already
depended on them.

### Fixed

- Restored true per-record log deletion across core, FFI, and Flutter APIs.
- Restored headless-bundle FFI loading.
- Restored race-free force-loading for the iOS XCFramework.
- Synchronized the public-API snapshot with the restored surface and fixed the
  fully qualified FFI rustdoc link used by the Linux `-D warnings` gate.

## [1.2.0] — 2026-07-15

Feature release for multi-space host applications and authenticated fast-open
checkpoints. The container `format_version` remains 3; see the compatibility
note below for checkpoint-aware writers and older v3 readers.

### Added

- **True per-record log deletion (`Tx::delete_log`, FFI `WriteOp::DeleteLog`,
  Flutter `HvWriteOpDeleteLog`).** Removes the logical id from a Log
  namespace's B+ index instead of replacing its payload with an empty record,
  so bounded host-app chunk stores can reclaim unique-id capacity without
  erasing the whole namespace. The prior DataBatch remains an orphan until
  `vacuum_data_batches` / `compact_known`, preserving the append-only commit
  invariant and existing forensic-erasure contract.

- **KV key enumeration over FFI (`SpaceHandle::kv_keys`,
  `MultiSpaceHandle::kv_keys`).** Returns every key of a namespace,
  framed as `[count u32 LE] ( [len u32 LE][key bytes] )*` inside one
  `Vec<u8>` so the handwritten Dart bindings decode it without a uniffi
  sequence type; values are not transferred. Rationale: a namespace's
  2-level B+ index has a hard entry budget (`Error::IndexFull`), and a
  host app garbage-collecting stale per-content bookkeeping keys (which
  on aged stores wedged every new write) must be able to enumerate them
  to delete them. Same O(N) index walk as `count`; core `Space::list`
  already existed — this exposes keys through the FFI and the Flutter
  plugin (`HvSpace.kvKeys` / `HvMultiSpace.kvKeys`).

- **Fast-open checkpoint — O(working-set) open (behavior).** Activates
  the checkpoint groundwork below: opens now run in O(working-set +
  tail) instead of O(total slots) once a checkpoint exists.
  - **Reader (`crate::open`).** Before the full sweep the sequential
    scan attempts a fast path: a bounded reverse scan recovers a recent
    superblock's `checkpoint_slot`, the Checkpoint chain yields
    `(cp_high_water, owned_below)`, and only `owned_below`
    (re-validated by trial-decrypt) plus the fresh tail are scanned.
    Any inconsistency declines to the full sweep — which is always
    correct — so the reconstructed state is provably identical to a
    full scan (owned_slots, commit_history, superblock, data). The
    parallel / mmap scan modes are unchanged (full scan).
  - **Writer (`crate::space::checkpoint`).** `commit_tx` never writes a
    checkpoint (zero per-commit overhead — it only carries the pointer
    forward). A lazy self-heal runs at most once per open, after
    `vacuum_orphans`, gated by a size floor + a tail-growth threshold
    (amortized disk writes). It snapshots the post-vacuum owned set,
    writes a fresh Checkpoint chain (multi-chunk, §4.5), publishes a
    bumped-seq superblock, and scrubs the chain it supersedes.
  - **Forward-secrecy preserved.** The reconstructed `owned_slots` is
    complete, so `vacuum_orphans` / `vacuum_data_batches` scrub exactly
    the orphans a full-scan-driven vacuum would.
  - **Timing / deniability.** The skip is post-authentication: without
    the key the superblock/checkpoint can't be decrypted, so a wrong
    password pays the full scan (no fast-vs-slow password oracle), and
    a decoy open never touches another space's slots (its wall-clock
    reflects only the decoy's own working set, never hidden-space
    existence). Each Checkpoint chunk is AEAD-sealed, same `CHUNK_SIZE`
    as any chunk. The constant-time scan still equalizes MAC-fails on
    the (reduced) scanned set.

- **Fast-open checkpoint — format groundwork (inert).** The open-scan
  is O(total slots): a long-history / low-utilization container (e.g.
  a messenger store bloated by per-commit padding) pays a full
  trial-decrypt sweep of every slot on each unlock. This change lands
  the *inert* on-disk groundwork for an O(working-set) open; the
  acceleration behavior (self-heal writer + fast-path reader) follows
  in a companion change. Three additive, forward-inert pieces:
  - `ChunkKind::Checkpoint = 0x07` — a new (additive, `#[non_exhaustive]`)
    chunk kind reserved for the open-scan acceleration structure. Not
    yet produced by any writer.
  - `Superblock` gains an optional `checkpoint_slot: u64` pointer with a
    **canonical 48/56-byte codec**: `NO_RECORD` encodes as the 48-byte
    short form, byte-identical to a pre-checkpoint v3 superblock;
    any other value encodes as a 56-byte long form (short form ‖
    pointer). `decode` accepts both and rejects the non-canonical
    "56-byte-but-NO_RECORD" form, preserving the strict-length
    canonical-uniqueness contract (audit pass 19). `commit_tx` carries
    the pointer forward verbatim at zero extra disk cost. `Superblock::encode`
    now returns `Vec<u8>` (was `[u8; 48]`); new
    `Superblock::ENCODED_LEN_WITH_CHECKPOINT` (= 56) and
    `Superblock::is_valid_encoded_len`.
  - The open-scan superblock length-gate now accepts both canonical
    lengths {48, 56} on all three scan paths (sequential / parallel /
    mmap) — and the mmap path gains the length-gate it previously
    lacked (a memory-bound parity fix, audit pass 20).
  - **No `format_version` bump (stays 3).** The version is
    cryptographically bound into the key schedule
    (`derive_master_key`), so bumping it would orphan every existing
    container. The checkpoint is therefore an *optional, forward-inert
    v3 optimization hint* (AEAD-sealed under the per-space key, opaque
    to a foreign adversary; a reader that ignores it is always
    correct), not a format generation. Existing containers read back
    byte-identically; a container that has *been* checkpointed by a
    checkpoint-aware writer is not readable by a pre-checkpoint binary
    (one-way forward-incompat within v3 — acceptable for this
    project's single-app deployment, see `docs/en/reference/format.md` §8).

### Security

- **Release dependency refresh.** Updated `crossbeam-epoch` to 0.9.20,
  `memmap2` to 0.9.11, and transitive `anyhow` to 1.0.103 to clear the current
  release advisories.

- **FFI open paths now use the constant-time space scan (F-TM1 mitigation).**
  The constant-time open family already existed in the core
  (`Container::open_space_constant_time` and friends) but was opt-in, so the FFI
  — the surface used by the Flutter/mobile deniability app — still opened via the
  early-exit scan, leaving an unlock-timing oracle that an observer able to
  measure open latency could use to distinguish a real space, a decoy, or a wrong
  password. `SpaceHandle::open` / `open_with_keys` (sync **and** async) and
  `MultiSpaceHandle::open_space` now route through the constant-time scan. No FFI
  C-ABI / signature change (the hand-written Dart bindings are unaffected); only
  the scan's timing profile changes. Cost: the equalizer roughly doubles
  open-time on garbage-heavy containers (negligible on the small containers a
  client app holds). New helpers `OwnedSpace::wrap_open_constant_time` /
  `wrap_open_with_keys_constant_time` (rt) and `MultiSpace::open_space_constant_time`
  (core) back this; the original non-CT `wrap_open*` / `MultiSpace::open_space`
  remain for callers that want the faster early-exit scan (e.g. the standalone
  async crate).

### Performance

- **Root-payload cache in `Space::load_prior_roots`.** The read-hot namespace
  lookup path (`get` / `list_namespaces` / `find_root_slot` plus the commit and
  vacuum validation paths) re-read and re-AEAD-decrypted the *same* `Commit`
  chunk on every call, so a read sweep over N namespaces paid N redundant
  XChaCha20-Poly1305 opens of one chunk. `SpaceState` now caches that chunk's
  decrypted payload bytes keyed by `superblock.seq`; subsequent lookups in the
  same commit era decode straight from the cache (pure parsing — no crypto, no
  disk read). The `seq` equality gate plus an explicit clear in `commit_tx`
  guarantee a stale era is never served (`seq` is strictly monotonic per space),
  and the bytes are held in `Zeroizing` and scrubbed on drop / replace, so
  decrypted index data never outlives its commit era in cleartext. Transparent —
  no on-disk format or public-API change. Regression test
  `tx_multi.rs::roots_cache_transparent_across_reads_and_commits`.

### Added

- **Core `MultiSpace` — host several spaces of ONE container open at once** under
  the file's single exclusive lock. The single-space `Container::open_space`
  returns a `Space` that borrows the file for its whole lifetime (one space at a
  time); `MultiSpace` instead holds each space's recovered `SpaceState`
  *detached* and binds one to the file only for the duration of a single
  operation (`MultiSpace::with_space`), so all spaces stay open while writes are
  serialized in-core (which is what the single-writer lock requires). This is the
  storage foundation for a host that runs several identities simultaneously (one
  network node per identity) over one deniable container. New seam on `Space`:
  `from_state` / `into_state` (crate-internal). Additive — the single-space API
  is unchanged. New integration test `multi_space.rs` (two spaces coexist +
  isolate + persist; wrong-keys → AuthFailed; unknown id → Malformed).
- **FFI `MultiSpaceHandle`** — exposes `MultiSpace` over the C ABI: `open(path)`
  takes the container lock; `open_space(keys) → space_id`; then per-space
  `commit` / `get` / `read_log` / `iter_log_range` / `count` / `commit_seq` /
  `space_keys` / `vacuum_data_batches`, each addressed by `space_id`. Lets a
  host run several identities at once over one container from the FFI. Sync-only
  for now (async mirror deferred — no consumer yet). Round-trip test in
  `tests::multi_space_handle_hosts_two_spaces_at_once`.
- **FFI `SpaceHandle::open_with_keys` + `SpaceHandle::space_keys`, and core
  `Space::space_keys`** — the master-space primitive. `space_keys()` exports an
  open space's `SpaceKeys` as 64 opaque bytes (`container_id ‖ aead_root`);
  `open_with_keys(path, keys)` reopens that space from those bytes alone,
  skipping Argon2 (delegates to the existing `Container::open_space_with_keys`).
  This lets a host-app's *master* space store its children's keys (inside its
  own deniable space) and switch between identities without a per-child password
  prompt. Wrong length → `Malformed`; non-matching keys → `AuthFailed` (same
  indistinguishable path as a wrong password, so the count of spaces never
  leaks). The bytes are the per-space decryption root — sensitive, never logged,
  to be kept only inside another deniable space. Additive (no format/existing-API
  change); backed by the rt helper `OwnedSpace::wrap_open_with_keys`.
- **FFI `SpaceHandle::add_space` (+ async `AsyncSpaceHandle::add_space`)** — add a
  new parallel, deniable space to an *existing* container, keyed by a new
  password. Where `create` bootstraps a fresh container file (and fails if one
  exists), `add_space` opens the container already on disk and bootstraps an
  additional space inside it (`Container::open` + `create_space`). This is the
  FFI primitive for host-apps that hide several identities in one file; it
  returns `SpaceAlreadyExists` on password collision so the caller can fall back
  to `open`. Additive (no format/existing-API change); the sync↔async 1:1 mirror
  is preserved.

## [1.1.0] — 2026-06-11

audit pass 20 — soundness, error-fidelity, walker-consistency,
doc-actualization. No on-disk format change (format stays
`format_version = 3`). The single breaking change is confined to the
internal `hidden-volume-rt` crate (`space_mut` → `with_space_mut`),
which is documented as not-for-end-user-consumption; the frozen
`hidden-volume` + `hidden-volume-ffi` public API gains only the
additive `HvError::ContainerTooLarge` variant.

### Security — audit pass 20

- **`hidden-volume-rt::OwnedSpace::space_mut` was unsound** and is
  replaced by a higher-ranked closure accessor `with_space_mut`. The
  old signature `&'a mut self -> &'a mut Space<'a>` let region
  inference unify the inner lifetime across two `OwnedSpace` values,
  so `mem::swap(a.space_mut(), b.space_mut())` could exchange the two
  `Space`s between containers in 100% safe code — dropping one then
  freed the `Box<Container>` the other borrowed (use-after-free). The
  `for<'a> FnOnce(&mut Space<'a>) -> R` bound makes the borrow
  un-nameable and unswappable. The async/FFI wrappers (the only
  shipped consumers) were never reachable for the swap, but
  `hidden-volume-rt` is a published `1.0.0` crate with a public API.
  *Breaking* for any direct `hidden-volume-rt` consumer (an explicitly
  internal crate).
- **`derive_master_key` / `SpaceKeys` now have known-answer tests**
  (`tests/v3_key_schedule.rs::key_schedule_known_answer_vectors`). The
  v3 key schedule is the on-disk format's cryptographic identity, yet
  no test pinned the actual derived bytes — a refactor of a kind-tag,
  context label, or LE-encoding could silently brick every container
  while passing the suite. The bytes are unchanged; the format stays
  `format_version = 3`.

### Fixed — audit pass 20

- **FFI dropped `Error::ContainerTooLarge` into `Internal("unknown
  error variant")`.** Added `HvError::ContainerTooLarge { extra, cap }`
  + an explicit `From` arm + the Dart `_hvErrorKinds` entry. The
  write-side budget error is caller-actionable (shrink
  `initial_garbage_chunks` / pick a lighter padding policy) and now
  surfaces as a typed variant instead of "internal bug". *Additive*
  to the `#[non_exhaustive]` `HvError`.
- **`Space::get` accepted a Leaf one level deeper than every other
  walker.** The `MAX_TREE_DEPTH` check sat inside the `Internal` arm,
  so a forged tree presenting a `Leaf` at depth 4 returned a value
  while `list` / `count` / `iter_log_*` / `verify` rejected it. Moved
  the check to loop entry, restoring the documented "identical across
  read paths" invariant.
- **Log read paths (`iter_log_*`, `read_log`) relied on the
  8-byte-key / DataBatch-pointer shape heuristic** instead of the
  persisted `NamespaceKind` byte (R-NSKIND parity gap — vacuum/repack
  were already kind-driven). A KV namespace holding 8-byte keys *and*
  values gave an unpredictable error taxonomy; it now returns a clean
  `WrongNamespaceKind` before any leaf walk.
- **A forged tree with overlapping leaf ranges could commit an
  unsorted leaf** (per-node decode checks only intra-leaf order; the
  release `LeafNode::encode` only `debug_assert`s global sortedness),
  bricking the namespace on the next read. `flatten_tree` now rejects
  a non-globally-sorted / duplicate-key flatten.
- **Out-of-range slot pointers reported `Error::Internal`** (reserved
  for crate bugs) instead of `Error::Malformed`; a decrypted-but-
  corrupt or forged pointer is input-driven. `read_slot` /
  `read_slot_concurrent` now return `Malformed`.
- **`run_blocking` mapped runtime-shutdown cancellation to
  `Internal`** despite `HvError::Cancelled` existing; now maps to
  `Cancelled`.
- **`open` retained every distinct-seq Superblock-kind payload
  unbounded** — a key-holder could force tens of GiB of retention.
  Candidates are now length-gated to `Superblock::ENCODED_LEN`
  (behaviour-preserving; `decode` rejected the rest anyway).
- **`PasswordRotation` derived `Debug`**, which would print both
  passwords; replaced with a redacted manual impl (mirrors the
  pass-17 no-`Clone` rationale).
- **Flutter platform unit tests asserted the removed
  `getPlatformVersion` MethodChannel handler** and would fail to
  build against the no-op plugin shells; rewritten as registration
  smoke tests.
- **Doc-actualization**: `format.md` IndexNode discriminators
  corrected to the real on-disk bytes (`0x00 = Leaf`, `0x01 =
  Internal`; the doc said `0x01`/`0x02`) and the unaligned-tail
  invariant corrected to "tolerated" (EN+RU); `operations.md` Argon2
  migration recipe switched from a racy manual `repack`+`rename` to
  the in-place `change_passwords` primitive, plus empty-password-list
  data-loss-by-design and stale-temp-cleanup notes (EN+RU); stale
  `uniffi 0.28` → `0.31`, Flutter "in progress" → "implemented",
  branch-CI-intentionally-disabled, and repo-URL fixes across docs,
  comments, and plugin metadata.
- **`cargo deny` duplicate-dependency warnings** (`cpufeatures`,
  `getrandom`, `thiserror`, `winnow`) documented in `deny.toml`;
  `head -n -1` (unsupported on BSD/macOS) replaced with `sed '$d'`
  in the build scripts; dead test helper + `LD_LIBRARY_PATH` placebo
  removed.

### Fixed

- **`fuzz-smoke` CI job was silently non-functional since v1.0.0.**
  `crates/hidden-volume/fuzz/Cargo.toml` still pinned
  `hidden-volume = { version = "0.1.0" }` while the crate was bumped
  to `1.0.0` at release; the fuzz harness is workspace-`exclude`d so
  the version bump skipped it and no regular CI job builds it. Every
  `cargo fuzz` invocation failed dependency resolution
  (`candidate versions found which didn't match: 1.0.0`). Because the
  `fuzz-smoke` job is `continue-on-error: true`, the breakage never
  blocked a release — it just went red unnoticed. Bumped the pin to
  `1.0.0` (matching the other three workspace crates); all three fuzz
  targets now build and run clean (plaintext_decode 105M runs,
  decoder_family 610K, container_open 2.58M, zero crashes). The fuzz
  lockfile is now gitignored as a build byproduct.

## [1.0.0] — 2026-05-28

**Production release. On-disk format and public API are now frozen.**

Twelve months from project bootstrap through v0.1 → v0.8 → v0.1.0
(first SemVer tag, 2026-05-10) to v1.0.0 (this tag). Cumulative
audit count: **19 in-tree passes**, 0 unaddressed critical / high
findings. **397 tests** green across the workspace at the cut
(`cargo test --workspace --all-features`). The Flutter plugin
exits `experimental/` only when uniffi-dart matures (tracked as
post-1.0 packaging, not v1.0-blocking).

What "frozen" means concretely:

- **On-disk format**: `format_version = 3` is the v1.0 generation.
  Future readers must continue to read v3 containers without
  modification for at least one major-version cycle (v2.x reads
  v3; v3.x may drop v3 support). Format breaks require a major
  bump and ship a migration tool. See
  [`docs/en/reference/format.md`](docs/en/reference/format.md) §7.
- **Public Rust API**: every `pub` item in `crates/hidden-volume/src/`
  (Container, Space, Tx, CancelToken, SpaceKeys, error variants,
  feature-gated entry points) is part of the SemVer contract. The
  snapshot is locked down in
  [`docs/en/reference/api-surface.txt`](docs/en/reference/api-surface.txt);
  `scripts/dump-public-api.sh --check` is a release-blocking gate.
- **Public FFI API**: every `#[uniffi::*]`-annotated item in
  `crates/hidden-volume-ffi/src/lib.rs` is part of the contract.
  Generated bindings (Kotlin / Swift / Python / Ruby) ship from
  the same source.

### Added — TM1 CT companions for parallel-scan and mmap

The threat-model §4.4 scope previously read "Sequential-scan only"
— this v1.0 ships the missing companions:

- [`Container::open_space_parallel_constant_time`](crates/hidden-volume/src/container/mod.rs)
  + `_with_keys_parallel_constant_time` sibling. Parallel-scan
  speedup + per-chunk ChaCha20 timing equalizer.
- [`Container::open_space_mmap_constant_time`](crates/hidden-volume/src/container/mod.rs)
  + `_with_keys_mmap_constant_time` sibling. Zero-allocation mmap
  read path + the same equalizer.

Both reuse the existing `equalize_timing_via_chacha20` primitive
on every MAC-fail (introduced by audit pass 19 round 1). New tests
in `tests/parallel_scan_constant_time.rs` and
`tests/mmap_scan_constant_time.rs` lock down the equivalence of
recovered `Space` state across scan modes (2 + 2 = 4 new tests).
The dead `try_decrypt` wrapper that round-1 left feature-cfg-gated
was removed; both `scan_and_recover_parallel` and
`scan_and_recover_mmap` now call `try_decrypt_with_options` directly,
mirroring the sequential path's plumbing. Threat-model §4.4 and
`docs/{en,ru}/reference/format.md` updated to reflect the shipped
shape (no more "sequential only" caveat).

### Breaking — v3 format-bump (2026-05-28)

`format_version` bumped 2 → 3. v2 containers are not readable by v3
builds and v3 containers are not readable by v2 builds. The reject is
**doubly bound**: by `Argon2Params::validate` policy gate AND by the
v3 cryptographic version-binding step in the key chain. Pre-1.0 — no
in-place migration tool ships; cross-version transitions go through
the export-and-reimport recipe documented in
[`docs/en/guide/migration.md`](docs/en/guide/migration.md).

Three independent hardenings shipped together as a single
format-bump (saves users from a double-migration through v3a/v3b):

- **#8 — Kind-tag bytes in BLAKE3 inputs.** Every BLAKE3-keyed input
  in the key chain now starts with an explicit kind-tag byte:
  `SUBKEY_KIND_TAG = 0x01` for [`derive_subkey`](crates/hidden-volume/src/crypto/derive.rs)
  inputs, `CHUNK_KEY_KIND_TAG = 0x02` for [`derive_chunk_key`](crates/hidden-volume/src/crypto/derive.rs).
  Replaces the audit-pass-7-D3 length-distinguishes convention with
  an explicit content-based domain separator. P-LOW2 closed.
- **#9 — Cryptographic version-binding (closes pass-18 M5).** [`derive_master_key`](crates/hidden-volume/src/crypto/kdf.rs)
  now folds `params.version` into the master key through a
  post-Argon2 BLAKE3 step: `versioned_master = BLAKE3-keyed(argon_out,
  b"hv/v3/master" || u32_le(params.version))`. Cross-version key
  reuse is closed cryptographically, not only by `validate()`
  policy. As a side effect F-PAD (audit pass 9) is **reclassified
  from silent privacy-degradation to DoS-class visible failure**:
  the `padding_policy_index` byte at bits 16..24 of `params.version`
  is now part of the BLAKE3 input, so a tamper produces a different
  `master_key` ⇒ next open hits `Error::AuthFailed`. The DoS
  surface remains acceptable (any cleartext-header tamper can deny
  open); the privacy surface is closed. See
  [`docs/en/security/threat-model.md`](docs/en/security/threat-model.md) §4.1.
- **#10 — Per-space derived `container_id` (closes D1-A2
  fingerprint).** `container_id` is no longer stored in the
  cleartext header. [`SpaceKeys::from_master`](crates/hidden-volume/src/crypto/derive.rs)
  derives it per-space alongside `aead_root` from the versioned
  master key. Cross-container relocation defense is preserved
  (different salts ⇒ different master_keys ⇒ different
  container_ids), and the cleartext header no longer carries any
  per-space identifier. `HEADER_LEN`: 80 → 48.

Public API impact:

- [`Header`](crates/hidden-volume/src/container/header.rs) struct
  loses its `container_id` field; the only fields are now `salt` and
  `params`.
- [`SpaceKeys`](crates/hidden-volume/src/crypto/derive.rs) gains a
  `container_id: [u8; 32]` field; `SpaceKeys::from_master(versioned_master)`
  is now the construction entry point.
- [`HEADER_LEN`](crates/hidden-volume/src/lib.rs) = 48 (was 80);
  `HEADER_CONTAINER_ID_OFFSET` / `HEADER_CONTAINER_ID_LEN` removed.
- [`HeaderInfo` (FFI)](crates/hidden-volume-ffi/src/lib.rs) loses
  its `container_id_hex` field; `hv info` CLI no longer prints
  `container_id:`.
- All docs (`docs/en/reference/format.md`, `docs/ru/...`,
  `docs/en/security/threat-model.md`, `docs/en/security/audits/self-audit.md`,
  `docs/en/security/audits/format-fuzzing.md`, `docs/en/guide/migration.md`,
  RU mirrors) actualized for v3 layout.

### Added — TM1 timing-oracle partial mitigation (2026-05-28)

Opt-in constant-time scan path closes the dominant component of the
F-TM1 leak documented in
[`docs/en/security/threat-model.md`](docs/en/security/threat-model.md) §4.4.

- New [`Container::open_space_constant_time`](crates/hidden-volume/src/container/mod.rs)
  + `open_space_with_keys_constant_time`. On MAC-fail, runs
  `crypto::aead::equalize_timing_via_chacha20` over the AEAD body
  length to equalize the dominant per-chunk cost component.
- Honest scope (audit pass 19 follow-through): the equalizer closes
  the ChaCha20-body component (~1-3 µs) of the bench-measured
  ~40 µs/chunk swing on M5 Pro. The remaining parsing/allocation/
  `owned_slots.push` overhead is **not** equalized — host-apps
  needing full constant-time should additionally pad the post-open
  processing externally. Documented in detail in the threat-model
  honest-scope table.
- New direct dep `chacha20 = "0.9"` to drive the equalizer without
  going through the full AEAD machinery.
- Default callers should stick with `open_space`; the constant-time
  path roughly doubles open-time on garbage-heavy containers.
- New test [`tests/constant_time_scan.rs`](crates/hidden-volume/tests/constant_time_scan.rs)
  + benches in [`benches/timing_oracle.rs`](crates/hidden-volume/benches/timing_oracle.rs)
  extended with multi-variant `ScanMode` enum (sequential / parallel
  / mmap) confirming the leak shape is uniform across modes (closes
  audit pass 5 SC-INFO2 hypothesis).

### Added — B+ tree depth cap (2026-05-28, F-A5)

New `pub(crate) const MAX_TREE_DEPTH: u8 = 3` in
[`crates/hidden-volume/src/space/index.rs`](crates/hidden-volume/src/space/index.rs).
Every recursive B+ tree walker now caps its descent at this depth:

- [`Space::get`](crates/hidden-volume/src/space/mod.rs) (KV lookup);
- `collect_leaves_at` / `count_leaves_at` ([`space/mod.rs`](crates/hidden-volume/src/space/mod.rs));
- [`log_iter::*`](crates/hidden-volume/src/space/log_iter.rs) (after / before / range);
- [`integrity::*`](crates/hidden-volume/src/space/integrity.rs) walkers;
- [`vacuum::*`](crates/hidden-volume/src/space/vacuum.rs).

A pathological cyclic Internal→Internal chain (T2 file-modification
adversary scenario) trips `Error::Malformed("tree depth exceeded
MAX_TREE_DEPTH")` after at most this many descents. Writer-side
invariant continues to guarantee depth ≤ 2 in well-formed containers.

### Added — Self-audit dossier + signed-release pipeline (2026-05-28)

External paid audit (Trail of Bits / Cure53 / NCC class) is not
planned for this project (anonymity + no-budget rationale). The
substitute is a documented self-audit + community-disclosure path.

- New [`docs/en/security/audits/self-audit.md`](docs/en/security/audits/self-audit.md)
  dossier covering: dependency provenance, primitive choices, all
  security invariants (D1 / D2 / I1-3 / R1 / M1 / C1) with code
  references, open items and acknowledged gaps, "how to verify
  yourself" procedures, community bug-bounty terms.
- 5-pass deep-review series committed alongside the dossier:
  [`adversarial-stance.md`](docs/en/security/audits/adversarial-stance.md),
  [`primitive-level.md`](docs/en/security/audits/primitive-level.md),
  [`side-channel-surface.md`](docs/en/security/audits/side-channel-surface.md),
  [`format-fuzzing.md`](docs/en/security/audits/format-fuzzing.md),
  [`threat-model-challenge.md`](docs/en/security/audits/threat-model-challenge.md).
  0 critical / 0 high / 0 medium findings across the series.
- Signed-release pipeline shipped in
  [`.github/workflows/release.yml`](.github/workflows/release.yml):
  cosign keyless via GitHub Actions OIDC, GitHub Release
  auto-creation, `cargo publish` auto-skip on `publish = false`
  crates. Verification doc:
  [`docs/en/contributing/verifying-release.md`](docs/en/contributing/verifying-release.md).

### iOS packaging — xcframework closed (2026-05-28)

The last open v0.8 item (iOS `xcframework`) is closed. Built on an
Apple-silicon macOS host now that the toolchain is available.

#### Added

- **`HiddenVolumeFFI.xcframework`** produced by
  [`scripts/build-ios.sh`](scripts/build-ios.sh): `ios-arm64` device
  slice + `ios-arm64_x86_64-simulator` fat slice (arm64 + x86_64),
  staged under `experimental/flutter_plugin/hidden_volume/ios/`. Swift
  bindings regenerated against uniffi 0.31. The same Dart FFI code path
  now runs on iOS, Android, Windows desktop, and the web-free desktop
  targets.

#### Fixed

- **iOS static-lib symbols dead-stripped from the dynamic plugin
  framework.** Under Flutter's `use_frameworks!`, the Rust staticlib is
  linked into the dynamic `hidden_volume` framework via
  `-l"hidden_volume_ffi"`, but the framework's only compiled code is the
  no-op `HiddenVolumePlugin` stub — so the linker pulled in zero objects
  from the archive and the framework shipped with no Rust symbols. The
  Dart-side `DynamicLibrary.process()` lookup then failed at the first
  call with `dlsym … ffi_hidden_volume_ffi_uniffi_contract_version:
  symbol not found`. Fixed by adding
  `OTHER_LDFLAGS = -force_load "${PODS_XCFRAMEWORKS_BUILD_DIR}/hidden_volume/libhidden_volume_ffi.a"`
  to the podspec `pod_target_xcconfig`. Verified by the example app's
  `integration_test/app_test.dart` passing on an iPhone 17 simulator
  (iOS 26.5) — full Argon2 + KV + log round-trip green.

#### Notes

- On macOS the FFI cdylib is `libhidden_volume_ffi.dylib`, not the
  `.so` the `bindings/README.md` regeneration recipe hard-codes; pass
  the `.dylib` to `uniffi-bindgen --library` on this host.
- The Flutter plugin still uses CocoaPods, not Swift Package Manager;
  recent Flutter prints a (currently non-fatal) SPM-adoption warning.
  Tracked as a future packaging task, not a blocker.

## [0.1.0] — 2026-05-10

First formal SemVer tag. Snapshot of the workspace at the close of
v0.8 (FFI + Flutter integration) plus audit pass 18. Still pre-1.0:
on-disk format and public API may change in v0.x → v0.y bumps. v1.0
will freeze both pending external crypto-review (see `TASKS.md`).

Cumulative highlights since the project's start (only major themes —
per-pass detail follows below):

- **v0.1–v0.7**: foundation, multi-space deniable container, B+ tree
  indexes, log namespaces (DataBatch + zstd), crash-safe commit,
  vacuum, multi-device anchor contract, hardening passes,
  performance pass, async wrapper crate.
- **v0.8 (closed 2026-05-10)**: FFI surface (uniffi 0.31), Android
  `.so` per-ABI shipping, Windows desktop plugin packaging, hand-
  written Dart `dart:ffi` bindings (Path C) with worker-isolate async
  wrapper, end-to-end Flutter integration test passing on Windows
  desktop and Android emulator. iOS xcframework remains gated on a
  macOS host (only open v0.8 item).
- **Audit passes 1–18** (refactor + security): 378 tests pass,
  `cargo clippy --all-targets --all-features -- -D warnings` clean,
  `cargo audit` 0 vulns, `cargo deny check` clean, `cargo fmt`
  clean. TM1 timing-oracle leak verified and quantified
  (mitigation tracked for v1.1).

Released artifacts (CI matrix on `tags: [v*.*.*]` trigger): per-target
Rust binaries / Android `.so` per ABI / regenerated bindings for
Kotlin / Swift / Python / Ruby. iOS `xcframework` produced when a
macOS runner is available.

### Audit pass 18 — second-reviewer follow-through (2026-05-10)

A second independent code review (post-pass-17) found 4 medium-severity
issues my own merged audit missed plus several cleanup items. All
verified by reading the code, then fixed in this pass. **378 tests
pass** (was 377; +1 M2 regression). `cargo clippy --workspace
--all-targets --all-features -- -D warnings` clean. `cargo audit`
clean. `cargo fmt --check` clean.

#### Closed — Medium severity

- **M1 — `commit_tx` no longer returns `Err` after a durable commit.**
  Previously, the post-fsync padding step (DESIGN §8) could fail and
  surface as `Err` from `Tx::commit()` even though the superblock fsync
  had already published the commit to other processes. This violated
  the docstring invariant ("if commit_tx returns Err, state.superblock
  is unchanged") and risked host-app retries / sync-state corruption.
  Fix: catch padding errors inside `commit_tx`, stash on
  `SpaceState::last_padding_error`, return `Ok(new_seq)` regardless.
  New public read-only accessor `Space::last_padding_error()` lets
  host-apps surface a privacy-hardening warning without confusing it
  with a commit failure. Files: [`crates/hidden-volume/src/space/commit.rs:280-310`](crates/hidden-volume/src/space/commit.rs),
  [`crates/hidden-volume/src/space/mod.rs:163-175,348-360`](crates/hidden-volume/src/space/mod.rs).

- **M2 — `verify_integrity` now covers `DataBatch` chunks for log
  namespaces.** Previously the Merkle walk stopped at Leaf nodes; the
  `DataBatch` chunks pointed at by log-namespace leaf entries were
  never AEAD-decrypted or `decode_batch`-validated. A corrupted
  DataBatch would pass `verify_integrity` and only fail later at
  `read_log` time. Fix: extend the walker for Log roots to collect +
  dedup batch_slot pointers, then AEAD-decrypt + decode each.
  `IntegrityReport` gains `data_batches_verified: usize` (mirrored on
  the FFI surface as `IntegrityResult.data_batches_verified: u64`).
  New regression test [`corruption_of_databatch_chunk_surfaces_as_integrity_failure`](crates/hidden-volume/tests/integrity.rs)
  proves a corrupted DataBatch now fails the walk. Files:
  [`crates/hidden-volume/src/space/integrity.rs`](crates/hidden-volume/src/space/integrity.rs),
  [`crates/hidden-volume/src/space/mod.rs:121-138`](crates/hidden-volume/src/space/mod.rs),
  [`crates/hidden-volume-ffi/src/lib.rs:518-528,770-776,1098-1104`](crates/hidden-volume-ffi/src/lib.rs).

- **M3 — `atomic_rewrite_under_source_lock` race window narrowed.**
  Between Container's drop (end of `write` closure) and the `rename`,
  there was a window in which an attacker with directory write+read
  access could substitute the tmp-file contents (we'd then rename
  attacker content into `path`). Fix: after writer drop, re-open tmp
  with `LOCK_EX`, validate the cleartext header (Argon2 params must
  pass `validate()`), and on Unix capture the inode before rename then
  verify the post-rename inode matches. Documented `path.parent()` as
  a trusted-directory precondition in the function docstring +
  [`SECURITY.md`](SECURITY.md). Files:
  [`crates/hidden-volume/src/container/mod.rs:1004-1148`](crates/hidden-volume/src/container/mod.rs).

- **M4 — Android lock skip precondition documented as a hard
  requirement.** The 2026-05-10 `cfg(target_os = "android")` flock
  skip is safe only when the container lives in app-private storage.
  Previously this was implicit ("Android sandbox provides isolation")
  with no enumerated NOT-safe paths. Fix: explicit precondition
  comment in [`container/file.rs`](crates/hidden-volume/src/container/file.rs)
  + new "Not in scope" bullet in [`SECURITY.md`](SECURITY.md) listing
  shared/external storage, MediaStore URIs, MultiUserMode, and the
  `android:process=...` multi-process case as out-of-scope.

- **M5 — v3 format-version cryptographic-binding constraint
  documented.** v2 ships safely (gate via `Argon2Params::validate()`),
  but any v3 spec must bind `format_version` either in the Argon2id
  input or in every per-chunk AEAD AAD to close the cross-version
  replay class. Added as new question 6 in [`DESIGN.md`](DESIGN.md)
  §11 ("Open questions"). Not a v2 vulnerability.

#### Cleanup

- **Method-channel scaffolding reduced to no-op stubs** on
  Android / iOS / Windows. The "PRIMARY (Dart `dart:ffi`) /
  SECONDARY (Method Channel)" two-path narrative documented in the
  scaffolding comments was never actually wired up; the secondary
  channel was a documented placeholder that integrators would have
  had to fill in themselves. With Path C (hand-written `dart:ffi`)
  now production-ready (audit 2026-05-10), the secondary path is
  unmotivated maintenance burden. Files:
  [`HiddenVolumePlugin.kt`](experimental/flutter_plugin/hidden_volume/android/src/main/kotlin/dev/hidden_volume/hidden_volume/HiddenVolumePlugin.kt),
  [`HiddenVolumePlugin.swift`](experimental/flutter_plugin/hidden_volume/ios/Classes/HiddenVolumePlugin.swift),
  [`hidden_volume_plugin.{cpp,h}`](experimental/flutter_plugin/hidden_volume/windows/hidden_volume_plugin.cpp).
- **Broken doc link** `docs/en/security/cli.md` removed from
  [`hv.rs:351`](crates/hidden-volume/src/bin/hv.rs); replaced with an
  inline `--help`-pointer that doesn't bit-rot.
- **Stale `UnimplementedError` Flutter docs** updated. The
  experimental plugin README and the parent `experimental/README.md`
  table both claimed the Dart facade throws `UnimplementedError`;
  reality (since Path C closure 2026-05-10) is the typed `HvSpace` +
  `HvAsyncSpace` API is fully implemented. Files updated:
  [`experimental/README.md`](experimental/README.md),
  [`experimental/flutter_plugin/hidden_volume/README.md`](experimental/flutter_plugin/hidden_volume/README.md).
- **Placeholder `LICENSE` ("TODO: Add your license here.")** in the
  example Flutter plugin replaced with a dual-MIT-OR-Apache-2.0
  pointer to the parent workspace's [`LICENSE-MIT`](LICENSE-MIT) /
  [`LICENSE-APACHE`](LICENSE-APACHE).
- **Duplicate Android `MainActivity`** removed. The example app had
  two — one at `com/example/hidden_volume_example/MainActivity.kt`
  (matches namespace + applicationId, used by the `.MainActivity`
  manifest reference) and one at
  `dev/hidden_volume/hidden_volume_example/MainActivity.kt` (stray,
  never reached). The unused stray + its empty parent dirs are gone.

### Flutter integration milestone (2026-05-10)

Closed two of the three open v0.8 platform-packaging items end-to-end
on a Windows dev box (the third — iOS xcframework — remains gated on
macOS+Xcode access). Highlights:

- **Android `.so` per ABI shipped.** All four ABIs (arm64-v8a /
  armeabi-v7a / x86_64 / x86) build via
  [`scripts/build-android.sh`](scripts/build-android.sh) using
  cargo-ndk 4.1.2 and NDK r27d. Output staged in the plugin's
  `jniLibs/` so any downstream `flutter build apk` picks them up.
- **Windows packaging shipped.** Plugin pubspec now declares Windows
  as a supported platform. New `scripts/build-windows.sh` stages the
  cdylib at `experimental/flutter_plugin/hidden_volume/windows/lib/`;
  the plugin's `windows/CMakeLists.txt` bundles it via
  `<plugin>_bundled_libraries`, so `flutter build windows` copies
  `hidden_volume_ffi.dll` next to the runner `.exe` automatically.
- **Typed Dart API shipped (Path C — hand-written `dart:ffi`).**
  `uniffi-bindgen-dart` 0.1.3 had two blocking bugs (enum marshalling
  generates wrong wire-format; async constructors are stubbed
  `UnsupportedError`-throwers) and required uniffi 0.31. We bumped
  uniffi 0.28 → 0.31 in `hidden-volume-ffi` (clean drop-in, source
  unchanged) and bypassed the buggy generator. The plugin now exposes
  a hand-written, typed `HvSpace` facade ([`lib/hidden_volume.dart`](experimental/flutter_plugin/hidden_volume/lib/hidden_volume.dart))
  backed by [`lib/src/bindings.dart`](experimental/flutter_plugin/hidden_volume/lib/src/bindings.dart)
  (~700 LOC speaking the stable uniffi 0.31 C ABI). Full sync surface:
  `create / open / commit / get / iterLogRange / commitSeq /
  commitHistory / count / eraseNamespace / readLog / listNamespaces /
  setPaddingPolicy / stats / vacuumDataBatches / verifyIntegrity /
  close` plus top-level `headerInfo / changePasswords / compactKnown`.
- **Async wrapper via worker isolate.** `HvAsyncSpace` ([`lib/src/async_bindings.dart`](experimental/flutter_plugin/hidden_volume/lib/src/async_bindings.dart))
  spawns a dedicated `Isolate`, owns the `SpaceHandleBindings` there,
  and routes typed requests over `SendPort`. Frees the Flutter UI
  thread from blocking on Argon2 KDF or the open-time scan.
  `headerInfoAsync / changePasswordsAsync / compactKnownAsync` use
  `Isolate.run` for one-shot off-main execution.
- **Auto-cleanup via `Finalizer`.** `SpaceHandleBindings` attaches a
  `Finalizer<int>` to free the Rust handle on GC if the host forgets
  `close()`. Mirrors Python's `__del__` discipline.
- **Example app + integration test.** Minimal Flutter app at
  [`experimental/flutter_plugin/hidden_volume/example/`](experimental/flutter_plugin/hidden_volume/example/)
  drives the round-trip end-to-end (create → commit puts +
  append_logs → get → iter_log_range → stats → close → headerInfo)
  and renders the result. Integration test
  ([`example/integration_test/app_test.dart`](experimental/flutter_plugin/hidden_volume/example/integration_test/app_test.dart))
  passes on **Windows desktop** AND on the **Android x86_64 emulator**
  (API 36) — full vertical: Rust core → uniffi 0.31 cdylib →
  hand-written Dart bindings → async worker isolate → Flutter UI.
- **Bench Dart vs Python (Windows / NVMe / Argon2 LIGHT).**
  `dart:ffi` per-op p50: `get` 45.7 µs, `headerInfo` 84.6 µs vs
  Python ctypes 58.2 µs / 125 µs respectively (Dart ~20-30% faster on
  read-side ops; `commit` and `create` are dominated by fsync /
  Argon2 and equalize). Sources:
  [`experimental/flutter_plugin/hidden_volume/bench/`](experimental/flutter_plugin/hidden_volume/bench/).

### Fixed — Android target lacks `File::try_lock`

- **Android flock skip.** Stable Rust 1.89's `File::try_lock` is not
  implemented for `target_os = "android"` — the literal returns
  `Unsupported "try_lock() not supported"` (only `linux`, `freebsd`,
  `apple`, etc. are wired up; `android` is omitted from the cfg gate
  in `library/std/src/sys/fs/unix.rs`). Detected when running the
  Flutter integration test against the Android emulator. Added
  `cfg(target_os = "android")` branches to `try_lock_exclusive` /
  `try_lock_shared` in [`crates/hidden-volume/src/container/file.rs`](crates/hidden-volume/src/container/file.rs)
  that return `Ok(())`. Rationale: Android sandboxes each app under
  its own UID and the container file lives in the app's private
  storage, so cross-process file-lock coordination is moot. The
  in-process `Mutex` inside `SpaceHandle` already enforces single-
  writer semantics within a process. **No security regression**:
  cross-process sharing of an Android container file is not a
  supported use-case.

### Closed — architectural backlog E5/E6/E7

- **E5/E6 confirmed already closed in audit pass 8.** TASKS.md
  carried them as «deferred» but [`crates/hidden-volume-rt`](crates/hidden-volume-rt/)
  has been the canonical home for `OwnedSpace` (E5) and
  `run_blocking` (E6) since pass 8. Both `hidden-volume-async` and
  `hidden-volume-ffi` import from it. Updated TASKS.md to reflect
  reality.
- **E7 reassessed as WONTFIX 2026-05-10.** Original concern was
  `space/mod.rs` at 1485 lines; after pass-8/13/16 refactoring the
  file is now 689 lines with a contiguous, well-organized
  `impl Space<'f>` block. Splitting now would harm auditor
  top-to-bottom readability for no maintainability win. Closed.

### Verified — TM1 (open-time scan timing oracle)

- **TM1 verified, leak quantified, mitigation deferred to v1.x.**
  Ran [`crates/hidden-volume/benches/timing_oracle.rs`](crates/hidden-volume/benches/timing_oracle.rs)
  on Windows / NVMe (Argon2 MIN, 500 slots). Result:
  `frac_owned=0.10 → 20.3 ms`, `0.50 → 48.5 ms`, `0.90 → 49.6 ms` —
  open-scan time grows roughly linearly with owned-fraction, ~37 ms
  per fraction unit (~75 µs per chunk). The original cache-effect
  hypothesis was wrong; the actual mechanism is more direct: a
  successful per-chunk AEAD-decrypt runs ChaCha20 over the full
  body, while a failed MAC short-circuits before the body decrypt.
  **Granularity:** the leak reveals owned/total fraction, not which
  chunks belong to which space — D2 (deniability of password) holds.
  **Mitigation** (deferred): replace early-MAC-fail with a constant-
  time AEAD that always runs ChaCha20 over the body and discards on
  MAC mismatch (~2× cost on garbage chunks; eliminates the
  side-channel). Tracked for v1.1 in [`docs/en/security/threat-model.md`](docs/en/security/threat-model.md)
  §F-TM1. The linearity test passed (~22 / 32 / 47 ms for total =
  100 / 500 / 1000 slots), confirming Θ(N) per-chunk cost.

### Breaking — uniffi bump 0.28 → 0.31

- **`hidden-volume-ffi` now requires uniffi 0.31** (previously 0.28).
  Drop-in: no source changes were needed inside the FFI crate. The
  bump was driven by Flutter Dart-binding work — `uniffi-bindgen-dart`
  needs uniffi 0.30+ contract version. New `scaffolding-ffi-buffer-fns`
  feature added to the uniffi dep so the cdylib exports the
  `uniffi_ffibuffer_*` symbol family that the foreign-side hand-
  written bindings consume. All 14 FFI unit tests + 3 smoke tests
  still pass; Kotlin / Swift / Python / Ruby / Dart bindings all
  regenerated cleanly against the bumped contract.
- **`tests/ffi_smoke.rs`** test renamed:
  `contract_version_value_is_uniffi_028_compatible` →
  `contract_version_value_is_plausible` (the bench was already
  version-agnostic in implementation; the name stuck from the 0.28
  era).

### Breaking — audit pass 17 (security/quality follow-through)

- **New `Error::ContainerTooLarge { extra, cap }` variant.** Symmetric
  write-side / read-side budget for [`MAX_OPEN_SCAN_CHUNKS`](crates/hidden-volume/src/open/mod.rs)
  (= 16 M chunks ≈ 64 GiB). `Container::create_with_options`,
  `commit_tx` post-commit padding, and `repack` destination growth
  refuse with this error if the write would push the file past the
  cap. Previously the open-side rejected with `Error::Malformed` —
  symmetric gate avoids the create-then-can't-reopen footgun.
- **`PaddingPolicy::garbage_after_commit` returns `Result<u64>`**
  (was `u64`). Extreme-input arithmetic (`div_ceil(b) * b` overflow,
  `u128 as u64` truncation) now surfaces as `Error::Internal` instead
  of panicking in debug or wrapping in release.
- **`Space::iter_log_after / before / range` strict mode.** Non-8-byte
  keys (caller passed a KV namespace by mistake, or writer-bug
  regression) now return `Error::WrongNamespaceKind` instead of
  silently skipping. Matches the strictness of `Space::iter_log`.
- **`Container::open_space_verified` defers auto-vacuum** until after
  `verify_integrity` succeeds. Old behavior leaked observable
  mutation on verify failure; the documented "no observable mutation
  on failure" guarantee now actually holds.
- **`PasswordRotation` no longer derives `Clone`.** Defense-in-depth
  against accidental `.clone()` bypass of the pass-16 `Zeroizing`
  flow. No current callsite cloned, so this is zero behavior cost
  on the happy path.
- **CLI `hv` and `hidden-volume-async` now use `Zeroizing` for
  password buffers** — symmetric with the FFI crate's pass-16
  treatment. New `zeroize = "1.8"` dep in `hidden-volume-async`.
- **MSRV bumped 1.85 → 1.89** to pick up `File::try_lock`
  stabilization.
- **New `pub use crate::MAX_OPEN_SCAN_CHUNKS`** at crate root.
  Integrators can pre-validate `initial_garbage_chunks` /
  padding-policy growth against the cap.
- **Internal:** `unreachable!()` in `space/index.rs` decode paths
  replaced with `Err(Error::Internal)` for friendlier failure mode.
  Error-string for the open-scan-budget gate trimmed (audit-pass
  references no longer leak through FFI to foreign-side consumers).
- **389 tests pass** (was 387; +2 PaddingPolicy extreme-input
  regressions in `padding/mod.rs`).

### Breaking — audit pass 16 (R-STREAMING-REPACK + DoS budget + FFI Zeroizing)

- **Streaming repack.** `Container::repack` and the in-place
  `compact_known` / `change_passwords` flows page through log
  namespaces via `iter_log_after(ns, cursor, log_page_size)` with
  per-page `Tx::commit`. Working set ceiling drops from
  O(total plaintext) to O(page) ≈ 4 MiB regardless of total log
  volume. KV namespaces still collect once per namespace (bounded
  by the structural B+ tree cap).
- **Open-scan budget.** New constant
  [`MAX_OPEN_SCAN_CHUNKS = 16 × 1024 × 1024`](crates/hidden-volume/src/open/mod.rs)
  (≈ 64 GiB at `CHUNK_SIZE = 4096`). All three discovery scans
  (sequential, parallel, mmap) call `check_scan_budget(total)`
  before iterating, so an adversary-inflated container header
  can no longer force the reader into a 100-GiB Argon2 / AEAD
  attempt loop. Closes the TM1 escalation flagged by audit pass 14.
- **FFI password Zeroizing.** Every FFI password entry point now
  wraps the incoming `Vec<u8>` in `zeroize::Zeroizing` immediately
  on entry: `SpaceHandle::create`, `SpaceHandle::open`,
  `AsyncSpaceHandle::create`, `AsyncSpaceHandle::open`, top-level
  `compact_known(path, passwords)`, and `change_passwords(path,
  rotations)`. Foreign-side buffers remain the caller's hygiene
  responsibility (documented at the crate level + on
  `PasswordRotation`).
- **387 tests pass** (was 385; +2 streaming-repack regressions).

### Breaking — audit pass 15 (`open_space_verified` strict mode)

- **New `Container::open_space_verified` / `open_space_with_keys_verified`.**
  Strict-mode opens that run `Space::verify_integrity` before
  returning, surfacing any Merkle-chain or AEAD failure at open
  time rather than at first read. Useful for forensics / backup
  tooling and security-paranoid host-apps.
- **`ContainerFile::append_garbage_chunks` batched I/O.** Coalesces
  writes into batches of up to 64 chunks (256 KiB) per syscall,
  reducing a 1024-chunk decoy from 1024 syscalls to 16. Buffer is
  `Zeroizing`-wrapped.
- **F-PAD threat-model entry added** (`docs/en/security/threat-model.md`
  §4.1 / `docs/ru/...`). Documents the multi-snapshot adversary's
  ability to read the cleartext `padding_policy_index` byte and the
  forward-compat fallback to `None` for unknown indices.

### Breaking — format v2 (audit pass 13, R-NSKIND)

- **`PARAMS_VERSION` bumped from 1 to 2.** v1 containers cannot be
  opened by v2 readers (`Argon2Params::validate` rejects unknown
  `format_version`). Pre-1.0 — breaking is acceptable per the
  maintainer policy.
- **`CommitPayload` per-root layout grew 41 → 42 bytes.** New
  1-byte `kind` field (0 = Kv, 1 = Log) immediately after the
  per-root `namespace` byte. Closes audit pass 12 HIGH
  ("mixed-namespace data loss" via shape-heuristic in repack).
  See [`docs/en/reference/format.md`](docs/en/reference/format.md) §4.3
  for the full layout. `MAX_NAMESPACES_PER_TX` adjusted from ≈97 to
  ≈95.
- **New `pub enum NamespaceKind { Kv = 0, Log = 1 }`** in
  `hidden_volume::tx`. Re-exported from the crate root
  prelude path.
- **New `Space::list_namespaces_with_kind` API**. Returns
  `Vec<(Namespace, NamespaceKind)>` from the persisted
  `IndexRoot.kind` bytes.
- **Three-layer kind enforcement**: Tx-time check (synchronous
  `Error::WrongNamespaceKind`), commit-time cross-Tx check
  (rejects before writing any chunk), and on-disk persistence
  (every IndexRoot carries its kind). `Space::erase_namespace`
  uses a `pub(crate) Tx::delete_internal` bypass to drop log
  namespaces' KV layer; `commit_tx` allows pure-`Delete` op
  sets against Log namespaces.
- **`vacuum_data_batches` now iterates only Log-kind namespaces**
  when collecting referenced batch_slot pointers. Closes audit
  pass 12 MEDIUM ("8-byte KV value coincidentally suppresses
  scrub" false-negative window).
- **`Container::repack` routes by persisted `kind`** — the v1-era
  shape heuristic and `RepackOptions::log_namespaces` hint were
  removed. The `RepackOptions` struct lost the `log_namespaces`
  field entirely; downstream code using `..Default::default()` is
  unaffected; explicit struct-literal callers of v1-era code must
  drop the field.

### Security

- **Audit pass 14 — `Superblock` chunk-seq cross-check.** Recovery
  now rejects an SB whose decoded `Superblock.seq` disagrees with
  its chunk-level `Plaintext.seq`. Mismatch indicates writer-bug
  regression or post-AEAD tamper by a key-holder; recovery falls
  through to the next candidate instead of silently adopting an
  inconsistent state. Applies to all three scan paths
  (sequential, parallel, mmap).

- **D1 HIGH — Argon2 m_cost DoS via header tampering closed.**
  `Argon2Params::validate()` now caps `m_cost_kib ≤ 1 GiB`,
  `t_cost ≤ 100`, `p_cost ≤ 64`. Previously the cleartext header was
  unprotected and a T2 file-modification adversary could write
  `m_cost_kib = u32::MAX` (≈4 TiB) to OOM every subsequent
  `Container::open` during Argon2id derivation. New constants
  `Argon2Params::{MAX_M_COST_KIB, MAX_T_COST, MAX_P_COST}` document
  the ceilings. Coverage:
  `tests/header_params::params_above_ceiling_rejected_by_validate`
  (boundary cases at MAX, MAX+1, u32::MAX) +
  `tests/header_params::header_tamper_with_huge_m_cost_rejected_on_open`
  (real-attack reproduction: tamper a legit container's header bytes,
  re-open must fail with `Kdf` error in <1s — never trying to
  allocate). See `docs/THREAT_MODEL.md` §F1.

- **D1 HIGH — Argon2 m_cost DoS via header tampering closed.**
  `Argon2Params::validate()` now caps `m_cost_kib ≤ 1 GiB`,
  `t_cost ≤ 100`, `p_cost ≤ 64`. Previously the cleartext header was
  unprotected and a T2 file-modification adversary could write
  `m_cost_kib = u32::MAX` (≈4 TiB) to OOM every subsequent
  `Container::open` during Argon2id derivation. New constants
  `Argon2Params::{MAX_M_COST_KIB, MAX_T_COST, MAX_P_COST}` document
  the ceilings. Coverage:
  `tests/header_params::params_above_ceiling_rejected_by_validate`
  (boundary cases at MAX, MAX+1, u32::MAX) +
  `tests/header_params::header_tamper_with_huge_m_cost_rejected_on_open`
  (real-attack reproduction: tamper a legit container's header bytes,
  re-open must fail with `Kdf` error in <1s — never trying to
  allocate). See `docs/THREAT_MODEL.md` §F1.

### Added (refactor audit pass 8 — architectural cleanups, started 2026-05-04)

Group C of the post-pass-7 summary. Six architectural cleanups
planned; **TM1 + minimal-variant E5/E6** landed in this session.
The remaining three (E7 mod-split, E5/E6 full extraction, S1 full
format change, D10 cancellable-API consolidation) are scoped and
deferred to focused sessions — each is a 0.5–2 day mechanical
refactor with subtle risk that doesn't compose well with other
work.

- **TM1** — `crates/hidden-volume/benches/timing_oracle.rs` (new).
  Criterion-based open-time micro-bench measuring
  `Container::open_space` wall-clock as a function of
  (owned_fraction, total_slots). Closes a long-standing
  threat-model open question once run on real hardware:
  cache-effects from the `owned_slots` / `commit_history` /
  `sb_candidates` bookkeeping vectors during the discovery scan
  could in principle leak the owned-fraction to a same-host
  observer. Bench provides the empirical evidence base. Acceptance
  criterion is documented in the bench header — distributions for
  different fractions should overlap within criterion's noise
  floor; if not, the mitigation is to add fake-AEAD-attempts on
  non-owned slots to mask the cache signal. Registered as a
  second `[[bench]]` target in `crates/hidden-volume/Cargo.toml`.

- **E5 / E6 (MIRROR-annotation variant)** — `SpaceInner` and
  `run_blocking` are duplicated across `hidden-volume-async` and
  `hidden-volume-ffi`. Full extraction into a shared internal
  `hidden-volume-rt` crate is deferred (it requires generics over
  error types + new crate scaffolding + uniffi regeneration —
  too invasive for this session). As a minimal precaution against
  the duplicates drifting, both copies of each helper now carry an
  explicit **MIRROR** doc-comment cross-referencing the other
  copy, stating that "any change to one MUST be applied to the
  other". Pass-6 audit verified the unsafe `Box<Container>` +
  `ManuallyDrop<Space<'static>>` pattern is sound and `Pin` is
  not needed; that conclusion is now annotated in both copies.

Verify: 356 tests pass, fmt --check ✓, clippy `-D warnings` ✓,
RUSTDOCFLAGS=-D warnings cargo doc ✓, `cargo bench --bench
timing_oracle --no-run` compiles cleanly.

### Fixed (refactor audit pass 7 — follow-up, 2026-05-04)

Closes the remaining 9 actionable items from pass-7's open backlog
(L3, L5, D1, D4, S2, C3, C4, D2, D3 + the FFI-exposure half of S1).

- **L3** — `Space::read_log` aligned with `iter_log_*` for
  structural inconsistency. If KV says "log_id X is in batch B"
  but batch B decodes without X, both APIs now return
  `Err(Malformed("log_id not found in pointed batch"))` instead of
  `read_log` returning `Ok(None)`. The `Ok(None)` path is
  preserved only for "KV doesn't have the key" — a true "not
  appended" condition.

- **L5** — `Space::vacuum_orphans` and `Space::vacuum_data_batches`
  return `Err(Error::ReadOnly)` when explicitly called on a
  `LOCK_SH` handle. The previous silent `Ok(0)` masked failed
  privacy expectations. The auto-call from `Container::open_space*`
  is suppressed at the container layer via an `is_readonly()`
  check, so read-only opens still succeed without trying to scrub.

- **D4** — `scan_and_recover` (sequential), `scan_and_recover_parallel`,
  and `scan_and_recover_mmap` gained `debug_assert!`s on same-seq
  Superblock-replica bit-equality (per-thread Acc loop, cross-
  thread merge, and mmap path). Same-seq replicas are produced as
  identical bytes by `commit_tx` (one `new_sb` written N times); a
  writer-bug regression that produced same-seq-different-payload
  SBs would silently mask first-wins. Release builds keep
  first-wins semantics with no cost.

- **S2** — `ContainerFile` fields (`header`, `padding_policy`,
  `superblock_replicas`, `lock_mode`) tightened from `pub` to
  `pub(crate)`. `header` is part of the crypto identity (salt,
  container_id, Argon2 params) and must never be mutated
  post-create — `pub(crate)` removes the type-level invitation. No
  external test or user touched these fields directly; only
  `tests/header_params.rs` uses `ContainerFile` and only via
  factory methods.

- **D1, C3, C4 — commit_tx + vacuum_data_batches doc clarified.**
  - `commit_tx` doc: orphan IndexNode chunks survive **only within
    one open session** (in-flight-commit fallback); next
    `Container::open_space` runs auto-`vacuum_orphans`. Cross-launch
    rollback works through the multi-Superblock-replicas path
    (`commit_history`), NOT through orphan IndexNode preservation.
  - `commit_tx` doc gained "Post-failure state" paragraph:
    `owned_slots` may include orphans, `superblock` unchanged,
    auto-`vacuum_orphans` reclaims IndexNode but not DataBatch.
  - `vacuum_data_batches` doc: recommended call after any
    `commit()` that returned an error (D1 forward-secrecy gap).

- **D2** — `make_aad` doc explains why format version is bound via
  the key chain (`Argon2Params.version → master → aead_root → per-slot
  key`), not in the AAD itself. Locks down the convention so a
  future refactor weakening the version-to-key binding is
  highlighted as a security regression.

- **D3** — `derive_chunk_key` doc explicitly states the
  domain-separation convention with `derive_subkey`: any future
  `derive_subkey(aead_root, ...)` MUST use a context label whose
  length differs from 40 bytes, OR encode an explicit kind-tag
  byte at position 0, to avoid input-prefix collision with the
  40-byte `container_id || slot_le` chunk-key input.

- **S1 (FFI exposure half)** — `Space::set_padding_policy` /
  `Space::padding_policy` accessor methods added on the sync core.
  FFI exposes a flat `PaddingPreset` enum
  (`None`, `Bucket256Kib`, `Bucket1Mib`, `Bucket16Mib`) and
  `SpaceHandle::set_padding_policy` /
  `AsyncSpaceHandle::set_padding_policy` methods. Host-apps now
  re-apply policy on every open (still not persisted in the header
  — that's a separate format-design pass).

New `HvError` variants (FFI surface): `WrongNamespaceKind(String)`,
`TooManyNamespaces { limit: u64 }` — mapping the corresponding
sync-core variants instead of falling through to
`Internal("unknown error variant")`.

Tests updated:
- `tests/readonly::open_space_on_readonly_skips_vacuum_and_explicit_call_errors`
  (renamed) asserts `Err(ReadOnly)` from explicit `vacuum_orphans` on RO.
- `tests/vacuum_data_batches::readonly_handle_errors_on_explicit_vacuum`
  (renamed) asserts the same for `vacuum_data_batches`.

Verify: 356 tests pass, fmt --check ✓, clippy `-D warnings` ✓,
`RUSTDOCFLAGS=-D warnings cargo doc` ✓.

### Fixed (refactor audit pass 7 — invariants & logic, 2026-05-03)

Two parallel agents audited function invariants vs implementation
and state-machine clarity. **One HIGH-severity finding** (data-loss
in repack), 2 MEDIUM, 1 LOW, 1 INFO closed in this commit. 4
remaining items (doc-only / design-required) tracked in TASKS.md.

- **L1 HIGH — `Container::repack` / `compact_*` no longer silently
  corrupts custom log namespaces.** Previously, any namespace not
  enumerated in `RepackOptions::log_namespaces` was treated as KV;
  for actual log namespaces (where values are 8-byte slot pointers
  to DataBatch chunks), this copied (log_id, slot_pointer_bytes) as
  raw KV into `dest`, where the slot pointers were meaningless.
  Atomic-rename in `compact_known` then destroyed the source —
  silent data loss.

  Fix: introduced `Error::WrongNamespaceKind(&'static str)` distinct
  from `Error::Malformed`. `parse_batch_slot_value`,
  `decode_log_entries`, and `read_log` now raise
  `WrongNamespaceKind` when the namespace's KV shape doesn't match
  the `(8-byte log_id_key, 8-byte → DataBatch)` log invariant.
  `repack_inner_mapped` tries `iter_log` first; on
  `WrongNamespaceKind` it falls back to `list` for KV.
  `RepackOptions::log_namespaces` is honoured as a hint (skips the
  probe) but no longer load-bearing — host-apps with custom log
  namespaces that forget to enumerate them are now safe.

  Regression test:
  `tests/repack::repack_auto_detects_unlisted_log_namespace`.

- **C1 MEDIUM — empty Tx `commit()` is now a true no-op.**
  `Tx::is_empty` doc claimed "commit on empty Tx is a no-op (no
  commit chunk emitted)" but `commit_tx` always advanced seq, wrote
  a Commit chunk + Superblock replicas, and ran 3 fsyncs (asserted
  by the previous regression test `empty_tx_increments_seq_with_no_changes`).

  Fix: `commit_tx` early-returns `Ok(self.state.superblock.seq)`
  when both pending maps are empty. Aligns code with doc; saves 3
  fsyncs per call; removes the multi-snapshot "writer was active"
  leak from no-op commits. The old test was renamed to
  `empty_tx_commit_is_a_no_op` and now asserts the new behaviour.

- **L2 MEDIUM — `Error::TooManyNamespaces { limit }` variant** added.
  Previously, exceeding `MAX_NAMESPACES_PER_TX` surfaced as
  `Error::Internal(...)` only at commit time — and `Error::Internal`
  is documented as "bug in the crate". User-driven failures now
  surface in `Tx::put` / `Tx::delete` / `Tx::append_log` with the
  dedicated variant via `check_namespace_capacity`. The encode-time
  `Internal` check stays as defense-in-depth.

- **L4 LOW — `Container::create_space` early-returns
  `Error::ReadOnly`** before kicking off Argon2id derivation +
  collision-scan. Saves ~100ms+ on weak ARM and closes a minor
  timing side-channel (caller could observe collision-check
  completion before getting `ReadOnly`).

- **C2 LOW — encoder/decoder symmetry** in B+tree nodes.
  `LeafNode::encode` and `InternalNode::encode` previously accepted
  unsorted input; decoders strict-rejected. Added `debug_assert!`
  ordering checks in encoders — catches writer-bug regressions in
  tests; release builds pay nothing.

- **C5 INFO — FFI `namespace == 0` rejected symmetrically** in
  read paths. `SpaceHandle::count`/`get`/`read_log`/`iter_log_range`
  and the `AsyncSpaceHandle` async mirrors now return
  `HvError::Malformed("namespace 0 is reserved")` instead of
  silently `Ok(0)` / `Ok(None)`. Aligns with write-path rejection
  (`Tx::put`/`delete`/`append_log` already rejected
  `Namespace::RESERVED`).

New `Error` variants (additive, no breakage for existing match arms
that don't catch `_` exhaustively):
- `Error::WrongNamespaceKind(&'static str)`
- `Error::TooManyNamespaces { limit: usize }`

Verify: 356 tests passed (355 existing + new
`repack_auto_detects_unlisted_log_namespace` regression), fmt
--check ✓, clippy `-D warnings` ✓, RUSTDOCFLAGS=-D warnings cargo
doc ✓.

### Fixed (CI green-up, 2026-05-03)

Seven CI failures uncovered after the Flutter scaffolding commit
landed; all fixed in this commit.

- **Windows: `tests/fault_injection.rs`** previously used
  `std::os::unix::fs::FileExt` (`pread` / `pwrite`) without a
  `cfg(unix)` gate, breaking the windows-latest runner. Rewrote
  `flip_bit` to `seek` + `read_exact` + `write_all` — cross-platform,
  same semantics, no Unix-only path.
- **MSRV bump 1.85 → 1.89.** The codebase already used Rust 1.89
  features: `File::try_lock` / `File::try_lock_shared` (stable in
  1.89; `container/file.rs`), `is_multiple_of` (stable in 1.87;
  `open/mod.rs` cancel-poll guard), and `if let` chains (stable in
  1.88; `open/mod.rs`, `space/mod.rs`). The MSRV CI job pinned
  `dtolnay/rust-toolchain@1.85.0` and was correctly failing. Bumped
  the toolchain pin and added `rust-version = "1.89"` to all three
  crates' `[package]` sections.
- **`crates/*/Cargo.toml` path dependencies** were declared as
  `hidden-volume = { path = "../hidden-volume" }` — implicitly a
  wildcard. cargo-deny's `wildcards = "deny"` (correctly) failed
  on this. Added `version = "0.1.0"` next to each `path = "..."`
  in `hidden-volume-async`, `hidden-volume-ffi`, and the fuzz crate.
- **cargo-deny advisory ignores for uniffi 0.28 transitives.**
  `bincode 1.3.3` (RUSTSEC-2025-0141, unmaintained — bincode team
  archived 1.x) and `paste 1.0.15` (RUSTSEC-2024-0436, unmaintained
  — author archived) are dependencies of uniffi 0.28's proc-macro
  / bindgen crates. We don't use either at runtime; both are
  compile-time-only. No safe upgrade available — uniffi 0.29+
  drops them. Added both advisory IDs to `[advisories] ignore` in
  `deny.toml` with rationale.
- **`crates/hidden-volume/fuzz/Cargo.toml`** lacked an empty
  `[workspace]` table, which caused `cargo +nightly fuzz` to
  detect the parent workspace and fail with "current package
  believes it's in a workspace when it's not". Added the empty
  marker as the cargo error message itself recommends. The parent
  workspace already has `exclude = ["crates/hidden-volume/fuzz"]`;
  this addition is the second half of the standard fuzz-out-of-
  workspace pattern.
- **`tests/ffi_smoke.rs`** first test (`cdylib_loads_and_uniffi
  _contract_version_symbol_resolves`) hard-asserted on cdylib
  presence. `cargo test --workspace --all-features` does not
  always rebuild the cdylib (depends on cache state), causing
  spurious CI failures. Switched to skip-on-missing-cdylib (matches
  the other two tests in the file). Set `HV_REQUIRE_CDYLIB=1` to
  promote skip back to a hard panic for explicit
  `cargo build -p hidden-volume-ffi && cargo test` flows.
- **`.github/workflows/ci.yml` Python e2e step** had a `LIB=$(ls A
  B 2>/dev/null | head)` line that fails under bash strict mode
  when one path doesn't exist (`ls` exits 2 even with stderr
  redirected). Replaced with explicit `if [[ -f ... ]]` ladder —
  produces a clean error if neither cdylib variant is present and
  no spurious shell errors otherwise.
- **`deny.toml` license allowance** pruned `ISC`,
  `Unicode-DFS-2016`, `Zlib` — no current dependency uses them and
  cargo-deny's `unused-allowed-license` warning was loud about it.
  Re-add when an actual dep needs them.

Verify: 355 tests pass, fmt --check ✓, clippy `-D warnings` ✓,
RUSTDOCFLAGS=-D warnings cargo doc ✓, `cargo deny check` →
`advisories ok, bans ok, licenses ok, sources ok`.

### Added (Flutter integration scaffolding, 2026-05-03)

End-to-end build infrastructure for consuming `hidden-volume` from a
Flutter app on Android and iOS. The Rust core + FFI surface were
already in place; this commit adds everything else needed for
`flutter run` to work after a one-time toolchain install.

- **Rust Android targets** added to the toolchain expectation:
  `aarch64-linux-android`, `armv7-linux-androideabi`,
  `x86_64-linux-android`, `i686-linux-android` (4 ABIs).
- **`scripts/build-android.sh`** — `cargo-ndk` wrapper. Pre-flights
  `$ANDROID_NDK_HOME`, `cargo-ndk` install, Rust target install;
  builds `libhidden_volume_ffi.so` for all 4 ABIs and copies into
  `flutter_plugin/hidden_volume/android/src/main/jniLibs/<abi>/`.
- **`scripts/build-ios.sh`** — macOS-only. `cargo build` for
  `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`;
  `lipo`s the simulator slices into a fat staticlib; emits
  `HiddenVolumeFFI.xcframework` via `xcodebuild -create-xcframework`.
- **Flutter plugin scaffolding** at `flutter_plugin/hidden_volume/`:
  - `pubspec.yaml` — Flutter plugin manifest (Android +
    iOS platform support; depends on `ffi` 2.x for `dart:ffi`).
  - `android/build.gradle` + `settings.gradle` +
    `AndroidManifest.xml` + `HiddenVolumePlugin.kt` — AGP 8.2
    library wiring the generated uniffi Kotlin binding.
  - `ios/hidden_volume.podspec` + `Classes/HiddenVolumePlugin.swift` —
    CocoaPods spec referencing the vendored `xcframework`.
  - `lib/hidden_volume.dart` — typed Dart facade
    (`HvContainer`, `HvSpace`, `HvTx`, `Argon2Params`,
    `HvException`); methods are `UnimplementedError`-throwing
    skeletons until uniffi-dart 0.4 stabilizes or the manual
    `dart:ffi` bindings are filled in.
  - `lib/src/bindings.dart` — manual `dart:ffi` skeleton with
    cross-platform `DynamicLibrary` resolution and one wired
    probe (`uniffiContractVersion`); typed wrappers TODO.
- **CI workflow `.github/workflows/flutter-build.yml`**:
  - Android matrix job (Ubuntu, NDK r26d via
    `nttld/setup-ndk@v1`) builds 4 `.so` artifacts on each push.
  - Kotlin binding regeneration job uploads
    `bindings/kotlin/uniffi/`.
  - iOS job (macOS-14, Apple-silicon) regenerates Swift
    bindings, runs `build-ios.sh`, uploads the xcframework
    + Swift binding as artifacts.
- **`crates/hidden-volume-ffi/tests/ffi_smoke.rs`** — three new
  tests (3/3 pass) that dlopen the host-target cdylib via
  `libloading` and probe the uniffi 0.28 C ABI: contract-version
  symbol resolves, contract-version value is in the expected
  range, and a representative subset of
  `uniffi_hidden_volume_ffi_checksum_*` symbols (sync `SpaceHandle`
  ctors + methods, async `AsyncSpaceHandle` ctors + methods, free
  function `header_info`) is present. Catches FFI-surface drift
  before it reaches a slow Android-emulator run. New
  `dev-dependencies`: `libloading = "0.8"`.
- **Flutter guide updated** (`docs/en/guide/flutter.md` +
  `docs/ru/guide/flutter.md`): new "Quick start" section with
  the 4-step pipeline (install → build natives → regenerate
  bindings → `flutter pub get`), shipped-vs-pending status
  table reflects the scaffolding.

Verify: 355 tests pass (352 existing + 3 new FFI smoke), fmt
--check ✓, clippy `-D warnings` ✓, RUSTDOCFLAGS=-D warnings cargo
doc ✓. Build scripts produce a clean error message when
prerequisites are missing (verified on a Linux host without NDK
and on a non-macOS host).

### Changed (refactor audit pass 6, 2026-05-03)

Security-focused audit re-run after passes 1-5 + bilingual docs. Three
parallel audits (security/threats, dead code, bugs/perf/duplicates).
**HIGH = 0, MEDIUM = 0.** Only stale dead code, doc drift, and a few
LOW perf wins. Plus formal closure of D3 (`Pin<Box>` proposal — proven
not needed).

- **Z1-Z6 — dead B+ tree mutators removed.** `LeafNode::put`,
  `LeafNode::delete`, `LeafNode::split`, `InternalNode::update_child`,
  `InternalNode::insert_child_after`, `IndexNode::namespace()` —
  artefacts of the original B+ tree design with in-place updates.
  Zero callers in src/tests/benches/examples/FFI/async; `commit_tx`
  uses flatten-and-rebuild via `apply_op_to_sorted` +
  `pack_into_leaves` instead. ~64 LOC removed from
  `src/space/index.rs`.
- **Z7 — `ContainerFile::write_slot` removed.** Rewrite-in-place
  primitive with zero callers. The append-only architecture writes
  to fresh slots via `append_slot` and overwrites with random via
  `scrub_slot`; in-place updates were never wired up. Module-doc
  Inv-W1 simplified to match. `src/container/file.rs`.
- **Z8-Z13 — stale version-references in doc comments trimmed.**
  Phrases like "v0.1 limits…v0.2 lifts this", "Phase 3 (v0.2.x)",
  "v0.1 surface only", "v0.2 first-cut sizes" removed from
  `superblock.rs`, `error.rs`, `space/mod.rs`, `space/index.rs`.
  ~25 LOC of doc churn cleaned up; doc now reflects shipped state.
- **Perf — `vacuum_orphans` / `vacuum_data_batches` use `HashSet<u64>`**
  for `reachable` and `referenced` (was `BTreeSet`). The membership
  check is the only operation; HashSet is O(1) vs BTreeSet's O(log N).
  Symmetric with the F1 fix in pass 4 that already moved `to_drop`
  to HashSet.
- **Perf — `or_insert(pt.payload)` replaces `or_insert_with(|| pt.payload.clone())`**
  in three discovery-scan sites (`open/mod.rs:116, 264, 401`). On
  `Vacant` the Vec is moved instead of cloned; on `Occupied` it is
  dropped (which would have happened anyway). Saves a per-Superblock
  allocation in the scan hot path.
- **Perf — `checked_add(1)` guards** for the `u64` log-cursor in the
  async stream (`hidden-volume-async/src/lib.rs`). Pure
  defense-in-depth: practical log_id values are far below
  `u64::MAX`, but `cursor + 1` would panic in debug / wrap in
  release at saturation.
- **Perf — `hex()` uses `write!` instead of `format!` per byte**
  (`hidden-volume-ffi/src/lib.rs:hex`). Cold path; cosmetic. Avoids
  the per-byte intermediate `String` allocation.
- **D3 — closed as not needed.** The self-referential `SpaceInner`
  pattern (`Box<Container>` + `ManuallyDrop<Space<'static>>`) is
  sound without `Pin`. `Box`'s heap pointee has a stable address;
  `Pin` is only needed when the borrowed-from data is in the *same*
  struct as the borrow. Drop order is enforced by `ManuallyDrop` +
  the explicit `Drop` impl; `Send`/`Sync` is correctly serialized
  via `Mutex`. `self_cell` / `ouroboros` migration would be a no-op
  of the same semantics.

Verify: 352 tests passed, fmt --check ✓, clippy -D warnings ✓,
`RUSTDOCFLAGS=-D warnings` cargo doc ✓.

### Changed (housekeeping, 2026-05-03)

- **C4 — generated FFI bindings unstaged from git.**
  `bindings/{python,kotlin,swift,ruby}/*` (the ~11k lines of
  uniffi-generated source) added to root `.gitignore` and
  `git rm --cached`'d. Tracked items kept: `bindings/README.md`
  (regeneration recipe), `bindings/python/test_smoke.py`
  (hand-written), `bindings/python/.gitignore`. Avoids history
  bloat on every uniffi version bump; integrators regenerate
  locally per the README.
- **TASKS.md hygiene** — 14 line items that had been closed by
  passes 1–3 + C4 marked `[x]` with cross-references to the
  closing pass / commit. Status overview updated: code-side open
  count is 0; remaining items are all deferred-with-rationale,
  out-of-band, or organizational.

### Changed (refactor audit pass 5, 2026-05-03)

Hardening mini-pass after passes 1-4 commit. **Zero HIGH-severity
bugs.** Two defense-in-depth bounds in B+tree decode, two
production `expect(...)` panic sites converted to `Error::Internal`,
one cargo-cult dead feature removed, and the long-standing D7+D8
fragile `windows(2)` indexing fixed.

- **G1 — empty `std` feature dropped.**
  `crates/hidden-volume/Cargo.toml` previously had `default =
  ["std"]; std = []` with **zero `cfg(feature = "std")` usage** in
  the workspace. Cargo-cult artifact of a pre-`no_std` intention
  that never materialized. Both lines deleted; the implicit
  `--no-default-features` promise nobody honored is gone.
- **G2 — `LeafNode::decode` defense-in-depth bound.**
  `src/space/index.rs`: a malformed (post-AEAD) leaf payload
  declaring `num_entries = 65535` would pre-allocate ~3 MiB of
  `Vec<(Vec<u8>, Vec<u8>)>` before per-entry bounds caught the
  truncation. New check: `num * MIN_LEAF_ENTRY_BYTES > bytes.len()
  - HEADER_LEN` returns `Error::Malformed("leaf count exceeds
  payload bound")` before allocating. `MIN_LEAF_ENTRY_BYTES = 7`
  (klen u16 + min-key 1 + vlen u32). Post-AEAD path so attacker
  without key cannot reach; protects against on-disk corruption /
  buggy writer.
- **G3 — `InternalNode::decode` defense-in-depth bound.** Same
  pattern as G2 with `MIN_INTERNAL_CHILD_BYTES = 43` (klen u16 +
  min-key 1 + child_slot u64 + child_hash 32B).
- **G4 — `cmd_put` panic site converted.** The
  `.expect("clap should require...")` in
  `src/bin/hv.rs::cmd_put` (paired with `--value-stdin`'s
  `required_unless_present`) is now `.ok_or(Error::Internal(...))?`.
  A clap schema regression now surfaces as a clean
  `Error::Internal` exit code instead of a process panic.
- **G5 — `scan_and_recover_parallel` rayon pool init
  fallibility.** `rayon::ThreadPoolBuilder::build().expect(...)`
  inside `OnceLock::get_or_init` is replaced with a `OnceLock::get`
  + fallible build + `OnceLock::set` chain. On build failure
  (thread-limit-hit / OOM-during-init) the function returns
  `Err(Error::Internal("rayon pool build failed"))`; the caller
  already returns `Result`. Race between two threads building
  concurrently is benign — `set`'s loser drops their pool.
- **G6 — `windows(2)` + index ops replaced with slice patterns.**
  Long-standing **D7+D8** closed. Both leaf/internal sort-check
  loops in `src/space/index.rs` use `let [a, b] = w else
  { unreachable!("windows(2) yields 2-slices") }` instead of
  `w[0]/w[1]` indexing — same safety, no footgun for future refactors.

### Changed (refactor audit pass 4, 2026-05-02)

Eight LOW/TRIVIAL findings from a focused re-audit + two test-suite
hygiene wins (C5/C6) and one re-export trim (B13). Zero behaviour
changes for library callers; one CLI behaviour change (F3).

- **F1 — `HashSet<u64>` in vacuum scrub paths.**
  `Space::vacuum_data_batches` and `Space::scrub_data_batches`
  previously built `to_drop: Vec<u64>` and used `to_drop.contains`
  inside a `.retain()` — quadratic in the dropped-slot count. Both
  now use `HashSet<u64>`, making the retain loop O(N). For the
  expected workload (≤ thousands of slots) this is invisible; for
  pathological 100k-batch repacks it's a ~50× win.
  See `crates/hidden-volume/src/space/mod.rs:1145,1253`.
- **F2 — `checked_mul` in mmap expected-length computation.**
  `streaming_open` previously did `(1 + total) as usize *
  CHUNK_SIZE` with implicit u64→usize→multiply chain. On a 32-bit
  target (or with corrupted `total` near `usize::MAX`) this could
  silently wrap. Replaced with `checked_add(1).ok_or(...)` then
  `checked_mul(CHUNK_SIZE).ok_or(...)`. Defensive — no exploitable
  bug on 64-bit hosts. See `src/open/mod.rs:348`.
- **F3 — `HV_PASSWORD` env-var fallback removed from `hv` CLI.**
  The CLI previously read `HV_PASSWORD` if set, ahead of stdin
  prompting. Env vars leak via `/proc/<pid>/environ` to anyone with
  ptrace_scope=0 access and (worse) into shell history when set
  inline (`HV_PASSWORD=… hv …`). Stdin-only is the correct UX. CLI
  tests rewired to spawn with `Stdio::piped()` and write
  `password\n` to the child. Breaking for anyone scripting the CLI
  via env — the recommended replacement is `printf 'pw\n' | hv …`
  or `--value-stdin` (F4) for puts.
- **F4 — `hv put --value-stdin` flag.** Previously the put
  subcommand required the value on the argv (`hv put … KEY VALUE`),
  which leaks the value via `ps`/`/proc/<pid>/cmdline`. With
  `--value-stdin`, the second line of stdin (after the password) is
  consumed as the value. `value` is now `Option<String>` with
  `conflicts_with = "value_stdin"` and `required_unless_present`
  semantics — clap rejects bad combinations.
- **F5 — `RepackOptions::default()` in CLI.** The `repack`/`compact`
  subcommands constructed `RepackOptions { argon2:
  Argon2Params::DEFAULT, ..Default::default() }`. Since
  `Argon2Params::DEFAULT` *is* `Argon2Params::default()`, the
  explicit field was redundant. One line. See `src/bin/hv.rs`.
- **F6 — `lib.rs` `# Status` doc drift.** The crate-level rustdoc
  still claimed "v0.1 (current) / v0.2 (in progress)" — six
  releases stale. Updated to reflect the actual posture: pre-1.0
  freeze, v0.1–v0.7 closed in `CHANGELOG.md`, v0.8 FFI scaffold
  landed.
- **F7 — `parse_params` explicit `unreachable!`.** clap's
  `value_parser!` already constrains `--params` to one of `min`,
  `default`, `interactive`, `bench` — the previous default arm
  panicked with a generic message. Now an explicit `"default"` arm
  + `unreachable!("clap value_parser should reject {other:?}")`.
  Documents the invariant; gives a better panic message if it ever
  *is* reached. See `src/bin/hv.rs::parse_params`.
- **F8 — inline `cursor_advance_above` in async stream.** The
  helper was a 3-line function with one caller; inlined to
  `lower = Some(last.0);` with a one-line comment explaining the
  invariant. See `crates/hidden-volume-async/src/lib.rs`.
- **B13 — chunk/mod.rs re-exports trimmed.** `MAGIC` and
  `PLAINTEXT_HEADER_LEN` were re-exported from `chunk::format` but
  had **zero external usages** (in-crate or out). Dropped from the
  re-export — they remain `pub` in `chunk::format` for the rare
  caller who needs to inspect raw chunk framing. See
  `src/chunk/mod.rs`.
- **C5 + C6 — test-suite helper extraction.** `fast_params()` (alias
  for `Argon2Params::MIN` to keep tests fast) and `scratch_path()`
  (tempfile-then-drop-then-keep-path dance) were duplicated across
  ~30 integration tests. Both now live in
  `crates/hidden-volume/tests/common/mod.rs`; consumers do
  `mod common; use common::{fast_params, scratch_path};`. Reduces
  test-file boilerplate by ~10 LOC per file. The compiler's
  `unused_imports` lint caught 26 stale `Argon2Params` imports
  left behind by the helper move; all stripped.

### Changed (refactor audit pass 3, 2026-05-03)

Final mini-pass before v1.0 freeze. Diminishing returns territory
after passes 1+2: **zero real bugs**, ~20 lines cleanup +
housekeeping.

- **B10 — `rand_core` direct dep removed** from
  `crates/hidden-volume/Cargo.toml`. **0 direct import sites**;
  pulled in transitively via `chacha20poly1305`'s `rand_core`
  feature.
- **B11 — 6 wire-format constants → `pub(crate)`.** `HEADER_LEN`,
  `HEADER_SALT_OFFSET`, `HEADER_SALT_LEN`,
  `HEADER_CONTAINER_ID_OFFSET`, `HEADER_CONTAINER_ID_LEN`,
  `FIRST_SLOT_OFFSET` had `pub` visibility but **0 external
  usages**. Shrinks public API surface before v1.0 freeze.
  `HEADER_PARAMS_OFFSET` and `HEADER_PARAMS_LEN` stay `pub` (used
  by `tests/header_params.rs` for header-tamper tests).
- **B12 — `AAD_LEN` → `pub(crate)`** + dropped from
  `crypto::mod` re-export. Used internally by `seal`/`open` array
  signatures but **0 external callers** (tests obtain AAD via
  `make_aad()` which is still `pub`).
- **E8 — `.gitignore` expanded** with stock Rust entries
  (`.idea/`, `.vscode/`, `*.swp` / `*.swo`, `*.bak`, `.DS_Store`,
  `Thumbs.db`, `.env*`, `/dist/`, cargo-fuzz artifacts).
  Previously only `/target` + `/.agent/`.

**Deferred (architectural, post-1.0 candidates):**
- **E5** — extract `OwnedSpace` helper to dedupe `SpaceInner`
  self-referential pattern across async + FFI crates (~30 lines
  duplicated incl. `unsafe { transmute }` safety comments).
  Centralizes unsafe to one safety-review point but requires API
  design pass.
- **E6** — generic `run_blocking` helper. Different error types
  (`Result` vs `HvResult`) make extraction non-trivial; ~10 lines
  each is small enough to leave.
- **E7** — split `space/mod.rs` (1485 lines) into submodules.
  `impl Space<'f>` block is contiguous and well-organized; auditors
  prefer top-to-bottom read.

### Changed (refactor audit pass 2, 2026-05-02)

Second-pass cleanup after pass 1's 11-item run. Pass 2 found ~75 lines
of additional cleanup + 1 footgun (`Namespace::default()` returning
the reserved/rejected namespace). **No real bugs**; pure code-quality
polish + dead-code removal. ~9 items addressed.

- **B5 — `impl Default for Namespace` removed.** Previously returned
  `Namespace::RESERVED`, but every `Tx::put` / `Tx::delete` /
  `Tx::append_log` rejects `RESERVED` as invalid. Calling
  `Namespace::default()` produced an unusable value that always
  failed at the next call site — pure footgun. `LeafNode` and
  `InternalNode`'s `#[derive(Default)]` removed accordingly (no
  external callers; constructors `LeafNode::new(ns)` and
  `InternalNode::new(ns)` remain).
- **A7 — `Error::NotImplemented` variant removed.** Declared in the
  `Error` enum + mirrored in FFI's `HvError` but **never constructed
  by any production code**. Pure placeholder. The `_ => HvError::Internal`
  catch-all in the FFI `From<hidden_volume::Error>` impl already
  handles any future variant safely.
- **A6 — `ffi-uniffi` Cargo feature removed.** Empty `[]` placeholder
  feature in `crates/hidden-volume/Cargo.toml`; never gated any code.
  Real FFI lives in the separate `hidden-volume-ffi` crate. Stale line
  in `docs/SEMVER.md` also removed.
- **B7 — `compact_all` / `compact_all_cancellable` removed.** Both
  had bit-identical bodies to `compact_known` / `_cancellable`
  (same `compact_in_place_impl` call). The supposed semantic
  difference ("caller asserts they have all passwords") was
  documentation-only and not enforced. Now there's one canonical
  `compact_known` with destructive-drop semantics documented in its
  rustdoc + the historical-note in `docs/INTEGRATION.md`. Tests
  using `compact_all*` updated to call `compact_known*`.
- **B6 — `crypto::derive_subkey` → `pub(crate)`.** No external
  callers; only used by `SpaceKeys::from_master`. The fixed-context
  BLAKE3 schedule (`b"hv/v1/space/aead"`) is part of the on-disk
  key-schedule contract — exposing publicly invited misuse with
  arbitrary `context` bytes that would silently fork the schedule.
  Type-regression test moved into `crypto/derive.rs` as a
  `#[cfg(test)] mod tests` block.
- **B8 — `pub mod open;` → `pub(crate) mod open;`.** Every fn inside
  is `pub(crate)` already; module-level `pub` was a no-op that just
  cluttered rustdoc.
- **B9 — Stale references to removed `SpaceKeys.master` / `kdf` updated**
  in `docs/CT_AUDIT.md` and `docs/MEMORY_AUDIT.md`. Both audits now
  cite only the live `aead_root` field and historical-note the
  cleanup.
- **A8 — Bench module-doc fix.** `read_log_random` → `read_log` to
  match the actual fn name + bench label.

**Deferred:**
- **D11** — header offset/length constants → `pub(crate)`. Several
  tests in `tests/header_params.rs` use `HEADER_PARAMS_OFFSET` /
  `HEADER_PARAMS_LEN` directly; tightening would require moving
  those tests into `#[cfg(test)] mod tests` inside source files.
  Not pre-1.0 critical — these constants are wire-format documentation
  and stable.
- **C4** — `bindings/{python,kotlin,swift,ruby}/*` (~11K lines)
  remain committed. Architectural decision: gitignore + CI-regenerate
  is cleaner but loses in-repo browseable reference for integrators.
  Pending user ack.
- **D10** — `*_cancellable` API consolidation (12 methods → 6 with
  `Option<&CancelToken>`). Heavy refactor; defer post-1.0.

### Changed (refactor audit pass 1, 2026-05-02)

Pre-1.0 cleanup of dead code, vestigial features, and panic-site
hardening per a comprehensive refactor audit. **~150 lines removed,
1 dead BLAKE3 derivation eliminated per space-open, 1 production
dependency dropped (`subtle`).** Breaking format change: the v1
on-disk format now strictly rejects non-zero reserved-flags bytes
and unknown chunk-kind discriminators (which were silently accepted
before).

- **Strict-mode flags validation** — `Plaintext::decode` now rejects
  non-zero values in the reserved `flags` byte at offset 5 with
  `Error::Malformed("non-zero reserved flags")`. Prevents a v1 reader
  silently accepting a v2-format chunk under unknown semantics. The
  `flags` field is no longer exposed on the `Plaintext` struct
  (always 0 on encode, validated 0 on decode); the `chunk::format::flags`
  module with its single `NONE = 0` constant is removed. Audit B3+A5.
- **Dead `ChunkKind` variants removed** — `ChunkKind::Data` (0x03) and
  `ChunkKind::Journal` (0x04) were declared in the enum but never
  produced by any writer. `from_u8` now treats those discriminator
  bytes as unknown and rejects with `Malformed`. `space/journal.rs`
  stub deleted (never implemented; superseded by `vacuum_orphans` +
  `vacuum_data_batches`). Audit A1+A2+A3.
- **Dead `SpaceKeys` fields removed** — `SpaceKeys::master` (32 B) and
  `SpaceKeys::kdf` (32 B) were written but never read. Both removed
  along with the `derive_subkey(master, b"hv/v1/space/kdf")`
  derivation step. `SpaceKeys` now contains only `aead_root` (the
  one field actually consumed by `derive_chunk_key`). Saves 64 B/space
  + one BLAKE3-keyed-hash per space-open. `from_master` no longer
  copies the master into the struct — the master key is dropped at
  end-of-derivation. Audit B1+B2.
- **`crypto::ct` module removed** — `eq_32` and `eq_slice` constant-
  time helpers were declared `pub` but used only by their own unit
  tests (audit-confirmed: 0 production callers). Doc explicitly
  framed them as "future-proofing for hypothetical sensitive
  comparisons". `subtle` dep removed from `Cargo.toml`. Audit A4.
- **D2 — Recovery now falls back from malformed-but-AEAD-valid
  Superblock.** Previously, if the highest-seq SB AEAD-passed but
  `Superblock::decode` failed (e.g. due to format-level corruption
  AEAD missed, or a v1 reader hitting a v2-format SB), `open` would
  return `Malformed` without trying lower-seq SBs. Recovery now
  collects all distinct-seq AEAD-passing SBs into a `BTreeMap<seq,
  payload>` and decodes in descending-seq order, taking the first
  success. Applied to all three scan paths: sequential
  (`scan_and_recover`), parallel (`scan_and_recover_parallel`), and
  mmap (`scan_and_recover_mmap`).
- **D4 — FFI mutex poisoning maps to `HvError::Internal`** rather
  than panicking. ~30 sites in `hidden-volume-ffi/src/lib.rs`
  changed from `.lock().unwrap()` to `.lock().map_err(|_|
  poisoned_mutex())?`. **API change:** `SpaceHandle::commit_seq()`
  and `SpaceHandle::commit_history()` now return `HvResult<u64>` /
  `HvResult<Vec<u64>>` (were `u64` / `Vec<u64>`). Same for
  `AsyncSpaceHandle`. Mirrors `hidden-volume-async`'s pattern; a
  panic across the FFI boundary would abort the foreign-side
  process. Audit D4.
- **D7+D8 — `unwrap()` panic sites eliminated.** `page.last().unwrap()`
  in async streaming methods replaced with `let Some(last) = page.last()
  else { break }`. `try_into().unwrap()` in `space::collect_leaves_*`
  replaced with `let Ok(bytes): Result<[u8; 8], _> = ... else { continue }`.
  Safe-by-construction before, but inviting bug if loop bodies were
  refactored. Audit D7+D8.

### Added
- **Fault-injection test suite** —
  [`crates/hidden-volume/tests/fault_injection.rs`](crates/hidden-volume/tests/fault_injection.rs).
  10 scenarios beyond the truncate-at-chunk-boundary matrix in
  `crash_recovery.rs`: bit-rot in data chunks (AEAD must catch),
  bit-flip in 1-of-3 SB replicas (recover via others), bit-flip in
  ALL latest SB replicas (fall back to prior seq), unaligned
  truncation, partial-trailing-chunk, garbage-tail (1 chunk / partial
  / 10 chunks), corruption + unaligned truncation combo, wrong-password
  under corruption (deniability invariant: `AuthFailed` regardless of
  what's broken). Pure byte-munging — no production-code refactor to
  abstract `File` behind a trait. Approach documented in the test
  module's rustdoc.
- **`scripts/release.sh`** — local release-artifact build script.
  Produces `dist/` with `hv` CLI binary, FFI cdylib, regenerated
  bindings, and a `SHA256SUMS` file. Mirrors the `release-build` GHA
  job; for ad-hoc local builds. Cross-compile via `TARGET=...`
  envvar.
- **`.github/workflows/ci.yml` extensions** — three new jobs:
  - `ffi-bindings-python` (Linux + macOS): builds cdylib, regenerates
    Python bindings, runs `bindings/python/test_smoke.py` end-to-end
    through ctypes. Canary for FFI binding correctness.
  - `fuzz-smoke` (nightly): 5 min/target via `cargo fuzz run --
    -max_total_time=300` for `plaintext_decode`, `decoder_family`,
    `container_open`. `continue-on-error` so PRs don't gate on a
    fuzz finding; crashes uploaded as `fuzz-crashes` artifact for
    triage.
  - `release-build` matrix (5 targets: x86_64-linux, aarch64-linux,
    x86_64-apple, aarch64-apple, x86_64-windows). Builds release
    artifacts on push to master/main, computes SHA-256 checksums,
    uploads as `release-<target>` artifacts. Validates that release
    builds compile cleanly across every target we publish for.
- **[`docs/FLUTTER_INTEGRATION.md`](docs/FLUTTER_INTEGRATION.md)** —
  Flutter integration guide. Path A (direct via `uniffi-dart` once
  stable) + Path B (per-platform plugin wrapping Kotlin/Swift
  bindings, works today). Recommended initial method subset for an
  MVP messenger; threading model (always async on main isolate);
  storage budget table; Argon2 preset selection by device class.

### Fixed
- **`Container::open` is now lenient about trailing partial chunks**.
  Previously rejected files whose size wasn't a multiple of
  `CHUNK_SIZE` with `Error::Malformed("file size not chunk-aligned")`,
  which made crash recovery impossible when the FS committed a
  partial block before fsync. Now silently rounds down — the partial
  bytes can't represent a complete AEAD-protected chunk anyway, so
  they aren't addressable as a slot. Discovered by the new fault-
  injection suite (`unaligned_truncation_skips_partial_trailing_chunk`,
  `unaligned_truncation_with_only_partial_last_chunk_works`,
  `corruption_then_unaligned_truncation_still_recovers`,
  `garbage_tail_partial_chunk_handled`). The pre-existing
  `non_chunk_aligned_truncation_is_malformed` test was renamed to
  `non_chunk_aligned_truncation_recovers_via_lenient_open` and now
  asserts the recovery behavior end-to-end.

### Added
- **Foreign-language bindings generated and committed** under
  [`bindings/`](bindings/). uniffi auto-produces idiomatic source for
  Python (`hidden_volume_ffi.py`), Kotlin (`hidden_volume_ffi.kt`),
  Swift (`hidden_volume_ffi.swift` + `*.h` + `*.modulemap`), and
  Ruby (`hidden_volume_ffi.rb`) from a single Rust source of truth
  (`#[uniffi::*]` proc-macros in `crates/hidden-volume-ffi/src/lib.rs`).
  Generated via a new in-tree
  [`uniffi-bindgen` bin](crates/hidden-volume-ffi/src/bin/uniffi-bindgen.rs)
  (uniffi 0.25+ recommended pattern — pins bindgen to the same crate
  version we use for exports, avoiding version-skew bugs from a
  globally-installed CLI). Per-language usage examples in
  [`bindings/README.md`](bindings/README.md).
- **Python end-to-end smoke test** —
  [`bindings/python/test_smoke.py`](bindings/python/test_smoke.py).
  Loads `libhidden_volume_ffi.so` via `ctypes` (through the
  auto-generated Python module) and exercises the full FFI surface:
  sync + async constructors, get/put/delete via batched `commit`,
  log read + range query, integrity verify, stats, header inspection,
  AuthFailed deniability check, durability across reopen. **5/5
  pass on Python 3.14.** Canary for binding correctness — same uniffi
  machinery generates Kotlin / Swift / Ruby, so a Python pass is
  strong evidence for the others.
- **`AsyncSpaceHandle` in `hidden-volume-ffi`** — async sibling of
  `SpaceHandle` for Kotlin coroutines / Swift `async/await`. Every
  sync method has an `async` equivalent (constructors `create`/`open`,
  reads `get` / `count` / `list_namespaces` / `read_log` /
  `iter_log_range` / `commit_seq` / `commit_history` / `stats` /
  `verify_integrity`, write `commit`). Internally each `async fn`
  offloads the sync-core call to `tokio::task::spawn_blocking`; the
  internal mutex (shared with `SpaceHandle` via the same `SpaceInner`
  type) is held only during the offloaded work, so concurrent async
  tasks can interleave between calls. uniffi `tokio` runtime
  feature starts a Tokio multi-thread runtime inside the Rust dylib
  for Kotlin/Swift integrators automatically. Pure-Rust callers
  wrap in `#[tokio::main]`. ADR §"Decision 6" rewritten — sync and
  async are now sibling surfaces rather than sync-only. Coverage:
  5 new `#[tokio::test]` tests in
  `crates/hidden-volume-ffi/src/lib.rs` (async create/open round-trip
  with reopen + AuthFailed, async iter_log_range, async
  verify+stats, async concurrent calls serialize correctly via
  20 spawned tasks against one handle, async empty-commit no-op).
- **`AsyncSpace` in `hidden-volume-async`.** Companion to `AsyncContainer`
  that keeps an opened `Space` alive across async calls (self-referential
  `Box<Container>` + `ManuallyDrop<Space<'static>>` behind `tokio`-friendly
  `std::sync::Mutex`). Solves the lifetime mismatch where a `Stream`
  yielding paginated log entries cannot re-open the Space on every
  `poll_next` (would pay the open-time scan repeatedly — hundreds of ms
  per poll on a 50K-slot container).
  - `AsyncSpace::create(path, password, params)` — bootstrap a fresh
    container + space in one `spawn_blocking`.
  - `AsyncSpace::open(path, password)` — open existing.
  - `AsyncSpace::run(closure)` — arbitrary `&mut Space<'_>` ops on the
    blocking pool.
  - **`stream_log_pages_after(ns, after, page_size)`** — async forward
    pagination, oldest-first. Returns `impl Stream<Item = Result<Vec<(u64, Vec<u8>)>>>`.
  - **`stream_log_pages_before(ns, before, page_size)`** — async reverse
    pagination, newest-first. The canonical "scroll up to load older
    messages" primitive for chat UIs.
  - **`stream_log_pages_range(ns, start, end, page_size)`** — async
    half-open `[start, end)` range. Pair with timestamp-encoded `log_id`s
    for cheap async date-range queries.
  Each `poll_next` runs one `spawn_blocking` task that grabs the mutex,
  fetches the next page via the corresponding sync `iter_log_*` method,
  and releases the lock — so other async tasks can interleave between
  pages. New deps: `futures-core` (Stream trait, zero transitive deps) +
  `async-stream` (try_stream! macro). Coverage: 10 new tests in
  `tests/async_streaming.rs` (forward, reverse, cursor offset, range
  half-open, unbounded above/below, degenerate, empty namespace,
  durability across reopen, run+stream interplay).
- **`crates/hidden-volume/fuzz/` cargo-fuzz scaffold** (v0.5 fuzzing
  milestone follow-up). Three coverage-guided fuzz targets via
  `libfuzzer-sys`:
  - **`plaintext_decode`** — `Plaintext::decode` directly. Hot path on
    every chunk read.
  - **`decoder_family`** — every public `decode`: `Plaintext`, `Superblock`,
    `CommitPayload`, `IndexNode`, `decode_batch`, `Argon2Params::decode`.
    Catches any format-parser regression in one target.
  - **`container_open`** — end-to-end `Container::open_readonly` on
    random byte files. Exercises magic-check, header parser, file-size
    validation, discovery-scan entry.
  Fuzz package excluded from workspace (`exclude = [...]` in root
  Cargo.toml) so stable-toolchain `cargo build --workspace` does not
  pull `libfuzzer-sys`'s nightly-only `-Z` deps. Run via
  `cd crates/hidden-volume && cargo +nightly fuzz run <target>`.
  See [`crates/hidden-volume/fuzz/README.md`](crates/hidden-volume/fuzz/README.md)
  for CI integration recipe + crash-replay instructions. Stable-only
  `tests/parser_fuzz.rs` (proptest-based) remains the in-tree
  panic-freedom gate; cargo-fuzz adds coverage-guided exploration for
  v1.0 external review.
- **`hidden-volume-ffi` crate** (v0.8 milestone scaffold). uniffi 0.28
  proc-macro-based FFI bindings — generates idiomatic Kotlin/Swift/
  Python/Ruby bindings from a single Rust source of truth (no UDL
  drift). Surface: `SpaceHandle::create` / `::open` constructors,
  read methods (`get`, `count`, `list_namespaces`, `read_log`,
  `iter_log_range`, `commit_seq`, `commit_history`, `stats`,
  `verify_integrity`), batched `commit(Vec<WriteOp>)` with `Put` /
  `Delete` / `AppendLog` ops in one Tx, password-less `header_info`
  free function. Error type: flat `HvError` enum (1:1 mirror of
  `hidden_volume::Error`) → typed exceptions on the foreign side.
  Internal layout: self-referential `SpaceInner` (boxed
  `Container` + `ManuallyDrop<Space<'static>>`) pinned behind
  `Mutex` — keeps `Space` alive across FFI calls without paying the
  O(N) trial-decrypt scan per call. ADR + integration guide in
  [`docs/FFI_DESIGN.md`](docs/FFI_DESIGN.md). Build pipeline (iOS
  xcframework, Android `.aar`, Flutter sample) explicitly deferred
  to v0.8.x — Rust scaffold does not depend on them. Coverage: 5 FFI
  integration tests in `crates/hidden-volume-ffi/src/lib.rs`
  (`create_open_round_trip`, `header_info_works_no_password`,
  `iter_log_range_through_ffi`, `verify_integrity_through_ffi`,
  `empty_commit_is_noop`).
- **Public API baseline snapshot** — [`docs/PUBLIC_API_v1.txt`](docs/PUBLIC_API_v1.txt),
  297 lines covering both `hidden-volume` and `hidden-volume-async` crates.
  Generated by grep-extraction (`cargo public-api` install blocked by
  `openssl-sys` build dep in our sandbox; grep dump is stable, sortable,
  and adequate for v1.0 freeze diffing). When the OpenSSL dev headers
  are available in CI, swap to `cargo public-api --simplified` for a
  semantically richer dump.
- **`BENCH.md` § "v0.6 perf-target validation".** Compares the original
  v0.6 aspirations (scan ≥5 GiB/s x86, ≥1 GiB/s ARM; append ≥50 MB/s
  mobile; repack ≥100 MB/s x86) to measured numbers. Repack target
  **met** (~333 MiB/s); scan target **missed** by ~2.5× — the
  `parallel-scan` ceiling on the dev host is 2.0–2.2 GiB/s, bound
  inherently by per-chunk XChaCha20-Poly1305 (~1.5 GiB/s/thread × 4
  threads with the contention-cliff cap). Revised v1.0 targets in the
  doc: ≥1.5 GiB/s x86, ≥300 MiB/s Cortex-A53. ARM measurement
  deferred to v0.8 (FFI / `.aar` deployment). Append re-formulated as
  Tx-batched throughput (50 MB/s sustained at ≥100 KB Tx commits), since
  the 3-fsync floor dominates raw byte-rate.
- **`hv` CLI: `verify` and `dump-stats` subcommands.** Both are
  read-only (LOCK_SH); password from stdin or `HV_PASSWORD`. `verify`
  walks the Merkle tree under the given password and prints
  `(namespaces_verified, chunks_verified, max_depth, status: ok)` —
  surfaces `Error::IntegrityFailure { detail, slot }` as nonzero exit
  on tampering. `dump-stats` prints aggregated `SpaceStats`
  (`commit_seq`, `commit_history_len`, `owned_chunk_count`,
  `total_entries`, per-namespace counts) — the same data
  host-app's "About this profile" UI would render. Coverage: 5 new
  CLI tests in `tests/cli.rs` (fresh-space verify, post-write verify,
  wrong-password verify, fresh-space dump-stats, post-write dump-stats).
  Closes the v0.3.x CLI scope (now: info / create / create-space /
  inspect / get / put / verify / dump-stats / repack).
- **`Space::iter_log_range(namespace, start, end, limit)`** — half-open
  range query over a log namespace, returning up to `limit` entries
  with `log_id` in `[start, end)` in ascending order. `None` on either
  side means unbounded. Walks B+ tree leaves left-to-right with early
  termination as soon as either `limit` is reached or an entry past
  `end` is observed (subtrees rooted to the right of `end` are not
  visited). Memory bound: O(limit). Pair with timestamp-encoded
  `log_id`s for cheap chat date-range queries
  ("messages from yesterday to today"). Coverage: 13 new tests in
  `tests/log_pagination.rs` (R1-R13: empty namespace, zero limit,
  degenerate range, equivalence to `iter_log_after`, lower-only,
  upper-only, both-bounds half-open, off-by-one at start/end, limit
  capping, range past last entry, range across DataBatch boundaries,
  sparse ids).
- **Auto-splitting log batches at commit time.** A Tx that touches the
  message-log namespace with many or incompressible records (random /
  base64 / already-encrypted blobs) no longer fails commit with
  `Error::PayloadTooLarge` from `encode_batch`. The new
  [`log::encode_batches_split`] in `crates/hidden-volume/src/space/log.rs`
  recursively halves the record set until each batch fits under
  `PAYLOAD_CAP` (4040 bytes); `commit_tx` emits one `DataBatch` chunk
  per resulting batch and routes per-record KV pointers accordingly.
  Split is transparent on read (`read_log` / `iter_log_*` follow KV
  pointers, not batch boundaries). Validates with two new integration
  tests in `tests/log_basic.rs`: 32×2 KiB random payloads in one Tx
  produce ≥8 batches all readable; pagination works across the splits.
  Common-case cost (records compress well, ≤ ~150 short messages):
  exactly one zstd call, no behavior change.
- **`#![deny(missing_docs)]` quality gate** on both `hidden-volume`
  and `hidden-volume-async` crates. Every public item — types,
  variants, constants, struct fields, methods, free functions —
  now carries a rustdoc comment. Closes 76 missing-doc warnings
  introduced by the lint promotion. The crate now fails to build
  if a future PR adds an undocumented `pub` item.
- **`#[must_use]` markers on 40 pure accessor / constructor /
  encoder methods** across the workspace. Cuts a class of bugs
  where callers forget to consume the return value of e.g.
  `Tx::is_empty()`, `Space::commit_seq()`, `Superblock::encode()`,
  `derive_chunk_key()`. `cargo clippy -W clippy::must_use_candidate`
  now reports zero candidates.

### Changed
- **CI workflow refresh** (`.github/workflows/ci.yml`): updated for
  the v0.7 workspace split + new feature flags (`parallel-scan`,
  `mmap`). Pre-existing `--features async` references removed (no
  longer a feature; lives in `hidden-volume-async` sibling crate).
  Jobs now: `test` (Linux/macOS/Windows × stable + Linux beta) on
  default features + workspace doctests + `cli`-feature subprocess
  tests; `features-unix` (Linux + macOS) running parallel-scan and
  mmap test suites separately + an all-features full-workspace
  test on Linux; `locking-unix` for the flock tests; `clippy` /
  `fmt` / `rustdoc` workspace-wide with `-D warnings`; `audit`
  (RustSec advisory-db, continue-on-error); `deny` (cargo-deny
  policy from `deny.toml`); `bench-check` (compile only); MSRV
  pin job on Rust 1.85.
- **Rustdoc broken-intra-doc-links fixed** in
  `crates/hidden-volume/src/container/mod.rs`,
  `crates/hidden-volume/src/crypto/derive.rs`,
  `crates/hidden-volume/src/tx/commit.rs` so the rustdoc CI job
  passes with `RUSTDOCFLAGS=-D warnings`.

### Added
- **`deny.toml`** — cargo-deny supply-chain policy at the workspace
  root. License whitelist (MIT, Apache-2.0, BSD-{2,3}-Clause, ISC,
  Unicode-3.0, Zlib, MPL-2.0, CC0-1.0); advisory-db check via
  RustSec; deny multi-version dups (warn) + wildcards (deny);
  explicitly deny `openssl` / `openssl-sys` / `native-tls` (the
  crate uses RustCrypto exclusively); registry source restricted
  to crates.io. Targets cover Linux x86_64+aarch64, macOS x86_64+
  aarch64, Windows MSVC.

### Changed
- **Public API freeze prep — `#[non_exhaustive]` audit.** The
  following enums and library-constructed-only structs are now
  marked `#[non_exhaustive]`, so future minor releases may add
  variants/fields without bumping major:
  - `Error` (enum) — has grown 5 → 12 variants pre-1.0.
  - `ChunkKind` (enum) — format reserves room for new chunk kinds.
  - `PaddingPolicy` (enum) — new policies may land later.
  - `IntegrityReport` (struct) — only the library constructs it.
  - `SpaceStats` (struct) — same.
  Downstream `match` arms on these enums MUST include a `_ =>`
  catch-all from this point forward. Destructuring the structs
  (`let SpaceStats { commit_seq, .. } = stats`) continues to
  work; struct-expression construction from outside the crate is
  forbidden — but only the library constructs them anyway.

  `ContainerOptions` and `RepackOptions` are deliberately NOT
  `#[non_exhaustive]` — that would forbid the natural
  `Foo { a: …, b: … }` syntax even with FRU. We accept that
  adding a field there is a major bump post-v1.0; the budget is
  documented in `docs/SEMVER.md` §1.2.1. Other format-internal
  pub types (Header, Plaintext, Superblock, IndexNode tree types,
  CommitPayload) stay non-`#[non_exhaustive]` so tests + parser-
  fuzz can construct them; the actual stability target there is
  the *byte layout* in `FORMAT_v1.md`, not the struct shape.

  `docs/SEMVER.md` updated with the policy table.

### Added
- **`docs/FORMAT_v1.md`** — canonical byte-level wire format spec
  (12 sections / ~480 lines), foundation for v1.0 format freeze
  and external crypto review. Covers: top-level container layout
  (header 80 B cleartext + chunk grid), Argon2 params encoding,
  per-chunk wire layout (24 B nonce / 4056 B ciphertext / 16 B
  tag), AAD construction, plaintext frame (magic / kind / flags /
  seq / payload_len / payload / pad), key schedule (Argon2id →
  BLAKE3-keyed derivation chain with `hv/v1/space/*` labels), all
  six `ChunkKind` payload encodings (Superblock / IndexNode {Leaf,
  Internal} / Data / Journal / Commit / DataBatch zstd-compressed),
  Tx commit 3-fsync protocol with crash-recovery contract, discovery
  scan + deniability invariant explanation, format-constant table,
  reservation bytes for non-breaking v1.x extensions (plaintext
  `flags` byte + Argon2 `params_version`), what is NOT in the
  format (no magic / no version marker / no TOC / no timestamps —
  ruled out for parser-differential reviewers), audit checklist
  for external reviewers, format change log scaffold.
- **`docs/SEMVER.md`** — semver coverage policy (7 sections):
  what's covered (public Rust API + on-disk format + Cargo
  features), what's NOT (internal modules, dep versions, MSRV,
  bench numbers, error message strings), version-to-format mapping
  (1.x.y reads + writes v1; hypothetical 2.x.y reads v1 + writes
  v2; 3.x.y v2-only with one-major-version deprecation cadence),
  yank policy (when to yank vs not), pre-release posture
  (alpha → rc → 1.0.0 sequence), out-of-band guarantees (format
  stability, test coverage, audit traceability, breaking-change
  rationale).
- Cross-links from `DESIGN.md` §2 (now points to `FORMAT_v1.md` for
  byte-level reference), `README.md` Status section, and
  `INTEGRATION.md` "Where to read next" table.

- **mmap reader** (feature `mmap`, Unix-only). New
  `Container::open_space_mmap(password)` /
  `open_space_with_keys_mmap(keys)` use a single `mmap(2)` of the
  entire container file and slice each chunk out of the mapping
  during the discovery scan — zero allocation per chunk on the
  read path. Behaviorally identical to `open_space` / `open_space_parallel`:
  same `Space` state, same vacuum semantics. The feature opts in
  to a `memmap2` dependency (~80 KiB compiled) and an `unsafe`
  `Mmap::map(&File)` call; concurrent file mutation is excluded by
  the `LOCK_EX` / `LOCK_SH` flock acquired at `Container::open` /
  `open_readonly` time. `ContainerFile::raw_file()` is a new
  crate-internal accessor for the underlying File handle (only
  compiled under the feature). `tests/mmap_scan.rs` (7 scenarios)
  cross-checks behavioral equivalence against both sequential and
  parallel scans, plus wrong-password / empty-file / with-keys
  edge cases. Closes the v0.6 mmap-reader deliverable.

### Changed
- **Workspace split** (v0.7 closeout). Repository layout is now a
  cargo workspace with two member crates:
  - `crates/hidden-volume/` — sync core, tokio-free.
  - `crates/hidden-volume-async/` — Tokio wrapper exposing
    `AsyncContainer`. Depends on `hidden-volume` via path.
  Top-level `Cargo.toml` is the workspace manifest; profiles
  (`release`, `bench`) are workspace-shared. `Cargo.lock` lives at
  the workspace root and covers both crates.
  The `async` feature flag is **removed** from the core crate —
  async users now opt in by depending on `hidden-volume-async`
  explicitly. Sync-only consumers (mobile, single-process desktop,
  embedded) pay zero tokio cost. `tokio` is no longer a dev-
  dependency of the core crate.
  Async tests moved out of the core crate:
  `crates/hidden-volume-async/tests/async_basic.rs` (7) +
  `crates/hidden-volume-async/tests/cancellation.rs` (1, formerly
  the `#[cfg(feature = "async")]` test in
  `tests/cancellation.rs`). `cargo test --workspace` still green.
  Public sync API surface is unchanged: import paths under
  `hidden_volume::*` are identical, only `hidden_volume::async_api`
  → `hidden_volume_async` (via the new crate's name).
- README "Architecture" diagram and "Async / Tokio integration"
  section updated to reflect the new layout. `INTEGRATION.md` §6
  updated.

### Added
- **`docs/OPERATIONS.md`** — operations playbook (10 sections):
  backup / restore with anchor warning, single + multi-space key
  rotation, Argon2 parameter migration via repack, corruption
  diagnostic + recovery (4 incident classes), storage budget
  management with vacuum_data_batches vs compact_known guidance,
  multi-device deployment patterns A-D, forensic scrub before
  disposal (best-effort logical + defense-in-depth: FDE / tmpfs /
  USB-key), size monitoring with overhead bands, 12-symptom
  troubleshooting matrix. Closes the v1.0 docs deliverable for
  `OPERATIONS.md`.
- **`docs/MIGRATION.md`** — empty shell for eventual v1→v2 format
  migration. Documents intra-v1 ops cross-link, candidate v2
  reasons (none committed: hidden header, 3-level B+ tree,
  format-level Merkle root), forward-compatible migration
  mechanism plan (header version byte detection, repack-style
  copy, one-major-version compatibility window, re-anchor
  requirement, what NOT to do). Closes the v1.0 docs deliverable
  for `MIGRATION.md`.
- Cross-links added from `README.md` Status section and
  `INTEGRATION.md` "Where to read next" table.

- **`docs/THREAT_MODEL.md`** — formal threat model for v1.0 external
  crypto-review process. Sections: system model (what the library
  is and isn't, trusted components), adversary tiers (T1
  single-snapshot, T2/T2' multi-snapshot append-diff vs in-place-
  diff, T3 compelled-key), security invariants each with precise
  statement + code paths + supporting audit pass (D1
  single-snapshot indistinguishability, D2 compelled-key
  deniability, I1 per-chunk integrity, I2 tail-corruption
  tolerance, I3 cross-space isolation, R1 rollback / fork-detection
  contract, M1 memory hygiene, C1 cancellation safety),
  out-of-scope mitigations table, mitigation summary by code area,
  audit history (4 v0.5 passes), review request enumerating what
  external reviewers should confirm/deny per invariant. Cross-
  linked from `DESIGN.md` §1, `README.md`, `INTEGRATION.md`, and
  `PLAINTEXT_AUDIT.md`. Closes the v1.0 milestone's
  `THREAT_MODEL.md` deliverable.

- **Parallel-scan scaling benchmarks** (`bench_open_50k_*`,
  `bench_open_100k_*`). Confirms that the `parallel-scan` feature
  scales monotonically with container size on the 12-thread x86 dev
  host: 10 K → 2.8×, 50 K → 2.3×, **100 K → 7.4×** speedup. The
  sequential path drops from 770 MiB/s at 40 MiB to 270 MiB/s at
  400 MiB (page-cache hot-path falloff), while parallel pread-from-
  4-threads keeps prefetching at ~2 GiB/s. `BENCH.md` "Scaling"
  table added; recommended-when matrix updated.

- **`Space::vacuum_data_batches() -> Result<usize>`** — scrub owned
  DataBatch chunks that no namespace's KV index references anymore.
  Closes the forward-secrecy gap of `erase_namespace` on log
  namespaces (which leaves DataBatch chunks AEAD-decryptable until
  compact) AND reclaims orphan batches from log-entry overwrites
  (each re-append with the same `log_id` makes the prior batch
  unreachable). Cheaper than `Container::compact_known` for
  forward-secrecy alone — leaves `commit_history` and `container_id`
  intact while scrubbing the unreferenced bytes. Walk cost ≈
  Σ count(ns) tree walks + O(M) owned-chunk reads; read-only safe
  (returns 0 on `open_readonly`). `tests/vacuum_data_batches.rs`
  (8 scenarios): empty / fresh-log / post-erase reclaims / 5-round
  overwrite reclaims / multi-namespace isolation / idempotence /
  read-only zero / integrity-holds-after-vacuum. `docs/INTEGRATION.md`
  §10a updated with the cheaper "erase + vacuum_data_batches"
  recipe in place of the previous "erase + compact_known".

- **`Space::stats() -> Result<SpaceStats>`** — aggregate per-space
  statistics (commit_seq, commit_history_len, owned_chunk_count,
  per-namespace entry counts) in one call. The structured form
  host-app UIs render in a "Storage" / "About this profile" page.
  Walks each active namespace's KV-index tree once (cost ≈ sum of
  `count` calls per namespace); read-only safe. `SpaceStats`
  implements a `total_entries()` helper that sums across namespaces.
  `tests/space_stats.rs` (8 scenarios) — empty space, single
  namespace, multi-namespace KV+log with ascending-byte ordering,
  post-erase namespace disappears, multi-commit history advances,
  post-repack owned-count drops, read-only handle path,
  total_entries helper sums correctly. `docs/INTEGRATION.md` §8b
  documents the Storage-UI pattern.

- **`Space::erase_namespace(ns) -> Result<usize>`** — drop every entry
  in a namespace in a single transaction. Use case: "Clear chat
  history" / "Wipe contacts" UI buttons in a messenger. Returns the
  count removed. Idempotent on empty (returns 0, no commit). The new
  commit omits the namespace from its `IndexRoot` set (rebuilt tree
  is empty); orphan IndexNode chunks scrubbed by the next
  `vacuum_orphans` (auto-runs on `open_space`). For log namespaces,
  `DataBatch` chunks remain AEAD-decryptable until a subsequent
  `compact_known` — the recommended "Clear chat history" recipe is
  `erase_namespace(MESSAGE_LOG) + compact_known`. `tests/erase_namespace.rs`
  (10 scenarios) covering empty (no commit), full KV wipe, peer-namespace
  preservation, log KV-pointer removal, vacuum scrubs orphans on
  reopen, post-compact DataBatch elimination, commit_seq increment,
  double-erase idempotence, write-after-erase recreates, multi-space
  isolation. `docs/INTEGRATION.md` §10a documents the pattern with
  the forward-secrecy caveat for log namespaces.

- **`Container::change_passwords(path, mapping, options)`** +
  **`Container::change_passwords_cancellable(...)`** — in-place
  password rotation. Production-critical for messenger UX (user
  changes their password without losing data). The mapping is
  `&[(open_with, write_as)]`: equal pair preserves a space verbatim,
  unequal pair rotates it. Spaces not listed in the mapping are
  dropped (same destructive semantics as `compact_known` — list each
  preserved space as `(p, p)`). Internally refactors `repack_inner`
  into `repack_inner_mapped` so the existing `repack` /
  `repack_cancellable` are now thin wrappers around the same
  primitive (no behavior change for them). Atomic-rename pattern via
  `path.hv-rotate-tmp`: any failure (`AuthFailed`,
  `SpaceAlreadyExists`, `Cancelled`, I/O error) removes the temp and
  leaves `path` untouched. `tests/password_change.rs` (8 scenarios):
  single rotation, multi-space rotate-one-preserve-other, rotate-
  both-at-once, wrong old password → AuthFailed + tmp cleanup,
  `write_as` collision → SpaceAlreadyExists + tmp cleanup, drop-non-
  mapped spaces, no-op rotation identical to `compact_known`,
  cancellable pre-fired aborts cleanly.
- `docs/INTEGRATION.md` §10b documents the password-change pattern
  and its forward-secrecy caveat (FS-released blocks may be reused
  by the allocator; forensic-grade scrub is host-app concern).

- **`README.md` refreshed** to reflect the v0.4–v0.7 work that had
  shipped without README updates: capability table now lists
  paginated log, multi-device anchors (`commit_history`),
  `verify_integrity` Merkle walk, cancellation (`CancelToken`),
  read-only mode, streaming open, `parallel-scan` feature with the
  2.8× number, and the four completed audit passes. Quick-start
  expanded with pagination, cancellation, rollback-anchor, and
  integrity-self-test snippets. Architecture diagram updated to
  list `cancel.rs`, `async_api/`, `bin/hv.rs`. Cross-links to
  `docs/INTEGRATION.md` and `docs/MULTI_DEVICE.md`. Test inventory
  rewritten to match the current 30 test files.

- **`tests/crash_proptest.rs`** — property-based crash-recovery tests
  complementing the 8 hand-written scenarios in `crash_recovery.rs`
  and the exhaustive truncate-at-every-slot sweep in
  `many_chained_crashes`. Generates random op sequences (Put / Delete
  / AppendLog / Commit) and random truncation points, then asserts
  three invariants: (1) **recovery monotonicity** — recovered seq
  must be a seq we actually committed, and ≤ max committed seq;
  (2) **read APIs never panic post-recovery** — count / list / get /
  iter_log_after / iter_log_before / verify_integrity / commit_seq /
  commit_history all return Ok or documented Err on any reachable
  truncated state; (3) **recovery is idempotent** — two consecutive
  opens of the same truncated file yield the same recovered seq.
  24 cases × up to 30 ops each.

### Changed
- **`parallel-scan` is now a real win** on multi-core hosts (was
  measured ~5× slower than sequential in the previous iteration).
  Three changes together flipped the curve from ×0.2 to ×2.8 on a
  12-thread x86 host opening a 10 K-slot / 40 MiB container
  (52 ms → 18 ms):
  1. **Coarse-grained chunking.** Each parallel work item processes
     256 consecutive slots sequentially; amortizes rayon's per-task
     overhead over ~1.3 ms of real work.
  2. **Capped thread pool** at `min(4, available_parallelism)`.
     Empirical scaling on this host: 1 thread = 51 ms, 2 = 32 ms,
     4 = 47 ms (variable), 12 = 141 ms — AEAD-decrypt + small-chunk
     pread saturate L1 / memory bandwidth long before they saturate
     cores. 4-thread cap stays on the good side of the cliff.
  3. **`OnceLock`-cached pool.** A fresh `rayon::ThreadPool` per
     `open_space_parallel` call costs several ms; reusing the pool
     across opens reclaims that.
  All three were necessary; details + per-step measurements in
  `BENCH.md` "Parallel-scan tuning".

### Added
- **`BENCH.md` updated with v0.6/v0.7 measurements** on a 12-thread
  x86 dev machine: pagination (`iter_log_before_50` at 87 µs vs
  `iter_log_full` at 484 µs — 5.6× win confirms the messenger-
  pagination primitive), `verify_integrity` (125 µs over 1 100 KV
  entries — sub-ms self-test), large-container open-scan benchmark
  (`open_large_sequential` 52 ms / `open_large_parallel` 18 ms for
  a 10 K-slot / 40 MiB messenger-sized container — 2.8× speedup
  with `parallel-scan` feature). Bench harness gained
  `bench_open_large_*`, `bench_iter_log_full`, `bench_iter_log_paged_50`,
  `bench_verify_integrity`.

- **Parallel-scan feature (`parallel-scan`, Unix-only).**
  `Container::open_space_parallel(password)` /
  `open_space_with_keys_parallel(keys)` use rayon's work-stealing
  pool to parallelize AEAD-decrypts across slots during the open
  scan. Behaviorally identical to the sequential streaming path —
  same `Space` state, same vacuum semantics, same return type. The
  feature pulls in rayon (~6 MiB compiled); leave it OFF on
  single-core mobile, ON for desktop / server. New
  `ContainerFile::read_slot_concurrent(&self, i)` uses `pread(2)`
  via `std::os::unix::fs::FileExt::read_exact_at` so multiple
  threads read concurrently from the same `&File` handle without
  Rust-side locking. `tests/parallel_scan.rs` (6 scenarios) — same
  state as sequential, max-seq across 7 replicas × 10 commits,
  owned_slots sorted post-parallel, wrong-password → AuthFailed,
  empty file → AuthFailed, with-keys path bypasses Argon2.

- **`docs/INTEGRATION.md`** — narrative host-app integration guide.
  Covers: quickstart, hardware tuning (Argon2 presets), KV vs log
  namespace choice, multi-device patterns (cross-link to
  `MULTI_DEVICE.md`), message-history pagination via
  `iter_log_after` / `iter_log_before`, cooperative cancellation with
  `CancelToken` (sync + async patterns), rollback / fork detection
  via `commit_seq` + `commit_history`, key caching with
  `derive_space_keys` + `open_space_with_keys`, integrity walks via
  `verify_integrity`, padding policies, compaction trade-offs,
  13-point anti-patterns checklist, FAQ, doc index. Cross-linked
  from the crate-level rustdoc in `src/lib.rs`.

- **`Container::repack_cancellable(source, dest, passwords, options, &CancelToken)`**
  — cancellable variant of `repack`. Cancel checkpoints at every
  password boundary (read phase) and at every Tx commit boundary
  (write phase). The opened source space goes through
  `open_space_cancellable`, so the per-password scan loop also polls
  the token. On cancel, returns `Error::Cancelled` and leaves `dest`
  partial (caller cleans up — `compact_*_cancellable` does this for
  the in-place variant).
- **`Container::compact_known_cancellable`** /
  **`Container::compact_all_cancellable`** — cancellable in-place
  compactions. On cancel, the temp `path.hv-compact-tmp` is removed
  and the original `path` is untouched (atomic rename hasn't run).
- `tests/repack_cancellation.rs` (7 scenarios) — pre-fired token,
  pre-fired compact with tmp-cleanup verification, mid-flight cancel
  with 3 passwords (race-tolerant), fresh token after cancelled
  succeeds, never-cancelled `repack_cancellable` matches plain
  `repack` byte-for-byte, compact_all pre-fired with tmp cleanup,
  cancel during write phase.

- **`Space::iter_log_after(ns, after: Option<u64>, limit)`** — forward
  cursor pagination over a log namespace. Returns up to `limit`
  entries with `log_id > after` (or all entries if `after = None`),
  ascending. Memory-bounded: O(limit) decoded entries plus a few
  touched DataBatch chunks. Independent of total namespace size.
- **`Space::iter_log_before(ns, before: Option<u64>, limit)`** —
  reverse cursor pagination (newest-first). Up to `limit` entries
  with `log_id < before`, descending. The canonical chat-UI primitive
  for "scroll up to see older messages". Same memory bounds as
  `iter_log_after`.
- The B+ tree walk now early-stops on the leaf level once `limit` is
  reached — pagination cost is `O(limit + leaves_touched)` rather
  than `O(N)`.
- `tests/log_pagination.rs` (13 scenarios): empty namespace / limit=0,
  full-forward & full-reverse equivalence with `iter_log`, cursor
  walks forward and reverse over a 200-msg log, across-DataBatch-
  boundary pagination (1500-msg multi-tx log), out-of-range cursors,
  sparse log_ids, limit > total, B+ tree split case, payload integrity
  preserved end-to-end through pagination.
- Existing `Space::iter_log` is now a thin sugar over the shared
  `decode_log_entries` helper that powers all three iter APIs.

- **`hidden_volume::cancel::CancelToken`** — cooperative-cancellation
  primitive (a thin `Arc<AtomicBool>`). `cancel()` / `is_cancelled()` /
  `check()` for use as a `?`-friendly poll point inside long sync
  operations. Cheap to clone; firing from any thread short-circuits
  every existing and future clone.
- **`Container::open_space_cancellable(password, &CancelToken)`** and
  **`Container::open_space_with_keys_cancellable(keys, &CancelToken)`**
  — same semantics as `open_space` / `open_space_with_keys` but the
  O(N) scan polls the token every 64 slots and returns
  `Error::Cancelled` if fired. Argon2id derivation itself is NOT
  cancellable (RustCrypto is uninterruptible), so there is a
  post-Argon2 cancel check before the scan begins. Mid-cancel state:
  no observable file side effects.
- **`Error::Cancelled`** variant — distinguishes user-initiated abort
  from `AuthFailed` / I/O errors.
- **`AsyncContainer::run_cancellable(token, |c, t| ...)`** — bridges
  async-side cancellation into the sync core. Necessary because
  `tokio::task::spawn_blocking` does not abort a running closure;
  the threaded `CancelToken` is the workaround.
- `tests/cancellation.rs` (10 scenarios) — flag/clone/idempotency,
  pre-fired abort, mid-scan race + post-cancel file integrity check,
  reuse-after-cancel, independent fresh tokens, isolation from
  non-cancellable API, with-keys path, async `run_cancellable`.

### Changed
- **`scan_and_recover` is now streaming** (v0.6). The previous
  implementation collected every decrypted Plaintext into a `Vec<Found>`
  for the duration of the scan — ~4 KiB of heap per owned chunk. The
  refactor drops each Plaintext at the end of its iteration and
  accumulates only `owned_slots: Vec<u64>` (8 B/owned chunk),
  `commit_history: Vec<u64>` (8 B/Superblock after dedup), and the
  current best-seq Superblock's raw payload (~48 B). Asymptotic memory
  drops from `O(M · PLAINTEXT_LEN)` to `O(M · 16 B)` — ~250× smaller —
  letting weak ARM devices open multi-GiB containers without OOM.
  Public API unchanged. `tests/streaming_open.rs` (6 scenarios) covers
  many-commit roundtrip, replica dedup, max-seq across many replicas,
  owned_slots completeness, mixed KV+log workload, and large-history
  stress. **Breaking nothing observable**, just the memory profile.

### Added
- **`Space::verify_integrity() -> Result<IntegrityReport>`** — explicit
  Merkle hash-chain walk from the current Superblock down to every
  leaf. Verifies `SB.root_hash` against `BLAKE3(concat(roots[i].payload_hash))`,
  the CommitPayload's stored `tx_root_hash` for internal consistency,
  each `IndexRoot.payload_hash` against the actual hash of the
  IndexNode chunk's plaintext, and recursively each `ChildPointer.child_hash`
  for Internal-node children. Read-only safe (works on
  `Container::open_readonly` handles). Returns
  `IntegrityReport { namespaces_verified, chunks_verified, max_depth }`.
  AEAD-decrypt failures on chunks the integrity walk expected to own
  surface as `Error::IntegrityFailure { detail, slot }` instead of
  `AuthFailed`, so host-apps can distinguish "wrong password / not our
  chunk" from "owned chunk corrupted". Cost: O(N) chunks reachable
  from current Superblock, each read once and BLAKE3-hashed.
- **`Error::IntegrityFailure { detail: &'static str, slot: u64 }`** —
  raised exclusively by `verify_integrity` so the caller can localize
  corruption to a specific slot.
- `tests/integrity.rs` (10 scenarios) — empty, single-leaf, multi-namespace,
  B+ tree split (depth=2), DataBatch log namespace, multi-space
  isolation, post-compact, AEAD-corruption of IndexNode root and Commit
  chunk both surface as IntegrityFailure pointing at the corrupted slot,
  read-only handle path.
- **Plaintext-leak audit pass (`docs/PLAINTEXT_AUDIT.md`)** — fourth and
  final v0.5 audit. Wraps 7 transient plaintext buffers in `Zeroizing`
  so heap/stack regions are scrubbed at drop: `aead::ChunkAead::open`
  return value (`Zeroizing<Vec<u8>>`), `space::append_chunk` `pt_bytes`
  (`Zeroizing<[u8; PLAINTEXT_LEN]>`), `space::log::encode_batch` /
  `decode_batch` raw concat / decompress buffers, and
  `space::write_tree_for_namespace` LeafNode / InternalNode encoded
  bytes (which carry user key/value bytes). User-owned `Vec<u8>`s
  (`Tx::pending_*`, `Space::get`/`list`/`iter_log` returns, decoded
  `IndexNode` entries) explicitly deferred with rationale; cross-linked
  in `MEMORY_AUDIT.md` §C.
- `tests/plaintext_hygiene.rs` (4 tests) — type-level regression locking
  in `Zeroizing` wrap on `ChunkAead::open` and on the auto-deref chain
  callers depend on.
- **`Space::commit_history() -> &[u64]`** — sorted-ascending,
  deduplicated list of every commit-anchor seq still on disk (Superblock
  chunks that AEAD-decrypt under the space's key). For host-app rollback
  / fork triage and P2P-sync logic. O(1) accessor; populated from the
  same trial-decrypt scan that already runs at `open_space` time and
  updated in-place on every successful `commit_tx`. The initial Superblock
  written at `create_space` (seq=1) counts. Replicas at the same seq are
  deduplicated. Compaction resets the destination to a fresh history
  (host must re-anchor).
- **`docs/MULTI_DEVICE.md`** — formal contract for host-apps building
  P2P sync over `hidden-volume`. Documents the four supported patterns
  (single / sequential hand-off / read-only fan-out / replicated
  containers), what the library does and does NOT do, anchor primitives
  + rollback-detection algorithm, and the privacy contract for
  anchoring decoy / hidden spaces.
- `DESIGN.md` §11.2 updated to reference `MULTI_DEVICE.md`.
- `tests/multi_device.rs` (8 scenarios): fresh=[1], grows monotonically,
  dedups replicas at superblock_replicas=3, survives reopen, host-app
  triage of rollback/fork/clean, cross-space isolation, compaction
  resets, readonly exposes.
- **`tests/messenger_simulation.rs`** — 8 end-to-end scenarios
  modeling realistic messenger workloads: 5-day simulation with
  100 messages + contacts/settings churn; 3-week simulation with
  weekly compaction validating storage stays bounded; 22 reopen
  cycles preserving day-1 readability; delete+compact eliminates
  message bytes (forward-secrecy claim); concurrent writer/reader
  handoff (10 rounds); hidden-space-coexists-with-main; drop-decoy-
  via-compact_known; long-running session (30 rounds, mixed KV +
  log workload).
- **`hv` CLI utility** (`cli` feature). 7 subcommands: `info`,
  `create`, `create-space`, `inspect`, `get`, `put`, `repack`.
  Reads passwords from stdin or `HV_PASSWORD` env. `tests/cli.rs`
  (8 scenarios) spawning the binary via `CARGO_BIN_EXE_hv`.
- **`Container::open_readonly(path)`** + **`Container::is_readonly()`** —
  opens with shared `flock(LOCK_SH)`; multiple readers can coexist
  concurrently. Used by P2P sync agents, backup tools, forensics.
- **`Error::ReadOnly`** variant — returned by `create_space`,
  `set_padding_policy`, `set_superblock_replicas`, and any `Tx::commit`
  on a read-only handle. `vacuum_orphans` becomes a silent no-op.
- `tests/readonly.rs` (10 scenarios): basic open, multiple-readers
  coexist, writer-blocks-reader and vice-versa, all write methods
  return ReadOnly, vacuum-no-op, sequential reader/writer handoff.
- **`CONTRIBUTING.md`** — open-source workflow docs.
- **`Container::derive_space_keys(password) -> Result<SpaceKeys>`** —
  exposes Argon2id derivation as a separate step.
- **`Container::open_space_with_keys(SpaceKeys) -> Result<Space>`** —
  opens a space using pre-derived keys, skipping Argon2id (~100 ms
  saved on every relaunch).
- Cross-session caching workflow: host-app calls `derive_space_keys`
  once, persists `SpaceKeys` in OS-level secret store (Keychain /
  Secret Service / Keystore), reuses across sessions via
  `open_space_with_keys`.
- `tests/keys_cache.rs` (6 scenarios): same-keys path, byte-for-byte
  determinism, wrong-keys → AuthFailed, Clone semantics, AAD binding
  prevents cross-container key reuse, password vs cached comparison.

### Changed
- Migrated file locking from `fs2` crate to std's native `File::try_lock`
  / `try_lock_shared` (stable since Rust 1.89). Drops one external
  dependency. Same `flock(2)` / `LockFileEx` semantics as before.
- `Container::set_padding_policy` and `set_superblock_replicas` now
  return `Result<()>` instead of `()` to surface `Error::ReadOnly`
  on read-only handles. Existing callers updated.

### Documented
- Security trade-off: caching `SpaceKeys` outside the process
  bypasses Argon2id's brute-force resistance. An attacker with file
  + keyring contents recovers data without password. Use platform-
  native secure storage; document the trade-off in host-app's
  security policy.

## [v0.7] — Tokio async wrapper

### Added
- **`async` feature flag** that enables `hidden_volume::async_api`
  with `AsyncContainer` — a thin wrapper around `Container` that
  offloads sync operations onto Tokio's blocking-thread pool via
  `spawn_blocking`. Sync core unchanged.
- **`AsyncContainer::run<F>(closure)`** — generic offload of any
  `FnOnce(&mut Container) -> Result<R>`. Host-apps batch their work
  inside one `run()` call, matching the natural transactional
  granularity.
- `AsyncContainer::create` / `create_with_options` / `open` for
  lifecycle, plus `set_padding_policy` / `set_superblock_replicas`
  for runtime config.
- `Clone` impl shares the underlying `Container` via `Arc<Mutex<_>>`;
  concurrent `run()` calls from cloned handles serialize on the mutex.
- **`tests/async_basic.rs`** (7 scenarios, feature-gated): create,
  open-and-read, typed return, clone-shares-container, concurrent
  serialization via mutex, padding policy via async API, error
  propagation.
- CI now runs `cargo test --features async --tests` in addition to
  the default-feature suite.

### v0.5 closeout
- **fsync ordering audit** ([`docs/FSYNC_AUDIT.md`](docs/FSYNC_AUDIT.md)):
  traced 7 fsync sites; 3-fsync barrier protocol in `commit_tx`
  matches DESIGN §6 and tests/crash_recovery.rs. Documented macOS
  `F_FULLFSYNC` as out-of-scope (host-app concern).

## [v0.5] — Hardening + audits

### Added
- **Property tests for the full KV/log API** (`tests/property_full.rs`):
  random sequences of `Put / Delete / AppendLog / Commit / Reopen` ops
  validated against an in-memory `BTreeMap` reference model. 16 cases
  × up to 40 ops each, plus 6 deterministic regression tests.
- **Stable-Rust parser fuzzing** (`tests/parser_fuzz.rs`): 26 tests
  with proptest for decode-doesn't-panic on arbitrary bytes, encode↔
  decode roundtrip with invariant-preserving generators, and edge
  cases (empty, single-byte, exact boundaries, unknown kinds, non-zstd
  bytes). 9 decoders covered.
- **Memory hygiene audit** (`docs/MEMORY_AUDIT.md` + `tests/memory_hygiene.rs`):
  `derive_chunk_key` and `derive_subkey` tightened to return
  `Zeroizing<[u8; 32]>` (was raw `[u8; 32]` — fixed). 7 type-level
  regression tests prevent signature regression.
- **Constant-time audit** (`docs/CT_AUDIT.md` + `src/crypto/ct.rs`):
  audited 17 distinct comparisons; none on secret data. Added
  `crypto::ct::eq_32` / `eq_slice` placeholder helpers (`subtle::ConstantTimeEq`)
  for any future defense-in-depth need. 4 unit tests.

### Changed
- `derive_chunk_key` and `derive_subkey` now return `Zeroizing<[u8; 32]>`
  instead of raw `[u8; 32]`. Callers automatically adapted via
  `Deref<Target=[u8; 32]>` — no API churn at call sites.

## [v0.6] — Performance baseline

### Added
- **Criterion benchmarks** (`benches/throughput.rs`, 9 benches):
  `create_space`, `open_space`, `commit_single_kv`, `commit_100_kv`,
  `commit_1000_kv`, `commit_log_100`, `get_random_kv`, `read_log`,
  `repack_1000`. Run with `cargo bench --bench throughput`.
- **`BENCH.md`** documenting baseline numbers, the 3-fsync floor
  insight, B+ tree split cost (~5% over single put), read paths
  sub-100µs, and hardware tuning recommendations per device class.

## [v0.4] — Multi-process safety

### Added
- **Exclusive flock on container open** via `fs2` crate. POSIX `flock(2)`
  per-OFD, so two separate `Container::open` calls produce
  `Error::Busy` for the second. Lock auto-released on `Container` drop.
- **`Error::Busy`** variant distinct from `Io` / `AuthFailed`.
- **`tests/locking.rs`** (8 scenarios) covering exclusive lock
  semantics, auto-release on drop, sequential reopens, distinct
  error variant.

## [v0.3] — Compaction + integrity + resilience

### Added
- **`Container::repack(source, dest, passwords, options)`** — primary
  compaction primitive. Reads all live state under supplied passwords,
  writes a fresh container with new salt + container_id, drops anything
  not unlocked. Closes the v0.2 DataBatch leak (deleted message bytes
  physically eliminated).
- **`Container::compact_known` / `compact_all`** — in-place wrappers
  over repack with atomic temp-file rename.
- **`RepackOptions`** with `argon2`, `initial_garbage_chunks`,
  `padding_policy`, `superblock_replicas`, `log_namespaces` fields.
- **`Space::list_namespaces`** and **`Space::iter_log`** helpers
  (cached batch decoding) for enumeration.
- **`tests/repack.rs`** (12 scenarios) including param rotation and
  realistic messenger compaction.
- **Multiple Superblock replicas** (`DEFAULT_SUPERBLOCK_REPLICAS = 3`):
  each commit writes N SB chunks at the same seq. AEAD-failed replicas
  drop from the recovery scan, so corruption of any single replica
  doesn't break the space. `Container::set_superblock_replicas` for
  runtime override. 9 corruption-survival tests in `tests/sb_replicas.rs`.

## [v0.2] — Real storage stack

### Added
- **Multi-op `Tx<'s, 'f>`** with `put` / `delete` / `append_log` /
  `commit`. 3-fsync barrier protocol validated by 8 truncation
  scenarios in `tests/crash_recovery.rs`.
- **`CommitPayload`** chunk encoding (per-namespace IndexNode root
  pointers + tx_root_hash).
- **KV index with namespaces** (`Namespace(u8)` newtype with
  `SETTINGS` / `CONTACTS` / `MESSAGE_LOG` / `MEDIA` constants).
  Sorted-vector `IndexNode` payload.
- **B+ tree split for IndexNode** (`Leaf` / `Internal` enum). Single
  leaf for small namespaces, Internal+Leaves for overflow. Caps each
  namespace at ~5000-10000 entries before `Error::IndexFull` (3rd
  level deferred). 7 overflow tests in `tests/kv_btree.rs`.
- **DataBatch + zstd** for the message log namespace
  (`ChunkKind::DataBatch = 0x06`). `Tx::append_log(ns, log_id, payload)`,
  `Space::read_log(ns, log_id)`. 100-msg batches compressed to ~3-5 KB.
  11 tests in `tests/log_basic.rs` including realistic_messenger_workload.
- **`Space::vacuum_orphans`** — forward-secrecy scrub of orphan
  IndexNode chunks. Auto-called at the end of `Container::open_space`.
  Idempotent. DataBatch chunks deferred to v0.3 compaction. 7 tests
  in `tests/scrub.rs`.
- **`PaddingPolicy`** enum (`None` / `BucketGrowth` / `FixedRatio`)
  applied at end of every commit. `ContainerOptions.initial_garbage_chunks`
  for decoy initial size. 8 integration + 4 unit tests.
- **`Error::PayloadTooLarge`** distinct from generic `Internal`.

### Changed
- BREAKING: replaced raw-records storage model with KV-only. Old
  `commit_record` / `read_latest_record` / `read_latest_records`
  removed; use `Tx::put` / `Space::get` / `Space::list`.

## [v0.1] — Foundation

### Added
- **Crypto primitives** (`src/crypto/`): XChaCha20-Poly1305 AEAD per
  chunk, Argon2id KDF (`MIN` / `LIGHT` / `DEFAULT` / `HEAVY` presets),
  BLAKE3-keyed per-slot key derivation, getrandom RNG.
- **Fixed 4096-byte chunk format** (`src/chunk/`) with 5 plaintext
  fields (magic, kind, flags, seq, payload_len, payload).
- **80-byte cleartext container header** (salt + container_id + Argon2
  params) — argon2 params persisted per-container, runtime device-class
  configurable.
- **Append-only `ContainerFile`** with `append_slot` / `write_slot` /
  `read_slot` / `scrub_slot` primitives.
- **Public `Container` + `Space<'f>` API** with `create_space` /
  `open_space` / `begin_tx` / `commit_seq`.
- **Trial-decrypt scan-and-recover** (`src/open/`) — O(N) scan, picks
  highest-seq Superblock; AuthFailed unifies wrong-password and no-such-space.
- **Property tests P1/P2/P3** — chunk roundtrip, scan determinism,
  wrong-password security-critical (D2).

### Documentation
- **`DESIGN.md`** — formal threat model (D1, D2, I1, I2, I3),
  on-disk format, key schedule, invariants.
- **`README.md`** — pitch, quickstart, status table, hardware tuning,
  architecture, testing summary.
- **`TASKS.md`** — milestone roadmap from v0.1 to v1.0.
- **Crate-level rustdoc** with passing doctest quickstart.
- **`examples/messenger_lifecycle.rs`** — runnable 8-step demo.

[v0.1]: https://example.invalid/v0.1
[v0.2]: https://example.invalid/v0.2
[v0.3]: https://example.invalid/v0.3
[v0.4]: https://example.invalid/v0.4
[v0.5]: https://example.invalid/v0.5
[v0.6]: https://example.invalid/v0.6
[Unreleased]: https://example.invalid/unreleased
