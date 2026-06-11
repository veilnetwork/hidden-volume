# Threat-model challenge

**Date.** 2026-05-28. **Pass.** 5 of 5 — the final pass in the
deeper-review series. **Reviewer.** LLM-assisted. **Stance.**
Narrative. Pass 1 enumerated ~34 atomic attacks defensively; this
pass takes a smaller number of *full scenarios* and walks each
through end-to-end as a specific adversary with concrete
capabilities, step-by-step, observing what they learn at each
stage and where the threat model's claims either hold up or
explicitly punt.

## Methodology

Pass 1 ([adversarial-stance.md](adversarial-stance.md)) was
analytical: each row is a single attack hypothesis, verdict
recorded, move on. This pass is narrative: each section is a story
about a concrete adversary with named capabilities, walking
through what they can do over hours or days. The two stances
should agree where they overlap; the narrative format surfaces
*cumulative* leaks that the atomic enumeration may miss.

References the **invariants** from [threat-model.md](../threat-model.md)
§3 (D1, D2, I1, I2, I3, R1, M1, C1) and the **adversary tiers**
from §2 (T1, T2, T2', T3).

Severity legend unchanged from prior passes.

## Headline

**0 CRITICAL / 0 HIGH / 0 MEDIUM / 0 LOW / 0 INFO findings.**

The narrative pass confirms what the analytical pass found: every
in-scope adversary tier has its claim either defended at the
library boundary or held by host-app cooperation per the documented
contract. The two cumulative-leak vectors a narrative format
sometimes surfaces — (a) the multi-stage adversary who alternates
snapshot, key extraction, and follow-up snapshot, and (b) the
patient observer who watches metadata evolve over time — were
already enumerated in adversarial-stance D2-A4, D2-A5, and R1-A1/A2,
with the trade-offs documented in [threat-model §4](../threat-model.md).

## Scenario A — Border seizure of a phone (T2 single snapshot, no compelled key yet)

**Setup.** A traveller's phone is seized at a border. The customs
officer takes the device to a lab, makes a forensic image of the
internal storage, then returns the phone. The traveller is not
detained; no password was compelled.

**Adversary capabilities.** T2 — single snapshot of the container
file (and any other files on the device).

**Step-by-step.**

1. **Officer parses the container file.** They notice an 80-byte
   structured prefix matching the `hidden-volume` cleartext-header
   layout: 32-byte high-entropy bytes and 16 bytes that look like
   Argon2id parameters (`m_cost_kib`, `t_cost`, `p_cost`, version).
   If they know the format, they recognise "this is a deniable-storage
   container".
   - **What they learn.** The file is a `hidden-volume` container.
     They can read: salt (32 random bytes), Argon2 parameters (e.g.,
     `m=64 MiB, t=3, p=1, format_version=3, padding=Bucket16Mib`).
   - **What's defended.** D1 explicitly carves out the 48-byte
     cleartext header (v3; was 80-byte in v2 — the `container_id`
     fingerprint at offset 32..64 was closed by v3 #10 per-space
     derivation). The fact that "this is a container" is known is
     acknowledged out-of-scope in
     [threat-model §3.D1](../threat-model.md). Eliminating the
     "this is a container" surface entirely would require a
     password-derived header (no fixed cleartext layout at all),
     which is a v4-class change not committed.

2. **Officer measures the file size.** They compute
   `slot_count = (file_size - 4096) / 4096`. Say it's 50000 slots
   ≈ 200 MiB.
   - **What they learn.** Approximate storage usage.
   - **What's defended.** File size is unavoidably public. The
     padding policy `Bucket16Mib` rounded the size up to a 16 MiB
     boundary, so they get coarse-grained usage info, not exact
     content count.

3. **Officer attempts byte-level statistical analysis** of bytes
   80..end. They run entropy tests, autocorrelation, frequency-
   distribution.
   - **What they learn.** Nothing. The XChaCha20-Poly1305
     ciphertext + uniform random garbage + random padding is
     computationally indistinguishable from uniform random under
     the standard ChaCha20 assumption.
   - **Defended.** D1.

4. **Officer attempts to enumerate spaces.** Without a password,
   they cannot derive any per-slot AEAD key. Every chunk is
   indistinguishable. They have no way to count or locate spaces.
   - **Defended.** D2 (the "is there even a space here?"
     unobservability extends to "how many" and "where").

5. **Officer attempts offline brute-force** of common passwords
   (e.g., the user's birthday, common patterns) against any random
   chunk in the file.
   - **What happens.** Each guess requires running `Argon2id(guess,
     salt, params)` to derive `master_key`, then `master_key →
     aead_root → derive_chunk_key → ChunkAead::open` on the chunk.
     At `m=64 MiB, t=3, p=1`, one guess takes ~700ms on lab
     hardware. A dictionary of 10⁹ passwords takes ~22 years on
     one machine. GPU clusters bring this down by factors of
     thousands but Argon2id's memory-hard property limits GPU
     parallelism (12 KB GPU shared memory per stream multiprocessor;
     64 MiB per Argon2 call → ~5K streams max per GPU).
   - **Practical conclusion.** Offline brute-force is gated by
     the user's password strength, with Argon2id's work factor
     amplifying the cost.

6. **Officer searches the file for "magic bytes"** that would
   suggest a known plaintext at a known offset (e.g., the
   `Plaintext::MAGIC` `b"HVC1"`).
   - **What they find.** Magic is *inside* the AEAD-protected
     plaintext, never exposed in ciphertext. They find nothing.
   - **Defended.** D1.

**Scenario A conclusion.** The traveller's deniability holds. The
officer learns:
- the file is a deniable-storage container (acknowledged);
- approximate storage usage (acknowledged);
- nothing about the actual content, number of spaces, or even
  whether the file contains *any* live spaces.

Their only path forward is to compel a password (→ scenario C).

## Scenario B — Returning traveller (T2', snapshot diff over time)

**Setup.** Same border, but six months later the traveller is
back. The customs lab still has the original forensic image; they
make a fresh one.

**Adversary capabilities.** T2' — two snapshots at known times.

**Step-by-step.**

1. **Lab diffs the two snapshots byte-by-byte.**
   - **What they observe.** Some byte ranges are unchanged
     (chunks that have not been rewritten). Others differ — a
     range of slots `[N1, N2)` is new (file grew by N2-N1
     chunks since the first snapshot).
   - **Defended.** D1 still holds *within* each snapshot. T2'
     is explicitly out of scope per
     [threat-model §2 + §4](../threat-model.md): "single-snapshot
     indistinguishability does NOT extend to byte-diff over
     time".

2. **Lab estimates how many commits happened.** With the
   `Bucket16Mib` padding policy, each commit's growth is rounded
   up. So the lab sees aggregate growth in 16 MiB increments and
   cannot pin per-commit boundaries.
   - **What they observe.** Roughly "the user wrote between 5
     and 10 commits", say.
   - **Defended.** D1 invariant on per-snapshot indistinguishability
     is not violated. T2'-level leak is acknowledged.

3. **Lab attempts to identify which slots are new vs which were
   updated-in-place.** This library is append-only (Inv-W1) —
   slots are never reused. So newly-grown slots are at the file
   tail; older slots are untouched.
   - **What they observe.** Append-only growth pattern is
     detectable (the file simply got longer). Older content
     "fingerprinted" via byte ranges that match the first
     snapshot is unchanged.
   - **Defended.** Append-only is design-explicit (DESIGN §9).
     This contributes to T2' leak; mitigated by `vacuum_orphans` +
     `compact_known` rewriting the whole file with a fresh
     `container_id`.

4. **Lab speculates which space is active.** They can see *some*
   space is being written. They cannot identify which password
   it corresponds to without compelled-key.
   - **What's defended.** D2 — they cannot prove "space B exists
     because of this growth". The growth could equally be "garbage
     padding under F-PAD upgrade", "space A's commits", or
     "space B's commits".

5. **Lab combines with metadata snooping.** If they had access to
   the device's mtime/atime via the same forensic image, they'd
   know *when* writes happened (correlatable with the user's known
   activity times).
   - **What's defended at the library layer.** Nothing — mtime
     is filesystem-level, observed at the snapshot.
   - **Documented out-of-scope.** Host-app should mount the
     container on `noatime` if mtime correlation is part of the
     adversary model.

**Scenario B conclusion.** T2' is acknowledged out-of-scope.
The narrative confirms: the leak is "the user wrote *something*
at some intervals", not "what they wrote, in which space, with
which password". Cumulative leak does not exceed what the
analytical adversarial-stance D2-A4 (writer-active signal)
predicted.

## Scenario C — Compelled-password disclosure (T3, single space)

**Setup.** The traveller is detained. Under duress, they reveal
the password to space `S_A`. They do NOT reveal `S_B` (which
holds the genuinely sensitive content). The officer holds the
forensic image and now `S_A`'s password.

**Adversary capabilities.** T3 for `S_A`; T2 (file image) overall.

**Step-by-step.**

1. **Officer opens space `S_A`.** `Container::open_space(path,
   S_A_password)` succeeds. They read everything in `S_A`:
   contacts, settings, message log, etc.
   - **What they learn.** `S_A`'s full content. By design — they
     have the key.
   - **Defended at boundary.** T3-for-S_A is *not* defended; D2's
     claim is that disclosure of `S_A`'s content doesn't leak
     `S_B`.

2. **Officer enumerates `S_A`'s commit_history.** They get the
   list of seq values of `S_A`'s superblocks.
   - **What they learn.** `S_A`'s commit history (R1 anchor data).
     They do NOT learn `S_B`'s commit history — its superblocks
     fail AEAD under `S_A`'s key.
   - **Defended.** D2-A5 in adversarial-stance pass.

3. **Officer attempts to identify `S_B` slots.** They time the
   open call (this is the TM1 oracle).
   - **What they learn.** Approximate `frac_owned` for `S_A`.
     Say `S_A` owns 30% of slots. The remaining 70% is split
     between "another space" and "garbage padding" — but the
     library treats both identically (AEAD fails the same way
     for "not our chunk" and "uniform random padding").
   - **Defended.** TM1 leak is quantified (±10-20% on `frac_owned`)
     and is the same leak as D1-A3 file-size visibility, plus
     the per-chunk granularity of "not owned by us".

4. **Officer asks: "is there another space?"** They try common
   alternative passwords (the user's other passwords, family
   member names, dates).
   - **What happens.** Each guess re-runs Argon2id and tries
     to open. Each takes ~700ms. Each one that fails is
     indistinguishable from "no space matches that password".
   - **Defended.** D2 — there's no observable difference
     between "guessed password matches no space in this file"
     and "guessed password matches a space but it's empty".

5. **Officer demands a SECOND password.** The user — armed with
   the deniability story — says "there is no second password, I
   only have the one I gave you, and the unowned 70% is just
   garbage padding from my paranoid setting".
   - **What backs this up.**
     - `Bucket16Mib` padding policy IS in the cleartext header
       (the officer can see it). It would, in fact, generate
       large garbage runs.
     - The library makes no out-of-band declaration of "I have N
       spaces". Every chunk that AEAD-fails under `S_A`'s key
       is, behaviorally, garbage padding.
     - The TM1 timing leak doesn't distinguish "another space's
       chunk" from "garbage padding chunk".
   - **What the officer cannot do.** Prove the user is lying.
     The "deniability" is not "the file looks like it has no
     other space" — it's "the file is consistent with the user's
     story that there is no other space, and no cryptographic
     evidence exists to refute it".
   - **Defended.** D2, by design.

6. **Officer takes the device home for "extended analysis".**
   They have unlimited time + a forensic image + `S_A`'s
   password.
   - **They try every plausible second-password.** Argon2id work
     factor amplifies cost. They get nothing matchable.
   - **They try sophisticated TM1 analysis.** They measure per-
     chunk MAC-fail-vs-pass timing across the unowned slots. With
     enough resolution they could partition unowned slots into
     "this chunk's MAC verifies under SOME password" vs
     "garbage". BUT: to verify MAC under SOME password, they'd
     need to guess the password — back to brute-force-Argon2id.
   - **Defended.** D2, even under unlimited offline analysis,
     given a strong second-password.

**Scenario C conclusion.** D2 holds at the library boundary.
The officer learns `S_A`'s contents and cannot prove `S_B`'s
existence. The deniability story for the user ("I only have one
space; the rest is padding") is cryptographically supported.

Caveats that the user (and host-app) must respect:
- If `S_B`'s password is weak, offline brute-force eventually
  finds it.
- If the host-app records "user has two spaces" elsewhere (e.g.,
  a UI cache, a backup manifest), the officer reads that instead.
- If the user has a different device elsewhere that holds an R1
  anchor to `S_B`'s commit_seq, the officer can compel that too.

These are all the host-app's domain (see
[multi-device.md](../../guide/multi-device.md)).

## Scenario D — Compromised host-app (T-host-app malicious)

**Setup.** The user installs an updated version of their
messenger app. The update has been silently modified by an
adversary (e.g., via a supply-chain attack on the app store,
or a malicious app pretending to be the legitimate one). The
container file itself is intact.

**Adversary capabilities.** Full control of the host process at
runtime. The library is loaded by them and called with their
arguments.

**Step-by-step.**

1. **Malicious app prompts user for password.** User types
   `S_A`'s password. App captures it, also derives `S_B`'s
   password through whatever the user enters next, etc.
   - **What's defended.** Nothing at the library layer — the
     password is in the host-app's address space. The library's
     `Zeroizing` discipline scrubs the *library's copy* but the
     host-app's copy is theirs to manage.
   - **Documented out-of-scope.** Host-app trust is required by
     the threat-model §1.3.

2. **Malicious app exfiltrates the container file.** Direct
   filesystem access.
   - **What's defended.** Nothing. File is on disk, host-app
     reads it.

3. **Malicious app tries to forge an "extra space" that
   appears to belong to the user.** They have `S_B`'s password
   (extracted in step 1). They could write new chunks under
   `S_B`'s key. But the file's superblock chain is
   AEAD-integrity-protected; they cannot write a fake "old
   commit" to `S_B` without `S_B`'s key — which they have.
   So they CAN forge anything they want with the captured
   password.
   - **What's defended.** Forge-resistance against an attacker
     *without* the key (T2/T2' adversaries). Not against a
     host-app that has the key.
   - **Documented out-of-scope.** "Host-app trust is required."

**Scenario D conclusion.** Out-of-scope adversary class. The
library cannot defend against a malicious host-app with the
user's password. Mitigation is at the host-app supply-chain
layer (reproducible signed builds, code signatures, app-store
review). The library *does* contribute to this layer via its
own [reproducible signed releases](../../contributing/verifying-release.md).

## Scenario E — Patient kernel-level adversary

**Setup.** Lab-class adversary with kernel-level access to the
device (e.g., rooted phone, bypassed secure-boot). They observe
the user open the container, watch every syscall, every
page-fault, every cache-line access.

**Adversary capabilities.** Beyond T2/T3 — observability
into the running process at kernel + microarchitecture level.

**Step-by-step.**

1. **Kernel-level observer logs every `pread(fd, buf, 4096,
   offset)` call** during open.
   - **What they observe.** Slot access order during the scan.
     In sequential mode, every slot is read once in order. In
     parallel mode, slot order is non-deterministic per thread.
     In mmap mode, slots are accessed as page-faults.

2. **They correlate access timing with TM1.** They have per-
   chunk timing resolution (not just aggregate open-time).
   - **What they observe.** Per-slot MAC-fail-vs-pass timing.
     They can identify "which specific slots are this user's
     space's" — TM1 at chunk granularity.
   - **What's defended.** Nothing — kernel-level cache/timing
     attacks are explicitly out-of-scope
     ([threat-model §1.3](../threat-model.md): "OS / firmware /
     CPU / RAM" all in the trusted base).
   - **Documented.** This is the rationale for the trusted
     base: a deniable-storage library cannot defend against an
     adversary with full machine access without the user noticing.

3. **They dump RAM during the open** and extract the master key
   from heap.
   - **What's defended.** Nothing in the live-memory phase. The
     library's `Zeroizing` discipline scrubs after the key is
     no longer needed, but during active use the key is in
     memory.
   - **Documented out-of-scope.** "Forensic RAM dumps — defended
     by full-disk encryption + secure boot at the host level."

**Scenario E conclusion.** Kernel-level adversaries are
out-of-scope. The library makes no claims against this tier and
delegates to the OS / secure-boot / TPM / full-disk-encryption
layers.

## Scenario F — Multi-stage cumulative leak

**Setup.** A patient adversary executes scenarios A → B → C → A in
sequence over a year. Snapshot in January, snapshot in July
(diff), compelled `S_A` password in August, snapshot in October.

**Adversary capabilities.** Cumulative T1 + T2' + T3.

**Step-by-step combined analysis.**

1. **January snapshot.** Knows: file is a hidden-volume
   container, ~200 MiB, header parameters (Argon2 `m=64 MiB`,
   `Bucket16Mib` padding). Scenario A conclusions.

2. **July snapshot diff.** Knows additionally: file grew by
   ~32 MiB between January and July (rounded up by
   `Bucket16Mib`), append-only growth pattern, slot range
   `[Jan_count, Jul_count)` is "new since January". Scenario B
   conclusions.

3. **August compelled-password (S_A).** Knows additionally:
   `S_A`'s full content, `S_A`'s commit history, ~`S_A`-frac
   from TM1.
   - **Cross-reference with B.** They cross-reference `S_A`'s
     commits-since-January with the July diff. If `S_A`'s
     contribution to the file growth is, say, 10 MiB out of the
     32 MiB grown, the remaining 22 MiB is either garbage
     padding OR `S_B`'s commits.
   - **Bucket16Mib + grown-by-32MiB.** The Bucket16Mib policy
     rounds each commit up to 16 MiB. `S_A`'s 10 MiB of real
     data could account for ~16 MiB of file growth (one
     bucket). The remaining 16 MiB *could* be `S_B`'s
     commits, OR could be additional `S_A` activity that fit
     within the bucket boundary, OR (if F-PAD-downgrade
     happened in between) variable padding.
   - **Concrete leak.** Aggregate file growth `Δ` vs `S_A`'s
     accounted commits ≈ "$\Delta$ - S_A_contrib" → upper bound on
     `S_B`'s activity. Bucketed padding obscures this; coarser
     than per-commit but not invisible.

4. **October snapshot.** Same analysis as B → C, refined with
   another 3-month window.

**Cumulative conclusion.** A patient T2' + T3 adversary CAN, over
time, build a probabilistic argument that "the user has been
active with another space" by subtracting `S_A`'s accounted
commits from total file growth. They cannot identify *what* `S_B`
contains or *prove* its existence in a cryptographic sense — the
remainder could equally be aggressive padding under a different
policy. This is T2' territory by definition, with deniability
preserved at the *content* level but eroded at the *activity-
existence* level.

**Defended at boundary.** D2's strict claim ("cannot prove
existence") holds: the user can always say "I changed my padding
policy to aggressive in March; that explains the extra growth".
The cryptographic story does not refute this. The probabilistic
inference is the T2' acknowledged-out-of-scope leak.

## Scenario G — Adversary with control of one of multiple devices

**Setup.** User syncs the container across two devices (e.g.,
phone + laptop) via some host-app sync mechanism. Adversary
controls the laptop completely (T-host-app on the laptop).

**Adversary capabilities.** Full control of laptop; T3-for-laptop's
spaces; passively observe sync traffic if app routes via cloud.

**Step-by-step.**

1. **Adversary reads the user's laptop password.** They keylog
   it.

2. **They open the synced container on the laptop.** They get
   `S_A` content from the laptop side.

3. **They observe sync traffic.** If the host-app does a
   file-level sync (rsync-style), they see every chunk's
   ciphertext on the wire — but no plaintext (chunks are AEAD).

4. **They wait for the user's phone to commit.** Sync brings the
   new chunks to laptop. Adversary observes the file size
   growing.
   - **What they learn.** Same T2' growth pattern as scenario B.

5. **R1 anchor check.** If host-app uses R1 anchors (commit_seq
   externally stored), and the adversary's laptop has access to
   that anchor store, they can detect rollback / fork attacks
   between phone and laptop.
   - **What's defended.** R1 is a host-app-cooperative property;
     library exposes the primitives, host-app stores and checks
     anchors. Documented in
     [multi-device.md](../../guide/multi-device.md).

**Scenario G conclusion.** Multi-device threat model is host-app
responsibility per the documented contract. The library does its
part: chunks are AEAD-protected end-to-end, container_id is unique
per container (so cross-container relocation fails), `commit_seq`
is exposed for anchor checks. The library does not, and cannot,
defend against a fully-compromised endpoint.

## Cross-scenario findings

**Cumulative leaks that the narrative pass surfaces (none new):**

1. **File-growth-minus-accounted-commits → S_B-activity upper
   bound.** Scenario F. Already covered by D2-A4 (writer-active
   signal) + acknowledged as T2'-out-of-scope. No new finding.
2. **R1 anchor reliance on host-app honesty.** Scenarios G. Already
   documented in multi-device.md. No new finding.
3. **TM1 at chunk-granularity for kernel-level observers.** Scenario E.
   Already noted in side-channel-surface T-9 + M-3 as kernel-level
   out-of-scope. No new finding.

**Scenarios where the library actively helps:**

- Reproducible signed builds (cosign keyless) defend against
  scenario D (compromised host-app at *install* time, before user
  enters password). Verifiable per
  [verifying-release.md](../../contributing/verifying-release.md).
- The "no observable difference between not-our-chunk and
  garbage" property (TM1's granularity limit) is the actual
  cryptographic backing for the deniability story in scenario C.

## What this pass completes

Pass 5 closes the deeper-review series scheduled in
[self-audit.md §9](self-audit.md). The series produced:

| Pass | File | Headline |
|---|---|---|
| 1 | [adversarial-stance.md](adversarial-stance.md) | 34 atomic attacks vs D1/D2/I1-3/R1/M1/C1; 0 critical/high/medium, 1 LOW (dossier doc-inconsistency, fixed in same commit) |
| 2 | [primitive-level.md](primitive-level.md) | Argon2/ChaCha/BLAKE3/getrandom/zeroize/subtle vs 2026 literature; 0 critical/high/medium, 2 LOW (Argon2Params::MIN below OWASP — doc warning applied; label-length convention — defense-in-depth opp) |
| 3 | [side-channel-surface.md](side-channel-surface.md) | 24 channels classified; 0 findings; 2 INFO (constant-time decode shell, TM1 multi-variant bench) |
| 4 | [format-fuzzing.md](format-fuzzing.md) | 9 decoders + 2 discriminator parsers, every boundary class mapped to defender + test; 0 uncovered; 1 INFO (CI fuzz-gate is continue-on-error) |
| 5 | [threat-model-challenge.md](threat-model-challenge.md) | 7 narrative scenarios (border seizure, snapshot diff, compelled-password, malicious host-app, kernel-level observer, multi-stage cumulative, multi-device); 0 new findings; confirms analytical results in narrative form |

**Cross-series total:** 0 CRITICAL, 0 HIGH, 0 MEDIUM, 3 LOW (all
in pass 1-2, all either fixed in-pass or tied to v3 format bump).

## Recommended actions (carried forward to v1.x)

Consolidated list from passes 1-5, in order of effort:

1. **P-LOW1 rustdoc warning on `Argon2Params::MIN`** — applied in
   pass 2 commit `df9dbc8`. Done.
2. **D1-LOW1 dossier "64-byte" → "80-byte" fix** — applied in
   pass 1 commit `230d40a`. Done.
3. **SC-INFO1 constant-time decode shell** — defense-in-depth,
   ~4 KiB extra work per chunk per decode call. Closes key-holder-
   self-DoS only. Tracked for v1.x.
4. **SC-INFO2 TM1 bench across feature variants** — extend
   `benches/timing_oracle.rs` to cover parallel-scan + mmap.
   Documentation only. Tracked for v1.x.
5. **F-A5 cycle-detection in walkers** — defense-in-depth depth-cap
   in `collect_leaves` / `count_leaves` / `iter_log_*` /
   `vacuum_orphans` recursive paths. Closes only the writer-bug-
   regression + adversarial-key-holder scenarios. Tracked for v1.x.
6. **P-LOW2 label-length domain-separation hardening** — tied to
   v3 format bump (any length-prefix or kind-tag byte change to
   the KDF chain is format-breaking).
7. **v3 cryptographic version-binding** (from dossier §3) — bind
   `format_version` into Argon2 input or AAD. v3 format bump.
8. **TM1 constant-time AEAD mitigation** (from
   [threat-model F-TM1](../threat-model.md)) — replace
   MAC-fail-fast with always-decrypt-body. ~2× cost on garbage
   chunks. v1.x.
9. **Hidden-header v3 roadmap** (from
   [migration.md](../../guide/migration.md)) — make header
   password-derived; eliminate the "is this a hidden-volume
   container" cleartext fingerprint. v3 format bump.

Items 1-2 done in this series; items 3-9 carried forward as v1.x
candidates. Items 6-9 cluster naturally into "the v3 format
change", which would be the next-after-1.0 work item if a
weakness motivates a format bump.
