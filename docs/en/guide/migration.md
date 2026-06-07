# Format migration

🇬🇧 **English** · [🇷🇺 Русский](../../ru/guide/migration.md)

**Status.** Pre-1.0. Format generation has bumped twice in pre-1.0
already (v1 → v2 in audit pass 13, v2 → v3 on 2026-05-28); these
bumps were **breaking by design** and no in-place migration tool
ships. Cross-version transitions go through export-and-reimport.

This document covers:

- The current cross-version reject policy (`Argon2Params::validate`
  refuses any `format_version` != current; in v3 this is also
  cryptographically bound — see [§7 of `format.md`](../reference/format.md)).
- The export-and-reimport recipe to move data from a vN container
  to a vM container.
- The post-1.0 plan: at v1.0 release the format is **frozen**;
  subsequent breaking changes require a new generation and a
  proper migration tool.

## Current format generation

`hidden-volume` currently writes **v3** (since 2026-05-28). Older
generations:

| Gen | Status | Introduced | Removed | Notes |
|---|---|---|---|---|
| v1 | unsupported | project start | audit pass 13 | Initial layout. |
| v2 | unsupported | audit pass 13 (R-NSKIND) | v3 bump (2026-05-28) | Added per-`IndexRoot` `kind` byte. |
| **v3** | **current** | 2026-05-28 | — | Added kind-tag bytes (#8), cryptographic version-binding (#9), per-space derived `container_id` (#10). Removed cleartext `container_id` from header. |

Intra-version migrations (no format bump):

- **Argon2 parameter change** — see [`operations.md`](operations.md) §3.
- **Password change** — see [`operations.md`](operations.md) §2.
- **Compaction / size reclaim** — see [`operations.md`](operations.md) §5.
- **Multi-device sync schemes** — see [`multi-device.md`](multi-device.md).

These stay within v3.

## Cross-version policy

A v3 reader refuses to open v1 or v2 containers. v1/v2 readers
likewise refuse v3 containers. The reject is **doubly bound** in v3:

1. **Policy:** [`Argon2Params::validate`](../../../crates/hidden-volume/src/crypto/kdf.rs)
   rejects `format_version != PARAMS_VERSION` at open.
2. **Cryptography (v3 #9):** [`derive_master_key`](../../../crates/hidden-volume/src/crypto/kdf.rs)
   folds `params.version` into the master key through a post-Argon2
   BLAKE3 step. A hypothetical reader that loosened the policy gate
   would still derive a different `master_key` and hit `AuthFailed`
   on the first AEAD attempt.

There is no in-place migration. The only way to move data across a
format-version boundary is **export from the source, import to a
fresh destination**.

## Migration recipe (vN → vM, any cross-version transition)

The recipe below works for any cross-version pair where you have a
build of the library that can read the source generation AND a
(possibly different) build that can write the destination generation.

```rust,ignore
// Pseudocode. Replace `ContainerVN` / `ContainerVM` with whichever
// crate version reads / writes each generation.

// 1. Open the source under the *old* library build.
let src = ContainerVN::open(&src_path)?;
let src_space = src.open_space(&password)?;

// 2. Enumerate every namespace the host-app knows about. There is
//    no global iterator over namespaces; the host-app must remember
//    which namespace ids it has used (this is part of the integration
//    contract — see docs/en/guide/integration.md §3).
let known_namespaces = host_app_namespace_registry();

// 3. Create a fresh destination under the *new* library build.
let dst = ContainerVM::create(&dst_path, Argon2Params::DEFAULT)?;
let mut dst_space = dst.create_space(&password)?;

// 4. Stream every KV pair and every log entry into the destination.
let mut tx = dst_space.begin_tx();
for ns in &known_namespaces {
    for (k, v) in src_space.list(*ns)? {
        tx.put(*ns, &k, &v)?;
    }
    // Log entries: iterate the source log; append in order.
    for entry in src_space.iter_log_after(*ns, 0)? {
        let (log_id, payload) = entry?;
        tx.append_log(*ns, log_id, &payload)?;
    }
}
tx.commit()?;

// 5. Verify integrity of the destination before discarding the source.
dst_space.verify_integrity()?;

// 6. Atomically rename or back up the source. Keep it readable until
//    the destination has survived at least one full app session.
```

Notes:

- This is a **full plaintext round-trip**. There is no shortcut that
  preserves AEAD ciphertext — different generations derive
  different `master_key`s for the same password+salt, so chunks
  cannot be re-tagged in place.
- The destination has a **fresh `container_salt`** (and in v3, a
  freshly-derived per-space `container_id`); host-apps tracking
  rollback anchors per [`multi-device.md`](multi-device.md) must
  reset their anchor state to `commit_history = [1]` after migration.
- `Container::repack` is **not** a cross-version migration tool.
  Repack stays within a single format generation; it does refresh
  Argon2 params / padding policy / replica count but it does NOT
  bump `format_version`.

## What NOT to do

- **Do not edit the header bytes by hand** to claim a different
  format version. v3 cryptographic version-binding means the
  resulting file will fail to open even if the policy gate were
  bypassed.
- **Do not assume the migration is reversible.** Plaintext export
  reveals everything that was encrypted in the source; once you have
  written the destination, treat the source as having had its
  plaintext touched (zeroize buffers, scrub if needed).
- **Do not run the migration on a live writer.** Take the source
  offline (close all handles in the host-app) before reading;
  `flock(LOCK_EX)` will reject a second writer, but if the
  filesystem does not honour `flock` (NFS without lockd, some FUSE
  configurations), the destination can be corrupted silently.
- **Do not discard the source until the destination has been
  verified.** Run `Space::verify_integrity` on the destination and
  exercise it through a full host-app session (incl. at least one
  commit on the destination) before deleting the source.

## Post-1.0 plan

At v1.0 release the format will be **frozen** for the v1.x line. Any
later breaking change (introducing v4) will:

1. Ship in a major-version bump of the library (v2.x).
2. Carry a proper migration tool (`hidden_volume::migrate::v3_to_v4`
   or equivalent) that wraps the export-and-reimport recipe above
   into a single API call.
3. Be documented here with `vN → vM` recipe + acceptance criteria.
4. Honour the cross-version policy: a v2.x library refuses to write
   v3 files (a reader-only fallback may exist for at most one major
   version, after which v3 is dropped).

The pre-1.0 "no migration tool" policy will be retired at v1.0; the
freeze trades flexibility for stability.

## Audit log

| Date | Event | Document |
|---|---|---|
| project start | v1 introduced | `DESIGN.md` (historical) |
| audit pass 13 (R-NSKIND) | v2 introduced (per-`IndexRoot` `kind` byte) | `CHANGELOG.md` pass-13 entry |
| 2026-05-28 | **v3 introduced** (#8 kind-tag bytes + #9 cryptographic version-binding + #10 per-space derived `container_id`) | [`format.md` §13](../reference/format.md) |
| v1.0 (planned) | Format freeze | TBD |
| post-1.0 (TBD) | First proper migration tool | This document, expanded |

## Cross-references

- [`format.md`](../reference/format.md) §7 — cross-version policy
  reject table; §13 — format change log.
- [`format.md`](../reference/format.md) §3 — v3 key schedule with
  the version-bind step.
- [`operations.md`](operations.md) §3 — intra-version Argon2 param
  migration (does not change `format_version`).
- [`../security/threat-model.md`](../security/threat-model.md) §4.1
  F-PAD — how v3 closes the v2 padding-downgrade silent-degrade
  surface as a side effect of #9.
- [`multi-device.md`](multi-device.md) — anchor strategy across
  migrations; `commit_history` reset after export-and-reimport.
