//! Transactional KV + log writes within a space. See DESIGN §6, §11.4, §12.
//!
//! A [`Tx`] accumulates two kinds of operations in memory:
//!
//! - **KV ops** (`put` / `delete`) — direct key→value entries in a
//!   namespace's IndexNode tree. Suitable for settings, contacts,
//!   media-cache index, and similar bounded-size random-access data.
//!
//! - **Log mutations** (`append_log` / `delete_log`) — records destined for a
//!   `DataBatch` chunk. The Tx accumulates per-namespace log buffers;
//!   on commit each non-empty buffer is encoded as one zstd-compressed
//!   batch, written as a `DataBatch` chunk, and pointers (8-byte slot
//!   addresses) are inserted into the namespace's KV index. Suitable
//!   for the message log namespace (`Namespace::MESSAGE_LOG`) where
//!   millions of short entries dominate.
//!
//! ## Commit protocol (3 fsync barriers, validated by `tests/crash_recovery.rs`)
//!
//! 1. Append `DataBatch` chunks (one per log namespace).
//! 2. Append updated `IndexNode` chunks (Leaves and possibly an Internal node)
//!    for each touched namespace.
//! 3. fsync (data durable).
//! 4. Append `Commit` chunk listing per-namespace IndexNode roots.
//! 5. fsync (intent durable).
//! 6. Append new `Superblock` pointing at `Commit`.
//! 7. fsync (visible).

pub mod commit;

use std::collections::BTreeMap;

use zeroize::Zeroize;

use crate::redact::{Redacted, Secret, SecretShape, redacted_debug};
use crate::space::Space;
use crate::space::index::Namespace;
use crate::space::log::{MAX_LOG_PAYLOAD_LEN, MAX_RECORDS_PER_BATCH};
use crate::{Error, Result};

pub use commit::{CommitPayload, IndexRoot, MAX_NAMESPACES_PER_TX, NamespaceKind};

/// One pending KV change inside a [`Tx`].
///
/// Deliberately NOT `Clone`. The plaintext lives here until commit and is
/// wiped by the `Redacted<PendingKv>` that holds it; a clone would be a copy
/// that wrapper never sees and never scrubs. Nothing cloned one -- the derive
/// was only the capability to start (report17).
pub(crate) enum KvOp {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

/// A transaction's pending KV ops: `namespace_byte → ordered ops`.
pub(crate) type PendingKv = BTreeMap<u8, Vec<KvOp>>;

/// How a namespace's pending KV ops were addressed — and therefore
/// what the namespace's **recorded** kind has to be for them to be
/// legal (audit HV-04).
///
/// Every mutation of a namespace's KV index arrives through one of
/// three doors, and until this existed the index could not tell them
/// apart. `Space::erase_namespace` needs to clear a Log namespace, and
/// it does so by issuing one `Delete` per key — so a pure-`Delete` op
/// set against a Log namespace was permitted, wholesale. That
/// exemption was written for erase and granted to everything shaped
/// like erase: `Tx::delete` on a message log went through it, and
/// `Tx::delete_log` on a KV namespace went around the kind check
/// altogether, because it shares erase's internal helper and its op
/// lands in the KV map where the log-side check never looks.
///
/// Naming the door closes both halves without taking anything away
/// from erase: the kind gate now asks where an op came from, and only
/// [`Self::Erase`] may disagree with what is on disk.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum KvOrigin {
    /// [`Tx::put`] / [`Tx::delete`] — addressed by key. The namespace
    /// must be recorded `Kv`.
    ByKey,
    /// [`Tx::delete_log`] — addressed by log id. The namespace must be
    /// recorded `Log`.
    ByLog,
    /// [`crate::space::Space::erase_namespace`] — removes every key
    /// there is, whatever the namespace holds. The only origin allowed
    /// to bypass the recorded kind, because it is the only one that
    /// cannot leave a namespace half of one kind and half of another:
    /// what it leaves behind is nothing.
    Erase,
}

/// A transaction's per-namespace [`KvOrigin`].
pub(crate) type PendingKvOrigin = BTreeMap<u8, KvOrigin>;

/// A transaction's pending log appends: `namespace_byte → ordered
/// (log_id, payload) records`.
pub(crate) type PendingLog = BTreeMap<u8, Vec<(u64, Vec<u8>)>>;

/// The pending KV ops of a whole transaction, `namespace → ops`.
///
/// This is the shape `Tx::pending_kv` stores, so wrapping that field in
/// [`Redacted`] needs it (audit HV-01, HV-07).
impl Secret for PendingKv {
    fn secret_shape(&self) -> SecretShape {
        SecretShape {
            items: self.values().map(Vec::len).sum(),
            bytes: self
                .values()
                .flat_map(|ops| ops.iter())
                .map(|op| match op {
                    KvOp::Put { key, value } => key.len() + value.len(),
                    KvOp::Delete { key } => key.len(),
                })
                .sum(),
        }
    }

    fn scrub_secret(&mut self) {
        for ops in self.values_mut() {
            for op in ops.iter_mut() {
                match op {
                    KvOp::Put { key, value } => {
                        key.zeroize();
                        value.zeroize();
                    },
                    KvOp::Delete { key } => key.zeroize(),
                }
            }
            ops.clear();
        }
        self.clear();
    }
}

/// One namespace's pending log appends, drained out of `Tx::pending_log`
/// by `commit_tx` and re-wrapped there so the payloads still get scrubbed.
impl Secret for Vec<(u64, Vec<u8>)> {
    fn secret_shape(&self) -> SecretShape {
        SecretShape {
            items: self.len(),
            bytes: self.iter().map(|(_, payload)| payload.len()).sum(),
        }
    }

    fn scrub_secret(&mut self) {
        for (_, payload) in self.iter_mut() {
            payload.zeroize();
        }
        self.clear();
    }
}

impl core::fmt::Debug for KvOp {
    /// REDACTED (audit HV-09). The derive printed the KEY and the VALUE — a
    /// contact record, a message, a setting — so a single `{:?}` on a
    /// transaction put user plaintext wherever that string went. Lengths say
    /// everything a diagnostic needs about a pending op.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Put { key, value } => f
                .debug_struct("Put")
                .field("key_len", &key.len())
                .field("value_len", &value.len())
                .finish(),
            Self::Delete { key } => f
                .debug_struct("Delete")
                .field("key_len", &key.len())
                .finish(),
        }
    }
}

/// In-progress transaction over a [`Space`]. Accumulates per-namespace
/// `put` / `delete` / `append_log` / `delete_log` ops and applies them atomically at
/// `commit` time via the 3-fsync protocol (DESIGN §6).
///
/// Drop-without-commit discards the pending ops with no on-disk
/// effect. Single Tx per Space at a time (enforced by Rust's borrow
/// checker via the `&mut Space<'f>` field).
pub struct Tx<'s, 'f> {
    space: &'s mut Space<'f>,
    /// `namespace_byte → ordered KV ops`. Insertion order preserved;
    /// last write wins for repeated keys at apply time.
    pub(crate) pending_kv: Redacted<PendingKv>,
    /// `namespace_byte → ordered (log_id, payload) appends`. Each
    /// non-empty entry produces one `DataBatch` chunk on commit.
    pub(crate) pending_log: Redacted<PendingLog>,
    /// Which door each namespace's `pending_kv` entries came through —
    /// see [`KvOrigin`]. One origin per namespace per Tx: the three are
    /// mutually exclusive (a whole-namespace erase and two disjoint
    /// ways of naming a single entry), so mixing them is a caller
    /// mistake rather than a shape the commit has to express.
    kv_origin: PendingKvOrigin,
}

// A transaction is the largest single pile of user plaintext this crate
// ever holds — every key, value and log payload the caller queued. `Tx` is
// also a public type an integrator can hold, so it is the most likely thing
// to end up in a `{:?}`. Both buffers are [`Redacted`]; `space` is omitted
// because a `Space` prints nothing useful here, and the whole impl is
// allow-list shaped so a field added later prints nothing at all until
// someone names it (audit HV-01).
redacted_debug!(Tx<'s, 'f> {
    pending_kv,
    pending_log,
    kv_origin
});

impl<'s, 'f> Tx<'s, 'f> {
    pub(crate) fn new(space: &'s mut Space<'f>) -> Self {
        Self {
            space,
            pending_kv: Redacted::default(),
            pending_log: Redacted::default(),
            kv_origin: PendingKvOrigin::new(),
        }
    }

    /// Record that this namespace's KV ops are addressed the `want`
    /// way, or reject the call if an earlier op in this Tx addressed
    /// them another way (audit HV-04).
    fn claim_kv_origin(&mut self, ns_byte: u8, want: KvOrigin) -> Result<()> {
        if let Some(have) = self.kv_origin.get(&ns_byte)
            && *have != want
        {
            return Err(Error::WrongNamespaceKind(
                "namespace already has KV ops addressed a different way in this Tx",
            ));
        }
        self.kv_origin.insert(ns_byte, want);
        Ok(())
    }

    /// Audit pass 7 (L2): a single Tx may touch at most
    /// `MAX_NAMESPACES_PER_TX` distinct namespaces (capacity of the
    /// `CommitPayload` chunk). Previously, exceeding this surfaced
    /// only at `commit()` time as `Error::Internal` (reserved for
    /// crate bugs). We now reject early in `put`/`delete`/`append_log`
    /// with `Error::TooManyNamespaces` — input-driven and
    /// distinguishable.
    fn check_namespace_capacity(&self, ns_byte: u8) -> Result<()> {
        // Already-touched namespaces don't add to the count.
        if self.pending_kv.contains_key(&ns_byte) || self.pending_log.contains_key(&ns_byte) {
            return Ok(());
        }
        // touched_namespaces() returns the existing count; adding ns_byte
        // would push us to count + 1. Reject if that exceeds the cap.
        if self.touched_namespaces() >= MAX_NAMESPACES_PER_TX {
            return Err(Error::TooManyNamespaces {
                limit: MAX_NAMESPACES_PER_TX,
            });
        }
        Ok(())
    }

    /// R-NSKIND: enforce single-kind-per-namespace at Tx-time. The
    /// commit-side enforcement in `Space::commit_tx` is the
    /// authoritative gate, but rejecting early here gives integrators
    /// a synchronous `WrongNamespaceKind` instead of letting them
    /// queue up a doomed Tx. Cross-Tx enforcement (vs prior root
    /// kind) lives in `commit_tx` because it needs space access.
    fn check_namespace_kind(&self, ns_byte: u8, want: NamespaceKind) -> Result<()> {
        let other_pending_present = match want {
            NamespaceKind::Kv => self.pending_log.contains_key(&ns_byte),
            NamespaceKind::Log => self.pending_kv.contains_key(&ns_byte),
        };
        if other_pending_present {
            return Err(Error::WrongNamespaceKind(
                "namespace already used as the other kind in this Tx",
            ));
        }
        Ok(())
    }

    /// Insert or replace a KV entry. Multiple puts of the same `key`
    /// in one Tx coalesce — the last one wins.
    ///
    /// **Single-kind-per-namespace contract (R-NSKIND, format v2).**
    /// A given `namespace` byte holds EITHER KV entries
    /// (via `put` / `delete`) OR log entries (via `append_log`),
    /// never both. Enforcement is in three layers:
    /// 1. **This call** — returns
    ///    [`Error::WrongNamespaceKind`] if the namespace is already
    ///    in `pending_log` (same Tx).
    /// 2. **`commit_tx`** — returns
    ///    [`Error::WrongNamespaceKind`] before writing any chunk if
    ///    the namespace already has a prior `IndexRoot` whose `kind`
    ///    disagrees with how the ops were addressed (cross-Tx). What
    ///    is weighed there is *how the ops were addressed* — by key, by
    ///    log id, or by a whole-namespace erase — not their shape;
    ///    audit HV-04 replaced a shape test that let a `delete` on a
    ///    log through.
    /// 3. **On-disk** — every `IndexRoot` carries an explicit
    ///    `kind` byte (CommitPayload v2 layout). Repack and vacuum
    ///    route by this persisted kind, no shape heuristic.
    ///
    /// The one operation permitted to disagree with the recorded kind
    /// is [`crate::space::Space::erase_namespace`], which removes every
    /// key there is and so leaves nothing that could be half of one
    /// kind and half of another.
    pub fn put(&mut self, namespace: Namespace, key: &[u8], value: &[u8]) -> Result<()> {
        if namespace == Namespace::RESERVED {
            return Err(Error::Malformed("namespace 0 is reserved"));
        }
        if key.is_empty() || key.len() > crate::space::index::MAX_KEY_LEN {
            return Err(Error::Malformed("invalid key length"));
        }
        if value.len() > crate::space::index::MAX_VALUE_LEN {
            return Err(Error::PayloadTooLarge);
        }
        self.check_namespace_capacity(namespace.0)?;
        self.check_namespace_kind(namespace.0, NamespaceKind::Kv)?;
        self.claim_kv_origin(namespace.0, KvOrigin::ByKey)?;
        self.pending_kv
            .entry(namespace.0)
            .or_default()
            .push(KvOp::Put {
                key: key.to_vec(),
                value: value.to_vec(),
            });
        Ok(())
    }

    /// Delete a KV entry.
    ///
    /// **Kind contract.** Same three layers as [`Self::put`], and for
    /// the same reason. A `delete` is addressed by key, so it belongs
    /// to a `Kv` namespace; against a namespace recorded `Log` it is
    /// rejected at commit with [`Error::WrongNamespaceKind`].
    ///
    /// It was not, until audit HV-04. The commit-side gate looked for a
    /// `Put` among the ops, because pure-`Delete` sets had been let
    /// through so that [`crate::space::Space::erase_namespace`] could
    /// clear a Log namespace — and a lone `delete` is a pure-`Delete`
    /// set. Deleting a log record's index entry this way left the
    /// `DataBatch` chunk behind with nothing pointing at it, through an
    /// API documented to refuse.
    pub fn delete(&mut self, namespace: Namespace, key: &[u8]) -> Result<()> {
        if namespace == Namespace::RESERVED {
            return Err(Error::Malformed("namespace 0 is reserved"));
        }
        if key.is_empty() || key.len() > crate::space::index::MAX_KEY_LEN {
            return Err(Error::Malformed("invalid key length"));
        }
        self.check_namespace_capacity(namespace.0)?;
        self.check_namespace_kind(namespace.0, NamespaceKind::Kv)?;
        self.claim_kv_origin(namespace.0, KvOrigin::ByKey)?;
        self.pending_kv
            .entry(namespace.0)
            .or_default()
            .push(KvOp::Delete { key: key.to_vec() });
        Ok(())
    }

    /// **Internal:** queue a `Delete` tagged with the door it came
    /// through, for the two callers that are not [`Self::delete`].
    ///
    /// `origin` is what `commit_tx` weighs against the namespace's
    /// recorded kind (see [`KvOrigin`]). It is a parameter rather than
    /// a blanket exemption because the blanket exemption is what audit
    /// HV-04 found: this helper skipped the kind check outright, which
    /// was right for [`crate::space::Space::erase_namespace`] and wrong
    /// for [`Self::delete_log`], whose op then reached disk without
    /// ever meeting the recorded kind.
    ///
    /// Takes the key **by value** so a bulk erase can hand over each
    /// key as it is enumerated instead of holding the whole key list
    /// alongside the whole op list (audit HV-03).
    pub(crate) fn delete_internal(
        &mut self,
        namespace: Namespace,
        key: Vec<u8>,
        origin: KvOrigin,
    ) -> Result<()> {
        if namespace == Namespace::RESERVED {
            return Err(Error::Malformed("namespace 0 is reserved"));
        }
        if key.is_empty() || key.len() > crate::space::index::MAX_KEY_LEN {
            return Err(Error::Malformed("invalid key length"));
        }
        self.check_namespace_capacity(namespace.0)?;
        // `check_namespace_kind` is deliberately not called here: it
        // asks whether the OTHER kind is pending in this same Tx, which
        // is a different question from the one `origin` answers. The
        // recorded-kind gate is in `commit_tx`, where the prior root is
        // readable.
        self.claim_kv_origin(namespace.0, origin)?;
        self.pending_kv
            .entry(namespace.0)
            .or_default()
            .push(KvOp::Delete { key });
        Ok(())
    }

    /// Append (or replace) a log entry. `log_id` is the caller's
    /// choice of key — typically a monotonic counter or
    /// UUID-derived u64. **Last-write-wins semantics**: appending
    /// twice with the same `log_id` (either within one Tx or across
    /// Txes) replaces the previous value on read. The behaviour is
    /// load-bearing for the messenger use-case (re-deliver / edit a
    /// message) and is locked down by
    /// [`tests/log_basic.rs::append_log_replaces_with_same_id_in_one_tx`](../../../tests/log_basic.rs)
    /// + `append_log_replace_across_txs`.
    ///
    /// **Storage note for the replace path.** The previous
    /// `DataBatch` chunk that held the old value is **not**
    /// physically scrubbed by `append_log` — it becomes orphaned
    /// (no live KV pointer references it) and is reclaimed by the
    /// next [`crate::Space::vacuum_data_batches`] or
    /// [`crate::Container::compact_known`]. Host-apps that need
    /// forward-secrecy after edits should schedule one of those
    /// passes; until then a key-holder forensic with the password
    /// can recover the prior value from the orphan chunk.
    ///
    /// At commit time, accumulated records are auto-split into one or
    /// more `DataBatch` chunks if the compressed encoding of the full
    /// set would exceed `PAYLOAD_CAP` — the caller does **not** need
    /// to predict zstd compression ratios. Splitting is transparent on
    /// read; `read_log` / `iter_log_*` follow per-record KV pointers.
    ///
    /// Errors with [`Error::PayloadTooLarge`] for payloads beyond
    /// [`MAX_LOG_PAYLOAD_LEN`] (8 KiB) or once the in-memory pending
    /// buffer exceeds [`MAX_RECORDS_PER_BATCH`] (a per-Tx cap, not a
    /// per-on-disk-batch cap).
    ///
    /// **Per-namespace `log_id` scaling (audit HV-15).** Each appended
    /// `log_id` becomes one entry in the namespace's KV index (8-byte
    /// log_id_key → 8-byte batch_slot pointer). There is **no longer a
    /// cap** on how many a namespace holds: the index grows a tree
    /// level whenever the level below outgrows one chunk, so the limit
    /// is the container's own ([`Error::ContainerTooLarge`] at
    /// [`crate::MAX_OPEN_SCAN_CHUNKS`]). The two-level shape used to
    /// stop at roughly ~15 K unique `log_id`s with `Error::IndexFull`.
    ///
    /// The cost of a commit does not scale with it either, since audit
    /// HV-16: `commit_tx` descends to the affected leaf and rewrites
    /// the path above it, so appending to a log holding 200 000 ids
    /// costs the same ~11 ms and ~12 MiB as appending to one holding
    /// 2 000. What a commit *does* cost is the span of keys it touches
    /// — irrelevant for a monotonic `log_id` writer, whose appends are
    /// always at the high end. Numbers in
    /// `docs/en/contributing/benchmarks.md`.
    ///
    /// **Single-kind-per-namespace contract (R-NSKIND, format v2).**
    /// See [`Tx::put`] for the three-layer enforcement (Tx-time +
    /// commit-time + on-disk `kind` byte). Calling `append_log` on a
    /// namespace previously used as `Kv` (in this Tx OR in any prior
    /// committed Tx) returns [`Error::WrongNamespaceKind`].
    pub fn append_log(&mut self, namespace: Namespace, log_id: u64, payload: &[u8]) -> Result<()> {
        if namespace == Namespace::RESERVED {
            return Err(Error::Malformed("namespace 0 is reserved"));
        }
        if payload.len() > MAX_LOG_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge);
        }
        // The length check alone is not the real limit. MAX_LOG_PAYLOAD_LEN is
        // 8 KiB and a DataBatch chunk holds ~4 KiB, so an INCOMPRESSIBLE 8 KiB
        // record passed here and then could not be encoded at all — the failure
        // surfaced at `commit`, where it names no record, arrives after the
        // caller has built the whole transaction, and takes every other write
        // in that transaction down with it (audit HV-12).
        //
        // Only records past the guaranteed-admissible size pay for the trial
        // encode; ordinary log entries are far below it.
        crate::space::log::single_record_fits(log_id, payload)?;
        self.check_namespace_capacity(namespace.0)?;
        self.check_namespace_kind(namespace.0, NamespaceKind::Log)?;
        let buf = self.pending_log.entry(namespace.0).or_default();
        if buf.len() >= MAX_RECORDS_PER_BATCH {
            return Err(Error::PayloadTooLarge);
        }
        buf.push((log_id, payload.to_vec()));
        Ok(())
    }

    /// Delete one log entry by its logical id. No-op if the id is absent.
    ///
    /// Unlike replacing an entry with an empty payload through
    /// [`Self::append_log`], this removes the `log_id → DataBatch` pointer from
    /// the namespace's B+ index and therefore releases one unique-id slot. The
    /// old DataBatch becomes orphaned and is physically reclaimed by
    /// [`crate::Space::vacuum_data_batches`] or
    /// [`crate::Container::compact_known`].
    ///
    /// A transaction may contain several `delete_log` calls for the same Log
    /// namespace, but it must not mix `delete_log` and `append_log` for that
    /// namespace in one transaction. Callers that replace some records and
    /// delete others should commit the appends first and the deletes second.
    ///
    /// **Kind contract.** The namespace must be recorded `Log`; against
    /// one recorded `Kv` this returns [`Error::WrongNamespaceKind`] at
    /// commit. Until audit HV-04 it did not: a log delete is stored as
    /// a KV `Delete` on the `log_id_key`, so it never passed the
    /// log-side gate, and it reached the index through
    /// the same internal helper `erase_namespace` uses, which skipped
    /// the KV-side one. It was
    /// the only op in the crate that met no kind check at all — an
    /// application that mixed up two namespace constants removed a real
    /// KV entry, silently, whenever its key happened to be the eight
    /// big-endian bytes of the id.
    pub fn delete_log(&mut self, namespace: Namespace, log_id: u64) -> Result<()> {
        if self.pending_log.contains_key(&namespace.0) {
            return Err(Error::WrongNamespaceKind(
                "delete_log cannot be mixed with append_log in one Tx",
            ));
        }
        // "Not mixed with KV ops in one Tx" is now the origin claim:
        // `ByLog` against a namespace already claimed `ByKey` (or being
        // erased) is the same rejection, stated once.
        self.delete_internal(namespace, log_id.to_be_bytes().to_vec(), KvOrigin::ByLog)
    }

    /// Number of distinct namespaces touched by pending ops in this
    /// transaction (KV + log combined).
    #[must_use]
    pub fn touched_namespaces(&self) -> usize {
        let mut s: std::collections::BTreeSet<u8> = std::collections::BTreeSet::new();
        s.extend(self.pending_kv.keys().copied());
        s.extend(self.pending_log.keys().copied());
        s.len()
    }

    /// True iff there are no pending KV or log ops in this Tx.
    /// `commit` on an empty Tx is a no-op (no commit chunk emitted).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending_kv.is_empty() && self.pending_log.is_empty()
    }

    /// Flush. Returns the new commit sequence. Consumes the [`Tx`].
    pub fn commit(self) -> Result<u64> {
        self.space
            .commit_tx(self.pending_kv, self.pending_log, self.kv_origin)
    }
}
