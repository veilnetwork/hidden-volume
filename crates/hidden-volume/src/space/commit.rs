//! Tx commit logic: the 3-fsync protocol that promotes a Tx's
//! pending operations into a new on-disk commit. Audit pass 8 (E7)
//! split out of `space/mod.rs` so the commit path (the most
//! security-sensitive write code in the crate) is reviewable as a
//! self-contained ~280-LOC chunk.

use std::collections::BTreeMap;

use crate::chunk::ChunkKind;
use crate::redact::Redacted;
use crate::tx::commit::{CommitPayload, IndexRoot};
use crate::tx::{KvOp, KvOrigin, PendingKv, PendingKvOrigin, PendingLog};
use crate::{Error, Result};

use super::Space;
use super::index::Namespace;
use super::log;
use super::superblock::Superblock;
use super::tree::{Build, KeyOps};

impl<'f> Space<'f> {
    /// Apply a Tx's pending KV + log operations and run the 3-fsync
    /// commit protocol. See [`crate::tx`] for the protocol details.
    ///
    /// commit_tx is append-only — it never scrubs. Within a single
    /// open session, old IndexNode chunks from previous commits
    /// remain on disk as in-flight-commit recovery fallbacks. They
    /// are scrubbed automatically by the next call to
    /// [`Container::open_space`] via [`Space::vacuum_orphans`], so
    /// **across application restarts those fallbacks are gone** —
    /// cross-launch rollback / fork detection works through the
    /// multi-Superblock-replicas path
    /// ([`Space::commit_history`]), not through orphan IndexNode
    /// preservation. (Audit pass 7 C3 — clarification.)
    ///
    /// **Post-failure state (audit pass 7 C4).** If `commit_tx`
    /// returns `Err`, some chunks may have been appended to the
    /// file and `state.owned_slots` extended before the failing
    /// step. `state.superblock` is **unchanged** (we only swap it
    /// after the final fsync). The next [`Space::vacuum_orphans`]
    /// reclaims orphan IndexNode chunks. **Orphan DataBatch chunks
    /// from a failed Phase 0 are NOT cleaned by `vacuum_orphans`**;
    /// run [`Space::vacuum_data_batches`] explicitly after a
    /// commit-fail to close the forward-secrecy gap (audit pass 7
    /// D1).
    ///
    /// **Which failure it was matters (report8 H-09).** Everything up to and
    /// including the Commit chunk's fsync is invisible to a reader, so those
    /// failures keep their own error and the caller may retry. From the
    /// superblock publish onwards the answer is
    /// [`Error::PublishUncertain`]: the seq is burnt, a replica may already be
    /// on the disk, and this handle may be an era behind the file. Retrying is
    /// then the wrong move and vacuuming is a destructive one — reopen instead.
    /// The underlying cause is kept on [`Space::last_publish_error`].
    ///
    /// **Padding-step failure (audit M1, 2026-05-10).** Once the
    /// superblock fsync (the durable-publish moment) succeeds, this
    /// function returns `Ok(seq)` regardless of whether the
    /// post-commit padding step succeeds or fails. A padding failure
    /// is recorded on [`SpaceState::last_padding_error`] for caller
    /// introspection but does not downgrade the durable commit into
    /// an apparent failure — that would lie about visibility of the
    /// commit to other processes (other processes already see the
    /// new superblock). Padding is a privacy hardening, not a
    /// correctness invariant; a single skipped padding round only
    /// makes that commit's size observable to a multi-snapshot
    /// adversary.
    /// Both buffers arrive still wrapped in [`Redacted`] and are consumed
    /// here rather than in [`crate::tx::Tx::commit`], so the keys, values
    /// and payloads a caller queued are scrubbed when this function
    /// returns — on the error paths as much as the success one (audit
    /// HV-07). They are the crate's own copies; what the caller still owns
    /// is the caller's to manage.
    pub(crate) fn commit_tx(
        &mut self,
        mut pending: Redacted<PendingKv>,
        pending_log: Redacted<PendingLog>,
        kv_origin: PendingKvOrigin,
    ) -> Result<u64> {
        // Audit pass 7 (C1): if both pending maps are empty, the
        // commit is a no-op. Previously commit_tx unconditionally
        // bumped seq, wrote a Commit chunk + Superblock replicas,
        // and ran 3 fsyncs — contradicting `Tx::is_empty`'s doc and
        // wasting disk + adding a multi-snapshot writer-active
        // signal. Early-return the current seq instead.
        if pending.values().all(|ops| ops.is_empty())
            && pending_log.values().all(|recs| recs.is_empty())
        {
            return Ok(self.state.superblock.seq);
        }

        // Committing on top of a stale root FORKS the space: the newer writer's
        // era and ours both claim descent from different states, and the open
        // scan resolves that by seq alone. Reading such a container is fine —
        // writing to it is not. See `SpaceState::unreadable_newer_superblock`.
        if self.state.unreadable_newer_superblock.is_some() {
            return Err(Error::UnreadableNewerState);
        }

        // Audit pass 11 (L3): defensive `checked_add`. Practically
        // unreachable through honest use (would require `u64::MAX`
        // commits), but a malformed AEAD-valid Superblock could push
        // `seq` to `u64::MAX` and crash a subsequent commit on
        // overflow. Convert to an explicit `Error::Internal` instead.
        // Derived from `attempted_seq`, not `superblock.seq`: a previous
        // publish may have put a replica of a higher seq on disk and then
        // failed, and re-using that number for a different payload loses one
        // of the two commits silently. See [`SpaceState::attempted_seq`].
        let new_seq = self
            .state
            .attempted_seq
            .max(self.state.superblock.seq)
            .checked_add(1)
            .ok_or(Error::Internal("commit seq overflow"))?;

        // R-NSKIND: validate kind consistency upfront. A namespace
        // that already has a prior IndexRoot must keep its kind;
        // touching it with the wrong kind in this Tx is a
        // `WrongNamespaceKind` error before we write a single chunk.
        // A namespace that's both in `pending` (KV ops) AND
        // `pending_log` is also rejected — `Tx` already enforces
        // single-kind-per-Tx, this is a defense-in-depth safety net.
        let prior_roots_by_ns: std::collections::BTreeMap<u8, IndexRoot> = self
            .load_prior_roots()?
            .into_iter()
            .map(|r| (r.namespace.0, r))
            .collect();

        for ns in pending.keys() {
            if pending_log.contains_key(ns) {
                return Err(Error::WrongNamespaceKind(
                    "namespace touched as both Kv and Log in one Tx",
                ));
            }
            // No prior root: the namespace does not exist yet, so there
            // is no recorded kind for these ops to contradict. The kind
            // this Tx establishes is decided below.
            let Some(prior) = prior_roots_by_ns.get(ns) else {
                continue;
            };
            // Audit HV-04. This gate used to read the op SHAPE — it
            // rejected a `Put` against a Log namespace and let every
            // pure-`Delete` set through, because that is how
            // `Space::erase_namespace` clears a Log namespace. The
            // exemption was written for erase and granted to anything
            // that looked like erase, so a `Tx::delete` on a log passed
            // it; and `Tx::delete_log` never reached this loop's
            // predicate at all, since its op is a KV `Delete` while the
            // log-side check below reads `pending_log`.
            //
            // It now reads where the op came from. Two of the three
            // origins name a kind and must match what is on disk; only
            // an erase may disagree with it, because the namespace it
            // leaves behind is empty and so cannot be half of one kind
            // and half of another.
            let origin = kv_origin
                .get(ns)
                .copied()
                .ok_or(Error::Internal("pending KV ops with no recorded origin"))?;
            match (origin, prior.kind) {
                (KvOrigin::Erase, _) => {},
                (KvOrigin::ByKey, crate::tx::NamespaceKind::Kv) => {},
                (KvOrigin::ByLog, crate::tx::NamespaceKind::Log) => {},
                (KvOrigin::ByKey, _) => {
                    return Err(Error::WrongNamespaceKind(
                        "KV op addressed by key against an existing Log namespace",
                    ));
                },
                (KvOrigin::ByLog, _) => {
                    return Err(Error::WrongNamespaceKind(
                        "delete addressed by log id against an existing Kv namespace",
                    ));
                },
            }
        }
        for ns in pending_log.keys() {
            if let Some(prior) = prior_roots_by_ns.get(ns)
                && prior.kind != crate::tx::NamespaceKind::Log
            {
                return Err(Error::WrongNamespaceKind(
                    "Log op against existing Kv namespace",
                ));
            }
        }

        // Audit pass 11 (L2): the resulting active root set is
        // `prior_roots ∪ pending` (not just `pending`) — `Tx`
        // already rejects `pending.len() > MAX_NAMESPACES_PER_TX`
        // via `check_namespace_capacity`, but a near-capacity space
        // could still cross the limit when prior untouched roots
        // are carried forward. Compute the union upfront and reject
        // BEFORE writing any chunk; previously the failure surfaced
        // late inside `CommitPayload::encode` as `Error::Internal`
        // with orphan chunks already on disk.
        //
        // The union is an **upper bound** on the resulting active
        // root count, not the exact value. A pending namespace that
        // ends up empty after applying ops (e.g. all-deletes) is
        // dropped from `new_roots` later (search for `entries.is_empty()`).
        // Rejecting on the upper bound is conservative: it can fail
        // a Tx that would have squeezed in just under the limit. The
        // host-app remedy is to split the Tx; the trade-off is that
        // every chunk write is preceded by a guaranteed-safe check.
        {
            let mut union: std::collections::BTreeSet<u8> =
                prior_roots_by_ns.keys().copied().collect();
            for ns in pending.keys() {
                union.insert(*ns);
            }
            for ns in pending_log.keys() {
                union.insert(*ns);
            }
            if union.len() > crate::tx::MAX_NAMESPACES_PER_TX {
                return Err(Error::TooManyNamespaces {
                    limit: crate::tx::MAX_NAMESPACES_PER_TX,
                });
            }
        }

        // Build the kind register for this Tx: Log for namespaces
        // touched by `pending_log`, otherwise inherit from prior root,
        // otherwise default Kv. This drives the `kind` field of every
        // new IndexRoot emitted below.
        let log_namespaces: std::collections::BTreeSet<u8> = pending_log.keys().copied().collect();
        let kind_for_namespace = |ns: u8| -> crate::tx::NamespaceKind {
            if log_namespaces.contains(&ns) {
                return crate::tx::NamespaceKind::Log;
            }
            if let Some(prior) = prior_roots_by_ns.get(&ns) {
                return prior.kind;
            }
            crate::tx::NamespaceKind::Kv
        };

        let slots_before = self.file.slot_count();
        // How many slots this commit takes out of the decoy pool decides
        // how many decoys the churn re-randomizes afterwards. Sampled
        // here, before the first chunk is placed.
        let reuse_before = self.state.reuse_count;
        // And how many it is ALLOWED to take, which is not the whole pool.
        // Reuse and churn draw from the same pool and reuse goes first, so an
        // unbudgeted commit could `take` the pool down to nothing and then ask
        // `sample_distinct` for victims that are no longer there — and that
        // call truncates in silence. The commit still returned `Ok`; the churn
        // simply did not happen. Reserving the churn's share before the first
        // chunk is placed is what keeps "one write process, not two" true on a
        // small pool, which is what a container has right after its first
        // `vacuum_orphans`. Past the budget the commit appends instead, and
        // pays the growth DESIGN §9.1 already prices.
        self.state.reuse_floor = super::reuse_floor_for(self.state.pool.len());

        // Phase 0: Flush each non-empty log buffer to a DataBatch chunk,
        // then route resulting batch_slot pointers as KV puts. After
        // this, the rest of commit_tx is the same KV-only flow.
        for (ns_byte, log_records) in pending_log.into_inner() {
            if log_records.is_empty() {
                continue;
            }
            // Coalesce duplicate log_ids — last append wins (matches
            // KV semantics for repeated puts in one tx). Use a BTreeMap
            // keyed by log_id; later inserts overwrite earlier ones.
            let mut by_id: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
            for (id, payload) in log_records {
                by_id.insert(id, payload);
            }
            // Re-wrapped once the shape settles. `into_iter` moves the same
            // payload buffers `Tx::append_log` allocated, so the wrapper's
            // drop is what scrubs them when this iteration ends (HV-07).
            let log_records = Redacted::new(by_id.into_iter().collect::<Vec<(u64, Vec<u8>)>>());

            // Auto-split into 1+ DataBatch chunks if the compressed
            // payload of the full record set would exceed PAYLOAD_CAP.
            // Common case (records compress well, ≤ ~150 messages):
            // exactly one batch, one zstd call.
            let batches = log::encode_batches_split(&log_records)?;

            let kv_ops = pending.entry(ns_byte).or_default();
            for (log_ids, batch_bytes) in batches {
                let batch_slot = self.place_chunk(ChunkKind::DataBatch, new_seq, &batch_bytes)?;
                for log_id in log_ids {
                    kv_ops.push(KvOp::Put {
                        key: log::log_id_key(log_id).to_vec(),
                        value: log::encode_batch_slot_value(batch_slot).to_vec(),
                    });
                }
            }
        }

        // 1. For each touched namespace, build the new tree and emit
        //    chunks (potentially multiple if leaf splits).
        let mut new_roots: Vec<IndexRoot> = Vec::new();

        // Carry forward untouched prior roots (kind preserved verbatim).
        for prior in prior_roots_by_ns.values() {
            if !pending.contains_key(&prior.namespace.0) {
                new_roots.push(*prior);
            }
        }

        for (ns_byte, ops) in pending.iter() {
            let ns = Namespace(*ns_byte);
            // Collapse the Tx's ops to one per key, in key order, so the
            // tree update is a merge against the entry stream rather
            // than a sequence of point edits (audit HV-16).
            let mut keyed = KeyOps::default();
            for op in ops {
                match op {
                    KvOp::Put { key, value } => {
                        keyed.insert(key.clone(), Some(value.clone()));
                    },
                    KvOp::Delete { key } => {
                        keyed.insert(key.clone(), None);
                    },
                }
            }

            if keyed.is_empty() {
                // Nothing to do for this namespace; keep whatever it
                // had. (The carry-forward loop above skips namespaces
                // present in `pending`.)
                if let Some(prior) = prior_roots_by_ns.get(ns_byte) {
                    new_roots.push(*prior);
                }
                continue;
            }

            // Descend to the affected leaf and rewrite the path above
            // it; nodes outside the neighbourhood of the change are not
            // read, not hashed and not written. Where a node ends is
            // decided by its own content, so this produces the same
            // bytes a full rebuild would — see `super::tree`.
            let mut build = Build::new(new_seq, self.new_tree_walk());
            let root = match prior_roots_by_ns.get(ns_byte) {
                Some(prior) => self.update_tree(ns, prior, &keyed, &mut build)?,
                None => {
                    // `into_inner` rather than iterating through the
                    // wrapper: taking the plaintext out is the one
                    // explicit step `Redacted` asks for, and the map is
                    // consumed here. The wrapper is left holding an
                    // empty map, so its own drop still scrubs.
                    let entries = keyed
                        .into_inner()
                        .into_iter()
                        .filter_map(|(key, value)| value.map(|v| (key, v)));
                    self.build_tree(ns, entries, &mut build)?
                },
            };

            // Empty namespace → omit from the new Commit.
            let Some((root_slot, root_hash)) = root else {
                continue;
            };
            new_roots.push(IndexRoot {
                namespace: ns,
                kind: kind_for_namespace(*ns_byte),
                index_slot: root_slot,
                payload_hash: root_hash,
            });
        }

        new_roots.sort_by_key(|r| r.namespace.0);

        self.file.fsync()?;

        // 2. Commit chunk.
        let tx_root_hash = CommitPayload::compute_tx_root_hash(&new_roots);
        let cp = CommitPayload {
            roots: new_roots,
            tx_root_hash,
        };
        let cp_bytes = cp.encode()?;
        let commit_slot = self.place_chunk(ChunkKind::Commit, new_seq, &cp_bytes)?;
        self.file.fsync()?;

        // 3. New Superblock — at this point the new commit is visible
        // and a crash here-or-later leaves the user with the new state.
        // Multiple replicas for resilience to torn writes / single-chunk
        // corruption (DESIGN §7). Recovery picks any readable replica
        // at max seq.
        let new_sb = Superblock {
            seq: new_seq,
            root_slot: commit_slot,
            root_hash: tx_root_hash,
            // Carry the checkpoint pointer forward verbatim. The commit
            // path never mints or moves a checkpoint (that is the
            // open-scan self-heal writer's job); copying the existing
            // pointer into the superblock we are already writing keeps
            // the latest superblock pointing at the live checkpoint at
            // zero extra disk cost. Defaults to NO_RECORD until the
            // first self-heal writes a checkpoint.
            checkpoint_slot: self.state.superblock.checkpoint_slot,
        };
        // Everything above this line is BEFORE the publish: a failure there has
        // put orphan chunks on the disk but nothing a reader can reach, so it
        // keeps its own error. From here the seq is burnt and a replica may
        // land, so every failure is `PublishUncertain` — the caller's remedy
        // stops being "retry" and becomes "reopen" (report8 H-09).
        self.publish_superblock(&new_sb, "committing")?;

        self.state.superblock = new_sb;
        // The prior commit era's cached roots payload is now stale — drop it so
        // its decrypted bytes are zeroized promptly (rather than lingering until
        // the next `load_prior_roots` replaces it), and so the next read decodes
        // the fresh era. The `seq` gate in `load_prior_roots` is the correctness
        // backstop; this clear is the memory-hygiene half.
        self.state.roots_payload_cache = None;
        // new_seq is strictly greater than every prior entry (commit_tx
        // monotonically increments seq), so push preserves sort order
        // and uniqueness of `commit_history` without re-sorting.
        self.state.commit_history.push(new_seq);

        // Post-commit padding (DESIGN §8): mask per-commit file size
        // growth from a multi-snapshot adversary. Garbage chunks are
        // uniform random — visually identical to AEAD-encrypted chunks.
        //
        // **M1 hardening (audit 2026-05-10).** The superblock fsync
        // above makes the commit durable and visible to
        // other processes; from that moment on, `new_seq` is the
        // canonical commit_seq for the space. Any failure in this
        // padding block must NOT downgrade that visible success into
        // an `Err` return — that would lie to the caller about
        // durability (host-app would retry the commit, double-write,
        // or corrupt its sync state). We therefore catch padding
        // failures, stash them on `state.last_padding_error` for
        // introspection, and still return `Ok(new_seq)`. Padding is
        // a privacy hardening (mask file-size growth from a
        // multi-snapshot adversary), not a correctness invariant —
        // a single missed padding round just means this one commit's
        // size is observable, not that data is lost.
        //
        // **Decoy churn rides here too (DESIGN §9.1).** It is the same
        // kind of thing as padding — a write that exists only to make the
        // real writes ambiguous — with the same non-downgrade rule, so it
        // shares this block and reports through the same field. It runs
        // in the same post-publish window and under the same fsync as the
        // padding, which is what makes churn and reuse land inside one
        // snapshot interval rather than in two the adversary can order.
        let real_added = self.file.slot_count() - slots_before;
        let pad_from = self.file.slot_count();
        // Padding and churn are ATTEMPTED SEPARATELY, and this is the whole
        // point of the shape below. They used to be one `and_then` chain, so a
        // padding failure — a quota, an arithmetic slip, ENOSPC — skipped churn
        // entirely. The superblock is already durable by here, so that left a
        // commit whose real writes reused slots and whose decoys never moved:
        // exactly the snapshot pair §9.1 exists to deny, produced by a failure
        // an adversary can provoke by filling the disk.
        //
        // Churn is not optional cleanup. It is what makes the reuse deniable,
        // so it runs whatever padding did.
        let padding_result = self
            .file
            .padding_policy
            .garbage_after_commit(pad_from, real_added)
            .and_then(|pad_count| {
                if pad_count > 0 {
                    self.file.append_garbage_chunks(pad_count)?;
                }
                Ok(())
            });
        // One churned decoy per slot this commit reused. Drawn from the pool
        // the reuse drew from, uniformly, in the same commit — see
        // `CHURN_PER_REUSE` for why the rate is tied to reuse and not a clock.
        let reused = self.state.reuse_count.saturating_sub(reuse_before) as usize;
        let churn_result = self
            .churn_decoys(reused.saturating_mul(super::CHURN_PER_REUSE))
            .map(|_| ());
        // One fsync for whatever landed, so both still share a single snapshot
        // interval — the property that made them one chain in the first place.
        let sync_result = self.file.fsync();
        // First failure reported, both attempted.
        let padding_outcome = padding_result.and(churn_result).and(sync_result);
        // Garbage THIS space appended, at a slot range this space watched
        // itself write — the second of the two populations it can prove
        // are decoys (DESIGN §9.1). Recorded outside the closure and from
        // the slot count rather than from `pad_count`, so a run that
        // failed part-way still hands over the chunks that did land:
        // `append_garbage_chunks` advances the count per batch.
        for slot in pad_from..self.file.slot_count() {
            self.state.pool.insert(slot);
        }
        // Replace (don't merge) — `last_padding_error` reflects only
        // the most recent commit's padding outcome. A successful
        // padding round clears any previously-stuck error.
        self.state.last_padding_error = padding_outcome.err();

        Ok(new_seq)
    }
}

#[cfg(test)]
mod publish_uncertainty_tests {
    use crate::chunk::ChunkKind;
    use crate::container::Container;
    use crate::crypto::kdf::Argon2Params;
    use crate::space::ForcedAppendFailure;
    use crate::space::index::Namespace;

    fn scratch() -> std::path::PathBuf {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let p = tmp.path().to_owned();
        drop(tmp);
        p
    }

    /// A commit that fails once a replica may be on the disk must say
    /// **reopen**, not "the write failed" (report8 H-09).
    ///
    /// The fault is armed on the SECOND superblock append, so the first replica
    /// genuinely lands: the file then holds seq N+1 while this handle's
    /// `superblock.seq` still says N. That is not a write that did nothing — it
    /// is a handle that is now behind the file, and the reopen below proves it
    /// by reading the value the "failed" commit wrote. Answering `Io` there
    /// described the syscall and told the caller the opposite of the truth.
    #[test]
    fn a_commit_that_fails_after_a_replica_lands_says_reopen() {
        let path = scratch();
        let durable;
        {
            let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
            c.set_superblock_replicas(3).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", b"v1").unwrap();
            tx.commit().unwrap();
            durable = s.commit_seq();

            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", b"v2").unwrap();
            let armed = ForcedAppendFailure::arm(ChunkKind::Superblock, 2);
            let err = tx
                .commit()
                .expect_err("the second replica was made to fail");
            drop(armed);

            assert!(
                matches!(err, crate::Error::PublishUncertain(_)),
                "a publish that may have landed must name its remedy, not the \
                 syscall that broke: got {err:?}"
            );

            // The cause is kept for whoever has to diagnose the device.
            assert!(
                matches!(s.last_publish_error(), Some(crate::Error::Io(_))),
                "the original failure was dropped on the floor: {:?}",
                s.last_publish_error()
            );

            // The seq is burnt, so the destructive path is refused — the gate
            // this error exists to arm (audit HV-01).
            assert!(
                matches!(s.vacuum_orphans(), Err(crate::Error::PublishUncertain(_))),
                "the burnt seq did not arm the vacuum refusal"
            );

            // ...and committing is NOT blocked (audit HV-01): the next seq is
            // derived from the burn mark, so it skips the number instead of
            // publishing a second payload under it.
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", b"v3").unwrap();
            let seq = tx.commit().expect("a burnt publish must not brick writes");
            assert!(
                seq > durable + 1,
                "the next commit re-used the burnt seq {}: got {seq}",
                durable + 1
            );
        }

        // The replica really did land: the era the caller was told about as a
        // failure is the one on the disk.
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert_eq!(
            s.get(Namespace::SETTINGS, b"k").unwrap().as_deref(),
            Some(&b"v3"[..])
        );
        assert!(
            s.commit_seq() > durable,
            "nothing was published at all — the fault fired too early for this \
             test to be about uncertainty"
        );
        drop(s);
        let _ = std::fs::remove_file(&path);
    }

    /// CONTROL: a failure BEFORE the publish window keeps its own error.
    ///
    /// Nothing is visible to a reader until a superblock names it, so a Commit
    /// chunk that never got written is a plain failed write with a plain
    /// remedy. Widening `PublishUncertain` to cover it would tell every caller
    /// to reopen after any full disk, and would make the distinction the
    /// variant exists to draw meaningless.
    #[test]
    fn a_failure_before_the_publish_window_is_not_uncertain() {
        let path = scratch();
        {
            let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
            c.set_superblock_replicas(3).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", b"v1").unwrap();
            tx.commit().unwrap();
            let durable = s.commit_seq();

            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", b"v2").unwrap();
            let armed = ForcedAppendFailure::arm(ChunkKind::Commit, 1);
            let err = tx.commit().expect_err("the Commit chunk was made to fail");
            drop(armed);

            assert!(
                matches!(err, crate::Error::Io(_)),
                "a pre-publish failure published nothing, so it must not send \
                 the caller off to reopen: got {err:?}"
            );
            assert_eq!(
                s.state.attempted_seq, durable,
                "nothing was published, so no seq should have been burnt"
            );
            assert!(s.last_publish_error().is_none());
            // And the destructive path stays available, because this handle is
            // not behind anything.
            s.vacuum_orphans()
                .expect("a pre-publish failure must not arm the reopen gate");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// The checkpoint self-heal publishes a superblock too, so it owes the
    /// caller the same answer. It is documented as "an optimisation hint", and
    /// that is true of the chain it writes — but publishing one bumps the
    /// superblock seq, and that half is an era transition like any other.
    #[test]
    fn a_checkpoint_publish_that_fails_says_reopen_too() {
        let path = scratch();
        {
            let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
            c.set_superblock_replicas(3).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", b"v1").unwrap();
            tx.commit().unwrap();
            let durable = s.commit_seq();

            let armed = ForcedAppendFailure::arm(ChunkKind::Superblock, 2);
            let err = s
                .write_self_heal_checkpoint()
                .expect_err("the second replica was made to fail");
            drop(armed);

            assert!(
                matches!(err, crate::Error::PublishUncertain(_)),
                "the checkpoint publish burnt a seq and may have landed a \
                 replica, yet reported a plain write failure: {err:?}"
            );
            assert!(
                matches!(s.last_publish_error(), Some(crate::Error::Io(_))),
                "the original failure was dropped on the floor: {:?}",
                s.last_publish_error()
            );
            assert!(
                s.state.attempted_seq > durable,
                "the checkpoint seq was not burnt"
            );
        }
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod seq_allocation_tests {
    use crate::container::Container;
    use crate::crypto::kdf::Argon2Params;
    use crate::space::index::Namespace;

    fn scratch() -> std::path::PathBuf {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let p = tmp.path().to_owned();
        drop(tmp);
        p
    }

    /// A seq whose replica may already be on disk must never be handed out
    /// again.
    ///
    /// Both publishers append N Superblock replicas and adopt the new
    /// superblock only after the final fsync. If a replica lands and the next
    /// one (or the fsync) fails — ENOSPC on a nearly-full disk is the mobile
    /// case — the disk holds seq N+1 while `superblock.seq` still says N.
    /// Deriving the next seq from `superblock.seq` alone published a DIFFERENT
    /// payload under that same N+1, and the open scan resolves a same-seq
    /// collision by slot order, so one of the two commits disappeared. Nothing
    /// detected it: the winner is self-consistent so `verify_integrity`
    /// passes, and N+1 is present in `commit_history` so the multi-device
    /// triage sees no fork.
    ///
    /// The partial publish itself needs an I/O fault to induce, so this drives
    /// the state it leaves behind: `attempted_seq` set without `superblock`
    /// advancing, exactly as `commit_tx` does before its first append.
    #[test]
    fn a_burnt_seq_is_never_reused() {
        let path = scratch();
        {
            let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", b"v1").unwrap();
            tx.commit().unwrap();
            let durable = s.commit_seq();

            // A publish of `durable + 1` got a replica onto the disk and then
            // failed; `superblock` was never adopted.
            s.state.attempted_seq = durable + 1;

            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", b"v2").unwrap();
            tx.commit().unwrap();
            assert_eq!(
                s.commit_seq(),
                durable + 2,
                "the next commit must skip the seq a failed publish may have \
                 already written"
            );
        }
        // ...and the container still opens on the era that was actually
        // published.
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert_eq!(
            s.get(Namespace::SETTINGS, b"k").unwrap().as_deref(),
            Some(&b"v2"[..])
        );
        drop(s);
        let _ = std::fs::remove_file(&path);
    }

    /// Reopening seeds the burn mark from the whole scan, not from the winning
    /// superblock — otherwise a seq burnt by a crash comes back on restart.
    #[test]
    fn the_burn_mark_survives_a_reopen() {
        let path = scratch();
        {
            let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", b"v1").unwrap();
            tx.commit().unwrap();
        }
        let mut c = Container::open(&path).unwrap();
        let s = c.open_space(b"pw").unwrap();
        assert!(
            s.state.attempted_seq >= s.commit_seq(),
            "attempted_seq {} must cover the published era {}",
            s.state.attempted_seq,
            s.commit_seq()
        );
        drop(s);
        let _ = std::fs::remove_file(&path);
    }
}
