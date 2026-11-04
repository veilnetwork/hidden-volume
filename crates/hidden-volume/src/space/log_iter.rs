//! Log-style namespace iteration: `iter_log_*`, `read_log`, and
//! their leaf-walk helpers. Audit pass 8 (E7) split out of
//! `space/mod.rs` so log-pagination logic is reviewable as a
//! self-contained ~340-LOC chunk.

use crate::chunk::ChunkKind;
use crate::{Error, Result};

use super::Space;
use super::index::{IndexNode, Namespace};
use super::log;
use super::point_read::PointIndexCache;
use super::walk::TreeWalk;

/// One decoded log record: `(log_id, payload)`.
///
/// The payload scrubs itself on drop. It has to: this cache holds up to 8 MiB
/// of decoded records, and every way one leaves — eviction, replacement, a
/// rejected batch, the end of the call — used to be an ordinary drop of a
/// user's log record in the clear (report17 HV17-M5).
type LogRecord = (u64, log::LogPayload);
/// A decoded `DataBatch`'s records, in append order.
type DecodedBatch = Vec<LogRecord>;
/// The digest of the exact compressed payload is needed even when another
/// index entry already caused this batch to be decoded.
struct CachedBatch {
    last_use: u64,
    hash: [u8; 32],
    records: DecodedBatch,
}

fn verify_batch_reference(value: &[u8], actual: &[u8; 32]) -> Result<()> {
    if log::parse_batch_content_hash(value).is_some_and(|expected| expected != *actual) {
        return Err(Error::Malformed(
            "log batch does not match the hash its index value commits to",
        ));
    }
    Ok(())
}

/// Per-call cache of decoded `DataBatch` chunks, bounded in both bytes
/// and entries ([`log::MAX_CACHED_BATCH_BYTES`],
/// [`log::MAX_CACHED_BATCHES`]) so a page cannot make the decoder hold
/// an arbitrary multiple of [`log::MAX_DECODED_BATCH_LEN`].
///
/// Eviction is least-recently-used, by an insertion/access counter
/// rather than an intrusive list: the entry cap keeps the "find the
/// oldest" scan at ≤ 64 comparisons, which is cheaper than maintaining
/// order across a map. Evicting is always safe — the batch can be
/// re-read and re-decoded — so results never depend on what stayed
/// resident.
struct BatchCache {
    /// `batch_slot -> authenticated payload digest and decoded records`.
    entries: std::collections::HashMap<u64, CachedBatch>,
    /// Decoded-record footprint plus one 32-byte digest per entry.
    bytes: usize,
    max_bytes: usize,
    max_entries: usize,
    tick: u64,
}

impl BatchCache {
    fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            bytes: 0,
            max_bytes,
            max_entries,
            tick: 0,
        }
    }

    /// Look up a decoded batch, marking it most-recently-used.
    fn get(&mut self, slot: u64) -> Option<(&[LogRecord], [u8; 32])> {
        self.tick += 1;
        let tick = self.tick;
        let entry = self.entries.get_mut(&slot)?;
        entry.last_use = tick;
        Some((entry.records.as_slice(), entry.hash))
    }

    fn cost(records: &[LogRecord]) -> usize {
        log::batch_footprint(records).saturating_add(std::mem::size_of::<[u8; 32]>())
    }

    /// Admit a decoded batch, evicting least-recently-used entries until
    /// it fits. A batch too large for the whole budget is simply not
    /// cached — it was already decoded for this one lookup, and holding
    /// it would evict everything for a single-use entry.
    fn insert(&mut self, slot: u64, records: DecodedBatch, hash: [u8; 32]) {
        let cost = Self::cost(&records);
        if cost > self.max_bytes || self.max_entries == 0 {
            return;
        }
        // Re-inserting a slot already resident (possible only if a
        // caller decoded it twice) must not double-count its bytes.
        if let Some(old) = self.entries.remove(&slot) {
            self.bytes = self.bytes.saturating_sub(Self::cost(&old.records));
        }
        while self.entries.len() >= self.max_entries
            || self.bytes.saturating_add(cost) > self.max_bytes
        {
            if !self.evict_one() {
                break;
            }
        }
        self.tick += 1;
        self.bytes = self.bytes.saturating_add(cost);
        self.entries.insert(
            slot,
            CachedBatch {
                last_use: self.tick,
                hash,
                records,
            },
        );
    }

    /// Drop the least-recently-used entry. Returns `false` when there
    /// was nothing left to drop.
    fn evict_one(&mut self) -> bool {
        let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_use)
            .map(|(slot, _)| *slot)
        else {
            return false;
        };
        if let Some(entry) = self.entries.remove(&oldest) {
            self.bytes = self.bytes.saturating_sub(Self::cost(&entry.records));
        }
        true
    }
}

impl<'f> Space<'f> {
    /// Read at most eight exact-ID groups and 64 records in total. Each group
    /// is concatenated in requested order under its own byte ceiling. None
    /// means a missing or over-budget record; no subsequent record is read.
    /// Errors retain the scalar read contract. Partial output is scrubbed.
    pub fn read_log_groups(
        &mut self,
        namespace: Namespace,
        groups: &[log::LogReadGroup<'_>],
    ) -> Result<Option<Vec<Vec<u8>>>> {
        if groups.len() > log::MAX_LOG_READ_GROUPS {
            return Err(Error::Malformed("too many log read groups"));
        }
        let mut remaining = log::MAX_LOG_READ_RECORDS;
        for group in groups {
            remaining = remaining
                .checked_sub(group.log_ids.len())
                .ok_or(Error::Malformed("too many requested log records"))?;
        }
        let has_records = groups.iter().any(|group| !group.log_ids.is_empty());
        let root = if has_records {
            self.find_log_root_slot(namespace)?
        } else {
            None
        };
        if has_records && root.is_none() {
            return Ok(None);
        }
        let mut index_cache = PointIndexCache::new();
        let mut cache = BatchCache::new(log::MAX_CACHED_BATCHES, log::MAX_CACHED_BATCH_BYTES);
        let mut out = Vec::with_capacity(groups.len());
        for group in groups {
            // Reserve a bounded ceiling once: growing a Vec could free an old
            // plaintext allocation before Zeroizing sees it. The total request
            // cap bounds all output capacities to 64 * MAX_LOG_PAYLOAD_LEN.
            let capacity = group
                .max_bytes
                .min(group.log_ids.len() * log::MAX_LOG_PAYLOAD_LEN);
            let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
            for &id in group.log_ids {
                let Some(root_slot) = root else {
                    return Ok(None);
                };
                let Some(value) = self.get_from_root(
                    namespace,
                    &log::log_id_key(id),
                    root_slot,
                    Some(&mut index_cache),
                )?
                else {
                    return Ok(None);
                };
                let record = self.log_payload_from_reference(id, &value, &mut cache)?;
                if record.len() > group.max_bytes.saturating_sub(bytes.len()) {
                    return Ok(None);
                }
                bytes.extend_from_slice(&record);
            }
            out.push(bytes);
        }
        Ok(Some(
            out.into_iter()
                .map(|mut bytes| std::mem::take(&mut *bytes))
                .collect(),
        ))
    }

    /// Enumerate all log entries in `namespace`, in ascending log_id
    /// order. Each entry's containing DataBatch chunk is read at most
    /// once (cached during iteration).
    ///
    /// Cost: O(K) chunk reads where K is the number of distinct batches
    /// referenced by the namespace's index, plus one zstd decompress
    /// per batch (more if the batch cache evicts).
    ///
    /// Memory: the returned entries — the whole namespace's payloads,
    /// which is what was asked for — plus the batch cache, which is
    /// bounded by [`log::MAX_CACHED_BATCH_BYTES`] and
    /// [`log::MAX_CACHED_BATCHES`] rather than by K.
    ///
    /// **For large namespaces use [`Self::iter_log_after`] /
    /// [`Self::iter_log_before`] instead** — those page bounded counts,
    /// so the *result* is bounded too.
    pub fn iter_log(&mut self, namespace: Namespace) -> Result<Vec<(u64, Vec<u8>)>> {
        // Enforce the persisted kind, like `read_log` and the paged APIs do.
        // Without it this alone reached the raw KV listing, and any 8-byte KV
        // value was taken for a batch-slot pointer — so asking a KV namespace
        // for its "log entries" chased whatever those bytes happened to
        // address instead of answering `WrongNamespaceKind` (audit HV-08).
        if self.find_log_root_slot(namespace)?.is_none() {
            return Ok(Vec::new());
        }
        let entries = self.list(namespace)?;
        self.decode_log_entries(entries)
    }

    /// Paginate forward through a log namespace.
    ///
    /// Returns up to `limit` entries with `log_id > after`, in ascending
    /// log_id order. Pass `after = None` to start from the very first
    /// entry; pass `after = Some(last_seen_log_id)` to fetch the next
    /// page.
    ///
    /// Cost: walks B+ tree leaves left-to-right, stopping after `limit`
    /// matching entries. Memory bound: at most `limit` decoded entries
    /// plus the batch cache, which is capped at
    /// [`log::MAX_CACHED_BATCH_BYTES`] / [`log::MAX_CACHED_BATCHES`] no
    /// matter how many distinct batches the page spans. Independent of
    /// total namespace size.
    ///
    /// This is the messenger-pagination primitive: oldest-first feed
    /// scrolling, "load more" buttons, export streams.
    pub fn iter_log_after(
        &mut self,
        namespace: Namespace,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let root_slot = match self.find_log_root_slot(namespace)? {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };
        // Cap allocation at a reasonable upper bound — callers can pass
        // `usize::MAX` to mean "give me everything", and `Vec::with_capacity`
        // panics on capacity overflow.
        let mut paged: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(limit.min(1024));
        self.collect_leaves_after(root_slot, namespace, after, limit, &mut paged)?;
        self.decode_log_entries(paged)
    }

    /// Paginate reverse through a log namespace (newest-first).
    ///
    /// Returns up to `limit` entries with `log_id < before`, in
    /// descending log_id order. Pass `before = None` to start from the
    /// latest entry; pass `before = Some(oldest_seen_log_id)` to fetch
    /// the next (older) page.
    ///
    /// Cost: walks B+ tree leaves right-to-left, stopping after `limit`
    /// matching entries. Memory bound: at most `limit` decoded entries
    /// plus the capped batch cache (see [`Self::iter_log_after`]).
    /// Independent of total namespace size.
    ///
    /// This is the messenger-pagination primitive for "scroll up to
    /// see older messages" — the canonical chat-UI pattern.
    pub fn iter_log_before(
        &mut self,
        namespace: Namespace,
        before: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let root_slot = match self.find_log_root_slot(namespace)? {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };
        // Cap allocation at a reasonable upper bound — callers can pass
        // `usize::MAX` to mean "give me everything", and `Vec::with_capacity`
        // panics on capacity overflow.
        let mut paged: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(limit.min(1024));
        self.collect_leaves_before(root_slot, namespace, before, limit, &mut paged)?;
        // `paged` is already in descending log_id order — walk right-to-left
        // produces newest-first.
        self.decode_log_entries(paged)
    }

    /// Range query over a log namespace.
    ///
    /// Returns up to `limit` entries with `log_id` in `[start, end)`,
    /// in ascending log_id order. Bounds follow the standard half-open
    /// convention: `start` is inclusive, `end` is exclusive. `None` on
    /// either side means "unbounded on this side".
    ///
    /// - `iter_log_range(_, None,    None,    limit)` → first `limit`
    ///   entries (equivalent to `iter_log_after(_, None, limit)`).
    /// - `iter_log_range(_, Some(a), None,    limit)` → up to `limit`
    ///   entries with `log_id >= a`.
    /// - `iter_log_range(_, None,    Some(b), limit)` → up to `limit`
    ///   entries with `log_id < b` (oldest-first).
    /// - `iter_log_range(_, Some(a), Some(b), limit)` → up to `limit`
    ///   entries in `[a, b)`. If `a >= b`, returns empty.
    ///
    /// Cost: walks B+ tree leaves left-to-right, short-circuiting as
    /// soon as either `limit` is reached or an entry `>= end` is
    /// observed. Memory bound: O(limit) decoded entries plus the capped
    /// batch cache (see [`Self::iter_log_after`]). Walk does not visit
    /// subtrees rooted to the right of `end`.
    ///
    /// This is the messenger primitive for "give me messages in a
    /// time window" — pair it with `log_id`s that encode wallclock
    /// time (e.g. unix-ms in the high bits, sequence in the low) and
    /// you get cheap date-range chat queries.
    pub fn iter_log_range(
        &mut self,
        namespace: Namespace,
        start: Option<u64>,
        end: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        if let (Some(s), Some(e)) = (start, end)
            && s >= e
        {
            return Ok(Vec::new());
        }
        let root_slot = match self.find_log_root_slot(namespace)? {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };
        let mut paged: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(limit.min(1024));
        self.collect_leaves_in_range(root_slot, namespace, start, end, limit, &mut paged)?;
        self.decode_log_entries(paged)
    }

    /// Shared decoder for log KV-pair pages: turns `(log_id_key,
    /// batch_slot_value)` pairs into `(log_id, payload)` entries.
    ///
    /// A batch is decoded once per run of entries that point at it, via
    /// a [`BatchCache`] bounded in both bytes and entries. The cache is
    /// an optimization only: an eviction costs a re-read plus a
    /// re-decode and cannot change what this returns.
    /// The result is handed over as ordinary `Vec<u8>` — the caller owns what
    /// it asked for. Everything BEFORE that boundary is scrubbed: the cache,
    /// the per-batch decode, and the partial result a failure abandons partway
    /// through (report17 HV17-M5).
    fn decode_log_entries(
        &mut self,
        kv_pairs: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut batch_cache = BatchCache::new(log::MAX_CACHED_BATCHES, log::MAX_CACHED_BATCH_BYTES);
        let mut out = Vec::with_capacity(kv_pairs.len());
        for (key, value) in kv_pairs {
            if key.len() != 8 {
                // Not a log namespace — its KV keys aren't fixed-8.
                // Distinct from `Malformed`: see Error::WrongNamespaceKind.
                return Err(Error::WrongNamespaceKind(
                    "log key not 8 bytes (namespace is not a log)",
                ));
            }
            let mut id_buf = [0u8; 8];
            id_buf.copy_from_slice(&key);
            let log_id = u64::from_be_bytes(id_buf);
            let payload = self.log_payload_from_reference(log_id, &value, &mut batch_cache)?;
            out.push((log_id, payload));
        }
        // Handed over only here. Until this point `out` is a vector of
        // self-scrubbing payloads, so an error raised partway through — a
        // later batch that fails to decode, a log_id its batch does not hold —
        // takes the records already collected down with it rather than
        // dropping them in the clear.
        Ok(out
            .into_iter()
            .map(|(id, mut payload)| (id, std::mem::take(&mut *payload)))
            .collect())
    }

    fn log_payload_from_reference(
        &mut self,
        log_id: u64,
        value: &[u8],
        batch_cache: &mut BatchCache,
    ) -> Result<log::LogPayload> {
        let batch_slot = log::parse_batch_slot_value(value)?;

        // The outer Option is "was the batch
        // resident", the inner is "did it hold this id". Collapsing
        // them would send a cached-but-id-absent entry down the
        // decode path instead of straight to the error.
        let hit = if let Some((batch, hash)) = batch_cache.get(batch_slot) {
            // A cached payload does not authorize a different reference's
            // commitment, including after a legacy unhashed reference.
            verify_batch_reference(value, &hash)?;
            Some(log::find_in_batch(batch, log_id).cloned())
        } else {
            None
        };
        let payload = match hit {
            Some(found) => found,
            None => {
                let pt = self.read_owned_chunk(batch_slot)?;
                if pt.kind != ChunkKind::DataBatch {
                    // Pointed slot exists but isn't DataBatch —
                    // namespace is not a log.
                    return Err(Error::WrongNamespaceKind(
                        "log pointer not a DataBatch chunk (namespace is not a log)",
                    ));
                }
                // Retain the actual digest for subsequent references even
                // when this first reference uses the unhashed v1 layout.
                let hash = *blake3::hash(&pt.payload).as_bytes();
                verify_batch_reference(value, &hash)?;
                let records = log::decode_batch(&pt.payload)?;
                let found = log::find_in_batch(&records, log_id).cloned();
                batch_cache.insert(batch_slot, records, hash);
                found
            },
        };
        let payload = payload.ok_or(Error::Malformed("log_id not found in pointed batch"))?;
        Ok(payload)
    }

    /// Resolve the root slot for a log namespace, enforcing that the
    /// namespace's persisted [`crate::tx::NamespaceKind`] is `Log`
    /// (audit pass 20 R-NSKIND parity). Returns `Ok(None)` for a
    /// never-written / fully-erased namespace (same as
    /// [`Space::find_root_slot`]); returns `Err(WrongNamespaceKind)`
    /// when the namespace exists but is a KV namespace — caught here,
    /// before any leaf walk, instead of via the downstream 8-byte-key
    /// / DataBatch-pointer shape heuristic.
    fn find_log_root_slot(&mut self, namespace: Namespace) -> Result<Option<u64>> {
        match self.find_root(namespace)? {
            None => Ok(None),
            Some(root) if root.kind != crate::tx::NamespaceKind::Log => Err(
                Error::WrongNamespaceKind("namespace is a KV namespace, not a log"),
            ),
            Some(root) => Ok(Some(root.index_slot)),
        }
    }

    /// Read a log entry by `log_id` from a namespace whose entries
    /// were written via [`crate::tx::Tx::append_log`]. Returns
    /// `Ok(None)` only if the id was never appended (KV index does
    /// not reference it). If the KV index points at a batch but the
    /// batch decodes without the id, returns `Err(Malformed)` —
    /// that is a structural inconsistency, not a "missing entry"
    /// (audit pass 7 L3 alignment with `iter_log_*`).
    ///
    /// Cost: one KV lookup (O(log N) tree walk) plus one chunk read +
    /// zstd decompress for the containing batch.
    pub fn read_log(&mut self, namespace: Namespace, log_id: u64) -> Result<Option<Vec<u8>>> {
        // Enforce the namespace's persisted kind up front (audit pass
        // 20 R-NSKIND parity): a KV namespace is rejected with
        // `WrongNamespaceKind` regardless of whether its values happen
        // to look like batch-slot pointers, instead of relying on the
        // downstream DataBatch-kind heuristic.
        match self.find_root(namespace)? {
            None => return Ok(None),
            Some(root) if root.kind != crate::tx::NamespaceKind::Log => {
                return Err(Error::WrongNamespaceKind(
                    "namespace is a KV namespace, not a log",
                ));
            },
            Some(_) => {},
        }
        let key = log::log_id_key(log_id);
        let value_bytes = match self.get(namespace, &key)? {
            Some(v) => v,
            None => return Ok(None),
        };
        let batch_slot = log::parse_batch_slot_value(&value_bytes)?;
        let pt = self.read_owned_chunk(batch_slot)?;
        if pt.kind != ChunkKind::DataBatch {
            // Namespace is not a log — `read_log` was the wrong API.
            return Err(Error::WrongNamespaceKind(
                "log pointer not a DataBatch chunk (namespace is not a log)",
            ));
        }
        if log::parse_batch_content_hash(&value_bytes).is_some() {
            verify_batch_reference(&value_bytes, blake3::hash(&pt.payload).as_bytes())?;
        }
        let records = log::decode_batch(&pt.payload)?;
        // Audit pass 7 (L3): align `read_log` with `iter_log_*`.
        // The KV pointer says "this batch contains log_id X" — if
        // the batch decodes but doesn't contain X, that's a
        // structural inconsistency (writer-bug regression or AEAD-
        // passed-but-corrupt batch), not a "missing entry".
        // Surfacing as `Ok(None)` was misleading. Both APIs now
        // return `Err(Malformed)` for this case.
        match log::find_in_batch(&records, log_id) {
            Some(p) => Ok(Some(p.to_vec())),
            None => Err(Error::Malformed("log_id not found in pointed batch")),
        }
    }

    /// Walk leaves left-to-right (ascending key order), pushing entries
    /// with `log_id > after` (or all entries if `after` is `None`) into
    /// `out`. Stops as soon as `out.len() >= limit`. Audit pass 17 D:
    /// non-8-byte keys (i.e. caller passed a KV namespace by mistake,
    /// or writer-bug regression) now surface as
    /// [`Error::WrongNamespaceKind`] rather than being silently
    /// skipped — this matches the strict behavior of
    /// [`Space::iter_log`] and avoids hiding namespace-kind violations
    /// behind a quiet truncation.
    fn collect_leaves_after(
        &mut self,
        slot: u64,
        namespace: Namespace,
        after: Option<u64>,
        limit: usize,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        let mut walk = self.new_tree_walk();
        self.collect_leaves_after_at(slot, namespace, after, limit, 0, &mut walk, out)
    }

    // `limit` bounds `out`, not the number of chunks read, so the
    // traversal guard is what bounds this walk on adversarial input —
    // see [`super::walk`]. On honest input `after` prunes it: audit
    // HV-05 taught the internal branch to seek to the cursor's subtree
    // rather than descend from child 0 and filter in the leaf.
    #[allow(clippy::too_many_arguments)]
    fn collect_leaves_after_at(
        &mut self,
        slot: u64,
        namespace: Namespace,
        after: Option<u64>,
        limit: usize,
        depth: u8,
        walk: &mut TreeWalk,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        if out.len() >= limit {
            return Ok(());
        }
        walk.admit(slot, depth)?;
        let node = self.read_index_node_at_expected(slot, namespace)?;
        match node {
            IndexNode::Leaf(l) => {
                for (k, v) in l.entries.into_inner() {
                    if out.len() >= limit {
                        break;
                    }
                    let bytes: [u8; 8] = k.as_slice().try_into().map_err(|_| {
                        Error::WrongNamespaceKind(
                            "log walker: non-8-byte key (KV namespace passed to log API?)",
                        )
                    })?;
                    let log_id = u64::from_be_bytes(bytes);
                    if let Some(after_id) = after
                        && log_id <= after_id
                    {
                        continue;
                    }
                    out.push((k, v));
                }
                Ok(())
            },
            IndexNode::Internal(i) => {
                // Seek to the cursor (audit HV-05). Log keys are the
                // 8-byte big-endian `log_id`, so byte order IS numeric
                // order and the same `first_key` bound the KV walker
                // uses applies here: siblings before
                // `child_index_for(after)` end at a `log_id` below the
                // cursor and contribute nothing.
                let after_key = after.map(log::log_id_key);
                let first = after_key.map_or(0, |k| i.child_index_for(&k));
                for c in i.children.into_iter().skip(first) {
                    if out.len() >= limit {
                        break;
                    }
                    self.collect_leaves_after_at(
                        c.child_slot,
                        namespace,
                        after,
                        limit,
                        depth + 1,
                        walk,
                        out,
                    )?;
                }
                Ok(())
            },
        }
    }

    /// Walk leaves right-to-left (descending key order), pushing entries
    /// with `log_id < before` (or all entries if `before` is `None`)
    /// into `out`. Stops as soon as `out.len() >= limit`. Audit pass 17
    /// D: non-8-byte keys surface as [`Error::WrongNamespaceKind`]
    /// (see [`Self::collect_leaves_after`] for rationale).
    fn collect_leaves_before(
        &mut self,
        slot: u64,
        namespace: Namespace,
        before: Option<u64>,
        limit: usize,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        let mut walk = self.new_tree_walk();
        self.collect_leaves_before_at(slot, namespace, before, limit, 0, &mut walk, out)
    }

    // Guarded for the same reason as [`Self::collect_leaves_after_at`]:
    // `limit` bounds the output, not the chunk reads. And pruned the
    // mirror-image way (audit HV-05) — this one walks down from
    // `before`, so it is the siblings AFTER the cursor's child that
    // cannot contribute.
    #[allow(clippy::too_many_arguments)]
    fn collect_leaves_before_at(
        &mut self,
        slot: u64,
        namespace: Namespace,
        before: Option<u64>,
        limit: usize,
        depth: u8,
        walk: &mut TreeWalk,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        if out.len() >= limit {
            return Ok(());
        }
        walk.admit(slot, depth)?;
        let node = self.read_index_node_at_expected(slot, namespace)?;
        match node {
            IndexNode::Leaf(l) => {
                for (k, v) in l.entries.into_inner().into_iter().rev() {
                    if out.len() >= limit {
                        break;
                    }
                    let bytes: [u8; 8] = k.as_slice().try_into().map_err(|_| {
                        Error::WrongNamespaceKind(
                            "log walker: non-8-byte key (KV namespace passed to log API?)",
                        )
                    })?;
                    let log_id = u64::from_be_bytes(bytes);
                    if let Some(before_id) = before
                        && log_id >= before_id
                    {
                        continue;
                    }
                    out.push((k, v));
                }
                Ok(())
            },
            IndexNode::Internal(i) => {
                // Descending twin of the `after` seek. Siblings past
                // `child_index_for(before)` start at a `log_id` at or
                // above the cursor, so nothing in them satisfies
                // `log_id < before`; `take(last + 1)` drops them before
                // the reverse iteration begins.
                let before_key = before.map(log::log_id_key);
                let last = before_key.map_or(i.children.len().saturating_sub(1), |k| {
                    i.child_index_for(&k)
                });
                for c in i.children.into_iter().take(last + 1).rev() {
                    if out.len() >= limit {
                        break;
                    }
                    self.collect_leaves_before_at(
                        c.child_slot,
                        namespace,
                        before,
                        limit,
                        depth + 1,
                        walk,
                        out,
                    )?;
                }
                Ok(())
            },
        }
    }

    /// Walk leaves left-to-right with both lower and upper bounds.
    /// Pushes entries whose `log_id` falls in `[start, end)` into
    /// `out`. Returns `true` if the walk should terminate (limit
    /// reached OR an entry past `end` was observed — leaves are
    /// sorted ascending, so no later sibling can satisfy the upper
    /// bound). Audit pass 17 D: non-8-byte keys surface as
    /// [`Error::WrongNamespaceKind`] (see
    /// [`Self::collect_leaves_after`] for rationale).
    fn collect_leaves_in_range(
        &mut self,
        slot: u64,
        namespace: Namespace,
        start: Option<u64>,
        end: Option<u64>,
        limit: usize,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<bool> {
        let mut walk = self.new_tree_walk();
        self.collect_leaves_in_range_at(slot, namespace, start, end, limit, 0, &mut walk, out)
    }

    // Recursive walker with namespace-aware namespace cross-check
    // (audit pass 19 round 6). Over clippy's default parameter cap;
    // bundling into a state struct would just shift the boilerplate to
    // construction. The walker stays linear and readable as-is.
    #[allow(clippy::too_many_arguments)]
    fn collect_leaves_in_range_at(
        &mut self,
        slot: u64,
        namespace: Namespace,
        start: Option<u64>,
        end: Option<u64>,
        limit: usize,
        depth: u8,
        walk: &mut TreeWalk,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<bool> {
        if out.len() >= limit {
            return Ok(true);
        }
        walk.admit(slot, depth)?;
        let node = self.read_index_node_at_expected(slot, namespace)?;
        match node {
            IndexNode::Leaf(l) => {
                for (k, v) in l.entries.into_inner() {
                    if out.len() >= limit {
                        return Ok(true);
                    }
                    let bytes: [u8; 8] = k.as_slice().try_into().map_err(|_| {
                        Error::WrongNamespaceKind(
                            "log walker: non-8-byte key (KV namespace passed to log API?)",
                        )
                    })?;
                    let log_id = u64::from_be_bytes(bytes);
                    if let Some(s) = start
                        && log_id < s
                    {
                        continue;
                    }
                    if let Some(e) = end
                        && log_id >= e
                    {
                        return Ok(true);
                    }
                    out.push((k, v));
                }
                Ok(out.len() >= limit)
            },
            IndexNode::Internal(i) => {
                // The upper bound already stops this walk early (the
                // leaf branch returns `true` on the first entry at or
                // past `end`). The LOWER bound did nothing until audit
                // HV-05 — and it is the one the app moves, one page per
                // scrollback step, so every page re-read the whole
                // history below `start`. Same seek as the `after`
                // walker.
                let start_key = start.map(log::log_id_key);
                let first = start_key.map_or(0, |k| i.child_index_for(&k));
                for c in i.children.into_iter().skip(first) {
                    let stop = self.collect_leaves_in_range_at(
                        c.child_slot,
                        namespace,
                        start,
                        end,
                        limit,
                        depth + 1,
                        walk,
                        out,
                    )?;
                    if stop {
                        return Ok(true);
                    }
                }
                Ok(false)
            },
        }
    }
}

#[cfg(test)]
mod batch_cache_tests {
    use super::*;

    #[test]
    fn the_digest_is_retained_and_charged_even_for_an_empty_batch() {
        let mut cache = BatchCache::new(8, 32);
        cache.insert(1, Vec::new(), [1; 32]);
        assert_eq!(cache.bytes, 32);
        cache.insert(2, Vec::new(), [2; 32]);
        assert_eq!(cache.bytes, 32);
        assert!(cache.get(1).is_none());
        let (records, hash) = cache.get(2).unwrap();
        assert!(records.is_empty());
        assert_eq!(hash, [2; 32]);
    }

    /// `n` records of `payload_len` bytes each, ids `0..n`.
    fn records(n: usize, payload_len: usize) -> DecodedBatch {
        (0..n)
            .map(|i| (i as u64, zeroize::Zeroizing::new(vec![0xAB; payload_len])))
            .collect()
    }

    /// The bound the finding was about: no matter how many distinct
    /// batches a page names, resident bytes stay under the budget.
    #[test]
    fn resident_bytes_never_exceed_the_budget() {
        let budget = 64 * 1024;
        let mut c = BatchCache::new(1024, budget);
        for slot in 0..200u64 {
            c.insert(slot, records(4, 1024), [0; 32]);
            assert!(
                c.bytes <= budget,
                "slot {slot}: {} bytes resident, budget {budget}",
                c.bytes
            );
        }
        assert!(c.entries.len() < 200, "nothing was evicted");
    }

    /// The entry cap is the other half: empty batches cost almost no
    /// bytes, so without it a page of them would grow the map without
    /// limit and make eviction itself the expensive part.
    #[test]
    fn the_entry_cap_bounds_batches_that_weigh_nothing() {
        let mut c = BatchCache::new(8, 1024 * 1024);
        for slot in 0..100u64 {
            c.insert(slot, Vec::new(), [0; 32]);
        }
        assert_eq!(c.entries.len(), 8);
    }

    /// A batch too large for the entire budget is not cached — it must
    /// not evict every resident entry to admit a single-use one.
    #[test]
    fn an_oversized_batch_is_not_admitted() {
        let mut c = BatchCache::new(16, 8 * 1024);
        c.insert(1, records(1, 512), [0; 32]);
        let resident_before = c.entries.len();
        c.insert(2, records(1, 64 * 1024), [0; 32]);
        assert_eq!(c.entries.len(), resident_before, "the small entry survived");
        assert!(c.get(2).is_none(), "the oversized batch was not cached");
        assert!(c.get(1).is_some());
    }

    /// Eviction is by least-recent *use*, not by insertion order: a
    /// batch that keeps being read must outlive one that was inserted
    /// later and never touched again.
    #[test]
    fn eviction_drops_the_least_recently_used_entry() {
        // Three entries fit; the fourth forces exactly one eviction.
        let one = log::batch_footprint(&records(1, 1000));
        let mut c = BatchCache::new(16, one * 3 + one / 2);

        c.insert(1, records(1, 1000), [0; 32]);
        c.insert(2, records(1, 1000), [0; 32]);
        c.insert(3, records(1, 1000), [0; 32]);
        // Touch 1 and 3, leaving 2 as the least recently used.
        assert!(c.get(1).is_some());
        assert!(c.get(3).is_some());

        c.insert(4, records(1, 1000), [0; 32]);
        assert!(c.get(2).is_none(), "the least recently used should go");
        assert!(c.get(1).is_some());
        assert!(c.get(3).is_some());
        assert!(c.get(4).is_some());
    }

    /// Re-admitting a slot already resident must not count its bytes
    /// twice — otherwise the accounting drifts up and the cache evicts
    /// itself down to nothing.
    #[test]
    fn re_inserting_a_resident_slot_does_not_double_count() {
        let mut c = BatchCache::new(16, 1024 * 1024);
        c.insert(7, records(2, 500), [0; 32]);
        let after_first = c.bytes;
        c.insert(7, records(2, 500), [0; 32]);
        assert_eq!(c.bytes, after_first);
        assert_eq!(c.entries.len(), 1);
    }
}

#[cfg(test)]
mod exact_group_read_tests {
    use super::super::CHUNK_READS;
    use super::*;
    use crate::{Container, crypto::kdf::Argon2Params};

    fn counted<T>(body: impl FnOnce() -> T) -> (u64, T) {
        CHUNK_READS.with(|count| count.set(0));
        let result = body();
        (CHUNK_READS.with(|count| count.get()), result)
    }

    #[test]
    fn exact_groups_share_actual_batch_chunk_reads() {
        let directory = tempfile::tempdir().unwrap();
        let mut container =
            Container::create(directory.path().join("cost.hv"), Argon2Params::MIN).unwrap();
        let mut space = container.create_space(b"pw").unwrap();
        let ns = Namespace::MESSAGE_LOG;
        let mut tx = space.begin_tx();
        for id in 0..32 {
            tx.append_log(ns, id, &[id as u8; 128]).unwrap();
        }
        tx.commit().unwrap();
        let ids: Vec<_> = (0..32).collect();
        // Warm the index before either counter; a one-read cache warmup is not batch reuse.
        space.read_log(ns, 0).unwrap().unwrap();
        let (scalar_reads, expected) = counted(|| {
            ids.iter()
                .flat_map(|&id| space.read_log(ns, id).unwrap().unwrap())
                .collect::<Vec<_>>()
        });
        let groups = [
            log::LogReadGroup {
                log_ids: &ids[..16],
                max_bytes: 2048,
            },
            log::LogReadGroup {
                log_ids: &ids[16..],
                max_bytes: 2048,
            },
        ];
        let (group_reads, actual) =
            counted(|| space.read_log_groups(ns, &groups).unwrap().unwrap());
        assert_eq!(actual.concat(), expected);
        assert!(
            scalar_reads.saturating_sub(group_reads) >= 31,
            "grouped {group_reads}, scalar {scalar_reads}: the 32-record shared batch must save at least 31 chunk reads"
        );
    }

    #[test]
    fn exact_group_reads_share_index_nodes() {
        let directory = tempfile::tempdir().unwrap();
        let mut container =
            Container::create(directory.path().join("index-cost.hv"), Argon2Params::MIN).unwrap();
        let mut space = container.create_space(b"pw").unwrap();
        let ns = Namespace::MESSAGE_LOG;
        let mut tx = space.begin_tx();
        for id in 0..32 {
            tx.append_log(ns, id, &[id as u8; 128]).unwrap();
        }
        tx.commit().unwrap();
        // One leaf and one compressed DataBatch, with the commit-root cache warm.
        let root = space.find_root_slot(ns).unwrap().unwrap();
        assert!(matches!(
            space.read_index_node_at_expected(root, ns).unwrap(),
            IndexNode::Leaf(_)
        ));
        space.read_log(ns, 0).unwrap().unwrap();
        let ids: Vec<_> = (0..32).collect();
        let groups = [
            log::LogReadGroup {
                log_ids: &ids[..16],
                max_bytes: 2048,
            },
            log::LogReadGroup {
                log_ids: &ids[16..],
                max_bytes: 2048,
            },
        ];
        let (reads, actual) = counted(|| space.read_log_groups(ns, &groups).unwrap().unwrap());
        assert_eq!(
            actual.concat(),
            (0..32).flat_map(|id| [id as u8; 128]).collect::<Vec<_>>()
        );
        assert_eq!(
            reads, 2,
            "one fresh leaf and one batch must serve all exact IDs; got {reads} chunk reads"
        );
    }

    #[test]
    fn exact_groups_keep_order_duplicates_bounds_and_freshness() {
        let directory = tempfile::tempdir().unwrap();
        let mut container =
            Container::create(directory.path().join("groups.hv"), Argon2Params::MIN).unwrap();
        let mut space = container.create_space(b"pw").unwrap();
        let ns = Namespace::MESSAGE_LOG;
        let mut tx = space.begin_tx();
        tx.append_log(ns, 1, b"a").unwrap();
        tx.append_log(ns, 2, b"bc").unwrap();
        tx.commit().unwrap();
        let groups = [
            log::LogReadGroup {
                log_ids: &[2, 1, 2],
                max_bytes: 5,
            },
            log::LogReadGroup {
                log_ids: &[],
                max_bytes: 0,
            },
        ];
        assert_eq!(
            space.read_log_groups(ns, &groups).unwrap(),
            Some(vec![b"bcabc".to_vec(), vec![]])
        );
        assert!(
            space
                .read_log_groups(
                    ns,
                    &[log::LogReadGroup {
                        log_ids: &[2, 1],
                        max_bytes: 2
                    }]
                )
                .unwrap()
                .is_none()
        );
        assert!(
            space
                .read_log_groups(
                    ns,
                    &[log::LogReadGroup {
                        log_ids: &[2, 99],
                        max_bytes: 5
                    }]
                )
                .unwrap()
                .is_none()
        );
        let mut tx = space.begin_tx();
        tx.delete_log(ns, 2).unwrap();
        tx.commit().unwrap();
        assert!(space.read_log_groups(ns, &groups).unwrap().is_none());
        let mut tx = space.begin_tx();
        tx.append_log(ns, 2, b"de").unwrap();
        tx.commit().unwrap();
        assert_eq!(
            space.read_log_groups(ns, &groups).unwrap().unwrap()[0],
            b"deade"
        );
        let (reads, result) = counted(|| {
            space.read_log_groups(
                ns,
                &vec![
                    log::LogReadGroup {
                        log_ids: &[],
                        max_bytes: 0
                    };
                    9
                ],
            )
        });
        assert!(result.is_err());
        assert_eq!(reads, 0);
        // A valid huge caller ceiling must not become an allocation size.
        let bounded = space
            .read_log_groups(
                ns,
                &[log::LogReadGroup {
                    log_ids: &[1; 64],
                    max_bytes: usize::MAX,
                }],
            )
            .unwrap()
            .unwrap();
        assert_eq!(bounded[0], b"a".repeat(64));
        let kv = Namespace(44);
        let mut tx = space.begin_tx();
        tx.put(kv, b"key", b"value").unwrap();
        tx.commit().unwrap();
        assert!(matches!(
            space.read_log_groups(
                kv,
                &[log::LogReadGroup {
                    log_ids: &[1],
                    max_bytes: 8
                }]
            ),
            Err(Error::WrongNamespaceKind(_))
        ));
        assert_eq!(space.read_log_groups(kv, &[]).unwrap(), Some(vec![]));
        let ids = [1; 65];
        let (reads, result) = counted(|| {
            space.read_log_groups(
                ns,
                &[log::LogReadGroup {
                    log_ids: &ids,
                    max_bytes: usize::MAX,
                }],
            )
        });
        assert!(result.is_err());
        assert_eq!(reads, 0);
    }
}
