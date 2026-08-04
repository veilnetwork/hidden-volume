//! Log-style namespace iteration: `iter_log_*`, `read_log`, and
//! their leaf-walk helpers. Audit pass 8 (E7) split out of
//! `space/mod.rs` so log-pagination logic is reviewable as a
//! self-contained ~340-LOC chunk.

use crate::chunk::ChunkKind;
use crate::{Error, Result};

use super::Space;
use super::index::{IndexNode, Namespace};
use super::log;
use super::walk::TreeWalk;

/// One decoded log record: `(log_id, payload)`.
type LogRecord = (u64, Vec<u8>);
/// A decoded `DataBatch`'s records, in append order.
type DecodedBatch = Vec<LogRecord>;
/// A resident cache entry: the tick of its last use plus the batch.
type CachedBatch = (u64, DecodedBatch);

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
    /// `batch_slot -> (last-use tick, decoded records)`.
    entries: std::collections::HashMap<u64, CachedBatch>,
    /// Sum of [`log::batch_footprint`] over `entries`.
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
    fn get(&mut self, slot: u64) -> Option<&[LogRecord]> {
        self.tick += 1;
        let tick = self.tick;
        let (last_use, records) = self.entries.get_mut(&slot)?;
        *last_use = tick;
        Some(records.as_slice())
    }

    /// Admit a decoded batch, evicting least-recently-used entries until
    /// it fits. A batch too large for the whole budget is simply not
    /// cached — it was already decoded for this one lookup, and holding
    /// it would evict everything for a single-use entry.
    fn insert(&mut self, slot: u64, records: DecodedBatch) {
        let cost = log::batch_footprint(&records);
        if cost > self.max_bytes || self.max_entries == 0 {
            return;
        }
        // Re-inserting a slot already resident (possible only if a
        // caller decoded it twice) must not double-count its bytes.
        if let Some((_, old)) = self.entries.remove(&slot) {
            self.bytes = self.bytes.saturating_sub(log::batch_footprint(&old));
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
        self.entries.insert(slot, (self.tick, records));
    }

    /// Drop the least-recently-used entry. Returns `false` when there
    /// was nothing left to drop.
    fn evict_one(&mut self) -> bool {
        let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, (last_use, _))| *last_use)
            .map(|(slot, _)| *slot)
        else {
            return false;
        };
        if let Some((_, records)) = self.entries.remove(&oldest) {
            self.bytes = self.bytes.saturating_sub(log::batch_footprint(&records));
        }
        true
    }
}

impl<'f> Space<'f> {
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
            let batch_slot = log::parse_batch_slot_value(&value)?;

            // `map`, not `and_then`: the outer Option is "was the batch
            // resident", the inner is "did it hold this id". Collapsing
            // them would send a cached-but-id-absent entry down the
            // decode path instead of straight to the error.
            let hit = batch_cache
                .get(batch_slot)
                .map(|batch| log::find_in_batch(batch, log_id).cloned());
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
                    let records = log::decode_batch(&pt.payload)?;
                    let found = log::find_in_batch(&records, log_id).cloned();
                    batch_cache.insert(batch_slot, records);
                    found
                },
            };
            let payload = payload.ok_or(Error::Malformed("log_id not found in pointed batch"))?;
            out.push((log_id, payload));
        }
        Ok(out)
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
        let records = log::decode_batch(&pt.payload)?;
        // Audit pass 7 (L3): align `read_log` with `iter_log_*`.
        // The KV pointer says "this batch contains log_id X" — if
        // the batch decodes but doesn't contain X, that's a
        // structural inconsistency (writer-bug regression or AEAD-
        // passed-but-corrupt batch), not a "missing entry".
        // Surfacing as `Ok(None)` was misleading. Both APIs now
        // return `Err(Malformed)` for this case.
        match log::find_in_batch(&records, log_id) {
            Some(p) => Ok(Some(p.clone())),
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

    /// `n` records of `payload_len` bytes each, ids `0..n`.
    fn records(n: usize, payload_len: usize) -> DecodedBatch {
        (0..n)
            .map(|i| (i as u64, vec![0xAB; payload_len]))
            .collect()
    }

    /// The bound the finding was about: no matter how many distinct
    /// batches a page names, resident bytes stay under the budget.
    #[test]
    fn resident_bytes_never_exceed_the_budget() {
        let budget = 64 * 1024;
        let mut c = BatchCache::new(1024, budget);
        for slot in 0..200u64 {
            c.insert(slot, records(4, 1024));
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
            c.insert(slot, Vec::new());
        }
        assert_eq!(c.entries.len(), 8);
    }

    /// A batch too large for the entire budget is not cached — it must
    /// not evict every resident entry to admit a single-use one.
    #[test]
    fn an_oversized_batch_is_not_admitted() {
        let mut c = BatchCache::new(16, 8 * 1024);
        c.insert(1, records(1, 512));
        let resident_before = c.entries.len();
        c.insert(2, records(1, 64 * 1024));
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

        c.insert(1, records(1, 1000));
        c.insert(2, records(1, 1000));
        c.insert(3, records(1, 1000));
        // Touch 1 and 3, leaving 2 as the least recently used.
        assert!(c.get(1).is_some());
        assert!(c.get(3).is_some());

        c.insert(4, records(1, 1000));
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
        c.insert(7, records(2, 500));
        let after_first = c.bytes;
        c.insert(7, records(2, 500));
        assert_eq!(c.bytes, after_first);
        assert_eq!(c.entries.len(), 1);
    }
}
