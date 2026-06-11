//! Log-style namespace iteration: `iter_log_*`, `read_log`, and
//! their leaf-walk helpers. Audit pass 8 (E7) split out of
//! `space/mod.rs` so log-pagination logic is reviewable as a
//! self-contained ~340-LOC chunk.

use crate::chunk::ChunkKind;
use crate::{Error, Result};

use super::Space;
use super::index::{self, IndexNode, Namespace};
use super::log;

impl<'f> Space<'f> {
    /// Enumerate all log entries in `namespace`, in ascending log_id
    /// order. Each entry's containing DataBatch chunk is read at most
    /// once (cached during iteration).
    ///
    /// Cost: O(K) chunk reads where K is the number of distinct batches
    /// referenced by the namespace's index, plus one zstd decompress
    /// per batch. Memory: holds all decoded batches simultaneously
    /// during the call.
    ///
    /// **For large namespaces use [`Self::iter_log_after`] /
    /// [`Self::iter_log_before`] instead** — those page bounded counts
    /// and bound memory by O(limit) decoded entries plus a few touched
    /// batches.
    pub fn iter_log(&mut self, namespace: Namespace) -> Result<Vec<(u64, Vec<u8>)>> {
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
    /// plus the few touched DataBatch chunks (cached during the call,
    /// dropped after return). Independent of total namespace size.
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
    /// plus the few touched DataBatch chunks. Independent of total
    /// namespace size.
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
    /// observed. Memory bound: O(limit) decoded entries plus the
    /// touched `DataBatch` chunks (cached during the call). Walk does
    /// not visit subtrees rooted to the right of `end`.
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
    /// Touches each DataBatch chunk at most once via a per-call cache.
    fn decode_log_entries(
        &mut self,
        kv_pairs: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut batch_cache: std::collections::HashMap<u64, Vec<(u64, Vec<u8>)>> =
            std::collections::HashMap::new();
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

            let batch = match batch_cache.entry(batch_slot) {
                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::hash_map::Entry::Vacant(e) => {
                    let pt = self.read_owned_chunk(batch_slot)?;
                    if pt.kind != ChunkKind::DataBatch {
                        // Pointed slot exists but isn't DataBatch —
                        // namespace is not a log.
                        return Err(Error::WrongNamespaceKind(
                            "log pointer not a DataBatch chunk (namespace is not a log)",
                        ));
                    }
                    let records = log::decode_batch(&pt.payload)?;
                    e.insert(records)
                },
            };
            let payload = log::find_in_batch(batch, log_id)
                .cloned()
                .ok_or(Error::Malformed("log_id not found in pointed batch"))?;
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
        self.collect_leaves_after_at(slot, namespace, after, limit, 0, out)
    }

    fn collect_leaves_after_at(
        &mut self,
        slot: u64,
        namespace: Namespace,
        after: Option<u64>,
        limit: usize,
        depth: u8,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        if depth > index::MAX_TREE_DEPTH {
            return Err(Error::Malformed("tree depth exceeded MAX_TREE_DEPTH"));
        }
        if out.len() >= limit {
            return Ok(());
        }
        let node = self.read_index_node_at_expected(slot, namespace)?;
        match node {
            IndexNode::Leaf(l) => {
                for (k, v) in l.entries {
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
                for c in i.children {
                    if out.len() >= limit {
                        break;
                    }
                    self.collect_leaves_after_at(
                        c.child_slot,
                        namespace,
                        after,
                        limit,
                        depth + 1,
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
        self.collect_leaves_before_at(slot, namespace, before, limit, 0, out)
    }

    fn collect_leaves_before_at(
        &mut self,
        slot: u64,
        namespace: Namespace,
        before: Option<u64>,
        limit: usize,
        depth: u8,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        if depth > index::MAX_TREE_DEPTH {
            return Err(Error::Malformed("tree depth exceeded MAX_TREE_DEPTH"));
        }
        if out.len() >= limit {
            return Ok(());
        }
        let node = self.read_index_node_at_expected(slot, namespace)?;
        match node {
            IndexNode::Leaf(l) => {
                for (k, v) in l.entries.into_iter().rev() {
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
                for c in i.children.into_iter().rev() {
                    if out.len() >= limit {
                        break;
                    }
                    self.collect_leaves_before_at(
                        c.child_slot,
                        namespace,
                        before,
                        limit,
                        depth + 1,
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
        self.collect_leaves_in_range_at(slot, namespace, start, end, limit, 0, out)
    }

    // Recursive walker with namespace-aware namespace cross-check
    // (audit pass 19 round 6). Eight parameters is one over clippy's
    // default cap; bundling into a state struct would just shift the
    // boilerplate to construction. The walker stays linear and
    // readable as-is.
    #[allow(clippy::too_many_arguments)]
    fn collect_leaves_in_range_at(
        &mut self,
        slot: u64,
        namespace: Namespace,
        start: Option<u64>,
        end: Option<u64>,
        limit: usize,
        depth: u8,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<bool> {
        if depth > index::MAX_TREE_DEPTH {
            return Err(Error::Malformed("tree depth exceeded MAX_TREE_DEPTH"));
        }
        if out.len() >= limit {
            return Ok(true);
        }
        let node = self.read_index_node_at_expected(slot, namespace)?;
        match node {
            IndexNode::Leaf(l) => {
                for (k, v) in l.entries {
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
                for c in i.children {
                    let stop = self.collect_leaves_in_range_at(
                        c.child_slot,
                        namespace,
                        start,
                        end,
                        limit,
                        depth + 1,
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
