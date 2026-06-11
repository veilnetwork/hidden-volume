//! DataBatch encoding for the messenger log namespace.
//!
//! ## Why batching
//!
//! For a messenger, the message log dominates by volume — millions of
//! short records. If each message went into its own KV entry, the
//! IndexNode tree would explode and per-message storage overhead would
//! be catastrophic (a 150-byte message in a 4040-byte chunk = ~3.7%
//! utilization). DataBatch packs many records into one zstd-compressed
//! chunk, while the per-namespace KV index stores only an 8-byte slot
//! pointer per record.
//!
//! ## Encoding (inside the AEAD-protected plaintext payload of a `DataBatch` chunk)
//!
//! The plaintext payload is the **zstd-compressed** form of:
//!
//! ```text
//!   num_records  : u32 LE        (≤ MAX_RECORDS_PER_BATCH)
//!   for each record, in append order:
//!     log_id     : u64 LE
//!     payload_len: u32 LE
//!     payload bytes
//! ```
//!
//! The compressed result must fit in `PAYLOAD_CAP` (≈ 4040 bytes).
//! With typical messenger text averaging ~150 bytes per message and
//! zstd level-3 compressing 5-10×, ~100-200 messages fit per batch.
//!
//! ## Index storage
//!
//! For each `(log_id, payload)` written as a log entry, the namespace's
//! KV index gets a regular [`crate::tx::Tx::put`]-style entry:
//!   - `key   = log_id.to_be_bytes()` (8 bytes, big-endian for natural sort order)
//!   - `value = batch_slot.to_le_bytes()` (8 bytes)
//!
//! Read path: KV `get` → 8-byte value → `batch_slot` → read DataBatch
//! chunk → decompress → linear scan for `log_id`.
//!
//! ## Auto-splitting at commit time
//!
//! [`encode_batches_split`] handles the case where the full set of
//! pending log records for a namespace, when zstd-compressed, would
//! exceed [`PAYLOAD_CAP`]. The set is split into 1+ contiguous batches
//! each fitting under the cap. `commit_tx` writes one DataBatch chunk
//! per resulting batch and routes each `log_id`'s KV pointer to the
//! slot of its containing batch. The split is invisible to readers —
//! `read_log` / `iter_log_*` follow KV pointers per-record, never
//! assuming a single underlying batch.

use byteorder::{ByteOrder, LittleEndian};
use zeroize::Zeroizing;

use crate::chunk::format::PAYLOAD_CAP;
use crate::{Error, Result};

/// Maximum log records per batch (sanity bound; usually limited earlier
/// by the compressed payload exceeding `PAYLOAD_CAP`).
pub const MAX_RECORDS_PER_BATCH: usize = 1024;

/// Maximum bytes for a single log entry's payload before compression.
/// Larger payloads should be referenced via media slots.
pub const MAX_LOG_PAYLOAD_LEN: usize = 8 * 1024;

/// Hard cap on the decompressed size of a single `DataBatch` chunk.
/// Audit pass 11 (M5): defense against a zstd compression bomb. The
/// cap is the absolute maximum a legitimate batch can decompress to:
/// `num_records (4)` + `num_records × (id (8) + plen (4) + payload)`
/// = `4 + MAX_RECORDS_PER_BATCH × (12 + MAX_LOG_PAYLOAD_LEN)`
/// = `4 + 1024 × 8204` ≈ 8.4 MiB. A `decode_batch` that streams
/// past this cap returns `Error::Malformed`.
pub const MAX_DECODED_BATCH_LEN: usize = 4 + MAX_RECORDS_PER_BATCH * (12 + MAX_LOG_PAYLOAD_LEN);

/// Maximum size of an in-tx pending log buffer (uncompressed). Soft cap
/// to bail out of obviously-too-large batches before zstd compresses.
const MAX_RAW_BATCH_LEN: usize = 1024 * 1024;

/// zstd compression level. Level 3 is the OWASP/zstd default — fast on
/// weak hardware (~50 MB/s on Cortex-A53), strong ratio for short text.
const ZSTD_LEVEL: i32 = 3;

/// Encode and compress a batch. Returns the bytes that should be the
/// plaintext payload of the `DataBatch` chunk.
///
/// Errors:
/// - [`Error::Malformed`] for too many records or invalid sizes.
/// - [`Error::PayloadTooLarge`] if compressed result exceeds `PAYLOAD_CAP`.
/// - [`Error::Compression`] for zstd internal failure.
pub fn encode_batch(records: &[(u64, Vec<u8>)]) -> Result<Vec<u8>> {
    if records.len() > MAX_RECORDS_PER_BATCH {
        return Err(Error::Malformed("batch exceeds MAX_RECORDS_PER_BATCH"));
    }

    // Pre-size raw buffer.
    let mut raw_size = 4;
    for (_, p) in records {
        raw_size += 8 + 4 + p.len();
        if raw_size > MAX_RAW_BATCH_LEN {
            return Err(Error::PayloadTooLarge);
        }
    }
    // Plaintext concatenation buffer. Held only long enough to feed
    // zstd; the resulting `compressed` bytes are what end up sealed by
    // AEAD. Wrap in `Zeroizing` so the heap region is scrubbed when this
    // buffer drops at end of function — even though the local goes out
    // of scope, freed pages can be re-allocated and inspected.
    let mut raw: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(raw_size));
    raw.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for (id, payload) in records {
        if payload.len() > MAX_LOG_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge);
        }
        raw.extend_from_slice(&id.to_le_bytes());
        raw.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        raw.extend_from_slice(payload);
    }

    let compressed = zstd::encode_all(&raw[..], ZSTD_LEVEL)
        .map_err(|_| Error::Compression("zstd encode failed"))?;
    if compressed.len() > PAYLOAD_CAP {
        return Err(Error::PayloadTooLarge);
    }
    Ok(compressed)
}

/// Auto-splitting variant of [`encode_batch`].
///
/// Returns one or more encoded `DataBatch` payloads, each guaranteed to
/// fit under [`PAYLOAD_CAP`]. The input slice is split into contiguous
/// runs (preserving the caller's append order) such that each run's
/// compressed encoding fits.
///
/// Algorithm: try to encode the whole slice; if it overflows, halve and
/// recurse on each half. Total cost is O(N) zstd calls in the common
/// case where everything fits on the first try, O(N log N) in the
/// pathological "every chunk needs to split to single records" case.
///
/// Each returned tuple is `(log_ids_in_this_batch, encoded_batch_bytes)`
/// — caller routes each `log_id`'s KV pointer to the slot where its
/// containing batch lands. The `log_ids` are returned in order matching
/// `records`.
///
/// Errors:
/// - [`Error::Malformed`] if `records.len() > MAX_RECORDS_PER_BATCH`.
/// - [`Error::PayloadTooLarge`] if a **single record** still overflows
///   `PAYLOAD_CAP` after compression — at that point splitting can't
///   help, the record itself is too big. Practically unreachable for
///   payloads ≤ [`MAX_LOG_PAYLOAD_LEN`] (8 KiB) since zstd headers add
///   at most a few hundred bytes.
/// - [`Error::Compression`] for zstd internal failure.
pub fn encode_batches_split(records: &[(u64, Vec<u8>)]) -> Result<Vec<(Vec<u64>, Vec<u8>)>> {
    if records.is_empty() {
        return Ok(Vec::new());
    }
    if records.len() > MAX_RECORDS_PER_BATCH {
        return Err(Error::Malformed("batch exceeds MAX_RECORDS_PER_BATCH"));
    }
    let mut out = Vec::new();
    encode_batches_split_into(records, &mut out)?;
    Ok(out)
}

fn encode_batches_split_into(
    records: &[(u64, Vec<u8>)],
    out: &mut Vec<(Vec<u64>, Vec<u8>)>,
) -> Result<()> {
    match encode_batch(records) {
        Ok(bytes) => {
            let ids = records.iter().map(|(id, _)| *id).collect();
            out.push((ids, bytes));
            Ok(())
        },
        Err(Error::PayloadTooLarge) => {
            if records.len() == 1 {
                // A single record's compressed form exceeds PAYLOAD_CAP.
                // Splitting can't help — surface the error to the caller.
                return Err(Error::PayloadTooLarge);
            }
            let mid = records.len() / 2;
            encode_batches_split_into(&records[..mid], out)?;
            encode_batches_split_into(&records[mid..], out)?;
            Ok(())
        },
        Err(e) => Err(e),
    }
}

/// Decompress and decode a batch. Returns records in append order.
///
/// **Audit pass 11 (M5).** The decompressed buffer is bounded by
/// [`MAX_DECODED_BATCH_LEN`]; a malicious or buggy writer that
/// produced a compressed-bomb DataBatch chunk would otherwise be
/// able to OOM the decoder via `zstd::decode_all`. The cap is set
/// to `MAX_RECORDS_PER_BATCH × (8 + 4 + MAX_LOG_PAYLOAD_LEN) + 4`
/// (≈ 8.4 MiB), which is the absolute maximum any *legitimate* batch
/// can decompress to.
pub fn decode_batch(compressed: &[u8]) -> Result<Vec<(u64, Vec<u8>)>> {
    // Decompressed plaintext form. Held only as long as we walk the
    // record headers; per-record `payload` slices are copied out to
    // owned `Vec<u8>`s in the result. Wrap the raw buffer in
    // `Zeroizing` so the decompressed plaintext is scrubbed when this
    // local drops at end of function. Streaming decode with a hard
    // cap defends against zstd compression bombs (audit pass 11 M5):
    // a 4 KiB ciphertext that decompresses to GiB of zeros would
    // otherwise OOM the host.
    let raw: Zeroizing<Vec<u8>> = {
        use std::io::Read;
        let mut decoder =
            zstd::Decoder::new(compressed).map_err(|_| Error::Compression("zstd decode failed"))?;
        // `take` enforces the cap at the byte level. We read up to
        // cap+1 so we can distinguish "fits" from "overflowed cap".
        let mut buf = Vec::new();
        let cap = MAX_DECODED_BATCH_LEN as u64;
        let read = std::io::Read::take(&mut decoder, cap + 1)
            .read_to_end(&mut buf)
            .map_err(|_| Error::Compression("zstd decode failed"))?;
        if read as u64 > cap {
            return Err(Error::Malformed("batch decompressed size exceeds cap"));
        }
        Zeroizing::new(buf)
    };
    if raw.len() < 4 {
        return Err(Error::Malformed("batch raw too short"));
    }
    let num = LittleEndian::read_u32(&raw[0..4]) as usize;
    if num > MAX_RECORDS_PER_BATCH {
        return Err(Error::Malformed("batch num_records too large"));
    }
    let mut records = Vec::with_capacity(num);
    let mut off = 4;
    for _ in 0..num {
        if raw.len() < off + 8 + 4 {
            return Err(Error::Malformed("batch truncated at record header"));
        }
        let id = LittleEndian::read_u64(&raw[off..off + 8]);
        off += 8;
        let plen = LittleEndian::read_u32(&raw[off..off + 4]) as usize;
        off += 4;
        if plen > MAX_LOG_PAYLOAD_LEN {
            return Err(Error::Malformed("batch invalid payload length"));
        }
        if raw.len() < off + plen {
            return Err(Error::Malformed("batch truncated at payload"));
        }
        let payload = raw[off..off + plen].to_vec();
        off += plen;
        records.push((id, payload));
    }
    // Audit pass 19 round 2: reject trailing bytes after the last
    // record. The decompressed batch encoding is exact-length;
    // trailing bytes are reachable only by a buggy/malicious writer.
    // Mirrors the canonical-form contracts in `Superblock::decode`,
    // `LeafNode::decode`, `InternalNode::decode`, and
    // `CommitPayload::decode`.
    if off != raw.len() {
        return Err(Error::Malformed(
            "batch decompressed payload trailing bytes after last record",
        ));
    }
    Ok(records)
}

/// Linear search by `log_id` within a decoded batch. Batches are small
/// (≤ MAX_RECORDS_PER_BATCH and typically ~100), so O(N) is fine.
/// If the same log_id appears multiple times in one batch, returns the
/// LAST occurrence (matches the "last write wins" coalesce semantics
/// for repeated `Tx::append_log` calls with the same id).
#[must_use]
pub fn find_in_batch(records: &[(u64, Vec<u8>)], log_id: u64) -> Option<&Vec<u8>> {
    records
        .iter()
        .rev()
        .find(|(id, _)| *id == log_id)
        .map(|(_, p)| p)
}

/// Encode a log_id as a sortable big-endian 8-byte key for KV storage.
#[must_use]
pub fn log_id_key(log_id: u64) -> [u8; 8] {
    log_id.to_be_bytes()
}

/// Decode a KV value into a batch slot pointer.
///
/// Returns [`Error::WrongNamespaceKind`] (not `Malformed`) when the
/// value isn't 8 bytes — this signals "namespace is regular KV, not
/// log" rather than "log namespace is corrupt". `repack` uses the
/// distinction to auto-classify namespaces (audit pass 7, L1).
pub fn parse_batch_slot_value(value: &[u8]) -> Result<u64> {
    if value.len() != 8 {
        return Err(Error::WrongNamespaceKind(
            "log entry value not 8 bytes (namespace is not a log)",
        ));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(value);
    Ok(u64::from_le_bytes(buf))
}

/// Encode a batch slot pointer as a KV value.
#[must_use]
pub fn encode_batch_slot_value(batch_slot: u64) -> [u8; 8] {
    batch_slot.to_le_bytes()
}
