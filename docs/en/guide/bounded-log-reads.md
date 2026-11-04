# Bounded exact-ID log reads

`Space::read_log_groups`, the sync/async single-space and
explicit multi-space FFI methods, and Dart sync/async facades read exact record ids without scanning
an id range. Each group concatenates payloads in caller order, including
duplicates, under its own byte ceiling. A call accepts at most eight groups
and 64 requested records in total; an empty group returns empty bytes.

A missing or over-budget record returns `None`/`null` for the whole call before
any subsequent requested record is looked up. Structural/authentication errors
propagate, as in scalar reads. Partial results and decoded batches scrub on
failure or eviction. Results become caller-owned plaintext only on success.

The call shares the existing 64-entry/8-MiB decoded-batch cache between groups.
Every index reference is checked against the actual compressed payload digest,
including cache hits after a legacy unhashed reference. The cache ends with
the call; the next call reads current index/data again. There is no routing,
authorization or persistent data cache. The output is additionally bounded by
64 times the existing maximum record payload length. The existing per-batch
decode cap still applies independently.

This additive API is available on sync/async single-space and explicit
multi-space handles. Async requests own their nested ID lists before dispatch;
space selection remains explicit for multi-space reads. Existing range/scalar
APIs retain their interfaces. Dart bindings and the native library must match: the UniFFI method
checksum gate rejects an old library missing the new method. Rebuild the native
artifact together with the binding update before distributing it. No container
format, cryptographic algorithm or network protocol changes.

Output buffers reserve only the bounded request ceiling up front (at most
64 maximum record payloads in total), avoiding plaintext copies freed by Vec
reallocation before zeroization. Caller byte ceilings do not become unbounded
allocation sizes.

Within the same call, decoded index pages also have a separate LRU cache: at
most 64 nodes and 1 MiB of accounted node storage (including vector capacity
and key/value allocations), plus the entry-bounded hash-table overhead. An
oversized node is read without retaining it; eviction only costs a reread.
Each exact key still starts a fresh guarded descent: cache hits retain cycle,
slot, depth and namespace checks. Decoded pages use the existing redacted
buffers and scrub when the last reference drops. No index page survives the
call or is reused across spaces or commits.
