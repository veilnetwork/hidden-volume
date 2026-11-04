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
