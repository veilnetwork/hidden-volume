# Security policy

🇬🇧 **English** · [🇷🇺 Русский](SECURITY.ru.md)

## Reporting a vulnerability

If you discover a security issue in `hidden-volume`, please report it
**privately** before public disclosure.

We take security seriously because this library underpins
plausible-deniability claims for messenger applications. A vulnerability
in the cryptographic surface or in the deniability logic could result in
real harm to users in adversarial environments.

### How to report

- Open a private GitHub Security Advisory ("Security" tab → "Report a
  vulnerability") if hosted on GitHub.
- Or email the maintainer with a detailed description, reproduction
  steps, and the affected version range.
- PGP-encrypt the report if it contains exploit details. Maintainer's
  PGP key fingerprint will be published once the project is released.

### What to include

- Affected version (commit hash if pre-release).
- Description of the issue and the assumed adversary model.
- Reproduction steps (test case, file, sequence of API calls).
- Suggested mitigation if you have one.

### Response

- We aim to acknowledge reports within 7 days.
- Critical issues (deniability bypass, key recovery, AEAD bypass) get a
  patch + coordinated disclosure within 30 days.
- Lower-severity issues (denial of service, performance, format
  inefficiency) may be folded into the next release cycle.

### Bug bounty (community review, no monetary reward)

Standing offer for security researchers willing to challenge this
project's deniability and cryptographic claims:

- **In scope.** Vulnerabilities that violate D1 (single-snapshot
  indistinguishability), D2 (compelled-key deniability), I1 (per-chunk
  integrity), I2 (tail-corruption tolerance), I3 (cross-space
  isolation), R1 (rollback resistance with anchor), M1 (memory
  hygiene of keys), C1 (cancellation safety). Plus any panic-via-input
  reachable through the public Rust / FFI API, any memory-safety
  issue in the `unsafe` blocks of `hidden-volume-rt`, and any flaw in
  the release-pipeline signing chain.
- **Out of scope.** Anything in the threat-model's "Out-of-scope
  mitigations" §4 (multi-snapshot byte-diff, NFS / FUSE / shared-
  storage Android, CPU-level side channels, host-app data leaks).
  TM1 (open-time timing oracle) is *acknowledged-open* — concrete
  numbers improving on the documented characterization are welcome;
  re-reporting the bare existence is not.
- **Reward.** Credit (CHANGELOG entry + SECURITY.md hall-of-fame
  line) and early access to the fix. **No monetary reward** —
  budget reality. Pseudonymous reporters are explicitly welcome;
  the maintainer is pseudonymous too. Pick whatever handle you want
  in the credit line.
- **Disclosure.** Coordinated, 90-day default, fast-tracked for
  critical findings. A reporter who waits the timeline and then
  posts a public technical write-up effectively becomes an *external
  reviewer* of this project — see [`docs/en/security/audits/self-audit.md`](docs/en/security/audits/self-audit.md)
  §9 for why that path matters here.
- **Channel.** GitHub Private Vulnerability Reporting (preferred —
  end-to-end encrypted to maintainer keys held in the GitHub
  account, no email) or the email path documented above with PGP.
- **No invoicing, no contracts.** This is a community offer, not a
  service agreement. The maintainer cannot pay invoices without
  deanonymizing — see the dossier §1 for the budget/anonymity
  rationale.

### Self-audit dossier

Why no external paid audit, what process substitutes for it, what
cryptographic properties are claimed, and how to independently verify
each claim:
[`docs/en/security/audits/self-audit.md`](docs/en/security/audits/self-audit.md)
(RU: [`docs/ru/security/audits/self-audit.md`](docs/ru/security/audits/self-audit.md)).

## Verifying release artifacts

Every SemVer-tagged release is signed by the workflow at
[`.github/workflows/release.yml`](.github/workflows/release.yml) via
**cosign keyless** (Sigstore). No long-lived signing keys exist; each
release's `SHA256SUMS` file is signed by a short-lived certificate
whose subject is the GitHub-Actions OIDC token of that exact workflow
run, with the signature recorded in the public Rekor transparency log.

Quick verify:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/veilnetwork/hidden-volume/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS

sha256sum --ignore-missing -c SHA256SUMS    # Linux
shasum -a 256 -c SHA256SUMS                 # macOS / BSD
```

Full procedure (what each check proves, what it doesn't, how to react
to a verification failure):
[`docs/en/contributing/verifying-release.md`](docs/en/contributing/verifying-release.md).

## Threat model

For context on what is and isn't in scope, see [`DESIGN.md`](DESIGN.md)
§1 and the README "What this protects" / "What this does NOT protect"
sections. In short:

**In scope** — vulnerabilities that violate any of:
- D1 (single-snapshot indistinguishability)
- D2 (compelled-key plausible deniability)
- I1 (per-chunk integrity)
- I2 (tail-corruption tolerance)
- I3 (cross-space isolation)

**Not in scope** (host-app responsibility):
- Application-layer side channels (recently-opened files, IME caches,
  thumbnails, swap, system logs)
- Multi-snapshot byte-diff analysis (T2'): in-place rewrites and
  tombstones leave "this byte changed" signals; documented as accepted
  trade-off
- Rollback attacks without an external anchor
- CPU-level side channels (Spectre, MDS) — defended by OS/microcode
- Forensic RAM dumps — defended by full-disk encryption + secure boot
- **Container file on shared / external Android storage** (audit M4,
  hardened in v1.0.0 2026-05-28). Pre-v1.0 the Android lock was a
  documented no-op because stable Rust 1.89's `File::try_lock` is
  `Err(Unsupported)` for `target_os = "android"`. v1.0 calls
  `flock(2)` directly via libc instead — see
  [`crates/hidden-volume/src/container/file.rs`](crates/hidden-volume/src/container/file.rs)
  `android_flock`. Multi-process serialization (`android:process=":subname"`,
  shared UID — increasingly rare in 2026) now works correctly on
  filesystems that honour `flock(2)`. The legacy out-of-scope set
  remains for **filesystems that don't honour flock**: shared /
  external storage (`/sdcard/`, `MediaStore` URIs), some FUSE
  backends (e.g. fuse-overlayfs), and `MultiUserMode` shared paths.
  Host-apps SHOULD still keep the container in app-private storage
  (`Context.getFilesDir()` / `getCacheDir()`) as the supported and
  recommended path; the lock fix narrows the gap, not closes it.
- **Container parent directory writable by an attacker UID.** The
  `compact_known` / `change_passwords` rewrite primitive uses an
  atomic-rename pattern with random tmp filenames. The 2026-05-10
  M3-hardening (header validation + LOCK_EX pin + post-rename inode
  check) raises the cost of a substitution attack but does not fully
  close it on a parent dir an attacker can list+write. Host-apps MUST
  keep the container in a directory only the app's UID can write.

## Security history

### Audits performed

- **v0.5 memory hygiene audit** ([`docs/en/security/audits/memory.md`](docs/en/security/audits/memory.md)):
  audited every key-material allocation. Found and fixed two leak
  paths (`derive_chunk_key` / `derive_subkey` returning raw `[u8; 32]`).
  Documented deferred items (user-data zeroize) with rationale.
- **v0.5 constant-time audit** ([`docs/en/security/audits/constant-time.md`](docs/en/security/audits/constant-time.md)):
  audited 17 distinct comparison sites; none operate on secret data.
  All secret-touching equality lives inside RustCrypto crates (Poly1305
  tag check, Argon2id KDF), both CT by construction.
- **v0.5 fsync ordering audit** ([`docs/en/security/audits/fsync.md`](docs/en/security/audits/fsync.md)):
  traced 7 fsync sites; all in correct positions. The 3-fsync barrier
  protocol in `Space::commit_tx` matches `DESIGN.md` §6 and the
  crash-safety claims are validated by 8 truncation scenarios in
  `tests/crash_recovery.rs`. No issues found.
- **Audit pass 16 (2026-05-09) — R-STREAMING-REPACK + TM1 + R-FFI-PWD-Z**:
  closed three pass-14 roadmap items in one commit. `Container::repack`
  rewritten as a streaming pipeline (working set ≈ 4 MiB per page,
  was O(total plaintext) — multi-GiB log namespaces no longer OOM
  the host). New `MAX_OPEN_SCAN_CHUNKS = 16M` (≈ 64 GiB) cap on
  open-scan, bounding DoS via T2-adversary file inflation. FFI
  password buffers wrapped in `Zeroizing` on every entry point
  (`SpaceHandle::{create,open}`, `AsyncSpaceHandle::{create,open}`,
  `compact_known`, `change_passwords`). 387 tests pass.
- **Audit pass 17 (2026-05-09) — security/quality follow-through**:
  new `Error::ContainerTooLarge` variant + symmetric write-side
  `MAX_OPEN_SCAN_CHUNKS` gate (closes the create-then-can't-reopen
  footgun). `Container::open_space_verified` defers auto-vacuum
  until after `verify_integrity` succeeds (preserves the
  "no observable mutation on verify failure" guarantee).
  `PaddingPolicy::garbage_after_commit` returns `Result<u64>`
  (extreme-input arithmetic now surfaces as `Error::Internal`
  instead of panic / silent wrap). `Space::iter_log_after / before
  / range` strict on non-8-byte keys (now returns
  `Error::WrongNamespaceKind` instead of silent skip).
  `hidden-volume-async::AsyncSpace::create / open` and CLI `hv`
  password buffers wrapped in `Zeroizing`. `PasswordRotation` no
  longer derives `Clone` (defense-in-depth against accidental
  bypass of pass-16 zeroizing flow). `unreachable!()` in
  `space/index.rs` decode paths replaced with `Err(Error::Internal)`.
  MSRV 1.85 → 1.89. **389 tests pass.**

### Vulnerabilities fixed

None published yet — this section will list CVEs / advisories once the
project hits v1.0.

### Planned audits

- External cryptographic review (Trail of Bits / Cure53 / NCC) before
  v1.0 freeze. Tracked in [`TASKS.md`](TASKS.md) v1.0 milestone.
- Fuzzing campaign (`cargo-fuzz` once we have CI infrastructure for
  multi-hour runs).

## Supply-chain — accepted advisories

CI runs `cargo audit` and `cargo deny check` on every tagged
release and on manual workflow dispatch (see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml); branch
pushes and PRs no longer trigger CI as of 2026-05-09 — local
`cargo audit` / `cargo deny check` invocations are the pre-tag
gate). One `unmaintained`-class advisory is explicitly ignored
in [`deny.toml`](deny.toml); it is a compile-time-only transitive
dependency of the `uniffi 0.31` proc-macro toolchain. It never
reaches a runtime code path of the shipped library.

| Advisory | Crate | Why ignored | Removal path |
|---|---|---|---|
| [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436) | `paste 1.0.15` | The author archived the `paste` repo. Transitive compile-time dep of `uniffi_bindgen` and `uniffi_core`; used during proc-macro expansion for identifier concatenation (no runtime effect). The community drop-in replacement is [`pastey`](https://crates.io/crates/pastey), which is source-compatible. | Gated on uniffi migrating away from `paste` to a maintained alternative (R-DEPS in `TASKS.md`). |

> `RUSTSEC-2025-0141` (`bincode 1.3.3`) was previously ignored here
> but was removed once the workspace moved to `uniffi 0.31`, which
> replaced bincode with `postcard` — bincode is no longer in the
> dependency tree.

**No runtime exposure.** The crate participates only in code
generation that runs during `cargo build` of the `hidden-volume-ffi`
proc-macro consumer. Its compiled code is not present in the
shipped `libhidden_volume_ffi.{so,dylib,dll}`. An attacker would need
to subvert the build host's compiler toolchain, which is out of
scope (covered by host trust under
[`docs/en/security/threat-model.md`](docs/en/security/threat-model.md) §2 out-of-scope).

**Review trigger.** When `uniffi` ships ≥ 0.29, both ignores must
be re-evaluated and the version bumped in the same commit that
removes them. CI's `cargo deny check` will fail loudly if either
advisory is still cited but the underlying crate is no longer in
`Cargo.lock` — preventing stale ignore-policy from accumulating.
