# Contributing to hidden-volume

🇬🇧 **English** · [🇷🇺 Русский](../../ru/contributing/guide.md)

Thank you for considering a contribution. This document describes the
development workflow, code style, and review expectations.

## Quick start

```sh
git clone <fork>
cd hidden-volume

# Build, test, lint — these are what CI runs.
cargo build --workspace --all-targets
cargo test --workspace --tests
cargo test --workspace --doc
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo doc --no-deps --lib
```

Three details in those flags are load-bearing, and this list got them wrong
for long enough to matter — **branch pushes do not run CI here**, so these
commands ARE the gate for everything short of a tag.

- `--workspace`, not the default member. `hidden-volume-async`,
  `hidden-volume-ffi` and `hidden-volume-rt` are separate crates; without it
  they are never built or tested. This list used to say
  `cargo test --features async --tests`, which has not existed since the async
  code became a crate of its own — it fails with "none of the selected
  packages contains this feature".
- `--all-features` on clippy, because code behind a feature is only linted
  when that feature is on — CI's clippy job runs it, and a lint nobody runs is
  a lint nobody obeys.
- **And the default-feature build has to be clean too.** CI sets
  `RUSTFLAGS: -D warnings` for every job, so a warning in a build WITHOUT a
  feature is an error in a dozen of them. That is how v2.0.1 first failed: a
  helper whose only caller moved behind `parallel-scan` became dead code
  everywhere else, and `--all-features` hid it from the one command that would
  have said so. Run `cargo build --workspace --all-targets` plainly as well as
  clippy with everything on; they are different questions.
- `--all-targets`, so test code is compiled. A signature change that only
  breaks tests is invisible otherwise.

If any of these fail before you've made changes, please open an issue —
your environment may be set up incorrectly, or there may be a real
regression we'd like to know about.

## Code style

- **Format with rustfmt** before committing: `cargo fmt --all`. The
  project's `rustfmt.toml` locks the few axes that vary between
  contributors; defaults handle the rest.
- **Lint clean under clippy**:
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
  CI rejects warnings.
- **Avoid emojis** in code, comments, commit messages, or PR descriptions.
- **Match existing patterns**: scan a similar nearby file before adding
  a new construct. The codebase has consistent module structure
  (`mod.rs` re-exports, sub-files for distinct responsibilities) and
  consistent error handling (return `crate::Result`, propagate via `?`).

## Architecture overview

See [`DESIGN.md`](../../../DESIGN.md) for the formal threat model and on-disk
format. The high-level module layout:

```
src/
├── crypto/        — KDF, AEAD, BLAKE3 derivation, RNG, ct helpers
├── chunk/         — fixed 4096-byte chunk format
├── container/     — file-level operations, header, ContainerOptions
├── space/         — per-space superblock, B+ tree IndexNode, DataBatch log
├── tx/            — multi-op transactions with 3-fsync commit protocol
├── padding/       — None | BucketGrowth | FixedRatio
├── open/          — discovery scan + recovery
├── async_api/     — feature-gated tokio wrapper (under `async` feature)
└── error.rs       — single Error enum
```

## What kinds of changes are welcome

- **Bug fixes** — always. Include a regression test.
- **Documentation** — README, rustdoc, DESIGN, audit docs.
- **Tests** — additional property-test coverage, edge cases, benchmarks.
- **Performance** — must come with criterion bench data showing the win.
- **Compatibility** — additional platforms, CI matrix expansion.

## What kinds of changes need discussion first

Open an issue (or draft PR with `WIP:` prefix) before significant work
on:

- **On-disk format changes** — even pre-1.0, format churn affects every
  test fixture and migration path. We're happy to break compat for a
  good reason; just talk first.
- **Cryptographic primitive substitutions** — XChaCha20-Poly1305,
  Argon2id, BLAKE3 are deliberate choices documented in `DESIGN.md` §10.
- **New external dependencies** — every dep is a supply-chain risk. We
  prefer the minimum cut. Get sign-off before adding one.
- **API breaking changes pre-1.0** — fine in principle (the v0.x line
  is unstable) but coordinate to bundle multiple breaks into one
  release rather than churn.
- **`unsafe` code** — currently zero in the crate. Adding `unsafe`
  requires written justification (in the PR description and a comment
  block at the call site).

## Testing standards

- **Every code change has at least one test.** Either a new test or
  an updated existing one.
- **Property tests** for any logic with non-trivial state machine or
  format roundtrip — see `tests/property_full.rs` and
  `tests/parser_fuzz.rs` for the pattern.
- **Crash injection** for any change to the commit protocol or
  durability path — extend `tests/crash_recovery.rs`.
- **No flaky tests.** Determinism over speed. If a test relies on
  timing, replace it with a stable equivalent.

## Security policy

See [`SECURITY.md`](../../../SECURITY.md) for vulnerability reporting. Please
do NOT open a public issue or PR for a security finding — use the
private disclosure channels listed there.

The `docs/` directory contains audit records:

- [`docs/en/security/audits/memory.md`](../security/audits/memory.md) — key material handling
- [`docs/en/security/audits/constant-time.md`](../security/audits/constant-time.md) — constant-time analysis
- [`docs/en/security/audits/fsync.md`](../security/audits/fsync.md) — durability protocol

If your change touches `crypto/`, `space/`, or `container/` in a way
that affects these audits, update the audit log and request a
reviewer with cryptographic background.

## Commit messages

The project uses descriptive multi-paragraph commit messages — see
`git log` for the pattern. Briefly:

- Imperative mood subject line, ≤ 70 chars.
- Body explaining what + why, wrapped at ~72 chars.
- Reference relevant issue/PR numbers if applicable.
- For substantial changes, include a brief test summary at the end:
  "X/Y tests green; clippy clean; cargo fmt clean."

## Pull requests

- Open against `master`.
- One logical change per PR. If you have several, file them
  separately — easier to review, easier to revert if needed.
- Include a "Test plan" in the description (what scenarios you
  exercised, what edge cases you considered).
- Wait for CI to pass before requesting review.

## License

Contributions are dual-licensed under MIT OR Apache-2.0, matching the
project. By submitting a PR you agree your contribution may be
distributed under either license.
