# Fuzz targets — `hidden-volume`

Coverage-guided fuzzing via [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html).

## Quick start

```sh
# One-time install (requires nightly).
cargo install cargo-fuzz
rustup toolchain install nightly

# Run a target indefinitely. Stop with Ctrl-C.
cd crates/hidden-volume
cargo +nightly fuzz run <target-name>

# Time-bounded run (e.g. 5 minutes per target in CI).
cargo +nightly fuzz run <target-name> -- -max_total_time=300
```

## Targets

| Target | What it fuzzes | Why |
|---|---|---|
| `plaintext_decode` | `Plaintext::decode` directly | Hot path on every chunk read; biggest blast radius if it panics. |
| `decoder_family` | All public `decode` functions: `Plaintext`, `Superblock`, `CommitPayload`, `IndexNode` (Leaf + Internal), `decode_batch`, `Argon2Params::decode_header` | Catches any format-parser regression in one target. |
| `container_open` | `Container::open_readonly` end-to-end on random byte files | Exercises the magic check, header parser, file-size validation, and discovery-scan entry point. Doesn't reach post-AEAD code paths (AEAD always fails on random bytes); pair with `decoder_family` for full coverage. |

## What "coverage" means here

`cargo fuzz` uses [libFuzzer](https://llvm.org/docs/LibFuzzer.html), a
**coverage-guided** mutational fuzzer. It instruments every basic
block in the target and prefers inputs that exercise new edges. For a
parser, this means it learns the framing format empirically — feed it
no seeds and it will eventually produce minimal magic-bytes-prefixed
inputs that exercise deep parser paths.

Seed corpus (in `corpus/<target>/`) is optional but recommended for
faster convergence. Generate one from real `hidden-volume` files
captured with the `hv` CLI:

```sh
mkdir -p corpus/container_open
hv create corpus/container_open/seed1.hv --params min --replicas 1
# Add more seeds with varying parameters, sizes, etc.
```

## Crashes

If libFuzzer finds an input that crashes, it writes the bytes to
`artifacts/<target>/`. Replay with:

```sh
cargo +nightly fuzz run <target-name> artifacts/<target-name>/crash-<hash>
```

Reduce the crash to a minimal reproducer:

```sh
cargo +nightly fuzz tmin <target-name> artifacts/<target-name>/crash-<hash>
```

File any crash as a `bug:fuzz` issue and treat as
`severity:critical` (parser panics on attacker-controlled input
violate the deniability invariant — the panic message itself becomes
an oracle distinguishing "valid for some space" from "invalid").

## CI integration

The fuzz package is intentionally NOT a workspace member (its
nightly-only `libfuzzer-sys` dep would force nightly on stable
workspace builds). To run in CI:

```yaml
- name: Fuzz (5 min per target)
  run: |
    cargo install cargo-fuzz
    rustup toolchain install nightly
    cd crates/hidden-volume
    for target in plaintext_decode decoder_family container_open; do
      cargo +nightly fuzz run "$target" -- -max_total_time=300
    done
```

This is **deferred until cargo-fuzz CI infra is allocated** (see
`TASKS.md` v0.5 fuzzing section). Meanwhile the proptest-based
`tests/parser_fuzz.rs` provides equivalent panic-freedom coverage on
stable.

## Adding a target

1. Write `fuzz_targets/<name>.rs` with the `fuzz_target!` macro.
2. Add a `[[bin]]` entry to `fuzz/Cargo.toml`.
3. Document the target in this README.
4. Test locally: `cargo +nightly fuzz run <name> -- -max_total_time=10`.

## Stable-build sanity

The fuzz crate's `Cargo.toml` does NOT compile on stable Rust because
`libfuzzer-sys` requires the nightly-only `-Z` instrumentation flags.
This is intentional. Workspace builds (`cargo build --workspace`) skip
this directory because it is excluded from `members` in the root
`Cargo.toml`. Stable CI ignores it; nightly fuzz runs pick it up.
