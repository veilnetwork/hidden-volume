# Verifying a release

Every tagged release publishes:

- Per-target binaries: `hv-<target>` (CLI) and
  `libhidden_volume_ffi-<target>.{so,dylib,dll}` (uniffi cdylib).
- `SHA256SUMS` — line-oriented `<sha256>  <filename>` for every
  binary, sorted by filename.
- `SHA256SUMS.cosign.bundle` — a Sigstore bundle (cosign keyless
  signature + Fulcio certificate chain + Rekor transparency-log
  entry, in one self-contained JSON file).

Verification proves two things:

1. The `SHA256SUMS` file was signed by *this repository's*
   [release workflow][release-yml] running on a *valid SemVer tag* —
   no one else can produce a matching signature.
2. The binary you downloaded matches its line in `SHA256SUMS` byte for
   byte — no on-the-wire tamper, no truncation.

Both steps are required. A signed `SHA256SUMS` with a mismatched
binary tells you the file was tampered with after release; an
unsigned matching `SHA256SUMS` proves nothing about who produced it.

## One-time setup

Install [`cosign`][cosign]. macOS:

```sh
brew install cosign
```

Linux (any distro, no root needed):

```sh
curl -L https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 \
  -o ~/.local/bin/cosign && chmod +x ~/.local/bin/cosign
```

Verify your cosign install is current (`>= 2.0` recommended):

```sh
cosign version
```

No keys to manage. Sigstore's public roots ship with cosign.

## Per-release verification

Download the four files for your platform from the release page:

- One binary, e.g. `hv-aarch64-apple-darwin`
- The matching `libhidden_volume_ffi-<target>.{so,dylib,dll}` if
  your application links it
- `SHA256SUMS`
- `SHA256SUMS.cosign.bundle`

Place all four in the same directory, then:

```sh
# 1. Verify that SHA256SUMS was signed by THIS repo's release workflow
#    on a SemVer tag. Replace OWNER/REPO with the GitHub coordinates
#    you downloaded from.
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/OWNER/REPO/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS

# Expected output: `Verified OK`. Any other output = do not trust the file.

# 2. Verify your downloaded binaries against the (now trusted) SHA256SUMS.
sha256sum --ignore-missing -c SHA256SUMS    # GNU sha256sum (Linux)
# OR:
shasum -a 256 -c SHA256SUMS                 # macOS / BSD
```

`--ignore-missing` lets you keep `SHA256SUMS` in full while
verifying only the subset of binaries you downloaded.

## What the signature commits to

The Sigstore bundle pins:

| Field | Value | What it proves |
|---|---|---|
| `subject` | the SHA-256 hash of `SHA256SUMS` | the file you have is the file that was signed |
| Certificate `Subject Alternative Name` | `https://github.com/OWNER/REPO/.github/workflows/release.yml@refs/tags/v…` | the signer was *this* workflow on *this* repo at *this* tag |
| Certificate `oidc.issuer` | `https://token.actions.githubusercontent.com` | the workflow ran on GitHub-hosted Actions (not a self-hosted runner that could have leaked OIDC tokens) |
| Rekor log entry | inclusion proof | the signature was recorded in the public Sigstore transparency log; an attacker cannot quietly issue a parallel signature without leaving a public trace |

Together those checks mean: *if a SHA256SUMS file passes
`cosign verify-blob` with the identity regex anchored to this
repo+workflow+tag pattern, only a GitHub Actions run of this exact
workflow on this exact repo at a SemVer tag could have signed it.*

## What it does NOT commit to

- **The source commit.** The signature ties to the *tag*, not to a
  specific commit SHA. If you need to bind to a commit, cross-check
  the release page's commit reference against your git history.
- **Pre-1.0 format stability.** Even if the binary verifies, the
  on-disk container format may break in a v0.x → v0.y bump — see
  [`docs/en/reference/semver.md`](../reference/semver.md) for the
  pre-1.0 stability posture.
- **Crate publication on crates.io.** Every workspace crate is
  `publish = false` until external crypto-review clears (see
  [`TASKS.md`](../../../TASKS.md) v1.0). Verifying a release artifact
  is independent of whether the underlying library is on crates.io.

## What can go wrong

| Symptom | Likely cause | Action |
|---|---|---|
| `cosign verify-blob` says `no matching signatures` | `SHA256SUMS` was modified after release; OR the `.cosign.bundle` you have is from a different release | Re-download both from the canonical release page |
| `cosign verify-blob` says `certificate identity does not match` | The bundle was signed by a different workflow / a different repo / a non-tag ref | Refuse — someone may be impersonating this repo's release pipeline |
| `cosign verify-blob` succeeds, `sha256sum -c` fails on one file | That file was tampered with in transit; the rest of the release may still be intact | Re-download just the failing file from a different mirror / network path |
| `sha256sum -c` reports `WARNING: N lines are improperly formatted` | You concatenated multiple `SHA256SUMS` files | Start over with one release's files only |

## Reporting a verification failure

If verification fails AND re-downloading from the canonical release
page reproduces the failure, treat it as a supply-chain incident.
Open a [security advisory][advisory] and email the maintainer per
[`SECURITY.md`](../../../SECURITY.md). Do **not** install the
unverified binaries.

[release-yml]: ../../../.github/workflows/release.yml
[cosign]: https://github.com/sigstore/cosign
[advisory]: https://github.com/veilnetwork/hidden-volume/security/advisories
