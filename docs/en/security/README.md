# Security — threat model + audits

[🇬🇧 English](README.md) · [🇷🇺 Русский](../../ru/security/README.md)

Threat model and the four v0.5 hardening audits. Read the threat
model first to understand the security posture; the audits are the
evidence that the implementation matches the model.

## Documents

- **[threat-model.md](threat-model.md)** — formal threat model.
  Adversary capabilities (T0 passive read, T1 single-snapshot, T2
  file-write tamper, T2' multi-snapshot diff, T3 compelled key),
  what is in/out of scope, and the mitigations per attack class.

### Audits ([audits/](audits/))

- **[self-audit.md](audits/self-audit.md)** — dossier (2026-05-28).
  Why no external paid audit (anonymity + no-budget), what process
  substitutes for it, every cryptographic property statement with
  code references and how to independently verify each claim. This
  is the document to send to anyone asking "has it been audited".
- **[adversarial-stance.md](audits/adversarial-stance.md)** — pass 1
  of the deeper-review series (2026-05-28). Inverted-stance audit:
  ~34 attempted attacks against D1/D2/I1/I2/I3/R1/M1/C1, with
  verdicts (defended / acknowledged-out-of-scope / mitigation-
  tracked). Zero critical/high/medium findings; one LOW (the dossier's
  own "64-byte" doc-inconsistency, fixed in the same commit).
- **[primitive-level.md](audits/primitive-level.md)** — pass 2 of
  the deeper-review series (2026-05-28). Challenges the
  *cryptographic primitive choices* themselves (Argon2id /
  XChaCha20-Poly1305 / BLAKE3 / `getrandom` / `zeroize` / `subtle`)
  against 2026 literature (OWASP, NIST, RFC 9106/8439, CFRG). Two
  LOW findings: P-LOW1 (Argon2Params::MIN m_cost below OWASP
  low-end — rustdoc warning applied) and P-LOW2 (label-length
  domain-separation convention — defense-in-depth opportunity for
  v3 format bump).
- **[side-channel-surface.md](audits/side-channel-surface.md)** —
  pass 3 of the deeper-review series (2026-05-28). Maps every
  non-TM1 side channel (timing, memory, filesystem, logging,
  microarchitectural) to: defended / acknowledged-out-of-scope /
  defense-in-depth opportunity. Zero critical/high/medium/low
  findings; 2 INFO (SC-INFO1 constant-time decode pass for
  key-holder-self-DoS; SC-INFO2 TM1 bench should cover the
  parallel + mmap variants).
- **[format-fuzzing.md](audits/format-fuzzing.md)** — pass 4 of
  the deeper-review series (2026-05-28). Formal boundary
  enumeration of every public `decode` entry point (9 decoders
  + 2 discriminator parsers), each mapped to its defending code
  line and to the specific fuzz / proptest test that exercises
  it. Zero uncovered boundary classes; 1 INFO (FZ-INFO1
  re: CI-failure-on-fuzz-finding gate, currently
  continue-on-error by design).
- **[threat-model-challenge.md](audits/threat-model-challenge.md)**
  — pass 5 (final) of the deeper-review series (2026-05-28).
  Narrative-stance: 7 step-by-step scenarios (border seizure,
  snapshot diff, compelled-password disclosure, malicious
  host-app, kernel-level observer, multi-stage cumulative,
  multi-device) walking through what each named adversary
  learns at each step. Zero new findings; confirms analytical
  results from passes 1-4 in narrative form. Includes the
  cross-series carried-forward action list.

All four audits were run as part of the v0.5 hardening pass and
ratified before any v1.0 freeze considerations.

- **[constant-time.md](audits/constant-time.md)** — every `==` /
  `!=` comparison site classified. **No constant-time issues
  found.** Documents which compares are on public values (OK to be
  data-dependent) vs. on key/tag material (must be `subtle::ct_eq`).
- **[fsync.md](audits/fsync.md)** — 3-fsync commit protocol audit.
  Every barrier in `Space::commit_tx` matches the DESIGN §6
  protocol; ordering is verified in the crash-recovery tests.
- **[memory.md](audits/memory.md)** — zeroize coverage on every
  secret type. Master keys, derived subkeys, AEAD tags, password
  bytes — all wrapped in `Zeroizing<...>` or `#[derive(ZeroizeOnDrop)]`.
- **[plaintext.md](audits/plaintext.md)** — transient
  pre/post-encryption buffers. Verifies plaintext never lingers in
  intermediate `Vec<u8>` allocations after AEAD seal completes.

## Reporting a vulnerability

See [`../../../SECURITY.md`](../../../SECURITY.md) for the
disclosure policy.
