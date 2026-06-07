# Guide — host-app integration

[🇬🇧 English](README.md) · [🇷🇺 Русский](../../ru/guide/README.md)

Practical recipes for building a host-app on top of `hidden-volume`.
Read [`integration.md`](integration.md) first; everything else is
reference material you consult as needed.

## Documents

- **[integration.md](integration.md)** — narrative walkthrough.
  Spaces, transactions, deniability invariants, anti-patterns,
  password change, message-history pagination. **Start here.**
- **[operations.md](operations.md)** — operations playbook.
  Deployment, backup, repack/compact, integrity verification,
  recovery from common failure modes.
- **[multi-device.md](multi-device.md)** — formal contract for
  multi-device host-apps. Locking primitives, anchor patterns,
  sync semantics, replay-rollback considerations.
- **[flutter.md](flutter.md)** — embedding `hidden-volume` in a
  Flutter app via the FFI bindings (uniffi 0.31).
- **[migration.md](migration.md)** — empty shell for the eventual
  v1 → v2 on-disk format migration.

## Where to read next

After the guide, you'll likely want one of:

- [`reference/format.md`](../reference/format.md) — byte-level
  format spec for understanding what's on disk.
- [`security/threat-model.md`](../security/threat-model.md) — what
  threats `hidden-volume` defends against (and what it doesn't).
- [`reference/semver.md`](../reference/semver.md) — what's stable
  vs. what may break across minor versions.
