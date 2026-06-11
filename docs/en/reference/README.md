# Reference — formal specs

[🇬🇧 English](README.md) · [🇷🇺 Русский](../../ru/reference/README.md)

Formal reference material. Read after [`../guide/`](../guide/) when
you need byte-level detail or stability guarantees.

## Documents

- **[format.md](format.md)** — canonical byte-level wire format
  spec for v1. Headers, chunk layout, AEAD framing, AAD
  composition. The single source of truth for on-disk bytes.
- **[api-surface.txt](api-surface.txt)** — frozen snapshot of every
  `pub` item at v1.0. Used by CI to detect accidental API drift.
- **[semver.md](semver.md)** — semver policy. What constitutes a
  breaking change in the v1.x line: format, public Rust API,
  cargo features, FFI ABI, error variants.
- **[ffi.md](ffi.md)** — architecture of `hidden-volume-ffi`.
  uniffi 0.31 binding strategy, error mapping, lifetime management.

## When to read each

| You need to … | Read |
|---|---|
| Implement a new reader/writer of the format | `format.md` |
| Check whether a refactor breaks public API | `api-surface.txt` |
| Understand version-bump rules | `semver.md` |
| Add a foreign-language binding | `ffi.md` |
