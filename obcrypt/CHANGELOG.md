# Changelog

All notable changes to `obcrypt` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

### Changed

### Fixed


## [0.1.1] - 2026-05-21

### Changed

- **Docs URLs** in `lib.rs`, `SECURITY.md`, and `FEATURES.md` now
  point at the public canonical repository
  (`gitlab.com/oboron/obcrypt-rs`) rather than the private mirror
  path. Cross-references on docs.rs and crates.io now resolve
  correctly for downstream readers.
- **Internal: per-scheme key extraction** centralized via a
  `Key::subkey<O, N>` crate-internal helper, replacing twelve
  hand-rolled `try_into().unwrap()` call sites across the scheme
  modules. Pure refactor — no public API change.
- **`Scheme::from_str`** no longer allocates a `String` per call
  (previously `s.to_lowercase()`; now ASCII-case-insensitive
  match guards).
- **`schemes::upbc::decrypt`** reduced from two heap allocations
  to one.
- **`schemes::apgs::encrypt`** nonce extraction simplified — the
  triple-nested `Nonce::from(*<&[u8;N]>::try_from(...).unwrap())`
  is replaced by a stack `[u8; NONCE_SIZE]` array, matching the
  cleaner pattern already used by the `_into` variant.
- **README versioning section** tightened — the wire-format
  stability statement no longer reads as contradicting the
  pre-1.0 API-evolution caveat in the same paragraph.


## [0.1.0] - 2026-05-20

### Added

- Initial release.
- Bytes-in / bytes-out cryptographic core lifted from `oboron-rs`.
- `a`-tier schemes: `aags`, `apgs`, `aasv`, `apsv`.
- `u`-tier schemes: `upbc`.
- Framed payload format (ciphertext + XOR'd 2-byte scheme marker).
- Dual API: `encrypt` / `encrypt_into`, `decrypt` / `decrypt_into`,
  `decrypt_as` / `decrypt_as_into`.
- Per-scheme raw primitives exposed under `obcrypt::schemes::*`,
  with parallel `encrypt_into` / `decrypt_into` variants on each that
  write directly into a caller-provided `&mut Vec<u8>` using AEAD's
  `encrypt_in_place` / `decrypt_in_place` (via a private `TailBuffer`
  adapter). The owned `encrypt` / `decrypt` are thin wrappers over the
  `_into` form.
- `Key` type with `Zeroize` / `ZeroizeOnDrop`.
- Testing-only `mock` feature (identity, reverse).

### Performance

- The top-level framed APIs (`encrypt_into`, `decrypt_into`,
  `decrypt_as_into`) are now genuinely zero-extra-allocation: ciphertext
  is written directly into the caller's buffer with no intermediate
  `Vec`. Previous implementation allocated a fresh `Vec` from the AEAD
  call and then copied into the caller's buffer.
