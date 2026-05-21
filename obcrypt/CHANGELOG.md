# Changelog

All notable changes to `obcrypt` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

### Changed

### Fixed


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
