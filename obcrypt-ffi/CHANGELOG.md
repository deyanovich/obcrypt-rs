# Changelog

All notable changes to `obcrypt-ffi` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]


## [0.1.0] - 2026-06-29

### Added

- Initial C ABI over the obcrypt 1.0 core — the binary
  (bytes-in / bytes-out) counterpart to oboron's string ABI, for
  languages without a first-class Rust bridge.
  - Raw-key functions `obcrypt_encrypt` / `obcrypt_decrypt`, each
    taking the scheme by name and a 64-byte key as `(ptr, len)`.
  - Hex-key functions `obcrypt_encrypt_hex_key` /
    `obcrypt_decrypt_hex_key`, taking the key as a NUL-terminated
    128-character hex string — the canonical oboron key form that
    env vars and config files carry.
  - `obcrypt_buffer_free` (release a returned buffer),
    `obcrypt_last_error` (this thread's last error message), and
    `obcrypt_abi_version` (the package version string).
- Status codes: `OBCRYPT_OK` (0); negative for FFI-layer faults
  (`OBCRYPT_ERR_NULL_ARG`, `_ERR_UTF8`, `_ERR_BAD_SCHEME`,
  `_ERR_PANIC`); positive for an obcrypt error
  (`OBCRYPT_ERR_OBCRYPT`).
- `OBCRYPT_ABI_VERSION` (1): the C ABI generation, bumped only on an
  incompatible change to the exported surface — independent of the
  package version.
- Contract: `(ptr, len)` byte buffers in (a null `ptr` only when
  `len == 0`); scheme (and hex key) as NUL-terminated UTF-8;
  heap-allocated, caller-owned output released via
  `obcrypt_buffer_free(ptr, len)`; a thread-local last-error message;
  every entry point wrapped in `catch_unwind` so panics never cross
  the boundary.
- Committed reference header `include/obcrypt.h` — the canonical ABI
  surface, the verbatim output of `cbindgen.toml`.
- Per-scheme cargo features (`dgcmsiv`, `pgcmsiv`, `dsiv`, `psiv`)
  forwarding to obcrypt; the default set enables the four production
  schemes.
- `examples/smoke.c`: a C round-trip including an embedded-NUL
  plaintext.

### Notes

- Not a registry publication target: `obcrypt-ffi` ships as a built
  shared / static library (`libobcrypt_ffi.{so,a}`; `obcrypt_ffi.dll`
  on Windows) plus the C header. The header is the versioned ABI
  surface.
- `obcrypt_last_error` is thread-local. The deterministic
  (`dsiv`, `dgcmsiv`) vs probabilistic (`psiv`, `pgcmsiv`)
  distinction is the caller's choice via the scheme name.
- Conformance is checked against the canonical oboron core test
  vectors driven through this ABI (`tests/conformance.rs`).
