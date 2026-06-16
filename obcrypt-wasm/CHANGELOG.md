# Changelog

All notable changes to `obcrypt-wasm` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]


## [1.0.0] - 2026-06-15

### Added

- Initial WebAssembly / JavaScript binding surface for `obcrypt`
  via wasm-bindgen, mirroring `obcrypt-py`:
  - Free functions: `encrypt`, `decrypt`, `generateKey`,
    `generateKeyBytes`, `version`. Both `encrypt(data, scheme, key)`
    and `decrypt(output, scheme, key)` take the scheme explicitly —
    the output carries no marker, so decrypting under the wrong
    scheme throws.
  - One codec class per scheme — `Dgcmsiv`, `Pgcmsiv`, `Dsiv`,
    `Psiv` — each constructed from a 128-character hex key, with
    `encrypt` / `decrypt` methods and `key` / `keyBytes` /
    `scheme` getters.
- Per-scheme cargo features (`dgcmsiv`, `pgcmsiv`, `dsiv`, `psiv`,
  `mock`) forwarding to the corresponding `obcrypt` feature; the
  default set enables the four production schemes.
- wasm-bindgen-test roundtrip suite (`tests/roundtrip.rs`),
  runnable via `wasm-pack test --node`.

### Notes

- Byte arguments and results map to JS `Uint8Array`; keys are hex
  strings. Errors surface as JS `Error`s carrying the underlying
  `obcrypt::Error` message.
- Randomness on wasm32 flows through obcrypt's getrandom "js"
  backend; no separate getrandom dependency is declared here.
- Ships to npm via wasm-pack — not a crates.io publication target.
