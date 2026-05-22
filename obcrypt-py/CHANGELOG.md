# Changelog

All notable changes to `obcrypt-py` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]


## [0.1.0] - 2026-05-22

### Added

- First release with a real binding surface. The PyO3 extension
  now exposes:
  - Five codec classes — `Aags`, `Apgs`, `Aasv`, `Apsv`, `Upbc`
    — each binding a scheme to a key. Construct as `Aasv(key)`
    where `key` is a 128-character hex string (the canonical
    oboron key form, what env vars and config files carry).
    `encrypt(plaintext)` and `decrypt(payload)` operate on
    bytes; `decrypt` requires the payload's trailing marker to
    match the codec's scheme. Properties: `key` (hex form),
    `key_bytes` (raw 64-byte form for interop), `scheme`.
  - Module-level free functions: `encrypt(plaintext, scheme,
    key)`, `decrypt(payload, key)` (auto-detects scheme from
    the trailing marker), and `decrypt_as(payload, scheme,
    key)` (strict-scheme variant).
  - `generate_key()` returns a fresh random key as a 128-char
    hex string; `generate_key_bytes()` returns the same key
    material as raw 64 bytes, for interop with byte-native APIs
    (HSMs, `cryptography`, `pynacl`, custom storage).
  - Four-class exception hierarchy rooted at `ObcryptError` —
    `InvalidKey`, `InvalidScheme`, `EncryptionFailed`,
    `DecryptionFailed`.
  - `obcrypt.schemes` submodule with `AAGS` / `APGS` / `AASV` /
    `APSV` / `UPBC` string constants for typo-resistant
    scheme selection.
- Type stubs (`_obcrypt.pyi`) covering the full surface.

## [0.0.1] - 2026-05-21

### Added

- Initial scaffold release on PyPI. PyO3 0.28 module entry point
  exposing only `__version__` — no real binding surface yet. This
  release reserves the `obcrypt` name on PyPI; the actual binding
  surface (classes, methods, exception types) follows in a later
  release.
- Built against PyO3 0.28's stable ABI (`abi3-py38`): one wheel per
  platform covers CPython 3.8 and later. The PyPI classifiers
  declare support through 3.14.
- Versioning decoupled from the workspace `obcrypt` Rust crate:
  `obcrypt-py` follows its own release cadence on PyPI.
