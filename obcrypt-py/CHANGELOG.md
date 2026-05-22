# Changelog

All notable changes to `obcrypt-py` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]


## [0.1.2] - 2026-05-22

### Changed

- License declaration migrated to PEP 639:
  - `pyproject.toml`: `license = { text = "MIT" }` →
    `license = "MIT"` (SPDX expression) plus
    `license-files = ["LICENSE"]`.
  - Wheel METADATA now emits `License-Expression: MIT` and
    `License-File: LICENSE` (instead of the legacy
    `License: MIT`).
- README's `[LICENSE](...)` link is now an absolute URL
  pointing at the public GitLab mirror. Relative `LICENSE`
  links don't dereference in PyPI's rendered README — this
  makes the link clickable on the PyPI project page.

### Fixed

- The LICENSE file is once again bundled in the wheel (at
  `obcrypt-0.1.2.dist-info/licenses/LICENSE`). 0.1.0's wheel
  shipped a LICENSE, 0.1.1 dropped it to work around the sdist
  publish bug — the PEP 639 config (above) resolves the
  publish bug without losing the bundled file.

### Notes

- No API or behavior changes.

## [0.1.1] - 2026-05-22

### Fixed

- Source distribution now publishes successfully. The 0.1.0 sdist
  upload was rejected by PyPI with
  `License-File LICENSE does not exist in distribution file` —
  maturin had auto-detected `obcrypt-py/LICENSE`, declared
  `License-File: LICENSE` in PKG-INFO, but placed the file at
  `obcrypt-py/LICENSE` inside the tarball rather than at the
  sdist root. The 0.1.0 wheels uploaded successfully and are
  installable; the sdist was missing. 0.1.1 removes the
  per-package `obcrypt-py/LICENSE` (matching the sibling
  `oboron-py` convention) — the workspace-root LICENSE remains
  authoritative, and PKG-INFO no longer claims a file it can't
  deliver. License continues to be declared via `License: MIT`
  in metadata and the standard OSI classifier.

### Notes

- No API or behavior changes. If you installed 0.1.0
  successfully, you don't need to upgrade for correctness; 0.1.1
  is for users whose platforms required the sdist
  (build-from-source fallback for archs without a published
  wheel).

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
