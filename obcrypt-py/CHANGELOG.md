# Changelog

All notable changes to `obcrypt-py` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]


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
