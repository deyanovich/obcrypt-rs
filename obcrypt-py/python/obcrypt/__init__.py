"""obcrypt — bytes-in/bytes-out symmetric encryption.

Python bindings for the `obcrypt` Rust crate (the cryptographic
core of the oboron protocol — a-tier and u-tier schemes operating
on raw bytes, no text encoding, no UTF-8 validation).

Docs: https://oboron.org/

This package is currently a scaffold; the binding surface is being
built incrementally.
"""

from . import _obcrypt as _ext

__version__ = _ext.__version__

__all__ = ["__version__"]
