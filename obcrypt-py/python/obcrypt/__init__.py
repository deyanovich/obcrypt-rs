"""obcrypt — bytes-in/bytes-out symmetric encryption.

Python bindings for the `obcrypt` Rust crate (the cryptographic core
of the oboron protocol — a-tier and u-tier schemes operating on raw
bytes, no text encoding, no UTF-8 validation).

Docs: https://oboron.org/

Keys are 128-character hex strings — the canonical oboron key form,
what comes out of env vars, config files, and secrets managers. Every
codec ctor and free function takes the key as a plain ``str``.

Quick start::

    import obcrypt
    from obcrypt import schemes

    key = obcrypt.generate_key()                  # 128-char hex
    payload = obcrypt.encrypt(b"hello", schemes.AASV, key)
    plaintext = obcrypt.decrypt(payload, key)
    assert plaintext == b"hello"

Codec class style (binds key + scheme together)::

    aasv = obcrypt.Aasv(key)
    payload = aasv.encrypt(b"hello")
    plaintext = aasv.decrypt(payload)

Raw 64-byte key material is available via ``.key_bytes`` and
``generate_key_bytes()`` for interop with byte-native APIs (HSMs,
``cryptography``, ``pynacl``, custom storage). The hex form is the
canonical input everywhere.

Schemes:

- ``aags`` — a-tier, deterministic, AES-GCM-SIV
- ``apgs`` — a-tier, probabilistic, AES-GCM-SIV
- ``aasv`` — a-tier, deterministic, AES-SIV (most general default)
- ``apsv`` — a-tier, probabilistic, AES-SIV
- ``upbc`` — u-tier (unauthenticated), probabilistic, AES-CBC

Exception hierarchy:

- ``ObcryptError`` — base class for all obcrypt exceptions
  - ``InvalidKey`` — bad hex / bad length
  - ``InvalidScheme`` — unknown scheme name / marker mismatch
  - ``EncryptionFailed`` — AEAD failure / empty plaintext
  - ``DecryptionFailed`` — tag check / padding / short payload / etc.
"""

from . import _obcrypt as _ext
from . import schemes

__version__ = _ext.__version__

# Codec classes
Aags = _ext.Aags
Apgs = _ext.Apgs
Aasv = _ext.Aasv
Apsv = _ext.Apsv
Upbc = _ext.Upbc

# Functions
encrypt = _ext.encrypt
decrypt = _ext.decrypt
decrypt_as = _ext.decrypt_as
generate_key = _ext.generate_key
generate_key_bytes = _ext.generate_key_bytes

# Exceptions
ObcryptError = _ext.ObcryptError
InvalidKey = _ext.InvalidKey
InvalidScheme = _ext.InvalidScheme
EncryptionFailed = _ext.EncryptionFailed
DecryptionFailed = _ext.DecryptionFailed

__all__ = [
    "__version__",
    # Codec classes
    "Aags",
    "Apgs",
    "Aasv",
    "Apsv",
    "Upbc",
    # Functions
    "encrypt",
    "decrypt",
    "decrypt_as",
    "generate_key",
    "generate_key_bytes",
    # Exceptions
    "ObcryptError",
    "InvalidKey",
    "InvalidScheme",
    "EncryptionFailed",
    "DecryptionFailed",
    # Submodules
    "schemes",
]
