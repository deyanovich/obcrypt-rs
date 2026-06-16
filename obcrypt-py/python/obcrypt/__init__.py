"""obcrypt — bytes-in/bytes-out authenticated encryption.

Python bindings for the `obcrypt` Rust crate (the cryptographic core
of the oboron protocol — the authenticated core schemes operating on
raw bytes, no text encoding, no UTF-8 validation).

Docs: https://oboron.org/

Keys are 128-character hex strings — the canonical oboron key form,
what comes out of env vars, config files, and secrets managers. Every
codec ctor and free function takes the key as a plain ``str``.

Quick start::

    import obcrypt
    from obcrypt import schemes

    key = obcrypt.generate_key()                  # 128-char hex
    payload = obcrypt.encrypt(b"hello", schemes.DSIV, key)
    plaintext = obcrypt.decrypt(payload, schemes.DSIV, key)
    assert plaintext == b"hello"

The output carries no scheme marker, so the same scheme used to encrypt
must be supplied to ``decrypt``; a wrong scheme fails the authentication
check. Codec class style binds key + scheme together::

    dsiv = obcrypt.Dsiv(key)
    payload = dsiv.encrypt(b"hello")
    plaintext = dsiv.decrypt(payload)

Raw 64-byte key material is available via ``.key_bytes`` and
``generate_key_bytes()`` for interop with byte-native APIs (HSMs,
``cryptography``, ``pynacl``, custom storage). The hex form is the
canonical input everywhere.

Schemes (all authenticated):

- ``dsiv`` — deterministic, AES-SIV (most general default)
- ``psiv`` — probabilistic, AES-SIV
- ``dgcmsiv`` — deterministic, AES-GCM-SIV
- ``pgcmsiv`` — probabilistic, AES-GCM-SIV

Exception hierarchy:

- ``ObcryptError`` — base class for all obcrypt exceptions
  - ``InvalidKey`` — bad hex / bad length
  - ``InvalidScheme`` — unknown scheme name
  - ``EncryptionFailed`` — AEAD failure / empty plaintext
  - ``DecryptionFailed`` — tag check / short payload / wrong scheme
"""

from . import _obcrypt as _ext
from . import schemes

__version__ = _ext.__version__

# Codec classes
Dgcmsiv = _ext.Dgcmsiv
Pgcmsiv = _ext.Pgcmsiv
Dsiv = _ext.Dsiv
Psiv = _ext.Psiv

# Functions
encrypt = _ext.encrypt
decrypt = _ext.decrypt
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
    "Dgcmsiv",
    "Pgcmsiv",
    "Dsiv",
    "Psiv",
    # Functions
    "encrypt",
    "decrypt",
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
