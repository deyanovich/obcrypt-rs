"""Type stubs for ``obcrypt._obcrypt`` — the PyO3 extension module.

The user-facing API is the ``obcrypt`` package; ``obcrypt/__init__.py``
re-exports every name listed below.
"""

__version__: str

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ObcryptError(Exception):
    """Base class for all obcrypt exceptions."""

class InvalidKey(ObcryptError):
    """Bad hex string or wrong-length key passed as ``key``."""

class InvalidScheme(ObcryptError):
    """Unknown scheme name, or trailing marker doesn't match the expected scheme."""

class EncryptionFailed(ObcryptError):
    """AEAD primitive failure, or empty plaintext passed to ``encrypt``."""

class DecryptionFailed(ObcryptError):
    """Tag check failure, padding failure, short payload, or block-length mismatch."""

# ---------------------------------------------------------------------------
# Codec classes
# ---------------------------------------------------------------------------
#
# Each codec binds a scheme to a key. ``key`` is a 128-character hex
# string — the canonical oboron key form. Bad hex / wrong length raises
# ``InvalidKey``.

class Aags:
    """Codec binding scheme ``aags`` (a-tier, deterministic, AES-GCM-SIV)."""

    def __init__(self, key: str) -> None: ...
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, payload: bytes) -> bytes: ...
    @property
    def key(self) -> str:
        """The bound key as a 128-character lowercase hex string."""
    @property
    def key_bytes(self) -> bytes:
        """The bound key as raw 64 bytes (interop accessor)."""
    @property
    def scheme(self) -> str: ...
    def __repr__(self) -> str: ...

class Apgs:
    """Codec binding scheme ``apgs`` (a-tier, probabilistic, AES-GCM-SIV)."""

    def __init__(self, key: str) -> None: ...
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, payload: bytes) -> bytes: ...
    @property
    def key(self) -> str: ...
    @property
    def key_bytes(self) -> bytes: ...
    @property
    def scheme(self) -> str: ...
    def __repr__(self) -> str: ...

class Aasv:
    """Codec binding scheme ``aasv`` (a-tier, deterministic, AES-SIV)."""

    def __init__(self, key: str) -> None: ...
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, payload: bytes) -> bytes: ...
    @property
    def key(self) -> str: ...
    @property
    def key_bytes(self) -> bytes: ...
    @property
    def scheme(self) -> str: ...
    def __repr__(self) -> str: ...

class Apsv:
    """Codec binding scheme ``apsv`` (a-tier, probabilistic, AES-SIV)."""

    def __init__(self, key: str) -> None: ...
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, payload: bytes) -> bytes: ...
    @property
    def key(self) -> str: ...
    @property
    def key_bytes(self) -> bytes: ...
    @property
    def scheme(self) -> str: ...
    def __repr__(self) -> str: ...

class Upbc:
    """Codec binding scheme ``upbc`` (u-tier, probabilistic, AES-CBC)."""

    def __init__(self, key: str) -> None: ...
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, payload: bytes) -> bytes: ...
    @property
    def key(self) -> str: ...
    @property
    def key_bytes(self) -> bytes: ...
    @property
    def scheme(self) -> str: ...
    def __repr__(self) -> str: ...

# ---------------------------------------------------------------------------
# Module-level functions
# ---------------------------------------------------------------------------

def encrypt(plaintext: bytes, scheme: str, key: str) -> bytes:
    """Encrypt ``plaintext`` under ``scheme`` and return the framed payload."""

def decrypt(payload: bytes, key: str) -> bytes:
    """Decrypt a framed payload, auto-detecting the scheme from the trailing marker."""

def decrypt_as(payload: bytes, scheme: str, key: str) -> bytes:
    """Decrypt a framed payload, requiring the trailing marker to match ``scheme``."""

def generate_key() -> str:
    """Generate a fresh random 64-byte key as a 128-character lowercase hex string."""

def generate_key_bytes() -> bytes:
    """Generate a fresh random 64-byte key as raw bytes (interop)."""
