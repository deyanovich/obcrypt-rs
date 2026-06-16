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
    """Unknown scheme name."""

class EncryptionFailed(ObcryptError):
    """AEAD primitive failure, or empty plaintext passed to ``encrypt``."""

class DecryptionFailed(ObcryptError):
    """Tag check failure, short payload, or wrong scheme supplied."""

# ---------------------------------------------------------------------------
# Codec classes
# ---------------------------------------------------------------------------
#
# Each codec binds a scheme to a key. ``key`` is a 128-character hex
# string — the canonical oboron key form. Bad hex / wrong length raises
# ``InvalidKey``. ``decrypt`` expects output produced under the codec's
# scheme; a wrong scheme fails the authentication check.

class Dgcmsiv:
    """Codec binding scheme ``dgcmsiv`` (deterministic, AES-GCM-SIV)."""

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

class Pgcmsiv:
    """Codec binding scheme ``pgcmsiv`` (probabilistic, AES-GCM-SIV)."""

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

class Dsiv:
    """Codec binding scheme ``dsiv`` (deterministic, AES-SIV)."""

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

class Psiv:
    """Codec binding scheme ``psiv`` (probabilistic, AES-SIV)."""

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
    """Encrypt ``plaintext`` under ``scheme`` and return the scheme output bytes."""

def decrypt(payload: bytes, scheme: str, key: str) -> bytes:
    """Decrypt scheme output under ``scheme``; a wrong scheme fails authentication."""

def generate_key() -> str:
    """Generate a fresh random 64-byte key as a 128-character lowercase hex string."""

def generate_key_bytes() -> bytes:
    """Generate a fresh random 64-byte key as raw bytes (interop)."""
