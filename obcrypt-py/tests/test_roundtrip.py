"""Behavioral tests for the obcrypt Python binding.

Exercises the PyO3 boundary the Rust core tests cannot reach: round-trip
correctness across all four schemes (free-function and codec styles),
codec/free-function interop, deterministic-vs-probabilistic behavior,
key handling, and the error-to-exception mapping.

Run with the wheel installed (e.g. ``maturin develop`` then ``pytest``).
"""

import pytest

import obcrypt
from obcrypt import schemes

# A fixed, valid 128-character lowercase-hex key (64 bytes). Canonical
# oboron key form; used so deterministic schemes are reproducible.
KEY = "0123456789abcdef" * 8

ALL_SCHEMES = [schemes.DSIV, schemes.PSIV, schemes.DGCMSIV, schemes.PGCMSIV]
DETERMINISTIC = [schemes.DSIV, schemes.DGCMSIV]
PROBABILISTIC = [schemes.PSIV, schemes.PGCMSIV]
CODECS = {
    schemes.DSIV: obcrypt.Dsiv,
    schemes.PSIV: obcrypt.Psiv,
    schemes.DGCMSIV: obcrypt.Dgcmsiv,
    schemes.PGCMSIV: obcrypt.Pgcmsiv,
}


# --------------------------------------------------------------------------
# Round-trip correctness
# --------------------------------------------------------------------------


@pytest.mark.parametrize("scheme", ALL_SCHEMES)
def test_free_function_roundtrip(scheme):
    pt = b"the quick brown fox"
    payload = obcrypt.encrypt(pt, scheme, KEY)
    assert isinstance(payload, bytes)
    assert payload != pt
    assert obcrypt.decrypt(payload, scheme, KEY) == pt


@pytest.mark.parametrize("scheme", ALL_SCHEMES)
def test_codec_roundtrip(scheme):
    codec = CODECS[scheme](KEY)
    pt = b"\x00\x01\x02 binary \xff\xfe payload \x00"
    payload = codec.encrypt(pt)
    assert isinstance(payload, bytes)
    assert codec.decrypt(payload) == pt
    assert codec.scheme == scheme


@pytest.mark.parametrize("scheme", ALL_SCHEMES)
def test_codec_and_free_function_interop(scheme):
    codec = CODECS[scheme](KEY)
    pt = b"interop"
    # Codec-encrypted output decrypts via the free function...
    assert obcrypt.decrypt(codec.encrypt(pt), scheme, KEY) == pt
    # ...and free-function output decrypts via the codec.
    assert codec.decrypt(obcrypt.encrypt(pt, scheme, KEY)) == pt


def test_empty_plaintext_roundtrips_only_if_nonempty():
    # Empty plaintext is rejected (see error-mapping tests); a 1-byte
    # plaintext is the smallest valid input and must round-trip.
    for scheme in ALL_SCHEMES:
        payload = obcrypt.encrypt(b"\x00", scheme, KEY)
        assert obcrypt.decrypt(payload, scheme, KEY) == b"\x00"


# --------------------------------------------------------------------------
# Deterministic vs probabilistic
# --------------------------------------------------------------------------


@pytest.mark.parametrize("scheme", DETERMINISTIC)
def test_deterministic_schemes_are_deterministic(scheme):
    pt = b"same input, same output"
    assert obcrypt.encrypt(pt, scheme, KEY) == obcrypt.encrypt(pt, scheme, KEY)


@pytest.mark.parametrize("scheme", PROBABILISTIC)
def test_probabilistic_schemes_differ_but_roundtrip(scheme):
    pt = b"same input, fresh randomness"
    a = obcrypt.encrypt(pt, scheme, KEY)
    b = obcrypt.encrypt(pt, scheme, KEY)
    assert a != b
    assert obcrypt.decrypt(a, scheme, KEY) == pt
    assert obcrypt.decrypt(b, scheme, KEY) == pt


# --------------------------------------------------------------------------
# Key handling
# --------------------------------------------------------------------------


def test_generate_key_is_128_char_lowercase_hex():
    k = obcrypt.generate_key()
    assert isinstance(k, str)
    assert len(k) == 128
    assert k == k.lower()
    int(k, 16)  # valid hex; raises ValueError otherwise


def test_generate_key_bytes_is_64_bytes():
    kb = obcrypt.generate_key_bytes()
    assert isinstance(kb, bytes)
    assert len(kb) == 64


def test_generate_key_is_random():
    assert obcrypt.generate_key() != obcrypt.generate_key()


def test_key_properties_match_input():
    codec = obcrypt.Dsiv(KEY)
    assert codec.key == KEY
    assert isinstance(codec.key_bytes, bytes)
    assert len(codec.key_bytes) == 64
    assert codec.key_bytes == bytes.fromhex(KEY)


# --------------------------------------------------------------------------
# Error -> exception mapping
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_key",
    [
        "xyz",                 # non-hex characters
        "abc",                 # odd length / too short
        "00" * 32,             # 64 chars = 32 bytes, wrong length
        ("ab" * 64).upper(),   # correct length but uppercase (non-canonical)
    ],
)
def test_invalid_key_raises_invalid_key(bad_key):
    with pytest.raises(obcrypt.InvalidKey):
        obcrypt.Dsiv(bad_key)
    with pytest.raises(obcrypt.InvalidKey):
        obcrypt.encrypt(b"x", schemes.DSIV, bad_key)


def test_unknown_scheme_raises_invalid_scheme():
    with pytest.raises(obcrypt.InvalidScheme):
        obcrypt.encrypt(b"x", "nope", KEY)
    with pytest.raises(obcrypt.InvalidScheme):
        obcrypt.decrypt(b"x" * 64, "nope", KEY)


def test_empty_plaintext_raises_encryption_failed():
    with pytest.raises(obcrypt.EncryptionFailed):
        obcrypt.encrypt(b"", schemes.DSIV, KEY)
    with pytest.raises(obcrypt.EncryptionFailed):
        obcrypt.Dgcmsiv(KEY).encrypt(b"")


def test_wrong_scheme_decrypt_raises_decryption_failed():
    payload = obcrypt.encrypt(b"secret", schemes.DSIV, KEY)
    with pytest.raises(obcrypt.DecryptionFailed):
        obcrypt.decrypt(payload, schemes.PSIV, KEY)


def test_wrong_key_decrypt_raises_decryption_failed():
    payload = obcrypt.encrypt(b"secret", schemes.DSIV, KEY)
    other = obcrypt.generate_key()
    with pytest.raises(obcrypt.DecryptionFailed):
        obcrypt.decrypt(payload, schemes.DSIV, other)


@pytest.mark.parametrize("scheme", ALL_SCHEMES)
def test_tampered_payload_raises_decryption_failed(scheme):
    payload = bytearray(obcrypt.encrypt(b"secret message", scheme, KEY))
    payload[-1] ^= 0xFF  # flip a bit in the authentication tag
    with pytest.raises(obcrypt.DecryptionFailed):
        obcrypt.decrypt(bytes(payload), scheme, KEY)


@pytest.mark.parametrize("scheme", ALL_SCHEMES)
def test_short_and_empty_payload_raise_decryption_failed(scheme):
    with pytest.raises(obcrypt.DecryptionFailed):
        obcrypt.decrypt(b"", scheme, KEY)
    with pytest.raises(obcrypt.DecryptionFailed):
        obcrypt.decrypt(b"\x00", scheme, KEY)


# --------------------------------------------------------------------------
# Exception hierarchy & misc surface
# --------------------------------------------------------------------------


def test_exception_hierarchy():
    for exc in (
        obcrypt.InvalidKey,
        obcrypt.InvalidScheme,
        obcrypt.EncryptionFailed,
        obcrypt.DecryptionFailed,
    ):
        assert issubclass(exc, obcrypt.ObcryptError)
    assert issubclass(obcrypt.ObcryptError, Exception)


def test_subclass_is_caught_as_base():
    with pytest.raises(obcrypt.ObcryptError):
        obcrypt.Dsiv("not-a-valid-key")


def test_repr_redacts_key():
    r = repr(obcrypt.Dsiv(KEY))
    assert "Dsiv" in r
    assert "redacted" in r
    assert KEY not in r


def test_version_is_nonempty_string():
    assert isinstance(obcrypt.__version__, str)
    assert obcrypt.__version__
