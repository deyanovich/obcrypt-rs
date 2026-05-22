"""Scheme name constants for obcrypt.

Use these instead of bare strings for typo-resistance and editor
autocomplete::

    import obcrypt
    from obcrypt import schemes

    payload = obcrypt.encrypt(b"x", schemes.AASV, key)

is equivalent to passing the literal ``"aasv"``, but a typo on the
constant (``schemes.AAVS``) fails at import / attribute access rather
than at the first encrypt call.

Schemes correspond one-to-one with ``obcrypt::Scheme`` variants in the
Rust crate; see the obcrypt crate docs for the algorithm and use-case
guidance for each.
"""

AAGS: str = "aags"
APGS: str = "apgs"
AASV: str = "aasv"
APSV: str = "apsv"
UPBC: str = "upbc"

__all__ = ["AAGS", "APGS", "AASV", "APSV", "UPBC"]
