"""Scheme name constants for obcrypt.

Use these instead of bare strings for typo-resistance and editor
autocomplete::

    import obcrypt
    from obcrypt import schemes

    payload = obcrypt.encrypt(b"x", schemes.DSIV, key)

is equivalent to passing the literal ``"dsiv"``, but a typo on the
constant (``schemes.DSVI``) fails at import / attribute access rather
than at the first encrypt call.

Schemes correspond one-to-one with ``obcrypt::Scheme`` variants in the
Rust crate; see the obcrypt crate docs for the algorithm and use-case
guidance for each.
"""

DGCMSIV: str = "dgcmsiv"
PGCMSIV: str = "pgcmsiv"
DSIV: str = "dsiv"
PSIV: str = "psiv"

__all__ = ["DGCMSIV", "PGCMSIV", "DSIV", "PSIV"]
