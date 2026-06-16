# obcrypt

Python bindings for [`obcrypt`][obcrypt-rs] — the bytes-in /
bytes-out cryptographic core of the [oboron][oboron] protocol.
Authenticated symmetric encryption operating on raw bytes; no
text encoding, no UTF-8 validation.

[obcrypt-rs]: https://gitlab.com/oboron/obcrypt-rs
[oboron]: https://oboron.org/

## Install

```bash
pip install obcrypt
```

Wheels are published for Linux (x86_64, aarch64), macOS (arm64,
x86_64), and Windows (x86_64). The extension is built against
PyO3's stable ABI (`abi3-py38`); a single wheel covers CPython
3.8 and later.

## Keys

Keys are 128-character hex strings — the canonical oboron key
form, the same form that comes out of env vars, config files,
and secrets managers. Generate one:

```python
import obcrypt

key = obcrypt.generate_key()
# 'd853c88c2b1f...f10649cb'  (128 lowercase hex chars)
```

Wherever obcrypt takes a key, it takes that string directly.
Raw 64-byte key material is available via the `key_bytes`
property and `generate_key_bytes()` for interop with byte-native
APIs (HSMs, `cryptography`, `pynacl`, custom storage), but the
hex form is the canonical input everywhere.

## Quick start

### Codec class style

Binds a key and scheme together — most ergonomic when one codec
handles many messages.

```python
import obcrypt

key = obcrypt.generate_key()
dsiv = obcrypt.Dsiv(key)

payload = dsiv.encrypt(b"hello")
plaintext = dsiv.decrypt(payload)
assert plaintext == b"hello"
```

Or, from an env var:

```python
import os, obcrypt
dsiv = obcrypt.Dsiv(os.environ["OBCRYPT_KEY"])
```

### Free-function style

Pass the scheme as a string (or a constant from
`obcrypt.schemes`) on each call.

```python
import obcrypt
from obcrypt import schemes

key = obcrypt.generate_key()

payload = obcrypt.encrypt(b"hello", schemes.DSIV, key)
plaintext = obcrypt.decrypt(payload, schemes.DSIV, key)
assert plaintext == b"hello"
```

The output carries no scheme marker, so the same scheme used to
encrypt must be supplied to `decrypt`; a wrong scheme raises
`DecryptionFailed` (the authentication check fails).

## Schemes

All four are authenticated.

| Name      | Determinism   | Algorithm     |
|-----------|---------------|---------------|
| `dsiv`    | deterministic | AES-SIV       |
| `psiv`    | probabilistic | AES-SIV       |
| `dgcmsiv` | deterministic | AES-GCM-SIV   |
| `pgcmsiv` | probabilistic | AES-GCM-SIV   |

`dsiv` is the most general default. See the [obcrypt crate
docs][obcrypt-rs] for algorithm details and per-scheme use-case
guidance.

## Exceptions

All errors inherit from `obcrypt.ObcryptError`:

- `InvalidKey` — bad hex / wrong-length key
- `InvalidScheme` — unknown scheme name
- `EncryptionFailed` — AEAD failure / empty plaintext
- `DecryptionFailed` — tag check, short payload, wrong scheme

## Development build

```bash
pip install maturin
cd obcrypt-py
maturin develop --release
```

## License

Licensed under either of Apache License, Version 2.0
([LICENSE-APACHE](https://gitlab.com/oboron/obcrypt-rs/-/blob/master/obcrypt-py/LICENSE-APACHE))
or the MIT license
([LICENSE-MIT](https://gitlab.com/oboron/obcrypt-rs/-/blob/master/obcrypt-py/LICENSE-MIT))
at your option. Both texts are bundled in the package.
