# obcrypt

Python bindings for [`obcrypt`][obcrypt-rs] — the bytes-in /
bytes-out cryptographic core of the [oboron][oboron] protocol.
Authenticated (a-tier) and unauthenticated-but-real (u-tier)
symmetric encryption operating on raw bytes; no text encoding,
no UTF-8 validation.

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
aasv = obcrypt.Aasv(key)

payload = aasv.encrypt(b"hello")
plaintext = aasv.decrypt(payload)
assert plaintext == b"hello"
```

Or, from an env var:

```python
import os, obcrypt
aasv = obcrypt.Aasv(os.environ["OBCRYPT_KEY"])
```

### Free-function style

Pass the scheme as a string (or a constant from
`obcrypt.schemes`) on each call.

```python
import obcrypt
from obcrypt import schemes

key = obcrypt.generate_key()

payload = obcrypt.encrypt(b"hello", schemes.AASV, key)
plaintext = obcrypt.decrypt(payload, key)         # auto-detect
assert plaintext == b"hello"
```

`decrypt` auto-detects the scheme from the trailing marker in
the payload. Use `decrypt_as(payload, scheme, key)` if you want
to require a specific scheme and reject mismatches.

## Schemes

| Name   | Tier        | Determinism   | Algorithm     |
|--------|-------------|---------------|---------------|
| `aags` | a (auth)    | deterministic | AES-GCM-SIV   |
| `apgs` | a (auth)    | probabilistic | AES-GCM-SIV   |
| `aasv` | a (auth)    | deterministic | AES-SIV       |
| `apsv` | a (auth)    | probabilistic | AES-SIV       |
| `upbc` | u (unauth)  | probabilistic | AES-CBC       |

See the [obcrypt crate docs][obcrypt-rs] for algorithm details
and per-scheme use-case guidance.

## Exceptions

All errors inherit from `obcrypt.ObcryptError`:

- `InvalidKey` — bad hex / wrong-length key
- `InvalidScheme` — unknown scheme name / marker mismatch
- `EncryptionFailed` — AEAD failure / empty plaintext
- `DecryptionFailed` — tag check, padding, short payload, etc.

## Development build

```bash
pip install maturin
cd obcrypt-py
maturin develop --release
```

## License

MIT — see [LICENSE](LICENSE).
