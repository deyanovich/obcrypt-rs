# obcrypt

[![Crates.io](https://img.shields.io/crates/v/obcrypt.svg)](https://crates.io/crates/obcrypt)
[![Documentation](https://docs.rs/obcrypt/badge.svg)](https://docs.rs/obcrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

The **bytes-in / bytes-out** cryptographic core of the
[oboron](https://oboron.org/) protocol.

`obcrypt` implements oboron's `a`-tier (authenticated) and `u`-tier
(unauthenticated) encryption schemes operating on raw byte slices. It
does **not** perform any text encoding (no base64, no base32, no hex)
and does **not** validate UTF-8 — plaintext bytes pass through
unchanged.

For the full string-in / string-out oboron protocol (with obtext
encoding, format strings, and the `z`-tier obfuscation schemes), use
the [`oboron`](https://gitlab.com/oboron/oboron-rs) crate, which
depends on this crate.

**Keys** do have a canonical text form: **hex** (128 lowercase
characters). `Key::from_hex` / `Key::to_hex` handle that. obcrypt
intentionally does not support other key encodings (base64, base32,
…) — in cryptography clarity beats compactness, and the size saving
of base64 over hex (86 vs 128 chars for a 64-byte key) isn't enough
to justify the visual noise.

## When to use which

| | `obcrypt` | `oboron` |
|---|---|---|
| Input / output | `&[u8]` / `Vec<u8>` | `&str` / `String` |
| Encoding | none | base64 / base32 / hex |
| UTF-8 validation | no | yes |
| Schemes | `a`-tier, `u`-tier | `a`-tier, `u`-tier, `z`-tier |
| Intended use | binary contexts, embedded, low-level integration | text contexts, identifiers, URLs |

## Quick start

```rust
use obcrypt::{encrypt, decrypt, Key, Scheme};

let key = Key::random();
let payload = encrypt(b"secret data", Scheme::Aasv, &key)?;
let plaintext = decrypt(&payload, &key)?;
assert_eq!(plaintext, b"secret data");
# Ok::<(), obcrypt::Error>(())
```

## Schemes

Each scheme is a 4-letter identifier of the form `<tier><props><alg>`.
Pick by what you need first; the table below ranks the schemes within
each row by recommended preference.

| Tier | Properties | Algorithm | Schemes (preferred → fallback) |
|---|---|---|---|
| `a` (authenticated) | deterministic | SIV / GCM-SIV | **`aasv`** → `aags` |
| `a` (authenticated) | probabilistic | SIV / GCM-SIV | **`apsv`** → `apgs` |
| `u` (unauthenticated, secure) | probabilistic | CBC | `upbc` |

Scheme decision matrix:

- **Need authentication?** Use an a-tier scheme (`aasv` /
  `apsv` / `aags` / `apgs`). u-tier `upbc` provides confidentiality
  only — pair with an outer authenticator if you use it.
- **Need same-plaintext-same-ciphertext?** (e.g. for stable IDs or
  encrypted lookups.) Use a deterministic variant (`aasv`, `aags`).
- **Need different-ciphertext-each-call?** Use a probabilistic
  variant (`apsv`, `apgs`, `upbc`).
- **Want broad nonce-misuse resistance?** Prefer SIV variants (`aasv`,
  `apsv`) — they degrade gracefully under accidental nonce reuse.
- **Want smallest footprint / fastest on AES-NI hardware?** Prefer
  GCM-SIV variants (`aags`, `apgs`).

Plus testing-only schemes behind the `mock` feature flag — `mock1`
(identity) and `mock2` (reverse). They perform **no encryption**
and exist solely for round-tripping unit tests, layering benchmarks,
and as inert fallbacks. Never enable `mock` in a production build.

See [`SECURITY.md`](SECURITY.md) for the full threat model and
algorithm justification.

## Framed payload format

For every scheme, the framed payload returned by `encrypt` is:

```text
[ scheme ciphertext bytes ][ marker[0] ^ ct[0] ][ marker[1] ^ ct[0] ]
```

- *scheme ciphertext bytes* — whatever the per-scheme primitive
  produces (for AEAD schemes that's `nonce || ct || tag` for the
  probabilistic ones, or `ct || tag` for the deterministic ones).
- *marker* — the 2-byte `Scheme` identifier.
- The XOR with `ct[0]` mixes entropy into the marker so it doesn't
  appear as a constant trailer on short payloads.

`decrypt` reverses this, dispatching on the recovered marker;
`decrypt_as` additionally checks that the marker matches the
caller-supplied scheme.

## API

Two parallel forms are provided for every operation:

- **Owned**: returns a fresh `Vec<u8>`. Convenient.
- **`_into`**: appends to a caller-provided `&mut Vec<u8>`. Lets
  integrators (notably `oboron`) avoid an intermediate buffer
  allocation when piping output to a downstream encoder.

```rust
pub fn encrypt(plaintext: &[u8], scheme: Scheme, key: &Key) -> Result<Vec<u8>, Error>;
pub fn encrypt_into(plaintext: &[u8], scheme: Scheme, key: &Key, out: &mut Vec<u8>) -> Result<(), Error>;

pub fn decrypt(payload: &[u8], key: &Key) -> Result<Vec<u8>, Error>;
pub fn decrypt_into(payload: &[u8], key: &Key, out: &mut Vec<u8>) -> Result<(), Error>;

pub fn decrypt_as(payload: &[u8], scheme: Scheme, key: &Key) -> Result<Vec<u8>, Error>;
pub fn decrypt_as_into(payload: &[u8], scheme: Scheme, key: &Key, out: &mut Vec<u8>) -> Result<(), Error>;
```

`decrypt` auto-dispatches on the trailing marker; `decrypt_as`
additionally verifies the marker matches an expected scheme.

Raw per-scheme primitives (without framing) live under
`obcrypt::schemes::{aasv, aags, apsv, apgs, upbc, ...}` for callers
that want to manage the marker themselves — e.g. integrators that
already track the scheme in a separate field, or hot-path consumers
that want to skip the dispatch. Each scheme module exposes the same
four functions: `encrypt`, `encrypt_into`, `decrypt`, `decrypt_into`.

## Performance

obcrypt is designed for low-overhead embedding in performance-
sensitive paths (the `oboron` crate uses it on every `enc` /
`dec` call). Notable choices:

- The owned `encrypt` / `decrypt` calls the underlying AEAD's
  exact-capacity allocator, avoiding intermediate buffers.
- The `_into` form writes ciphertext directly into the caller's
  buffer via `aead::encrypt_in_place`, with a private `TailBuffer`
  adapter to scope the in-place region — zero extra allocations.
- All public functions are `#[inline]`. Combined with workspace-
  level LTO (which the parent workspace `Cargo.toml` enables), the
  cross-crate boundary collapses on the hot path.

## Cargo features

See [`FEATURES.md`](FEATURES.md) for the full matrix. Default is
`secure-schemes` (every production scheme). Schemes are individually
gated so binary size scales with what you actually use.

## Versioning

Pre-1.0; the Rust API may evolve across 0.x minor releases. See
[`CHANGELOG.md`](CHANGELOG.md) for release notes. The framed
payload format and the `Scheme::marker` byte assignments are bound
to the oboron protocol spec and are stable across the 0.x series
— a payload produced by any `obcrypt 0.x` build decrypts under any
other 0.x build with the matching scheme feature enabled.

## License

MIT — see [LICENSE](../LICENSE).
