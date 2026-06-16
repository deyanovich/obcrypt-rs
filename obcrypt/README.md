# obcrypt

[![Crates.io](https://img.shields.io/crates/v/obcrypt.svg)](https://crates.io/crates/obcrypt)
[![Documentation](https://docs.rs/obcrypt/badge.svg)](https://docs.rs/obcrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

The **bytes-in / bytes-out** cryptographic core of the
[oboron](https://oboron.org/) protocol.

`obcrypt` implements oboron's authenticated core encryption schemes
operating on raw byte slices. It does **not** perform any text
encoding (no base64, no base32, no hex) and does **not** validate
UTF-8 — plaintext bytes pass through unchanged.

For the full string-in / string-out oboron protocol (with obtext
encoding and format strings), use the
[`oboron`](https://gitlab.com/oboron/oboron-rs) crate, which depends
on this one. The unauthenticated and obfuscation schemes live in the
separate obu layer, not here.

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
| Intended use | binary contexts, embedded, low-level integration | text contexts, identifiers, URLs |

## Quick start

```rust
use obcrypt::{encrypt, decrypt, Key, Scheme};

let key = Key::random();
let output = encrypt(b"secret data", Scheme::Dsiv, &key)?;
let plaintext = decrypt(&output, Scheme::Dsiv, &key)?;
assert_eq!(plaintext, b"secret data");
# Ok::<(), obcrypt::Error>(())
```

The output carries no scheme marker — the same `Scheme` used to
encrypt must be supplied to `decrypt`. Supplying the wrong scheme
fails the authentication check rather than returning garbage.

## Schemes

A scheme identifier is `<property><algorithm>`: the first letter is
`d` (deterministic) or `p` (probabilistic); the rest names the AEAD
(`siv` = AES-SIV, `gcmsiv` = AES-GCM-SIV). All four are authenticated.

| Properties | Algorithm | Scheme |
|---|---|---|
| deterministic | AES-SIV | **`dsiv`** |
| probabilistic | AES-SIV | **`psiv`** |
| deterministic | AES-GCM-SIV | `dgcmsiv` |
| probabilistic | AES-GCM-SIV | `pgcmsiv` |

Scheme decision matrix:

- **Need same-plaintext-same-output?** (e.g. for stable IDs or
  encrypted lookups.) Use a deterministic variant (`dsiv`,
  `dgcmsiv`). Otherwise use a probabilistic variant (`psiv`,
  `pgcmsiv`), which draws a fresh nonce per call.
- **Want broad nonce-misuse resistance with a clean security
  story?** Prefer the SIV variants (`dsiv`, `psiv`) — `dsiv` is the
  most general default.
- **Want smallest footprint / fastest on AES-NI hardware?** Prefer
  the GCM-SIV variants (`dgcmsiv`, `pgcmsiv`). SIV typically wins on
  short inputs; GCM-SIV scales better and pulls ahead on
  medium-to-large inputs (crossover around 256 bytes in practice).

Plus testing-only schemes behind the `mock` feature flag — `mock1`
(identity) and `mock2` (reverse). They perform **no encryption**
and exist solely for round-tripping unit tests, layering benchmarks,
and as inert fallbacks. Never enable `mock` in a production build.

See [`SECURITY.md`](SECURITY.md) for the full threat model and
algorithm justification.

## Output format

The output of `encrypt` is exactly the scheme's AEAD output — there
is no scheme marker:

- deterministic: `siv-tag || ciphertext` (`dsiv`) or
  `ciphertext || tag` (`dgcmsiv`).
- probabilistic: a fresh nonce is prepended.

The scheme is part of the caller's context on both sides; obcrypt
follows oboron's no-marker model, where decrypting under the wrong
scheme fails the authentication check.

## API

Two parallel forms are provided for every operation:

- **Owned**: returns a fresh `Vec<u8>`. Convenient.
- **`_into`**: appends to a caller-provided `&mut Vec<u8>`. Lets
  integrators (notably `oboron`) avoid an intermediate buffer
  allocation when piping output to a downstream encoder.

```rust
pub fn encrypt(plaintext: &[u8], scheme: Scheme, key: &Key) -> Result<Vec<u8>, Error>;
pub fn encrypt_into(plaintext: &[u8], scheme: Scheme, key: &Key, out: &mut Vec<u8>) -> Result<(), Error>;

pub fn decrypt(scheme_output: &[u8], scheme: Scheme, key: &Key) -> Result<Vec<u8>, Error>;
pub fn decrypt_into(scheme_output: &[u8], scheme: Scheme, key: &Key, out: &mut Vec<u8>) -> Result<(), Error>;
```

Raw per-scheme primitives live under
`obcrypt::schemes::{dsiv, psiv, dgcmsiv, pgcmsiv, ...}` for callers
that already know the scheme statically and want to skip the enum
dispatch. Each scheme module exposes the same four functions:
`encrypt`, `encrypt_into`, `decrypt`, `decrypt_into`.

## Key material

A single 64-byte master key serves every scheme:

- `dsiv` / `psiv` use the full 64 bytes directly as the AES-SIV key.
- `dgcmsiv` / `pgcmsiv` derive a 32-byte AES-256-GCM-SIV key from the
  master with `HKDF-Expand` (HMAC-SHA-256, info `gcmsiv` shared by both
  GCM-SIV schemes; the Extract step is skipped, as the master is
  already a uniform pseudorandom key).

`Key` is `ZeroizeOnDrop` and redacts its `Debug` output.

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

See [`FEATURES.md`](FEATURES.md) for the full matrix. By default
every production scheme (`dgcmsiv`, `pgcmsiv`, `dsiv`, `psiv`) is
enabled; schemes are individually gated so binary size scales with
what you actually use.

## Versioning

`obcrypt` follows semver from 1.0. See [`CHANGELOG.md`](CHANGELOG.md)
for release notes. The scheme output formats are bound to the oboron
protocol spec: output produced by any `obcrypt 1.x` build decrypts
under any other 1.x build with the matching scheme feature enabled.

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as
above, without any additional terms or conditions.
