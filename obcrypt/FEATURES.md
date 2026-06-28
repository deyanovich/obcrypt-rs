# Cargo features — `obcrypt`

obcrypt's feature flags let you trim the binary down to the schemes
you actually use. Each scheme pulls in only its required cipher
crates.

## Feature matrix

| Feature | Default | Enables | Pulls in |
|---|---|---|---|
| `dgcmsiv` | ✓ | Deterministic AES-GCM-SIV | `aes-gcm-siv`, `hkdf`, `sha2` |
| `pgcmsiv` | ✓ | Probabilistic AES-GCM-SIV | `aes-gcm-siv`, `hkdf`, `sha2` |
| `dsiv` | ✓ | Deterministic AES-SIV | `aes-siv` |
| `psiv` | ✓ | Probabilistic AES-SIV | `aes-siv` |
| `mock` |  | **Testing-only** mock1/mock2 | (none) |

obcrypt's core schemes are all authenticated, so there is no unsecure
subset to distinguish from — no `secure-schemes` aggregate exists at
this layer. The unauthenticated and obfuscation schemes live in the
separate obu layer, not in obcrypt.

## Always-on dependencies

These are needed regardless of which schemes you enable:

- `zeroize` — `Key` zeroization on drop
- `thiserror` — `Error` derives
- `aead` — `Buffer` trait used by the `_into` API path
- `rand` — random key + nonce generation

## Recipes

### Default (all production schemes)

```toml
obcrypt = "1"
```

Pulls in: `aes-gcm-siv`, `aes-siv`, `hkdf`, `sha2`.

### Smallest binary — single scheme

If you only need `dsiv`:

```toml
obcrypt = { version = "1", default-features = false, features = ["dsiv"] }
```

Pulls in: just `aes-siv`. The `dgcmsiv`/`pgcmsiv`/`psiv` code paths
and their cipher crates are never compiled.

### SIV only (no GCM-SIV)

```toml
obcrypt = { version = "1", default-features = false, features = ["dsiv", "psiv"] }
```

Skips the AES-GCM-SIV code path and the HKDF dependency entirely.

### Testing build

For unit tests / benchmarks that want the mock schemes:

```toml
[dev-dependencies]
obcrypt = { version = "1", features = ["mock"] }
```

Never enable `mock` in a production binary — `mock1` is the identity
function and `mock2` reverses bytes; neither performs encryption.

## Notes

- All scheme features are **purely additive**. Enabling a scheme adds
  its `Scheme` enum variant and the corresponding `obcrypt::schemes::*`
  module; no existing variant changes meaning when more schemes are
  enabled.
- `Scheme::from_str` only recognizes feature-enabled **core** schemes;
  a name that isn't compiled into the binary returns
  [`Error::UnknownScheme`](https://gitlab.com/oboron/obcrypt-rs/-/blob/master/obcrypt/src/error.rs).
  The `mock1` / `mock2` schemes are **never** parseable from a string,
  even when `mock` is enabled — a no-encryption scheme must not be
  selectable through a string/config channel; construct them explicitly
  via `Scheme::Mock1` / `Scheme::Mock2`. Because `decrypt` takes a
  `Scheme` value (not a marker), there is no scheme auto-detection — the
  caller supplies the scheme directly.
- The scheme output format is identical across feature combinations:
  output produced by a full-default build decrypts under a
  single-scheme build, as long as the receiver's enabled scheme
  matches the producer's.
