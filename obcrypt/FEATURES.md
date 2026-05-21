# Cargo features — `obcrypt`

obcrypt's feature flags let you trim the binary down to the schemes
you actually use. Each scheme pulls in only its required cipher
crates.

## Feature matrix

| Feature | Default | Enables | Pulls in |
|---|---|---|---|
| `secure-schemes` | ✓ | All production schemes | `atier` + `utier` |
| `atier` | ✓ (via `secure-schemes`) | All a-tier schemes | `aags`, `apgs`, `aasv`, `apsv` |
| `utier` | ✓ (via `secure-schemes`) | All u-tier schemes | `upbc` |
| `aags` |  | Deterministic AES-GCM-SIV | `aes-gcm-siv` |
| `apgs` |  | Probabilistic AES-GCM-SIV | `aes-gcm-siv` |
| `aasv` |  | Deterministic AES-SIV | `aes-siv` |
| `apsv` |  | Probabilistic AES-SIV | `aes-siv` |
| `upbc` |  | Probabilistic AES-CBC | `aes`, `cipher`, `cbc` |
| `mock` |  | **Testing-only** mock1/mock2 | (none) |

## Always-on dependencies

These are needed regardless of which schemes you enable:

- `zeroize` — `Key` zeroization on drop
- `thiserror` — `Error` derives
- `aead` — `Buffer` trait used by the `_into` API path
- `rand` — random key + nonce generation

## Recipes

### Default (all production schemes)

```toml
obcrypt = "0.1"
```

Pulls in: `aes-gcm-siv`, `aes-siv`, `aes`, `cipher`, `cbc`.

### Smallest binary — single scheme

If you only need `aasv`:

```toml
obcrypt = { version = "0.1", default-features = false, features = ["aasv"] }
```

Pulls in: just `aes-siv`. The `aags`/`apgs`/`apsv`/`upbc` code paths
and their cipher crates are never compiled.

### a-tier only (no `upbc`)

```toml
obcrypt = { version = "0.1", default-features = false, features = ["atier"] }
```

Skips the AES-CBC code path entirely.

### Testing build

For unit tests / benchmarks that want the mock schemes:

```toml
[dev-dependencies]
obcrypt = { version = "0.1", features = ["mock"] }
```

Never enable `mock` in a production binary — `mock1` is the identity
function and `mock2` reverses bytes; neither performs encryption.

## Notes

- All scheme features are **purely additive**. Enabling a scheme adds
  its `Scheme` enum variant and the corresponding `obcrypt::schemes::*`
  module; no existing variant changes meaning when more schemes are
  enabled.
- `Scheme::from_marker` and `Scheme::from_str` only recognize
  feature-enabled schemes. A payload encrypted with a scheme that
  isn't compiled into the consumer's binary will return
  [`Error::UnknownScheme`](https://gitlab.com/uvar/crypt/oboron/obcrypt-rs/-/blob/master/obcrypt/src/error.rs)
  on `decrypt`.
- The framed payload format is identical across feature combinations
  — a payload produced by a `secure-schemes` build can be decrypted
  by a single-scheme build, as long as the receiver's enabled scheme
  matches the producer's.
