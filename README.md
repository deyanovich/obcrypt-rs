# obcrypt-rs

Rust workspace for **obcrypt** — the bytes-in / bytes-out
cryptographic core of the [oboron](https://oboron.org/) protocol.

## Crates

- [`./obcrypt`](./obcrypt) — the core library: `a`-tier (authenticated)
  and `u`-tier (unauthenticated) encryption schemes operating on raw
  byte slices. No text encoding, no UTF-8 validation, no z-tier.

The `obcrypt` command-line interface lives separately in
[`gitlab.com/oboron/oboron-tools-rs`](https://gitlab.com/oboron/oboron-tools-rs)
alongside `ob` (the oboron-cli) and the shared `oboron-cli-core`
crate.

## Layering

`obcrypt` is the bytes-in / bytes-out layer of the oboron protocol.
For the full string-in / string-out protocol — with obtext encoding,
format strings, and the `z`-tier obfuscation schemes — see the
[`oboron`](https://gitlab.com/oboron/oboron-rs) workspace, which
depends on this crate.

| | `obcrypt` (this) | `oboron` |
|---|---|---|
| Input / output | `&[u8]` / `Vec<u8>` | `&str` / `String` |
| Encoding | none | base64 / base32 / hex |
| UTF-8 validation | no | yes |
| Schemes | `a`-tier, `u`-tier | `a`-tier, `u`-tier, `z`-tier |
| Intended use | binary contexts, embedded, low-level integration | text contexts, identifiers, URLs |

## Build

```bash
cargo build --workspace
cargo test --workspace
```

## License

MIT — see [LICENSE](LICENSE).
