# obcrypt-rs

Rust workspace for **obcrypt** — the bytes-in / bytes-out
cryptographic core of the [oboron](https://oboron.org/) protocol —
plus its sibling distribution surfaces.

## Crates

- [`./obcrypt`](./obcrypt) — the core library: oboron's authenticated
  core encryption schemes operating on raw byte slices. No text
  encoding, no UTF-8 validation.
- [`./obcrypt-py`](./obcrypt-py) — Python bindings via PyO3 / maturin
  (published to PyPI as `obcrypt`).
- [`./obcrypt-wasm`](./obcrypt-wasm) — WebAssembly / JS bindings via
  wasm-bindgen / wasm-pack (ships to npm as `obcrypt-wasm`).
- [`./obcrypt-ffi`](./obcrypt-ffi) — C ABI (a `(ptr, len)` byte-buffer
  surface) for languages without a first-class Rust bridge.

The `obcrypt` command-line interface lives separately in
[`gitlab.com/oboron/oboron-tools-rs`](https://gitlab.com/oboron/oboron-tools-rs)
alongside `ob` (the oboron-cli) and the shared `oboron-cli-core`
crate.

## Layering

`obcrypt` is the bytes-in / bytes-out layer of the oboron protocol.
For the full string-in / string-out protocol — with obtext encoding
and format strings — see the
[`oboron`](https://gitlab.com/oboron/oboron-rs) workspace, which
depends on this crate. The unauthenticated and obfuscation schemes
live in the separate obu layer.

| | `obcrypt` (this) | `oboron` |
|---|---|---|
| Input / output | `&[u8]` / `Vec<u8>` | `&str` / `String` |
| Encoding | none | base64 / base32 / hex |
| UTF-8 validation | no | yes |
| Intended use | binary contexts, embedded, low-level integration | text contexts, identifiers, URLs |

## Build

```bash
cargo build --workspace
cargo test --workspace
```

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
