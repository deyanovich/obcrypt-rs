# obcrypt-wasm

WebAssembly / JavaScript bindings for [`obcrypt`][obcrypt-rs] — the
bytes-in / bytes-out cryptographic core of the [oboron][oboron]
protocol. Authenticated symmetric encryption operating on raw
bytes; no text encoding, no UTF-8 validation.

[obcrypt-rs]: https://gitlab.com/oboron/obcrypt-rs
[oboron]: https://oboron.org/

## Install

```bash
npm install obcrypt-wasm
```

The package is built with [`wasm-pack`][wasm-pack]; the compiled
wasm and generated TypeScript declarations ship in the package.
Byte arguments and results are `Uint8Array`; keys are hex strings.

[wasm-pack]: https://rustwasm.github.io/wasm-pack/

## Keys

Keys are 128-character hex strings — the canonical oboron key
form, the same form that comes out of env vars, config files, and
secrets managers. Generate one:

```js
import * as obcrypt from "obcrypt-wasm";

const key = obcrypt.generateKey();
// 'd853c88c2b1f...f10649cb'  (128 lowercase hex chars)
```

Wherever obcrypt takes a key, it takes that string directly. Raw
64-byte key material is available via the `keyBytes` getter and
`generateKeyBytes()` for byte-native interop, but the hex form is
the canonical input everywhere.

## Quick start

### Codec class style

Binds a key and scheme together — most ergonomic when one codec
handles many messages.

```js
import { Dsiv, generateKey } from "obcrypt-wasm";

const key = generateKey();
const dsiv = new Dsiv(key);

const payload = dsiv.encrypt(new TextEncoder().encode("hello"));
const plaintext = dsiv.decrypt(payload);
// new TextDecoder().decode(plaintext) === "hello"
```

### Free-function style

Pass the scheme as a string on each call.

```js
import { encrypt, decrypt, generateKey } from "obcrypt-wasm";

const key = generateKey();
const data = new TextEncoder().encode("hello");

const payload = encrypt(data, "dsiv", key);
const plaintext = decrypt(payload, "dsiv", key);
```

The output carries no scheme marker, so the same scheme used to
encrypt must be supplied to `decrypt`; a wrong scheme throws (the
authentication check fails).

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

## Errors

Operations throw a JS `Error` whose message describes the failure
— bad hex / wrong-length key, unknown scheme name, AEAD failure /
empty plaintext, or a failed decryption (tag check, short payload,
wrong scheme). Wrap calls in `try`/`catch` to handle them.

## Development build

Requires the `wasm32-unknown-unknown` target and
[`wasm-pack`][wasm-pack]:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

cd obcrypt-wasm

# Bundler target (webpack, Vite, …); also: --target web | nodejs
wasm-pack build --release --target bundler

# Run the roundtrip tests in Node
wasm-pack test --node
```

The generated npm package lands in `pkg/`.

## License

Licensed under either of Apache License, Version 2.0
([LICENSE-APACHE](https://gitlab.com/oboron/obcrypt-rs/-/blob/master/obcrypt-wasm/LICENSE-APACHE))
or the MIT license
([LICENSE-MIT](https://gitlab.com/oboron/obcrypt-rs/-/blob/master/obcrypt-wasm/LICENSE-MIT))
at your option. Both texts are bundled in the package.
