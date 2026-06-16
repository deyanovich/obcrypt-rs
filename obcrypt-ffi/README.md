# obcrypt-ffi

A C ABI for [obcrypt](https://oboron.org) — a thin `extern "C"`
surface over the bytes-in/bytes-out crypto core so languages
without a first-class Rust bridge can call it through FFI. It is
the third binding strategy alongside `obcrypt-py` (PyO3) and
`obcrypt-wasm` (wasm-bindgen).

It is the **binary counterpart** to [`oboron-ffi`](https://gitlab.com/oboron/oboron-rs):
oboron is string-in/string-out, so its ABI uses NUL-terminated C
strings; obcrypt is bytes-in/bytes-out, so this ABI passes
`(ptr, len)` buffers that carry arbitrary bytes — NUL, `0xFF`,
anything. obsigil's CBOR encoding rides this binary path, which is
why `obsigil-ffi` will need this crate.

## The contract

- **Buffers in** — `(const uint8_t *ptr, size_t len)`. A null
  `ptr` is allowed only when `len == 0`.
- **Scheme** — a name string (`"psiv"`, `"dsiv"`, …) as a
  NUL-terminated `const char *`.
- **Buffers out** — heap-allocated, written through
  `(*out, *out_len)`, **owned by the caller**, released with
  `obcrypt_buffer_free(ptr, len)` (pass back the same `ptr` and
  `len`). Never libc `free`.
- **Return** — a status code: `0` (`OBCRYPT_OK`) on success,
  negative for an FFI-layer fault, positive for an obcrypt error.
  On any nonzero return do **not** read `*out`; fetch a message
  from `obcrypt_last_error()` (valid until the next call on the
  thread).
- **Panics** never cross the boundary — every entry point is
  wrapped in `catch_unwind`.

## Build

```sh
cargo build --release -p obcrypt-ffi
# → target/release/libobcrypt_ffi.{so,dylib,dll}  (cdylib)
#   target/release/libobcrypt_ffi.a               (staticlib)
```

The committed header is [`include/obcrypt.h`](include/obcrypt.h);
regenerate it with [cbindgen](https://github.com/mozilla/cbindgen):

```sh
cbindgen --config cbindgen.toml --output include/obcrypt.h
```

## Try it

[`examples/smoke.c`](examples/smoke.c) — build/run command in its
header. It round-trips a plaintext containing an embedded NUL byte,
demonstrating the binary path the string ABI can't serve.

For higher-level languages the buffer pattern is: pass
`(pointer, length)` in; receive an out-pointer plus a length;
copy exactly `length` bytes out; hand the buffer back to
`obcrypt_buffer_free`.

## Scope

Exposes `obcrypt_encrypt` and `obcrypt_decrypt` — each taking the
scheme by name and a 64-byte raw key. The output carries no marker,
so the same scheme used to encrypt must be named on decrypt; a wrong
scheme fails authentication. Scheme features mirror obcrypt's, so a
consumer can trim the ABI to the schemes it needs.
