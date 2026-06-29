# obcrypt-ffi

A C ABI for [obcrypt](https://oboron.org) — a thin `extern "C"`
surface over the bytes-in/bytes-out crypto core so languages
without a first-class Rust bridge can call it through FFI. It is
the third binding strategy alongside `obcrypt-py` (PyO3) and
`obcrypt-wasm` (wasm-bindgen).

It is the **binary counterpart** to
[`oboron-ffi`](https://gitlab.com/oboron/oboron-rs):
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

Encrypt / decrypt come in two key forms:

- `obcrypt_encrypt` / `obcrypt_decrypt` — key as a raw 64-byte
  `(ptr, len)` buffer.
- `obcrypt_encrypt_hex_key` / `obcrypt_decrypt_hex_key` — key as a
  NUL-terminated 128-character hex string (the canonical oboron key
  form, what env vars and config files carry). Bad hex or wrong
  length is reported as `OBCRYPT_ERR_OBCRYPT`.

Both take the scheme by name. The output carries no marker, so the
same scheme used to encrypt must be named on decrypt; a wrong scheme
fails authentication. Plus `obcrypt_buffer_free`, `obcrypt_last_error`,
and `obcrypt_abi_version` (the package version string);
`OBCRYPT_ABI_VERSION` is the coarse ABI-generation guard. Scheme
features mirror obcrypt's, so a consumer can trim the ABI to the
schemes it needs.

## Notes

- **Threading.** `obcrypt_last_error()` is thread-local: an error
  set on one thread is invisible to another, and the returned
  pointer is valid only until the next `obcrypt_*` call on the same
  thread (copy it if you need to keep it). `encrypt` / `decrypt` are
  otherwise stateless and safe to call concurrently.
- **Determinism.** `dsiv` / `dgcmsiv` are deterministic — same
  plaintext + key yields the same output, leaking plaintext
  equality. `psiv` / `pgcmsiv` draw a fresh nonce per call. The
  choice is purely the scheme name; there is no API difference.
- **Windows.** The artifact is `obcrypt_ffi.dll` plus an import
  library; the header and contract are identical. (`extern "C"`
  exports the symbols unmangled on MSVC; no `.def` file is needed.)
