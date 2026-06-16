# obcrypt-ffi — TODO

Next steps for the C ABI binding. Written for a cold start: read
the Context first, then work the steps in priority order.

## Context

`obcrypt-ffi` is a C ABI over the obcrypt core — the third binding
strategy alongside `obcrypt-py` (PyO3) and `obcrypt-wasm`
(wasm-bindgen). It is the **binary** counterpart to `oboron-ffi`
(in the sibling `oboron-rs` workspace): oboron is
string-in/string-out and its ABI uses NUL-terminated strings;
obcrypt is bytes-in/bytes-out, so this ABI passes `(ptr, len)`
buffers that carry arbitrary bytes. obsigil's CBOR encoding rides
this path, so **`obsigil-ffi` will depend on this crate** for its
binary mandate/manifest payloads.

Current state — **scaffold complete and verified**:

- `src/lib.rs` exposes `obcrypt_encrypt`, `obcrypt_decrypt`
  (both take the scheme by name), plus `obcrypt_buffer_free` and
  `obcrypt_last_error` — 4 functions, all exported unmangled.
- The contract (full text in the `src/lib.rs` module docs and
  `README.md`): input buffers are `(const uint8_t *ptr, size_t
  len)` (null only when empty); the scheme is a name string; each
  output buffer is heap-allocated (a `Box<[u8]>`, so free needs
  only `(ptr, len)`) and caller-owned, released with
  `obcrypt_buffer_free`; the return is a status code (0 ok, <0 FFI
  fault, >0 obcrypt error) with a message from the thread-local
  `obcrypt_last_error`; panics are caught via `catch_unwind`,
  centralised in the `finish` helper.
- `include/obcrypt.h` is the committed reference header;
  `cbindgen.toml` regenerates it.
- `examples/smoke.c` round-trips a plaintext with an embedded NUL
  byte — the case the string ABI can't serve.

Confirm the baseline before changing anything:

- `cargo test -p obcrypt-ffi` → 4 passing tests.
- `cargo build -p obcrypt-ffi` then build & run `examples/smoke.c`
  (command in its header) → prints a live binary round-trip.
- `nm -D --defined-only target/debug/libobcrypt_ffi.so | grep
  obcrypt_` → 4 `T` symbols.

## Next steps

1. **Wire this into `obsigil-ffi` when it lands.** This crate
   exists for obsigil's binary (CBOR) payloads. When `obsigil-ffi`
   is built, it should depend on `obcrypt-ffi` for the bytes path
   and on `oboron-ffi` for the text path — mirroring how
   `obsigil-rs` itself splits (oboron for text, obcrypt for CBOR).

2. **cbindgen drift guard.** `include/obcrypt.h` is committed and
   hand-maintainable. Add a CI check that runs `cbindgen --config
   cbindgen.toml` and fails if the output differs from the
   committed header, so the ABI surface can't silently drift.

3. **Conformance vectors through the ABI.** Run the obcrypt test
   vectors through the C ABI and assert byte-identical output with
   the Rust/Python/wasm paths — the real proof of conformance.

4. **Key ergonomics.** The ABI takes a raw 64-byte key
   (`Key::from_slice`). Consider an optional hex-key entry point
   (`obcrypt_*_hex_key`, or a `key_is_hex` flag) if downstream
   consumers commonly hold hex keys, to avoid each binding
   re-implementing hex decoding. Keep raw bytes as the primary.

5. **Artifact distribution + ABI versioning.** Same as oboron-ffi:
   decide prebuilt-per-platform vs build-from-source for
   `libobcrypt_ffi`, and once the surface settles document the
   stability contract (the header is the contract) and add an
   `obcrypt_abi_version()`.

6. **Platform & polish.**
   - Windows symbol export / calling convention and the
     `obcrypt_ffi.dll` naming difference.
   - A test that deliberately triggers and catches a panic to
     exercise the `catch_unwind` path.
   - Document the threading model (`last_error` is per-thread).
   - The deterministic schemes (`dgcmsiv`/`dsiv`) vs probabilistic
     (`pgcmsiv`/`psiv`) distinction is the caller's to choose via
     the scheme name; no API change needed, but note it in consumer
     docs.
