/* obcrypt C ABI — committed reference header.
 *
 * The binary counterpart to oboron's C ABI: where oboron passes
 * NUL-terminated strings, obcrypt passes (ptr, len) byte buffers,
 * so payloads may contain NUL, 0xFF, anything. Regenerate from the
 * Rust source with:
 *   cbindgen --config cbindgen.toml --output include/obcrypt.h
 *
 * Contract (see src/lib.rs for the full text):
 *  - Input buffers are (const uint8_t *ptr, size_t len); a null ptr
 *    is allowed only when len == 0.
 *  - `scheme` is a name string ("psiv", "dsiv", …), NUL-terminated.
 *  - Each output buffer is heap-allocated and owned by the caller,
 *    who MUST release it with obcrypt_buffer_free(ptr, len), passing
 *    back the same (ptr, len). Never libc free.
 *  - Return is a status code: 0 = OBCRYPT_OK, < 0 = FFI-layer fault,
 *    > 0 = obcrypt error. On any nonzero return do NOT read *out;
 *    fetch a message with obcrypt_last_error().
 */
#ifndef OBCRYPT_H
#define OBCRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OBCRYPT_OK 0
#define OBCRYPT_ERR_NULL_ARG -1
#define OBCRYPT_ERR_UTF8 -2
#define OBCRYPT_ERR_BAD_SCHEME -3
#define OBCRYPT_ERR_PANIC -4
#define OBCRYPT_ERR_OBCRYPT 1

/* Borrow this thread's last error message (NUL-terminated), or NULL
 * if the last call succeeded. Valid only until the next obcrypt_*
 * call on this thread; do not free. */
const char *obcrypt_last_error(void);

/* Release a buffer returned through (*out, *out_len). Pass back the
 * same (ptr, len). NULL ptr is a no-op; a wrong length or double
 * free is undefined behavior. */
void obcrypt_buffer_free(uint8_t *ptr, size_t len);

/* Encrypt `plaintext` under the named `scheme` (e.g. "psiv") with a
 * 64-byte `key`. */
int32_t obcrypt_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                        const char *scheme,
                        const uint8_t *key, size_t key_len,
                        uint8_t **out, size_t *out_len);

/* Decrypt `payload` under the named `scheme` (e.g. "psiv") with a
 * 64-byte `key`. The output carries no marker, so the same scheme used
 * to encrypt must be named; a wrong scheme fails authentication. */
int32_t obcrypt_decrypt(const uint8_t *payload, size_t payload_len,
                        const char *scheme,
                        const uint8_t *key, size_t key_len,
                        uint8_t **out, size_t *out_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* OBCRYPT_H */
