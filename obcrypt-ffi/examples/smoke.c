/* Minimal C consumer of the obcrypt C ABI — a binary round-trip
 * across the real FFI boundary, including a plaintext with an
 * embedded NUL byte (which the string-based oboron ABI cannot carry).
 *
 * Build & run:
 *   cargo build --release -p obcrypt-ffi
 *   cc examples/smoke.c -Iinclude -Ltarget/release -lobcrypt_ffi -o /tmp/obcrypt-smoke
 *   LD_LIBRARY_PATH=target/release /tmp/obcrypt-smoke
 */
#include <stdio.h>
#include <string.h>
#include "obcrypt.h"

static int fail(const char *what) {
    fprintf(stderr, "%s: %s\n", what, obcrypt_last_error());
    return 1;
}

int main(void) {
    /* A 64-byte key; any bytes will do for a demo. */
    uint8_t key[64];
    for (int i = 0; i < 64; i++) key[i] = (uint8_t)i;

    const uint8_t plaintext[] = { 'h','i',0,'\xff','b','y','t','e','s' };
    const size_t plaintext_len = sizeof plaintext;

    uint8_t *payload = NULL, *decoded = NULL;
    size_t payload_len = 0, decoded_len = 0;

    if (obcrypt_encrypt(plaintext, plaintext_len, "psiv",
                        key, sizeof key, &payload, &payload_len) != OBCRYPT_OK)
        return fail("encrypt");

    if (obcrypt_decrypt(payload, payload_len, "psiv",
                        key, sizeof key, &decoded, &decoded_len) != OBCRYPT_OK)
        return fail("decrypt");

    int ok = decoded_len == plaintext_len
          && memcmp(decoded, plaintext, plaintext_len) == 0;
    printf("payload : %zu bytes\n", payload_len);
    printf("round-trip (incl. embedded NUL): %s\n", ok ? "ok" : "MISMATCH");

    obcrypt_buffer_free(payload, payload_len);
    obcrypt_buffer_free(decoded, decoded_len);
    return ok ? 0 : 1;
}
