//! C ABI for obcrypt — a thin `extern "C"` surface over the
//! bytes-in/bytes-out crypto core so languages without a first-class
//! Rust bridge (Perl, C#, Java via Panama, Ruby, …) can call it
//! through FFI. It is the **binary** counterpart to `oboron-ffi`:
//! where oboron is string-in/string-out and its ABI uses
//! NUL-terminated C strings, obcrypt is bytes-in/bytes-out, so this
//! ABI passes `(ptr, len)` buffers that can carry arbitrary bytes —
//! NUL, `0xFF`, anything. (obsigil's CBOR encoding rides this path.)
//!
//! The contract every consumer relies on:
//!
//! - **Buffers in** are `(const uint8_t *ptr, size_t len)`. A null
//!   `ptr` is allowed only when `len == 0`.
//! - **Scheme** is a name string (`"psiv"`, `"dsiv"`, …) as a
//!   NUL-terminated UTF-8 `const char *`, parsed by obcrypt.
//! - **Buffers out** are heap-allocated and written through
//!   `(*out, *out_len)`. The caller **owns** the buffer and MUST
//!   release it with [`obcrypt_buffer_free`], passing back the same
//!   `(ptr, len)`. Freeing with libc `free` is undefined behavior —
//!   the buffer is Rust-allocated.
//! - **Return** is a status code: [`OBCRYPT_OK`] (0) on success,
//!   negative for an FFI-layer fault, positive for an obcrypt error.
//!   On any nonzero return do not read `*out`; a human-readable
//!   message is available from [`obcrypt_last_error`].
//! - **Panics** never cross the boundary — every entry point is
//!   wrapped in `catch_unwind`.

// The exported `extern "C"` functions deliberately take raw `(ptr, len)`
// C buffers and dereference them after runtime null checks; the safety
// contract is the documented C ABI, not Rust's `unsafe fn` marker. That
// keeps the entry points callable without `unsafe` (matching the
// buffer-free / last-error accessors and the in-crate tests).
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use obcrypt::Scheme;

/// Success.
pub const OBCRYPT_OK: i32 = 0;
/// A required pointer argument was null (with a nonzero length).
pub const OBCRYPT_ERR_NULL_ARG: i32 = -1;
/// The scheme name was not valid UTF-8.
pub const OBCRYPT_ERR_UTF8: i32 = -2;
/// The scheme name is not a scheme this build supports.
pub const OBCRYPT_ERR_BAD_SCHEME: i32 = -3;
/// A panic was caught at the FFI boundary.
pub const OBCRYPT_ERR_PANIC: i32 = -4;
/// obcrypt rejected the operation; see [`obcrypt_last_error`].
pub const OBCRYPT_ERR_OBCRYPT: i32 = 1;

/// C ABI generation. Independent of the package version: this bumps
/// only on an *incompatible* change to the exported C surface (a
/// removed/renamed symbol, a changed signature or status-code
/// meaning), never on an ordinary release. The committed header is
/// the full contract; this is a coarse `#if`-able guard for
/// consumers (`#if OBCRYPT_ABI_VERSION != 1`).
pub const OBCRYPT_ABI_VERSION: u32 = 1;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_last_error(msg: impl Into<Vec<u8>>) {
    let mut bytes = msg.into();
    bytes.retain(|&b| b != 0);
    let cstr = CString::new(bytes).expect("interior NULs stripped above");
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(cstr));
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

/// Map an obcrypt error onto the status code, recording its text.
fn obcrypt_err(e: obcrypt::Error) -> i32 {
    set_last_error(e.to_string());
    OBCRYPT_ERR_OBCRYPT
}

/// Borrow an incoming `(ptr, len)` byte buffer. Null is permitted
/// only when empty.
///
/// # Safety
/// `ptr` must be null or point to `len` readable bytes that outlive
/// the returned borrow.
unsafe fn bytes<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a [u8], i32> {
    if ptr.is_null() {
        if len == 0 {
            return Ok(&[]);
        }
        set_last_error(format!("argument `{name}` was null"));
        return Err(OBCRYPT_ERR_NULL_ARG);
    }
    Ok(slice::from_raw_parts(ptr, len))
}

/// Parse a scheme-name C string into a [`Scheme`].
///
/// # Safety
/// `p` must be null or a valid NUL-terminated UTF-8 string.
unsafe fn scheme_arg(p: *const c_char) -> Result<Scheme, i32> {
    if p.is_null() {
        set_last_error("argument `scheme` was null");
        return Err(OBCRYPT_ERR_NULL_ARG);
    }
    let s = CStr::from_ptr(p).to_str().map_err(|_| {
        set_last_error("argument `scheme` was not valid UTF-8");
        OBCRYPT_ERR_UTF8
    })?;
    s.parse::<Scheme>().map_err(|_| {
        set_last_error(format!("unknown or unsupported scheme: {s}"));
        OBCRYPT_ERR_BAD_SCHEME
    })
}

fn make_key(key_bytes: &[u8]) -> Result<obcrypt::Key, i32> {
    obcrypt::Key::from_slice(key_bytes).map_err(obcrypt_err)
}

/// Parse a scheme-key C string in canonical hex form (128 lowercase
/// hex characters) into a [`Key`].
///
/// # Safety
/// `p` must be null or a valid NUL-terminated string.
unsafe fn key_hex_arg(p: *const c_char) -> Result<obcrypt::Key, i32> {
    if p.is_null() {
        set_last_error("argument `key_hex` was null");
        return Err(OBCRYPT_ERR_NULL_ARG);
    }
    let s = CStr::from_ptr(p).to_str().map_err(|_| {
        set_last_error("argument `key_hex` was not valid UTF-8");
        OBCRYPT_ERR_UTF8
    })?;
    obcrypt::Key::from_hex(s).map_err(obcrypt_err)
}

/// Run `f` and marshal its `Result<Vec<u8>, i32>` into the ABI: on
/// success hand the bytes out as a `Box<[u8]>` via `(*out, *out_len)`
/// (caller frees with [`obcrypt_buffer_free`]); on error leave the
/// out-params untouched and return the code. Catches panics.
fn finish(out: *mut *mut u8, out_len: *mut usize, f: impl FnOnce() -> Result<Vec<u8>, i32>) -> i32 {
    let ran = catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() || out_len.is_null() {
            set_last_error("output pointer argument was null");
            return OBCRYPT_ERR_NULL_ARG;
        }
        clear_last_error();
        match f() {
            Ok(bytes) => {
                // into_boxed_slice gives an allocation of exactly len,
                // so obcrypt_buffer_free can reconstruct it from
                // (ptr, len) alone — no capacity to track.
                let boxed = bytes.into_boxed_slice();
                let len = boxed.len();
                let ptr = Box::into_raw(boxed) as *mut u8;
                // SAFETY: both out-params checked non-null above.
                unsafe {
                    *out = ptr;
                    *out_len = len;
                }
                OBCRYPT_OK
            }
            Err(code) => code,
        }
    }));
    ran.unwrap_or_else(|_| {
        set_last_error("obcrypt-ffi: caught a panic at the FFI boundary");
        OBCRYPT_ERR_PANIC
    })
}

/// The obcrypt-ffi package version as a static NUL-terminated C
/// string (matches `Cargo.toml`, e.g. `"0.1.0"`). The pointer is
/// borrowed and `'static` — never free it. This is the package
/// version, which moves every release; for the coarse ABI-stability
/// guard see the `OBCRYPT_ABI_VERSION` constant.
#[no_mangle]
pub extern "C" fn obcrypt_abi_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Borrow this thread's last error message as a NUL-terminated C
/// string, or null if the last call on this thread succeeded.
///
/// Valid only until the next `obcrypt_*` call on this thread; copy it
/// if you need to keep it. Do **not** free it.
#[no_mangle]
pub extern "C" fn obcrypt_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| match &*slot.borrow() {
        Some(cstr) => cstr.as_ptr(),
        None => ptr::null(),
    })
}

/// Free a buffer this library returned through `(*out, *out_len)`.
/// Pass back the exact `(ptr, len)` you received. A null `ptr` is a
/// no-op; any other pointer, a wrong length, or a double free is
/// undefined behavior.
#[no_mangle]
pub extern "C" fn obcrypt_buffer_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        // SAFETY: per the contract `ptr`/`len` came from a Box<[u8]>
        // produced in `finish`.
        unsafe { drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len))) };
    }
}

/// Encrypt `plaintext` under the named `scheme` (e.g. `"psiv"`) with
/// a 64-byte `key`. Writes the payload to `(*out, *out_len)`.
#[no_mangle]
pub extern "C" fn obcrypt_encrypt(
    plaintext: *const u8,
    plaintext_len: usize,
    scheme: *const c_char,
    key: *const u8,
    key_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    finish(out, out_len, || {
        let plaintext = unsafe { bytes(plaintext, plaintext_len, "plaintext") }?;
        let scheme = unsafe { scheme_arg(scheme) }?;
        let key = make_key(unsafe { bytes(key, key_len, "key") }?)?;
        obcrypt::encrypt(plaintext, scheme, &key).map_err(obcrypt_err)
    })
}

/// Decrypt `payload` under the named `scheme` (e.g. `"psiv"`) with a
/// 64-byte `key`. The output carries no marker, so the same scheme used
/// to encrypt must be named here; a wrong scheme fails the
/// authentication check. Writes the plaintext to `(*out, *out_len)`.
#[no_mangle]
pub extern "C" fn obcrypt_decrypt(
    payload: *const u8,
    payload_len: usize,
    scheme: *const c_char,
    key: *const u8,
    key_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    finish(out, out_len, || {
        let payload = unsafe { bytes(payload, payload_len, "payload") }?;
        let scheme = unsafe { scheme_arg(scheme) }?;
        let key = make_key(unsafe { bytes(key, key_len, "key") }?)?;
        obcrypt::decrypt(payload, scheme, &key).map_err(obcrypt_err)
    })
}

/// Encrypt `plaintext` under the named `scheme` with the key given as
/// a NUL-terminated 128-character hex string (the canonical oboron
/// key form, what env vars and config files carry). The hex-key
/// counterpart of [`obcrypt_encrypt`] — identical buffer contract and
/// status codes; bad hex / wrong length is reported as
/// [`OBCRYPT_ERR_OBCRYPT`]. Writes the payload to `(*out, *out_len)`.
#[no_mangle]
pub extern "C" fn obcrypt_encrypt_hex_key(
    plaintext: *const u8,
    plaintext_len: usize,
    scheme: *const c_char,
    key_hex: *const c_char,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    finish(out, out_len, || {
        let plaintext = unsafe { bytes(plaintext, plaintext_len, "plaintext") }?;
        let scheme = unsafe { scheme_arg(scheme) }?;
        let key = unsafe { key_hex_arg(key_hex) }?;
        obcrypt::encrypt(plaintext, scheme, &key).map_err(obcrypt_err)
    })
}

/// Decrypt `payload` under the named `scheme` with the key given as a
/// NUL-terminated 128-character hex string. The hex-key counterpart
/// of [`obcrypt_decrypt`] — identical buffer contract and status
/// codes. The output carries no marker, so the same scheme used to
/// encrypt must be named; a wrong scheme fails the authentication
/// check. Writes the plaintext to `(*out, *out_len)`.
#[no_mangle]
pub extern "C" fn obcrypt_decrypt_hex_key(
    payload: *const u8,
    payload_len: usize,
    scheme: *const c_char,
    key_hex: *const c_char,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    finish(out, out_len, || {
        let payload = unsafe { bytes(payload, payload_len, "payload") }?;
        let scheme = unsafe { scheme_arg(scheme) }?;
        let key = unsafe { key_hex_arg(key_hex) }?;
        obcrypt::decrypt(payload, scheme, &key).map_err(obcrypt_err)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cs(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// Copy an out-buffer the way a C caller would, then free it.
    unsafe fn take(ptr: *mut u8, len: usize) -> Vec<u8> {
        let v = slice::from_raw_parts(ptr, len).to_vec();
        obcrypt_buffer_free(ptr, len);
        v
    }

    #[test]
    fn round_trip_arbitrary_bytes() {
        // A plaintext with an embedded NUL and a high byte — exactly
        // what the string ABI could not carry.
        let key = [7u8; 64];
        let pt: &[u8] = b"binary \x00 payload \xff end";

        let mut ct: *mut u8 = ptr::null_mut();
        let mut ct_len = 0usize;
        assert_eq!(
            obcrypt_encrypt(
                pt.as_ptr(),
                pt.len(),
                cs("psiv").as_ptr(),
                key.as_ptr(),
                key.len(),
                &mut ct,
                &mut ct_len
            ),
            OBCRYPT_OK
        );
        let payload = unsafe { take(ct, ct_len) };

        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len = 0usize;
        assert_eq!(
            obcrypt_decrypt(
                payload.as_ptr(),
                payload.len(),
                cs("psiv").as_ptr(),
                key.as_ptr(),
                key.len(),
                &mut out,
                &mut out_len
            ),
            OBCRYPT_OK
        );
        assert_eq!(unsafe { take(out, out_len) }, pt);
        assert!(obcrypt_last_error().is_null());
    }

    #[test]
    fn bad_key_length_is_an_obcrypt_error() {
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len = 0usize;
        let short_key = [0u8; 16];
        let code = obcrypt_encrypt(
            b"x".as_ptr(),
            1,
            cs("psiv").as_ptr(),
            short_key.as_ptr(),
            short_key.len(),
            &mut out,
            &mut out_len,
        );
        assert_eq!(code, OBCRYPT_ERR_OBCRYPT);
        assert!(out.is_null());
        assert!(!obcrypt_last_error().is_null());
    }

    #[test]
    fn unknown_scheme_is_reported() {
        let key = [7u8; 64];
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len = 0usize;
        let code = obcrypt_encrypt(
            b"x".as_ptr(),
            1,
            cs("nope").as_ptr(),
            key.as_ptr(),
            key.len(),
            &mut out,
            &mut out_len,
        );
        assert_eq!(code, OBCRYPT_ERR_BAD_SCHEME);
        assert!(out.is_null());
    }

    #[test]
    fn null_buffer_with_zero_len_is_ok() {
        // A null data pointer is allowed when the length is zero.
        let r = unsafe { bytes(ptr::null(), 0, "x") };
        assert_eq!(r, Ok(&[][..]));
    }

    // A 128-char lowercase-hex key (decodes to the byte pattern
    // 01 23 45 67 89 ab cd ef × 8). Lets the hex-key path be checked
    // against the raw-key path for byte-identical agreement.
    const KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
                           0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn key_hex_bytes() -> Vec<u8> {
        (0..8)
            .flat_map(|_| [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
            .collect()
    }

    #[test]
    fn panic_in_closure_is_caught() {
        // A panic inside the wrapped work must never cross the FFI
        // boundary: catch_unwind turns it into OBCRYPT_ERR_PANIC.
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len = 0usize;
        let code = finish(&mut out, &mut out_len, || panic!("boom"));
        assert_eq!(code, OBCRYPT_ERR_PANIC);
        assert!(out.is_null());
        assert!(!obcrypt_last_error().is_null());
    }

    #[test]
    fn buffer_free_null_is_a_noop() {
        // A null pointer is a documented no-op for any length.
        obcrypt_buffer_free(ptr::null_mut(), 0);
        obcrypt_buffer_free(ptr::null_mut(), 5);
    }

    #[test]
    fn last_error_clears_on_success() {
        let key = [7u8; 64];
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len = 0usize;
        // A failing call records a thread-local error...
        assert_eq!(
            obcrypt_encrypt(
                b"x".as_ptr(),
                1,
                cs("nope").as_ptr(),
                key.as_ptr(),
                key.len(),
                &mut out,
                &mut out_len
            ),
            OBCRYPT_ERR_BAD_SCHEME
        );
        assert!(!obcrypt_last_error().is_null());
        // ...and a subsequent success clears it.
        assert_eq!(
            obcrypt_encrypt(
                b"x".as_ptr(),
                1,
                cs("psiv").as_ptr(),
                key.as_ptr(),
                key.len(),
                &mut out,
                &mut out_len
            ),
            OBCRYPT_OK
        );
        assert!(obcrypt_last_error().is_null());
        obcrypt_buffer_free(out, out_len);
    }

    #[test]
    fn null_out_pointer_is_reported() {
        let key = [7u8; 64];
        let mut out_len = 0usize;
        let code = obcrypt_encrypt(
            b"x".as_ptr(),
            1,
            cs("psiv").as_ptr(),
            key.as_ptr(),
            key.len(),
            ptr::null_mut(),
            &mut out_len,
        );
        assert_eq!(code, OBCRYPT_ERR_NULL_ARG);
    }

    #[test]
    fn null_scheme_is_reported() {
        let key = [7u8; 64];
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len = 0usize;
        let code = obcrypt_encrypt(
            b"x".as_ptr(),
            1,
            ptr::null(),
            key.as_ptr(),
            key.len(),
            &mut out,
            &mut out_len,
        );
        assert_eq!(code, OBCRYPT_ERR_NULL_ARG);
        assert!(out.is_null());
    }

    #[test]
    fn non_utf8_scheme_is_reported() {
        let key = [7u8; 64];
        // 0xff 0xfe: no interior NUL, not valid UTF-8.
        let bad = CString::new(vec![0xff, 0xfe]).unwrap();
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len = 0usize;
        let code = obcrypt_encrypt(
            b"x".as_ptr(),
            1,
            bad.as_ptr(),
            key.as_ptr(),
            key.len(),
            &mut out,
            &mut out_len,
        );
        assert_eq!(code, OBCRYPT_ERR_UTF8);
        assert!(out.is_null());
    }

    #[test]
    fn hex_key_roundtrips() {
        let pt: &[u8] = b"hex key path \x00 with NUL";
        let mut ct: *mut u8 = ptr::null_mut();
        let mut ct_len = 0usize;
        assert_eq!(
            obcrypt_encrypt_hex_key(
                pt.as_ptr(),
                pt.len(),
                cs("psiv").as_ptr(),
                cs(KEY_HEX).as_ptr(),
                &mut ct,
                &mut ct_len
            ),
            OBCRYPT_OK
        );
        let payload = unsafe { take(ct, ct_len) };

        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len = 0usize;
        assert_eq!(
            obcrypt_decrypt_hex_key(
                payload.as_ptr(),
                payload.len(),
                cs("psiv").as_ptr(),
                cs(KEY_HEX).as_ptr(),
                &mut out,
                &mut out_len
            ),
            OBCRYPT_OK
        );
        assert_eq!(unsafe { take(out, out_len) }, pt);
    }

    #[test]
    fn hex_key_and_raw_key_agree() {
        // The hex and raw key paths must encode identically for the
        // same key (checked on a deterministic scheme).
        let key_bytes = key_hex_bytes();
        let pt: &[u8] = b"same key, two forms";

        let mut a: *mut u8 = ptr::null_mut();
        let mut al = 0usize;
        assert_eq!(
            obcrypt_encrypt(
                pt.as_ptr(),
                pt.len(),
                cs("dgcmsiv").as_ptr(),
                key_bytes.as_ptr(),
                key_bytes.len(),
                &mut a,
                &mut al
            ),
            OBCRYPT_OK
        );

        let mut b: *mut u8 = ptr::null_mut();
        let mut bl = 0usize;
        assert_eq!(
            obcrypt_encrypt_hex_key(
                pt.as_ptr(),
                pt.len(),
                cs("dgcmsiv").as_ptr(),
                cs(KEY_HEX).as_ptr(),
                &mut b,
                &mut bl
            ),
            OBCRYPT_OK
        );

        assert_eq!(unsafe { take(a, al) }, unsafe { take(b, bl) });
    }

    #[test]
    fn bad_hex_key_is_an_obcrypt_error() {
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len = 0usize;
        let code = obcrypt_encrypt_hex_key(
            b"x".as_ptr(),
            1,
            cs("psiv").as_ptr(),
            cs("not-hex").as_ptr(),
            &mut out,
            &mut out_len,
        );
        assert_eq!(code, OBCRYPT_ERR_OBCRYPT);
        assert!(out.is_null());
        assert!(!obcrypt_last_error().is_null());
    }

    #[test]
    fn abi_output_matches_core() {
        // The C ABI is a faithful pass-through: for a deterministic
        // scheme its output is byte-identical to the Rust core's.
        let key_bytes = [7u8; 64];
        let pt: &[u8] = b"determinism check";
        let core = obcrypt::encrypt(
            pt,
            obcrypt::Scheme::Dsiv,
            &obcrypt::Key::from_bytes(key_bytes),
        )
        .unwrap();

        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len = 0usize;
        assert_eq!(
            obcrypt_encrypt(
                pt.as_ptr(),
                pt.len(),
                cs("dsiv").as_ptr(),
                key_bytes.as_ptr(),
                key_bytes.len(),
                &mut out,
                &mut out_len
            ),
            OBCRYPT_OK
        );
        assert_eq!(unsafe { take(out, out_len) }, core);
    }

    #[test]
    fn abi_version_is_the_package_version() {
        let p = obcrypt_abi_version();
        assert!(!p.is_null());
        let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
        assert_eq!(s, env!("CARGO_PKG_VERSION"));
        assert!(!s.is_empty());
    }
}
