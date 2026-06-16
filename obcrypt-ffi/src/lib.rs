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

/// Run `f` and marshal its `Result<Vec<u8>, i32>` into the ABI: on
/// success hand the bytes out as a `Box<[u8]>` via `(*out, *out_len)`
/// (caller frees with [`obcrypt_buffer_free`]); on error leave the
/// out-params untouched and return the code. Catches panics.
fn finish(
    out: *mut *mut u8,
    out_len: *mut usize,
    f: impl FnOnce() -> Result<Vec<u8>, i32>,
) -> i32 {
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
        unsafe { drop(Box::from_raw(slice::from_raw_parts_mut(ptr, len))) };
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
            obcrypt_encrypt(pt.as_ptr(), pt.len(), cs("psiv").as_ptr(),
                            key.as_ptr(), key.len(), &mut ct, &mut ct_len),
            OBCRYPT_OK
        );
        let payload = unsafe { take(ct, ct_len) };

        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len = 0usize;
        assert_eq!(
            obcrypt_decrypt(payload.as_ptr(), payload.len(), cs("psiv").as_ptr(),
                            key.as_ptr(), key.len(), &mut out, &mut out_len),
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
        let code = obcrypt_encrypt(b"x".as_ptr(), 1, cs("psiv").as_ptr(),
                                   short_key.as_ptr(), short_key.len(), &mut out, &mut out_len);
        assert_eq!(code, OBCRYPT_ERR_OBCRYPT);
        assert!(out.is_null());
        assert!(!obcrypt_last_error().is_null());
    }

    #[test]
    fn unknown_scheme_is_reported() {
        let key = [7u8; 64];
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len = 0usize;
        let code = obcrypt_encrypt(b"x".as_ptr(), 1, cs("nope").as_ptr(),
                                   key.as_ptr(), key.len(), &mut out, &mut out_len);
        assert_eq!(code, OBCRYPT_ERR_BAD_SCHEME);
        assert!(out.is_null());
    }

    #[test]
    fn null_buffer_with_zero_len_is_ok() {
        // A null data pointer is allowed when the length is zero.
        let r = unsafe { bytes(ptr::null(), 0, "x") };
        assert_eq!(r, Ok(&[][..]));
    }
}
