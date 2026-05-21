//! `mock1` — identity scheme. **Testing only — no encryption.**
//!
//! Returns plaintext unchanged. Behind the `mock` feature flag,
//! disabled by default. Exists to:
//!
//! - Provide a no-crypto round-trip baseline for unit tests.
//! - Isolate framing / cross-crate / dispatch overhead from AEAD
//!   cost in benchmarks (any timing diff between `mock1` and master
//!   is pure layering overhead).
//! - Serve as the simplest possible valid scheme for testing the
//!   marker dispatch logic.
//!
//! **Never enable `mock` in a production build.** Ciphertext == plaintext.

use crate::{Error, Key};

/// Return `plaintext` unchanged in a fresh `Vec<u8>`.
///
/// # Errors
///
/// [`Error::EmptyPlaintext`] if `plaintext` is empty.
#[inline]
pub fn encrypt(plaintext: &[u8], _key: &Key) -> Result<Vec<u8>, Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }
    Ok(plaintext.to_vec())
}

/// Append `plaintext` unchanged to `out`. `out` is appended to, not cleared.
///
/// # Errors
///
/// Same as [`encrypt`].
#[inline]
pub fn encrypt_into(plaintext: &[u8], _key: &Key, out: &mut Vec<u8>) -> Result<(), Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }
    out.extend_from_slice(plaintext);
    Ok(())
}

/// Return `ciphertext` unchanged in a fresh `Vec<u8>`.
///
/// # Errors
///
/// [`Error::EmptyPayload`] if `ciphertext` is empty.
#[inline]
pub fn decrypt(ciphertext: &[u8], _key: &Key) -> Result<Vec<u8>, Error> {
    if ciphertext.is_empty() {
        return Err(Error::EmptyPayload);
    }
    Ok(ciphertext.to_vec())
}

/// Append `ciphertext` unchanged to `out`. `out` is appended to, not cleared.
///
/// # Errors
///
/// Same as [`decrypt`].
#[inline]
pub fn decrypt_into(ciphertext: &[u8], _key: &Key, out: &mut Vec<u8>) -> Result<(), Error> {
    if ciphertext.is_empty() {
        return Err(Error::EmptyPayload);
    }
    out.extend_from_slice(ciphertext);
    Ok(())
}
