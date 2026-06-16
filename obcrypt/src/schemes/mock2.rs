//! `mock2` — reverse scheme. **Testing only — no encryption.**
//!
//! Returns plaintext bytes reversed. Behind the `mock` feature flag,
//! disabled by default. Like [`mock1`](super::mock1) but produces a
//! distinguishable output, useful for testing that scheme dispatch
//! routes to the right scheme.
//!
//! **Never enable `mock` in a production build.** Reversing bytes is
//! not encryption.

use crate::{Error, Key};

/// Return `plaintext` reversed in a fresh `Vec<u8>`.
///
/// # Errors
///
/// [`Error::EmptyPlaintext`] if `plaintext` is empty.
#[inline]
pub fn encrypt(plaintext: &[u8], _key: &Key) -> Result<Vec<u8>, Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }
    Ok(plaintext.iter().rev().copied().collect())
}

/// Append `plaintext` reversed to `out`. `out` is appended to, not cleared.
///
/// # Errors
///
/// Same as [`encrypt`].
#[inline]
pub fn encrypt_into(plaintext: &[u8], _key: &Key, out: &mut Vec<u8>) -> Result<(), Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }
    out.extend(plaintext.iter().rev().copied());
    Ok(())
}

/// Return `ciphertext` reversed in a fresh `Vec<u8>` (recovers the original plaintext).
///
/// # Errors
///
/// [`Error::EmptyPayload`] if `ciphertext` is empty.
#[inline]
pub fn decrypt(ciphertext: &[u8], _key: &Key) -> Result<Vec<u8>, Error> {
    if ciphertext.is_empty() {
        return Err(Error::EmptyPayload);
    }
    Ok(ciphertext.iter().rev().copied().collect())
}

/// Append `ciphertext` reversed to `out` (recovers the original plaintext).
/// `out` is appended to, not cleared.
///
/// # Errors
///
/// Same as [`decrypt`].
#[inline]
pub fn decrypt_into(ciphertext: &[u8], _key: &Key, out: &mut Vec<u8>) -> Result<(), Error> {
    if ciphertext.is_empty() {
        return Err(Error::EmptyPayload);
    }
    out.extend(ciphertext.iter().rev().copied());
    Ok(())
}
