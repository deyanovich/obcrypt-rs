//! `dgcmsiv` — deterministic AES-GCM-SIV.
//!
//! - **Properties**: deterministic (uses a constant zero nonce — safe
//!   with GCM-SIV because the algorithm is nonce-misuse resistant for
//!   the deterministic case).
//! - **Algorithm**: AES-GCM-SIV ([RFC 8452]) using `Aes256GcmSiv` from
//!   the [`aes-gcm-siv`] crate.
//! - **Key**: `HKDF-Expand(master, "gcmsiv", 32)` (HMAC-SHA-256;
//!   Extract is skipped — the 64-byte master is already a uniform PRK).
//!   Shared with [`pgcmsiv`](super::pgcmsiv): both GCM-SIV schemes derive
//!   the same key (safe by GCM-SIV nonce-misuse resistance).
//! - **Nonce**: zero, 12 bytes (deterministic mode).
//! - **AAD**: empty.
//! - **Payload**: `ciphertext_with_tag`. Tag is 16 bytes, so a 1-byte
//!   plaintext yields a 17-byte ciphertext.
//!
//! Compared to [`dsiv`](super::dsiv): typically faster on CPUs with
//! AES-NI; the security posture is similar (both nonce-misuse resistant).
//!
//! **Determinism leaks equality.** Like [`dsiv`](super::dsiv), identical
//! plaintexts under the same key produce identical output, revealing
//! when two inputs are equal. Use [`pgcmsiv`](super::pgcmsiv) when that
//! must not leak.
//!
//! **Usage bound.** The fixed zero nonce is safe under GCM-SIV's
//! nonce-misuse resistance, but security bounds still degrade as
//! messages accumulate under one key; observe the AES-256-GCM-SIV
//! per-key message and data limits of RFC 8452 §6.
//!
//! [RFC 8452]: https://www.rfc-editor.org/rfc/rfc8452
//! [`aes-gcm-siv`]: https://docs.rs/aes-gcm-siv/

use super::buffer::TailBuffer;
use super::gcmsiv::derive_key;
use crate::{Error, Key};
use aes_gcm_siv::{
    aead::{Aead, AeadInPlace, KeyInit},
    Aes256GcmSiv, Nonce,
};

const NONCE_SIZE: usize = 12;
const MIN_PAYLOAD_LEN: usize = 17;

/// Encrypt `plaintext` and return a fresh `Vec<u8>` of `ciphertext_with_tag`.
///
/// # Errors
///
/// - [`Error::EmptyPlaintext`] if `plaintext` is empty.
/// - [`Error::EncryptionFailed`] for AEAD-internal failures (rare).
#[inline]
pub fn encrypt(plaintext: &[u8], key: &Key) -> Result<Vec<u8>, Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }
    let key_arr = derive_key(key);
    let cipher = Aes256GcmSiv::new((&*key_arr).into());
    let nonce = Nonce::from([0u8; NONCE_SIZE]);
    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| Error::EncryptionFailed)
}

/// Encrypt `plaintext` and append `ciphertext_with_tag` to `out`.
///
/// On success `out` is extended by the scheme output; on error `out` is
/// left exactly as it was on entry (all-or-nothing).
///
/// # Errors
///
/// Same as [`encrypt`].
#[inline]
pub fn encrypt_into(plaintext: &[u8], key: &Key, out: &mut Vec<u8>) -> Result<(), Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }
    let key_arr = derive_key(key);
    let cipher = Aes256GcmSiv::new((&*key_arr).into());
    let nonce = Nonce::from([0u8; NONCE_SIZE]);

    let start = out.len();
    out.extend_from_slice(plaintext);
    let mut tail = TailBuffer::new(out, start);
    if cipher.encrypt_in_place(&nonce, b"", &mut tail).is_err() {
        out.truncate(start);
        return Err(Error::EncryptionFailed);
    }
    Ok(())
}

/// Decrypt `ciphertext` and return a fresh `Vec<u8>` of plaintext.
///
/// # Errors
///
/// - [`Error::PayloadTooShort`] if `ciphertext.len() < 17`.
/// - [`Error::DecryptionFailed`] if the GCM tag check fails (wrong key
///   or tampered ciphertext).
#[inline]
pub fn decrypt(ciphertext: &[u8], key: &Key) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < MIN_PAYLOAD_LEN {
        return Err(Error::PayloadTooShort);
    }
    let key_arr = derive_key(key);
    let cipher = Aes256GcmSiv::new((&*key_arr).into());
    let nonce = Nonce::from([0u8; NONCE_SIZE]);
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| Error::DecryptionFailed)
}

/// Decrypt `ciphertext` and append plaintext to `out`.
///
/// On success `out` is extended by the recovered plaintext; on error
/// `out` is left exactly as it was on entry (all-or-nothing) — a failed
/// authentication never leaves partial or unverified bytes behind.
///
/// # Errors
///
/// Same as [`decrypt`].
#[inline]
pub fn decrypt_into(ciphertext: &[u8], key: &Key, out: &mut Vec<u8>) -> Result<(), Error> {
    if ciphertext.len() < MIN_PAYLOAD_LEN {
        return Err(Error::PayloadTooShort);
    }
    let key_arr = derive_key(key);
    let cipher = Aes256GcmSiv::new((&*key_arr).into());
    let nonce = Nonce::from([0u8; NONCE_SIZE]);

    let start = out.len();
    out.extend_from_slice(ciphertext);
    let mut tail = TailBuffer::new(out, start);
    if cipher.decrypt_in_place(&nonce, b"", &mut tail).is_err() {
        out.truncate(start);
        return Err(Error::DecryptionFailed);
    }
    Ok(())
}
