//! `aags` — deterministic AES-GCM-SIV.
//!
//! - **Tier**: a (authenticated)
//! - **Properties**: deterministic (uses a constant zero nonce —
//!   safe with GCM-SIV because the algorithm is nonce-misuse resistant
//!   for the deterministic case).
//! - **Algorithm**: AES-GCM-SIV ([RFC 8452]) using `Aes256GcmSiv` from
//!   the [`aes-gcm-siv`] crate.
//! - **Key**: uses **bytes 32..64** of the master key (32 bytes —
//!   AES-256).
//! - **Nonce**: zero (deterministic mode).
//! - **Payload**: `ciphertext_with_tag`. Tag is 16 bytes, so a 1-byte
//!   plaintext yields a 17-byte ciphertext.
//!
//! Compared to [`aasv`](super::aasv): smaller key footprint (32 bytes
//! vs 64) and typically faster on CPUs with AES-NI; the security
//! posture is similar (both nonce-misuse resistant).
//!
//! [RFC 8452]: https://www.rfc-editor.org/rfc/rfc8452
//! [`aes-gcm-siv`]: https://docs.rs/aes-gcm-siv/

use super::buffer::TailBuffer;
use crate::{Error, Key};
use aes_gcm_siv::{
    aead::{Aead, AeadInPlace, KeyInit},
    Aes256GcmSiv, Nonce,
};

const KEY_OFFSET: usize = 32;
const KEY_LEN: usize = 32;
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
    let key_arr = key.subkey::<KEY_OFFSET, KEY_LEN>();
    let cipher = Aes256GcmSiv::new(key_arr.into());
    let nonce = Nonce::from([0u8; NONCE_SIZE]);
    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| Error::EncryptionFailed)
}

/// Encrypt `plaintext` and append `ciphertext_with_tag` to `out`.
/// `out` is appended to, not cleared.
///
/// # Errors
///
/// Same as [`encrypt`].
#[inline]
pub fn encrypt_into(plaintext: &[u8], key: &Key, out: &mut Vec<u8>) -> Result<(), Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }
    let key_arr = key.subkey::<KEY_OFFSET, KEY_LEN>();
    let cipher = Aes256GcmSiv::new(key_arr.into());
    let nonce = Nonce::from([0u8; NONCE_SIZE]);

    let start = out.len();
    out.extend_from_slice(plaintext);
    let mut tail = TailBuffer::new(out, start);
    cipher
        .encrypt_in_place(&nonce, b"", &mut tail)
        .map_err(|_| Error::EncryptionFailed)
}

/// Decrypt `ciphertext` and return a fresh `Vec<u8>` of plaintext.
///
/// # Errors
///
/// - [`Error::PayloadTooShort`] if `ciphertext.len() < 17`.
/// - [`Error::DecryptionFailed`] if the GCM tag check fails (wrong
///   key or tampered ciphertext).
#[inline]
pub fn decrypt(ciphertext: &[u8], key: &Key) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < MIN_PAYLOAD_LEN {
        return Err(Error::PayloadTooShort);
    }
    let key_arr = key.subkey::<KEY_OFFSET, KEY_LEN>();
    let cipher = Aes256GcmSiv::new(key_arr.into());
    let nonce = Nonce::from([0u8; NONCE_SIZE]);
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| Error::DecryptionFailed)
}

/// Decrypt `ciphertext` and append plaintext to `out`. `out` is
/// appended to, not cleared.
///
/// # Errors
///
/// Same as [`decrypt`].
#[inline]
pub fn decrypt_into(ciphertext: &[u8], key: &Key, out: &mut Vec<u8>) -> Result<(), Error> {
    if ciphertext.len() < MIN_PAYLOAD_LEN {
        return Err(Error::PayloadTooShort);
    }
    let key_arr = key.subkey::<KEY_OFFSET, KEY_LEN>();
    let cipher = Aes256GcmSiv::new(key_arr.into());
    let nonce = Nonce::from([0u8; NONCE_SIZE]);

    let start = out.len();
    out.extend_from_slice(ciphertext);
    let mut tail = TailBuffer::new(out, start);
    cipher
        .decrypt_in_place(&nonce, b"", &mut tail)
        .map_err(|_| Error::DecryptionFailed)
}
