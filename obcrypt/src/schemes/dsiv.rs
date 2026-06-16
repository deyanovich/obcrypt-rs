//! `dsiv` — deterministic AES-SIV.
//!
//! - **Properties**: deterministic — same plaintext + same key always
//!   produces the same ciphertext.
//! - **Algorithm**: AES-SIV ([RFC 5297]) using `Aes256Siv` from the
//!   [`aes-siv`] crate.
//! - **Key**: uses the **full 64-byte** master key.
//! - **Nonce**: none — SIV synthesizes its IV from the plaintext +
//!   associated data.
//! - **Payload**: `ciphertext_with_tag` (no nonce prefix). Tag is
//!   16 bytes, so a 1-byte plaintext yields a 17-byte ciphertext.
//!
//! dsiv is the **default recommended scheme** for new
//! deterministic-encryption use cases — broad nonce-misuse resistance
//! and a clean security story. The deterministic property is
//! deliberate: it lets you use ciphertext as a stable identifier or
//! lookup key. If you don't want plaintext equality to be observable,
//! use [`psiv`](super::psiv) instead.
//!
//! [RFC 5297]: https://www.rfc-editor.org/rfc/rfc5297
//! [`aes-siv`]: https://docs.rs/aes-siv/

use super::buffer::TailBuffer;
use crate::{Error, Key};
use aes_siv::{aead::KeyInit, siv::Aes256Siv};

const MIN_PAYLOAD_LEN: usize = 17;

/// Encrypt `plaintext` and return a fresh `Vec<u8>` of `ciphertext || tag`.
///
/// Uses `Aes256Siv::encrypt`, which allocates the output Vec at
/// exact capacity (plaintext_len + 16-byte tag) in a single pass.
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
    let mut cipher = Aes256Siv::new(key.as_bytes().into());
    let headers: &[&[u8]] = &[];
    cipher
        .encrypt(headers, plaintext)
        .map_err(|_| Error::EncryptionFailed)
}

/// Encrypt `plaintext` and append `ciphertext || tag` to `out`.
///
/// Writes directly into `out` via `encrypt_in_place` — no intermediate
/// Vec allocation. `out` is appended to, not cleared.
///
/// # Errors
///
/// Same as [`encrypt`].
#[inline]
pub fn encrypt_into(plaintext: &[u8], key: &Key, out: &mut Vec<u8>) -> Result<(), Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }
    let start = out.len();
    out.extend_from_slice(plaintext);

    let mut cipher = Aes256Siv::new(key.as_bytes().into());
    let headers: &[&[u8]] = &[];
    let mut tail = TailBuffer::new(out, start);
    cipher
        .encrypt_in_place(headers, &mut tail)
        .map_err(|_| Error::EncryptionFailed)
}

/// Decrypt `ciphertext` (= raw `ciphertext || tag` from `encrypt`)
/// and return a fresh `Vec<u8>` of plaintext.
///
/// # Errors
///
/// - [`Error::PayloadTooShort`] if `ciphertext.len() < 17`.
/// - [`Error::DecryptionFailed`] if the SIV tag check fails (wrong
///   key or tampered ciphertext).
#[inline]
pub fn decrypt(ciphertext: &[u8], key: &Key) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < MIN_PAYLOAD_LEN {
        return Err(Error::PayloadTooShort);
    }
    let mut cipher = Aes256Siv::new(key.as_bytes().into());
    let headers: &[&[u8]] = &[];
    cipher
        .decrypt(headers, ciphertext)
        .map_err(|_| Error::DecryptionFailed)
}

/// Decrypt `ciphertext` and append plaintext to `out`.
///
/// Internally copies `ciphertext` into the `out` tail and runs
/// `decrypt_in_place` on it (the AEAD trait requires a mutable buffer).
/// `out` is appended to, not cleared.
///
/// # Errors
///
/// Same as [`decrypt`].
#[inline]
pub fn decrypt_into(ciphertext: &[u8], key: &Key, out: &mut Vec<u8>) -> Result<(), Error> {
    if ciphertext.len() < MIN_PAYLOAD_LEN {
        return Err(Error::PayloadTooShort);
    }
    let start = out.len();
    out.extend_from_slice(ciphertext);

    let mut cipher = Aes256Siv::new(key.as_bytes().into());
    let headers: &[&[u8]] = &[];
    let mut tail = TailBuffer::new(out, start);
    cipher
        .decrypt_in_place(headers, &mut tail)
        .map_err(|_| Error::DecryptionFailed)
}
