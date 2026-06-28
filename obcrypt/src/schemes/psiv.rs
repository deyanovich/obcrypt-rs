//! `psiv` — probabilistic AES-SIV.
//!
//! - **Properties**: probabilistic — fresh 16-byte nonce per call.
//! - **Algorithm**: AES-SIV ([RFC 5297]) using `Aes256Siv`, with the
//!   nonce passed as the SIV "associated data".
//! - **Key**: uses the **full 64-byte** master key.
//! - **Nonce**: 16 bytes from the OS RNG, prepended to the payload.
//! - **Payload**: `nonce(16) || ciphertext_with_tag`. Tag is 16 bytes,
//!   so a 1-byte plaintext yields a 33-byte ciphertext.
//! - **Nonce-misuse resistance**: even if two calls accidentally use
//!   the same nonce (e.g. catastrophic RNG failure), `psiv` degrades
//!   only to the equality-leak property of [`dsiv`](super::dsiv) — no
//!   key recovery, no plaintext recovery.
//!
//! Use this when you want authenticated encryption with **no
//! observable equality** between same-plaintext calls.
//!
//! [RFC 5297]: https://www.rfc-editor.org/rfc/rfc5297

use super::buffer::TailBuffer;
use crate::{Error, Key};
use aes_siv::{aead::KeyInit, siv::Aes256Siv};
use rand::RngCore;

const NONCE_SIZE: usize = 16;
const TAG_SIZE: usize = 16;
const MIN_PAYLOAD_LEN: usize = NONCE_SIZE + 1 + TAG_SIZE;

/// Encrypt `plaintext` and return a fresh `Vec<u8>` of `nonce(16) || ciphertext_with_tag`.
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

    let mut buffer = Vec::with_capacity(NONCE_SIZE + plaintext.len() + TAG_SIZE);
    buffer.resize(NONCE_SIZE, 0);
    rand::thread_rng().fill_bytes(&mut buffer[..NONCE_SIZE]);

    let mut cipher = Aes256Siv::new(key.as_bytes().into());
    let ct_with_tag = cipher
        .encrypt([&buffer[..NONCE_SIZE]], plaintext)
        .map_err(|_| Error::EncryptionFailed)?;
    buffer.extend_from_slice(&ct_with_tag);
    Ok(buffer)
}

/// Encrypt `plaintext` and append `nonce || ciphertext_with_tag` to `out`.
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
    // Nonce on the stack — keeps it borrowable while TailBuffer holds `out`.
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);

    let start = out.len();
    out.reserve(NONCE_SIZE + plaintext.len() + TAG_SIZE);
    out.extend_from_slice(&nonce);
    let pt_start = out.len();
    out.extend_from_slice(plaintext);

    let mut cipher = Aes256Siv::new(key.as_bytes().into());
    let mut tail = TailBuffer::new(out, pt_start);
    if cipher.encrypt_in_place([&nonce[..]], &mut tail).is_err() {
        out.truncate(start);
        return Err(Error::EncryptionFailed);
    }
    Ok(())
}

/// Decrypt `ciphertext` (= `nonce(16) || ciphertext_with_tag`) and
/// return a fresh `Vec<u8>` of plaintext.
///
/// # Errors
///
/// - [`Error::PayloadTooShort`] if `ciphertext.len() < 33`
///   (16-byte nonce + ≥1 plaintext byte + 16-byte tag).
/// - [`Error::DecryptionFailed`] if the SIV tag check fails.
#[inline]
pub fn decrypt(ciphertext: &[u8], key: &Key) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < MIN_PAYLOAD_LEN {
        return Err(Error::PayloadTooShort);
    }
    let nonce_bytes = &ciphertext[..NONCE_SIZE];
    let ct_with_tag = &ciphertext[NONCE_SIZE..];

    let mut cipher = Aes256Siv::new(key.as_bytes().into());
    cipher
        .decrypt([nonce_bytes], ct_with_tag)
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
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&ciphertext[..NONCE_SIZE]);

    let ct_start = out.len();
    out.extend_from_slice(&ciphertext[NONCE_SIZE..]);

    let mut cipher = Aes256Siv::new(key.as_bytes().into());
    let mut tail = TailBuffer::new(out, ct_start);
    if cipher.decrypt_in_place([&nonce[..]], &mut tail).is_err() {
        out.truncate(ct_start);
        return Err(Error::DecryptionFailed);
    }
    Ok(())
}
