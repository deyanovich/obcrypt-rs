//! `upbc` — probabilistic AES-CBC.
//!
//! - **Tier**: u (**unauthenticated** — confidentiality only).
//! - **Properties**: probabilistic — fresh 16-byte IV per call.
//! - **Algorithm**: AES-CBC with `Aes256` from the [`aes`] crate and
//!   the [`cbc`] mode wrapper.
//! - **Key**: uses **bytes 8..40** of the master key (32 bytes —
//!   AES-256).
//! - **IV**: 16 bytes from the OS RNG, prepended to the payload.
//! - **Padding**: custom byte-pattern padding using `CBC_PADDING_BYTE`
//!   (0x01) — plaintext is padded to a 16-byte multiple by appending
//!   `0x01` bytes; on decrypt, all trailing `0x01` bytes are stripped.
//!   This means plaintexts ending in `0x01` will lose those bytes on
//!   round-trip — caller must avoid that suffix or apply its own
//!   length encoding.
//! - **Payload**: `iv(16) || ciphertext_padded`. A 1-byte plaintext
//!   yields a 32-byte ciphertext (16 IV + 16 padded block).
//!
//! ## ⚠ No authentication
//!
//! `upbc` does **not** detect tampering. A flipped bit in the
//! ciphertext yields a different plaintext on decrypt with no error.
//! Use this scheme only when an outer mechanism authenticates the
//! payload (signed transport, MAC over `iv || ct`, etc.).
//!
//! For most use cases prefer the a-tier schemes ([`aasv`](super::aasv),
//! [`apsv`](super::apsv), [`aags`](super::aags), [`apgs`](super::apgs)).
//!
//! [`aes`]: https://docs.rs/aes/
//! [`cbc`]: https://docs.rs/cbc/

use super::constants::{AES_BLOCK_SIZE, CBC_PADDING_BYTE};
use crate::{Error, Key};
use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

const KEY_OFFSET: usize = 8;
const KEY_LEN: usize = 32;
const IV_SIZE: usize = 16;

/// Encrypt `plaintext` and return a fresh `Vec<u8>` of `iv(16) || ciphertext_padded`.
///
/// # Errors
///
/// - [`Error::EmptyPlaintext`] if `plaintext` is empty.
/// - [`Error::EncryptionFailed`] for cipher-internal failures (rare).
#[inline]
pub fn encrypt(plaintext: &[u8], key: &Key) -> Result<Vec<u8>, Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }
    let key_arr = key.subkey::<KEY_OFFSET, KEY_LEN>();

    let data_len = plaintext.len();
    let padding_size = (AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
    let total_len = data_len + padding_size;

    let mut buffer = Vec::with_capacity(IV_SIZE + total_len);
    buffer.resize(IV_SIZE, 0);
    rand::thread_rng().fill_bytes(&mut buffer[..IV_SIZE]);
    buffer.extend_from_slice(plaintext);
    buffer.resize(IV_SIZE + total_len, CBC_PADDING_BYTE);

    let cipher = Aes256CbcEnc::new(key_arr.into(), buffer[..IV_SIZE].into());
    cipher
        .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer[IV_SIZE..], total_len)
        .map_err(|_| Error::EncryptionFailed)?;
    Ok(buffer)
}

/// Encrypt `plaintext` and append `iv || ciphertext_padded` to `out`.
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

    let data_len = plaintext.len();
    let padding_size = (AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
    let total_len = data_len + padding_size;

    let start = out.len();
    out.reserve(IV_SIZE + total_len);
    out.resize(start + IV_SIZE, 0);
    rand::thread_rng().fill_bytes(&mut out[start..start + IV_SIZE]);
    out.extend_from_slice(plaintext);
    out.resize(start + IV_SIZE + total_len, CBC_PADDING_BYTE);

    let mut iv = [0u8; IV_SIZE];
    iv.copy_from_slice(&out[start..start + IV_SIZE]);

    let cipher = Aes256CbcEnc::new(key_arr.into(), (&iv).into());
    cipher
        .encrypt_padded_mut::<cipher::block_padding::NoPadding>(
            &mut out[start + IV_SIZE..start + IV_SIZE + total_len],
            total_len,
        )
        .map_err(|_| Error::EncryptionFailed)?;
    Ok(())
}

/// Decrypt `ciphertext` (= `iv(16) || ciphertext_padded`) and return
/// a fresh `Vec<u8>` of plaintext (with trailing `0x01` padding bytes
/// stripped).
///
/// # Errors
///
/// - [`Error::PayloadTooShort`] if `ciphertext.len() < 32` (16-byte
///   IV + at least one ciphertext block).
/// - [`Error::InvalidBlockLength`] if the ciphertext-after-IV portion
///   isn't a multiple of 16.
/// - [`Error::DecryptionFailed`] for cipher-internal failures.
///
/// **Note:** because `upbc` is unauthenticated, decryption with the
/// wrong key or against tampered ciphertext does **not** raise an
/// error — it produces garbled plaintext. Use only with an outer
/// authentication mechanism.
#[inline]
pub fn decrypt(ciphertext: &[u8], key: &Key) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < 2 * IV_SIZE {
        return Err(Error::PayloadTooShort);
    }
    if (ciphertext.len() - IV_SIZE) % AES_BLOCK_SIZE != 0 {
        return Err(Error::InvalidBlockLength);
    }
    let key_arr = key.subkey::<KEY_OFFSET, KEY_LEN>();

    let iv = &ciphertext[..IV_SIZE];
    let mut buf = ciphertext[IV_SIZE..].to_vec();

    let cipher = Aes256CbcDec::new(key_arr.into(), iv.into());
    cipher
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|_| Error::DecryptionFailed)?;

    // Strip custom padding (CBC_PADDING_BYTE).
    let mut end = buf.len();
    while end > 0 && buf[end - 1] == CBC_PADDING_BYTE {
        end -= 1;
    }
    buf.truncate(end);
    Ok(buf)
}

/// Decrypt `ciphertext` and append plaintext to `out` (with trailing
/// `0x01` padding bytes stripped). `out` is appended to, not cleared.
///
/// # Errors
///
/// Same as [`decrypt`].
#[inline]
pub fn decrypt_into(ciphertext: &[u8], key: &Key, out: &mut Vec<u8>) -> Result<(), Error> {
    if ciphertext.len() < 2 * IV_SIZE {
        return Err(Error::PayloadTooShort);
    }
    let key_arr = key.subkey::<KEY_OFFSET, KEY_LEN>();
    if (ciphertext.len() - IV_SIZE) % AES_BLOCK_SIZE != 0 {
        return Err(Error::InvalidBlockLength);
    }

    let mut iv = [0u8; IV_SIZE];
    iv.copy_from_slice(&ciphertext[..IV_SIZE]);

    let ct_start = out.len();
    out.extend_from_slice(&ciphertext[IV_SIZE..]);

    let cipher = Aes256CbcDec::new(key_arr.into(), (&iv).into());
    cipher
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut out[ct_start..])
        .map_err(|_| Error::DecryptionFailed)?;

    let mut end = out.len();
    while end > ct_start && out[end - 1] == CBC_PADDING_BYTE {
        end -= 1;
    }
    out.truncate(end);
    Ok(())
}
