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
//! [RFC 8452]: https://www.rfc-editor.org/rfc/rfc8452
//! [`aes-gcm-siv`]: https://docs.rs/aes-gcm-siv/

use super::buffer::TailBuffer;
use crate::{Error, Key};
use aes_gcm_siv::{
    aead::{Aead, AeadInPlace, KeyInit},
    Aes256GcmSiv, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const NONCE_SIZE: usize = 12;
const MIN_PAYLOAD_LEN: usize = 17;

/// HKDF-Expand the master into the 32-byte AES-256-GCM-SIV key. The
/// `gcmsiv` info is shared with `pgcmsiv`, so both GCM-SIV schemes derive
/// the same key. Extract is omitted: the 64-byte master is already a
/// uniform pseudorandom key.
#[inline]
fn derive_key(key: &Key) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::from_prk(key.as_bytes()).expect("master is a valid 64-byte PRK");
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"gcmsiv", &mut okm[..])
        .expect("32-byte OKM is within HKDF length bounds");
    okm
}

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
    let key_arr = derive_key(key);
    let cipher = Aes256GcmSiv::new((&*key_arr).into());
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
    let key_arr = derive_key(key);
    let cipher = Aes256GcmSiv::new((&*key_arr).into());
    let nonce = Nonce::from([0u8; NONCE_SIZE]);

    let start = out.len();
    out.extend_from_slice(ciphertext);
    let mut tail = TailBuffer::new(out, start);
    cipher
        .decrypt_in_place(&nonce, b"", &mut tail)
        .map_err(|_| Error::DecryptionFailed)
}
