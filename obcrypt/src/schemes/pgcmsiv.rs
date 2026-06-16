//! `pgcmsiv` — probabilistic AES-GCM-SIV.
//!
//! - **Properties**: probabilistic — fresh 12-byte nonce per call.
//! - **Algorithm**: AES-GCM-SIV ([RFC 8452]) using `Aes256GcmSiv`.
//! - **Key**: `HKDF-Expand(master, "gcmsiv", 32)` (HMAC-SHA-256;
//!   Extract is skipped — the 64-byte master is already a uniform PRK).
//!   Shared with [`dgcmsiv`](super::dgcmsiv): both GCM-SIV schemes derive
//!   the same key (safe by GCM-SIV nonce-misuse resistance).
//! - **Nonce**: 12 bytes from the OS RNG, prepended to the payload.
//! - **AAD**: empty.
//! - **Payload**: `nonce(12) || ciphertext_with_tag`. Tag is 16 bytes,
//!   so a 1-byte plaintext yields a 29-byte ciphertext.
//!
//! Compared to [`psiv`](super::psiv): smaller nonce footprint; typically
//! faster on CPUs with AES-NI. Use this when you want probabilistic
//! authenticated encryption with a smaller-than-SIV footprint.
//!
//! [RFC 8452]: https://www.rfc-editor.org/rfc/rfc8452

use super::buffer::TailBuffer;
use crate::{Error, Key};
use aes_gcm_siv::{
    aead::{Aead, AeadInPlace, KeyInit},
    Aes256GcmSiv, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const MIN_PAYLOAD_LEN: usize = NONCE_SIZE + 1 + TAG_SIZE;

/// HKDF-Expand the master into the 32-byte AES-256-GCM-SIV key. The
/// `gcmsiv` info is shared with `dgcmsiv`, so both GCM-SIV schemes derive
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

/// Encrypt `plaintext` and return a fresh `Vec<u8>` of `nonce(12) || ciphertext_with_tag`.
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

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = Aes256GcmSiv::new((&*key_arr).into());
    let nonce = Nonce::from(nonce_bytes);
    let ct_with_tag = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| Error::EncryptionFailed)?;

    let mut buffer = Vec::with_capacity(NONCE_SIZE + ct_with_tag.len());
    buffer.extend_from_slice(&nonce_bytes);
    buffer.extend_from_slice(&ct_with_tag);
    Ok(buffer)
}

/// Encrypt `plaintext` and append `nonce || ciphertext_with_tag` to `out`.
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

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    out.reserve(NONCE_SIZE + plaintext.len() + TAG_SIZE);
    out.extend_from_slice(&nonce_bytes);
    let pt_start = out.len();
    out.extend_from_slice(plaintext);

    let nonce = Nonce::from(nonce_bytes);
    let mut tail = TailBuffer::new(out, pt_start);
    cipher
        .encrypt_in_place(&nonce, b"", &mut tail)
        .map_err(|_| Error::EncryptionFailed)
}

/// Decrypt `ciphertext` (= `nonce(12) || ciphertext_with_tag`) and
/// return a fresh `Vec<u8>` of plaintext.
///
/// # Errors
///
/// - [`Error::PayloadTooShort`] if `ciphertext.len() < 29`
///   (12-byte nonce + ≥1 plaintext byte + 16-byte tag).
/// - [`Error::DecryptionFailed`] if the GCM tag check fails.
#[inline]
pub fn decrypt(ciphertext: &[u8], key: &Key) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < MIN_PAYLOAD_LEN {
        return Err(Error::PayloadTooShort);
    }
    let key_arr = derive_key(key);

    let nonce_arr: &[u8; NONCE_SIZE] = (&ciphertext[..NONCE_SIZE]).try_into().unwrap();
    let ct_with_tag = &ciphertext[NONCE_SIZE..];

    let cipher = Aes256GcmSiv::new((&*key_arr).into());
    let nonce = Nonce::from(*nonce_arr);

    cipher
        .decrypt(&nonce, ct_with_tag)
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

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes.copy_from_slice(&ciphertext[..NONCE_SIZE]);
    let nonce = Nonce::from(nonce_bytes);

    let ct_start = out.len();
    out.extend_from_slice(&ciphertext[NONCE_SIZE..]);

    let mut tail = TailBuffer::new(out, ct_start);
    cipher
        .decrypt_in_place(&nonce, b"", &mut tail)
        .map_err(|_| Error::DecryptionFailed)
}
