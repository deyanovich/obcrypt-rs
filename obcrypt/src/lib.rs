//! Bytes-in / bytes-out cryptographic core of the
//! [oboron](https://oboron.org/) protocol.
//!
//! `obcrypt` implements oboron's authenticated core encryption schemes
//! operating on raw byte slices. It does *not* encode the output (no
//! base64, no base32) and does *not* validate UTF-8 — plaintext bytes
//! pass through unchanged.
//!
//! Keys do have a canonical text form: **hex** (128 lowercase
//! characters). [`Key::from_hex`] / [`Key::to_hex`] handle that — see
//! [`Key`] for rationale.
//!
//! For the full string-in / string-out oboron protocol — with obtext
//! encoding and format strings — see the
//! [`oboron`](https://gitlab.com/oboron/oboron-rs) crate, which depends
//! on this one. The unauthenticated and obfuscation schemes live in the
//! separate obu layer.
//!
//! # Quick start
//!
//! ```
//! # #[cfg(feature = "dsiv")] {
//! use obcrypt::{encrypt, decrypt, Key, Scheme};
//!
//! let key = Key::random();
//! let ct = encrypt(b"secret data", Scheme::Dsiv, &key)?;
//! let pt = decrypt(&ct, Scheme::Dsiv, &key)?;
//! assert_eq!(pt, b"secret data");
//! # }
//! # Ok::<(), obcrypt::Error>(())
//! ```
//!
//! # Schemes
//!
//! | Scheme | Properties | Algorithm | Key material |
//! |--------|------------|-----------|--------------|
//! | [`Scheme::Dsiv`] | deterministic | AES-SIV | full 64-byte master |
//! | [`Scheme::Dgcmsiv`] | deterministic | AES-GCM-SIV | HKDF-derived |
//! | [`Scheme::Psiv`] | probabilistic | AES-SIV | full 64-byte master |
//! | [`Scheme::Pgcmsiv`] | probabilistic | AES-GCM-SIV | HKDF-derived |
//!
//! All four are authenticated: `decrypt` returns
//! [`Error::DecryptionFailed`] on tampering, a wrong key, or the wrong
//! scheme. Deterministic variants (`dsiv`, `dgcmsiv`) leak plaintext
//! equality (same plaintext + key → same output); use a probabilistic
//! variant when that isn't acceptable.
//!
//! Plus testing-only schemes behind the `mock` feature flag —
//! [`Scheme::Mock1`] (identity) and [`Scheme::Mock2`] (reverse), which
//! perform **no encryption**.
//!
//! # Output format
//!
//! The output is exactly the scheme's AEAD output — there is no scheme
//! marker. The scheme is supplied by the caller to both [`encrypt`] and
//! [`decrypt`] (oboron's no-marker model: supplying the wrong scheme
//! fails the authentication check). Per-scheme byte layouts:
//!
//! - deterministic: `siv-tag || ciphertext` (`dsiv`) or
//!   `ciphertext || tag` (`dgcmsiv`).
//! - probabilistic: a fresh nonce is prepended.
//!
//! # API
//!
//! Each operation has an **owned** form (returns a fresh `Vec<u8>`) and
//! an **`_into`** form (appends to a caller buffer; zero extra
//! allocation on the AEAD path):
//!
//! - [`encrypt`] / [`encrypt_into`] — `(plaintext, scheme, key)`
//! - [`decrypt`] / [`decrypt_into`] — `(scheme_output, scheme, key)`
//!
//! Keys come last; data first. The per-scheme primitives live under
//! [`schemes`] for callers that already know the scheme statically.
//!
//! # Security model
//!
//! Symmetric **authenticated** encryption over a 64-byte master key.
//!
//! - **Authenticity**: every scheme is authenticated via the AEAD tag.
//! - **Determinism**: deterministic variants leak plaintext equality.
//! - **Key derivation**: the SIV schemes use the master key directly;
//!   the GCM-SIV schemes derive a 32-byte key with `HKDF-Expand` over
//!   the master (HMAC-SHA-256, info `gcmsiv`, shared by both GCM-SIV
//!   schemes; Extract is skipped, as the master is already a uniform
//!   pseudorandom key).
//! - **Nonce handling**: probabilistic schemes draw a fresh nonce per
//!   call from the OS RNG. AES-SIV and AES-GCM-SIV are nonce-misuse
//!   resistant — even under accidental reuse they degrade only to the
//!   equality-leak property of the deterministic variants.
//! - **Side channels**: obcrypt relies on the underlying `aes-siv`,
//!   `aes-gcm-siv`, and `hkdf` crates for constant-time primitives where
//!   applicable; no extra side-channel hardening is added here.
//! - **Key zeroization**: [`Key`] is `ZeroizeOnDrop`; derived GCM-SIV
//!   subkeys are held in `Zeroizing` buffers.
//!
//! See [`SECURITY.md`](https://gitlab.com/oboron/obcrypt-rs/-/blob/master/obcrypt/SECURITY.md)
//! for the full threat model and reporting policy.
//!
//! # Cargo features
//!
//! - `default = ["dgcmsiv", "pgcmsiv", "dsiv", "psiv"]` — every
//!   production scheme.
//! - Per-scheme: `dgcmsiv`, `pgcmsiv`, `dsiv`, `psiv`.
//! - `mock` — adds the testing-only [`Scheme::Mock1`] / [`Scheme::Mock2`].
//!
//! Schemes are individually gated so binary size scales with the schemes
//! you actually use.

mod error;
mod key;
mod keygen;
mod scheme;

pub mod schemes;

pub use error::Error;
pub use key::Key;
pub use keygen::generate_key;
pub use scheme::Scheme;

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` under `scheme`, returning the scheme output bytes.
///
/// The output is the scheme's AEAD output directly (no marker); see the
/// [crate docs](crate#output-format) for the per-scheme layouts.
///
/// # Errors
///
/// - [`Error::EmptyPlaintext`] if `plaintext` is empty.
/// - [`Error::EncryptionFailed`] if the underlying AEAD primitive
///   reports failure (in practice: out-of-memory or platform randomness
///   failure for probabilistic schemes).
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "dsiv")] {
/// use obcrypt::{encrypt, Key, Scheme};
///
/// let key = Key::random();
/// let ct = encrypt(b"hello", Scheme::Dsiv, &key)?;
/// assert!(ct.len() > b"hello".len()); // includes the AEAD tag
/// # }
/// # Ok::<(), obcrypt::Error>(())
/// ```
#[inline]
pub fn encrypt(plaintext: &[u8], scheme: Scheme, key: &Key) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    encrypt_into(plaintext, scheme, key, &mut out)?;
    Ok(out)
}

/// Encrypt `plaintext` under `scheme`, appending the output to `out`.
///
/// The zero-extra-allocation form: the scheme writes its ciphertext
/// directly into `out`. `out` is appended to, not cleared.
///
/// # Errors
///
/// Same as [`encrypt`].
#[inline]
pub fn encrypt_into(
    plaintext: &[u8],
    scheme: Scheme,
    key: &Key,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    match scheme {
        #[cfg(feature = "dgcmsiv")]
        Scheme::Dgcmsiv => schemes::dgcmsiv::encrypt_into(plaintext, key, out),
        #[cfg(feature = "pgcmsiv")]
        Scheme::Pgcmsiv => schemes::pgcmsiv::encrypt_into(plaintext, key, out),
        #[cfg(feature = "dsiv")]
        Scheme::Dsiv => schemes::dsiv::encrypt_into(plaintext, key, out),
        #[cfg(feature = "psiv")]
        Scheme::Psiv => schemes::psiv::encrypt_into(plaintext, key, out),
        #[cfg(feature = "mock")]
        Scheme::Mock1 => schemes::mock1::encrypt_into(plaintext, key, out),
        #[cfg(feature = "mock")]
        Scheme::Mock2 => schemes::mock2::encrypt_into(plaintext, key, out),
    }
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

/// Decrypt `scheme_output` under `scheme`, returning the plaintext.
///
/// The scheme is supplied by the caller — the output carries no marker
/// to detect it. Supplying the wrong scheme fails the authentication
/// check rather than returning garbage.
///
/// # Errors
///
/// - [`Error::PayloadTooShort`] if `scheme_output` is shorter than the
///   scheme's minimum layout length.
/// - [`Error::DecryptionFailed`] if the AEAD tag check fails (wrong key,
///   wrong scheme, or tampered output).
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "dsiv")] {
/// use obcrypt::{encrypt, decrypt, Key, Scheme};
///
/// let key = Key::random();
/// let ct = encrypt(b"hello", Scheme::Dsiv, &key)?;
/// let pt = decrypt(&ct, Scheme::Dsiv, &key)?;
/// assert_eq!(pt, b"hello");
/// # }
/// # Ok::<(), obcrypt::Error>(())
/// ```
#[inline]
pub fn decrypt(scheme_output: &[u8], scheme: Scheme, key: &Key) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decrypt_into(scheme_output, scheme, key, &mut out)?;
    Ok(out)
}

/// Decrypt `scheme_output` under `scheme`, appending the plaintext to `out`.
///
/// `out` is appended to, not cleared. See [`decrypt`] for behavior.
///
/// # Errors
///
/// Same as [`decrypt`].
#[inline]
pub fn decrypt_into(
    scheme_output: &[u8],
    scheme: Scheme,
    key: &Key,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    match scheme {
        #[cfg(feature = "dgcmsiv")]
        Scheme::Dgcmsiv => schemes::dgcmsiv::decrypt_into(scheme_output, key, out),
        #[cfg(feature = "pgcmsiv")]
        Scheme::Pgcmsiv => schemes::pgcmsiv::decrypt_into(scheme_output, key, out),
        #[cfg(feature = "dsiv")]
        Scheme::Dsiv => schemes::dsiv::decrypt_into(scheme_output, key, out),
        #[cfg(feature = "psiv")]
        Scheme::Psiv => schemes::psiv::decrypt_into(scheme_output, key, out),
        #[cfg(feature = "mock")]
        Scheme::Mock1 => schemes::mock1::decrypt_into(scheme_output, key, out),
        #[cfg(feature = "mock")]
        Scheme::Mock2 => schemes::mock2::decrypt_into(scheme_output, key, out),
    }
}
