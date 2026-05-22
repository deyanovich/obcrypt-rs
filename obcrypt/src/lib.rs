//! Bytes-in / bytes-out cryptographic core of the
//! [oboron](https://oboron.org/) protocol.
//!
//! `obcrypt` implements oboron's `a`-tier (authenticated) and `u`-tier
//! (unauthenticated) encryption schemes operating on raw byte slices.
//! It does *not* encode the **payload** (no base64, no base32) and
//! does *not* validate UTF-8 — plaintext bytes pass through unchanged.
//!
//! Keys, on the other hand, do have a canonical text form: **hex**
//! (128 lowercase characters). [`Key::from_hex`] / [`Key::to_hex`]
//! handle that — see [`Key`] for rationale.
//!
//! For the full string-in / string-out oboron protocol — with obtext
//! encoding, format strings, and the `z`-tier obfuscation schemes — see
//! the [`oboron`](https://gitlab.com/oboron/oboron-rs) crate,
//! which depends on this crate.
//!
//! # Quick start
//!
//! ```
//! # #[cfg(feature = "aasv")] {
//! use obcrypt::{encrypt, decrypt, Key, Scheme};
//!
//! let key = Key::random();
//! let payload = encrypt(b"secret data", Scheme::Aasv, &key)?;
//! let plaintext = decrypt(&payload, &key)?;
//! assert_eq!(plaintext, b"secret data");
//! # }
//! # Ok::<(), obcrypt::Error>(())
//! ```
//!
//! # Schemes
//!
//! Each scheme is a 4-letter identifier of the form `<tier><props><alg>`:
//!
//! | Scheme | Tier | Properties | Algorithm | Use when…                           |
//! |--------|------|------------|-----------|--------------------------------------|
//! | [`Scheme::Aasv`] | a | deterministic | AES-SIV | you want auth + same-input → same-output (lookups, idempotent IDs); MOST GENERAL DEFAULT. |
//! | [`Scheme::Aags`] | a | deterministic | AES-GCM-SIV | same as `aasv` but with a 32-byte key slice; faster on hardware AES. |
//! | [`Scheme::Apsv`] | a | probabilistic | AES-SIV | you want auth + different ciphertext per call (no equality leak). |
//! | [`Scheme::Apgs`] | a | probabilistic | AES-GCM-SIV | same as `apsv`, faster on hardware AES. |
//! | [`Scheme::Upbc`] | u | probabilistic | AES-CBC | you need confidentiality but the channel already provides authenticity. |
//!
//! - **`a`-tier (authenticated)**: ciphertext is bound to a tag; the
//!   `decrypt*` functions return [`Error::DecryptionFailed`] if the
//!   ciphertext is tampered with or the wrong key is used.
//! - **`u`-tier (unauthenticated, secure)**: encrypts but does not
//!   authenticate. A flipped bit may decrypt to a different plaintext
//!   without error. Pair with an outer authentication mechanism.
//!
//! Plus testing-only schemes behind the `mock` feature flag —
//! [`Scheme::Mock1`] (identity) and [`Scheme::Mock2`] (reverse). They
//! perform **no encryption** and exist solely for round-tripping unit
//! tests, layering benchmarks, and as inert fallbacks.
//!
//! # Framed payload format
//!
//! For every scheme, the framed payload returned by [`encrypt`] is:
//!
//! ```text
//! [ scheme ciphertext bytes ][ marker[0] ^ ct[0] ][ marker[1] ^ ct[0] ]
//! ```
//!
//! - `scheme ciphertext bytes` is whatever the per-scheme primitive
//!   produces (for AEAD schemes that's `nonce || ct || tag` for the
//!   probabilistic ones, or `ct || tag` for the deterministic ones).
//! - `marker` is the 2-byte [`Scheme`] identifier (see [`Scheme::marker`]).
//! - The XOR with `ct[0]` mixes entropy into the marker so it doesn't
//!   appear as a constant trailer on short payloads.
//!
//! [`decrypt`] reverses this, dispatching on the recovered marker;
//! [`decrypt_as`] additionally checks that the marker matches the
//! caller-supplied scheme.
//!
//! # API map
//!
//! Every operation comes in two forms:
//!
//! - **Owned** — returns a fresh `Vec<u8>`. Convenient for one-shot use.
//! - **`_into`** — appends to a caller-provided `&mut Vec<u8>`.
//!   Zero-extra-allocation on the AEAD path (writes ciphertext directly
//!   into the caller's buffer via `aead::encrypt_in_place`); intended
//!   for integrators that want to pipe into a downstream encoder.
//!
//! Top-level (framed) API — applies the scheme-marker framing:
//!
//! - [`encrypt`] / [`encrypt_into`]
//! - [`decrypt`] / [`decrypt_into`] (auto-dispatch on trailing marker)
//! - [`decrypt_as`] / [`decrypt_as_into`] (require marker to match)
//!
//! Per-scheme raw API (no framing) lives under [`schemes`] for callers
//! that want to manage the marker themselves — e.g. when bypassing the
//! framed API for a tighter hot path. See `schemes::*::{encrypt,
//! decrypt, encrypt_into, decrypt_into}`.
//!
//! # Parameter convention
//!
//! All operations follow oboron's `data, scheme, key` order:
//!
//! ```text
//! encrypt(plaintext, scheme, key)            // top-level framed
//! encrypt(plaintext, key)                    // per-scheme raw (scheme is implicit)
//! encrypt_into(plaintext, scheme, key, &mut out)
//! ```
//!
//! Keys come last; data first.
//!
//! # Security model
//!
//! `obcrypt` provides **symmetric authenticated encryption** (a-tier)
//! or **symmetric unauthenticated encryption** (u-tier) over a 64-byte
//! master key. There is no asymmetric key exchange, no key derivation,
//! and no rotation built in — those belong above this layer.
//!
//! - **Authenticity**: a-tier schemes detect tampering via the AEAD's
//!   tag. u-tier schemes do not.
//! - **Determinism**: deterministic variants (`aasv`, `aags`) leak
//!   plaintext equality (same plaintext + same key → same ciphertext).
//!   This is sometimes desired (lookups, idempotent IDs); when it isn't,
//!   use a probabilistic variant (`apsv`, `apgs`, `upbc`).
//! - **Nonce handling**: probabilistic schemes generate a fresh random
//!   nonce per call from the OS RNG and prepend it to the payload. Even
//!   under nonce reuse, AES-SIV and AES-GCM-SIV degrade gracefully (only
//!   to the equality-leak property of the deterministic variants).
//! - **Side channels**: obcrypt relies on the underlying `aes-siv`,
//!   `aes-gcm-siv`, `aes`, and `cbc` crates for constant-time
//!   primitives where applicable. No additional side-channel hardening
//!   is added at this layer.
//! - **Key zeroization**: [`Key`] is `ZeroizeOnDrop`; the 64 key bytes
//!   are zeroed when the value is dropped.
//!
//! See [`SECURITY.md`](https://gitlab.com/oboron/obcrypt-rs/-/blob/master/obcrypt/SECURITY.md)
//! for the full threat model, algorithm justification, and vulnerability
//! reporting policy.
//!
//! # Cargo features
//!
//! - `default = ["secure-schemes"]` — enables every production scheme.
//! - `secure-schemes = ["atier", "utier"]` — convenience alias.
//! - `atier = ["aags", "apgs", "aasv", "apsv"]` — every a-tier scheme.
//! - `utier = ["upbc"]` — every u-tier scheme.
//! - Per-scheme: `aags`, `apgs`, `aasv`, `apsv`, `upbc`.
//! - `mock` — adds [`Scheme::Mock1`] and [`Scheme::Mock2`] (testing only,
//!   not for production).
//!
//! Schemes are individually gated so binary size scales with the schemes
//! you actually use. See
//! [`FEATURES.md`](https://gitlab.com/oboron/obcrypt-rs/-/blob/master/obcrypt/FEATURES.md)
//! for the full matrix.

mod constants;
mod error;
mod key;
mod keygen;
mod scheme;

pub mod schemes;

pub use constants::SCHEME_MARKER_SIZE;
pub use error::Error;
pub use key::Key;
pub use keygen::generate_key;
pub use scheme::Scheme;

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` under `scheme` and return the framed payload.
///
/// The output is `ciphertext || marker_xor`: the scheme's raw
/// ciphertext (which may itself include a prepended nonce, depending on
/// the scheme) followed by two scheme-marker bytes XORed with
/// `ciphertext[0]`. See the [crate docs](crate#framed-payload-format)
/// for the framing details.
///
/// # Errors
///
/// - [`Error::EmptyPlaintext`] if `plaintext` is empty.
/// - [`Error::EncryptionFailed`] if the underlying AEAD primitive
///   reports failure (in practice: out-of-memory or platform-level
///   randomness failure for probabilistic schemes).
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "aasv")] {
/// use obcrypt::{encrypt, Key, Scheme};
///
/// let key = Key::random();
/// let payload = encrypt(b"hello", Scheme::Aasv, &key)?;
/// assert!(payload.len() > b"hello".len()); // framed (tag + marker)
/// # }
/// # Ok::<(), obcrypt::Error>(())
/// ```
#[inline]
pub fn encrypt(plaintext: &[u8], scheme: Scheme, key: &Key) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    encrypt_into(plaintext, scheme, key, &mut out)?;
    Ok(out)
}

/// Encrypt `plaintext` under `scheme`, appending the framed payload to `out`.
///
/// This is the zero-extra-allocation form intended for integrators that
/// want to pipe the framed payload directly into a downstream buffer
/// (e.g. an encoder writing into a pre-sized output buffer). The
/// scheme's ciphertext is written directly into `out` via the per-
/// scheme `encrypt_into` (no intermediate `Vec`); then the 2-byte
/// XOR'd scheme marker is pushed.
///
/// `out` is appended to, not cleared. If you pass a non-empty `out`,
/// the framed payload is concatenated to whatever was there.
///
/// # Errors
///
/// Same as [`encrypt`].
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "aasv")] {
/// use obcrypt::{encrypt_into, Key, Scheme};
///
/// let key = Key::random();
/// let mut buf = Vec::new();
/// encrypt_into(b"hello", Scheme::Aasv, &key, &mut buf)?;
/// // `buf` now holds the framed payload.
/// # }
/// # Ok::<(), obcrypt::Error>(())
/// ```
#[inline]
pub fn encrypt_into(
    plaintext: &[u8],
    scheme: Scheme,
    key: &Key,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    let start = out.len();
    encrypt_raw_into(plaintext, scheme, key, out)?;
    let marker = scheme.marker();
    let first = out[start];
    out.push(marker[0] ^ first);
    out.push(marker[1] ^ first);
    Ok(())
}

#[inline(always)]
fn encrypt_raw_into(
    plaintext: &[u8],
    scheme: Scheme,
    key: &Key,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    match scheme {
        #[cfg(feature = "aags")]
        Scheme::Aags => schemes::aags::encrypt_into(plaintext, key, out),
        #[cfg(feature = "apgs")]
        Scheme::Apgs => schemes::apgs::encrypt_into(plaintext, key, out),
        #[cfg(feature = "aasv")]
        Scheme::Aasv => schemes::aasv::encrypt_into(plaintext, key, out),
        #[cfg(feature = "apsv")]
        Scheme::Apsv => schemes::apsv::encrypt_into(plaintext, key, out),
        #[cfg(feature = "upbc")]
        Scheme::Upbc => schemes::upbc::encrypt_into(plaintext, key, out),
        #[cfg(feature = "mock")]
        Scheme::Mock1 => schemes::mock1::encrypt_into(plaintext, key, out),
        #[cfg(feature = "mock")]
        Scheme::Mock2 => schemes::mock2::encrypt_into(plaintext, key, out),
    }
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

/// Decrypt a framed payload, auto-detecting the scheme from the trailing marker.
///
/// Reads the trailing 2-byte XOR'd marker, identifies the scheme via
/// [`Scheme::from_marker`], then dispatches to the appropriate per-scheme
/// `decrypt`. Use this when the caller doesn't know the scheme up front
/// (typical for general-purpose decoders); use [`decrypt_as`] when the
/// scheme is known and you want to verify the payload matches.
///
/// # Errors
///
/// - [`Error::PayloadTooShort`] if `payload` doesn't carry at least the
///   marker + 1 ciphertext byte.
/// - [`Error::UnknownScheme`] if the recovered marker doesn't match any
///   feature-enabled scheme.
/// - [`Error::DecryptionFailed`] if the AEAD tag check fails (a-tier),
///   or padding doesn't validate (u-tier `upbc`).
/// - [`Error::InvalidBlockLength`] for `upbc` if the payload's
///   ciphertext length isn't a multiple of the AES block size.
/// - [`Error::EmptyPayload`] only for the mock schemes' empty-input
///   guard.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "aasv")] {
/// use obcrypt::{encrypt, decrypt, Key, Scheme};
///
/// let key = Key::random();
/// let payload = encrypt(b"hello", Scheme::Aasv, &key)?;
/// let plaintext = decrypt(&payload, &key)?;
/// assert_eq!(plaintext, b"hello");
/// # }
/// # Ok::<(), obcrypt::Error>(())
/// ```
#[inline]
pub fn decrypt(payload: &[u8], key: &Key) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decrypt_into(payload, key, &mut out)?;
    Ok(out)
}

/// Decrypt a framed payload (auto-detected scheme), appending plaintext to `out`.
///
/// `out` is appended to, not cleared. See [`decrypt`] for behavior and
/// [`encrypt_into`] for the symmetric `_into` rationale.
///
/// # Errors
///
/// Same as [`decrypt`].
#[inline]
pub fn decrypt_into(payload: &[u8], key: &Key, out: &mut Vec<u8>) -> Result<(), Error> {
    let (scheme, ciphertext_end) = parse_marker(payload)?;
    decrypt_raw_into(&payload[..ciphertext_end], scheme, key, out)
}

/// Decrypt a framed payload, requiring the trailing marker to match `scheme`.
///
/// Use this over [`decrypt`] when the caller already knows which scheme
/// the payload should be encoded under — it adds a marker-mismatch
/// check that catches confusion between scheme variants.
///
/// # Errors
///
/// Same as [`decrypt`], plus:
///
/// - [`Error::SchemeMarkerMismatch`] if the recovered marker doesn't
///   match `scheme`.
///
/// # Examples
///
/// ```
/// # #[cfg(all(feature = "aasv", feature = "apsv"))] {
/// use obcrypt::{encrypt, decrypt_as, Error, Key, Scheme};
///
/// let key = Key::random();
/// let payload = encrypt(b"hello", Scheme::Aasv, &key)?;
///
/// // Same scheme: ok.
/// assert_eq!(decrypt_as(&payload, Scheme::Aasv, &key)?, b"hello");
///
/// // Different scheme: rejected with SchemeMarkerMismatch.
/// assert!(matches!(
///     decrypt_as(&payload, Scheme::Apsv, &key),
///     Err(Error::SchemeMarkerMismatch)
/// ));
/// # }
/// # Ok::<(), obcrypt::Error>(())
/// ```
#[inline]
pub fn decrypt_as(payload: &[u8], scheme: Scheme, key: &Key) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decrypt_as_into(payload, scheme, key, &mut out)?;
    Ok(out)
}

/// Decrypt a framed payload requiring marker to match `scheme`, appending plaintext to `out`.
///
/// `out` is appended to, not cleared. See [`decrypt_as`] for behavior.
///
/// # Errors
///
/// Same as [`decrypt_as`].
#[inline]
pub fn decrypt_as_into(
    payload: &[u8],
    scheme: Scheme,
    key: &Key,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    let (found, ciphertext_end) = parse_marker(payload)?;
    if found != scheme {
        return Err(Error::SchemeMarkerMismatch);
    }
    decrypt_raw_into(&payload[..ciphertext_end], scheme, key, out)
}

/// Parse the trailing scheme marker from a framed payload.
///
/// Returns `(scheme, ciphertext_end_index)` — the index past which the
/// trailing marker lives. The slice `&payload[..ciphertext_end_index]`
/// is the raw ciphertext to hand to the scheme-specific decrypt
/// function.
#[inline(always)]
fn parse_marker(payload: &[u8]) -> Result<(Scheme, usize), Error> {
    if payload.len() < SCHEME_MARKER_SIZE + 1 {
        return Err(Error::PayloadTooShort);
    }
    let len = payload.len();
    let first = payload[0];
    let marker = [payload[len - 2] ^ first, payload[len - 1] ^ first];
    Ok((Scheme::from_marker(marker)?, len - SCHEME_MARKER_SIZE))
}

#[inline(always)]
fn decrypt_raw_into(
    ciphertext: &[u8],
    scheme: Scheme,
    key: &Key,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    match scheme {
        #[cfg(feature = "aags")]
        Scheme::Aags => schemes::aags::decrypt_into(ciphertext, key, out),
        #[cfg(feature = "apgs")]
        Scheme::Apgs => schemes::apgs::decrypt_into(ciphertext, key, out),
        #[cfg(feature = "aasv")]
        Scheme::Aasv => schemes::aasv::decrypt_into(ciphertext, key, out),
        #[cfg(feature = "apsv")]
        Scheme::Apsv => schemes::apsv::decrypt_into(ciphertext, key, out),
        #[cfg(feature = "upbc")]
        Scheme::Upbc => schemes::upbc::decrypt_into(ciphertext, key, out),
        #[cfg(feature = "mock")]
        Scheme::Mock1 => schemes::mock1::decrypt_into(ciphertext, key, out),
        #[cfg(feature = "mock")]
        Scheme::Mock2 => schemes::mock2::decrypt_into(ciphertext, key, out),
    }
}
