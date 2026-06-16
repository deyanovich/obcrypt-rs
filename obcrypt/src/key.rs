//! 64-byte symmetric master key.
//!
//! [`Key`] wraps a 64-byte buffer with [`Zeroize`] / [`ZeroizeOnDrop`]
//! semantics: the bytes are zeroed when the `Key` is dropped, and the
//! [`Debug`](std::fmt::Debug) impl redacts the contents.
//!
//! Schemes consume the master differently:
//!
//! - `dsiv` / `psiv` (AES-SIV) use all 64 bytes directly.
//! - `dgcmsiv` / `pgcmsiv` (AES-GCM-SIV) derive a 32-byte AES-256 key
//!   from the master with `HKDF-Expand` (HMAC-SHA-256, info `gcmsiv`,
//!   shared by both), so a single master serves every scheme.
//!
//! # Text encoding
//!
//! The canonical text encoding for an obcrypt key is **hex** (128
//! lowercase characters). [`Key::from_hex`] / [`Key::to_hex`] handle
//! this directly. obcrypt does not support other text encodings (e.g.
//! base64, base32) — those are the responsibility of higher-level
//! libraries that need them. Hex was chosen as the canonical encoding
//! because in cryptography clarity beats compactness; the
//! length-saving over base64 is too small to justify the visual
//! noise.

use crate::Error;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 64-byte symmetric master key for obcrypt operations.
///
/// Construct from raw bytes ([`Self::from_bytes`], [`Self::from_slice`]),
/// from a hex string ([`Self::from_hex`]), or generate fresh
/// ([`Self::random`]). Hex is the canonical text encoding — see the
/// [module docs] for rationale.
///
/// [module docs]: index.html#text-encoding
///
/// # Zeroization
///
/// The underlying byte array is zeroed when the `Key` is dropped (via
/// `ZeroizeOnDrop`). Cloning produces a new `Key` whose own bytes are
/// independently zeroed on drop.
///
/// # Debug redaction
///
/// The [`Debug`](std::fmt::Debug) impl prints `Key { bytes: "[redacted]" }`
/// rather than the actual key material — safe to log accidentally.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key {
    bytes: [u8; 64],
}

impl Key {
    /// Construct a key from 64 raw bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use obcrypt::Key;
    ///
    /// let raw = [0u8; 64];
    /// let key = Key::from_bytes(raw);
    /// ```
    #[inline]
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Key { bytes }
    }

    /// Construct a key from a byte slice.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKeyLength`] if `bytes` isn't exactly 64 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use obcrypt::{Error, Key};
    ///
    /// let raw = vec![0u8; 64];
    /// let key = Key::from_slice(&raw)?;
    ///
    /// let bad = vec![0u8; 32];
    /// assert!(matches!(Key::from_slice(&bad), Err(Error::InvalidKeyLength)));
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; 64] = bytes.try_into().map_err(|_| Error::InvalidKeyLength)?;
        Ok(Key { bytes: arr })
    }

    /// Generate a fresh random 64-byte key from the OS RNG
    /// ([`rand::thread_rng`]).
    ///
    /// # Panics
    ///
    /// Panics if the OS RNG fails (extremely rare; would also break
    /// the probabilistic schemes).
    ///
    /// # Examples
    ///
    /// ```
    /// use obcrypt::Key;
    ///
    /// let key = Key::random();
    /// assert_eq!(key.as_bytes().len(), 64);
    /// ```
    #[inline]
    pub fn random() -> Self {
        let mut bytes = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut bytes);
        Key { bytes }
    }

    /// Borrow the underlying 64 bytes.
    ///
    /// `dsiv`/`psiv` use all 64 bytes directly; `dgcmsiv`/`pgcmsiv`
    /// derive their 32-byte AES key from the master via HKDF.
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    /// Construct a key from a 128-character hex string (lowercase or
    /// uppercase, no `0x` prefix).
    ///
    /// Hex is the canonical text encoding for obcrypt keys.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHex`] if `s` isn't valid hex or doesn't decode
    /// to exactly 64 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use obcrypt::Key;
    ///
    /// let hex = "0".repeat(128);
    /// let key = Key::from_hex(&hex)?;
    /// assert_eq!(key.as_bytes(), &[0u8; 64]);
    /// # Ok::<(), obcrypt::Error>(())
    /// ```
    #[inline]
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let bytes = hex::decode(s).map_err(|_| Error::InvalidHex)?;
        let arr: [u8; 64] = bytes.try_into().map_err(|_| Error::InvalidHex)?;
        Ok(Key { bytes: arr })
    }

    /// Encode the key as a 128-character lowercase hex string.
    ///
    /// Inverse of [`Self::from_hex`].
    ///
    /// # Examples
    ///
    /// ```
    /// use obcrypt::Key;
    ///
    /// let key = Key::from_bytes([0u8; 64]);
    /// assert_eq!(key.to_hex().len(), 128);
    /// ```
    #[inline]
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key").field("bytes", &"[redacted]").finish()
    }
}
