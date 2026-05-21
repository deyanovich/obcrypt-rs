//! Error types returned by obcrypt operations.

use thiserror::Error;

/// All errors that can occur in obcrypt operations.
///
/// `#[non_exhaustive]` — new variants may be added in minor releases.
/// Match with a wildcard arm if you exhaustively-match in your code.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    /// `Key::from_slice` was called with a slice whose length isn't 64.
    #[error("key must be 64 bytes")]
    InvalidKeyLength,

    /// `Key::from_hex` was called with a string that isn't valid hex
    /// or doesn't decode to exactly 64 bytes (i.e. isn't 128 hex
    /// characters).
    #[error("invalid hex key (expected 128 hex characters)")]
    InvalidHex,

    /// `Scheme::from_marker` / `Scheme::from_str` / [`crate::decrypt`]
    /// could not match the input to any feature-enabled scheme.
    #[error("unknown scheme")]
    UnknownScheme,

    /// [`crate::decrypt_as`] / [`crate::decrypt_as_into`] found a
    /// trailing marker that didn't match the expected scheme.
    #[error("scheme marker mismatch")]
    SchemeMarkerMismatch,

    /// The underlying AEAD primitive reported a generic encryption
    /// failure (in practice: out-of-memory or RNG failure).
    #[error("encryption failed")]
    EncryptionFailed,

    /// `encrypt*` was called with `plaintext.is_empty()`.
    #[error("encryption failed: empty plaintext")]
    EmptyPlaintext,

    /// AEAD tag check failed (a-tier) or padding didn't validate
    /// (`upbc`). Indicates wrong key, tampered ciphertext, or scheme
    /// mismatch slipping past the marker dispatch.
    #[error("decryption failed")]
    DecryptionFailed,

    /// `decrypt*` (mock schemes) was called with `payload.is_empty()`.
    #[error("decryption failed: empty payload")]
    EmptyPayload,

    /// Payload doesn't carry enough bytes for the framed format
    /// (marker + at least one ciphertext byte) or the scheme's
    /// minimum payload (e.g. SIV's tag size).
    #[error("decryption failed: payload too short")]
    PayloadTooShort,

    /// `upbc` decrypt: ciphertext length isn't a multiple of the AES
    /// block size (16). Indicates a corrupted payload — CBC requires
    /// block-aligned ciphertext.
    #[error("decryption failed: invalid block length")]
    InvalidBlockLength,
}
