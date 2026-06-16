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

    /// [`Scheme::from_str`](crate::Scheme) could not match the input to
    /// any feature-enabled scheme.
    #[error("unknown scheme")]
    UnknownScheme,

    /// The underlying AEAD primitive reported a generic encryption
    /// failure (in practice: out-of-memory or RNG failure).
    #[error("encryption failed")]
    EncryptionFailed,

    /// `encrypt*` was called with `plaintext.is_empty()`.
    #[error("encryption failed: empty plaintext")]
    EmptyPlaintext,

    /// AEAD tag check failed. Indicates a wrong key, a tampered
    /// ciphertext, or the wrong scheme supplied for decryption.
    #[error("decryption failed")]
    DecryptionFailed,

    /// `decrypt*` (mock schemes) was called with `payload.is_empty()`.
    #[error("decryption failed: empty payload")]
    EmptyPayload,

    /// The scheme output is shorter than the scheme's minimum layout
    /// length (e.g. a SIV tag, or a probabilistic scheme's nonce plus
    /// tag) — so it cannot be a valid output.
    #[error("decryption failed: payload too short")]
    PayloadTooShort,
}
