//! Scheme identifiers for obcrypt encryption schemes.
//!
//! A [`Scheme`] is a tagged enum identifying *what* algorithm a payload
//! was encrypted with. Each variant maps to a 2-byte marker (see
//! [`Scheme::marker`]) used in the framed payload format documented at
//! the [crate root](crate#framed-payload-format).
//!
//! Variants are conditionally compiled per the corresponding feature
//! flag (`aags`, `aasv`, `apgs`, `apsv`, `upbc`, `mock`).

use crate::{constants, error::Error};

/// Scheme identifier — selects the algorithm + properties of a payload.
///
/// See the [crate-level scheme table](crate#schemes) for guidance on
/// when to use which.
///
/// All variants are conditionally compiled. Only variants whose
/// corresponding cargo feature is enabled exist in your build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// **a-tier, deterministic, AES-GCM-SIV.** Authenticated; same
    /// plaintext + same key → same ciphertext (leaks plaintext
    /// equality, sometimes desired for IDs / lookups). Uses 32 bytes
    /// of the master key (`key[32..64]`).
    #[cfg(feature = "aags")]
    Aags,
    /// **a-tier, probabilistic, AES-GCM-SIV.** Authenticated; nonce
    /// generated per call from the OS RNG and prepended to the
    /// ciphertext. Uses 32 bytes of the master key (`key[32..64]`).
    #[cfg(feature = "apgs")]
    Apgs,
    /// **a-tier, deterministic, AES-SIV.** Authenticated; same
    /// plaintext + same key → same ciphertext (leaks plaintext
    /// equality, sometimes desired for IDs / lookups). Uses the full
    /// 64-byte master key. **Default recommendation** for new
    /// deterministic-encryption use cases.
    #[cfg(feature = "aasv")]
    Aasv,
    /// **a-tier, probabilistic, AES-SIV.** Authenticated; nonce
    /// generated per call from the OS RNG and prepended to the
    /// ciphertext. Uses the full 64-byte master key. Nonce-misuse
    /// resistant — even under accidental nonce reuse, only the
    /// equality-leak property of `aasv` emerges (no catastrophic loss).
    #[cfg(feature = "apsv")]
    Apsv,
    /// **u-tier, probabilistic, AES-CBC.** **Unauthenticated** — only
    /// confidentiality, no integrity. Random IV per call. Uses 32
    /// bytes of the master key (`key[8..40]`). Pair with an outer
    /// authentication mechanism.
    #[cfg(feature = "upbc")]
    Upbc,
    /// **Mock — identity (no encryption).** Returns plaintext
    /// unchanged. Behind the `mock` feature flag. Testing only —
    /// **never** use in production.
    #[cfg(feature = "mock")]
    Mock1,
    /// **Mock — reverse (no encryption).** Returns plaintext bytes
    /// reversed. Behind the `mock` feature flag. Testing only —
    /// **never** use in production.
    #[cfg(feature = "mock")]
    Mock2,
}

impl Scheme {
    /// Lowercase 4-letter identifier of this scheme (`"aags"`, `"aasv"`, …).
    pub fn as_str(&self) -> &'static str {
        match self {
            #[cfg(feature = "aags")]
            Scheme::Aags => "aags",
            #[cfg(feature = "apgs")]
            Scheme::Apgs => "apgs",
            #[cfg(feature = "aasv")]
            Scheme::Aasv => "aasv",
            #[cfg(feature = "apsv")]
            Scheme::Apsv => "apsv",
            #[cfg(feature = "upbc")]
            Scheme::Upbc => "upbc",
            #[cfg(feature = "mock")]
            Scheme::Mock1 => "mock1",
            #[cfg(feature = "mock")]
            Scheme::Mock2 => "mock2",
        }
    }

    /// `true` if same plaintext + same key always produces the same
    /// ciphertext — i.e. ciphertext leaks plaintext equality.
    ///
    /// Deterministic schemes are useful for lookups (you can encrypt a
    /// query and compare against stored ciphertext) and idempotent
    /// IDs. They're not appropriate when an observer should be unable
    /// to tell if two payloads carry the same plaintext.
    pub fn is_deterministic(&self) -> bool {
        match self {
            #[cfg(feature = "aags")]
            Scheme::Aags => true,
            #[cfg(feature = "apgs")]
            Scheme::Apgs => false,
            #[cfg(feature = "aasv")]
            Scheme::Aasv => true,
            #[cfg(feature = "apsv")]
            Scheme::Apsv => false,
            #[cfg(feature = "upbc")]
            Scheme::Upbc => false,
            #[cfg(feature = "mock")]
            Scheme::Mock1 => true,
            #[cfg(feature = "mock")]
            Scheme::Mock2 => true,
        }
    }

    /// `true` if a fresh random nonce is generated per call, so the
    /// ciphertext for the same plaintext varies between calls.
    ///
    /// Inverse of [`Self::is_deterministic`].
    pub fn is_probabilistic(&self) -> bool {
        !self.is_deterministic()
    }

    /// The 2-byte scheme marker.
    ///
    /// In the framed payload, both bytes are XORed with the first
    /// ciphertext byte before being appended (so they don't appear as
    /// a constant trailer on short payloads). See the
    /// [framed payload format](crate#framed-payload-format) at the
    /// crate root.
    pub fn marker(&self) -> [u8; 2] {
        match self {
            #[cfg(feature = "aags")]
            Scheme::Aags => constants::AAGS_MARKER,
            #[cfg(feature = "apgs")]
            Scheme::Apgs => constants::APGS_MARKER,
            #[cfg(feature = "aasv")]
            Scheme::Aasv => constants::AASV_MARKER,
            #[cfg(feature = "apsv")]
            Scheme::Apsv => constants::APSV_MARKER,
            #[cfg(feature = "upbc")]
            Scheme::Upbc => constants::UPBC_MARKER,
            #[cfg(feature = "mock")]
            Scheme::Mock1 => constants::MOCK1_MARKER,
            #[cfg(feature = "mock")]
            Scheme::Mock2 => constants::MOCK2_MARKER,
        }
    }

    /// Look up a scheme from its 2-byte marker.
    ///
    /// Used by [`crate::decrypt`] / [`crate::decrypt_into`] to dispatch
    /// on the trailing marker after un-XOR'ing it.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownScheme`] if `marker` doesn't match any
    /// feature-enabled scheme.
    pub fn from_marker(marker: [u8; 2]) -> Result<Self, Error> {
        match marker {
            #[cfg(feature = "aags")]
            constants::AAGS_MARKER => Ok(Scheme::Aags),
            #[cfg(feature = "apgs")]
            constants::APGS_MARKER => Ok(Scheme::Apgs),
            #[cfg(feature = "aasv")]
            constants::AASV_MARKER => Ok(Scheme::Aasv),
            #[cfg(feature = "apsv")]
            constants::APSV_MARKER => Ok(Scheme::Apsv),
            #[cfg(feature = "upbc")]
            constants::UPBC_MARKER => Ok(Scheme::Upbc),
            #[cfg(feature = "mock")]
            constants::MOCK1_MARKER => Ok(Scheme::Mock1),
            #[cfg(feature = "mock")]
            constants::MOCK2_MARKER => Ok(Scheme::Mock2),
            _ => Err(Error::UnknownScheme),
        }
    }
}

impl std::str::FromStr for Scheme {
    type Err = Error;

    /// Parse a scheme from its 4-letter identifier (case-insensitive).
    ///
    /// Inverse of [`Scheme::as_str`].
    ///
    /// # Errors
    ///
    /// [`Error::UnknownScheme`] if `s` doesn't match a feature-enabled
    /// scheme name.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            #[cfg(feature = "aags")]
            _ if s.eq_ignore_ascii_case("aags") => Ok(Scheme::Aags),
            #[cfg(feature = "apgs")]
            _ if s.eq_ignore_ascii_case("apgs") => Ok(Scheme::Apgs),
            #[cfg(feature = "aasv")]
            _ if s.eq_ignore_ascii_case("aasv") => Ok(Scheme::Aasv),
            #[cfg(feature = "apsv")]
            _ if s.eq_ignore_ascii_case("apsv") => Ok(Scheme::Apsv),
            #[cfg(feature = "upbc")]
            _ if s.eq_ignore_ascii_case("upbc") => Ok(Scheme::Upbc),
            #[cfg(feature = "mock")]
            _ if s.eq_ignore_ascii_case("mock1") => Ok(Scheme::Mock1),
            #[cfg(feature = "mock")]
            _ if s.eq_ignore_ascii_case("mock2") => Ok(Scheme::Mock2),
            _ => Err(Error::UnknownScheme),
        }
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
