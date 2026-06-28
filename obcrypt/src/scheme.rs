//! Scheme identifiers for obcrypt encryption schemes.
//!
//! A [`Scheme`] selects the AEAD algorithm and properties for an
//! operation. The scheme is supplied by the caller to both `encrypt`
//! and `decrypt` — the output carries no marker. Variants are
//! conditionally compiled per the corresponding feature flag
//! (`dgcmsiv`, `dsiv`, `pgcmsiv`, `psiv`, `mock`).

use crate::error::Error;

/// Scheme identifier — selects the algorithm + properties.
///
/// See the [crate-level scheme table](crate#schemes) for guidance on
/// when to use which.
///
/// All variants are conditionally compiled. Only variants whose
/// corresponding cargo feature is enabled exist in your build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// **Deterministic, AES-GCM-SIV.** Authenticated; same plaintext +
    /// key → same output (leaks plaintext equality). Key derived from
    /// the master via HKDF.
    #[cfg(feature = "dgcmsiv")]
    Dgcmsiv,
    /// **Probabilistic, AES-GCM-SIV.** Authenticated; fresh random nonce
    /// per call, prepended to the output. Key derived from the master
    /// via HKDF.
    #[cfg(feature = "pgcmsiv")]
    Pgcmsiv,
    /// **Deterministic, AES-SIV.** Authenticated; same plaintext + key →
    /// same output (leaks plaintext equality). Uses the full 64-byte
    /// master key.
    #[cfg(feature = "dsiv")]
    Dsiv,
    /// **Probabilistic, AES-SIV.** Authenticated; fresh random nonce per
    /// call, supplied as associated data and prepended to the output.
    /// Uses the full 64-byte master key. Nonce-misuse resistant.
    #[cfg(feature = "psiv")]
    Psiv,
    /// **Mock — identity (no encryption).** Returns plaintext unchanged.
    /// Behind the `mock` feature flag. Testing only — **never** use in
    /// production.
    #[cfg(feature = "mock")]
    Mock1,
    /// **Mock — reverse (no encryption).** Returns plaintext bytes
    /// reversed. Behind the `mock` feature flag. Testing only —
    /// **never** use in production.
    #[cfg(feature = "mock")]
    Mock2,
}

impl Scheme {
    /// Lowercase scheme identifier (`"dgcmsiv"`, `"dsiv"`, …).
    pub fn as_str(&self) -> &'static str {
        match self {
            #[cfg(feature = "dgcmsiv")]
            Scheme::Dgcmsiv => "dgcmsiv",
            #[cfg(feature = "pgcmsiv")]
            Scheme::Pgcmsiv => "pgcmsiv",
            #[cfg(feature = "dsiv")]
            Scheme::Dsiv => "dsiv",
            #[cfg(feature = "psiv")]
            Scheme::Psiv => "psiv",
            #[cfg(feature = "mock")]
            Scheme::Mock1 => "mock1",
            #[cfg(feature = "mock")]
            Scheme::Mock2 => "mock2",
        }
    }

    /// `true` if same plaintext + same key always produces the same
    /// output — i.e. the output leaks plaintext equality.
    ///
    /// Deterministic schemes are useful for lookups (encrypt a query and
    /// compare against stored output) and idempotent IDs. They're not
    /// appropriate when an observer should be unable to tell whether two
    /// outputs carry the same plaintext.
    pub fn is_deterministic(&self) -> bool {
        match self {
            #[cfg(feature = "dgcmsiv")]
            Scheme::Dgcmsiv => true,
            #[cfg(feature = "pgcmsiv")]
            Scheme::Pgcmsiv => false,
            #[cfg(feature = "dsiv")]
            Scheme::Dsiv => true,
            #[cfg(feature = "psiv")]
            Scheme::Psiv => false,
            #[cfg(feature = "mock")]
            Scheme::Mock1 => true,
            #[cfg(feature = "mock")]
            Scheme::Mock2 => true,
        }
    }

    /// `true` if a fresh random nonce is generated per call, so the
    /// output for the same plaintext varies between calls.
    ///
    /// Inverse of [`Self::is_deterministic`].
    pub fn is_probabilistic(&self) -> bool {
        !self.is_deterministic()
    }
}

impl std::str::FromStr for Scheme {
    type Err = Error;

    /// Parse a core scheme from its identifier (case-insensitive).
    ///
    /// Inverse of [`Scheme::as_str`] **for the four authenticated core
    /// schemes only**. The testing-only `mock1` / `mock2` schemes are
    /// deliberately *not* parseable from a string, even when the `mock`
    /// feature is enabled: a no-encryption scheme must never be
    /// selectable through a string/config channel (which is the channel
    /// most likely to carry external input). Construct them explicitly
    /// via the `Scheme::Mock1` / `Scheme::Mock2` variants when needed in
    /// tests.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownScheme`] if `s` doesn't match a feature-enabled
    /// core scheme name (`"mock1"` / `"mock2"` always return this error).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            #[cfg(feature = "dgcmsiv")]
            _ if s.eq_ignore_ascii_case("dgcmsiv") => Ok(Scheme::Dgcmsiv),
            #[cfg(feature = "pgcmsiv")]
            _ if s.eq_ignore_ascii_case("pgcmsiv") => Ok(Scheme::Pgcmsiv),
            #[cfg(feature = "dsiv")]
            _ if s.eq_ignore_ascii_case("dsiv") => Ok(Scheme::Dsiv),
            #[cfg(feature = "psiv")]
            _ if s.eq_ignore_ascii_case("psiv") => Ok(Scheme::Psiv),
            _ => Err(Error::UnknownScheme),
        }
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
