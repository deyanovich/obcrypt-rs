//! Per-scheme raw cryptographic primitives.
//!
//! Each submodule exposes four functions for one scheme:
//!
//! - `encrypt(plaintext, key) -> Vec<u8>`
//! - `encrypt_into(plaintext, key, &mut Vec<u8>)`
//! - `decrypt(scheme_output, key) -> Vec<u8>`
//! - `decrypt_into(scheme_output, key, &mut Vec<u8>)`
//!
//! These produce / consume the scheme's own output bytes — whatever the
//! underlying AEAD returns. The top-level [`crate::encrypt`] /
//! [`crate::decrypt`] dispatch to these by [`crate::Scheme`]; the output
//! carries no scheme marker.
//!
//! # Owned vs `_into`
//!
//! - The owned form (`encrypt` / `decrypt`) calls the AEAD's own
//!   exact-capacity path — fastest for "give me a `Vec`".
//! - The `_into` form writes directly into the caller's buffer via
//!   `aead::encrypt_in_place` (with a private `TailBuffer` adapter) —
//!   zero intermediate allocation, intended for integrators that pipe
//!   into a downstream encoder.

// Only the four real AEAD schemes use the in-place `_into` adapter; the
// mock schemes append directly. Gate it so a mock-only build stays
// warning-clean.
#[cfg(any(
    feature = "dgcmsiv",
    feature = "pgcmsiv",
    feature = "dsiv",
    feature = "psiv"
))]
pub(crate) mod buffer;

/// Shared GCM-SIV key derivation for `dgcmsiv` / `pgcmsiv`.
///
/// Both GCM-SIV schemes derive the same 32-byte AES-256-GCM-SIV key
/// from the master; keeping that derivation in one place (rather than
/// duplicated per scheme) ensures the security-sensitive HKDF step
/// cannot drift between them.
#[cfg(any(feature = "dgcmsiv", feature = "pgcmsiv"))]
pub(crate) mod gcmsiv {
    use crate::Key;
    use hkdf::Hkdf;
    use sha2::Sha256;
    use zeroize::Zeroizing;

    /// HKDF-Expand the 64-byte master into the 32-byte AES-256-GCM-SIV
    /// key shared by `dgcmsiv` and `pgcmsiv`.
    ///
    /// `key = HKDF-Expand(PRK = master, info = "gcmsiv", L = 32)` over
    /// HMAC-SHA-256 (RFC 5869). HKDF-Extract is omitted: the 64-byte
    /// master is already a uniform pseudorandom key and serves directly
    /// as the PRK. The `gcmsiv` info is shared, so both GCM-SIV schemes
    /// derive the same key (safe by GCM-SIV nonce-misuse resistance).
    /// See the oboron spec, §3.1.
    #[inline]
    pub(crate) fn derive_key(key: &Key) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::from_prk(key.as_bytes()).expect("master is a valid 64-byte PRK");
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(b"gcmsiv", &mut okm[..])
            .expect("32-byte OKM is within HKDF length bounds");
        okm
    }
}

#[cfg(feature = "dgcmsiv")]
pub mod dgcmsiv;
#[cfg(feature = "dsiv")]
pub mod dsiv;
#[cfg(feature = "pgcmsiv")]
pub mod pgcmsiv;
#[cfg(feature = "psiv")]
pub mod psiv;

#[cfg(feature = "mock")]
pub mod mock1;
#[cfg(feature = "mock")]
pub mod mock2;
