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

pub(crate) mod buffer;

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
