//! Per-scheme raw cryptographic primitives — bypasses framing.
//!
//! Each submodule exposes four functions for one scheme:
//!
//! - `encrypt(plaintext, key) -> Vec<u8>`
//! - `encrypt_into(plaintext, key, &mut Vec<u8>)`
//! - `decrypt(ciphertext, key) -> Vec<u8>`
//! - `decrypt_into(ciphertext, key, &mut Vec<u8>)`
//!
//! These produce / consume the **scheme's own** ciphertext bytes —
//! whatever the underlying AEAD or block cipher returns. The 2-byte
//! XOR'd scheme marker that the [crate root](crate#framed-payload-format)
//! describes is *not* applied here; that's the framed-API's job.
//!
//! # When to use the per-scheme API
//!
//! - You're managing the scheme identifier out-of-band and don't need
//!   the marker (e.g. you store scheme + ciphertext in separate columns).
//! - You're a hot-path consumer that wants to skip the dispatch layer
//!   in [`crate::encrypt`] / [`crate::decrypt`]. The static-dispatch
//!   `oboron::AasvC32` codec types do this.
//!
//! # When to use the framed top-level API
//!
//! - You want a single byte slice that carries scheme + ciphertext and
//!   can self-identify on decrypt.
//! - You want auto-dispatch in [`crate::decrypt`] without tracking the
//!   scheme separately.
//!
//! # Owned vs `_into`
//!
//! - The owned form (`encrypt` / `decrypt`) calls the AEAD's own
//!   exact-capacity path (e.g. `Aes256GcmSiv::encrypt`) — fastest for
//!   "give me a Vec".
//! - The `_into` form writes ciphertext directly into the caller's
//!   buffer via `aead::encrypt_in_place` (with a private `TailBuffer`
//!   adapter) — zero intermediate allocation, intended for integrators
//!   that want to pipe into a downstream encoder.

pub(crate) mod buffer;
pub(crate) mod constants;

#[cfg(feature = "aags")]
pub mod aags;
#[cfg(feature = "aasv")]
pub mod aasv;
#[cfg(feature = "apgs")]
pub mod apgs;
#[cfg(feature = "apsv")]
pub mod apsv;
#[cfg(feature = "upbc")]
pub mod upbc;

#[cfg(feature = "mock")]
pub mod mock1;
#[cfg(feature = "mock")]
pub mod mock2;
