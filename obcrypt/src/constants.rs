//! Scheme marker constants.
//!
//! Scheme marker structure (2 bytes = 16 bits):
//!
//! Byte 1: `[ext:1][version:4][tier:3]`
//! Byte 2: `[properties:4][algorithm:4]`
//!
//! Note: in the framed payload, both marker bytes are XORed with the
//! first ciphertext byte for entropy mixing.
//!
//! - ext (1 bit): extension flag (0 = no extension)
//! - version (4 bits): format version (0 = v0)
//! - tier (3 bits):
//!   - 000 (0): `mock` - testing
//!   - 001 (1): `a` - authenticated (secure)
//!   - 010 (2): `u` - unauthenticated (secure)
//! - properties (4 bits):
//!   - 0000 (0): probabilistic
//!   - 0001 (1): deterministic / avalanche
//! - algorithm (4 bits):
//!   - 0001 (1): CBC
//!   - 0010 (2): GCM-SIV
//!   - 0011 (3): SIV

/// Number of bytes the scheme marker occupies at the tail of a framed payload.
pub const SCHEME_MARKER_SIZE: usize = 2;

const fn make_marker(tier: u8, properties: u8, algorithm: u8) -> [u8; 2] {
    let byte1 = tier; // ext=0, version=0000, tier
    let byte2 = (properties << 4) | algorithm;
    [byte1, byte2]
}

// `a`-tier - secure, authenticated
#[cfg(feature = "aags")]
pub const AAGS_MARKER: [u8; 2] = make_marker(1, 1, 2);
#[cfg(feature = "apgs")]
pub const APGS_MARKER: [u8; 2] = make_marker(1, 0, 2);
#[cfg(feature = "aasv")]
pub const AASV_MARKER: [u8; 2] = make_marker(1, 1, 3);
#[cfg(feature = "apsv")]
pub const APSV_MARKER: [u8; 2] = make_marker(1, 0, 3);

// `u`-tier - secure, unauthenticated
#[cfg(feature = "upbc")]
pub const UPBC_MARKER: [u8; 2] = make_marker(2, 0, 1);

// Testing only (no encryption)
#[cfg(feature = "mock")]
pub const MOCK1_MARKER: [u8; 2] = make_marker(0, 4, 15);
#[cfg(feature = "mock")]
pub const MOCK2_MARKER: [u8; 2] = make_marker(0, 4, 14);
