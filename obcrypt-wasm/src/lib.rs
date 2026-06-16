//! WebAssembly / JavaScript bindings for `obcrypt` via wasm-bindgen.
//!
//! Compiled to wasm and packaged for npm with `wasm-pack`, this crate
//! exposes obcrypt's bytes-in / bytes-out symmetric encryption to JS.
//! It mirrors the `obcrypt-py` surface: free functions plus one codec
//! class per scheme.
//!
//! JS-facing names are camelCase (`generateKey`, `keyBytes`); the Rust
//! identifiers stay snake_case. Byte arguments and results map to JS
//! `Uint8Array`; keys are 128-character hex strings — the canonical
//! oboron key form. See the project README for usage.
//!
//! Errors are thrown as JS `Error`s whose message is the underlying
//! `obcrypt::Error` description (e.g. `"invalid hex key (expected 128
//! hex characters)"`, `"unknown scheme"`, `"decryption failed"`).

use obcrypt::{Key, Scheme};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a scheme string (case-insensitive identifier) into the Rust
/// enum, surfacing parse failure as a JS error.
fn parse_scheme(s: &str) -> Result<Scheme, JsError> {
    s.parse::<Scheme>().map_err(JsError::from)
}

/// Parse a 128-character hex key string, surfacing failures as JS errors.
fn parse_key(hex: &str) -> Result<Key, JsError> {
    Key::from_hex(hex).map_err(JsError::from)
}

// ---------------------------------------------------------------------------
// Module-level functions
// ---------------------------------------------------------------------------

/// The obcrypt-wasm package version (matches `package.json`).
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Encrypt `plaintext` under `scheme` and return the scheme output bytes.
///
/// `scheme` is a lowercase identifier like `"dsiv"` or `"pgcmsiv"`.
/// `key` is a 128-character hex string — the canonical oboron key form,
/// what env vars and config files carry. Bad hex or wrong length throws.
///
/// The output is exactly the scheme's AEAD output — there is no marker,
/// so the same `scheme` must be supplied to `decrypt`.
#[wasm_bindgen]
pub fn encrypt(plaintext: &[u8], scheme: &str, key: &str) -> Result<Vec<u8>, JsError> {
    let s = parse_scheme(scheme)?;
    let k = parse_key(key)?;
    obcrypt::encrypt(plaintext, s, &k).map_err(JsError::from)
}

/// Decrypt `output` under `scheme` and return the plaintext.
///
/// The output carries no marker, so the same `scheme` used to encrypt
/// must be supplied. A wrong scheme throws (the authentication check
/// fails). `key` is a 128-character hex string.
#[wasm_bindgen]
pub fn decrypt(payload: &[u8], scheme: &str, key: &str) -> Result<Vec<u8>, JsError> {
    let s = parse_scheme(scheme)?;
    let k = parse_key(key)?;
    obcrypt::decrypt(payload, s, &k).map_err(JsError::from)
}

/// Generate a fresh random 64-byte key, returned as a 128-character
/// lowercase hex string — the canonical oboron key form, suitable for
/// dropping into env vars, config files, and codec / function `key`
/// arguments.
///
/// For the raw 64-byte form (byte-native crypto interop, custom
/// storage), use `generateKeyBytes()`.
#[wasm_bindgen(js_name = generateKey)]
pub fn generate_key() -> String {
    obcrypt::generate_key().to_hex()
}

/// Generate a fresh random 64-byte key, returned as a `Uint8Array`.
///
/// Provided for interop with byte-native APIs and custom storage
/// formats. For the canonical hex form used everywhere else in
/// obcrypt, use `generateKey()`.
#[wasm_bindgen(js_name = generateKeyBytes)]
pub fn generate_key_bytes() -> Vec<u8> {
    obcrypt::generate_key().as_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Codec classes — one per scheme
// ---------------------------------------------------------------------------

macro_rules! impl_codec_class {
    ($name:ident, $scheme_variant:ident, $scheme_lit:literal, $feature:literal) => {
        #[cfg(feature = $feature)]
        #[doc = concat!(
            "Codec binding scheme `", $scheme_lit, "` to a key.\n\n",
            "Construct with a 128-character hex key string — the canonical ",
            "oboron key form, what env vars carry. `decrypt` expects output ",
            "produced under `", $scheme_lit, "`; a wrong scheme fails the ",
            "authentication check."
        )]
        #[wasm_bindgen]
        pub struct $name {
            inner: Key,
        }

        #[cfg(feature = $feature)]
        #[wasm_bindgen]
        impl $name {
            #[wasm_bindgen(constructor)]
            pub fn new(key: &str) -> Result<$name, JsError> {
                Ok(Self {
                    inner: parse_key(key)?,
                })
            }

            /// Encrypt `plaintext` under this codec's scheme.
            pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
                obcrypt::encrypt(plaintext, Scheme::$scheme_variant, &self.inner)
                    .map_err(JsError::from)
            }

            /// Decrypt output produced under this codec's scheme. A
            /// wrong scheme throws (the authentication check fails).
            pub fn decrypt(&self, payload: &[u8]) -> Result<Vec<u8>, JsError> {
                obcrypt::decrypt(payload, Scheme::$scheme_variant, &self.inner)
                    .map_err(JsError::from)
            }

            /// The key bound to this codec, as a 128-character lowercase
            /// hex string (the canonical oboron form).
            #[wasm_bindgen(getter)]
            pub fn key(&self) -> String {
                self.inner.to_hex()
            }

            /// The raw 64-byte key material bound to this codec, as a
            /// `Uint8Array`. Provided for byte-native interop; the
            /// canonical form everywhere else is `.key` (hex).
            #[wasm_bindgen(getter, js_name = keyBytes)]
            pub fn key_bytes(&self) -> Vec<u8> {
                self.inner.as_bytes().to_vec()
            }

            /// The scheme identifier (constant for this class).
            #[wasm_bindgen(getter)]
            pub fn scheme(&self) -> String {
                $scheme_lit.to_string()
            }
        }
    };
}

impl_codec_class!(Dgcmsiv, Dgcmsiv, "dgcmsiv", "dgcmsiv");
impl_codec_class!(Pgcmsiv, Pgcmsiv, "pgcmsiv", "pgcmsiv");
impl_codec_class!(Dsiv, Dsiv, "dsiv", "dsiv");
impl_codec_class!(Psiv, Psiv, "psiv", "psiv");
