//! Roundtrip + behavioral tests for the wasm bindings.
//!
//! These exercise the actual wasm build and so run under a JS host:
//!
//! ```text
//! wasm-pack test --node
//! # or, in a headless browser:
//! wasm-pack test --headless --firefox
//! ```
//!
//! Gated to `wasm32` so a host-target `cargo test` compiles them away
//! to nothing rather than failing to link.
//!
//! Mirrors `obcrypt-py`'s `test_roundtrip.py` for parity. Two py tests
//! have no wasm analog and are intentionally omitted: the exception
//! *hierarchy* tests (wasm surfaces every failure as a single
//! `JsError`, with no subclass tree — the most we assert is
//! `.is_err()`), and the `__repr__`-redaction test (wasm codecs have
//! no repr; the `key` getter deliberately exposes the hex key as the
//! canonical accessor, so there is nothing to redact).
#![cfg(target_arch = "wasm32")]

use obcrypt_wasm::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

/// A fixed, valid 128-character lowercase-hex key (64 bytes). Lets the
/// deterministic schemes be reproducible across calls.
fn fixed_key() -> String {
    "0123456789abcdef".repeat(8)
}

const ALL: [&str; 4] = ["dsiv", "psiv", "dgcmsiv", "pgcmsiv"];
const DETERMINISTIC: [&str; 2] = ["dsiv", "dgcmsiv"];
const PROBABILISTIC: [&str; 2] = ["psiv", "pgcmsiv"];

// ---------------------------------------------------------------------------
// Round-trip correctness — free functions
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
fn free_function_roundtrip_all_schemes() -> Result<(), JsValue> {
    let key = generate_key();
    assert_eq!(key.len(), 128);
    let pt = b"the quick brown fox";
    for s in ALL {
        let payload = encrypt(pt, s, &key)?;
        assert_ne!(payload, pt, "{s}: payload equals plaintext");
        assert_eq!(decrypt(&payload, s, &key)?, pt, "{s}");
    }
    Ok(())
}

#[wasm_bindgen_test]
fn one_byte_roundtrips() -> Result<(), JsValue> {
    let key = fixed_key();
    for s in ALL {
        let payload = encrypt(b"\x00", s, &key)?;
        assert_eq!(decrypt(&payload, s, &key)?, b"\x00", "{s}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Round-trip correctness — codec classes (one test set per scheme type)
// ---------------------------------------------------------------------------

macro_rules! codec_tests {
    ($($name:ident: $codec:ident => $scheme:literal),* $(,)?) => {
        $(
            mod $name {
                use super::*;

                #[wasm_bindgen_test]
                fn roundtrip() -> Result<(), JsValue> {
                    let codec = $codec::new(&fixed_key())?;
                    assert_eq!(codec.scheme(), $scheme);
                    let pt = b"\x00\x01\x02 binary \xff\xfe payload \x00";
                    let payload = codec.encrypt(pt)?;
                    assert_eq!(codec.decrypt(&payload)?, pt);
                    Ok(())
                }

                #[wasm_bindgen_test]
                fn interop_with_free_functions() -> Result<(), JsValue> {
                    let key = fixed_key();
                    let codec = $codec::new(&key)?;
                    let pt = b"interop";
                    // Codec output decrypts via the free function...
                    assert_eq!(decrypt(&codec.encrypt(pt)?, $scheme, &key)?, pt);
                    // ...and free-function output decrypts via the codec.
                    assert_eq!(codec.decrypt(&encrypt(pt, $scheme, &key)?)?, pt);
                    Ok(())
                }

                #[wasm_bindgen_test]
                fn key_getters_match_input() -> Result<(), JsValue> {
                    let key = fixed_key();
                    let codec = $codec::new(&key)?;
                    assert_eq!(codec.key(), key);
                    assert_eq!(codec.key_bytes(), hex::decode(&key).unwrap());
                    assert_eq!(codec.key_bytes().len(), 64);
                    Ok(())
                }
            }
        )*
    };
}

codec_tests!(
    dsiv_codec: Dsiv => "dsiv",
    psiv_codec: Psiv => "psiv",
    dgcmsiv_codec: Dgcmsiv => "dgcmsiv",
    pgcmsiv_codec: Pgcmsiv => "pgcmsiv",
);

// ---------------------------------------------------------------------------
// Deterministic vs probabilistic
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
fn deterministic_schemes_are_deterministic() -> Result<(), JsValue> {
    let key = fixed_key();
    let pt = b"same input, same output";
    for s in DETERMINISTIC {
        assert_eq!(encrypt(pt, s, &key)?, encrypt(pt, s, &key)?, "{s}");
    }
    Ok(())
}

#[wasm_bindgen_test]
fn probabilistic_schemes_differ_but_roundtrip() -> Result<(), JsValue> {
    let key = fixed_key();
    let pt = b"same input, fresh randomness";
    for s in PROBABILISTIC {
        let a = encrypt(pt, s, &key)?;
        let b = encrypt(pt, s, &key)?;
        assert_ne!(a, b, "{s}");
        assert_eq!(decrypt(&a, s, &key)?, pt, "{s}");
        assert_eq!(decrypt(&b, s, &key)?, pt, "{s}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
fn generate_key_is_128_char_lowercase_hex() {
    let k = generate_key();
    assert_eq!(k.len(), 128);
    assert!(k
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
}

#[wasm_bindgen_test]
fn generate_key_bytes_is_64_bytes() {
    assert_eq!(generate_key_bytes().len(), 64);
}

#[wasm_bindgen_test]
fn generate_key_is_random() {
    assert_ne!(generate_key(), generate_key());
}

// ---------------------------------------------------------------------------
// Errors (every failure surfaces as a thrown JsError → `.is_err()`)
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
fn invalid_key_throws() {
    let zeros = "00".repeat(32); // 64 hex chars = 32 bytes, wrong length
    let upper = "ab".repeat(64).to_uppercase(); // right length, non-canonical
    let bad_keys: [&str; 4] = ["xyz", "abc", zeros.as_str(), upper.as_str()];
    for bad in bad_keys {
        assert!(Dsiv::new(bad).is_err(), "ctor accepted {bad}");
        assert!(
            encrypt(b"x", "dsiv", bad).is_err(),
            "encrypt accepted {bad}"
        );
    }
}

#[wasm_bindgen_test]
fn unknown_scheme_throws() {
    let key = fixed_key();
    assert!(encrypt(b"x", "nope", &key).is_err());
    assert!(decrypt(&[0u8; 64], "nope", &key).is_err());
}

#[wasm_bindgen_test]
fn empty_plaintext_throws() -> Result<(), JsValue> {
    let key = fixed_key();
    for s in ALL {
        assert!(encrypt(b"", s, &key).is_err(), "{s}");
    }
    assert!(Dgcmsiv::new(&key)?.encrypt(b"").is_err());
    Ok(())
}

#[wasm_bindgen_test]
fn wrong_scheme_decrypt_throws() -> Result<(), JsValue> {
    let key = fixed_key();
    // Long enough to clear both schemes' minimum lengths, so the
    // failure is an authentication mismatch, not a length rejection.
    let payload = encrypt(b"a sufficiently long plaintext here", "dsiv", &key)?;
    assert_eq!(
        decrypt(&payload, "dsiv", &key)?,
        b"a sufficiently long plaintext here"
    );
    assert!(decrypt(&payload, "psiv", &key).is_err());
    Ok(())
}

#[wasm_bindgen_test]
fn wrong_key_decrypt_throws() -> Result<(), JsValue> {
    let payload = encrypt(b"secret", "dsiv", &fixed_key())?;
    let other = generate_key();
    assert!(decrypt(&payload, "dsiv", &other).is_err());
    Ok(())
}

#[wasm_bindgen_test]
fn tampered_payload_throws() -> Result<(), JsValue> {
    let key = fixed_key();
    for s in ALL {
        let mut payload = encrypt(b"secret message", s, &key)?;
        let last = payload.len() - 1;
        payload[last] ^= 0xff; // flip a bit in the authentication tag
        assert!(decrypt(&payload, s, &key).is_err(), "{s}");
    }
    Ok(())
}

#[wasm_bindgen_test]
fn short_and_empty_payload_throws() {
    let key = fixed_key();
    for s in ALL {
        assert!(decrypt(b"", s, &key).is_err(), "{s}: empty");
        assert!(decrypt(b"\x00", s, &key).is_err(), "{s}: 1 byte");
    }
}

// ---------------------------------------------------------------------------
// Misc surface
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
fn version_is_nonempty() {
    assert!(!version().is_empty());
}
