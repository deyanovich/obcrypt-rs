//! Roundtrip tests for the wasm bindings.
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
#![cfg(target_arch = "wasm32")]

use obcrypt_wasm::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn free_function_roundtrip() -> Result<(), JsValue> {
    let key = generate_key();
    assert_eq!(key.len(), 128);

    let payload = encrypt(b"secret data", "dsiv", &key)?;
    let plaintext = decrypt(&payload, "dsiv", &key)?;
    assert_eq!(plaintext, b"secret data");
    Ok(())
}

#[wasm_bindgen_test]
fn decrypt_with_wrong_scheme_fails() -> Result<(), JsValue> {
    let key = generate_key();
    // Long enough to clear both schemes' minimum lengths, so the
    // failure is an authentication mismatch, not a length rejection.
    let payload = encrypt(b"a sufficiently long plaintext here", "dsiv", &key)?;

    // Same scheme: ok.
    let plaintext = decrypt(&payload, "dsiv", &key)?;
    assert_eq!(plaintext, b"a sufficiently long plaintext here");

    // Different scheme: rejected (no marker to auto-detect).
    assert!(decrypt(&payload, "dgcmsiv", &key).is_err());
    Ok(())
}

#[wasm_bindgen_test]
fn codec_class_roundtrip() -> Result<(), JsValue> {
    let key = generate_key();
    let codec = Dsiv::new(&key)?;

    assert_eq!(codec.scheme(), "dsiv");
    assert_eq!(codec.key(), key);
    assert_eq!(codec.key_bytes().len(), 64);

    let payload = codec.encrypt(b"hello")?;
    let plaintext = codec.decrypt(&payload)?;
    assert_eq!(plaintext, b"hello");
    Ok(())
}

#[wasm_bindgen_test]
fn bad_key_throws() {
    assert!(Dsiv::new("not-hex").is_err());
    assert!(encrypt(b"x", "dsiv", "short").is_err());
}
