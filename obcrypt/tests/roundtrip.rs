//! Roundtrip tests for every scheme: encrypt → decrypt → assert plaintext.

use obcrypt::{decrypt, decrypt_into, encrypt, encrypt_into, Error, Key, Scheme};

const SAMPLES: &[&[u8]] = &[
    b"x",
    b"hello world",
    b"\x00\x01\x02\x03\xff\xfe\xfd",
    b"The quick brown fox jumps over the lazy dog.",
    b"\xf0\x9f\x91\x8b non-utf8-safe \xc3\x28",
];

fn fixed_key() -> Key {
    let mut bytes = [0u8; 64];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(13);
    }
    Key::from_bytes(bytes)
}

fn assert_roundtrip(scheme: Scheme) {
    let key = fixed_key();
    for pt in SAMPLES {
        let payload = encrypt(pt, scheme, &key).expect("encrypt");
        let recovered = decrypt(&payload, scheme, &key).expect("decrypt");
        assert_eq!(&recovered[..], *pt, "roundtrip failed for {scheme:?}");
    }
}

#[cfg(feature = "dgcmsiv")]
#[test]
fn dgcmsiv_roundtrip() {
    assert_roundtrip(Scheme::Dgcmsiv);
}

#[cfg(feature = "pgcmsiv")]
#[test]
fn pgcmsiv_roundtrip() {
    assert_roundtrip(Scheme::Pgcmsiv);
}

#[cfg(feature = "dsiv")]
#[test]
fn dsiv_roundtrip() {
    assert_roundtrip(Scheme::Dsiv);
}

#[cfg(feature = "psiv")]
#[test]
fn psiv_roundtrip() {
    assert_roundtrip(Scheme::Psiv);
}

#[cfg(feature = "mock")]
#[test]
fn mock1_roundtrip() {
    assert_roundtrip(Scheme::Mock1);
}

#[cfg(feature = "mock")]
#[test]
fn mock2_roundtrip() {
    assert_roundtrip(Scheme::Mock2);
}

#[cfg(feature = "dsiv")]
#[test]
fn encrypt_into_appends_to_existing_buffer() {
    let key = fixed_key();
    let prefix = b"prefix:";
    let mut buf = Vec::from(&prefix[..]);
    encrypt_into(b"payload", Scheme::Dsiv, &key, &mut buf).unwrap();
    assert!(buf.starts_with(prefix));
    // The appended bytes are a standalone dsiv output that decrypts back.
    let recovered = decrypt(&buf[prefix.len()..], Scheme::Dsiv, &key).unwrap();
    assert_eq!(recovered, b"payload");
}

#[cfg(feature = "psiv")]
#[test]
fn decrypt_into_appends_plaintext() {
    let key = fixed_key();
    let payload = encrypt(b"payload", Scheme::Psiv, &key).unwrap();
    let mut buf = Vec::from(&b"out:"[..]);
    decrypt_into(&payload, Scheme::Psiv, &key, &mut buf).unwrap();
    assert_eq!(buf, b"out:payload");
}

#[cfg(feature = "dsiv")]
#[test]
fn deterministic_schemes_are_stable() {
    let key = fixed_key();
    let a = encrypt(b"identical input", Scheme::Dsiv, &key).unwrap();
    let b = encrypt(b"identical input", Scheme::Dsiv, &key).unwrap();
    assert_eq!(a, b, "dsiv should be deterministic");
}

#[cfg(feature = "psiv")]
#[test]
fn probabilistic_schemes_vary() {
    let key = fixed_key();
    let a = encrypt(b"identical input", Scheme::Psiv, &key).unwrap();
    let b = encrypt(b"identical input", Scheme::Psiv, &key).unwrap();
    assert_ne!(a, b, "psiv should be probabilistic");
}

#[cfg(feature = "dgcmsiv")]
#[test]
fn wrong_key_fails() {
    let key1 = fixed_key();
    let key2 = {
        let mut bytes = *key1.as_bytes();
        // Any change to the master alters the HKDF-derived dgcmsiv key.
        bytes[40] ^= 0xff;
        Key::from_bytes(bytes)
    };
    let payload = encrypt(b"secret", Scheme::Dgcmsiv, &key1).unwrap();
    match decrypt(&payload, Scheme::Dgcmsiv, &key2) {
        Err(Error::DecryptionFailed) => {}
        other => panic!("expected DecryptionFailed, got {other:?}"),
    }
}

#[cfg(feature = "dgcmsiv")]
#[test]
fn tampered_payload_fails() {
    let key = fixed_key();
    let mut payload = encrypt(b"secret", Scheme::Dgcmsiv, &key).unwrap();
    // Flip a bit in the ciphertext.
    payload[4] ^= 0x01;
    assert!(decrypt(&payload, Scheme::Dgcmsiv, &key).is_err());
}

#[cfg(all(feature = "dsiv", feature = "dgcmsiv"))]
#[test]
fn wrong_scheme_fails_authentication() {
    // No marker selects the scheme: decrypting under the wrong scheme
    // must fail the authentication check, never return wrong plaintext.
    // A long plaintext keeps both outputs above either scheme's minimum
    // length, so the failure is a tag mismatch, not a length rejection.
    let key = fixed_key();
    let pt = b"a sufficiently long plaintext to clear both minimum lengths";
    let payload = encrypt(pt, Scheme::Dsiv, &key).unwrap();
    match decrypt(&payload, Scheme::Dgcmsiv, &key) {
        Err(Error::DecryptionFailed) => {}
        other => panic!("expected DecryptionFailed, got {other:?}"),
    }
}

#[cfg(feature = "dsiv")]
#[test]
fn payload_too_short() {
    let key = fixed_key();
    assert!(matches!(
        decrypt(&[0u8; 1], Scheme::Dsiv, &key),
        Err(Error::PayloadTooShort)
    ));
}

#[cfg(feature = "dsiv")]
#[test]
fn empty_plaintext_rejected() {
    let key = fixed_key();
    assert!(matches!(
        encrypt(b"", Scheme::Dsiv, &key),
        Err(Error::EmptyPlaintext)
    ));
}

#[test]
fn scheme_parse_roundtrip() {
    for name in ["dgcmsiv", "pgcmsiv", "dsiv", "psiv"] {
        // Only feature-enabled schemes parse; under --all-features all do.
        if let Ok(s) = name.parse::<Scheme>() {
            assert_eq!(s.as_str(), name);
        }
    }
    assert!(matches!(
        "nope".parse::<Scheme>(),
        Err(Error::UnknownScheme)
    ));
}

#[test]
fn key_hex_roundtrip() {
    let original = fixed_key();
    let hex = original.to_hex();
    assert_eq!(hex.len(), 128);
    let recovered = Key::from_hex(&hex).expect("from_hex");
    assert_eq!(recovered.as_bytes(), original.as_bytes());
}

#[test]
fn key_from_hex_rejects_invalid() {
    assert!(matches!(Key::from_hex("not hex"), Err(Error::InvalidHex)));
    assert!(matches!(
        Key::from_hex(&"a".repeat(127)),
        Err(Error::InvalidHex)
    ));
    assert!(matches!(
        Key::from_hex(&"a".repeat(129)),
        Err(Error::InvalidHex)
    ));
    assert!(matches!(Key::from_hex(""), Err(Error::InvalidHex)));
}

// ── Known-answer tests: regression lock on the wire format ──────────
//
// Constants pinned from the vector-verified 1.0 implementation (the same
// outputs that reproduce the canonical oboron cross-language vectors). A
// change to any scheme's byte layout — tag position, key derivation, AD
// structure, nonce handling — breaks these, catching interop-breaking
// drift that a round-trip-only test cannot.

#[cfg(any(feature = "dsiv", feature = "dgcmsiv"))]
fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(feature = "dsiv")]
#[test]
fn dsiv_known_answer() {
    let out = encrypt(b"obcrypt KAT vector", Scheme::Dsiv, &fixed_key()).unwrap();
    assert_eq!(
        to_hex(&out),
        "8028351d2bbda401961f6531ad15633a1772e5ba9903d4a332a92c0f581d2c969b1d"
    );
}

#[cfg(feature = "dgcmsiv")]
#[test]
fn dgcmsiv_known_answer() {
    let out = encrypt(b"obcrypt KAT vector", Scheme::Dgcmsiv, &fixed_key()).unwrap();
    assert_eq!(
        to_hex(&out),
        "847300ea81b3c96241382c2b5573f9eef393c5aaaab32a81e6f1ecd54efe200e7c70"
    );
}

// ── owned vs `_into` must produce identical bytes (deterministic) ────

#[cfg(feature = "dsiv")]
#[test]
fn owned_matches_into_dsiv() {
    let key = fixed_key();
    let owned = encrypt(b"payload", Scheme::Dsiv, &key).unwrap();
    let mut into = Vec::new();
    encrypt_into(b"payload", Scheme::Dsiv, &key, &mut into).unwrap();
    assert_eq!(owned, into);
}

#[cfg(feature = "dgcmsiv")]
#[test]
fn owned_matches_into_dgcmsiv() {
    let key = fixed_key();
    let owned = encrypt(b"payload", Scheme::Dgcmsiv, &key).unwrap();
    let mut into = Vec::new();
    encrypt_into(b"payload", Scheme::Dgcmsiv, &key, &mut into).unwrap();
    assert_eq!(owned, into);
}

// ── Adversarial coverage for every scheme (not just one each) ────────

#[cfg(any(
    feature = "dsiv",
    feature = "psiv",
    feature = "dgcmsiv",
    feature = "pgcmsiv"
))]
fn assert_rejects_tamper_and_wrong_key(scheme: Scheme) {
    let key = fixed_key();
    let other = {
        let mut b = *key.as_bytes();
        b[40] ^= 0xff;
        Key::from_bytes(b)
    };
    let pt = b"a sufficiently long plaintext to clear every minimum length";
    let payload = encrypt(pt, scheme, &key).unwrap();

    // Wrong key.
    assert!(
        matches!(
            decrypt(&payload, scheme, &other),
            Err(Error::DecryptionFailed)
        ),
        "{scheme:?}: wrong key must fail authentication"
    );
    // Tamper the last byte (tag / ciphertext).
    let mut t = payload.clone();
    *t.last_mut().unwrap() ^= 0x01;
    assert!(
        decrypt(&t, scheme, &key).is_err(),
        "{scheme:?}: tail tamper"
    );
    // Tamper the first byte (nonce for probabilistic, tag for SIV).
    let mut h = payload.clone();
    h[0] ^= 0x01;
    assert!(
        decrypt(&h, scheme, &key).is_err(),
        "{scheme:?}: head tamper"
    );
}

#[cfg(any(
    feature = "dsiv",
    feature = "psiv",
    feature = "dgcmsiv",
    feature = "pgcmsiv"
))]
fn assert_rejects_too_short(scheme: Scheme) {
    // 1 byte is below every core scheme's minimum layout length.
    assert!(matches!(
        decrypt(&[0u8; 1], scheme, &fixed_key()),
        Err(Error::PayloadTooShort)
    ));
}

#[cfg(feature = "dsiv")]
#[test]
fn dsiv_negative() {
    assert_rejects_tamper_and_wrong_key(Scheme::Dsiv);
    assert_rejects_too_short(Scheme::Dsiv);
}

#[cfg(feature = "psiv")]
#[test]
fn psiv_negative() {
    assert_rejects_tamper_and_wrong_key(Scheme::Psiv);
    assert_rejects_too_short(Scheme::Psiv);
}

#[cfg(feature = "dgcmsiv")]
#[test]
fn dgcmsiv_negative() {
    assert_rejects_tamper_and_wrong_key(Scheme::Dgcmsiv);
    assert_rejects_too_short(Scheme::Dgcmsiv);
}

#[cfg(feature = "pgcmsiv")]
#[test]
fn pgcmsiv_negative() {
    assert_rejects_tamper_and_wrong_key(Scheme::Pgcmsiv);
    assert_rejects_too_short(Scheme::Pgcmsiv);
}

// ── Determinism / nonce-variation for the GCM-SIV pair too ───────────

#[cfg(feature = "dgcmsiv")]
#[test]
fn dgcmsiv_is_deterministic() {
    let key = fixed_key();
    assert_eq!(
        encrypt(b"same", Scheme::Dgcmsiv, &key).unwrap(),
        encrypt(b"same", Scheme::Dgcmsiv, &key).unwrap()
    );
}

#[cfg(feature = "pgcmsiv")]
#[test]
fn pgcmsiv_varies() {
    let key = fixed_key();
    assert_ne!(
        encrypt(b"same", Scheme::Pgcmsiv, &key).unwrap(),
        encrypt(b"same", Scheme::Pgcmsiv, &key).unwrap()
    );
}

// ── `decrypt_into` is all-or-nothing on authentication failure ───────

#[cfg(feature = "dgcmsiv")]
#[test]
fn decrypt_into_failure_leaves_buffer_unchanged_gcm() {
    let key = fixed_key();
    let mut payload = encrypt(b"a secret payload to authenticate", Scheme::Dgcmsiv, &key).unwrap();
    *payload.last_mut().unwrap() ^= 0xff; // force a tag mismatch
    let mut buf = Vec::from(&b"prior good data"[..]);
    let before = buf.clone();
    assert!(decrypt_into(&payload, Scheme::Dgcmsiv, &key, &mut buf).is_err());
    assert_eq!(
        buf, before,
        "failed decrypt_into must not alter the caller's buffer"
    );
}

#[cfg(feature = "psiv")]
#[test]
fn decrypt_into_failure_leaves_buffer_unchanged_siv() {
    // Exercises the nonce-stripping probabilistic path.
    let key = fixed_key();
    let mut payload = encrypt(b"a secret payload to authenticate", Scheme::Psiv, &key).unwrap();
    *payload.last_mut().unwrap() ^= 0xff;
    let mut buf = Vec::from(&b"prior good data"[..]);
    let before = buf.clone();
    assert!(decrypt_into(&payload, Scheme::Psiv, &key, &mut buf).is_err());
    assert_eq!(buf, before);
}

// ── A no-encryption mock scheme must not be string-selectable ────────

#[cfg(feature = "mock")]
#[test]
fn mock_not_parseable_from_string() {
    assert!(matches!(
        "mock1".parse::<Scheme>(),
        Err(Error::UnknownScheme)
    ));
    assert!(matches!(
        "mock2".parse::<Scheme>(),
        Err(Error::UnknownScheme)
    ));
    // Explicit construction still works for tests that want it.
    assert!(encrypt(b"x", Scheme::Mock1, &fixed_key()).is_ok());
}

#[test]
fn key_from_hex_rejects_uppercase() {
    // Canonical obcrypt keys are lowercase hex (oboron spec §3.3):
    // uppercase and mixed-case are rejected with no case-folding.
    let upper = "A".repeat(128);
    assert!(matches!(Key::from_hex(&upper), Err(Error::InvalidHex)));
    let mixed = "AbCdEf".to_string() + &"0".repeat(122);
    assert!(matches!(Key::from_hex(&mixed), Err(Error::InvalidHex)));
    // The lowercase form of the same value is accepted.
    let lower = "abcdef".to_string() + &"0".repeat(122);
    assert!(Key::from_hex(&lower).is_ok());
}
