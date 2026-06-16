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
    assert!(matches!(Key::from_hex(&"a".repeat(127)), Err(Error::InvalidHex)));
    assert!(matches!(Key::from_hex(&"a".repeat(129)), Err(Error::InvalidHex)));
    assert!(matches!(Key::from_hex(""), Err(Error::InvalidHex)));
}

#[test]
fn key_from_hex_accepts_uppercase() {
    let mixed = "AbCdEf".to_string() + &"0".repeat(122);
    let lower = "abcdef".to_string() + &"0".repeat(122);
    assert_eq!(
        Key::from_hex(&mixed).unwrap().as_bytes(),
        Key::from_hex(&lower).unwrap().as_bytes()
    );
}
