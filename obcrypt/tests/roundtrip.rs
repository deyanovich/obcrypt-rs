//! Roundtrip tests for every scheme: encrypt → decrypt → assert plaintext.

use obcrypt::{decrypt, decrypt_as, encrypt, encrypt_into, Error, Key, Scheme};

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
        let recovered = decrypt(&payload, &key).expect("decrypt");
        assert_eq!(&recovered[..], *pt, "roundtrip failed for {scheme:?}");

        // Also test the explicit-scheme decrypt
        let recovered_as = decrypt_as(&payload, scheme, &key).expect("decrypt_as");
        assert_eq!(&recovered_as[..], *pt, "decrypt_as failed for {scheme:?}");
    }
}

#[cfg(feature = "aags")]
#[test]
fn aags_roundtrip() {
    assert_roundtrip(Scheme::Aags);
}

#[cfg(feature = "apgs")]
#[test]
fn apgs_roundtrip() {
    assert_roundtrip(Scheme::Apgs);
}

#[cfg(feature = "aasv")]
#[test]
fn aasv_roundtrip() {
    assert_roundtrip(Scheme::Aasv);
}

#[cfg(feature = "apsv")]
#[test]
fn apsv_roundtrip() {
    assert_roundtrip(Scheme::Apsv);
}

#[cfg(feature = "upbc")]
#[test]
fn upbc_roundtrip() {
    assert_roundtrip(Scheme::Upbc);
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

#[cfg(feature = "aasv")]
#[test]
fn encrypt_into_appends_to_existing_buffer() {
    let key = fixed_key();
    let mut buf = Vec::from(&b"prefix:"[..]);
    encrypt_into(b"payload", Scheme::Aasv, &key, &mut buf).unwrap();
    assert!(buf.starts_with(b"prefix:"));
    assert!(buf.len() > b"prefix:".len() + 2);
}

#[cfg(feature = "aasv")]
#[test]
fn deterministic_schemes_are_stable() {
    let key = fixed_key();
    let a = encrypt(b"identical input", Scheme::Aasv, &key).unwrap();
    let b = encrypt(b"identical input", Scheme::Aasv, &key).unwrap();
    assert_eq!(a, b, "aasv should be deterministic");
}

#[cfg(feature = "apsv")]
#[test]
fn probabilistic_schemes_vary() {
    let key = fixed_key();
    let a = encrypt(b"identical input", Scheme::Apsv, &key).unwrap();
    let b = encrypt(b"identical input", Scheme::Apsv, &key).unwrap();
    assert_ne!(a, b, "apsv should be probabilistic");
}

#[cfg(feature = "aags")]
#[test]
fn wrong_key_fails_a_tier() {
    let key1 = fixed_key();
    let key2 = {
        let mut bytes = *key1.as_bytes();
        // Flip a byte in aags's actual key slice (master_key[32..64]).
        bytes[40] ^= 0xff;
        Key::from_bytes(bytes)
    };
    let payload = encrypt(b"secret", Scheme::Aags, &key1).unwrap();
    match decrypt(&payload, &key2) {
        Err(Error::DecryptionFailed) => {}
        other => panic!("expected DecryptionFailed, got {other:?}"),
    }
}

#[cfg(feature = "aags")]
#[test]
fn tampered_payload_fails_a_tier() {
    let key = fixed_key();
    let mut payload = encrypt(b"secret", Scheme::Aags, &key).unwrap();
    // Flip a bit in the ciphertext (not the marker bytes).
    payload[4] ^= 0x01;
    assert!(decrypt(&payload, &key).is_err());
}

#[cfg(all(feature = "aasv", feature = "apsv"))]
#[test]
fn decrypt_as_rejects_mismatched_marker() {
    let key = fixed_key();
    let payload = encrypt(b"hello", Scheme::Aasv, &key).unwrap();
    let err = decrypt_as(&payload, Scheme::Apsv, &key).unwrap_err();
    assert!(matches!(err, Error::SchemeMarkerMismatch));
}

#[test]
fn payload_too_short() {
    let key = fixed_key();
    assert!(matches!(
        decrypt(&[0u8; 1], &key),
        Err(Error::PayloadTooShort)
    ));
}

#[test]
fn unknown_marker_fails() {
    let key = fixed_key();
    // 5 bytes: first=0x00, rest=0x00 -> marker XOR first = [0xff, 0xff] (unknown)
    let mut payload = [0u8; 5];
    payload[3] = 0xff;
    payload[4] = 0xff;
    match decrypt(&payload, &key) {
        Err(Error::UnknownScheme) => {}
        other => panic!("expected UnknownScheme, got {other:?}"),
    }
}

#[cfg(feature = "aasv")]
#[test]
fn empty_plaintext_rejected() {
    let key = fixed_key();
    assert!(matches!(
        encrypt(b"", Scheme::Aasv, &key),
        Err(Error::EmptyPlaintext)
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
    let lo = "0".repeat(128);
    let hi = "0".repeat(128); // (no letters above 9 here, just shape check)
    assert_eq!(
        Key::from_hex(&lo).unwrap().as_bytes(),
        Key::from_hex(&hi).unwrap().as_bytes()
    );
    let mixed = "AbCdEf".to_string() + &"0".repeat(122);
    let lower = "abcdef".to_string() + &"0".repeat(122);
    assert_eq!(
        Key::from_hex(&mixed).unwrap().as_bytes(),
        Key::from_hex(&lower).unwrap().as_bytes()
    );
}
