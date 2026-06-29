//! Conformance: drive the canonical oboron core test vectors through
//! the obcrypt C ABI and assert byte-exact results.
//!
//! The vectors live in the sibling `oboron-test-vectors` repo, not in
//! this workspace. The test finds `test-vectors.jsonl` via the
//! `OBORON_TEST_VECTORS` env var, falling back to the sibling's
//! default location next to this crate. If neither is present the test
//! is **skipped** (so a bare `cargo test` without the sibling checkout
//! still passes); CI provides the file and thereby enforces it.
//!
//! Only the `.hex` format variants are used: a vector's `obtext` is
//! the encoding of the bare scheme output with no marker, so for the
//! `.hex` encoding it is exactly the bytes the obcrypt byte core
//! produces. Per the vectors' documented rules:
//!
//! - deterministic schemes (`dsiv`, `dgcmsiv`): `encrypt(plaintext)`
//!   must reproduce `obtext` exactly, and `decrypt(obtext)` must
//!   reproduce `plaintext` exactly.
//! - probabilistic schemes (`psiv`, `pgcmsiv`): `decrypt(obtext)` must
//!   reproduce `plaintext`; the encrypt path is exercised by a fresh
//!   encrypt/decrypt roundtrip (its output varies per call).
//!
//! Keys are passed through the hex-key ABI entry points, so this also
//! exercises `obcrypt_encrypt_hex_key` / `obcrypt_decrypt_hex_key`.

use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::ptr;
use std::slice;

use obcrypt_ffi::*;

/// The hardcoded 512-bit master test key from the oboron-test-vectors
/// README ("Fixed Public Test Key"). Insecure by design — published
/// for cross-implementation conformance only.
const MASTER_KEY_HEX: &str = "381284633d02ea5f35df8596b5cc4218310060468e8b465455a415174ea6e966\
                              a9f48eec4ba446ddfc8b78587895356f45a75a1ab7419454dd9f7aa8a95dbdd5";

/// Locate `test-vectors.jsonl`: explicit env var first, then the
/// sibling repo at its conventional path relative to this crate.
fn vectors_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("OBORON_TEST_VECTORS") {
        let p = PathBuf::from(p);
        assert!(
            p.exists(),
            "OBORON_TEST_VECTORS set but not found: {}",
            p.display()
        );
        return Some(p);
    }
    // CARGO_MANIFEST_DIR = .../oboron/obcrypt-rs/obcrypt-ffi; the
    // vectors sibling is .../oboron/oboron-test-vectors.
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../oboron-test-vectors/test-vectors.jsonl");
    p.exists().then_some(p)
}

fn last_error() -> String {
    let p = obcrypt_last_error();
    if p.is_null() {
        "(no message)".to_string()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

/// Copy an out-buffer the way a C caller would, then free it.
unsafe fn take(ptr: *mut u8, len: usize) -> Vec<u8> {
    let v = slice::from_raw_parts(ptr, len).to_vec();
    obcrypt_buffer_free(ptr, len);
    v
}

fn enc(pt: &[u8], scheme: &CStr, key_hex: &CStr) -> Vec<u8> {
    let mut out: *mut u8 = ptr::null_mut();
    let mut out_len = 0usize;
    let code = obcrypt_encrypt_hex_key(
        pt.as_ptr(),
        pt.len(),
        scheme.as_ptr(),
        key_hex.as_ptr(),
        &mut out,
        &mut out_len,
    );
    assert_eq!(code, OBCRYPT_OK, "encrypt failed: {}", last_error());
    unsafe { take(out, out_len) }
}

fn dec(ct: &[u8], scheme: &CStr, key_hex: &CStr) -> Vec<u8> {
    let mut out: *mut u8 = ptr::null_mut();
    let mut out_len = 0usize;
    let code = obcrypt_decrypt_hex_key(
        ct.as_ptr(),
        ct.len(),
        scheme.as_ptr(),
        key_hex.as_ptr(),
        &mut out,
        &mut out_len,
    );
    assert_eq!(code, OBCRYPT_OK, "decrypt failed: {}", last_error());
    unsafe { take(out, out_len) }
}

#[test]
fn canonical_vectors_through_the_abi() {
    let Some(path) = vectors_path() else {
        eprintln!(
            "SKIP: oboron-test-vectors not found. Set OBORON_TEST_VECTORS \
             to the path of test-vectors.jsonl to run conformance."
        );
        return;
    };

    let key_hex = CString::new(MASTER_KEY_HEX).unwrap();
    let data = std::fs::read_to_string(&path).expect("read test-vectors.jsonl");

    let (mut checked, mut det, mut prob) = (0usize, 0usize, 0usize);
    for (i, line) in data.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line {}: bad JSON: {e}", i + 1));
        if v.get("type").and_then(|t| t.as_str()) == Some("meta") {
            continue;
        }

        let format = v["format"].as_str().expect("format");
        let Some(scheme) = format.strip_suffix(".hex") else {
            continue; // only the .hex encoding is the bare byte output
        };
        let plaintext = v["plaintext"].as_str().expect("plaintext").as_bytes();
        let expected = hex::decode(v["obtext"].as_str().expect("obtext")).expect("obtext hex");
        let scheme_c = CString::new(scheme).unwrap();
        let deterministic = matches!(scheme, "dsiv" | "dgcmsiv");

        // decrypt(obtext) == plaintext, for every scheme.
        let recovered = dec(&expected, &scheme_c, &key_hex);
        assert_eq!(
            recovered,
            plaintext,
            "decrypt mismatch ({format}, line {})",
            i + 1
        );

        if deterministic {
            // encrypt(plaintext) == obtext, exactly.
            let produced = enc(plaintext, &scheme_c, &key_hex);
            assert_eq!(
                produced,
                expected,
                "encrypt mismatch ({format}, line {})",
                i + 1
            );
            det += 1;
        } else {
            // Fresh encrypt then decrypt back to the plaintext.
            let fresh = enc(plaintext, &scheme_c, &key_hex);
            let round = dec(&fresh, &scheme_c, &key_hex);
            assert_eq!(
                round,
                plaintext,
                "roundtrip mismatch ({format}, line {})",
                i + 1
            );
            prob += 1;
        }
        checked += 1;
    }

    assert!(checked > 0, "no .hex vectors found in {}", path.display());
    eprintln!(
        "conformance: {checked} .hex vectors through the C ABI \
         ({det} deterministic exact-match, {prob} probabilistic roundtrip)"
    );
}
