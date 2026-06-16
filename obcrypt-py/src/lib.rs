//! Python bindings for `obcrypt` via PyO3 / maturin.
//!
//! The Rust extension module `obcrypt._obcrypt`. The user-facing API
//! is the `obcrypt` Python package; `python/obcrypt/__init__.py`
//! re-exports from this module. See the project README for usage.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

create_exception!(_obcrypt, ObcryptError, PyException);
create_exception!(_obcrypt, InvalidKey, ObcryptError);
create_exception!(_obcrypt, InvalidScheme, ObcryptError);
create_exception!(_obcrypt, EncryptionFailed, ObcryptError);
create_exception!(_obcrypt, DecryptionFailed, ObcryptError);

/// Map an `obcrypt::Error` to the closest custom Python exception.
fn map_error(e: obcrypt::Error) -> PyErr {
    let msg = e.to_string();
    match e {
        obcrypt::Error::InvalidKeyLength | obcrypt::Error::InvalidHex => {
            InvalidKey::new_err(msg)
        }
        obcrypt::Error::UnknownScheme => InvalidScheme::new_err(msg),
        obcrypt::Error::EncryptionFailed | obcrypt::Error::EmptyPlaintext => {
            EncryptionFailed::new_err(msg)
        }
        obcrypt::Error::DecryptionFailed
        | obcrypt::Error::EmptyPayload
        | obcrypt::Error::PayloadTooShort => DecryptionFailed::new_err(msg),
        // obcrypt::Error is #[non_exhaustive]; future variants fall here.
        _ => ObcryptError::new_err(msg),
    }
}

/// Parse a scheme string (case-insensitive identifier) into the Rust
/// enum, mapping parse failure to `InvalidScheme`.
fn parse_scheme(s: &str) -> PyResult<obcrypt::Scheme> {
    s.parse::<obcrypt::Scheme>().map_err(map_error)
}

/// Parse a 128-character hex key string, mapping failures to `InvalidKey`.
fn parse_key(hex: &str) -> PyResult<obcrypt::Key> {
    obcrypt::Key::from_hex(hex).map_err(map_error)
}

// ---------------------------------------------------------------------------
// Module-level functions
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` under `scheme` and return the scheme output bytes.
///
/// `scheme` is a lowercase identifier like `"dsiv"` or `"pgcmsiv"`.
/// `key` is a 128-character hex string — the canonical oboron key form,
/// what env vars and config files carry. Bad hex or wrong length raises
/// `InvalidKey`.
///
/// The output is exactly the scheme's AEAD output — there is no marker,
/// so the same `scheme` must be supplied to `decrypt`.
#[pyfunction]
fn encrypt<'py>(
    py: Python<'py>,
    plaintext: &[u8],
    scheme: &str,
    key: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let s = parse_scheme(scheme)?;
    let k = parse_key(key)?;
    let out = obcrypt::encrypt(plaintext, s, &k).map_err(map_error)?;
    Ok(PyBytes::new(py, &out))
}

/// Decrypt `scheme_output` under `scheme` and return the plaintext.
///
/// The output carries no marker, so the same `scheme` used to encrypt
/// must be supplied. A wrong scheme raises `DecryptionFailed` (the
/// authentication check fails). `key` is a 128-character hex string.
#[pyfunction]
fn decrypt<'py>(
    py: Python<'py>,
    payload: &[u8],
    scheme: &str,
    key: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let s = parse_scheme(scheme)?;
    let k = parse_key(key)?;
    let out = obcrypt::decrypt(payload, s, &k).map_err(map_error)?;
    Ok(PyBytes::new(py, &out))
}

/// Generate a fresh random 64-byte key, returned as a 128-character
/// lowercase hex string — the canonical oboron key form, suitable for
/// dropping into env vars, config files, and codec / function `key`
/// arguments.
///
/// For the raw 64-byte form (HSM sealing, byte-native crypto library
/// interop, custom storage), use `generate_key_bytes()`.
#[pyfunction]
fn generate_key() -> String {
    obcrypt::generate_key().to_hex()
}

/// Generate a fresh random 64-byte key, returned as raw `bytes`.
///
/// Provided for interop with byte-native APIs (HSMs, `cryptography`,
/// `pynacl`, custom storage formats). For the canonical hex form used
/// everywhere else in obcrypt, use `generate_key()`.
#[pyfunction]
fn generate_key_bytes(py: Python<'_>) -> Bound<'_, PyBytes> {
    PyBytes::new(py, obcrypt::generate_key().as_bytes())
}

// ---------------------------------------------------------------------------
// Codec classes — one per scheme
// ---------------------------------------------------------------------------

macro_rules! impl_codec_class {
    ($py_name:ident, $scheme_variant:ident, $scheme_lit:literal, $feature:literal) => {
        #[cfg(feature = $feature)]
        #[doc = concat!(
            "Codec binding scheme `", $scheme_lit, "` to a key.\n\n",
            "Construct with a 128-character hex key string — the canonical ",
            "oboron key form, what env vars carry. `decrypt` expects output ",
            "produced under `", $scheme_lit, "`; a wrong scheme fails the ",
            "authentication check."
        )]
        #[pyclass(module = "obcrypt._obcrypt")]
        pub struct $py_name {
            inner: obcrypt::Key,
        }

        #[cfg(feature = $feature)]
        #[pymethods]
        impl $py_name {
            #[new]
            fn new(key: &str) -> PyResult<Self> {
                Ok(Self {
                    inner: parse_key(key)?,
                })
            }

            /// Encrypt `plaintext` under this codec's scheme.
            fn encrypt<'py>(
                &self,
                py: Python<'py>,
                plaintext: &[u8],
            ) -> PyResult<Bound<'py, PyBytes>> {
                let out = obcrypt::encrypt(
                    plaintext,
                    obcrypt::Scheme::$scheme_variant,
                    &self.inner,
                )
                .map_err(map_error)?;
                Ok(PyBytes::new(py, &out))
            }

            /// Decrypt output produced under this codec's scheme. A
            /// wrong scheme raises `DecryptionFailed` (authentication
            /// check fails).
            fn decrypt<'py>(
                &self,
                py: Python<'py>,
                payload: &[u8],
            ) -> PyResult<Bound<'py, PyBytes>> {
                let out = obcrypt::decrypt(
                    payload,
                    obcrypt::Scheme::$scheme_variant,
                    &self.inner,
                )
                .map_err(map_error)?;
                Ok(PyBytes::new(py, &out))
            }

            /// The key bound to this codec, as a 128-character lowercase
            /// hex string (the canonical oboron form).
            #[getter]
            fn key(&self) -> String {
                self.inner.to_hex()
            }

            /// The raw 64-byte key material bound to this codec. Provided
            /// for interop with byte-native APIs; the canonical form
            /// everywhere else is `.key` (hex).
            #[getter]
            fn key_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
                PyBytes::new(py, self.inner.as_bytes())
            }

            /// The scheme identifier (constant for this class).
            #[getter]
            fn scheme(&self) -> &'static str {
                $scheme_lit
            }

            fn __repr__(&self) -> String {
                format!("{}(key=<redacted>)", stringify!($py_name))
            }
        }
    };
}

impl_codec_class!(Dgcmsiv, Dgcmsiv, "dgcmsiv", "dgcmsiv");
impl_codec_class!(Pgcmsiv, Pgcmsiv, "pgcmsiv", "pgcmsiv");
impl_codec_class!(Dsiv, Dsiv, "dsiv", "dsiv");
impl_codec_class!(Psiv, Psiv, "psiv", "psiv");

// ---------------------------------------------------------------------------
// Module init
// ---------------------------------------------------------------------------

#[pymodule]
fn _obcrypt(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    // Exceptions
    m.add("ObcryptError", py.get_type::<ObcryptError>())?;
    m.add("InvalidKey", py.get_type::<InvalidKey>())?;
    m.add("InvalidScheme", py.get_type::<InvalidScheme>())?;
    m.add("EncryptionFailed", py.get_type::<EncryptionFailed>())?;
    m.add("DecryptionFailed", py.get_type::<DecryptionFailed>())?;

    // Codec classes (each feature-gated to match the obcrypt crate)
    #[cfg(feature = "dgcmsiv")]
    m.add_class::<Dgcmsiv>()?;
    #[cfg(feature = "pgcmsiv")]
    m.add_class::<Pgcmsiv>()?;
    #[cfg(feature = "dsiv")]
    m.add_class::<Dsiv>()?;
    #[cfg(feature = "psiv")]
    m.add_class::<Psiv>()?;

    // Module-level functions
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key_bytes, m)?)?;

    Ok(())
}
