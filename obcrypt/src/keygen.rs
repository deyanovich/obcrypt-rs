use crate::Key;

/// Generate a cryptographically secure random 64-byte [`Key`].
///
/// Equivalent to [`Key::random`]; kept as a free function for ergonomic
/// parity with `oboron::generate_key` (which returns a hex-encoded
/// string instead of a `Key`).
///
/// # Examples
///
/// ```
/// let key = obcrypt::generate_key();
/// assert_eq!(key.as_bytes().len(), 64);
/// ```
#[must_use]
#[inline]
pub fn generate_key() -> Key {
    Key::random()
}
