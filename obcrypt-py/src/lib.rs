//! Python bindings for `obcrypt` via PyO3 / maturin.
//!
//! Scaffold only — the real binding surface is the next step.

use pyo3::prelude::*;

/// Module-level placeholder. Real classes / functions will land in
/// the next step of the release plan.
#[pymodule]
fn _obcrypt(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
