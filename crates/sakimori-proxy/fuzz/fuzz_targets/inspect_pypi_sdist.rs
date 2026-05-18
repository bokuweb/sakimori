#![no_main]
//! PyPI sdist inspector — gzipped tar with `setup.py` / `pyproject.toml`.
//! Same decode-surface risk as the npm inspector.

use libfuzzer_sys::fuzz_target;
use sakimori_proxy::lifecycle::inspect_pypi_sdist;

fuzz_target!(|data: &[u8]| {
    let _ = inspect_pypi_sdist(data);
});
