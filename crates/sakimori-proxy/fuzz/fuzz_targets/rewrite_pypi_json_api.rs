#![no_main]
//! Warehouse JSON API rewriter (`/pypi/<pkg>/json`).

use chrono::Utc;
use libfuzzer_sys::fuzz_target;
use sakimori_proxy::rewrite_pypi::rewrite_pypi_json_api;
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    let _ = rewrite_pypi_json_api(data, Duration::from_secs(86_400), Utc::now());
});
