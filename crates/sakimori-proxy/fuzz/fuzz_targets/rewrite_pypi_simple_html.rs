#![no_main]
//! PEP 503 Simple HTML rewriter — the trickiest of the PyPI shapes
//! because it mutates raw bytes around anchor boundaries. Off-by-one
//! / unicode-boundary bugs land here.

use chrono::Utc;
use libfuzzer_sys::fuzz_target;
use sakimori_proxy::rewrite_pypi::rewrite_pypi_simple_html;
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    let _ = rewrite_pypi_simple_html(data, Duration::from_secs(86_400), Utc::now(), |_| None);
});
