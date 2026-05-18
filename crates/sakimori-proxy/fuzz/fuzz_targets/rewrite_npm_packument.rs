#![no_main]
//! npm packument JSON rewriter — drops too-young versions and
//! retargets `dist-tags`. Attacker model: an upstream / on-path
//! mirror serving crafted JSON that triggers a panic or
//! mis-classification.

use chrono::Utc;
use libfuzzer_sys::fuzz_target;
use sakimori_proxy::rewrite_npm::rewrite_npm_packument;
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    let _ = rewrite_npm_packument(data, Duration::from_secs(86_400), Utc::now());
});
