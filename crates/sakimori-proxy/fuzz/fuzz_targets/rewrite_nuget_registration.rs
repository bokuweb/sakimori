#![no_main]
//! NuGet v3 registration-index rewriter.

use chrono::Utc;
use libfuzzer_sys::fuzz_target;
use sakimori_proxy::rewrite_nuget::rewrite_nuget_registration;
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    let _ = rewrite_nuget_registration(data, Duration::from_secs(86_400), Utc::now());
});
