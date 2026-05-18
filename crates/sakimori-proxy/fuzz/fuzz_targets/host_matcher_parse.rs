#![no_main]
//! Host-allow parser + matcher. Drives `from_patterns` with a
//! `\n`-split chunk so a single fuzz input exercises both arbitrary
//! patterns *and* arbitrary match queries.

use libfuzzer_sys::fuzz_target;
use sakimori_proxy::host_allow::HostMatcher;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let mut lines = s.split('\n');
    let query = lines.next().unwrap_or("");
    let patterns: Vec<&str> = lines.collect();
    if let Ok(m) = HostMatcher::from_patterns(patterns) {
        let _ = m.allows(query);
    }
});
