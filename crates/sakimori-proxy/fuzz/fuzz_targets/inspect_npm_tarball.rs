#![no_main]
//! Inspector reads attacker-controlled npm tarballs (gzipped tar +
//! JSON `package.json`). A panic at the proxy layer becomes a 5xx
//! and silently disables the lifecycle-script defence.

use libfuzzer_sys::fuzz_target;
use sakimori_proxy::lifecycle::inspect_npm_tarball;

fuzz_target!(|data: &[u8]| {
    let _ = inspect_npm_tarball(data);
});
