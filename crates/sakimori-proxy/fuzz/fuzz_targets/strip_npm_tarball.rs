#![no_main]
//! Strip-mode rewriter — the most complex byte-level path in the
//! proxy (gzip → tar → JSON edit → tar rebuild → gzip → SHA hash).
//! Default `StripLimits` is sized to admit every legitimate npm
//! package; the cap-check itself is part of what's under test for
//! pathological inputs.

use libfuzzer_sys::fuzz_target;
use sakimori_proxy::lifecycle::{StripLimits, strip_npm_tarball};

fuzz_target!(|data: &[u8]| {
    let _ = strip_npm_tarball(data, &StripLimits::default());
});
