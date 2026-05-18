# sakimori-proxy fuzz harnesses

Coverage-guided libFuzzer harnesses for the proxy's attacker-controlled
byte parsers / rewriters. Excluded from the main workspace so the
nightly + sanitizer toolchain doesn't leak into ordinary
`cargo build` / `cargo test`.

## Why this exists alongside proptest

Each module under `crates/sakimori-proxy/src/` already has a
`#[cfg(test)] mod tests` block with `proptest!` invariants (no-panic,
idempotence, hash drift, `min_age=0` no-op). Those run on every
`cargo test` and catch the obvious shapes.

The fuzz harnesses below go deeper on the byte-decoder surface — gzip
framing, tar header parsing, JSON parser corner cases, raw HTML byte
walking — using libFuzzer's coverage guidance to discover inputs
proptest's random generation would miss in any reasonable case count.
They're intended for ad-hoc / nightly CI runs, not the pre-commit
gate.

## Running

Requires nightly Rust and `cargo install cargo-fuzz`.

```sh
cd crates/sakimori-proxy/fuzz
cargo +nightly fuzz run inspect_npm_tarball
```

Targets:

| target                       | what it drives                                   |
| ---------------------------- | ------------------------------------------------ |
| `inspect_npm_tarball`        | `lifecycle::inspect_npm_tarball`                 |
| `strip_npm_tarball`          | `lifecycle::strip_npm_tarball` (gzip→tar→edit→) |
| `inspect_pypi_sdist`         | `lifecycle::inspect_pypi_sdist`                  |
| `rewrite_npm_packument`      | `rewrite_npm::rewrite_npm_packument`             |
| `rewrite_pypi_simple_html`   | `rewrite_pypi::rewrite_pypi_simple_html`         |
| `rewrite_pypi_json_api`      | `rewrite_pypi::rewrite_pypi_json_api`            |
| `rewrite_nuget_registration` | `rewrite_nuget::rewrite_nuget_registration`      |
| `host_matcher_parse`         | `host_allow::HostMatcher` parse + match          |

## Seeding corpora

Drop interesting inputs under `corpus/<target>/`. The proxy's existing
test fixtures (e.g. captured npm packuments, real PyPI Simple HTML
samples) make excellent seeds — fewer wasted cycles before the fuzzer
finds structured paths.
