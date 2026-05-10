//! `sakimori-win` — Windows audit tool, feature-parity with the Linux
//! `sakimori` binary for the subset of functionality that makes sense
//! on Windows (audit of exec / network connects / file opens).
//!
//! Runs on `windows-latest` GitHub runners (which are elevated by default).
//! Uses ETW public providers — no kernel driver install, no signing.
//!
//! What's the same as Linux:
//! - `--policy <file>` reads the same YAML/JSON format
//! - `--mode audit|block` same semantics (block = exit non-zero on deny)
//! - `--log <path>` JSON log, same schema (Event enum via sakimori-core)
//! - `--summary <path>` markdown for GITHUB_STEP_SUMMARY
//! - `--html <path>` same HTML dashboard
//!
//! What's different / documented in README "Limitations":
//! - File / exec deny is **audit only** (same as Linux — no kernel block
//!   on either side right now).
//! - Network deny is **also audit only** on Windows for this first pass.
//!   True kernel-level network block on Windows needs a WFP driver; the
//!   lighter weight workaround using `New-NetFirewallRule` is a roadmap
//!   item.

#![cfg_attr(not(windows), allow(unused))]

#[cfg(windows)]
mod firewall;
#[cfg(windows)]
mod win;

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    win::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("sakimori-win only builds on Windows");
    std::process::exit(1);
}
