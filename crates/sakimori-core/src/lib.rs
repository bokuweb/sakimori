//! Shared, platform-neutral building blocks for the sakimori family:
//! - [`events`]: the audit event schema (Exec / Open / Connect)
//! - [`stats`]: aggregate counters + per-kind sample buffer
//! - [`policy`]: YAML/JSON policy loader
//! - [`matcher`]: userspace-side file / exec deny matching
//! - [`html`]: self-contained HTML report renderer
//! - [`report`]: JSON log + `$GITHUB_STEP_SUMMARY` writer
//!
//! This crate exists so the Linux (`sakimori`) and Windows
//! (`sakimori-win`) binaries can emit **identical** JSON logs and HTML
//! reports. Anything that needs eBPF / ETW / OS-specific APIs stays in
//! the respective binary crates.

pub mod actions;
pub mod advisories;
pub mod attribution;
pub mod deps;
pub mod events;
pub mod html;
pub mod installs;
pub mod matcher;
pub mod policy;
pub mod presets;
pub mod report;
pub mod stats;
pub mod suggest;
pub mod tamper;

pub use events::Event;
pub use policy::{
    DefaultDecision, EnvDefault, EnvPolicy, FilePolicy, Mode, NetRule, NetworkPolicy, Policy,
    ProcessPolicy,
};
pub use stats::Stats;
