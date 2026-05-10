//! Desktop "watch" mode for `sakimori deps`.
//!
//! Runs as a long-lived process (typically under `launchd` on macOS).
//! Walks the configured workspace dirs for known lockfile names,
//! subscribes to FS events via the `notify` crate, debounces bursts of
//! writes, and runs the usual [`crate::deps::check`] every time a
//! lockfile settles. Violations are pushed to a pluggable [`Notifier`].
//!
//! The public surface is intentionally small and pure-Rust so the whole
//! thing is unit-testable without touching FS events or macOS.

pub mod action;
pub mod debounce;
pub mod discover;
pub mod engine;
pub mod format;
pub mod notifier;

pub use action::{
    GitRevert, HandlerOutcome, NotifyOnly, Prompt, PromptChoice, Prompter, ViolationHandler,
};

#[cfg(target_os = "macos")]
pub use action::OsaScriptPrompter;
pub use debounce::Debouncer;
pub use discover::{LOCKFILE_NAMES, scan_lockfiles};
pub use engine::{EventSource, NotifyEventSource, WatchLoop};
pub use format::format_violation;
pub use notifier::{CollectingNotifier, Notifier, StdoutNotifier};

#[cfg(target_os = "macos")]
pub use notifier::MacNotifier;
