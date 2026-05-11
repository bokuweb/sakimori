//! Pluggable notification sink.
//!
//! `Notifier` abstracts "how to tell the user" so the watch loop is
//! pure-function-testable. `MacNotifier` shells out to `osascript`
//! (works on vanilla macOS, no extra install), `StdoutNotifier` prints
//! to stderr for CLI debugging, and `CollectingNotifier` captures into
//! a `Vec` for unit tests.

use std::sync::{Arc, Mutex};

use anyhow::Result;

pub trait Notifier: Send + Sync {
    fn notify(&self, title: &str, body: &str) -> Result<()>;
}

// ---- stdout ----

pub struct StdoutNotifier;

impl Notifier for StdoutNotifier {
    fn notify(&self, title: &str, body: &str) -> Result<()> {
        eprintln!("[notify] {title}\n  {}", body.replace('\n', "\n  "));
        Ok(())
    }
}

// ---- in-memory collector (tests) ----

#[derive(Default, Clone)]
pub struct CollectingNotifier {
    pub events: Arc<Mutex<Vec<(String, String)>>>,
}

impl CollectingNotifier {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn take(&self) -> Vec<(String, String)> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
}

impl Notifier for CollectingNotifier {
    fn notify(&self, title: &str, body: &str) -> Result<()> {
        self.events
            .lock()
            .unwrap()
            .push((title.to_string(), body.to_string()));
        Ok(())
    }
}

// ---- macOS ----

#[cfg(target_os = "macos")]
pub struct MacNotifier {
    pub subtitle: String,
}

#[cfg(target_os = "macos")]
impl MacNotifier {
    pub fn new() -> Self {
        Self {
            subtitle: "sakimori".to_string(),
        }
    }
}

#[cfg(target_os = "macos")]
impl Default for MacNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
impl Notifier for MacNotifier {
    fn notify(&self, title: &str, body: &str) -> Result<()> {
        use std::process::Command;
        // AppleScript quoting: embed `"` by doubling. Newlines are fine
        // inside an AppleScript string literal.
        let esc_title = title.replace('"', "\\\"");
        let esc_body = body.replace('"', "\\\"");
        let esc_sub = self.subtitle.replace('"', "\\\"");
        let script = format!(
            "display notification \"{esc_body}\" with title \"{esc_title}\" subtitle \"{esc_sub}\""
        );
        let status = Command::new("osascript").args(["-e", &script]).status()?;
        if !status.success() {
            anyhow::bail!("osascript exited {status}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collecting_captures_in_order() {
        let n = CollectingNotifier::new();
        n.notify("A", "body a").unwrap();
        n.notify("B", "body b").unwrap();
        let got = n.take();
        assert_eq!(
            got,
            vec![
                ("A".to_string(), "body a".to_string()),
                ("B".to_string(), "body b".to_string())
            ]
        );
        // Subsequent `take` returns empty.
        assert!(n.take().is_empty());
    }

    #[test]
    fn stdout_notifier_never_errors() {
        StdoutNotifier.notify("x", "y").unwrap();
    }
}
