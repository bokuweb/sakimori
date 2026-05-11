//! Append-only log of every package install / fetch the proxy
//! resolves. Feeds two consumers:
//!
//! - `sakimori advisories scan` — local OSV.dev batch query against the
//!   installs we've seen, so a newly-disclosed advisory on a package we
//!   pulled last week surfaces without re-running CI.
//! - the optional `sakimori-hub` self-host server — same `InstallEvent`
//!   JSON shape, sent over HTTP for team-wide push notifications.
//!
//! The file lives at `~/.sakimori/installs.jsonl` (override via
//! [`InstallLogger::at`]) and is opened with `O_APPEND` per write, so
//! parallel proxies on the same machine interleave whole lines without
//! corrupting each other (POSIX guarantees `write()` of ≤ PIPE_BUF on
//! `O_APPEND` is atomic; we stay well under that). On Windows the same
//! flag (`FILE_APPEND_DATA`) gives the same property.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::deps::Ecosystem;

/// How the install was invoked — drives the host UI's recommended
/// remediation. See CLAUDE.md roadmap item #6 for the rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionMode {
    /// Pinned in a lockfile (`npm install`, `cargo add`, `pip install`,
    /// `dotnet add package`). Advisory → "bump and re-install".
    Persistent,
    /// One-shot (`npx`, `pnpm dlx`, `uvx`, `pipx run`, `cargo install`,
    /// `go run <remote>`). Advisory → "this ran on the machine — investigate".
    Ephemeral,
    /// Couldn't classify from User-Agent + URL shape. Surface to the
    /// UI as "unknown" rather than mis-classifying as ephemeral.
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallEvent {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub resolved_at: DateTime<Utc>,
    pub execution_mode: ExecutionMode,
    /// Best-effort working-directory of the invoking package manager,
    /// or `None` if not derivable from the proxy request alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_path: Option<String>,
    /// Raw User-Agent header the proxy saw — keeps the attribution
    /// chain reconstructable after the fact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

impl InstallEvent {
    pub fn new(eco: Ecosystem, name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            ecosystem: eco.label().to_string(),
            name: name.into(),
            version: version.into(),
            resolved_at: Utc::now(),
            execution_mode: ExecutionMode::Unknown,
            project_path: None,
            user_agent: None,
        }
    }

    pub fn with_mode(mut self, mode: ExecutionMode) -> Self {
        self.execution_mode = mode;
        self
    }

    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    pub fn with_project_path(mut self, path: impl Into<String>) -> Self {
        self.project_path = Some(path.into());
        self
    }
}

/// Append-only writer. Cheap to construct (no file is opened until the
/// first `record`); cloning is intentionally not implemented to keep the
/// expected pattern of "one logger held behind an `Arc`".
pub struct InstallLogger {
    path: PathBuf,
}

impl InstallLogger {
    /// Default location: `~/.sakimori/installs.jsonl`. Falls back to
    /// `./installs.jsonl` in the unlikely case `$HOME` is unset.
    pub fn default_path() -> PathBuf {
        match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(".sakimori").join("installs.jsonl"),
            None => PathBuf::from("installs.jsonl"),
        }
    }

    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record(&self, event: &InstallEvent) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut f: File = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("opening {}", self.path.display()))?;
        let mut line = serde_json::to_string(event).context("serializing InstallEvent")?;
        line.push('\n');
        f.write_all(line.as_bytes())
            .with_context(|| format!("writing to {}", self.path.display()))?;
        Ok(())
    }

    /// Read every event currently in the log. Skips malformed lines so
    /// a single corrupt write (e.g. a hard kill mid-line) doesn't make
    /// the whole history unreadable.
    pub fn read_all(&self) -> Result<Vec<InstallEvent>> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.path.display())),
        };
        let mut out = Vec::new();
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(ev) = serde_json::from_str::<InstallEvent>(trimmed) {
                out.push(ev);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_path() -> PathBuf {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("sakimori-installs-{id}/installs.jsonl"))
    }

    #[test]
    fn record_then_read_roundtrips() {
        let p = tmp_path();
        let logger = InstallLogger::at(&p);
        let ev = InstallEvent::new(Ecosystem::Npm, "left-pad", "1.3.0")
            .with_mode(ExecutionMode::Persistent)
            .with_user_agent("npm/10.0.0 node/20.0.0");
        logger.record(&ev).unwrap();
        logger.record(&ev).unwrap();
        let back = logger.read_all().unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].name, "left-pad");
        assert_eq!(back[0].ecosystem, "npm");
        assert_eq!(back[0].execution_mode, ExecutionMode::Persistent);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn read_all_skips_garbage_lines() {
        let p = tmp_path();
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            b"{\"ecosystem\":\"npm\",\"name\":\"a\",\"version\":\"1\",\"resolved_at\":\"2026-01-01T00:00:00Z\",\"execution_mode\":\"persistent\"}\n\
              not json at all\n\
              {\"ecosystem\":\"crates\",\"name\":\"b\",\"version\":\"2\",\"resolved_at\":\"2026-01-01T00:00:00Z\",\"execution_mode\":\"ephemeral\"}\n",
        ).unwrap();
        let back = InstallLogger::at(&p).read_all().unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].name, "a");
        assert_eq!(back[1].name, "b");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn read_all_on_missing_file_is_empty() {
        let p = tmp_path();
        assert!(InstallLogger::at(&p).read_all().unwrap().is_empty());
    }

    #[test]
    fn default_path_under_home() {
        // Just exercise the function — concrete location depends on env.
        let _ = InstallLogger::default_path();
    }
}
