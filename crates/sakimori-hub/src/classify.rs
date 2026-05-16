//! Hub-side classification of *where* an InstallEvent originated.
//!
//! The proxy already records `execution_mode` (persistent vs ephemeral
//! — see [`sakimori_core::installs::ExecutionMode`]). That's the
//! "what shape of install" axis. This module adds the orthogonal
//! "what shape of machine" axis: a CI runner or a developer's laptop?
//!
//! The two answers together drive different inventory views ("who on
//! the team has `<pkg>@<ver>` checked in" vs. "did any CI job pull
//! `<pkg>@<ver>` last week") and, eventually, different advisory
//! notification routing.
//!
//! The classifier is intentionally conservative: when neither a
//! User-Agent nor a project-path gives a confident answer we return
//! [`Source::Unknown`] rather than guess.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// GitHub Actions runner (and, by reasonable extension, other
    /// hosted CI we haven't fingerprinted yet — for now this variant
    /// is GHA-shaped).
    Actions,
    /// Developer endpoint — laptop / workstation.
    Desktop,
    /// Couldn't classify confidently. Surface as "unknown" rather
    /// than mis-attribute.
    Unknown,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Actions => "actions",
            Source::Desktop => "desktop",
            Source::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "actions" => Some(Source::Actions),
            "desktop" => Some(Source::Desktop),
            "unknown" => Some(Source::Unknown),
            _ => None,
        }
    }
}

/// Decide where an event came from.
///
/// Order of precedence:
///
/// 1. **`project_path`** — GitHub-hosted runners always check the
///    repo out under `/home/runner/work/<repo>/<repo>/` (Linux) or
///    `D:\a\<repo>\<repo>\` / `C:\actions-runner\_work\...` (Windows
///    self-hosted). Anything matching is a CI runner.
/// 2. **`user_agent`** — the GHA-shipped tooling sets distinctive
///    UAs (e.g. `actions/setup-node`, `GitHubActions`). Less reliable
///    than path because package managers themselves don't advertise
///    "I'm on a runner", but useful when `project_path` is absent.
/// 3. **Otherwise** — if we have *some* signal that suggests a
///    developer machine (`/Users/...`, `/home/<non-runner>/...`,
///    `C:\Users\...`) we say `Desktop`. If we have nothing, `Unknown`.
pub fn classify(project_path: Option<&str>, user_agent: Option<&str>) -> Source {
    if let Some(path) = project_path {
        if looks_like_runner_path(path) {
            return Source::Actions;
        }
        if looks_like_desktop_path(path) {
            return Source::Desktop;
        }
    }
    if let Some(ua) = user_agent
        && looks_like_actions_ua(ua)
    {
        return Source::Actions;
    }
    Source::Unknown
}

fn looks_like_runner_path(path: &str) -> bool {
    // GitHub-hosted (Linux, macOS): /home/runner/work/<repo>/<repo>/
    // GitHub-hosted (Linux runners post-2024 also expose /Users/runner on macOS)
    // Self-hosted: typically `_work` directory under the runner home.
    let normalised = path.replace('\\', "/");
    normalised.contains("/home/runner/work/")
        || normalised.contains("/Users/runner/work/")
        || normalised.contains("/actions-runner/_work/")
        || normalised.contains(":/a/")
        // Windows GitHub-hosted: D:\a\<repo>\<repo>\
        || normalised.starts_with("D:/a/")
        || normalised.starts_with("C:/a/")
}

fn looks_like_desktop_path(path: &str) -> bool {
    let normalised = path.replace('\\', "/");
    // POSIX user homes that aren't `runner`. Match prefix + path
    // separator to avoid `/Users/runnerfoo/...` collisions.
    if let Some(rest) = normalised.strip_prefix("/Users/")
        && !rest.starts_with("runner/")
    {
        return true;
    }
    if let Some(rest) = normalised.strip_prefix("/home/")
        && !rest.starts_with("runner/")
    {
        return true;
    }
    // Windows user profile dir.
    let lower = normalised.to_ascii_lowercase();
    lower.starts_with("c:/users/") && !lower.starts_with("c:/users/runneradmin/")
}

fn looks_like_actions_ua(ua: &str) -> bool {
    // GHA-shipped tooling and the runner itself set distinctive UAs.
    // The list is deliberately small — we'd rather mis-classify as
    // Unknown than mis-attribute a developer's `npm install` to CI.
    let lower = ua.to_ascii_lowercase();
    lower.contains("githubactions")
        || lower.contains("github-actions")
        || lower.contains("actions/setup-")
        || lower.contains("actions/runner")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_hosted_linux_path_is_actions() {
        assert_eq!(
            classify(Some("/home/runner/work/myrepo/myrepo"), None),
            Source::Actions
        );
    }

    #[test]
    fn github_hosted_windows_path_is_actions() {
        assert_eq!(classify(Some(r"D:\a\myrepo\myrepo"), None), Source::Actions);
    }

    #[test]
    fn self_hosted_runner_path_is_actions() {
        assert_eq!(
            classify(Some("/opt/actions-runner/_work/myrepo/myrepo"), None),
            Source::Actions
        );
    }

    #[test]
    fn macos_user_home_is_desktop() {
        assert_eq!(
            classify(Some("/Users/alice/code/proj"), None),
            Source::Desktop
        );
    }

    #[test]
    fn linux_user_home_is_desktop() {
        assert_eq!(
            classify(Some("/home/alice/src/proj"), None),
            Source::Desktop
        );
    }

    #[test]
    fn similar_but_not_runner_user_is_desktop() {
        // The startswith check must not be tricked by usernames
        // starting with "runner".
        assert_eq!(
            classify(Some("/home/runnerfoo/proj"), None),
            Source::Desktop
        );
    }

    #[test]
    fn windows_user_profile_is_desktop() {
        assert_eq!(
            classify(Some(r"C:\Users\alice\proj"), None),
            Source::Desktop
        );
    }

    #[test]
    fn actions_ua_without_path_classifies() {
        assert_eq!(
            classify(None, Some("actions/setup-node@4.0.0")),
            Source::Actions
        );
    }

    #[test]
    fn nothing_known_is_unknown() {
        assert_eq!(classify(None, None), Source::Unknown);
        assert_eq!(
            classify(None, Some("npm/10.0.0 node/20.0.0")),
            Source::Unknown
        );
        // Path that matches neither bucket.
        assert_eq!(classify(Some("/srv/build/proj"), None), Source::Unknown);
    }

    #[test]
    fn path_beats_ambiguous_ua() {
        // Path is the higher-confidence signal — even if UA looks
        // CI-ish, a clearly-desktop path wins.
        assert_eq!(
            classify(Some("/Users/alice/proj"), Some("actions/setup-node")),
            Source::Desktop
        );
    }

    #[test]
    fn source_string_roundtrip() {
        for s in [Source::Actions, Source::Desktop, Source::Unknown] {
            assert_eq!(Source::parse(s.as_str()), Some(s));
        }
        assert_eq!(Source::parse("nonsense"), None);
    }
}
