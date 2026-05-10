//! Pluggable "what to do when we see a violation".
//!
//! The watch loop always posts a desktop notification — that's the
//! user-facing part and is handled by the [`super::Notifier`] layer.
//! On top of that, `ViolationHandler` may *also* try to undo damage:
//!
//! - [`NotifyOnly`]: nothing extra. The lockfile stays as written and
//!   the next `cargo build` / `npm install` will happily install the
//!   too-young package. Historically the default; now opt-in via
//!   `--action=notify`.
//!
//! - [`GitRevert`]: if the workspace is a git repo and the lockfile is
//!   tracked, restore it to `HEAD` (`git checkout HEAD -- <lockfile>`).
//!   This undoes the "promote a new dep into the lockfile" effect.
//!   Already-extracted packages under `~/.cargo/registry` etc. stay
//!   on disk — only the source-of-truth is rolled back — but the
//!   next build will re-resolve without the bad entry. Default for
//!   `deps watch` starting v0.12.
//!
//! **What this is NOT**: we do not yet implement pnpm-style
//! auto-fallback where resolution silently picks an older in-range
//! version. Doing that correctly would need per-ecosystem resolver
//! logic (cargo's solver, npm's peer-dep math, pip's backtracking, …)
//! and a registry proxy to rewrite metadata. Roadmap item; see
//! CLAUDE.md "Known limitations".

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::deps::CheckReport;

/// Outcome of running a handler. The `message` ends up appended to the
/// violation notification so the user knows what (if anything) was done.
pub struct HandlerOutcome {
    pub reverted: bool,
    pub message: String,
}

pub trait ViolationHandler: Send + Sync {
    fn handle(&self, lockfile: &Path, report: &CheckReport) -> Result<HandlerOutcome>;
    fn name(&self) -> &'static str;
}

// ---------------- NotifyOnly ----------------

pub struct NotifyOnly;

impl ViolationHandler for NotifyOnly {
    fn handle(&self, _lockfile: &Path, _report: &CheckReport) -> Result<HandlerOutcome> {
        Ok(HandlerOutcome {
            reverted: false,
            message: "no action taken (use --action=revert to roll the lockfile back)".into(),
        })
    }
    fn name(&self) -> &'static str {
        "notify"
    }
}

// ---------------- GitRevert ----------------

pub struct GitRevert {
    /// Overridable for tests so we can point at a fake `git` binary
    /// (or check behaviour in a workspace that's not a repo).
    pub git_binary: String,
}

impl GitRevert {
    pub fn new() -> Self {
        Self {
            git_binary: "git".to_string(),
        }
    }
}

impl Default for GitRevert {
    fn default() -> Self {
        Self::new()
    }
}

impl ViolationHandler for GitRevert {
    fn handle(&self, lockfile: &Path, _report: &CheckReport) -> Result<HandlerOutcome> {
        // Resolve the workspace root = directory containing the lockfile.
        let workdir = lockfile
            .parent()
            .ok_or_else(|| anyhow::anyhow!("lockfile has no parent dir: {}", lockfile.display()))?;
        let lockfile_name = lockfile
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("lockfile has no filename: {}", lockfile.display()))?;

        // 1. Is this a git repo?
        if !is_git_repo(&self.git_binary, workdir) {
            return Ok(HandlerOutcome {
                reverted: false,
                message: format!(
                    "not a git repo ({}) — leaving lockfile as-is; please review manually",
                    workdir.display()
                ),
            });
        }

        // 2. Is the lockfile tracked?
        if !is_tracked(&self.git_binary, workdir, Path::new(lockfile_name)) {
            return Ok(HandlerOutcome {
                reverted: false,
                message: "lockfile is not tracked by git — leaving as-is".into(),
            });
        }

        // 3. Run `git checkout HEAD -- <lockfile>`.
        let output = Command::new(&self.git_binary)
            .current_dir(workdir)
            .args(["checkout", "HEAD", "--"])
            .arg(lockfile_name)
            .output()
            .with_context(|| format!("spawning {}", self.git_binary))?;
        if !output.status.success() {
            return Ok(HandlerOutcome {
                reverted: false,
                message: format!(
                    "git checkout failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }

        Ok(HandlerOutcome {
            reverted: true,
            message: format!(
                "reverted {} to HEAD — re-run your install to pick older deps.",
                lockfile
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("lockfile")
            ),
        })
    }

    fn name(&self) -> &'static str {
        "revert"
    }
}

// ---------------- Prompt (modal dialog, user chooses Keep/Revert) ----------------

/// User's choice when asked what to do about a violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptChoice {
    /// Leave the lockfile alone — user intends to keep the new dep.
    Keep,
    /// Run the git revert flow.
    Revert,
    /// Dialog timed out / user dismissed — treat like Keep but log it.
    Timeout,
}

pub trait Prompter: Send + Sync {
    fn prompt(&self, title: &str, body: &str) -> Result<PromptChoice>;
}

/// Handler that asks the user via a modal dialog, then (on Revert)
/// delegates to [`GitRevert`].
pub struct Prompt<P: Prompter + ?Sized> {
    pub prompter: Box<P>,
    pub revert: GitRevert,
}

impl<P: Prompter + ?Sized> Prompt<P> {
    pub fn new(prompter: Box<P>) -> Self {
        Self {
            prompter,
            revert: GitRevert::new(),
        }
    }
}

impl<P: Prompter + ?Sized> ViolationHandler for Prompt<P> {
    fn handle(&self, lockfile: &Path, report: &CheckReport) -> Result<HandlerOutcome> {
        let preview_body = prompt_body(lockfile, report);
        let title = format!(
            "sakimori: {} too-young dep(s) in {}",
            report.violations,
            lockfile
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("lockfile")
        );
        let choice = self.prompter.prompt(&title, &preview_body)?;
        match choice {
            PromptChoice::Revert => self.revert.handle(lockfile, report),
            PromptChoice::Keep => Ok(HandlerOutcome {
                reverted: false,
                message: "user chose Keep — lockfile left as-is.".into(),
            }),
            PromptChoice::Timeout => Ok(HandlerOutcome {
                reverted: false,
                message: "prompt timed out — lockfile left as-is (default to Keep).".into(),
            }),
        }
    }
    fn name(&self) -> &'static str {
        "prompt"
    }
}

fn prompt_body(lockfile: &Path, report: &CheckReport) -> String {
    let mut lines = vec![format!(
        "min-age {}h, {} checked",
        report.min_age_hours, report.checked
    )];
    for p in report.packages.iter().filter(|p| p.too_new).take(5) {
        let age = p
            .age_hours
            .map(|h| format!("{h}h"))
            .unwrap_or_else(|| "?".into());
        lines.push(format!(
            "• {}/{}@{} ({age})",
            p.ecosystem, p.name, p.version
        ));
    }
    let extra = report.violations.saturating_sub(5);
    if extra > 0 {
        lines.push(format!("+{extra} more"));
    }
    lines.push(String::new());
    lines.push(format!(
        "Revert restores {} to HEAD via git.",
        short(lockfile)
    ));
    lines.join("\n")
}

fn short(p: &Path) -> String {
    p.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("lockfile")
        .to_string()
}

// ---------------- macOS osascript prompter ----------------

#[cfg(target_os = "macos")]
pub struct OsaScriptPrompter {
    pub timeout_seconds: u32,
}

#[cfg(target_os = "macos")]
impl OsaScriptPrompter {
    pub fn new() -> Self {
        Self {
            timeout_seconds: 60,
        }
    }
}

#[cfg(target_os = "macos")]
impl Default for OsaScriptPrompter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
impl Prompter for OsaScriptPrompter {
    fn prompt(&self, title: &str, body: &str) -> Result<PromptChoice> {
        // AppleScript: display dialog with two buttons. `giving up after`
        // auto-dismisses to protect against AFK users. Escape `"` by
        // doubling via `\"`.
        let esc_title = title.replace('"', "\\\"");
        let esc_body = body.replace('"', "\\\"");
        let script = format!(
            "set d to display dialog \"{esc_body}\" with title \"{esc_title}\" \
             buttons {{\"Keep\", \"Revert\"}} default button \"Keep\" \
             cancel button \"Keep\" with icon caution giving up after {to}
            set b to button returned of d
            set g to gave up of d
            return b & \"|\" & g",
            to = self.timeout_seconds
        );
        let out = Command::new("osascript")
            .args(["-e", &script])
            .output()
            .with_context(|| "spawning osascript")?;
        if !out.status.success() {
            return Ok(PromptChoice::Timeout);
        }
        let reply = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // Expect "<button>|<bool>", e.g. "Revert|false" or "Keep|true".
        let mut parts = reply.splitn(2, '|');
        let button = parts.next().unwrap_or("").trim();
        let gave_up = parts.next().unwrap_or("").trim();
        if gave_up.eq_ignore_ascii_case("true") {
            return Ok(PromptChoice::Timeout);
        }
        Ok(match button {
            "Revert" => PromptChoice::Revert,
            _ => PromptChoice::Keep,
        })
    }
}

fn is_git_repo(git: &str, dir: &Path) -> bool {
    Command::new(git)
        .current_dir(dir)
        .args(["rev-parse", "--git-dir"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn is_tracked(git: &str, dir: &Path, path: &Path) -> bool {
    Command::new(git)
        .current_dir(dir)
        .args(["ls-files", "--error-unmatch"])
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::{CheckReport, PackageReport};
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("sakimori-revert-{tag}-{id}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn dummy_report() -> CheckReport {
        CheckReport {
            min_age_hours: 168,
            checked: 1,
            violations: 1,
            errors: 0,
            packages: vec![PackageReport {
                ecosystem: "crates",
                name: "badpkg".into(),
                version: "0.1.0".into(),
                published: None,
                age_hours: Some(2),
                too_new: true,
                error: None,
            }],
        }
    }

    fn run_git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("git spawn");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn init_repo_with_committed_lockfile(dir: &Path, initial: &str) -> PathBuf {
        run_git(dir, &["init", "-q", "-b", "main"]);
        run_git(dir, &["config", "user.email", "t@example.com"]);
        run_git(dir, &["config", "user.name", "t"]);
        // Disable signing even if the global config enables it — tests
        // run on CI / unknown machines.
        run_git(dir, &["config", "commit.gpgsign", "false"]);
        let lf = dir.join("Cargo.lock");
        std::fs::write(&lf, initial).unwrap();
        run_git(dir, &["add", "Cargo.lock"]);
        run_git(dir, &["commit", "-q", "-m", "seed"]);
        lf
    }

    #[test]
    fn notify_only_is_a_noop_but_reports_nothing_done() {
        let d = tmp("notify");
        std::fs::write(d.join("Cargo.lock"), "body").unwrap();
        let out = NotifyOnly
            .handle(&d.join("Cargo.lock"), &dummy_report())
            .unwrap();
        assert!(!out.reverted);
        assert!(out.message.contains("no action"), "got {:?}", out.message);
    }

    #[test]
    fn revert_restores_tracked_lockfile_to_head() {
        let d = tmp("revert-happy");
        let original = "version = 3\n# initial committed body\n";
        let lf = init_repo_with_committed_lockfile(&d, original);

        // Simulate a bad install rewriting the lockfile.
        std::fs::write(&lf, "version = 3\n# BAD NEW DEP\n").unwrap();
        assert!(std::fs::read_to_string(&lf).unwrap().contains("BAD NEW"));

        let out = GitRevert::new().handle(&lf, &dummy_report()).unwrap();
        assert!(
            out.reverted,
            "expected reverted=true, got {:?}",
            out.message
        );
        assert!(out.message.contains("reverted"), "got {:?}", out.message);
        assert_eq!(std::fs::read_to_string(&lf).unwrap(), original);
    }

    #[test]
    fn revert_in_non_repo_leaves_file_alone() {
        let d = tmp("not-a-repo");
        let lf = d.join("Cargo.lock");
        std::fs::write(&lf, "body").unwrap();

        let out = GitRevert::new().handle(&lf, &dummy_report()).unwrap();
        assert!(!out.reverted);
        assert!(out.message.contains("not a git repo"));
        // File is untouched.
        assert_eq!(std::fs::read_to_string(&lf).unwrap(), "body");
    }

    #[test]
    fn revert_leaves_untracked_lockfile_alone() {
        let d = tmp("untracked");
        init_repo_with_committed_lockfile(&d, "# first\n");
        // Write a DIFFERENT lockfile (untracked).
        let lf = d.join("package-lock.json");
        std::fs::write(&lf, "{\"lockfileVersion\":3,\"packages\":{}}").unwrap();

        let out = GitRevert::new().handle(&lf, &dummy_report()).unwrap();
        assert!(!out.reverted);
        assert!(out.message.contains("not tracked"));
    }

    // ---- Prompt handler tests (with mock prompters) ----

    struct FixedPrompter(PromptChoice);
    impl Prompter for FixedPrompter {
        fn prompt(&self, _title: &str, _body: &str) -> Result<PromptChoice> {
            Ok(self.0)
        }
    }

    #[test]
    fn prompt_keep_leaves_lockfile_alone() {
        let d = tmp("prompt-keep");
        let lf = init_repo_with_committed_lockfile(&d, "# original\n");
        std::fs::write(&lf, "# modified\n").unwrap();

        let handler = Prompt::new(Box::new(FixedPrompter(PromptChoice::Keep)));
        let out = handler.handle(&lf, &dummy_report()).unwrap();
        assert!(!out.reverted);
        assert!(out.message.contains("Keep"), "got {:?}", out.message);
        assert_eq!(std::fs::read_to_string(&lf).unwrap(), "# modified\n");
    }

    #[test]
    fn prompt_revert_actually_reverts_via_git() {
        let d = tmp("prompt-revert");
        let original = "# pristine\n";
        let lf = init_repo_with_committed_lockfile(&d, original);
        std::fs::write(&lf, "# corrupted\n").unwrap();

        let handler = Prompt::new(Box::new(FixedPrompter(PromptChoice::Revert)));
        let out = handler.handle(&lf, &dummy_report()).unwrap();
        assert!(out.reverted);
        assert_eq!(std::fs::read_to_string(&lf).unwrap(), original);
    }

    #[test]
    fn prompt_timeout_is_treated_as_keep() {
        let d = tmp("prompt-timeout");
        let lf = init_repo_with_committed_lockfile(&d, "# before\n");
        std::fs::write(&lf, "# after\n").unwrap();

        let handler = Prompt::new(Box::new(FixedPrompter(PromptChoice::Timeout)));
        let out = handler.handle(&lf, &dummy_report()).unwrap();
        assert!(!out.reverted);
        assert!(out.message.contains("timed out"));
        assert_eq!(std::fs::read_to_string(&lf).unwrap(), "# after\n");
    }

    #[test]
    fn prompt_body_mentions_min_age_and_violating_packages() {
        let r = dummy_report();
        let body = prompt_body(Path::new("/x/Cargo.lock"), &r);
        assert!(body.contains("min-age 168h"));
        assert!(body.contains("crates/badpkg@0.1.0"));
        assert!(body.contains("Revert"));
    }
}
