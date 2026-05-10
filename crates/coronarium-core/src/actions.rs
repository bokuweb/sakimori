//! GitHub Actions workflow auditor — flags `uses:` refs that point at
//! a mutable tag/branch instead of an immutable commit SHA.
//!
//! A floating tag (`@v4`, `@main`, `@latest`) is the supply-chain
//! analogue of an unpinned dependency: the action author can move
//! the tag at any time and your workflow silently picks up the new
//! code on the next run. The defence is the same as everywhere else
//! in the ecosystem — pin to the exact commit SHA, ideally with a
//! comment naming the tag for human readability:
//!
//! ```yaml
//! - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11   # v4.1.1
//! ```
//!
//! Findings are emitted with a coarse severity:
//!
//! - [`Severity::Error`]: a mutable ref where pinning is unambiguous
//!   — third-party action with `@v1` / `@main` / `@<branch>`.
//! - [`Severity::Warn`]: first-party (`actions/*`, `github/*`) with
//!   a mutable ref. Still risky, but GitHub-owned actions have a
//!   stronger publish process so we don't fail builds by default.
//! - [`Severity::Ok`]: 40-char hex SHA, local action (`./...`), or a
//!   docker image reference with a digest.
//!
//! Out of scope (intentionally): walking `action.yml` composite
//! action files, resolving tags to SHAs via the GitHub API
//! (offline tool), and detecting `actions/*` published from a fork.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Ok,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Job id from the YAML (`jobs.<this>`).
    pub job: String,
    /// Step name (`name:`) when present, else the step's own `uses:`
    /// echoed back. `None` means the `uses:` was at job-level —
    /// i.e. a reusable-workflow call rather than a step.
    pub step: Option<String>,
    /// The raw `uses:` value as written in the workflow.
    pub uses: String,
    pub severity: Severity,
    pub message: String,
}

impl Finding {
    pub fn is_blocking(&self) -> bool {
        matches!(self.severity, Severity::Error)
    }
}

/// Audit a single workflow YAML document. Returns one [`Finding`]
/// per `uses:` value encountered (including OK ones, so callers
/// can show "N actions, M pinned" stats if they want).
pub fn audit_yaml(yaml: &str) -> Result<Vec<Finding>> {
    let doc: serde_yaml::Value = serde_yaml::from_str(yaml).context("parsing workflow YAML")?;
    let jobs = match doc.get("jobs").and_then(|v| v.as_mapping()) {
        Some(m) => m,
        // `action.yml` (composite action) and other non-workflow
        // YAMLs have no `jobs:` block — nothing to audit. Empty
        // result is the right answer; the caller decides whether
        // to treat that as a problem.
        None => return Ok(Vec::new()),
    };

    let mut out = Vec::new();
    // BTreeMap iter would be nicer but serde_yaml gives us a
    // Mapping (insertion-ordered) — iterate in source order so
    // findings line up with the file.
    for (job_id, job_val) in jobs {
        let job_id = job_id.as_str().unwrap_or("<non-string>").to_string();
        let job_map = match job_val.as_mapping() {
            Some(m) => m,
            None => continue,
        };

        // Reusable workflow call: `jobs.<id>.uses: org/repo/...@ref`.
        if let Some(uses) = job_map
            .get(serde_yaml::Value::String("uses".into()))
            .and_then(|v| v.as_str())
        {
            out.push(classify_finding(job_id.clone(), None, uses));
        }

        // Regular job: `jobs.<id>.steps[].uses`.
        if let Some(steps) = job_map
            .get(serde_yaml::Value::String("steps".into()))
            .and_then(|v| v.as_sequence())
        {
            for step in steps {
                let step_map = match step.as_mapping() {
                    Some(m) => m,
                    None => continue,
                };
                let uses = match step_map
                    .get(serde_yaml::Value::String("uses".into()))
                    .and_then(|v| v.as_str())
                {
                    Some(u) => u,
                    // `run:` step or anything else without `uses` —
                    // not in scope for the SHA-pin auditor.
                    None => continue,
                };
                let name = step_map
                    .get(serde_yaml::Value::String("name".into()))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                out.push(classify_finding(job_id.clone(), name, uses));
            }
        }
    }
    Ok(out)
}

/// Aggregate stats over a flat finding list — handy for the CLI
/// summary line without re-walking the vector.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Summary {
    pub total: usize,
    pub ok: usize,
    pub warn: usize,
    pub error: usize,
    pub by_owner: BTreeMap<String, usize>,
}

impl Summary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut s = Summary {
            total: findings.len(),
            ..Self::default()
        };
        for f in findings {
            match f.severity {
                Severity::Ok => s.ok += 1,
                Severity::Warn => s.warn += 1,
                Severity::Error => s.error += 1,
            }
            if let Some(owner) = owner_of(&f.uses) {
                *s.by_owner.entry(owner.to_string()).or_default() += 1;
            }
        }
        s
    }
}

fn classify_finding(job: String, step: Option<String>, uses: &str) -> Finding {
    let (severity, message) = classify(uses);
    Finding {
        job,
        step,
        uses: uses.to_string(),
        severity,
        message,
    }
}

/// Decide whether a `uses:` value is acceptable.
///
/// The rules, in order:
/// 1. Local action (`./...`, `../...`) — OK, nothing to pin.
/// 2. Docker image with a `@sha256:…` digest — OK; bare `:tag` is
///    Warn (Docker tags are mutable but not in the same trust
///    model as a GitHub-hosted action).
/// 3. `<owner>/<repo>...@<ref>`:
///    - `<ref>` is 40 hex chars → OK.
///    - `<ref>` looks like a version tag or branch:
///      - first-party owner → Warn
///      - third-party owner → Error
/// 4. Anything else (no `@`, malformed) → Warn — we'd rather
///    surface than silently accept.
pub fn classify(uses: &str) -> (Severity, String) {
    let trimmed = uses.trim();
    if trimmed.starts_with("./") || trimmed.starts_with("../") {
        return (Severity::Ok, "local action; no pin needed".into());
    }
    if let Some(rest) = trimmed.strip_prefix("docker://") {
        return classify_docker(rest);
    }
    let (path, reference) = match trimmed.split_once('@') {
        Some((p, r)) => (p, r),
        None => {
            return (
                Severity::Warn,
                format!("no `@<ref>` — cannot tell what version `{trimmed}` resolves to"),
            );
        }
    };
    if is_sha40(reference) {
        return (Severity::Ok, "pinned to commit SHA".into());
    }
    let owner = path.split('/').next().unwrap_or("");
    let first_party = matches!(owner, "actions" | "github");
    let sev = if first_party {
        Severity::Warn
    } else {
        Severity::Error
    };
    let kind = if looks_like_branch(reference) {
        "branch"
    } else {
        "tag"
    };
    (
        sev,
        format!(
            "mutable {kind} `{reference}` on {} action `{path}` — pin to a 40-char commit SHA \
             (e.g. `{path}@<sha>  # {reference}`)",
            if first_party {
                "first-party"
            } else {
                "third-party"
            }
        ),
    )
}

fn classify_docker(rest: &str) -> (Severity, String) {
    if rest.contains("@sha256:") {
        (Severity::Ok, "docker image pinned by digest".into())
    } else if rest.contains(':') {
        (
            Severity::Warn,
            format!("docker image `{rest}` uses a mutable tag — pin with `@sha256:…`"),
        )
    } else {
        (
            Severity::Warn,
            format!("docker image `{rest}` has no tag/digest — defaults to `:latest`"),
        )
    }
}

fn is_sha40(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Heuristic: `main`, `master`, `develop`, `dev`, `trunk`, `latest`,
/// or any single-word name without a leading `v` and no dots. Used
/// only to make the message read better — severity is the same
/// either way.
fn looks_like_branch(reference: &str) -> bool {
    matches!(
        reference,
        "main" | "master" | "develop" | "dev" | "trunk" | "latest" | "HEAD"
    ) || (!reference.starts_with('v') && !reference.contains('.'))
}

fn owner_of(uses: &str) -> Option<&str> {
    let rest = uses.strip_prefix("docker://").unwrap_or(uses);
    let path = rest.split_once('@').map(|(p, _)| p).unwrap_or(rest);
    if path.starts_with('.') {
        return None;
    }
    path.split('/').next().filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_sha_pinned_third_party_is_ok() {
        let (sev, _) = classify("foo/bar@b4ffde65f46336ab88eb53be808477a3936bae11");
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn classify_third_party_v_tag_is_error() {
        let (sev, msg) = classify("foo/bar@v1");
        assert_eq!(sev, Severity::Error);
        assert!(msg.contains("third-party"));
        assert!(msg.contains("v1"));
        assert!(msg.contains("foo/bar@<sha>"));
    }

    #[test]
    fn classify_first_party_v_tag_is_warn_not_error() {
        // `actions/checkout@v4` is the canonical example. Risky but
        // not "fail the build" risky — first-party publish is
        // tightly controlled. Ratchet later if we want to be strict.
        let (sev, _) = classify("actions/checkout@v4");
        assert_eq!(sev, Severity::Warn);
        let (sev, _) = classify("github/codeql-action/init@v3");
        assert_eq!(sev, Severity::Warn);
    }

    #[test]
    fn classify_branch_ref_says_branch_in_message() {
        let (sev, msg) = classify("foo/bar@main");
        assert_eq!(sev, Severity::Error);
        assert!(msg.contains("branch"), "msg = {msg}");
    }

    #[test]
    fn classify_local_action_is_ok() {
        let (sev, _) = classify("./.github/actions/setup");
        assert_eq!(sev, Severity::Ok);
        let (sev, _) = classify("../shared/build");
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn classify_docker_with_digest_is_ok_else_warn() {
        let (sev, _) = classify(
            "docker://alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        assert_eq!(sev, Severity::Ok);
        let (sev, _) = classify("docker://alpine:3.19");
        assert_eq!(sev, Severity::Warn);
        let (sev, _) = classify("docker://alpine");
        assert_eq!(sev, Severity::Warn);
    }

    #[test]
    fn classify_missing_ref_is_warn_not_silent_pass() {
        // Without `@<ref>` GitHub Actions resolves to the default
        // branch — the most-mutable possible target. Don't silently
        // ignore this.
        let (sev, msg) = classify("foo/bar");
        assert_eq!(sev, Severity::Warn);
        assert!(msg.contains("no `@<ref>`"));
    }

    #[test]
    fn classify_sha_lowercase_only_uppercase_still_ok() {
        // GitHub stores SHAs lowercase but humans paste either case.
        let (sev, _) = classify("foo/bar@B4FFDE65F46336AB88EB53BE808477A3936BAE11");
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn classify_sha_too_short_is_treated_as_tag() {
        // Short SHAs are technically valid in git but Actions
        // resolves them via the API and they can become ambiguous;
        // treat as a tag for safety.
        let (sev, _) = classify("foo/bar@b4ffde6");
        assert_eq!(sev, Severity::Error);
    }

    #[test]
    fn audit_yaml_walks_jobs_and_steps_in_source_order() {
        let yaml = r#"
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: setup rust
        uses: dtolnay/rust-toolchain@stable
      - run: cargo test
      - uses: foo/bar@b4ffde65f46336ab88eb53be808477a3936bae11
  deploy:
    uses: org/repo/.github/workflows/release.yml@v1
"#;
        let f = audit_yaml(yaml).unwrap();
        // 3 step uses + 1 reusable workflow uses; the run-only step
        // is not listed.
        assert_eq!(f.len(), 4, "findings: {f:#?}");

        // Order: build's three steps first, then deploy.
        assert_eq!(f[0].uses, "actions/checkout@v4");
        assert_eq!(f[0].job, "build");
        assert_eq!(f[0].step, None); // no `name:` set
        assert_eq!(f[0].severity, Severity::Warn);

        assert_eq!(f[1].uses, "dtolnay/rust-toolchain@stable");
        assert_eq!(f[1].step.as_deref(), Some("setup rust"));
        assert_eq!(f[1].severity, Severity::Error);

        assert_eq!(f[2].severity, Severity::Ok);

        // Reusable workflow at job-level: step is None, severity
        // depends on third-party-ness.
        assert_eq!(f[3].job, "deploy");
        assert_eq!(f[3].step, None);
        assert_eq!(f[3].severity, Severity::Error);
    }

    #[test]
    fn audit_yaml_returns_empty_on_non_workflow_yaml() {
        // `action.yml` doesn't have a `jobs:` block — out of scope.
        let yaml = r#"
name: my action
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
"#;
        let f = audit_yaml(yaml).unwrap();
        assert!(
            f.is_empty(),
            "composite actions are out of scope for v1; got {f:#?}"
        );
    }

    #[test]
    fn summary_aggregates_severity_and_owners() {
        let yaml = r#"
on: [push]
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
      - uses: foo/bar@v1
      - uses: foo/baz@b4ffde65f46336ab88eb53be808477a3936bae11
"#;
        let f = audit_yaml(yaml).unwrap();
        let s = Summary::from_findings(&f);
        assert_eq!(s.total, 3);
        assert_eq!(s.ok, 1);
        assert_eq!(s.warn, 1);
        assert_eq!(s.error, 1);
        assert_eq!(s.by_owner.get("actions").copied(), Some(1));
        assert_eq!(s.by_owner.get("foo").copied(), Some(2));
    }

    #[test]
    fn is_blocking_only_for_error_severity() {
        let mk = |s: Severity| Finding {
            job: "j".into(),
            step: None,
            uses: "x".into(),
            severity: s,
            message: String::new(),
        };
        assert!(!mk(Severity::Ok).is_blocking());
        assert!(!mk(Severity::Warn).is_blocking());
        assert!(mk(Severity::Error).is_blocking());
    }
}
