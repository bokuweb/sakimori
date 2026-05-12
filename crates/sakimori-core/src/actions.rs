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
//! Tag→SHA resolution is opt-in via the [`Resolver`] trait
//! ([`GithubResolver`] uses the GitHub REST API). Without one, the
//! audit stays fully offline and just flags problems.
//!
//! Out of scope (intentionally): walking `action.yml` composite
//! action files; detecting `actions/*` published from a fork.

use std::collections::{BTreeMap, HashMap};

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
    /// Set when the caller passed a [`Resolver`] and the mutable
    /// `@<ref>` resolved to a 40-char commit SHA — gives the user
    /// the exact replacement they should pin to. Skipped for OK
    /// (already-pinned) findings, local actions, and lookup
    /// failures (those are surfaced via [`Self::resolve_error`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_sha: Option<String>,
    /// Reason the resolver couldn't produce a SHA. Only set when a
    /// resolver was wired in *and* it returned an error — silent
    /// skips (no resolver, OK finding, local action) leave both
    /// `resolved_sha` and `resolve_error` as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolve_error: Option<String>,
}

impl Finding {
    pub fn is_blocking(&self) -> bool {
        matches!(self.severity, Severity::Error)
    }

    /// Owner/repo extracted from `uses` if it's a `<owner>/<repo>...@<ref>`
    /// form. `None` for local (`./...`) and docker actions, and for
    /// any malformed input.
    fn owner_repo(&self) -> Option<(&str, &str)> {
        let trimmed = self.uses.trim();
        if trimmed.starts_with("./")
            || trimmed.starts_with("../")
            || trimmed.starts_with("docker://")
        {
            return None;
        }
        let path = trimmed.split_once('@').map(|(p, _)| p).unwrap_or(trimmed);
        let mut parts = path.splitn(3, '/');
        let owner = parts.next()?;
        let repo = parts.next()?;
        if owner.is_empty() || repo.is_empty() {
            return None;
        }
        Some((owner, repo))
    }

    /// `<ref>` from `uses` (everything after `@`), or `None` when no
    /// `@` is present.
    fn reference(&self) -> Option<&str> {
        self.uses.split_once('@').map(|(_, r)| r)
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
        resolved_sha: None,
        resolve_error: None,
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

// --- tag→SHA resolution ---------------------------------------------------

/// Resolves a (`owner`, `repo`, `<ref>`) triple to a 40-char commit
/// SHA. Trait so the audit core stays offline by default and so
/// tests can substitute a deterministic fake.
pub trait Resolver {
    /// Returns the resolved SHA on success. The contract is "the
    /// commit `<ref>` currently points at" — caller should treat
    /// `Ok` as "this SHA is what `@<ref>` would resolve to right
    /// now", which is exactly what the user should pin to.
    fn resolve(&self, owner: &str, repo: &str, reference: &str) -> Result<String>;
}

/// Walk findings and ask `resolver` to fill in a SHA for every
/// non-OK row that points at a `<owner>/<repo>@<ref>`. Rows
/// without a parseable owner/repo or already-pinned rows are left
/// alone. Lookups are cached per `(owner, repo, ref)` so a workflow
/// that uses `actions/checkout@v4` ten times only hits the API once.
///
/// Failures populate `Finding::resolve_error` rather than aborting
/// — one rate-limited or removed action shouldn't kill the whole
/// audit.
pub fn resolve_all(findings: &mut [Finding], resolver: &dyn Resolver) {
    let mut cache: HashMap<(String, String, String), Result<String, String>> = HashMap::new();
    for f in findings.iter_mut() {
        if matches!(f.severity, Severity::Ok) {
            continue;
        }
        let Some((owner, repo)) = f.owner_repo() else {
            continue;
        };
        let Some(reference) = f.reference() else {
            continue;
        };
        // Already a SHA → nothing to resolve.
        if is_sha40(reference) {
            continue;
        }
        let key = (owner.to_string(), repo.to_string(), reference.to_string());
        let entry = cache.entry(key).or_insert_with(|| {
            resolver
                .resolve(owner, repo, reference)
                .map_err(|e| format!("{e:#}"))
        });
        match entry {
            Ok(sha) => f.resolved_sha = Some(sha.clone()),
            Err(msg) => f.resolve_error = Some(msg.clone()),
        }
    }
}

/// `Resolver` backed by the GitHub REST API. Reads `GITHUB_TOKEN`
/// from the environment when present (raises the rate limit from
/// 60 req/hour unauthenticated to 5000 authenticated). Network
/// timeouts are hard-coded conservatively — the caller usually
/// audits a handful of unique refs, not a flood.
///
/// Endpoint: `GET /repos/{owner}/{repo}/commits/{ref}` returns a
/// commit object whose `.sha` we extract. This works for tags and
/// branches alike (GitHub resolves the ref through to the commit
/// for us; for an annotated tag the API peels the tag automatically).
pub struct GithubResolver {
    user_agent: String,
    token: Option<String>,
    timeout: std::time::Duration,
}

impl GithubResolver {
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self {
            user_agent: user_agent.into(),
            token: std::env::var("GITHUB_TOKEN").ok(),
            timeout: std::time::Duration::from_secs(15),
        }
    }

    pub fn with_token(mut self, token: Option<String>) -> Self {
        self.token = token;
        self
    }

    pub fn with_timeout(mut self, t: std::time::Duration) -> Self {
        self.timeout = t;
        self
    }
}

impl Resolver for GithubResolver {
    fn resolve(&self, owner: &str, repo: &str, reference: &str) -> Result<String> {
        // Percent-encode the ref since branches like `feature/x` contain `/`
        // and tags can technically include `+` etc. owner/repo are validated
        // upstream by the YAML parser; we still sanity-check shape here
        // because passing an empty segment to GitHub returns a misleading
        // 404.
        if owner.is_empty() || repo.is_empty() || reference.is_empty() {
            anyhow::bail!("empty owner/repo/ref");
        }
        let url = format!(
            "https://api.github.com/repos/{owner}/{repo}/commits/{}",
            url_encode_ref(reference)
        );
        let mut req = ureq::get(&url)
            .set("user-agent", &self.user_agent)
            .set("accept", "application/vnd.github+json")
            .timeout(self.timeout);
        if let Some(t) = &self.token {
            req = req.set("authorization", &format!("Bearer {t}"));
        }
        let resp = req.call().with_context(|| format!("GET {url}"))?;
        if resp.status() != 200 {
            anyhow::bail!("HTTP {} from {url}", resp.status());
        }
        let body: serde_json::Value = resp.into_json().context("parsing commit JSON")?;
        let sha = body
            .get("sha")
            .and_then(|v| v.as_str())
            .filter(|s| s.len() == 40)
            .ok_or_else(|| anyhow::anyhow!("`sha` field missing or not 40 chars"))?;
        Ok(sha.to_string())
    }
}

/// Tiny percent-encoder for the chars we actually see in tag/branch
/// names. Avoids pulling `urlencoding` for one call site.
fn url_encode_ref(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

// --- workflow-level lints -------------------------------------------------

/// A workflow-level finding — independent of any single `uses:` row.
/// Used for whole-file patterns like "this `pull_request_target`
/// workflow can also write to the Actions cache, which an untrusted
/// fork PR can abuse to poison a later trusted run" (the
/// TanStack 2025 npm supply-chain vector).
#[derive(Debug, Clone, Serialize)]
pub struct WorkflowFinding {
    /// Stable rule id so users can grep / suppress / link to docs.
    pub rule: &'static str,
    pub severity: Severity,
    pub message: String,
    /// Trigger names that put this workflow in scope (e.g.
    /// `pull_request_target`, `workflow_run`).
    pub triggers: Vec<String>,
    /// Steps that write to the Actions cache. Empty when the rule
    /// fires for a non-cache reason (none today; keep the door open).
    pub cache_writers: Vec<CacheWriter>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheWriter {
    pub job: String,
    pub step: Option<String>,
    pub uses: String,
    /// Human-readable reason this step is treated as a cache writer
    /// — e.g. "actions/cache writes on post-step", "setup-node with
    /// cache: pnpm".
    pub reason: String,
}

/// Triggers that grant the workflow base-repo cache write scope
/// reachable from an attacker-controlled fork PR. `pull_request`
/// from a fork is scoped to the PR's own ref and can't poison the
/// trusted scope, so it's deliberately not on this list.
const DANGEROUS_TRIGGERS: &[&str] = &["pull_request_target", "workflow_run"];

/// Audit a workflow YAML for whole-file lint rules. Today: the
/// `pull_request_target` + writable Actions cache pattern. Returns
/// an empty vec when nothing fires.
pub fn audit_workflow_yaml(yaml: &str) -> Result<Vec<WorkflowFinding>> {
    let doc: serde_yaml::Value = serde_yaml::from_str(yaml).context("parsing workflow YAML")?;
    // serde_yaml maps `on:` to the boolean `true` in YAML 1.1 mode
    // (the famous "Norway problem" cousin). Try both keys.
    let on = doc
        .get("on")
        .or_else(|| doc.get(serde_yaml::Value::Bool(true)));
    let Some(on) = on else {
        return Ok(Vec::new());
    };
    let triggers = collect_triggers(on);
    let dangerous: Vec<String> = triggers
        .iter()
        .filter(|t| DANGEROUS_TRIGGERS.contains(&t.as_str()))
        .cloned()
        .collect();
    if dangerous.is_empty() {
        return Ok(Vec::new());
    }

    let writers = collect_cache_writers(&doc);
    if writers.is_empty() {
        return Ok(Vec::new());
    }

    let trigger_list = dangerous.join(", ");
    let msg = format!(
        "workflow runs on `{trigger_list}` and writes to the Actions cache — an untrusted fork \
         PR can poison the cache that a later trusted workflow restores (TanStack-style npm \
         supply-chain compromise). Cache writes use a runner-internal token, so `permissions: \
         contents: read` does not block them. Split cache-writing steps into a separate \
         workflow that does not run on fork PRs, or gate this job behind \
         `if: github.event.pull_request.head.repo.full_name == github.repository`."
    );
    Ok(vec![WorkflowFinding {
        rule: "pull_request_target_with_cache_write",
        severity: Severity::Error,
        message: msg,
        triggers: dangerous,
        cache_writers: writers,
    }])
}

fn collect_triggers(on: &serde_yaml::Value) -> Vec<String> {
    match on {
        serde_yaml::Value::String(s) => vec![s.clone()],
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        serde_yaml::Value::Mapping(map) => map
            .iter()
            .filter_map(|(k, _)| k.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

fn collect_cache_writers(doc: &serde_yaml::Value) -> Vec<CacheWriter> {
    let mut out = Vec::new();
    let Some(jobs) = doc.get("jobs").and_then(|v| v.as_mapping()) else {
        return out;
    };
    for (job_id, job_val) in jobs {
        let job_id = job_id.as_str().unwrap_or("<non-string>").to_string();
        let Some(job_map) = job_val.as_mapping() else {
            continue;
        };
        let Some(steps) = job_map
            .get(serde_yaml::Value::String("steps".into()))
            .and_then(|v| v.as_sequence())
        else {
            continue;
        };
        for step in steps {
            let Some(step_map) = step.as_mapping() else {
                continue;
            };
            let Some(uses) = step_map
                .get(serde_yaml::Value::String("uses".into()))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let with = step_map
                .get(serde_yaml::Value::String("with".into()))
                .and_then(|v| v.as_mapping());
            let Some(reason) = classify_cache_writer(uses, with) else {
                continue;
            };
            let step_name = step_map
                .get(serde_yaml::Value::String("name".into()))
                .and_then(|v| v.as_str())
                .map(String::from);
            out.push(CacheWriter {
                job: job_id.clone(),
                step: step_name,
                uses: uses.to_string(),
                reason,
            });
        }
    }
    out
}

/// Decide whether a single step is a cache writer. Returns a short
/// human-readable reason on a hit, `None` otherwise.
///
/// The matcher strips `@<ref>` so versioning is irrelevant, and
/// lowercases owner/path comparison because GitHub treats them
/// case-insensitively. Sub-path actions (`actions/cache/save`) are
/// recognised by exact path prefix.
fn classify_cache_writer(uses: &str, with: Option<&serde_yaml::Mapping>) -> Option<String> {
    let path = uses.split_once('@').map(|(p, _)| p).unwrap_or(uses);
    let path_lc = path.to_ascii_lowercase();

    // Explicit cache actions. `actions/cache/restore` is read-only,
    // so deliberately not on this list.
    if path_lc == "actions/cache" {
        return Some("actions/cache writes via post-step on cache miss".into());
    }
    if path_lc == "actions/cache/save" {
        return Some("actions/cache/save writes the cache".into());
    }

    // setup-* actions that wire up caching when the user sets a
    // `with.cache:` input. setup-go enables caching by default
    // (input defaults to "true"), so the rule fires even without an
    // explicit `with.cache:` unless it's explicitly disabled.
    let setup_with_cache_input = matches!(
        path_lc.as_str(),
        "actions/setup-node"
            | "actions/setup-python"
            | "actions/setup-java"
            | "actions/setup-dotnet"
            | "actions/setup-ruby"
            | "ruby/setup-ruby"
    );
    if setup_with_cache_input {
        if let Some(cache_val) = with.and_then(|w| w.get(serde_yaml::Value::String("cache".into())))
            && !is_falsy(cache_val)
        {
            return Some(format!(
                "{path} with cache: {} enables Actions cache write",
                yaml_scalar_display(cache_val)
            ));
        }
        return None;
    }
    if path_lc == "actions/setup-go" {
        // Default-on; only NOT a writer if `with.cache: false`.
        let disabled = with
            .and_then(|w| w.get(serde_yaml::Value::String("cache".into())))
            .map(is_falsy)
            .unwrap_or(false);
        if !disabled {
            return Some("actions/setup-go caches by default (writes Actions cache)".into());
        }
        return None;
    }

    // Well-known third-party cache-providing actions.
    if path_lc == "swatinem/rust-cache" {
        return Some("Swatinem/rust-cache writes the cargo registry/target cache".into());
    }
    if path_lc == "mozilla-actions/sccache-action" {
        return Some("mozilla-actions/sccache-action backs sccache with the Actions cache".into());
    }
    if path_lc == "astral-sh/setup-uv" {
        // uv's setup action only writes cache when `enable-cache:
        // true` is set; default is off in current versions.
        let enabled = with
            .and_then(|w| w.get(serde_yaml::Value::String("enable-cache".into())))
            .map(|v| !is_falsy(v))
            .unwrap_or(false);
        if enabled {
            return Some("astral-sh/setup-uv with enable-cache: true writes the uv cache".into());
        }
        return None;
    }

    None
}

fn is_falsy(v: &serde_yaml::Value) -> bool {
    match v {
        serde_yaml::Value::Bool(false) => true,
        serde_yaml::Value::String(s) => {
            let l = s.to_ascii_lowercase();
            l == "false" || l == "no" || l == "off" || l.is_empty()
        }
        serde_yaml::Value::Null => true,
        _ => false,
    }
}

fn yaml_scalar_display(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        _ => "<non-scalar>".to_string(),
    }
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
            resolved_sha: None,
            resolve_error: None,
        };
        assert!(!mk(Severity::Ok).is_blocking());
        assert!(!mk(Severity::Warn).is_blocking());
        assert!(mk(Severity::Error).is_blocking());
    }

    /// Static-map resolver — every test that exercises `resolve_all`
    /// uses one to keep the assertions deterministic and offline.
    struct FakeResolver {
        map: std::collections::HashMap<(String, String, String), Result<String, String>>,
    }
    impl FakeResolver {
        fn new() -> Self {
            Self {
                map: std::collections::HashMap::new(),
            }
        }
        fn ok(mut self, owner: &str, repo: &str, r: &str, sha: &str) -> Self {
            self.map
                .insert((owner.into(), repo.into(), r.into()), Ok(sha.into()));
            self
        }
        fn err(mut self, owner: &str, repo: &str, r: &str, msg: &str) -> Self {
            self.map
                .insert((owner.into(), repo.into(), r.into()), Err(msg.into()));
            self
        }
    }
    impl Resolver for FakeResolver {
        fn resolve(&self, owner: &str, repo: &str, reference: &str) -> Result<String> {
            match self.map.get(&(owner.into(), repo.into(), reference.into())) {
                Some(Ok(s)) => Ok(s.clone()),
                Some(Err(e)) => anyhow::bail!("{e}"),
                None => anyhow::bail!("no fixture for {owner}/{repo}@{reference}"),
            }
        }
    }

    fn fake_finding(uses: &str) -> Finding {
        let (sev, msg) = classify(uses);
        Finding {
            job: "j".into(),
            step: None,
            uses: uses.into(),
            severity: sev,
            message: msg,
            resolved_sha: None,
            resolve_error: None,
        }
    }

    #[test]
    fn resolve_all_fills_sha_for_mutable_refs_and_skips_pinned_ones() {
        let sha40 = "b4ffde65f46336ab88eb53be808477a3936bae11";
        let mut findings = vec![
            fake_finding("actions/checkout@v4"),       // Warn → resolve
            fake_finding("foo/bar@main"),              // Error → resolve
            fake_finding(&format!("foo/baz@{sha40}")), // Ok → skip
            fake_finding("./local-action"),            // Ok local → skip
        ];
        let r = FakeResolver::new()
            .ok("actions", "checkout", "v4", sha40)
            .ok(
                "foo",
                "bar",
                "main",
                "0000000000000000000000000000000000000000",
            );
        resolve_all(&mut findings, &r);

        assert_eq!(findings[0].resolved_sha.as_deref(), Some(sha40));
        assert_eq!(findings[0].resolve_error, None);
        assert_eq!(
            findings[1].resolved_sha.as_deref(),
            Some("0000000000000000000000000000000000000000")
        );
        assert!(findings[2].resolved_sha.is_none()); // already pinned
        assert!(findings[3].resolved_sha.is_none()); // local action
    }

    #[test]
    fn resolve_all_caches_repeated_lookups() {
        // Two findings on the same (owner, repo, ref) should hit the
        // resolver exactly once. The fake doesn't count calls
        // directly, but if the cache is broken the second call
        // would error (the fixture only matches once if we use a
        // counting wrapper) — simpler check: drop the fixture and
        // observe both findings still get the same answer because
        // of cache, OR both fail with the same error.
        struct Counter {
            inner: FakeResolver,
            calls: std::cell::Cell<u32>,
        }
        impl Resolver for Counter {
            fn resolve(&self, o: &str, r: &str, x: &str) -> Result<String> {
                self.calls.set(self.calls.get() + 1);
                self.inner.resolve(o, r, x)
            }
        }
        let r = Counter {
            inner: FakeResolver::new().ok("a", "b", "v1", "1".repeat(40).as_str()),
            calls: std::cell::Cell::new(0),
        };
        let mut findings = vec![
            fake_finding("a/b@v1"),
            fake_finding("a/b@v1"),
            fake_finding("a/b@v1"),
        ];
        resolve_all(&mut findings, &r);
        assert_eq!(r.calls.get(), 1, "expected one cached resolve");
        for f in &findings {
            assert!(f.resolved_sha.is_some());
        }
    }

    #[test]
    fn resolve_all_records_error_per_finding_without_aborting() {
        let mut findings = vec![
            fake_finding("good/repo@v1"),
            fake_finding("rate/limited@v1"),
        ];
        let sha = "a".repeat(40);
        let r = FakeResolver::new().ok("good", "repo", "v1", &sha).err(
            "rate",
            "limited",
            "v1",
            "HTTP 403 from api.github.com",
        );
        resolve_all(&mut findings, &r);
        assert_eq!(findings[0].resolved_sha.as_deref(), Some(sha.as_str()));
        assert!(findings[0].resolve_error.is_none());
        assert!(findings[1].resolved_sha.is_none());
        let err = findings[1].resolve_error.as_deref().unwrap();
        assert!(err.contains("HTTP 403"), "{err}");
    }

    #[test]
    fn finding_owner_repo_extraction_handles_subpath_and_local() {
        let f = fake_finding("foo/bar/sub/path@v1");
        assert_eq!(f.owner_repo(), Some(("foo", "bar")));
        let f = fake_finding("./local");
        assert_eq!(f.owner_repo(), None);
        let f = fake_finding("docker://alpine:3");
        assert_eq!(f.owner_repo(), None);
    }

    // --- workflow-level lint tests ---------------------------------------

    #[test]
    fn workflow_lint_fires_on_pull_request_target_plus_actions_cache() {
        // The TanStack 2025 vector reduced to its essentials: a PR
        // workflow that uses pull_request_target and runs
        // actions/cache. Cache is restored & written under the base
        // repo scope from untrusted fork code → trusted release
        // workflow later restores the poisoned blob.
        let yaml = r#"
name: bundle-size
on:
  pull_request_target:
    branches: [main]
jobs:
  size:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v4
        with:
          path: ~/.local/share/pnpm/store
          key: Linux-pnpm-store-${{ hashFiles('**/pnpm-lock.yaml') }}
      - run: pnpm install
"#;
        let f = audit_workflow_yaml(yaml).unwrap();
        assert_eq!(f.len(), 1, "expected one workflow finding: {f:#?}");
        assert_eq!(f[0].rule, "pull_request_target_with_cache_write");
        assert_eq!(f[0].severity, Severity::Error);
        assert_eq!(f[0].triggers, vec!["pull_request_target".to_string()]);
        assert_eq!(f[0].cache_writers.len(), 1);
        assert_eq!(f[0].cache_writers[0].uses, "actions/cache@v4");
        assert!(f[0].message.contains("TanStack"), "{}", f[0].message);
    }

    #[test]
    fn workflow_lint_fires_for_setup_node_with_cache_input() {
        let yaml = r#"
on: [pull_request_target]
jobs:
  build:
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm
"#;
        let f = audit_workflow_yaml(yaml).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].cache_writers.len(), 1);
        assert!(
            f[0].cache_writers[0].reason.contains("cache: pnpm"),
            "{}",
            f[0].cache_writers[0].reason
        );
    }

    #[test]
    fn workflow_lint_fires_for_setup_go_default_on_cache() {
        // setup-go enables caching by default — no `with.cache:`
        // required to be dangerous.
        let yaml = r#"
on:
  pull_request_target: {}
jobs:
  build:
    steps:
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
"#;
        let f = audit_workflow_yaml(yaml).unwrap();
        assert_eq!(f.len(), 1, "expected setup-go default-on cache to fire");
        assert_eq!(f[0].cache_writers[0].uses, "actions/setup-go@v5");
    }

    #[test]
    fn workflow_lint_quiet_when_setup_go_disables_cache() {
        let yaml = r#"
on: [pull_request_target]
jobs:
  build:
    steps:
      - uses: actions/setup-go@v5
        with:
          cache: false
"#;
        let f = audit_workflow_yaml(yaml).unwrap();
        assert!(f.is_empty(), "expected no finding: {f:#?}");
    }

    #[test]
    fn workflow_lint_fires_for_swatinem_rust_cache() {
        let yaml = r#"
on: [pull_request_target]
jobs:
  build:
    steps:
      - uses: Swatinem/rust-cache@v2
"#;
        let f = audit_workflow_yaml(yaml).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].cache_writers[0].uses, "Swatinem/rust-cache@v2");
    }

    #[test]
    fn workflow_lint_owner_case_insensitive() {
        // Action paths are case-insensitive on GitHub — `SWATINEM`
        // should match the same as `Swatinem`.
        let yaml = r#"
on: [pull_request_target]
jobs:
  build:
    steps:
      - uses: SWATINEM/Rust-Cache@v2
"#;
        let f = audit_workflow_yaml(yaml).unwrap();
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn workflow_lint_fires_on_workflow_run_trigger() {
        let yaml = r#"
on:
  workflow_run:
    workflows: [ci]
    types: [completed]
jobs:
  publish:
    steps:
      - uses: actions/cache@v4
        with:
          path: ./target
          key: cache-key
"#;
        let f = audit_workflow_yaml(yaml).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].triggers, vec!["workflow_run".to_string()]);
    }

    #[test]
    fn workflow_lint_quiet_when_only_pull_request_trigger() {
        // `pull_request` from a fork runs scoped to the PR ref —
        // doesn't reach the trusted cache scope. Don't fire.
        let yaml = r#"
on: [pull_request]
jobs:
  build:
    steps:
      - uses: actions/cache@v4
        with: { path: ., key: k }
"#;
        let f = audit_workflow_yaml(yaml).unwrap();
        assert!(f.is_empty(), "expected no finding: {f:#?}");
    }

    #[test]
    fn workflow_lint_quiet_when_no_cache_writer_present() {
        let yaml = r#"
on: [pull_request_target]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache/restore@v4  # read-only, fine
        with: { path: ., key: k }
      - run: echo hello
"#;
        let f = audit_workflow_yaml(yaml).unwrap();
        assert!(f.is_empty(), "restore-only must not trip the rule: {f:#?}");
    }

    #[test]
    fn workflow_lint_quiet_when_setup_node_has_no_cache_input() {
        let yaml = r#"
on: [pull_request_target]
jobs:
  build:
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 20
"#;
        let f = audit_workflow_yaml(yaml).unwrap();
        assert!(f.is_empty());
    }

    #[test]
    fn workflow_lint_fires_for_actions_cache_save_subpath() {
        let yaml = r#"
on: [pull_request_target]
jobs:
  build:
    steps:
      - uses: actions/cache/save@v4
        with: { path: ., key: k }
"#;
        let f = audit_workflow_yaml(yaml).unwrap();
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn workflow_lint_handles_on_as_yaml_true_key() {
        // YAML 1.1 parsers (incl. serde_yaml) interpret bare `on:`
        // as the boolean `true`. The lint must still find it.
        let yaml = r#"
on:
  pull_request_target:
    branches: [main]
jobs:
  build:
    steps:
      - uses: actions/cache@v4
        with: { path: ., key: k }
"#;
        let f = audit_workflow_yaml(yaml).unwrap();
        assert_eq!(
            f.len(),
            1,
            "expected finding even when `on` parsed as bool key"
        );
    }

    #[test]
    fn workflow_lint_collects_multiple_writers_in_one_finding() {
        let yaml = r#"
on: [pull_request_target]
jobs:
  a:
    steps:
      - uses: actions/cache@v4
        with: { path: ., key: k1 }
  b:
    steps:
      - uses: Swatinem/rust-cache@v2
"#;
        let f = audit_workflow_yaml(yaml).unwrap();
        assert_eq!(f.len(), 1, "one finding aggregating all writers");
        assert_eq!(f[0].cache_writers.len(), 2);
        let jobs: Vec<&str> = f[0].cache_writers.iter().map(|w| w.job.as_str()).collect();
        assert!(jobs.contains(&"a") && jobs.contains(&"b"));
    }

    #[test]
    fn url_encode_ref_handles_slashes_and_pluses() {
        assert_eq!(url_encode_ref("v4"), "v4");
        assert_eq!(url_encode_ref("feature/x"), "feature%2Fx");
        assert_eq!(url_encode_ref("v1.0+build"), "v1.0%2Bbuild");
    }
}
