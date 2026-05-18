//! CODEOWNERS auditor — checks whether `.github/workflows/` (and the
//! wider `.github/` tree) is covered by an owner pattern.
//!
//! Motivation: the TanStack 2025 npm compromise was made possible by
//! a workflow change merged into the base repo. CODEOWNERS gating on
//! `.github/` would have forced a security-aware reviewer onto every
//! PR that touched workflow code, including the one that introduced
//! the dangerous `pull_request_target` pattern in the first place.
//!
//! GitHub looks for CODEOWNERS at three canonical paths (first hit
//! wins):
//! - `.github/CODEOWNERS`
//! - `CODEOWNERS`
//! - `docs/CODEOWNERS`
//!
//! Pattern syntax is gitignore-derived. We implement enough of it to
//! answer "would this pattern match `.github/workflows/foo.yml`?" —
//! `*` (single-segment wildcard), `**` (zero-or-more segments),
//! leading `/` (anchored to repo root), trailing `/` (directory).
//! Character classes (`[...]`) and `?` are out of scope; if a real
//! repo ever needs them we can grow the matcher.
//!
//! The check is **structural**: any rule with at least one owner
//! token (`@user`, `@org/team`, or an `<email>`) whose pattern
//! covers `.github/workflows/` is enough to satisfy the lint. We
//! don't try to validate that the owners actually exist or have
//! review authority — that's the GitHub server's job.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

/// One parsed line of a CODEOWNERS file.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Rule {
    pub pattern: String,
    /// Raw owner tokens (`@user`, `@org/team`, `user@example.com`).
    /// Empty means "explicitly unowned" — GitHub treats that as
    /// "no required reviewer", which for this lint counts as
    /// **not** owned.
    pub owners: Vec<String>,
    /// 1-indexed line number in the source file. Surfaced in
    /// findings so reviewers can jump straight to the rule.
    pub line_no: usize,
}

/// Where the CODEOWNERS file we used was found, plus the rules it
/// contained. `source = None` means none of the three canonical
/// locations existed.
#[derive(Debug, Clone, Serialize)]
pub struct CodeownersFile {
    pub source: Option<PathBuf>,
    pub rules: Vec<Rule>,
}

/// Result of auditing a repo root for `.github/`-coverage owners.
#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    /// The CODEOWNERS source we read (relative to the repo root if
    /// possible). `None` means no CODEOWNERS existed.
    pub source: Option<PathBuf>,
    /// First rule (in CODEOWNERS order) whose pattern covers
    /// `.github/workflows/foo.yml`. We surface the *first* rather
    /// than "last wins" because the lint question is "is there any
    /// owner gating at all" — order-of-precedence within the file
    /// matters only when you want to know who'll actually be
    /// requested as reviewer.
    pub workflows_rule: Option<Rule>,
    /// As above for `.github/dependabot.yml` — a file in `.github/`
    /// outside `workflows/`. Lets the report distinguish "covered
    /// because the rule was `.github/`" from "covered only because
    /// of a workflows-specific rule".
    pub github_rule: Option<Rule>,
}

impl Coverage {
    pub fn workflows_covered(&self) -> bool {
        self.workflows_rule.is_some()
    }
    pub fn github_covered(&self) -> bool {
        self.github_rule.is_some()
    }
}

/// Walk the three canonical CODEOWNERS locations under `root` in
/// GitHub's documented order and return the first one that exists.
/// Returns `Ok(CodeownersFile { source: None, rules: vec![] })` when
/// none are present — distinguishable from "exists but empty".
pub fn load(root: &Path) -> Result<CodeownersFile> {
    for rel in [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"] {
        let p = root.join(rel);
        if p.exists() {
            let text =
                std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
            return Ok(CodeownersFile {
                source: Some(PathBuf::from(rel)),
                rules: parse(&text),
            });
        }
    }
    Ok(CodeownersFile {
        source: None,
        rules: Vec::new(),
    })
}

/// Convenience wrapper: load + classify in one call. Pure I/O for the
/// load, pure compute for the classify — same `Coverage` shape either
/// way.
pub fn audit_repo(root: &Path) -> Result<Coverage> {
    let file = load(root)?;
    Ok(classify(&file))
}

/// Compute coverage from already-parsed rules — extracted so tests
/// can exercise the matching logic without touching the filesystem.
pub fn classify(file: &CodeownersFile) -> Coverage {
    let workflows_rule = first_owning_rule(&file.rules, ".github/workflows/example.yml");
    let github_rule = first_owning_rule(&file.rules, ".github/dependabot.yml");
    Coverage {
        source: file.source.clone(),
        workflows_rule,
        github_rule,
    }
}

fn first_owning_rule(rules: &[Rule], path: &str) -> Option<Rule> {
    rules
        .iter()
        .find(|r| !r.owners.is_empty() && pattern_matches(&r.pattern, path))
        .cloned()
}

/// Parse a CODEOWNERS file. Tolerant — invalid lines are silently
/// skipped rather than failing the audit, since GitHub itself is
/// lenient and we'd rather surface coverage gaps than punt on parsing.
pub fn parse(text: &str) -> Vec<Rule> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        // Strip inline comments. CODEOWNERS doesn't formally support
        // mid-line `#`, but GitHub's parser does — treat anything from
        // an unescaped `#` to EOL as comment.
        let no_comment = match raw.find('#') {
            Some(i) => &raw[..i],
            None => raw,
        };
        let trimmed = no_comment.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(pattern) = parts.next() else {
            continue;
        };
        let owners: Vec<String> = parts
            .filter(|s| is_owner_token(s))
            .map(String::from)
            .collect();
        out.push(Rule {
            pattern: pattern.to_string(),
            owners,
            line_no,
        });
    }
    out
}

fn is_owner_token(s: &str) -> bool {
    // `@user`, `@org/team`, or an email — anything else is junk we
    // shouldn't count as ownership.
    s.starts_with('@') || s.contains('@')
}

/// Does `pattern` match `path` under CODEOWNERS semantics?
///
/// Implemented features:
/// - leading `/` anchors to repo root; without it the pattern matches
///   anywhere in the tree.
/// - trailing `/` requires the matched name to be (or be under) a
///   directory of that name.
/// - `*` matches any run of non-`/` characters within one segment.
/// - `**` matches zero or more segments (including empty).
/// - bare `*` (no other segments) is treated as "everything", which
///   is how GitHub treats it.
///
/// Out of scope: `?`, `[abc]`, escape sequences. None of those appear
/// in any CODEOWNERS file we'd reasonably encounter for `.github/`
/// gating, and growing the matcher would just expand the surface
/// area without changing the lint's verdict.
pub fn pattern_matches(pattern: &str, path: &str) -> bool {
    let p = pattern.trim();
    if p.is_empty() {
        return false;
    }
    // Bare `*` — GitHub treats this as the catch-all "owns everything".
    if p == "*" {
        return true;
    }
    let dir_only = p.ends_with('/');
    let body = p.trim_end_matches('/');
    // gitignore semantics: a pattern is anchored to the repo root if
    // it contains a `/` anywhere except as a trailing directory
    // marker. So `.github/workflows/` is anchored even without a
    // leading `/`, but `workflows/` (single segment) floats.
    let anchored_leading = body.starts_with('/');
    let core = body.trim_start_matches('/');
    let anchored = anchored_leading || core.contains('/');
    let pat_segs: Vec<&str> = core.split('/').collect();
    let path_segs: Vec<&str> = path.split('/').collect();

    if anchored {
        match match_prefix(&pat_segs, &path_segs) {
            Some(consumed) => {
                if dir_only {
                    // Directory pattern: need at least one descendant
                    // segment in the path beyond what the pattern
                    // consumed.
                    consumed < path_segs.len()
                } else {
                    // File pattern: must consume the whole path
                    // exactly, OR match a prefix when the last pattern
                    // segment is `**` (zero-or-more under that prefix).
                    consumed == path_segs.len() || pat_segs.last() == Some(&"**")
                }
            }
            None => false,
        }
    } else {
        // Floating single-segment pattern: try every start offset.
        // `**` cannot appear in this branch in practice (would imply
        // a multi-segment pattern, which is anchored).
        for start in 0..path_segs.len() {
            if let Some(consumed) = match_prefix(&pat_segs, &path_segs[start..]) {
                let total = start + consumed;
                let ok = if dir_only {
                    total < path_segs.len()
                } else {
                    total == path_segs.len()
                };
                if ok {
                    return true;
                }
            }
        }
        false
    }
}

/// Try to match `pat` against the beginning of `path`. Returns the
/// number of *path* segments consumed on success, or `None` on
/// failure. `**` greedily consumes zero or more path segments.
fn match_prefix(pat: &[&str], path: &[&str]) -> Option<usize> {
    if pat.is_empty() {
        return Some(0);
    }
    if pat[0] == "**" {
        // Try the longest consumption first — slightly cheaper for
        // the common `prefix/**` case where we want to swallow the
        // rest. Either direction is correct.
        for take in (0..=path.len()).rev() {
            if let Some(rest) = match_prefix(&pat[1..], &path[take..]) {
                return Some(take + rest);
            }
        }
        return None;
    }
    if path.is_empty() {
        return None;
    }
    if !segment_matches(pat[0], path[0]) {
        return None;
    }
    match_prefix(&pat[1..], &path[1..]).map(|r| 1 + r)
}

/// Single-segment match with `*` glob support.
fn segment_matches(pat: &str, seg: &str) -> bool {
    if pat == "*" {
        return true;
    }
    if !pat.contains('*') {
        return pat == seg;
    }
    // Split on `*` and check the literal parts appear in order, with
    // anchors at the ends.
    let parts: Vec<&str> = pat.split('*').collect();
    let mut rest = seg;
    for (i, p) in parts.iter().enumerate() {
        if i == 0 {
            if !rest.starts_with(p) {
                return false;
            }
            rest = &rest[p.len()..];
        } else if i == parts.len() - 1 {
            if !rest.ends_with(p) {
                return false;
            }
        } else {
            let Some(idx) = rest.find(p) else {
                return false;
            };
            rest = &rest[idx + p.len()..];
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skips_comments_and_blanks() {
        let text = "\
# top comment

.github/ @org/security  # inline comment
*.rs @rustlang
";
        let rules = parse(text);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].pattern, ".github/");
        assert_eq!(rules[0].owners, vec!["@org/security".to_string()]);
        assert_eq!(rules[1].pattern, "*.rs");
        assert_eq!(rules[1].owners, vec!["@rustlang".to_string()]);
    }

    #[test]
    fn parse_recognises_email_owners() {
        let rules = parse("README.md security@example.com\n");
        assert_eq!(rules[0].owners, vec!["security@example.com".to_string()]);
    }

    #[test]
    fn parse_filters_garbage_owner_tokens() {
        // Tokens that aren't `@…` or an email are dropped — gives a
        // sharper "explicitly unowned" signal.
        let rules = parse("path foobar @real\n");
        assert_eq!(rules[0].owners, vec!["@real".to_string()]);
    }

    #[test]
    fn pattern_star_matches_anything() {
        assert!(pattern_matches("*", ".github/workflows/foo.yml"));
        assert!(pattern_matches("*", "src/main.rs"));
    }

    #[test]
    fn pattern_double_star_directory_covers_subtree() {
        assert!(pattern_matches(".github/**", ".github/workflows/foo.yml"));
        assert!(pattern_matches(".github/**", ".github/dependabot.yml"));
        // Doesn't match unrelated paths.
        assert!(!pattern_matches(".github/**", "src/main.rs"));
    }

    #[test]
    fn pattern_directory_trailing_slash_matches_subtree() {
        assert!(pattern_matches(".github/", ".github/workflows/foo.yml"));
        assert!(pattern_matches(
            ".github/workflows/",
            ".github/workflows/foo.yml"
        ));
        // Trailing-slash patterns require children — don't match the
        // bare directory name.
        assert!(!pattern_matches(".github/workflows/", ".github/workflows"));
    }

    #[test]
    fn pattern_anchored_vs_floating() {
        // Anchored: only matches from repo root.
        assert!(pattern_matches(
            "/.github/workflows/",
            ".github/workflows/x"
        ));
        // Floating single segment: matches anywhere.
        assert!(pattern_matches("workflows/", "deep/nested/workflows/x"));
        // Multi-segment unanchored is treated as anchored per
        // gitignore semantics — no match at depth.
        assert!(!pattern_matches(
            ".github/workflows/",
            "nested/.github/workflows/x"
        ));
    }

    #[test]
    fn pattern_specific_file_does_not_cover_siblings() {
        let p = ".github/workflows/release.yml";
        assert!(pattern_matches(p, ".github/workflows/release.yml"));
        assert!(!pattern_matches(p, ".github/workflows/ci.yml"));
    }

    #[test]
    fn pattern_wildcard_in_segment() {
        assert!(pattern_matches(
            ".github/workflows/*.yml",
            ".github/workflows/ci.yml"
        ));
        assert!(!pattern_matches(
            ".github/workflows/*.yml",
            ".github/workflows/sub/ci.yml"
        ));
    }

    #[test]
    fn classify_finds_workflows_owner() {
        let file = CodeownersFile {
            source: Some(PathBuf::from(".github/CODEOWNERS")),
            rules: parse(".github/ @org/security\n"),
        };
        let c = classify(&file);
        assert!(c.workflows_covered());
        assert!(c.github_covered());
        assert_eq!(
            c.workflows_rule.as_ref().unwrap().owners,
            vec!["@org/security".to_string()]
        );
    }

    #[test]
    fn classify_distinguishes_workflows_only_coverage() {
        let file = CodeownersFile {
            source: Some(PathBuf::from(".github/CODEOWNERS")),
            rules: parse(".github/workflows/ @ci-team\n"),
        };
        let c = classify(&file);
        assert!(c.workflows_covered());
        assert!(
            !c.github_covered(),
            "workflows-only rule must not also cover .github/dependabot.yml"
        );
    }

    #[test]
    fn classify_treats_unowned_rule_as_uncovered() {
        // An owner-less rule (`path` with no `@user`) is an explicit
        // "no required reviewer" — GitHub blocks the merge on it
        // only if branch protection is configured that way, and for
        // our lint we want to flag this as "not actually gated".
        let file = CodeownersFile {
            source: Some(PathBuf::from(".github/CODEOWNERS")),
            rules: parse(".github/\n"),
        };
        let c = classify(&file);
        assert!(!c.workflows_covered());
    }

    #[test]
    fn classify_returns_no_rule_when_codeowners_missing() {
        let file = CodeownersFile {
            source: None,
            rules: Vec::new(),
        };
        let c = classify(&file);
        assert!(!c.workflows_covered());
        assert!(!c.github_covered());
        assert!(c.source.is_none());
    }

    #[test]
    fn load_walks_three_canonical_locations_in_order() {
        let tmp = std::env::temp_dir().join(format!(
            "sakimori-codeowners-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(tmp.join(".github")).unwrap();
        std::fs::create_dir_all(tmp.join("docs")).unwrap();
        std::fs::write(tmp.join(".github/CODEOWNERS"), ".github/ @first\n").unwrap();
        std::fs::write(tmp.join("CODEOWNERS"), "* @second\n").unwrap();
        std::fs::write(tmp.join("docs/CODEOWNERS"), "* @third\n").unwrap();
        let f = load(&tmp).unwrap();
        assert_eq!(f.source.as_deref(), Some(Path::new(".github/CODEOWNERS")));
        assert_eq!(f.rules[0].owners, vec!["@first".to_string()]);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn load_falls_back_to_root_and_docs() {
        let tmp = std::env::temp_dir().join(format!(
            "sakimori-codeowners-fall-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(tmp.join("docs")).unwrap();
        std::fs::write(tmp.join("docs/CODEOWNERS"), "* @docs-team\n").unwrap();
        let f = load(&tmp).unwrap();
        assert_eq!(f.source.as_deref(), Some(Path::new("docs/CODEOWNERS")));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn load_returns_none_source_when_no_codeowners() {
        let tmp = std::env::temp_dir().join(format!(
            "sakimori-codeowners-none-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let f = load(&tmp).unwrap();
        assert!(f.source.is_none());
        assert!(f.rules.is_empty());
        std::fs::remove_dir_all(&tmp).ok();
    }

    // --- proptest: invariants on the parser + matcher -------------------

    use proptest::prelude::*;

    fn path_segment() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_.-]{0,8}"
    }

    fn repo_path() -> impl Strategy<Value = String> {
        proptest::collection::vec(path_segment(), 1..6).prop_map(|segs| segs.join("/"))
    }

    proptest! {
        /// `parse` must never panic on arbitrary input. Garbage lines
        /// are dropped — the parser is explicitly tolerant.
        #[test]
        fn parse_never_panics(text in ".{0,512}") {
            let _ = parse(&text);
        }

        /// `pattern_matches` must never panic on arbitrary inputs.
        /// (It's called from the audit path which sees both
        /// user-authored patterns and real paths.)
        #[test]
        fn pattern_matches_never_panics(
            pat in ".{0,64}",
            path in ".{0,64}",
        ) {
            let _ = pattern_matches(&pat, &path);
        }

        /// Bare `*` is the documented catch-all — must match every
        /// non-empty path.
        #[test]
        fn bare_star_matches_everything(path in repo_path()) {
            prop_assert!(pattern_matches("*", &path));
        }

        /// `.github/**` must cover every path under `.github/`.
        /// Hardcodes the rule sakimori's audit-repo command relies on.
        #[test]
        fn double_star_directory_covers_subtree(
            depth in 1usize..=4,
            tail in proptest::collection::vec(path_segment(), 1..4),
        ) {
            let _ = depth; // breadth is captured via `tail.len()`
            let path = format!(".github/{}", tail.join("/"));
            prop_assert!(pattern_matches(".github/**", &path));
        }

        /// A trailing-slash pattern must NOT match the bare directory
        /// name (only descendants). Regressing this would cause the
        /// audit to wrongly claim `.github/` covers itself with no
        /// children, which is gibberish.
        #[test]
        fn trailing_slash_excludes_bare_dir(dir in path_segment()) {
            let pat = format!("{dir}/");
            prop_assert!(!pattern_matches(&pat, &dir));
        }

        /// A literal anchored path must match itself and nothing else.
        #[test]
        fn literal_path_matches_self_only(
            base in repo_path(),
            other in repo_path(),
        ) {
            let pat = format!("/{base}");
            prop_assert!(pattern_matches(&pat, &base));
            if base != other {
                prop_assert!(!pattern_matches(&pat, &other));
            }
        }
    }
}
