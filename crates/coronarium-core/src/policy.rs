use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Audit,
    Block,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultDecision {
    Allow,
    /// Implicit default: if `default:` is omitted, everything not on the
    /// allow list is denied. Combine with `--mode audit` the first time
    /// you write a policy to see what *would* break before enforcing.
    #[default]
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub file: FilePolicy,
    #[serde(default)]
    pub process: ProcessPolicy,
    #[serde(default)]
    pub env: EnvPolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub default: DefaultDecision,
    #[serde(default)]
    pub allow: Vec<NetRule>,
    #[serde(default)]
    pub deny: Vec<NetRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetRule {
    /// Either a hostname, an IPv4/IPv6 literal, or a CIDR string.
    pub target: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilePolicy {
    #[serde(default)]
    pub default: DefaultDecision,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessPolicy {
    #[serde(default)]
    pub deny_exec: Vec<String>,
}

/// What to do with environment variables that match neither `allow`
/// nor `deny`. `pass` (default) is "supervisor only strips what `deny`
/// names"; `clear` flips it to allowlist semantics — anything not on
/// `allow` is removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvDefault {
    #[default]
    Pass,
    Clear,
}

/// Filter the environment block before exec'ing the child. Patterns
/// are matched against the env-var **name** and support a single `*`
/// wildcard per segment (e.g. `AWS_*`, `*_TOKEN`, `GITHUB_*_PATH`).
///
/// `deny` always wins over `allow`. With `default: pass` the supervisor
/// only strips `deny`-matched names; with `default: clear` it starts
/// from an empty env and keeps only `allow`-matched names (then still
/// honours `deny` on top, in case `allow` was broader).
///
/// Unlike eBPF-backed deny lists, this is genuine **prevention**: the
/// child never sees the value, because `Command::env_clear` happens
/// before `execve`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvPolicy {
    #[serde(default)]
    pub default: EnvDefault,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

impl EnvPolicy {
    /// True when the policy would change *something* about the child's
    /// env. `false` means the supervisor can safely skip the env_clear
    /// dance and inherit untouched.
    pub fn is_active(&self) -> bool {
        !matches!(self.default, EnvDefault::Pass) || !self.allow.is_empty() || !self.deny.is_empty()
    }

    /// Apply the policy to a parent environment, returning the
    /// `(kept, removed_keys)` pair. `removed_keys` is the set of names
    /// that *were* in the parent env but were stripped — useful for
    /// audit logging. Names matching nothing in either list are kept
    /// or dropped according to `default`.
    pub fn resolve<I, K, V>(&self, parent: I) -> (Vec<(String, String)>, Vec<String>)
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut kept = Vec::new();
        let mut removed = Vec::new();
        for (k, v) in parent {
            let name: String = k.into();
            let value: String = v.into();
            let denied = self.deny.iter().any(|p| glob_match(p, &name));
            let allowed = self.allow.iter().any(|p| glob_match(p, &name));
            let keep = if denied {
                false
            } else if allowed {
                true
            } else {
                matches!(self.default, EnvDefault::Pass)
            };
            if keep {
                kept.push((name, value));
            } else {
                removed.push(name);
            }
        }
        removed.sort();
        (kept, removed)
    }
}

/// Glob match on env-var names. Supports `*` (matches any run of
/// characters, including empty); literal otherwise. We intentionally
/// don't pull in the `glob` crate — names are ASCII-ish and the
/// patterns we care about (`AWS_*`, `*_TOKEN`, `GITHUB_*_PATH`) all
/// fit this minimal grammar.
fn glob_match(pattern: &str, name: &str) -> bool {
    // Fast path: no wildcard.
    if !pattern.contains('*') {
        return pattern == name;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut cursor = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !name[cursor..].starts_with(part) {
                return false;
            }
            cursor += part.len();
        } else if i == parts.len() - 1 {
            // Last literal segment must align with the end of the name.
            if !name[cursor..].ends_with(part) {
                return false;
            }
            // And it has to come *after* `cursor`.
            if name.len() < cursor + part.len() {
                return false;
            }
        } else {
            match name[cursor..].find(part) {
                Some(pos) => cursor += pos + part.len(),
                None => return false,
            }
        }
    }
    true
}

impl Policy {
    pub fn from_file(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        let policy: Policy = match ext {
            "yaml" | "yml" => serde_yaml::from_slice(&bytes)?,
            "json" => serde_json::from_slice(&bytes)?,
            other => bail!("unsupported policy extension: {other:?}"),
        };
        Ok(policy)
    }

    /// Policy used when no `--policy` argument is passed: audit everything,
    /// deny nothing. Handy for "what would this job do?" dry-runs.
    pub fn permissive_audit() -> Self {
        Self {
            mode: Mode::Audit,
            network: NetworkPolicy {
                default: DefaultDecision::Allow,
                ..Default::default()
            },
            file: FilePolicy {
                default: DefaultDecision::Allow,
                ..Default::default()
            },
            process: ProcessPolicy::default(),
            env: EnvPolicy::default(),
        }
    }

    /// Spot obviously-redundant policy shapes. Kept small on purpose —
    /// prefer clear docs over implicit behaviour.
    ///
    /// `default: deny + deny: [...]` is only redundant when there are
    /// no `allow` entries: with an allow overlay, deny is what
    /// re-blocks sensitive subtrees of an otherwise-allowed parent
    /// (e.g. `allow: [/etc/]` + `deny: [/etc/shadow]`).
    pub fn lint(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.network.deny.is_empty()
            && matches!(self.network.default, DefaultDecision::Deny)
            && self.network.allow.is_empty()
        {
            out.push(
                "network.deny is non-empty but network.default is already 'deny' \
                 with no allow overlay — the deny list is redundant."
                    .to_string(),
            );
        }
        if !self.file.deny.is_empty()
            && matches!(self.file.default, DefaultDecision::Deny)
            && self.file.allow.is_empty()
        {
            out.push(
                "file.deny is non-empty but file.default is already 'deny' \
                 with no allow overlay — the deny list is redundant."
                    .to_string(),
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_deny_everywhere() {
        let p: Policy = serde_yaml::from_str("{}").unwrap();
        assert_eq!(p.mode, Mode::Audit);
        assert_eq!(p.network.default, DefaultDecision::Deny);
        assert_eq!(p.file.default, DefaultDecision::Deny);
        assert!(p.network.allow.is_empty());
        assert!(p.file.deny.is_empty());
        assert!(p.process.deny_exec.is_empty());
        assert_eq!(p.env.default, EnvDefault::Pass);
        assert!(p.env.allow.is_empty());
        assert!(p.env.deny.is_empty());
        assert!(!p.env.is_active());
    }

    #[test]
    fn env_glob_match_basics() {
        assert!(glob_match("PATH", "PATH"));
        assert!(!glob_match("PATH", "PATHX"));
        assert!(glob_match("AWS_*", "AWS_SECRET_ACCESS_KEY"));
        assert!(glob_match("AWS_*", "AWS_"));
        assert!(!glob_match("AWS_*", "AW"));
        assert!(glob_match("*_TOKEN", "NPM_TOKEN"));
        assert!(glob_match("*_TOKEN", "_TOKEN"));
        assert!(!glob_match("*_TOKEN", "TOKEN"));
        assert!(glob_match("GITHUB_*_PATH", "GITHUB_STEP_PATH"));
        assert!(glob_match("GITHUB_*_PATH", "GITHUB__PATH"));
        assert!(!glob_match("GITHUB_*_PATH", "GITHUB_STEP"));
        assert!(glob_match("*", "ANYTHING"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn env_resolve_default_pass_strips_only_deny() {
        let p = EnvPolicy {
            default: EnvDefault::Pass,
            allow: vec![],
            deny: vec!["*_TOKEN".into(), "AWS_*".into()],
        };
        let parent = [
            ("PATH", "/usr/bin"),
            ("HOME", "/root"),
            ("NPM_TOKEN", "abc"),
            ("AWS_SECRET_ACCESS_KEY", "xyz"),
        ];
        let (kept, removed) = p.resolve(parent);
        let names: Vec<_> = kept.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"PATH"));
        assert!(names.contains(&"HOME"));
        assert!(!names.contains(&"NPM_TOKEN"));
        assert!(!names.contains(&"AWS_SECRET_ACCESS_KEY"));
        assert_eq!(removed, vec!["AWS_SECRET_ACCESS_KEY", "NPM_TOKEN"]);
    }

    #[test]
    fn env_resolve_default_clear_keeps_only_allow() {
        let p = EnvPolicy {
            default: EnvDefault::Clear,
            allow: vec!["PATH".into(), "HOME".into(), "GITHUB_*".into()],
            deny: vec![],
        };
        let parent = [
            ("PATH", "/usr/bin"),
            ("HOME", "/root"),
            ("GITHUB_TOKEN", "ghp"),
            ("GITHUB_STEP_SUMMARY", "/tmp/x"),
            ("AWS_SECRET_ACCESS_KEY", "xyz"),
            ("RANDOM", "1"),
        ];
        let (kept, removed) = p.resolve(parent);
        let names: Vec<_> = kept.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"PATH"));
        assert!(names.contains(&"HOME"));
        assert!(names.contains(&"GITHUB_TOKEN"));
        assert!(names.contains(&"GITHUB_STEP_SUMMARY"));
        assert!(!names.contains(&"AWS_SECRET_ACCESS_KEY"));
        assert!(!names.contains(&"RANDOM"));
        assert!(removed.contains(&"AWS_SECRET_ACCESS_KEY".to_string()));
        assert!(removed.contains(&"RANDOM".to_string()));
    }

    #[test]
    fn env_resolve_deny_wins_over_allow() {
        let p = EnvPolicy {
            default: EnvDefault::Clear,
            allow: vec!["GITHUB_*".into()],
            deny: vec!["GITHUB_TOKEN".into()],
        };
        let parent = [("GITHUB_TOKEN", "ghp"), ("GITHUB_STEP_SUMMARY", "/tmp")];
        let (kept, removed) = p.resolve(parent);
        let names: Vec<_> = kept.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!names.contains(&"GITHUB_TOKEN"));
        assert!(names.contains(&"GITHUB_STEP_SUMMARY"));
        assert_eq!(removed, vec!["GITHUB_TOKEN"]);
    }

    #[test]
    fn env_is_active_only_when_configured() {
        assert!(!EnvPolicy::default().is_active());
        assert!(
            EnvPolicy {
                default: EnvDefault::Clear,
                ..Default::default()
            }
            .is_active()
        );
        assert!(
            EnvPolicy {
                deny: vec!["X".into()],
                ..Default::default()
            }
            .is_active()
        );
    }

    #[test]
    fn parses_yaml_env_section() {
        let y = r#"
env:
  default: clear
  allow: [PATH, HOME, "GITHUB_*"]
  deny: ["*_TOKEN", "AWS_*"]
"#;
        let p: Policy = serde_yaml::from_str(y).unwrap();
        assert_eq!(p.env.default, EnvDefault::Clear);
        assert_eq!(p.env.allow, vec!["PATH", "HOME", "GITHUB_*"]);
        assert_eq!(p.env.deny, vec!["*_TOKEN", "AWS_*"]);
    }

    #[test]
    fn parses_yaml_with_all_sections() {
        let y = r#"
mode: block
network:
  default: deny
  allow:
    - target: api.github.com
      ports: [443]
file:
  default: allow
  deny:
    - /etc/shadow
process:
  deny_exec:
    - /usr/bin/nc
"#;
        let p: Policy = serde_yaml::from_str(y).unwrap();
        assert_eq!(p.mode, Mode::Block);
        assert_eq!(p.network.default, DefaultDecision::Deny);
        assert_eq!(p.network.allow.len(), 1);
        assert_eq!(p.network.allow[0].target, "api.github.com");
        assert_eq!(p.network.allow[0].ports, vec![443]);
        assert_eq!(p.file.default, DefaultDecision::Allow);
        assert_eq!(p.file.deny, vec!["/etc/shadow".to_string()]);
        assert_eq!(p.process.deny_exec, vec!["/usr/bin/nc".to_string()]);
    }

    #[test]
    fn parses_equivalent_json() {
        let j = r#"{"mode":"audit","network":{"default":"allow"}}"#;
        let p: Policy = serde_json::from_str(j).unwrap();
        assert_eq!(p.mode, Mode::Audit);
        assert_eq!(p.network.default, DefaultDecision::Allow);
    }

    #[test]
    fn ports_default_to_empty_list() {
        let y = r#"
network:
  allow:
    - target: 1.2.3.4
"#;
        let p: Policy = serde_yaml::from_str(y).unwrap();
        assert_eq!(p.network.allow[0].target, "1.2.3.4");
        assert!(p.network.allow[0].ports.is_empty());
    }

    #[test]
    fn from_file_yaml_and_json() {
        let d = tempdir("policy-from-file");
        let yml = d.join("a.yml");
        std::fs::write(&yml, "mode: block\n").unwrap();
        let js = d.join("a.json");
        std::fs::write(&js, r#"{"mode":"block"}"#).unwrap();
        assert_eq!(Policy::from_file(&yml).unwrap().mode, Mode::Block);
        assert_eq!(Policy::from_file(&js).unwrap().mode, Mode::Block);
    }

    #[test]
    fn unsupported_extension_errors() {
        let d = tempdir("policy-bad-ext");
        let bad = d.join("x.toml");
        std::fs::write(&bad, "mode = 'block'").unwrap();
        assert!(Policy::from_file(&bad).is_err());
    }

    #[test]
    fn permissive_audit_is_allow_everywhere_audit_mode() {
        let p = Policy::permissive_audit();
        assert_eq!(p.mode, Mode::Audit);
        assert_eq!(p.network.default, DefaultDecision::Allow);
        assert_eq!(p.file.default, DefaultDecision::Allow);
    }

    #[test]
    fn lint_flags_redundant_deny_lists() {
        let mut p = Policy::permissive_audit();
        p.network.default = DefaultDecision::Deny;
        p.network.deny.push(NetRule {
            target: "x".into(),
            ports: vec![],
        });
        p.file.default = DefaultDecision::Deny;
        p.file.deny.push("/etc".into());
        let msgs = p.lint();
        assert!(msgs.iter().any(|m| m.contains("network.deny")));
        assert!(msgs.iter().any(|m| m.contains("file.deny")));
    }

    #[test]
    fn lint_does_not_flag_deny_when_allow_overlay_present() {
        // default-deny with an allow overlay: deny rules carve sensitive
        // subtrees out of an otherwise-allowed parent. Not redundant.
        let mut p = Policy::permissive_audit();
        p.network.default = DefaultDecision::Deny;
        p.network.allow.push(NetRule {
            target: "github.com".into(),
            ports: vec![443],
        });
        p.network.deny.push(NetRule {
            target: "x".into(),
            ports: vec![],
        });
        p.file.default = DefaultDecision::Deny;
        p.file.allow.push("/etc/".into());
        p.file.deny.push("/etc/shadow".into());
        let msgs = p.lint();
        assert!(
            !msgs.iter().any(|m| m.contains("network.deny")),
            "got: {msgs:?}"
        );
        assert!(
            !msgs.iter().any(|m| m.contains("file.deny")),
            "got: {msgs:?}"
        );
    }

    #[test]
    fn lint_clean_by_default() {
        assert!(Policy::permissive_audit().lint().is_empty());
    }

    fn tempdir(tag: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("coronarium-{tag}-{id}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
