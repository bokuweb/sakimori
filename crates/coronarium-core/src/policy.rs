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
