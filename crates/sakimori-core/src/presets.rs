//! Curated policy rule packs for known supply-chain attack patterns.
//!
//! Each preset returns a [`Policy`] populated with only the relevant
//! deny rules. The CLI subcommand `sakimori policy preset <name>`
//! renders one as a YAML block annotated with explanatory comments so
//! the operator can drop it into an existing policy file or use it
//! standalone.
//!
//! Presets are intentionally conservative: every rule is something
//! that should never legitimately fire during a `npm install` /
//! `cargo build` / `pip install`. False positives here are a strong
//! signal of compromise, not noise.
//!
//! Kernel cap reminder: `file.deny` is limited to 8 entries under
//! `mode: block` on Linux (see [`sakimori_common::FILE_DENY_MAX_ENTRIES`]).
//! The persistence preset exceeds that on purpose — the user picks the
//! 8 highest-value entries for their threat model and leaves the rest
//! for audit mode (which is uncapped).
//!
//! Out of scope here: workspace-relative paths (`.claude/setup.mjs`,
//! `.vscode/tasks.json`). The file matcher is absolute-prefix only, so
//! those belong to the IOC workspace scanner (roadmap item 18), not
//! `file.deny`.

use std::str::FromStr;

use anyhow::{Result, anyhow};

use crate::policy::{
    DefaultDecision, EnvPolicy, FilePolicy, Mode, NetRule, NetworkPolicy, Policy, ProcessPolicy,
};

/// One of the curated rule packs. See module docs for the design
/// philosophy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// File-write tripwire for OS-level persistence locations
    /// (launchd / systemd / cron / shell-rc / ~/.ssh).
    Persistence,
    /// Network-egress tripwire for cloud metadata services and
    /// secret-bearing endpoints (AWS / GCP / Azure IMDS + STS).
    CloudSecretEgress,
}

impl Preset {
    /// Canonical CLI name (kebab-case).
    pub fn name(&self) -> &'static str {
        match self {
            Preset::Persistence => "persistence",
            Preset::CloudSecretEgress => "cloud-secret-egress",
        }
    }

    /// All preset names, for `--help` discovery.
    pub fn all() -> &'static [Preset] {
        &[Preset::Persistence, Preset::CloudSecretEgress]
    }

    /// One-line description shown above the YAML block.
    pub fn description(&self) -> &'static str {
        match self {
            Preset::Persistence => {
                "Tripwire for OS-level persistence writes — launchd / systemd / cron / \
                 shell-rc / ~/.ssh. Any package-manager subtree touching these is a strong \
                 signal of a worm-style supply-chain compromise (Shai-Hulud class)."
            }
            Preset::CloudSecretEgress => {
                "Tripwire for cloud-credential exfiltration — AWS / GCP / Azure metadata \
                 services and STS-style secret endpoints. Pairs with the proxy's SNI \
                 filter (v0.33+) so a CDN-rotated IP can't slip past the IP-only rules."
            }
        }
    }
}

impl FromStr for Preset {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "persistence" => Ok(Preset::Persistence),
            "cloud-secret-egress" => Ok(Preset::CloudSecretEgress),
            other => Err(anyhow!(
                "unknown preset `{other}` (known: persistence, cloud-secret-egress)"
            )),
        }
    }
}

/// Inputs for rendering a preset. `home` is consulted by
/// [`Preset::Persistence`] to expand `~/.ssh` etc. into absolute paths
/// the file matcher understands.
#[derive(Debug, Clone, Default)]
pub struct PresetCtx {
    /// Home directory to expand into. When `None`, the per-user entries
    /// are omitted from the rendered policy and a comment notes that
    /// the operator should add them by hand.
    pub home: Option<String>,
}

/// Build the [`Policy`] for the requested preset.
pub fn build(preset: Preset, ctx: &PresetCtx) -> Policy {
    let mut policy = Policy {
        mode: Mode::Block,
        network: NetworkPolicy {
            default: DefaultDecision::Allow,
            allow: Vec::new(),
            deny: Vec::new(),
        },
        file: FilePolicy {
            default: DefaultDecision::Allow,
            allow: Vec::new(),
            deny: Vec::new(),
        },
        process: ProcessPolicy::default(),
        env: EnvPolicy::default(),
    };
    match preset {
        Preset::Persistence => {
            policy.file.deny = persistence_paths(ctx.home.as_deref());
        }
        Preset::CloudSecretEgress => {
            policy.network.deny = cloud_secret_egress_rules();
        }
    }
    policy
}

/// Concrete file-prefix list for [`Preset::Persistence`]. Visible for
/// tests; the CLI goes through [`build`].
pub fn persistence_paths(home: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    // System-wide persistence (no $HOME needed).
    out.extend(
        [
            // macOS launchd
            "/Library/LaunchAgents/",
            "/Library/LaunchDaemons/",
            // Linux systemd (system scope)
            "/etc/systemd/system/",
            "/etc/init.d/",
            // Linux cron
            "/var/spool/cron/",
            "/etc/cron.d/",
            "/etc/cron.hourly/",
            "/etc/cron.daily/",
            "/etc/cron.weekly/",
            "/etc/cron.monthly/",
        ]
        .iter()
        .map(|s| (*s).to_string()),
    );

    if let Some(home) = home {
        let h = home.trim_end_matches('/');
        out.extend([
            // macOS per-user launchd
            format!("{h}/Library/LaunchAgents/"),
            format!("{h}/Library/LaunchDaemons/"),
            // Linux per-user systemd + autostart
            format!("{h}/.config/systemd/user/"),
            format!("{h}/.config/autostart/"),
            // SSH
            format!("{h}/.ssh/"),
            // Shell rc / profile — common worm injection targets.
            // Listed as exact files (no trailing slash) so the
            // matcher doesn't accidentally allow a directory.
            format!("{h}/.bashrc"),
            format!("{h}/.bash_profile"),
            format!("{h}/.bash_logout"),
            format!("{h}/.profile"),
            format!("{h}/.zshrc"),
            format!("{h}/.zprofile"),
            format!("{h}/.zshenv"),
        ]);
    }

    out
}

/// Concrete `network.deny` rules for [`Preset::CloudSecretEgress`].
/// Visible for tests; the CLI goes through [`build`].
pub fn cloud_secret_egress_rules() -> Vec<NetRule> {
    // No ports = match every port for the target. Belt-and-braces:
    // include the IMDS IP literal alongside the hostnames, since
    // cgroup-side enforcement sees an IP and the hostname-keyed rules
    // only fire after DNS resolution catches up.
    let target = |s: &str| NetRule {
        target: s.to_string(),
        ports: Vec::new(),
    };
    vec![
        // AWS / GCP / Azure share the link-local IMDS IP.
        target("169.254.169.254"),
        // GCP metadata (always resolves to 169.254.169.254 but the
        // hostname appears in user code).
        target("metadata.google.internal"),
        // Azure IMDS (same IP, different naming).
        target("metadata.azure.com"),
        // AWS STS — the "assume this role" endpoint.
        target("sts.amazonaws.com"),
    ]
}

/// Render a preset as a YAML block, prefixed with a comment header
/// explaining what it is and how to merge it.
pub fn format_yaml(preset: Preset, ctx: &PresetCtx) -> Result<String> {
    let policy = build(preset, ctx);
    let mut out = String::new();
    out.push_str(&format!(
        "# Generated by `sakimori policy preset {}`.\n# {}\n",
        preset.name(),
        preset.description(),
    ));
    match preset {
        Preset::Persistence => {
            if ctx.home.is_none() {
                out.push_str(
                    "# NOTE: --home was not supplied, so per-user paths \
                     (~/.ssh, shell rc) were omitted.\n#       Re-run with --home \
                     /path/to/home to include them.\n",
                );
            }
            out.push_str(
                "# Kernel-side block (Linux) caps file.deny at 8 entries — prune to your \
                 8 most critical\n# locations under `mode: block`, or keep the full list \
                 under `mode: audit` (uncapped).\n",
            );
        }
        Preset::CloudSecretEgress => {
            out.push_str(
                "# Pair with `sakimori proxy start --network-allow ...` for SNI-level \
                 enforcement;\n# the rules below are eBPF-cgroup enforced (Linux) and \
                 fire on IP/hostname resolution.\n",
            );
        }
    }
    out.push_str(&serde_yaml::to_string(&policy)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_name_round_trip() {
        for p in Preset::all() {
            assert_eq!(Preset::from_str(p.name()).unwrap(), *p);
        }
    }

    #[test]
    fn unknown_preset_errors() {
        assert!(Preset::from_str("nope").is_err());
    }

    #[test]
    fn persistence_without_home_keeps_only_system_paths() {
        let paths = persistence_paths(None);
        assert!(paths.iter().any(|p| p == "/Library/LaunchAgents/"));
        assert!(paths.iter().any(|p| p == "/etc/systemd/system/"));
        assert!(paths.iter().any(|p| p == "/etc/cron.d/"));
        assert!(
            !paths.iter().any(|p| p.contains(".ssh")),
            "no $HOME → no per-user entries"
        );
    }

    #[test]
    fn persistence_with_home_expands_user_paths() {
        let paths = persistence_paths(Some("/Users/alice"));
        assert!(paths.iter().any(|p| p == "/Users/alice/.ssh/"));
        assert!(paths.iter().any(|p| p == "/Users/alice/.zshrc"));
        assert!(
            paths
                .iter()
                .any(|p| p == "/Users/alice/Library/LaunchAgents/")
        );
        assert!(
            paths
                .iter()
                .any(|p| p == "/Users/alice/.config/systemd/user/")
        );
    }

    #[test]
    fn persistence_strips_trailing_slash_on_home() {
        let with = persistence_paths(Some("/home/bob/"));
        let without = persistence_paths(Some("/home/bob"));
        assert_eq!(with, without, "trailing slash on --home must not matter");
    }

    #[test]
    fn cloud_egress_includes_imds_ip_literal() {
        let rules = cloud_secret_egress_rules();
        assert!(rules.iter().any(|r| r.target == "169.254.169.254"));
        assert!(rules.iter().any(|r| r.target == "sts.amazonaws.com"));
        for r in &rules {
            assert!(
                r.ports.is_empty(),
                "every-port match for {} (was {:?})",
                r.target,
                r.ports
            );
        }
    }

    #[test]
    fn build_persistence_sets_file_deny_not_network() {
        let p = build(
            Preset::Persistence,
            &PresetCtx {
                home: Some("/h".into()),
            },
        );
        assert!(!p.file.deny.is_empty());
        assert!(p.network.deny.is_empty());
        assert_eq!(p.file.default, DefaultDecision::Allow);
        assert_eq!(p.mode, Mode::Block);
    }

    #[test]
    fn build_cloud_egress_sets_network_deny_not_file() {
        let p = build(Preset::CloudSecretEgress, &PresetCtx::default());
        assert!(!p.network.deny.is_empty());
        assert!(p.file.deny.is_empty());
        assert_eq!(p.network.default, DefaultDecision::Allow);
    }

    #[test]
    fn format_yaml_persistence_announces_missing_home() {
        let s = format_yaml(Preset::Persistence, &PresetCtx::default()).unwrap();
        assert!(s.contains("--home was not supplied"));
        assert!(s.contains("file:"));
        assert!(s.contains("/Library/LaunchAgents/"));
    }

    #[test]
    fn format_yaml_persistence_with_home_omits_warning() {
        let s = format_yaml(
            Preset::Persistence,
            &PresetCtx {
                home: Some("/Users/alice".into()),
            },
        )
        .unwrap();
        assert!(!s.contains("--home was not supplied"));
        assert!(s.contains("/Users/alice/.ssh/"));
    }

    #[test]
    fn format_yaml_cloud_egress_mentions_proxy_pairing() {
        let s = format_yaml(Preset::CloudSecretEgress, &PresetCtx::default()).unwrap();
        assert!(s.contains("--network-allow"));
        assert!(s.contains("169.254.169.254"));
    }

    #[test]
    fn format_yaml_round_trips_as_loadable_policy() {
        // What the CLI emits must parse back into a Policy via the
        // same loader real users hit (`Policy::from_file` indirectly).
        for preset in Preset::all() {
            let yaml = format_yaml(
                *preset,
                &PresetCtx {
                    home: Some("/h".into()),
                },
            )
            .unwrap();
            let parsed: Policy = serde_yaml::from_str(&yaml).expect("yaml parses as Policy");
            // Validate against a permissive mode so the file-deny cap
            // doesn't trip on the persistence preset (deliberately
            // exceeds 8 — see module docs).
            parsed
                .validate(Mode::Audit)
                .expect("rendered policy passes audit-mode validation");
        }
    }
}
