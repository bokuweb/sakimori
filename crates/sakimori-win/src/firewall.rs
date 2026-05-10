//! Windows Defender Firewall-based network block.
//!
//! How it works:
//! - At startup in `mode: block`, we resolve every `network.deny` rule
//!   to an IP address / CIDR and create a per-rule
//!   `New-NetFirewallRule … -Action Block -Program <child.exe>` via
//!   PowerShell. All created rules share the prefix `sakimori-<pid>`.
//! - When the [`FirewallGuard`] drops (RAII), we remove every rule with
//!   that prefix in one `Get-NetFirewallRule … | Remove-NetFirewallRule`
//!   call. Clean teardown even on panic / non-zero exit.
//!
//! Limitations (intentional — documented in README):
//! - `-Program` scopes by exe path, not PID. In a CI runner this is
//!   fine because the supervised command is the only instance running,
//!   but worth noting.
//! - Only `network.deny` rules get real enforcement. `default: deny`
//!   with `allow: [...]` (the "allowlist" pattern) can't be translated
//!   into Windows FW rules cleanly without disabling default-allow-
//!   outbound globally — we warn loudly and fall back to audit-only.
//! - IPv6 literals and CIDRs are supported; hostname resolution uses
//!   the OS resolver (`ToSocketAddrs`). DNS changes during the run are
//!   not re-resolved (same as the Linux side).

use std::{net::ToSocketAddrs, path::PathBuf, process::Command};

use anyhow::{Context, Result};
use sakimori_core::policy::{NetRule, NetworkPolicy};

/// Holds ownership of a set of firewall rules added for the supervised
/// child. Rules are removed when the guard drops.
pub struct FirewallGuard {
    rule_prefix: String,
    rule_count: u32,
}

impl FirewallGuard {
    pub fn rule_prefix(&self) -> &str {
        &self.rule_prefix
    }

    pub fn rule_count(&self) -> u32 {
        self.rule_count
    }

    /// Apply `network.deny` to Windows Defender Firewall, scoped to
    /// `child_exe`. Returns `Ok(None)` if there are no deny rules to
    /// apply (so the caller doesn't pay the PowerShell startup cost).
    pub fn apply(
        policy: &NetworkPolicy,
        child_exe: &str,
    ) -> Result<Option<Self>> {
        if policy.deny.is_empty() {
            return Ok(None);
        }

        let prefix = format!("sakimori-{}", std::process::id());
        let mut count = 0u32;

        for (i, rule) in policy.deny.iter().enumerate() {
            let targets = resolve_rule(rule);
            if targets.is_empty() {
                log::warn!(
                    "network.deny[{i}] target {:?} resolved to no addresses; skipping",
                    rule.target
                );
                continue;
            }
            // One FW rule per target; `-RemoteAddress` accepts a list, but
            // one-per-address makes logs easier to read.
            for (j, addr) in targets.iter().enumerate() {
                let name = format!("{prefix}-{i}-{j}");
                match add_block_rule(&name, child_exe, addr, &rule.ports) {
                    Ok(()) => count += 1,
                    Err(e) => log::warn!("failed to add FW rule {name}: {e:#}"),
                }
            }
        }

        log::info!("added {count} firewall block rule(s) with prefix {prefix}");
        Ok(Some(Self {
            rule_prefix: prefix,
            rule_count: count,
        }))
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        // Best-effort cleanup. If the process is being killed, rules
        // may linger — a subsequent run with the same PID would
        // collide on rule names, but `-ErrorAction SilentlyContinue`
        // in the removal script handles that.
        let script = format!(
            "Get-NetFirewallRule -DisplayName '{}*' -ErrorAction SilentlyContinue | \
             Remove-NetFirewallRule -ErrorAction SilentlyContinue",
            self.rule_prefix
        );
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .status();
    }
}

/// Public wrapper so the event-handling path can share the same
/// resolution logic for tagging denied connects.
pub fn resolve_rule_public(rule: &NetRule) -> Vec<String> {
    resolve_rule(rule)
}

/// Expand a single `NetRule` into a list of `remote-address` strings
/// acceptable to `New-NetFirewallRule`. Accepts bare IPs, CIDR blocks,
/// and hostnames (resolved via the OS resolver).
fn resolve_rule(rule: &NetRule) -> Vec<String> {
    // IP literal → as-is
    if rule.target.parse::<std::net::IpAddr>().is_ok() {
        return vec![rule.target.clone()];
    }
    // CIDR → expand; Windows FW takes CIDR notation directly.
    if rule.target.parse::<ipnet::IpNet>().is_ok() {
        return vec![rule.target.clone()];
    }
    // Hostname → resolve via OS.
    match format!("{}:0", rule.target).to_socket_addrs() {
        Ok(iter) => {
            let mut out: Vec<String> = iter.map(|a| a.ip().to_string()).collect();
            out.sort();
            out.dedup();
            out
        }
        Err(err) => {
            log::warn!("resolving {:?}: {err}", rule.target);
            vec![]
        }
    }
}

fn add_block_rule(
    name: &str,
    program: &str,
    remote_addr: &str,
    ports: &[u16],
) -> Result<()> {
    // Quote path in single quotes; PowerShell single-quoted strings
    // don't interpret `$` or escapes, which is what we want for paths
    // like `C:\Users\runneradmin\...`.
    let program_q = ps_single_quote(program);
    let addr_q = ps_single_quote(remote_addr);
    let name_q = ps_single_quote(name);

    let mut parts = vec![
        format!("New-NetFirewallRule"),
        format!("-DisplayName {name_q}"),
        format!("-Program {program_q}"),
        "-Direction Outbound".to_string(),
        "-Action Block".to_string(),
        format!("-RemoteAddress {addr_q}"),
        "-ErrorAction Stop".to_string(),
    ];
    if !ports.is_empty() {
        // RemotePort requires Protocol (TCP is a reasonable default; UDP
        // block needs a separate rule — roadmap).
        let ports_str: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        parts.push(format!("-RemotePort {}", ports_str.join(",")));
        parts.push("-Protocol TCP".to_string());
    }
    parts.push("| Out-Null".to_string());

    let script = parts.join(" ");
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .with_context(|| format!("spawning powershell for FW rule {name}"))?;

    if !output.status.success() {
        anyhow::bail!(
            "New-NetFirewallRule failed (exit {}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn ps_single_quote(s: &str) -> String {
    // PowerShell: literal single-quoted string; embed `'` as `''`.
    format!("'{}'", s.replace('\'', "''"))
}

/// Resolve a program name to an absolute path so `-Program` on the FW
/// rule matches what Windows actually execs. For basenames like
/// `whoami`, shell out to `where.exe`.
pub fn resolve_program(name: &str) -> PathBuf {
    let p = std::path::Path::new(name);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    if let Ok(output) = Command::new("where").arg(name).output() {
        if output.status.success() {
            if let Some(line) = String::from_utf8_lossy(&output.stdout).lines().next() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    return PathBuf::from(trimmed);
                }
            }
        }
    }
    p.to_path_buf()
}
