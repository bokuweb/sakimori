//! Install / uninstall the root CA into the OS trust store.
//!
//! Each OS has a different trust-store path and a different CLI. We
//! shell out to the native tool for two reasons:
//!
//! 1. We want the install to be auditable and reversible by the user
//!    with the same standard commands (`security delete-certificate`,
//!    etc.). Writing the keystore directly would make us harder to
//!    trust.
//! 2. macOS Keychain writes require `sudo` for the System keychain;
//!    rather than embed a sudo-prompting library, we print the exact
//!    command the user should run when they didn't launch us with
//!    privileges.

use std::process::Command;

use anyhow::{Context, Result};

use crate::ca::CaFiles;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// The CA is now trusted (or was already trusted).
    Installed,
    /// We identified the command but would need elevated privileges to
    /// run it. The caller should print `command_hint` to the user.
    NeedsPrivilege,
    /// This OS has no automated install path yet.
    Manual,
}

pub struct InstallResult {
    pub outcome: InstallOutcome,
    pub command_hint: String,
}

/// Attempt to install the CA into the current user's trust store.
/// On macOS we target the **System** keychain (rather than login) so
/// children of tools like cargo that talk to the system trust store
/// via the Security framework pick it up. Requires sudo; if the
/// process isn't privileged we return `NeedsPrivilege` with the
/// exact shell line the user should run.
pub fn install_ca(files: &CaFiles) -> Result<InstallResult> {
    #[cfg(target_os = "macos")]
    {
        return install_macos(files);
    }
    #[cfg(target_os = "linux")]
    {
        return install_linux(files);
    }
    #[cfg(target_os = "windows")]
    {
        return install_windows(files);
    }
    #[allow(unreachable_code)]
    {
        Ok(InstallResult {
            outcome: InstallOutcome::Manual,
            command_hint: crate::ca::trust_instructions(files),
        })
    }
}

pub fn uninstall_ca(files: &CaFiles) -> Result<InstallResult> {
    #[cfg(target_os = "macos")]
    {
        return uninstall_macos(files);
    }
    #[cfg(target_os = "linux")]
    {
        return uninstall_linux(files);
    }
    #[cfg(target_os = "windows")]
    {
        return uninstall_windows(files);
    }
    #[allow(unreachable_code)]
    {
        Ok(InstallResult {
            outcome: InstallOutcome::Manual,
            command_hint: "(manual uninstall — see README)".into(),
        })
    }
}

// ---------------- macOS ----------------

#[cfg(target_os = "macos")]
fn install_macos(files: &CaFiles) -> Result<InstallResult> {
    let cert = files.cert_pem.display().to_string();
    let cmd = format!(
        "sudo security add-trusted-cert -d -r trustRoot \
         -k /Library/Keychains/System.keychain {cert}"
    );
    // Only attempt the install directly if we're already root. Otherwise
    // return the hint — the user re-runs with sudo.
    if !is_root_unix() {
        return Ok(InstallResult {
            outcome: InstallOutcome::NeedsPrivilege,
            command_hint: cmd,
        });
    }
    let status = Command::new("security")
        .args([
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
        ])
        .arg(&files.cert_pem)
        .status()
        .context("spawning security(1)")?;
    if !status.success() {
        anyhow::bail!("`security add-trusted-cert` exited {status}");
    }
    Ok(InstallResult {
        outcome: InstallOutcome::Installed,
        command_hint: cmd,
    })
}

#[cfg(target_os = "macos")]
fn uninstall_macos(files: &CaFiles) -> Result<InstallResult> {
    let cert = files.cert_pem.display().to_string();
    let cmd = format!("sudo security remove-trusted-cert -d {cert}");
    if !is_root_unix() {
        return Ok(InstallResult {
            outcome: InstallOutcome::NeedsPrivilege,
            command_hint: cmd,
        });
    }
    // `security remove-trusted-cert` exits non-zero when the cert
    // wasn't trusted, which we treat as idempotent success.
    let _ = Command::new("security")
        .args(["remove-trusted-cert", "-d"])
        .arg(&files.cert_pem)
        .status();
    Ok(InstallResult {
        outcome: InstallOutcome::Installed,
        command_hint: cmd,
    })
}

// ---------------- Linux ----------------

#[cfg(target_os = "linux")]
fn install_linux(files: &CaFiles) -> Result<InstallResult> {
    let cert = files.cert_pem.display().to_string();
    let dest = "/usr/local/share/ca-certificates/sakimori-ca.crt";
    let cmd = format!("sudo cp {cert} {dest} && sudo update-ca-certificates");
    if !is_root_unix() {
        return Ok(InstallResult {
            outcome: InstallOutcome::NeedsPrivilege,
            command_hint: cmd,
        });
    }
    std::fs::copy(&files.cert_pem, dest).context("copying CA into /usr/local/share")?;
    let status = Command::new("update-ca-certificates").status();
    match status {
        Ok(s) if s.success() => Ok(InstallResult {
            outcome: InstallOutcome::Installed,
            command_hint: cmd,
        }),
        _ => Ok(InstallResult {
            outcome: InstallOutcome::Manual,
            command_hint: format!(
                "copied CA to {dest}, but `update-ca-certificates` is missing — \
                 run the refresh step manually (e.g. `trust extract-compat` on Fedora)."
            ),
        }),
    }
}

#[cfg(target_os = "linux")]
fn uninstall_linux(files: &CaFiles) -> Result<InstallResult> {
    let dest = "/usr/local/share/ca-certificates/sakimori-ca.crt";
    let cmd = format!("sudo rm {dest} && sudo update-ca-certificates --fresh");
    if !is_root_unix() {
        return Ok(InstallResult {
            outcome: InstallOutcome::NeedsPrivilege,
            command_hint: cmd,
        });
    }
    let _ = std::fs::remove_file(dest);
    let _ = Command::new("update-ca-certificates")
        .args(["--fresh"])
        .status();
    let _ = files; // silence unused if target has specific code
    Ok(InstallResult {
        outcome: InstallOutcome::Installed,
        command_hint: cmd,
    })
}

// ---------------- Windows ----------------

#[cfg(target_os = "windows")]
fn install_windows(files: &CaFiles) -> Result<InstallResult> {
    let cert = files.cert_pem.display().to_string();
    // Two-tier strategy:
    // 1. If we're already Administrator, run `Import-Certificate`
    //    directly — no UAC prompt, no extra process.
    // 2. Otherwise try `Start-Process -Verb RunAs` from a
    //    non-elevated PowerShell, which triggers the UAC prompt.
    //    We wait for the elevated child to exit and bubble up its
    //    status. The user sees exactly one UAC prompt and the CLI
    //    returns cleanly.
    //
    // If even that fails (no interactive session, policy-blocked
    // elevation, etc.) we fall through to returning the hint as a
    // copy-pasteable command, matching the macOS/Linux fallback.
    let direct_cmd = format!(
        "Import-Certificate -FilePath '{cert}' -CertStoreLocation Cert:\\LocalMachine\\Root"
    );
    if is_windows_admin() {
        let status = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &direct_cmd])
            .status()
            .context("spawning powershell.exe")?;
        if status.success() {
            return Ok(InstallResult {
                outcome: InstallOutcome::Installed,
                command_hint: direct_cmd,
            });
        }
        anyhow::bail!("Import-Certificate exited {status}");
    }
    // Non-admin path: fire off `Start-Process -Verb RunAs` which
    // prompts UAC. `-Wait` blocks until the elevated child exits.
    let elevated = format!(
        "Start-Process -Wait -Verb RunAs powershell.exe \
         -ArgumentList '-NoProfile','-Command','Import-Certificate -FilePath ''{cert}'' -CertStoreLocation Cert:\\LocalMachine\\Root'"
    );
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &elevated])
        .status();
    match status {
        Ok(s) if s.success() => Ok(InstallResult {
            outcome: InstallOutcome::Installed,
            command_hint: direct_cmd,
        }),
        _ => Ok(InstallResult {
            // Couldn't confirm — return the hint so the user can run
            // it by hand in an elevated shell.
            outcome: InstallOutcome::NeedsPrivilege,
            command_hint: direct_cmd,
        }),
    }
}

#[cfg(target_os = "windows")]
fn uninstall_windows(files: &CaFiles) -> Result<InstallResult> {
    // We identify our own cert by subject substring (`sakimori`
    // is unique enough) so we don't need to remember the thumbprint.
    let direct_cmd = "Get-ChildItem Cert:\\LocalMachine\\Root | \
                      Where-Object { $_.Subject -like '*sakimori*' } | \
                      Remove-Item"
        .to_string();
    let _ = files;
    if is_windows_admin() {
        let status = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &direct_cmd])
            .status()
            .context("spawning powershell.exe")?;
        // Non-zero is fine (nothing matched) — treat as idempotent.
        let _ = status;
        return Ok(InstallResult {
            outcome: InstallOutcome::Installed,
            command_hint: direct_cmd,
        });
    }
    let elevated = format!(
        "Start-Process -Wait -Verb RunAs powershell.exe \
         -ArgumentList '-NoProfile','-Command','{direct_cmd}'"
    );
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &elevated])
        .status();
    match status {
        Ok(s) if s.success() => Ok(InstallResult {
            outcome: InstallOutcome::Installed,
            command_hint: direct_cmd,
        }),
        _ => Ok(InstallResult {
            outcome: InstallOutcome::NeedsPrivilege,
            command_hint: direct_cmd,
        }),
    }
}

/// Very-best-effort admin check on Windows: run an `[Security.Principal…]`
/// one-liner and read the boolean. Heavier than the Unix USER==root
/// check, but still cheap enough to do unconditionally (single
/// short-lived powershell invocation).
#[cfg(target_os = "windows")]
fn is_windows_admin() -> bool {
    use std::process::Stdio;
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    match output {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            s.trim().eq_ignore_ascii_case("True")
        }
        Err(_) => false,
    }
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
fn is_windows_admin() -> bool {
    false
}

// ---------------- shared helpers ----------------

/// Whether we're running with the privileges needed to modify the
/// system trust store. Detection is cheap-and-cheerful:
///
/// - `$USER == "root"` (common for `sudo sakimori …`), or
/// - `$SUDO_UID` is set (set by sudo(8) when invoking non-interactively).
///
/// When unsure we return `false`, which is safe — the caller will
/// print the exact command hint instead of silently failing.
#[cfg(unix)]
fn is_root_unix() -> bool {
    std::env::var("USER").as_deref() == Ok("root") || std::env::var_os("SUDO_UID").is_some()
}

#[cfg(not(unix))]
fn is_root_unix() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn files() -> CaFiles {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        CaFiles::at(PathBuf::from(format!("/tmp/sakimori-install-{id}")))
    }

    #[test]
    fn install_emits_a_platform_specific_command_hint() {
        let f = files();
        let r = install_ca(&f).unwrap();
        assert!(
            !r.command_hint.is_empty(),
            "command_hint should not be empty"
        );
        // Platform-specific substrings — we know at least one will match.
        let hint = &r.command_hint;
        let recognised = hint.contains("security add-trusted-cert")
            || hint.contains("update-ca-certificates")
            || hint.contains("Import-Certificate");
        assert!(recognised, "unrecognised hint: {hint}");
    }

    #[test]
    fn uninstall_emits_a_platform_specific_command_hint() {
        let f = files();
        let r = uninstall_ca(&f).unwrap();
        assert!(!r.command_hint.is_empty());
        let hint = &r.command_hint;
        let recognised = hint.contains("remove-trusted-cert")
            || hint.contains("update-ca-certificates")
            || hint.contains("Remove-Item");
        assert!(recognised, "unrecognised hint: {hint}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_install_hint_uses_system_keychain() {
        let r = install_ca(&files()).unwrap();
        assert!(
            r.command_hint
                .contains("/Library/Keychains/System.keychain")
        );
        assert!(r.command_hint.contains("-r trustRoot"));
    }
}
