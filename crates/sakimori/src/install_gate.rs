//! `install-gate` — wire the user's shell to route every package
//! manager install through `sakimori proxy`.
//!
//! The idea:
//!
//! 1. User runs `sakimori proxy start` once (or via launchd /
//!    systemd — see docs).
//! 2. User runs `sakimori install-gate install` once; we append a
//!    line to their shell rc that evals the output of
//!    `sakimori install-gate shellenv` at every new shell.
//! 3. `shellenv` exports `HTTPS_PROXY` / `HTTP_PROXY` pointing at
//!    the proxy, plus a couple of tool-specific shims (cargo,
//!    dotnet) for registries that don't honour those env vars.
//!
//! After that: `npm install`, `pip install`, `cargo add`,
//! `dotnet add package` — all traffic routes through the proxy,
//! so too-young versions are auto-fallback'd (crates.io/npm/pypi/
//! nuget registration) or fail-hard (tarballs / unhandled paths).
//!
//! This module is **pure** — it takes inputs, returns strings.
//! The subcommand wiring in `cli.rs` handles the IO.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// The sentinel marker we stamp on our append line so uninstall can
/// remove it deterministically without grepping loose substrings.
pub const RC_MARKER: &str = "# >>> sakimori install-gate >>>";
pub const RC_END: &str = "# <<< sakimori install-gate <<<";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    /// Windows PowerShell / PowerShell Core. Same rendered snippet
    /// for both — differences are only in rc-file location, which
    /// `default_rc_file` reports as the PowerShell Core path
    /// (Windows PowerShell users can pass `--rc` explicitly).
    PowerShell,
}

impl Shell {
    /// Return the eval-style line that belongs in the rc file.
    /// Zsh / bash: `eval "$(sakimori install-gate shellenv)"`.
    /// Fish uses its own syntax because `eval` behaves differently.
    /// PowerShell expands `$(…)` via `Invoke-Expression`.
    pub fn eval_line(self) -> &'static str {
        match self {
            Shell::Bash | Shell::Zsh => "eval \"$(sakimori install-gate shellenv)\"",
            Shell::Fish => "sakimori install-gate shellenv | source",
            Shell::PowerShell => {
                "sakimori install-gate shellenv --shell powershell | Out-String | Invoke-Expression"
            }
        }
    }

    /// Conventional rc file for each shell.
    ///
    /// For POSIX shells this is appended to `$HOME`; for PowerShell
    /// the path is the conventional `$PROFILE` location relative to
    /// the user profile on Windows (`Documents\PowerShell\Microsoft.PowerShell_profile.ps1`
    /// for PS 7+, also valid for PS 5.1 with a slightly different
    /// folder name — we pick the PS7 path; Windows PowerShell users
    /// can override with `--rc`).
    pub fn default_rc_file(self) -> &'static str {
        match self {
            Shell::Bash => ".bashrc",
            Shell::Zsh => ".zshrc",
            Shell::Fish => ".config/fish/config.fish",
            Shell::PowerShell => "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "bash" => Some(Shell::Bash),
            "zsh" => Some(Shell::Zsh),
            "fish" => Some(Shell::Fish),
            "powershell" | "pwsh" => Some(Shell::PowerShell),
            _ => None,
        }
    }
}

/// Render the snippet that `eval "$(sakimori install-gate shellenv)"`
/// pipes into the shell. The output is deterministic so integration
/// tests can snapshot it byte-for-byte.
pub fn render_shellenv(shell: Shell, listen: SocketAddr) -> String {
    let proxy_url = format!("http://{listen}");
    match shell {
        Shell::Bash | Shell::Zsh => render_sh(&proxy_url),
        Shell::Fish => render_fish(&proxy_url),
        Shell::PowerShell => render_powershell(&proxy_url),
    }
}

fn render_sh(proxy_url: &str) -> String {
    // A few notes on the shape of this snippet:
    //
    // * We set both `HTTPS_PROXY` and `https_proxy` — curl and some
    //   older tools only consult the lowercase form; python's
    //   requests consults uppercase; we pick both to avoid
    //   surprises.
    // * `NO_PROXY` stays empty — callers who need e.g. internal
    //   registries should set it after sourcing us.
    // * `CARGO_HTTP_CAINFO` points at our CA bundle so cargo (which
    //   uses libcurl) can verify the MITM certificates without the
    //   caller having to install the CA into the system trust
    //   store. Same trick for `PIP_CERT` and `NODE_EXTRA_CA_CERTS`.
    //   These files must exist — `install` prints a warning if the
    //   CA hasn't been generated yet.
    // * `REQUESTS_CA_BUNDLE` catches Python's `requests` and by
    //   transitivity `pip-tools`, `poetry`, `uv` that re-use it.
    //
    // If the user doesn't have the CA file yet the CAINFO lines
    // will reference a missing path — tools that don't use them
    // keep working, tools that do will error clearly, and
    // `sakimori proxy install-ca` is the documented fix.
    let ca_file = default_ca_cert_path_hint();
    format!(
        r#"# sakimori install-gate: shell environment (sh/bash/zsh)
export HTTPS_PROXY='{proxy}'
export HTTP_PROXY='{proxy}'
export https_proxy='{proxy}'
export http_proxy='{proxy}'
# Pinpoint the CA so tools that don't honour the system trust store
# still accept the proxy's leaf certs.
if [ -f '{ca}' ]; then
  export CARGO_HTTP_CAINFO='{ca}'
  export PIP_CERT='{ca}'
  export NODE_EXTRA_CA_CERTS='{ca}'
  export REQUESTS_CA_BUNDLE='{ca}'
  export SSL_CERT_FILE='{ca}'
fi
"#,
        proxy = proxy_url,
        ca = ca_file.display(),
    )
}

fn render_fish(proxy_url: &str) -> String {
    let ca_file = default_ca_cert_path_hint();
    format!(
        r#"# sakimori install-gate: shell environment (fish)
set -gx HTTPS_PROXY '{proxy}'
set -gx HTTP_PROXY '{proxy}'
set -gx https_proxy '{proxy}'
set -gx http_proxy '{proxy}'
if test -f '{ca}'
  set -gx CARGO_HTTP_CAINFO '{ca}'
  set -gx PIP_CERT '{ca}'
  set -gx NODE_EXTRA_CA_CERTS '{ca}'
  set -gx REQUESTS_CA_BUNDLE '{ca}'
  set -gx SSL_CERT_FILE '{ca}'
end
"#,
        proxy = proxy_url,
        ca = ca_file.display(),
    )
}

fn render_powershell(proxy_url: &str) -> String {
    // PowerShell equivalent of the sh snippet. A few notes:
    //
    // * `$env:FOO = 'bar'` is the PowerShell scope-current way of
    //   setting an environment variable; variables set this way are
    //   inherited by child processes launched from the same shell,
    //   which is what we want for `cargo` / `npm` / `dotnet`.
    // * Windows doesn't care about the lowercase `https_proxy` the
    //   way POSIX tools do, but we still set it because
    //   cross-platform libraries (e.g. Git, some Python tools) look
    //   for both forms regardless of OS.
    // * `[System.Environment]::SetEnvironmentVariable` with `'User'`
    //   scope would persist across shells, but install-gate's model
    //   is "process-local; user opts in per shell", so we stick to
    //   `$env:` (matching the POSIX `export` semantics).
    // * If the CA file is absent we silently skip the CAINFO/CERT
    //   assignments — tools that don't use them keep working, and
    //   `sakimori proxy install-ca` is the documented fix.
    let ca_file = default_ca_cert_path_hint();
    let ca_ps = ca_file.to_string_lossy().replace('\\', "\\\\");
    format!(
        r#"# sakimori install-gate: shell environment (PowerShell)
$env:HTTPS_PROXY = '{proxy}'
$env:HTTP_PROXY = '{proxy}'
$env:https_proxy = '{proxy}'
$env:http_proxy = '{proxy}'
$__sakimori_ca = '{ca}'
if (Test-Path -LiteralPath $__sakimori_ca) {{
    $env:CARGO_HTTP_CAINFO = $__sakimori_ca
    $env:PIP_CERT = $__sakimori_ca
    $env:NODE_EXTRA_CA_CERTS = $__sakimori_ca
    $env:REQUESTS_CA_BUNDLE = $__sakimori_ca
    $env:SSL_CERT_FILE = $__sakimori_ca
}}
Remove-Variable -Name __sakimori_ca -ErrorAction SilentlyContinue
"#,
        proxy = proxy_url,
        ca = ca_ps,
    )
}

/// Best-effort default CA path, matching what `sakimori proxy` uses.
/// We only need a *path* here — the file may or may not exist.
fn default_ca_cert_path_hint() -> PathBuf {
    // POSIX: XDG, then HOME.
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return PathBuf::from(xdg).join("sakimori").join("ca.pem");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config/sakimori/ca.pem");
    }
    // Windows: mirror `CaFiles::at_default_location` in
    // sakimori-proxy, which uses `%LOCALAPPDATA%\sakimori\ca.pem`
    // (via the `directories` crate's `config_local_dir`). We
    // reconstruct it here without pulling that dep in — the path
    // only matters as a *hint* the shell snippet renders literally.
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA")
        && !local_appdata.is_empty()
    {
        return PathBuf::from(local_appdata).join("sakimori").join("ca.pem");
    }
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        return PathBuf::from(userprofile)
            .join("AppData")
            .join("Local")
            .join("sakimori")
            .join("ca.pem");
    }
    PathBuf::from("sakimori-ca.pem")
}

/// Build the multi-line block we splice into a shell rc file. The
/// `RC_MARKER` / `RC_END` sentinels let `strip_block` reverse it.
pub fn build_rc_block(shell: Shell) -> String {
    format!(
        "{marker}\n{line}\n{end}\n",
        marker = RC_MARKER,
        line = shell.eval_line(),
        end = RC_END,
    )
}

/// Remove any previously-installed block from `contents`. Idempotent:
/// if no block is present, returns `contents` unchanged. If multiple
/// blocks are present (someone ran install twice manually) all are
/// removed.
pub fn strip_block(contents: &str) -> String {
    let mut out = String::with_capacity(contents.len());
    let mut inside = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed == RC_MARKER {
            inside = true;
            continue;
        }
        if trimmed == RC_END {
            inside = false;
            continue;
        }
        if !inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    // Preserve trailing newline behaviour: if the original ended
    // without `\n`, we still emit one after stripping — that's a
    // cosmetic win for most rc files.
    if !contents.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Whether the rc file already contains an (un-stripped) block.
pub fn has_block(contents: &str) -> bool {
    contents.contains(RC_MARKER)
}

/// Produce the new contents of the rc file after installing the
/// block. If a block is already present it is left untouched
/// (idempotent). Otherwise the block is appended, with a blank line
/// separator if `contents` doesn't already end with one.
pub fn install_block(contents: &str, shell: Shell) -> String {
    if has_block(contents) {
        return contents.to_string();
    }
    let mut out = contents.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() && !out.ends_with("\n\n") {
        out.push('\n');
    }
    out.push_str(&build_rc_block(shell));
    out
}

/// Best-effort shell detection for `install` when the user didn't
/// pass `--shell`.
///
/// - Unix-y: read `$SHELL` and match the basename.
/// - Windows: default to PowerShell since that's the interactive
///   shell the vast majority of developers use.
pub fn detect_shell_from_env() -> Shell {
    if cfg!(windows) {
        return Shell::PowerShell;
    }
    std::env::var("SHELL")
        .ok()
        .and_then(|s| {
            let name = Path::new(&s).file_name()?.to_string_lossy().to_string();
            Shell::from_name(&name)
        })
        .unwrap_or(Shell::Bash)
}

/// Resolve the rc file path for `shell` under `home`.
pub fn default_rc_path(home: &Path, shell: Shell) -> PathBuf {
    home.join(shell.default_rc_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listen() -> SocketAddr {
        "127.0.0.1:8910".parse().unwrap()
    }

    #[test]
    fn shellenv_sh_has_expected_exports() {
        let out = render_shellenv(Shell::Zsh, listen());
        assert!(out.contains("export HTTPS_PROXY='http://127.0.0.1:8910'"));
        assert!(out.contains("export https_proxy='http://127.0.0.1:8910'"));
        assert!(out.contains("export CARGO_HTTP_CAINFO="));
        assert!(out.contains("export NODE_EXTRA_CA_CERTS="));
        assert!(out.contains("if [ -f "));
    }

    #[test]
    fn shellenv_fish_uses_set_gx() {
        let out = render_shellenv(Shell::Fish, listen());
        assert!(out.contains("set -gx HTTPS_PROXY 'http://127.0.0.1:8910'"));
        assert!(out.contains("set -gx CARGO_HTTP_CAINFO"));
        assert!(out.contains("if test -f "));
        // No bash/sh syntax leaked in.
        assert!(!out.contains("export "));
        assert!(!out.contains("if [ -f "));
    }

    #[test]
    fn install_block_is_idempotent() {
        let base = "# existing .zshrc\nalias foo=bar\n";
        let once = install_block(base, Shell::Zsh);
        let twice = install_block(&once, Shell::Zsh);
        assert_eq!(once, twice, "install_block must be idempotent");
        assert!(once.contains(RC_MARKER));
        assert!(once.contains(RC_END));
        assert!(once.contains("eval \"$(sakimori install-gate shellenv)\""));
    }

    #[test]
    fn strip_block_removes_our_lines_only() {
        let original = "alias foo=bar\n# unrelated\nexport BAZ=1\n";
        let installed = install_block(original, Shell::Zsh);
        let stripped = strip_block(&installed);
        assert_eq!(stripped.trim_end(), original.trim_end());
    }

    #[test]
    fn strip_block_handles_missing_marker() {
        let s = "nothing to see here\n";
        assert_eq!(strip_block(s), s);
    }

    #[test]
    fn strip_block_removes_multiple_accidental_copies() {
        let mut s = install_block("", Shell::Bash);
        s.push_str(&build_rc_block(Shell::Bash));
        let stripped = strip_block(&s);
        assert!(!stripped.contains(RC_MARKER));
        assert!(!stripped.contains("eval \""));
    }

    #[test]
    fn install_block_appends_blank_line_separator() {
        // When the existing file ends with one newline, we insert
        // one more so there's a visible gap before our marker.
        let base = "existing\n";
        let out = install_block(base, Shell::Zsh);
        assert!(out.contains("existing\n\n# >>> sakimori"));
    }

    #[test]
    fn shellenv_powershell_uses_env_assignment() {
        let out = render_shellenv(Shell::PowerShell, listen());
        assert!(out.contains("$env:HTTPS_PROXY = 'http://127.0.0.1:8910'"));
        assert!(out.contains("$env:CARGO_HTTP_CAINFO = $__sakimori_ca"));
        // Guard with Test-Path not `if [ -f ]`.
        assert!(out.contains("Test-Path"));
        // No POSIX sh syntax leaked in.
        assert!(!out.contains("export "));
        assert!(!out.contains("set -gx"));
    }

    #[test]
    fn eval_line_differs_per_shell_family() {
        assert!(Shell::Bash.eval_line().starts_with("eval"));
        assert!(Shell::Zsh.eval_line().starts_with("eval"));
        assert!(Shell::Fish.eval_line().ends_with("| source"));
        assert!(Shell::PowerShell.eval_line().contains("Invoke-Expression"));
    }

    #[test]
    fn default_rc_file_is_standard() {
        assert_eq!(Shell::Bash.default_rc_file(), ".bashrc");
        assert_eq!(Shell::Zsh.default_rc_file(), ".zshrc");
        assert_eq!(Shell::Fish.default_rc_file(), ".config/fish/config.fish");
        assert_eq!(
            Shell::PowerShell.default_rc_file(),
            "Documents/PowerShell/Microsoft.PowerShell_profile.ps1"
        );
    }

    #[test]
    fn shell_from_name_recognises_common_shells() {
        assert_eq!(Shell::from_name("bash"), Some(Shell::Bash));
        assert_eq!(Shell::from_name("zsh"), Some(Shell::Zsh));
        assert_eq!(Shell::from_name("fish"), Some(Shell::Fish));
        assert_eq!(Shell::from_name("powershell"), Some(Shell::PowerShell));
        assert_eq!(Shell::from_name("pwsh"), Some(Shell::PowerShell));
        assert_eq!(Shell::from_name("tcsh"), None);
    }

    #[test]
    fn powershell_install_block_is_idempotent() {
        let base = "# my PowerShell profile\nSet-Alias ll Get-ChildItem\n";
        let once = install_block(base, Shell::PowerShell);
        let twice = install_block(&once, Shell::PowerShell);
        assert_eq!(once, twice);
        assert!(once.contains("Invoke-Expression"));
    }
}
