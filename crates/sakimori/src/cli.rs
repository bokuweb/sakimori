use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use sakimori_core::report::ReportArgs;
use std::time::Duration;

use crate::{loader, policy};

/// Resolve the CA directory either from the `--config-dir` override or
/// the default location. Centralised so every `proxy …` subcommand
/// uses the same layout.
fn ca_files_for(dir: Option<PathBuf>) -> anyhow::Result<sakimori_proxy::ca::CaFiles> {
    Ok(match dir {
        Some(d) => sakimori_proxy::ca::CaFiles::at(d.join("sakimori")),
        None => sakimori_proxy::ca::CaFiles::at_default_location()?,
    })
}

/// Build the proxy's egress allow-list from `--network-allow` flags
/// plus an optional file. Returns `None` (= "feature off") when no
/// patterns came from either source — `Some(empty)` would also work
/// but `None` lets the proxy skip the per-request check entirely.
fn build_network_allow(
    flags: &[String],
    file: &Option<PathBuf>,
) -> Result<Option<sakimori_proxy::host_allow::HostMatcher>> {
    let mut all: Vec<String> = flags.to_vec();
    if let Some(path) = file {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading --network-allow-file {}", path.display()))?;
        for line in text.lines() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if !trimmed.is_empty() {
                all.push(trimmed.to_string());
            }
        }
    }
    if all.is_empty() {
        return Ok(None);
    }
    let matcher = sakimori_proxy::host_allow::HostMatcher::from_patterns(all)
        .map_err(|(pat, e)| anyhow::anyhow!("--network-allow `{pat}`: {e}"))?;
    Ok(Some(matcher))
}

/// Parse a simple `<N><unit>` duration (e.g. `7d`, `12h`, `30m`, `3600s`).
/// Bare numbers default to days. Used by proxy/watch-style CLI flags
/// where pulling in humantime feels overkill.
fn parse_simple_duration(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty duration");
    }
    let (num, unit) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => (&s[..s.len() - 1], c),
        _ => (s, 'd'),
    };
    let n: u64 = num.parse()?;
    let secs = match unit {
        'd' | 'D' => n * 86400,
        'h' | 'H' => n * 3600,
        'm' | 'M' => n * 60,
        's' | 'S' => n,
        _ => anyhow::bail!("unknown duration unit {unit:?}"),
    };
    Ok(Duration::from_secs(secs))
}

#[derive(Debug, Parser)]
#[command(
    name = "sakimori",
    version,
    about = "eBPF-based audit & block for CI workloads"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Attach eBPF programs, run the given command under supervision, detach
    /// on exit.
    Run(RunArgs),
    /// Validate a policy file without attaching anything.
    CheckPolicy {
        #[arg(long, short = 'p')]
        policy: PathBuf,
    },
    /// Supply-chain hardening: fail if any package in the given lockfile(s)
    /// was published less than `--min-age` ago.
    Deps {
        #[command(subcommand)]
        cmd: DepsCommand,
    },
    /// Transparent HTTPS MITM proxy that enforces minimum-release-age
    /// at the registry fetch layer. Experimental — see CLAUDE.md.
    Proxy {
        #[command(subcommand)]
        cmd: ProxyCommand,
    },
    /// Route the user's shell through `sakimori proxy` so every
    /// `npm install` / `cargo add` / `pip install` / `dotnet add`
    /// goes through the minimum-release-age filter automatically.
    #[command(name = "install-gate")]
    InstallGate {
        #[command(subcommand)]
        cmd: InstallGateCommand,
    },
    /// One-command diagnostic: checks CA files, proxy liveness,
    /// $HTTPS_PROXY, rc-file block, and daemon unit. Exits non-zero
    /// if any critical check fails.
    Doctor(DoctorArgs),
    /// Policy authoring helpers (suggest a starter policy from an
    /// audit-mode log, etc.). `check-policy` (the validation
    /// subcommand) lives at the top level for backwards compatibility.
    Policy {
        #[command(subcommand)]
        cmd: PolicyCommand,
    },
    /// Static analysis of GitHub Actions workflow files. Currently
    /// just `audit`, which flags `uses:` refs that aren't pinned to
    /// a 40-char commit SHA.
    Actions {
        #[command(subcommand)]
        cmd: ActionsCommand,
    },
    /// Workspace tamper detection — snapshot file hashes before a
    /// build, diff afterwards. Surfaces unexpected edits made by
    /// dependency post-install scripts or any other process the
    /// supervised step exec'd.
    Workspace {
        #[command(subcommand)]
        cmd: WorkspaceCommand,
    },
    /// Job-scoped supervised mode: attach to an existing cgroup v2
    /// hierarchy (typically the GitHub Actions runner's worker process)
    /// and observe every step the runner spawns until told to stop. The
    /// counterpart to `run`, which is tied to a single child process tree.
    /// Linux-only.
    Daemon {
        #[command(subcommand)]
        cmd: DaemonCommand,
    },
    /// Retroactive CVE notification: read the proxy's install log and
    /// query OSV.dev for advisories that affect installs you've
    /// already done. Local-first — only `(ecosystem, name, version)`
    /// tuples are sent to OSV; project paths, User-Agents, and
    /// timestamps never leave the machine.
    Advisories {
        #[command(subcommand)]
        cmd: AdvisoriesCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum AdvisoriesCommand {
    /// Query OSV.dev for advisories matching every install in the log.
    /// Exits non-zero if any hits are found.
    Scan(AdvisoriesScanArgs),
}

#[derive(Debug, Parser)]
pub struct AdvisoriesScanArgs {
    /// Override the install-log path. Defaults to
    /// `~/.sakimori/installs.jsonl`.
    #[arg(long)]
    pub install_log: Option<PathBuf>,
    /// Emit machine-readable JSON instead of the default human report.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    /// Attach eBPF programs to an existing cgroup and park until SIGTERM.
    /// Runs in the foreground; the caller is responsible for backgrounding
    /// (e.g. `setsid sakimori daemon start … &`).
    Start(DaemonStartArgs),
    /// Send SIGTERM to the daemon identified by `--pid-file` and wait for
    /// it to flush its report and exit. Idempotent: a missing pid-file or
    /// a dead pid both count as success.
    Stop(DaemonStopArgs),
}

#[derive(Debug, Parser)]
pub struct DaemonStartArgs {
    /// Policy file (YAML or JSON). Defaults to a permissive audit-only
    /// policy when omitted, same as `sakimori run`.
    #[arg(long, short = 'p', env = "SAKIMORI_POLICY")]
    pub policy: Option<PathBuf>,

    /// Override the policy's `mode`.
    #[arg(long, value_enum)]
    pub mode: Option<Mode>,

    /// Where to write the JSON audit log when the daemon shuts down.
    /// `-` for stdout.
    #[arg(long, default_value = "-")]
    pub log: String,

    /// Optional path to write a human-readable summary at shutdown.
    /// Typically `$GITHUB_STEP_SUMMARY`.
    #[arg(long, env = "GITHUB_STEP_SUMMARY")]
    pub summary: Option<PathBuf>,

    /// Optional path to write a self-contained HTML audit report at
    /// shutdown.
    #[arg(long)]
    pub html: Option<PathBuf>,

    /// File the daemon writes its pid to once eBPF programs are
    /// attached and observation is live. `daemon stop` reads from
    /// the same path. The daemon also removes the file on clean exit.
    #[arg(long, value_name = "FILE")]
    pub pid_file: PathBuf,

    /// Attach to the cgroup v2 hierarchy that this pid is already in,
    /// so every descendant the cgroup spawns (= every subsequent step
    /// in a GitHub Actions job) is observed. No process migration: we
    /// leave the runner's own cgroup management untouched.
    #[arg(long, value_name = "PID")]
    pub observe_cgroup_of: u32,

    /// Allow attaching to the root cgroup (`/`). Refused by default
    /// because it would observe every process on the host. Only set
    /// this on a single-tenant runner where that's actually what you
    /// want.
    #[arg(long)]
    pub allow_root_cgroup: bool,

    /// Same semantics as `sakimori run --dns-refresh-interval`.
    #[arg(long, default_value_t = 15, value_name = "SECS")]
    pub dns_refresh_interval: u64,

    /// Free-form label written into the JSON log / HTML report's
    /// `command` field. Daemon mode doesn't exec anything itself, so
    /// this is just metadata describing what the surrounding job is
    /// doing (e.g. "ci: build + test").
    #[arg(long, default_value = "sakimori daemon (job-scoped)")]
    pub command_label: String,

    /// Path to a workspace snapshot file (produced by
    /// `sakimori workspace snapshot <dir>`). When set, the daemon
    /// re-snapshots `--workspace-dir` at shutdown and surfaces the
    /// diff under `workspace_drift` in the report. Must be set
    /// together with `--workspace-dir`.
    ///
    /// Unlike `sakimori run --snapshot-workspace`, the daemon does
    /// NOT take the baseline itself — daemon mode starts before
    /// checkout (so the workspace would be empty at start time).
    /// Take the baseline yourself after checkout, in a separate
    /// step.
    #[arg(long, value_name = "FILE")]
    pub workspace_baseline: Option<PathBuf>,

    /// Directory to re-snapshot + diff against `--workspace-baseline`
    /// at shutdown. Must match the directory the baseline was taken
    /// from.
    #[arg(long, value_name = "DIR")]
    pub workspace_dir: Option<PathBuf>,

    /// Extra directory basenames to skip during the post-shutdown
    /// snapshot — must match what was passed to
    /// `sakimori workspace snapshot` when the baseline was taken,
    /// otherwise added/removed entries will fire spuriously.
    #[arg(long = "workspace-skip", value_name = "NAME")]
    pub workspace_skip: Vec<String>,
}

#[derive(Debug, Parser)]
pub struct DaemonStopArgs {
    /// Same pid-file the matching `daemon start` was given.
    #[arg(long, value_name = "FILE")]
    pub pid_file: PathBuf,

    /// How long to wait for the daemon to exit after SIGTERM, in
    /// seconds. We don't escalate to SIGKILL — if the daemon's stuck,
    /// the report would be incomplete anyway, and a half-written
    /// report is worse than an obvious timeout.
    #[arg(long, default_value_t = 30, value_name = "SECS")]
    pub timeout_secs: u64,
}

#[derive(Debug, Subcommand)]
pub enum WorkspaceCommand {
    /// Walk a directory and emit a JSON snapshot of every regular
    /// file's size + SHA-256. Writes to stdout by default.
    Snapshot(WorkspaceSnapshotArgs),
    /// Compare a previously-taken snapshot against the current
    /// state of `<dir>` and report added / modified / removed
    /// files. Exits non-zero when there's any drift (suppress with
    /// `--allow-drift`).
    Diff(WorkspaceDiffArgs),
    /// Walk `<dir>` and check every path against the known-IOC
    /// catalog (Shai-Hulud-class fingerprints). Standalone — does
    /// not need a baseline snapshot. Useful for a fresh-checkout
    /// quick scan or for post-mortem on a runner you don't have a
    /// baseline for.
    ScanIocs(WorkspaceScanIocsArgs),
}

#[derive(Debug, Parser)]
pub struct WorkspaceSnapshotArgs {
    /// Directory to snapshot.
    pub dir: PathBuf,
    /// Output file. `-` (default) writes to stdout.
    #[arg(long, short = 'o', default_value = "-")]
    pub output: PathBuf,
    /// Extra directory basenames to skip on top of the built-in
    /// list (`.git`, `node_modules`, `target`, `dist`, `build`,
    /// `vendor`, `__pycache__`, `.venv`, `venv`, `.next`, `.turbo`,
    /// `.cache`). Repeatable.
    #[arg(long = "skip")]
    pub skip: Vec<String>,
    /// Files larger than this many bytes get a size-only entry
    /// (no hash). 0 means unlimited.
    #[arg(long, default_value_t = sakimori_core::tamper::DEFAULT_MAX_FILE_BYTES)]
    pub max_file_bytes: u64,
}

#[derive(Debug, Parser)]
pub struct WorkspaceDiffArgs {
    /// Baseline snapshot JSON, as produced by
    /// `sakimori workspace snapshot`.
    pub baseline: PathBuf,
    /// Directory to diff against the baseline.
    pub dir: PathBuf,
    #[arg(long, value_enum, default_value = "text")]
    pub format: WorkspaceDiffFormat,
    /// Extra directory basenames to skip — must match what was
    /// passed to `snapshot`, otherwise added/removed entries will
    /// fire spuriously.
    #[arg(long = "skip")]
    pub skip: Vec<String>,
    #[arg(long, default_value_t = sakimori_core::tamper::DEFAULT_MAX_FILE_BYTES)]
    pub max_file_bytes: u64,
    /// Don't exit non-zero when drift is found. Useful for an
    /// audit-only step where you just want the report.
    #[arg(long)]
    pub allow_drift: bool,
    /// Disable the known-IOC scan that runs against added /
    /// modified paths. The scan is on by default — turning it off
    /// is rarely useful but exists so the diff output stays
    /// stable for golden-file regression tests.
    #[arg(long)]
    pub no_check_iocs: bool,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum WorkspaceDiffFormat {
    Text,
    Json,
}

#[derive(Debug, Parser)]
pub struct WorkspaceScanIocsArgs {
    /// Directory to scan.
    pub dir: PathBuf,
    #[arg(long, value_enum, default_value = "text")]
    pub format: WorkspaceDiffFormat,
    /// Extra directory basenames to skip on top of the built-in
    /// `tamper::DEFAULT_SKIP_DIRS` list.
    #[arg(long = "skip")]
    pub skip: Vec<String>,
    /// Treat Medium-severity hits as exit-1 too. Default is to
    /// exit non-zero only on High.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Debug, Subcommand)]
pub enum ActionsCommand {
    /// Walk one or more workflow YAMLs and report every `uses:`
    /// pointing at a mutable tag/branch instead of a commit SHA.
    /// Exits non-zero when at least one Error-severity finding
    /// is present (third-party `@v1` style); first-party warnings
    /// don't fail by default — pass `--strict` to escalate them.
    Audit(ActionsAuditArgs),
    /// Repo-scoped audit: walks `.github/workflows/*.{yml,yaml}` and
    /// runs the same per-file checks as `audit`, plus a CODEOWNERS
    /// coverage lint that fires when no owner pattern protects the
    /// `.github/` tree (the gate that would have caught the TanStack
    /// 2025 workflow change before merge).
    AuditRepo(ActionsAuditRepoArgs),
}

#[derive(Debug, Parser)]
pub struct ActionsAuditArgs {
    /// Workflow YAML files to audit. Pass `.github/workflows/*.yml`
    /// from your shell to glob — we don't expand globs ourselves.
    #[arg(required = true)]
    pub files: Vec<PathBuf>,
    #[arg(long, value_enum, default_value = "text")]
    pub format: ActionsFormat,
    /// Treat first-party (`actions/*`, `github/*`) mutable refs as
    /// blocking too. Default is to warn for first-party, error for
    /// third-party, on the theory that GitHub's own publish
    /// pipeline is harder to compromise than a random vendor's.
    #[arg(long)]
    pub strict: bool,
    /// Look up the current SHA each mutable `@<ref>` resolves to via
    /// the GitHub REST API and surface it on the finding (text
    /// output prints `→ <sha>`, JSON adds `resolved_sha`). Lets you
    /// copy-paste the right pinned form straight from the report.
    /// Off by default — keeps the audit offline. Reads `GITHUB_TOKEN`
    /// from the environment when present (raises the rate limit
    /// from 60/hour to 5000/hour).
    #[arg(long)]
    pub resolve: bool,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ActionsFormat {
    Text,
    Json,
}

#[derive(Debug, Parser)]
pub struct ActionsAuditRepoArgs {
    /// Repo root. Defaults to the current directory.
    #[arg(default_value = ".")]
    pub root: PathBuf,
    #[arg(long, value_enum, default_value = "text")]
    pub format: ActionsFormat,
    /// Treat first-party (`actions/*`, `github/*`) mutable refs as
    /// blocking too. Same semantics as on `audit`.
    #[arg(long)]
    pub strict: bool,
    /// Escalate the CODEOWNERS-coverage warning to a blocking error.
    /// Default is Warn — many repos historically didn't gate
    /// `.github/` and we don't want to break their first audit run.
    #[arg(long)]
    pub strict_codeowners: bool,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Read a JSON audit log (typically produced by
    /// `sakimori run --mode audit --log foo.json`) and emit a
    /// starter `policy.yml` covering every observed connect / open.
    /// Exec targets are surfaced as a commented `# observed_exec`
    /// block so you can pick which to deny — the suggester never
    /// auto-populates `process.deny_exec`.
    Suggest(PolicySuggestArgs),
    /// Emit a curated policy preset for a Shai-Hulud-class threat.
    /// Output is YAML on stdout (or `--output`); merge into an
    /// existing policy file or use as-is.
    Preset(PolicyPresetArgs),
}

#[derive(Debug, Parser)]
pub struct PolicySuggestArgs {
    /// Audit log to read. Use `-` for stdin.
    pub log: PathBuf,
    /// Where to write the suggested policy. Defaults to stdout.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct PolicyPresetArgs {
    /// Which preset to emit. `persistence` is a file-write deny list
    /// for launchd / systemd / ssh / shell-rc paths.
    /// `cloud-secret-egress` is a network deny list for cloud-IMDS
    /// and secret-store endpoints.
    pub name: String,
    /// Override the home directory used to expand `~` in the
    /// `persistence` preset. Defaults to `$HOME`. No effect on other
    /// presets.
    #[arg(long)]
    pub home: Option<String>,
    /// Where to write the preset. Defaults to stdout.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum InstallGateCommand {
    /// Print the shell snippet to `eval` at shell startup. Output is
    /// shell-specific; the `install` subcommand uses this too.
    Shellenv(InstallGateShellenvArgs),
    /// Append an `eval`-style line to the shell rc file so every new
    /// shell picks up the proxy env. Idempotent.
    Install(InstallGateInstallArgs),
    /// Reverse of `install` — strip the block from the shell rc file.
    Uninstall(InstallGateInstallArgs),
}

#[derive(Debug, Parser)]
pub struct InstallGateShellenvArgs {
    /// Proxy listen address the shell env should point at. Default
    /// matches the `proxy start` default.
    #[arg(long, default_value = "127.0.0.1:8910")]
    pub listen: std::net::SocketAddr,
    /// Override the shell syntax flavour. Defaults to auto-detect
    /// from `$SHELL`.
    #[arg(long, value_enum)]
    pub shell: Option<InstallGateShell>,
}

#[derive(Debug, Parser)]
pub struct InstallGateInstallArgs {
    /// Explicit rc file path. Defaults to the conventional one for
    /// the detected shell (e.g. `~/.zshrc`).
    #[arg(long)]
    pub rc: Option<PathBuf>,
    /// Override the shell flavour. Defaults to auto-detect from
    /// `$SHELL`.
    #[arg(long, value_enum)]
    pub shell: Option<InstallGateShell>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TyposquatMode {
    Warn,
    Block,
}

impl From<TyposquatMode> for sakimori_proxy::decision::TyposquatMode {
    fn from(m: TyposquatMode) -> Self {
        match m {
            TyposquatMode::Warn => Self::Warn,
            TyposquatMode::Block => Self::Block,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[allow(clippy::enum_variant_names)]
pub enum InstallGateShell {
    Bash,
    Zsh,
    Fish,
    /// Windows PowerShell / PowerShell Core (`pwsh`).
    Powershell,
}

impl From<InstallGateShell> for crate::install_gate::Shell {
    fn from(s: InstallGateShell) -> Self {
        match s {
            InstallGateShell::Bash => crate::install_gate::Shell::Bash,
            InstallGateShell::Zsh => crate::install_gate::Shell::Zsh,
            InstallGateShell::Fish => crate::install_gate::Shell::Fish,
            InstallGateShell::Powershell => crate::install_gate::Shell::PowerShell,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum ProxyCommand {
    /// Start the proxy. Prints the root CA's install instructions on
    /// first run.
    Start(Box<ProxyStartArgs>),
    /// Add the proxy's root CA to the OS trust store (sudo required on
    /// macOS/Linux; admin PowerShell on Windows). Prints the exact
    /// command when we can't run it ourselves.
    InstallCa(ProxyCaArgs),
    /// Remove the proxy's root CA from the OS trust store.
    UninstallCa(ProxyCaArgs),
    /// Write a user-level launchd plist (macOS) or systemd user unit
    /// (Linux) so `proxy start` runs in the background and restarts on
    /// failure. Idempotent. Prints the exact command to activate it.
    InstallDaemon(ProxyDaemonArgs),
    /// Remove the daemon unit written by `install-daemon`.
    UninstallDaemon(ProxyDaemonArgs),
}

#[derive(Debug, Parser)]
pub struct DoctorArgs {
    /// Proxy listen address to probe. Must match whatever you passed
    /// to `proxy start` / `install-daemon`.
    #[arg(long, default_value = "127.0.0.1:8910")]
    pub listen: std::net::SocketAddr,
    /// Override the CA/config directory. Defaults to the same logic
    /// as `proxy start`.
    #[arg(long)]
    pub config_dir: Option<PathBuf>,
    /// Shell rc file to inspect. Defaults to the one `install-gate`
    /// would target for the detected shell.
    #[arg(long)]
    pub rc: Option<PathBuf>,
    /// Path to a `sakimori daemon start --pid-file` file. When given,
    /// doctor reads the pid and reports whether the daemon process is
    /// alive. Skipped when omitted.
    #[arg(long, value_name = "FILE")]
    pub daemon_pidfile: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct ProxyDaemonArgs {
    /// Address the proxy will listen on.
    #[arg(long, default_value = "127.0.0.1:8910")]
    pub listen: std::net::SocketAddr,
    /// Minimum age a package must have, same grammar as `deps check`.
    #[arg(long, default_value = "7d")]
    pub min_age: String,
    /// Override the binary path embedded in the unit. Defaults to
    /// the canonical path of the currently-running executable.
    #[arg(long)]
    pub binary: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct ProxyCaArgs {
    /// Override the CA/config directory.
    #[arg(long)]
    pub config_dir: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct ProxyStartArgs {
    /// Address the proxy listens on. Clients set `HTTPS_PROXY` /
    /// `HTTP_PROXY` to this.
    #[arg(long, default_value = "127.0.0.1:8910")]
    pub listen: std::net::SocketAddr,
    /// Minimum age a package must have, same grammar as `deps check`.
    #[arg(long, default_value = "7d")]
    pub min_age: String,
    /// Treat unknown publish dates as a deny (default: fail-open /
    /// allow through).
    #[arg(long)]
    pub fail_on_missing: bool,
    /// **Strict mode.** Drop every npm package version that doesn't
    /// carry a Sigstore provenance claim (`dist.attestations.provenance`).
    /// Closes the "stolen publish token" hole that `--min-age`
    /// alone can't cover: a token thief can publish immediately,
    /// but without an OIDC-authenticated CI run they can't attach a
    /// valid provenance attestation.
    ///
    /// Only affects the npm packument path. pypi / nuget / crates
    /// equivalents (PEP 740, cargo attestation) are roadmap items.
    #[arg(long)]
    pub require_provenance: bool,
    /// Consult OSV.dev on every decision. Versions flagged as
    /// malicious packages (MAL-* IDs or advisories whose
    /// summary/details say "malicious") are hard-denied regardless
    /// of `--min-age` — catching e.g. event-stream 3.3.6 which is
    /// old enough to pass the age filter but still poisonous.
    ///
    /// OSV lookups are in-memory cached. On lookup error (network
    /// blip, OSV downtime) the check fails open and the age filter
    /// still runs.
    #[arg(long)]
    pub osv: bool,
    /// Consume the sakimori-hosted pre-filtered OSV mirror at
    /// `https://raw.githubusercontent.com/bokuweb/sakimori/osv-mirror-data/mal.json`.
    ///
    /// This is the recommended way to enable OSV known-malicious
    /// blocking: it's O(1) in-memory after a single background
    /// refresh per 10 minutes, instead of a live HTTP lookup per
    /// decision. Combine with `--osv` to additionally fall back to
    /// the live API when the mirror hasn't yet indexed a new
    /// advisory.
    #[arg(long)]
    pub osv_mirror: bool,
    /// Override the mirror URL (e.g. your org's self-hosted mirror).
    /// Only meaningful with `--osv-mirror`.
    #[arg(long)]
    pub osv_mirror_url: Option<String>,
    /// Typosquat detection: compare incoming package names against
    /// a small top-N list per ecosystem (lodash, requests, tokio,
    /// Newtonsoft.Json, …). `warn` logs a warning and lets the
    /// install proceed; `block` hard-denies. Off by default.
    #[arg(long, value_enum)]
    pub typosquat: Option<TyposquatMode>,
    /// Use the sakimori-hosted pre-fetched top-1000-per-ecosystem
    /// list instead of the ~100-name baseline baked into the binary.
    /// Refreshes daily in the background and falls back to the
    /// baseline when the mirror is unreachable. Only meaningful with
    /// `--typosquat`.
    #[arg(long)]
    pub typosquat_mirror: bool,
    /// Override the typosquat mirror URL.
    #[arg(long)]
    pub typosquat_mirror_url: Option<String>,
    /// Hostname egress allow-list. Repeatable. When set, the proxy
    /// default-denies every CONNECT / HTTP request whose target
    /// host doesn't match an entry, returning 403. Patterns:
    ///
    /// - `host.example.com` — exact (case-insensitive)
    /// - `*.example.com` — any subdomain (does NOT match the apex)
    ///
    /// Embedded `*` is a parse error. Off by default; without any
    /// `--network-allow` flag the proxy passes every host through.
    #[arg(long = "network-allow", value_name = "HOST")]
    pub network_allow: Vec<String>,
    /// Read additional `--network-allow` patterns from a file (one
    /// per line; `#` comments and blank lines are skipped). Layered
    /// on top of any `--network-allow` flags.
    #[arg(long)]
    pub network_allow_file: Option<PathBuf>,
    /// Override the CA/config directory. Defaults to
    /// `$XDG_CONFIG_HOME/sakimori` (or `~/.config/sakimori`).
    #[arg(long)]
    pub config_dir: Option<PathBuf>,
    /// Disable the local install log
    /// (`~/.sakimori/installs.jsonl`). The log is the input for
    /// `sakimori advisories scan`; turning it off opts out of
    /// retroactive CVE notification.
    #[arg(long)]
    pub no_install_log: bool,
    /// Override the install-log path. Defaults to
    /// `~/.sakimori/installs.jsonl`.
    #[arg(long)]
    pub install_log: Option<PathBuf>,
    /// Opt-in OTLP/HTTP logs endpoint. When set, every allowed
    /// install is also exported as an OTLP `LogRecord` with
    /// `package.*` attributes — for fan-out to Datadog / Honeycomb /
    /// Loki / a self-run otel-collector without standing up
    /// sakimori-hub. Pass the full URL (typically ending in
    /// `/v1/logs`); we don't auto-suffix. Coexists with the local
    /// install log.
    #[arg(long, value_name = "URL")]
    pub otlp_endpoint: Option<String>,
    /// Additional header sent on every OTLP request, in `KEY=VALUE`
    /// form. Repeatable. Typical use: `--otlp-header
    /// Authorization="Bearer …"` for vendor backends. Ignored when
    /// `--otlp-endpoint` is not set.
    #[arg(long = "otlp-header", value_name = "K=V", value_parser = parse_kv)]
    pub otlp_headers: Vec<(String, String)>,
    /// Lifecycle-script gate for npm tarballs (Shai-Hulud-class
    /// defence). `audit` logs every fetched tarball that ships
    /// `install` / `preinstall` / `postinstall` / `prepare` scripts
    /// without blocking; `block` returns 403 for those tarballs so
    /// npm never runs the scripts. `strip` is on the roadmap but not
    /// yet implemented — pass `audit` or `block` for now. Unset
    /// disables the gate entirely (current default).
    #[arg(long = "lifecycle-policy", value_name = "MODE")]
    pub lifecycle_policy: Option<String>,
    /// Per-package allow-list for the lifecycle gate. Repeatable.
    /// Names listed here keep their install scripts even under
    /// `--lifecycle-policy block`. Use for legitimate native-addon
    /// packages (e.g. `sharp`, `bcrypt`) whose `install` script
    /// compiles bindings.
    #[arg(long = "lifecycle-allow", value_name = "PKG")]
    pub lifecycle_allow: Vec<String>,
}

fn parse_kv(s: &str) -> std::result::Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
        _ => Err(format!("expected KEY=VALUE, got `{s}`")),
    }
}

#[derive(Debug, Subcommand)]
pub enum DepsCommand {
    /// Check publish ages against all dependencies in the given lockfile(s).
    Check(DepsCheckArgs),
    /// Stay resident: watch one or more workspace roots, run `check` on
    /// every lockfile change, and surface violations via a desktop
    /// notification. Designed for `launchd` / `systemd --user`.
    Watch(DepsWatchArgs),
    /// Re-hash the package manager's local cache against the
    /// `integrity:` fields in a lockfile. Catches the *content* half
    /// of TanStack-style GHA cache poisoning: cache restored bytes
    /// that don't match what the lockfile pinned. MVP: npm cacache
    /// only (default root `~/.npm/_cacache`).
    #[command(name = "verify-cache")]
    VerifyCache(DepsVerifyCacheArgs),
}

#[derive(Debug, Parser)]
pub struct DepsVerifyCacheArgs {
    /// Lockfile to read integrity hashes from. MVP supports
    /// `package-lock.json` (npm v2/v3).
    #[arg(long, short = 'l')]
    pub lockfile: PathBuf,
    /// Path to the package manager's cache root. Defaults to
    /// `~/.npm/_cacache` (npm cacache layout).
    #[arg(long)]
    pub cache: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "text")]
    pub format: DepsFormat,
    /// Also fail when blobs are merely *missing* from the cache.
    /// Default: only `mismatch` (the actual tampering signal) fails
    /// the run. Cargo.lock legitimately lists platform-conditional
    /// crates (`windows-*`, `fsevent-sys`, `wasm-bindgen`, …) that
    /// never land in a Linux runner's cache, so a strict missing
    /// check is a false alarm there. Opt in for npm/pnpm runs where
    /// you want post-install completeness checking too.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Debug, Parser)]
pub struct DepsWatchArgs {
    /// Workspace root(s) to watch recursively.
    #[arg(required = true)]
    pub roots: Vec<PathBuf>,
    /// Minimum age a package must have.
    #[arg(long, default_value = "7d")]
    pub min_age: String,
    #[arg(long)]
    pub ignore: Vec<String>,
    #[arg(long)]
    pub no_cache: bool,
    #[arg(long)]
    pub cache: Option<PathBuf>,
    /// How long to wait for a burst of edits to settle, in ms.
    #[arg(long, default_value_t = 800)]
    pub debounce_ms: u64,
    /// Poll interval for the FS-event source, in ms.
    #[arg(long, default_value_t = 250)]
    pub tick_ms: u64,
    /// Notification sink. `mac` uses osascript (macOS only), `stdout`
    /// prints to stderr — good for launchctl log redirects.
    #[arg(long, value_enum, default_value = "mac")]
    pub notifier: DepsNotifier,
    /// What to do when a violation is detected.
    ///
    /// - `notify` (default): just post a notification. The lockfile is
    ///   left as-is; nothing is blocked.
    /// - `prompt` (macOS only): show a Keep/Revert modal. Only useful
    ///   **after** the install has already completed, so this is
    ///   detection, not prevention — see README "Limitations".
    /// - `revert`: silently restore the lockfile to `HEAD` via git.
    ///   Destructive. Requires the lockfile to be git-tracked.
    #[arg(long, value_enum, default_value = "notify")]
    pub action: DepsAction,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum DepsNotifier {
    Mac,
    Stdout,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum DepsAction {
    Notify,
    Prompt,
    Revert,
}

#[derive(Debug, Parser)]
pub struct DepsCheckArgs {
    /// Lockfiles to inspect. Currently: package-lock.json, Cargo.lock.
    #[arg(required = true)]
    pub lockfiles: Vec<PathBuf>,
    /// Minimum age a package must have. Units: `d` (default), `h`, `m`, `s`.
    #[arg(long, default_value = "7d")]
    pub min_age: String,
    /// Don't check packages whose name matches this pattern. Accepts plain
    /// names, `prefix*`, `*suffix`, or scope globs like `@types/*`. Repeat.
    #[arg(long)]
    pub ignore: Vec<String>,
    /// Treat missing publish-date lookups as violations instead of warnings.
    #[arg(long)]
    pub fail_on_missing: bool,
    /// Skip the on-disk cache of publish dates entirely.
    #[arg(long)]
    pub no_cache: bool,
    /// Override the default cache path.
    #[arg(long)]
    pub cache: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    pub format: DepsFormat,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum DepsFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Mode {
    Audit,
    Block,
}

#[derive(Debug, Parser)]
pub struct RunArgs {
    /// Policy file (YAML or JSON).
    #[arg(long, short = 'p', env = "SAKIMORI_POLICY")]
    pub policy: Option<PathBuf>,

    /// Override the policy's `mode`.
    #[arg(long, value_enum)]
    pub mode: Option<Mode>,

    /// Where to write the JSON audit log. `-` for stdout.
    #[arg(long, default_value = "-")]
    pub log: String,

    /// Optional path to write a human-readable summary (suitable for
    /// `$GITHUB_STEP_SUMMARY`).
    #[arg(long, env = "GITHUB_STEP_SUMMARY")]
    pub summary: Option<PathBuf>,

    /// Optional path to write a self-contained HTML audit report. Open
    /// directly in a browser; designed to be uploaded as a workflow
    /// artifact.
    #[arg(long)]
    pub html: Option<PathBuf>,

    /// Re-resolve hostname-based `network.allow` / `network.deny`
    /// rules on this interval (seconds) and additively populate the
    /// eBPF map with any newly-observed IPs. Needed for supervised
    /// jobs behind round-robin DNS (github.com, registry.npmjs.org,
    /// most CDNs): the IPs returned by a fresh DNS query mid-run
    /// can differ from the ones captured at startup, so without
    /// refresh the second connect to the same hostname can be
    /// denied with `Operation not permitted`. Entries are never
    /// removed once written. `0` disables refresh entirely.
    #[arg(long, default_value_t = 15, value_name = "SECS")]
    pub dns_refresh_interval: u64,

    /// Snapshot the contents of this directory before exec'ing the
    /// supervised command, take a fresh snapshot afterwards, and
    /// surface any files added / modified / removed by the build
    /// in the JSON log (under `workspace_drift`) and the step
    /// summary. Off by default — same skip list as
    /// `sakimori workspace snapshot` (`.git`, `node_modules`,
    /// `target`, …). In `mode: block`, any drift causes a non-zero
    /// exit (the same way denied events do); in `mode: audit` the
    /// drift is reported but doesn't change exit code.
    #[arg(long, value_name = "DIR")]
    pub snapshot_workspace: Option<PathBuf>,

    /// Extra directory basenames to skip during the workspace
    /// snapshot, on top of the built-in build-artefact list.
    /// Repeatable. Only meaningful with `--snapshot-workspace`.
    #[arg(long = "snapshot-skip", value_name = "NAME")]
    pub snapshot_skip: Vec<String>,

    /// Command + args to execute under supervision.
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::CheckPolicy { policy } => {
            let p = policy::Policy::from_file(&policy)
                .with_context(|| format!("loading {}", policy.display()))?;
            p.validate(p.mode)?;
            for w in p.lint() {
                eprintln!("warning: {w}");
            }
            println!("{}", serde_json::to_string_pretty(&p)?);
            Ok(())
        }
        Command::Run(args) => run_supervised(args).await,
        Command::Deps {
            cmd: DepsCommand::Check(args),
        } => {
            let exit = sakimori_core::deps::cli::run(sakimori_core::deps::cli::CliArgs {
                lockfiles: args.lockfiles,
                min_age: args.min_age,
                ignore: args.ignore,
                fail_on_missing: args.fail_on_missing,
                no_cache: args.no_cache,
                cache_path: args.cache,
                format: match args.format {
                    DepsFormat::Text => sakimori_core::deps::cli::Format::Text,
                    DepsFormat::Json => sakimori_core::deps::cli::Format::Json,
                },
                user_agent: None,
            })?;
            std::process::exit(exit);
        }
        Command::Proxy {
            cmd: ProxyCommand::InstallCa(args),
        } => {
            let ca_files = ca_files_for(args.config_dir)?;
            // Ensure the CA exists first so the install command has
            // something to point at.
            sakimori_proxy::ca::ensure_ca(&ca_files)?;
            let r = sakimori_proxy::install::install_ca(&ca_files)?;
            use sakimori_proxy::install::InstallOutcome;
            match r.outcome {
                InstallOutcome::Installed => {
                    println!(
                        "✓ sakimori root CA installed into the system trust store\n  ({})",
                        ca_files.cert_pem.display()
                    );
                }
                InstallOutcome::NeedsPrivilege => {
                    println!(
                        "Need elevated privileges to install the CA. Run:\n\n  {}\n",
                        r.command_hint
                    );
                }
                InstallOutcome::Manual => {
                    println!("{}", r.command_hint);
                }
            }
            Ok(())
        }
        Command::Proxy {
            cmd: ProxyCommand::UninstallCa(args),
        } => {
            let ca_files = ca_files_for(args.config_dir)?;
            let r = sakimori_proxy::install::uninstall_ca(&ca_files)?;
            use sakimori_proxy::install::InstallOutcome;
            match r.outcome {
                InstallOutcome::Installed => {
                    println!("✓ sakimori root CA removed from the system trust store");
                }
                InstallOutcome::NeedsPrivilege => {
                    println!(
                        "Need elevated privileges to remove the CA. Run:\n\n  {}\n",
                        r.command_hint
                    );
                }
                InstallOutcome::Manual => {
                    println!("{}", r.command_hint);
                }
            }
            Ok(())
        }
        Command::Proxy {
            cmd: ProxyCommand::Start(args),
        } => {
            let min_age = parse_simple_duration(&args.min_age)?;
            let ca_files = ca_files_for(args.config_dir)?;
            let network_allow = build_network_allow(&args.network_allow, &args.network_allow_file)?;
            let lifecycle_policy = args
                .lifecycle_policy
                .as_deref()
                .map(sakimori_proxy::lifecycle::LifecyclePolicy::parse)
                .transpose()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let cfg = sakimori_proxy::ProxyConfig {
                listen: args.listen,
                min_age,
                fail_on_missing: args.fail_on_missing,
                require_provenance: args.require_provenance,
                osv: args.osv,
                osv_mirror: args.osv_mirror,
                osv_mirror_url: args.osv_mirror_url,
                typosquat: args.typosquat.map(Into::into),
                typosquat_mirror: args.typosquat_mirror,
                typosquat_mirror_url: args.typosquat_mirror_url,
                ca_files,
                user_agent: format!("sakimori-proxy/{}", env!("CARGO_PKG_VERSION")),
                oracle: None,
                network_allow,
                install_log_path: args.install_log,
                install_log_enabled: !args.no_install_log,
                otlp_endpoint: args.otlp_endpoint,
                otlp_headers: args.otlp_headers,
                lifecycle_policy,
                lifecycle_allow: args.lifecycle_allow,
            };
            sakimori_proxy::run(cfg).await?;
            Ok(())
        }
        Command::Doctor(args) => run_doctor(args),
        Command::Proxy {
            cmd: ProxyCommand::InstallDaemon(args),
        } => run_install_daemon(args),
        Command::Proxy {
            cmd: ProxyCommand::UninstallDaemon(args),
        } => run_uninstall_daemon(args),
        Command::Deps {
            cmd: DepsCommand::Watch(args),
        } => {
            sakimori_core::deps::cli::run_watch(sakimori_core::deps::cli::WatchCliArgs {
                roots: args.roots,
                min_age: args.min_age,
                ignore: args.ignore,
                no_cache: args.no_cache,
                cache_path: args.cache,
                debounce_ms: args.debounce_ms,
                tick_ms: args.tick_ms,
                notifier: match args.notifier {
                    DepsNotifier::Mac => sakimori_core::deps::cli::WatchNotifierKind::Mac,
                    DepsNotifier::Stdout => sakimori_core::deps::cli::WatchNotifierKind::Stdout,
                },
                action: match args.action {
                    DepsAction::Notify => sakimori_core::deps::cli::WatchActionKind::Notify,
                    DepsAction::Prompt => sakimori_core::deps::cli::WatchActionKind::Prompt,
                    DepsAction::Revert => sakimori_core::deps::cli::WatchActionKind::Revert,
                },
                user_agent: None,
            })?;
            Ok(())
        }
        Command::Deps {
            cmd: DepsCommand::VerifyCache(args),
        } => run_deps_verify_cache(args),
        Command::InstallGate {
            cmd: InstallGateCommand::Shellenv(args),
        } => {
            let shell = args
                .shell
                .map(crate::install_gate::Shell::from)
                .unwrap_or_else(crate::install_gate::detect_shell_from_env);
            print!(
                "{}",
                crate::install_gate::render_shellenv(shell, args.listen)
            );
            Ok(())
        }
        Command::InstallGate {
            cmd: InstallGateCommand::Install(args),
        } => run_install_gate_install(args),
        Command::InstallGate {
            cmd: InstallGateCommand::Uninstall(args),
        } => run_install_gate_uninstall(args),
        Command::Policy {
            cmd: PolicyCommand::Suggest(args),
        } => run_policy_suggest(args),
        Command::Policy {
            cmd: PolicyCommand::Preset(args),
        } => run_policy_preset(args),
        Command::Actions {
            cmd: ActionsCommand::Audit(args),
        } => run_actions_audit(args),
        Command::Actions {
            cmd: ActionsCommand::AuditRepo(args),
        } => run_actions_audit_repo(args),
        Command::Workspace {
            cmd: WorkspaceCommand::Snapshot(args),
        } => run_workspace_snapshot(args),
        Command::Workspace {
            cmd: WorkspaceCommand::Diff(args),
        } => run_workspace_diff(args),
        Command::Workspace {
            cmd: WorkspaceCommand::ScanIocs(args),
        } => run_workspace_scan_iocs(args),
        Command::Daemon {
            cmd: DaemonCommand::Start(args),
        } => run_daemon_start(args).await,
        Command::Daemon {
            cmd: DaemonCommand::Stop(args),
        } => run_daemon_stop(args),
        Command::Advisories {
            cmd: AdvisoriesCommand::Scan(args),
        } => run_advisories_scan(args),
    }
}

fn run_advisories_scan(args: AdvisoriesScanArgs) -> Result<()> {
    use sakimori_core::advisories::{LiveOsvBatch, scan};
    use sakimori_core::installs::{ExecutionMode, InstallLogger};

    let path = args.install_log.unwrap_or_else(InstallLogger::default_path);
    let logger = InstallLogger::at(&path);
    let oracle = LiveOsvBatch::new(format!("sakimori/{}", env!("CARGO_PKG_VERSION")));
    let report = scan(&logger, &oracle)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "scanned {} install(s), {} unique package(s) from {}",
            report.installs_scanned,
            report.unique_packages,
            path.display()
        );
        if report.hits.is_empty() {
            println!("no matching advisories");
        } else {
            println!("{} package(s) implicated:\n", report.hits.len());
            for hit in &report.hits {
                let tag = match hit.execution_mode {
                    ExecutionMode::Persistent => "persistent",
                    ExecutionMode::Ephemeral => "ephemeral — code ran on this machine",
                    ExecutionMode::Unknown => "unknown mode",
                };
                println!(
                    "  {} {}@{}  [{}]\n    {}",
                    hit.ecosystem,
                    hit.name,
                    hit.version,
                    tag,
                    hit.advisory_ids.join(", "),
                );
            }
        }
    }
    if !report.hits.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

async fn run_daemon_start(args: DaemonStartArgs) -> Result<()> {
    let mode_override = args.mode.map(|m| match m {
        Mode::Audit => policy::Mode::Audit,
        Mode::Block => policy::Mode::Block,
    });
    crate::daemon::start(crate::daemon::DaemonStartArgs {
        policy_path: args.policy,
        mode_override,
        log: args.log,
        summary: args.summary,
        html: args.html,
        pid_file: args.pid_file,
        observe_cgroup_of: args.observe_cgroup_of,
        allow_root_cgroup: args.allow_root_cgroup,
        dns_refresh: Duration::from_secs(args.dns_refresh_interval),
        command_label: args.command_label,
        workspace_baseline: args.workspace_baseline,
        workspace_dir: args.workspace_dir,
        workspace_skip: args.workspace_skip,
    })
    .await
}

fn run_daemon_stop(args: DaemonStopArgs) -> Result<()> {
    crate::daemon::stop(crate::daemon::DaemonStopArgs {
        pid_file: args.pid_file,
        timeout: Duration::from_secs(args.timeout_secs),
    })
}

fn tamper_options(skip: Vec<String>, max_file_bytes: u64) -> sakimori_core::tamper::Options {
    sakimori_core::tamper::Options {
        skip_extra: skip,
        max_file_bytes: if max_file_bytes == 0 {
            u64::MAX
        } else {
            max_file_bytes
        },
    }
}

fn run_workspace_snapshot(args: WorkspaceSnapshotArgs) -> Result<()> {
    let opts = tamper_options(args.skip, args.max_file_bytes);
    let snap = sakimori_core::tamper::Snapshot::take(&args.dir, &opts)
        .with_context(|| format!("snapshotting {}", args.dir.display()))?;
    let json = snap.to_json_pretty()?;
    if args.output.as_os_str() == "-" {
        println!("{json}");
    } else {
        std::fs::write(&args.output, json)
            .with_context(|| format!("writing {}", args.output.display()))?;
        eprintln!(
            "sakimori: wrote snapshot of {} files to {}",
            snap.files.len(),
            args.output.display()
        );
    }
    Ok(())
}

fn run_workspace_diff(args: WorkspaceDiffArgs) -> Result<()> {
    let baseline_json = std::fs::read_to_string(&args.baseline)
        .with_context(|| format!("reading baseline {}", args.baseline.display()))?;
    let baseline = sakimori_core::tamper::Snapshot::from_json(&baseline_json)?;
    let opts = tamper_options(args.skip, args.max_file_bytes);
    let current = sakimori_core::tamper::Snapshot::take(&args.dir, &opts)
        .with_context(|| format!("snapshotting {}", args.dir.display()))?;
    let dif = sakimori_core::tamper::diff(&baseline, &current);

    // Only scan paths the diff implicates — a clean file that was
    // already in the baseline gets no IOC re-check, because the
    // baseline-scan opportunity is the snapshot step itself (todo:
    // wire `workspace snapshot --check-iocs` as a follow-up).
    let ioc_targets: Vec<&std::path::Path> = if args.no_check_iocs {
        Vec::new()
    } else {
        dif.added
            .iter()
            .map(std::path::PathBuf::as_path)
            .chain(dif.modified.iter().map(|m| m.path.as_path()))
            .collect()
    };
    let ioc_findings = sakimori_core::iocs::scan_paths(ioc_targets.iter().copied());
    let ioc_report = sakimori_core::iocs::Report::new(ioc_findings);

    match args.format {
        WorkspaceDiffFormat::Json => {
            #[derive(serde::Serialize)]
            struct Combined<'a> {
                #[serde(flatten)]
                diff: &'a sakimori_core::tamper::Diff,
                iocs: &'a sakimori_core::iocs::Report,
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&Combined {
                    diff: &dif,
                    iocs: &ioc_report,
                })?
            );
        }
        WorkspaceDiffFormat::Text => {
            if dif.is_clean() {
                eprintln!("sakimori: workspace clean — no changes detected");
            } else {
                eprintln!(
                    "sakimori: {} changes ({} added, {} modified, {} removed)\n",
                    dif.total(),
                    dif.added.len(),
                    dif.modified.len(),
                    dif.removed.len(),
                );
                for p in &dif.added {
                    println!("+  {}", p.display());
                }
                for m in &dif.modified {
                    println!("~  {}", m.path.display());
                }
                for p in &dif.removed {
                    println!("-  {}", p.display());
                }
            }
            if !ioc_report.is_clean() {
                eprintln!(
                    "\nsakimori: ❌ {} known-IOC hit(s) (catalog {})",
                    ioc_report.findings.len(),
                    ioc_report.catalog_version,
                );
                for f in &ioc_report.findings {
                    let tag = match f.severity {
                        sakimori_core::iocs::Severity::High => "HIGH",
                        sakimori_core::iocs::Severity::Medium => "MED ",
                    };
                    println!("!! {tag}  {}  [{}]", f.path.display(), f.rule_id);
                    println!("       {}", f.description);
                }
            }
        }
    }

    // A High-severity IOC is exit-1 even with `--allow-drift`: that
    // flag is meant for "I expect drift", not for "I expect a
    // known-malicious-file fingerprint".
    let drift_blocks = !dif.is_clean() && !args.allow_drift;
    if drift_blocks || ioc_report.has_high() {
        std::process::exit(1);
    }
    Ok(())
}

fn run_workspace_scan_iocs(args: WorkspaceScanIocsArgs) -> Result<()> {
    let opts = tamper_options(args.skip, sakimori_core::tamper::DEFAULT_MAX_FILE_BYTES);
    let snap = sakimori_core::tamper::Snapshot::take(&args.dir, &opts)
        .with_context(|| format!("scanning {}", args.dir.display()))?;
    let findings = sakimori_core::iocs::scan_paths(snap.files.keys());
    let report = sakimori_core::iocs::Report::new(findings);

    match args.format {
        WorkspaceDiffFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        WorkspaceDiffFormat::Text => {
            if report.is_clean() {
                eprintln!(
                    "sakimori: no known-IOC hits ({} file(s) scanned, catalog {})",
                    snap.files.len(),
                    report.catalog_version,
                );
            } else {
                eprintln!(
                    "sakimori: ❌ {} known-IOC hit(s) in {} (catalog {})",
                    report.findings.len(),
                    args.dir.display(),
                    report.catalog_version,
                );
                for f in &report.findings {
                    let tag = match f.severity {
                        sakimori_core::iocs::Severity::High => "HIGH",
                        sakimori_core::iocs::Severity::Medium => "MED ",
                    };
                    println!("!! {tag}  {}  [{}]", f.path.display(), f.rule_id);
                    println!("       {}", f.description);
                }
            }
        }
    }

    let block = report.has_high()
        || (args.strict
            && report
                .findings
                .iter()
                .any(|f| matches!(f.severity, sakimori_core::iocs::Severity::Medium)));
    if block {
        std::process::exit(1);
    }
    Ok(())
}

fn run_deps_verify_cache(args: DepsVerifyCacheArgs) -> Result<()> {
    use sakimori_core::deps::verify_cache::{
        Outcome, cargo_integrity_entries, npm_integrity_entries, pnpm_integrity_entries,
        verify_cargo_registry, verify_npm_cacache, verify_pnpm_store,
    };

    // Pick lockfile flavour by basename. Each flavour has its own
    // default cache root convention; everything else funnels into
    // the shared VerifyReport.
    let fname = args
        .lockfile
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let report = match fname {
        "package-lock.json" => {
            let cache_root = match args.cache {
                Some(p) => p,
                None => default_npm_cacache_root()?,
            };
            let entries = npm_integrity_entries(&args.lockfile)
                .with_context(|| format!("reading integrity from {}", args.lockfile.display()))?;
            verify_npm_cacache(&entries, &cache_root)
        }
        "pnpm-lock.yaml" => {
            let store_root = match args.cache {
                Some(p) => p,
                None => default_pnpm_store_root()?,
            };
            let entries = pnpm_integrity_entries(&args.lockfile)
                .with_context(|| format!("reading integrity from {}", args.lockfile.display()))?;
            verify_pnpm_store(&entries, &store_root)
        }
        "Cargo.lock" => {
            let cargo_home = match args.cache {
                Some(p) => p,
                None => default_cargo_home()?,
            };
            let entries = cargo_integrity_entries(&args.lockfile)
                .with_context(|| format!("reading integrity from {}", args.lockfile.display()))?;
            verify_cargo_registry(&entries, &cargo_home)
        }
        other => anyhow::bail!(
            "unsupported lockfile `{other}` (supported: package-lock.json, pnpm-lock.yaml, Cargo.lock)"
        ),
    };

    match args.format {
        DepsFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        DepsFormat::Text => {
            println!(
                "{}  ({} checked, {} ok, {} missing, {} mismatch, {} unsupported)",
                args.lockfile.display(),
                report.checked,
                report.ok,
                report.missing,
                report.mismatched,
                report.unsupported
            );
            for v in &report.packages {
                let tag = match v.outcome {
                    Outcome::Ok => continue, // hide OK rows in text mode
                    Outcome::Missing => "MISSING ",
                    Outcome::Mismatch => "MISMATCH",
                    Outcome::Unsupported => "skipped ",
                };
                println!("  {tag}  {}@{}", v.name, v.version);
                if let Some(p) = &v.cache_path {
                    println!("           path: {}", p.display());
                }
                if let (Some(exp), Some(act)) = (&v.expected_sha_hex, &v.actual_sha_hex) {
                    println!("           expected: {exp}");
                    println!("           actual:   {act}");
                }
                if let Some(m) = &v.message {
                    println!("           {m}");
                }
            }
        }
    }

    // Threat model: mismatch = bytes don't match what the lockfile
    // pinned = real cache-poisoning signal. Missing = blob isn't in
    // the cache yet (normal for Cargo.lock's platform-conditional
    // crates on a single-OS runner; not a security event). Default
    // exit predicate is mismatch-only; `--strict` opts into the
    // older "fail on anything not Ok" behaviour.
    if report.missing > 0 && !args.strict {
        eprintln!(
            "note: {} entr{} not in cache (treated as warnings; \
             pass --strict to fail the run on missing too)",
            report.missing,
            if report.missing == 1 { "y" } else { "ies" }
        );
    }
    let fatal = if args.strict {
        !report.is_clean()
    } else {
        report.mismatched > 0
    };
    if fatal {
        std::process::exit(1);
    }
    Ok(())
}

fn default_cargo_home() -> Result<PathBuf> {
    // `CARGO_HOME` is the canonical override; cargo respects it
    // everywhere. Default is `~/.cargo` on Unix and `%USERPROFILE%
    // \.cargo` on Windows. The verifier walks `<cargo_home>/
    // registry/cache/*/` for the .crate tarballs.
    if let Some(p) = std::env::var_os("CARGO_HOME") {
        return Ok(PathBuf::from(p));
    }
    Ok(home_or_userprofile()?.join(".cargo"))
}

fn home_or_userprofile() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!("neither $HOME nor $USERPROFILE set — pass --cache explicitly")
        })
}

fn local_app_data() -> Result<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("$LOCALAPPDATA not set — pass --cache explicitly"))
}

fn default_pnpm_store_root() -> Result<PathBuf> {
    // pnpm settings docs: storeDir defaults are
    //   Linux:   ~/.local/share/pnpm/store
    //   macOS:   ~/Library/pnpm/store
    //   Windows: %LOCALAPPDATA%\pnpm\store
    // pnpm appends a STORE_VERSION segment itself. v8/v9/v10 use
    // `v3`; v11+ uses `v11` (and ships a SQLite `index.db` we don't
    // yet read — surfaces as `Unsupported`). Prefer the highest
    // version directory present so a user on v11 gets a clear
    // "not yet supported" message rather than a "store missing"
    // false negative; fall back to v3 otherwise. Override with
    // `--cache` when the layout is non-default.
    let base = if cfg!(target_os = "windows") {
        local_app_data()?.join("pnpm").join("store")
    } else if cfg!(target_os = "macos") {
        home_or_userprofile()?
            .join("Library")
            .join("pnpm")
            .join("store")
    } else {
        home_or_userprofile()?
            .join(".local")
            .join("share")
            .join("pnpm")
            .join("store")
    };
    let v11 = base.join("v11");
    if v11.is_dir() {
        return Ok(v11);
    }
    Ok(base.join("v3"))
}

fn default_npm_cacache_root() -> Result<PathBuf> {
    // npm puts cacache at `~/.npm/_cacache` on Linux/macOS and at
    // `%LOCALAPPDATA%\npm-cache\_cacache` on Windows. Override with
    // `--cache` if your runner uses a non-default location.
    if cfg!(target_os = "windows") {
        return Ok(local_app_data()?.join("npm-cache").join("_cacache"));
    }
    Ok(home_or_userprofile()?.join(".npm").join("_cacache"))
}

fn run_actions_audit(args: ActionsAuditArgs) -> Result<()> {
    use sakimori_core::actions::{
        Finding, Severity, Summary, WorkflowFinding, audit_workflow_yaml, audit_yaml,
    };
    use serde::Serialize;

    #[derive(Serialize)]
    struct PerFile<'a> {
        file: &'a std::path::Path,
        findings: &'a [Finding],
        workflow_findings: &'a [WorkflowFinding],
        summary: Summary,
    }

    let mut all: Vec<(PathBuf, Vec<Finding>, Vec<WorkflowFinding>)> = Vec::new();
    for path in &args.files {
        let yaml =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let findings = audit_yaml(&yaml).with_context(|| format!("auditing {}", path.display()))?;
        let workflow_findings = audit_workflow_yaml(&yaml)
            .with_context(|| format!("auditing workflow rules in {}", path.display()))?;
        all.push((path.clone(), findings, workflow_findings));
    }

    // `--strict` rewrites Warn → Error in-place so both the printed
    // output and the exit code reflect the user's choice.
    if args.strict {
        for (_, findings, _) in &mut all {
            for f in findings {
                if f.severity == Severity::Warn {
                    f.severity = Severity::Error;
                }
            }
        }
    }

    // `--resolve` is opt-in because it goes online. The same
    // GithubResolver instance is reused across all files so its
    // internal `GITHUB_TOKEN` env read happens once and the cache
    // sees the most repeated `actions/checkout@v4` situation.
    if args.resolve {
        let resolver = sakimori_core::actions::GithubResolver::new(format!(
            "sakimori/{}",
            env!("CARGO_PKG_VERSION")
        ));
        for (_, findings, _) in &mut all {
            sakimori_core::actions::resolve_all(findings, &resolver);
        }
    }

    let mut blocking = 0usize;
    match args.format {
        ActionsFormat::Json => {
            let payload: Vec<PerFile<'_>> = all
                .iter()
                .map(|(p, f, wf)| PerFile {
                    file: p.as_path(),
                    findings: f,
                    workflow_findings: wf,
                    summary: Summary::from_findings(f),
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&payload)?);
            blocking = all
                .iter()
                .flat_map(|(_, f, _)| f.iter())
                .filter(|f| f.is_blocking())
                .count()
                + all
                    .iter()
                    .flat_map(|(_, _, wf)| wf.iter())
                    .filter(|w| matches!(w.severity, Severity::Error))
                    .count();
        }
        ActionsFormat::Text => {
            for (path, findings, workflow_findings) in &all {
                let summary = Summary::from_findings(findings);
                println!(
                    "{}  ({} ok, {} warn, {} error)",
                    path.display(),
                    summary.ok,
                    summary.warn,
                    summary.error
                );
                for f in findings {
                    if matches!(f.severity, Severity::Ok) {
                        continue;
                    }
                    let tag = match f.severity {
                        Severity::Error => "ERROR",
                        Severity::Warn => "warn ",
                        Severity::Ok => "ok   ",
                    };
                    let where_ = match &f.step {
                        Some(name) => format!("{}/{name}", f.job),
                        None => f.job.clone(),
                    };
                    println!("  {tag}  {where_}: {}", f.message);
                    // Surface the resolved SHA (or the lookup error)
                    // on a dedicated indented line — keeps the
                    // primary message readable while still showing
                    // the actionable suggestion.
                    if let Some(sha) = &f.resolved_sha {
                        println!("         → resolved: {sha}");
                    } else if let Some(err) = &f.resolve_error {
                        println!("         → resolve failed: {err}");
                    }
                    if f.is_blocking() {
                        blocking += 1;
                    }
                }
                for wf in workflow_findings {
                    let tag = match wf.severity {
                        Severity::Error => "ERROR",
                        Severity::Warn => "warn ",
                        Severity::Ok => "ok   ",
                    };
                    println!("  {tag}  [{rule}] {msg}", rule = wf.rule, msg = wf.message);
                    for w in &wf.cache_writers {
                        let where_ = match &w.step {
                            Some(name) => format!("{}/{name}", w.job),
                            None => w.job.clone(),
                        };
                        println!(
                            "         · {where_} ({uses}): {r}",
                            uses = w.uses,
                            r = w.reason
                        );
                    }
                    for c in &wf.untrusted_checkouts {
                        let where_ = match &c.step {
                            Some(name) => format!("{}/{name}", c.job),
                            None => c.job.clone(),
                        };
                        println!(
                            "         · {where_} ({uses}): ref = `{r}`",
                            uses = c.uses,
                            r = c.reference
                        );
                    }
                    if matches!(wf.severity, Severity::Error) {
                        blocking += 1;
                    }
                }
            }
        }
    }

    if blocking > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn run_actions_audit_repo(args: ActionsAuditRepoArgs) -> Result<()> {
    use sakimori_core::actions::{
        Finding, Severity, Summary, WorkflowFinding, audit_workflow_yaml, audit_yaml,
    };
    use sakimori_core::codeowners;
    use serde::Serialize;
    use std::path::Path;

    let workflows_dir = args.root.join(".github").join("workflows");
    let mut files: Vec<PathBuf> = Vec::new();
    if workflows_dir.is_dir() {
        for entry in std::fs::read_dir(&workflows_dir)
            .with_context(|| format!("reading {}", workflows_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if matches!(ext.to_ascii_lowercase().as_str(), "yml" | "yaml") {
                files.push(path);
            }
        }
        files.sort();
    }

    let mut per_file: Vec<(PathBuf, Vec<Finding>, Vec<WorkflowFinding>)> = Vec::new();
    for path in &files {
        let yaml =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut findings =
            audit_yaml(&yaml).with_context(|| format!("auditing {}", path.display()))?;
        let workflow_findings = audit_workflow_yaml(&yaml)
            .with_context(|| format!("auditing workflow rules in {}", path.display()))?;
        if args.strict {
            for f in &mut findings {
                if f.severity == Severity::Warn {
                    f.severity = Severity::Error;
                }
            }
        }
        per_file.push((path.clone(), findings, workflow_findings));
    }

    let coverage = codeowners::audit_repo(&args.root)?;

    // The CODEOWNERS finding is a singleton — either the rule is
    // satisfied (Ok), satisfied at the broader `.github/` level only
    // (Warn-ish "fine but consider tightening to workflows/" — we
    // collapse this into Ok for the lint), or unsatisfied (Warn /
    // Error per `--strict-codeowners`).
    let codeowners_status = if coverage.workflows_covered() {
        CoStatus::Ok
    } else if args.strict_codeowners {
        CoStatus::Error
    } else {
        CoStatus::Warn
    };

    #[derive(Serialize)]
    struct PerFile<'a> {
        file: &'a Path,
        findings: &'a [Finding],
        workflow_findings: &'a [WorkflowFinding],
        summary: Summary,
    }
    #[derive(Serialize)]
    struct CodeownersReport<'a> {
        source: Option<&'a Path>,
        workflows_covered: bool,
        github_covered: bool,
        workflows_rule: Option<&'a codeowners::Rule>,
        github_rule: Option<&'a codeowners::Rule>,
        status: &'static str,
        message: String,
    }
    #[derive(Serialize)]
    struct RepoReport<'a> {
        root: &'a Path,
        files: Vec<PerFile<'a>>,
        codeowners: CodeownersReport<'a>,
    }

    let co_message = describe_codeowners(&coverage);
    let report = RepoReport {
        root: &args.root,
        files: per_file
            .iter()
            .map(|(p, f, wf)| PerFile {
                file: p.as_path(),
                findings: f,
                workflow_findings: wf,
                summary: Summary::from_findings(f),
            })
            .collect(),
        codeowners: CodeownersReport {
            source: coverage.source.as_deref(),
            workflows_covered: coverage.workflows_covered(),
            github_covered: coverage.github_covered(),
            workflows_rule: coverage.workflows_rule.as_ref(),
            github_rule: coverage.github_rule.as_ref(),
            status: codeowners_status.label(),
            message: co_message.clone(),
        },
    };

    let mut blocking = 0usize;
    match args.format {
        ActionsFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ActionsFormat::Text => {
            for (path, findings, wfs) in &per_file {
                let summary = Summary::from_findings(findings);
                println!(
                    "{}  ({} ok, {} warn, {} error)",
                    path.display(),
                    summary.ok,
                    summary.warn,
                    summary.error
                );
                for f in findings {
                    if matches!(f.severity, Severity::Ok) {
                        continue;
                    }
                    let tag = match f.severity {
                        Severity::Error => "ERROR",
                        Severity::Warn => "warn ",
                        Severity::Ok => "ok   ",
                    };
                    let where_ = match &f.step {
                        Some(name) => format!("{}/{name}", f.job),
                        None => f.job.clone(),
                    };
                    println!("  {tag}  {where_}: {}", f.message);
                }
                for wf in wfs {
                    let tag = match wf.severity {
                        Severity::Error => "ERROR",
                        Severity::Warn => "warn ",
                        Severity::Ok => "ok   ",
                    };
                    println!("  {tag}  [{rule}] {msg}", rule = wf.rule, msg = wf.message);
                }
            }
            let co_tag = match codeowners_status {
                CoStatus::Ok => "ok   ",
                CoStatus::Warn => "warn ",
                CoStatus::Error => "ERROR",
            };
            println!("CODEOWNERS  {co_tag}  {co_message}");
        }
    }

    for (_, findings, wfs) in &per_file {
        blocking += findings.iter().filter(|f| f.is_blocking()).count();
        blocking += wfs
            .iter()
            .filter(|w| matches!(w.severity, Severity::Error))
            .count();
    }
    if matches!(codeowners_status, CoStatus::Error) {
        blocking += 1;
    }

    if blocking > 0 {
        std::process::exit(1);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum CoStatus {
    Ok,
    Warn,
    Error,
}

impl CoStatus {
    fn label(&self) -> &'static str {
        match self {
            CoStatus::Ok => "ok",
            CoStatus::Warn => "warn",
            CoStatus::Error => "error",
        }
    }
}

fn describe_codeowners(c: &sakimori_core::codeowners::Coverage) -> String {
    match (&c.source, c.workflows_covered(), c.github_covered()) {
        (None, _, _) => "no CODEOWNERS file found at .github/CODEOWNERS, CODEOWNERS, or \
             docs/CODEOWNERS — add one with a rule like `.github/ @your-org/security` to require \
             a reviewer on every workflow change"
            .to_string(),
        (Some(src), false, _) => format!(
            "{} exists but no rule with owners covers `.github/workflows/` — any maintainer can \
             merge a workflow change unreviewed. Add e.g. `.github/ @your-org/security`.",
            src.display()
        ),
        (Some(src), true, _) => {
            let rule = c.workflows_rule.as_ref().unwrap();
            format!(
                "{} covers `.github/workflows/` via `{}` (line {}) → {}",
                src.display(),
                rule.pattern,
                rule.line_no,
                rule.owners.join(" ")
            )
        }
    }
}

fn run_policy_suggest(args: PolicySuggestArgs) -> Result<()> {
    let suggestion = if args.log.as_os_str() == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("reading audit log from stdin")?;
        let samples = sakimori_core::suggest::parse_log_samples(&buf)
            .context("parsing audit log JSON from stdin")?;
        sakimori_core::suggest::suggest_from_samples(&samples)
    } else {
        sakimori_core::suggest::suggest_from_log(&args.log)?
    };
    let yaml = sakimori_core::suggest::format_yaml(&suggestion)?;
    match args.output {
        Some(path) => {
            std::fs::write(&path, yaml)
                .with_context(|| format!("writing suggested policy to {}", path.display()))?;
            eprintln!("sakimori: wrote suggested policy to {}", path.display());
        }
        None => print!("{yaml}"),
    }
    Ok(())
}

fn run_policy_preset(args: PolicyPresetArgs) -> Result<()> {
    let preset = sakimori_core::presets::Preset::parse(&args.name).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown preset {:?}; known presets: persistence, cloud-secret-egress",
            args.name
        )
    })?;
    let yaml = sakimori_core::presets::render(preset, args.home.as_deref());
    match args.output {
        Some(path) => {
            std::fs::write(&path, &yaml)
                .with_context(|| format!("writing preset to {}", path.display()))?;
            eprintln!(
                "sakimori: wrote {} preset to {}",
                preset.name(),
                path.display()
            );
        }
        None => print!("{yaml}"),
    }
    Ok(())
}

fn run_install_gate_install(args: InstallGateInstallArgs) -> Result<()> {
    let shell = args
        .shell
        .map(crate::install_gate::Shell::from)
        .unwrap_or_else(crate::install_gate::detect_shell_from_env);
    let rc = resolve_rc_path(args.rc, shell)?;
    // Ensure parent dir exists (fish's config.fish lives under
    // `~/.config/fish/` which may not exist on a fresh system).
    if let Some(parent) = rc.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let before = std::fs::read_to_string(&rc).unwrap_or_default();
    let after = crate::install_gate::install_block(&before, shell);
    if before == after {
        println!("sakimori: install-gate already present in {}", rc.display());
        return Ok(());
    }
    std::fs::write(&rc, &after).with_context(|| format!("writing {}", rc.display()))?;
    println!(
        "sakimori: install-gate appended to {}\n\n\
         Open a new shell (or `source {}`) and make sure the proxy \
         is running:\n\n    sakimori proxy start &\n    sakimori proxy install-ca\n",
        rc.display(),
        rc.display(),
    );
    Ok(())
}

fn run_install_gate_uninstall(args: InstallGateInstallArgs) -> Result<()> {
    let shell = args
        .shell
        .map(crate::install_gate::Shell::from)
        .unwrap_or_else(crate::install_gate::detect_shell_from_env);
    let rc = resolve_rc_path(args.rc, shell)?;
    let before = match std::fs::read_to_string(&rc) {
        Ok(s) => s,
        Err(_) => {
            println!("sakimori: nothing to do — {} does not exist", rc.display());
            return Ok(());
        }
    };
    if !crate::install_gate::has_block(&before) {
        println!("sakimori: no install-gate block found in {}", rc.display());
        return Ok(());
    }
    let after = crate::install_gate::strip_block(&before);
    std::fs::write(&rc, &after).with_context(|| format!("writing {}", rc.display()))?;
    println!("sakimori: install-gate removed from {}", rc.display());
    Ok(())
}

fn resolve_rc_path(
    explicit: Option<PathBuf>,
    shell: crate::install_gate::Shell,
) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    // $HOME on Unix, %USERPROFILE% on Windows (PowerShell).
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("$HOME / %USERPROFILE% is unset; pass --rc explicitly"))?;
    Ok(crate::install_gate::default_rc_path(&home, shell))
}

async fn run_supervised(args: RunArgs) -> Result<()> {
    let policy = match &args.policy {
        Some(p) => policy::Policy::from_file(p)?,
        None => policy::Policy::permissive_audit(),
    };
    let mode = match args.mode {
        Some(Mode::Audit) => policy::Mode::Audit,
        Some(Mode::Block) => policy::Mode::Block,
        None => policy.mode,
    };
    policy.validate(mode)?;
    for w in policy.lint() {
        log::warn!("{w}");
    }
    log::info!(
        "starting sakimori (mode={:?}, command={:?})",
        mode,
        args.command
    );

    // Workspace tamper baseline. Taken BEFORE the eBPF supervisor
    // starts so we don't accidentally hash any files the supervisor
    // itself writes (cgroup state etc.). Off-path failure is a hard
    // error — if the user explicitly asked for tamper detection, a
    // missing snapshot would silently make every later diff "clean".
    let baseline = match &args.snapshot_workspace {
        Some(dir) => {
            let opts = sakimori_core::tamper::Options {
                skip_extra: args.snapshot_skip.clone(),
                ..Default::default()
            };
            let snap = sakimori_core::tamper::Snapshot::take(dir, &opts)
                .with_context(|| format!("snapshotting workspace {} before run", dir.display()))?;
            log::info!(
                "workspace baseline: {} files under {}",
                snap.files.len(),
                dir.display()
            );
            Some(snap)
        }
        None => None,
    };

    let supervised = loader::Supervisor::start(
        policy.clone(),
        mode,
        std::time::Duration::from_secs(args.dns_refresh_interval),
    )
    .await?;
    let exit = supervised.run_child(&args.command).await?;
    let mut stats = supervised.shutdown().await?;

    // After-snapshot + diff. Errors here are non-fatal: the audit
    // log + summary still go out, just without `workspace_drift`.
    let drift = if let Some(baseline) = baseline.as_ref() {
        let dir = args
            .snapshot_workspace
            .as_ref()
            .expect("baseline implies dir");
        let opts = sakimori_core::tamper::Options {
            skip_extra: args.snapshot_skip.clone(),
            ..Default::default()
        };
        match sakimori_core::tamper::Snapshot::take(dir, &opts) {
            Ok(after) => Some(sakimori_core::tamper::diff(baseline, &after)),
            Err(e) => {
                log::warn!("post-run workspace snapshot failed: {e:#} — skipping drift section");
                None
            }
        }
    } else {
        None
    };

    // Best-effort PTR enrichment so the HTML report shows hostnames
    // next to raw IPs. Failures are silent — the report is still
    // useful without resolved names, and we don't want to block the
    // CI step on flaky DNS.
    crate::resolve_hostnames::resolve(&mut stats).await;

    let ioc_report = drift.as_ref().map(|d| {
        let paths: Vec<&std::path::Path> = d
            .added
            .iter()
            .map(|p| p.as_path())
            .chain(d.modified.iter().map(|m| m.path.as_path()))
            .collect();
        sakimori_core::iocs::Report::new(sakimori_core::iocs::scan_paths(paths.iter().copied()))
    });

    let command_str = args.command.join(" ");
    let report_args = ReportArgs {
        log: &args.log,
        summary: args.summary.as_deref(),
        html: args.html.as_deref(),
        command: command_str.as_str(),
        mode,
        policy: &policy,
        workspace_drift: drift.as_ref().filter(|d| !d.is_clean()),
        workspace_iocs: ioc_report.as_ref().filter(|r| !r.is_clean()),
    };
    sakimori_core::report::write(&report_args, &stats)?;

    let drift_violation = drift.as_ref().map(|d| !d.is_clean()).unwrap_or(false);
    let ioc_high = ioc_report.as_ref().map(|r| r.has_high()).unwrap_or(false);

    if stats.denied > 0 && matches!(mode, policy::Mode::Block) {
        // GitHub Actions error annotation — renders as a red banner on the
        // step UI so block-mode failures don't hide in the log.
        eprintln!(
            "::error title=sakimori::policy violation: {} events denied in block mode",
            stats.denied
        );
        std::process::exit(1);
    }
    if drift_violation && matches!(mode, policy::Mode::Block) {
        let n = drift.as_ref().map(|d| d.total()).unwrap_or(0);
        eprintln!(
            "::error title=sakimori::workspace tamper detected: {n} files added/modified/removed during the supervised step"
        );
        std::process::exit(1);
    }
    // High-severity IOC fails the supervised step regardless of mode —
    // see daemon.rs for the matching policy and rationale.
    if ioc_high {
        let n = ioc_report.as_ref().map(|r| r.findings.len()).unwrap_or(0);
        eprintln!(
            "::error title=sakimori::known-IOC hit: {n} workspace path(s) match a known supply-chain campaign fingerprint"
        );
        std::process::exit(1);
    }
    std::process::exit(exit);
}

fn run_install_daemon(args: ProxyDaemonArgs) -> Result<()> {
    use sakimori_proxy::daemon::{
        DaemonBackend, DaemonInputs, current_exe_canonical, render, write_unit,
    };
    let backend = DaemonBackend::detect()
        .ok_or_else(|| anyhow::anyhow!("no daemon backend for this OS; see README"))?;
    let binary = match args.binary {
        Some(p) => p,
        None => current_exe_canonical()
            .ok_or_else(|| anyhow::anyhow!("couldn't resolve current exe; pass --binary"))?,
    };
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("$HOME / %USERPROFILE% is unset"))?;
    let plan = render(
        backend,
        &DaemonInputs {
            binary_path: binary,
            listen: args.listen,
            min_age: args.min_age,
            home,
        },
    );
    write_unit(&plan).with_context(|| format!("writing {}", plan.unit_path.display()))?;
    println!(
        "sakimori: wrote daemon unit to {}\n\n\
         Activate it with:\n\n    {}\n\n\
         (On macOS you may be prompted by System Settings to allow \
         background items the first time.)",
        plan.unit_path.display(),
        plan.activate_command,
    );
    Ok(())
}

fn run_uninstall_daemon(args: ProxyDaemonArgs) -> Result<()> {
    use sakimori_proxy::daemon::{
        DaemonBackend, DaemonInputs, current_exe_canonical, remove_unit, render,
    };
    let backend = DaemonBackend::detect()
        .ok_or_else(|| anyhow::anyhow!("no daemon backend for this OS; see README"))?;
    let binary = args
        .binary
        .or_else(current_exe_canonical)
        .unwrap_or_else(|| PathBuf::from("sakimori"));
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("$HOME / %USERPROFILE% is unset"))?;
    let plan = render(
        backend,
        &DaemonInputs {
            binary_path: binary,
            listen: args.listen,
            min_age: args.min_age,
            home,
        },
    );
    remove_unit(&plan.unit_path)
        .with_context(|| format!("removing {}", plan.unit_path.display()))?;
    println!(
        "sakimori: removed {} (if it existed).\n\n\
         Deactivate the running instance with:\n\n    {}\n",
        plan.unit_path.display(),
        plan.deactivate_command,
    );
    Ok(())
}

fn run_doctor(args: DoctorArgs) -> Result<()> {
    let ca_files = ca_files_for(args.config_dir)?;
    let expected_https_proxy = format!("http://{}", args.listen);
    let rc_path = args.rc.or_else(|| {
        let home = std::env::var_os("HOME").map(PathBuf::from)?;
        let shell = crate::install_gate::detect_shell_from_env();
        Some(crate::install_gate::default_rc_path(&home, shell))
    });
    let daemon_unit_path = std::env::var_os("HOME")
        .map(PathBuf::from)
        .and_then(|home| {
            use sakimori_proxy::daemon::{DaemonBackend, DaemonInputs, render};
            let backend = DaemonBackend::detect()?;
            let plan = render(
                backend,
                &DaemonInputs {
                    binary_path: PathBuf::from("sakimori"),
                    listen: args.listen,
                    min_age: "7d".into(),
                    home,
                },
            );
            Some(plan.unit_path)
        });
    let inputs = crate::doctor::DoctorInputs {
        ca_cert: ca_files.cert_pem.clone(),
        ca_key: ca_files.key_pem.clone(),
        proxy_addr: args.listen,
        https_proxy_env: std::env::var("HTTPS_PROXY")
            .ok()
            .or_else(|| std::env::var("https_proxy").ok()),
        expected_https_proxy,
        rc_path,
        daemon_unit_path,
        daemon_pidfile: args.daemon_pidfile,
        kprobe_override: Some(crate::kprobe_override::detect()),
    };
    let results = crate::doctor::run_checks(&inputs);
    print!("{}", crate::doctor::render_report(&results));
    std::process::exit(crate::doctor::exit_code(&results));
}
