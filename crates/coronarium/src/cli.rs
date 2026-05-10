use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use coronarium_core::report::ReportArgs;
use std::time::Duration;

use crate::{loader, policy};

/// Resolve the CA directory either from the `--config-dir` override or
/// the default location. Centralised so every `proxy …` subcommand
/// uses the same layout.
fn ca_files_for(dir: Option<PathBuf>) -> anyhow::Result<coronarium_proxy::ca::CaFiles> {
    Ok(match dir {
        Some(d) => coronarium_proxy::ca::CaFiles::at(d.join("coronarium")),
        None => coronarium_proxy::ca::CaFiles::at_default_location()?,
    })
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
    name = "coronarium",
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
    /// Route the user's shell through `coronarium proxy` so every
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

impl From<TyposquatMode> for coronarium_proxy::decision::TyposquatMode {
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
    Start(ProxyStartArgs),
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
    /// Consume the coronarium-hosted pre-filtered OSV mirror at
    /// `https://raw.githubusercontent.com/bokuweb/coronarium/osv-mirror-data/mal.json`.
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
    /// Use the coronarium-hosted pre-fetched top-1000-per-ecosystem
    /// list instead of the ~100-name baseline baked into the binary.
    /// Refreshes daily in the background and falls back to the
    /// baseline when the mirror is unreachable. Only meaningful with
    /// `--typosquat`.
    #[arg(long)]
    pub typosquat_mirror: bool,
    /// Override the typosquat mirror URL.
    #[arg(long)]
    pub typosquat_mirror_url: Option<String>,
    /// Override the CA/config directory. Defaults to
    /// `$XDG_CONFIG_HOME/coronarium` (or `~/.config/coronarium`).
    #[arg(long)]
    pub config_dir: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum DepsCommand {
    /// Check publish ages against all dependencies in the given lockfile(s).
    Check(DepsCheckArgs),
    /// Stay resident: watch one or more workspace roots, run `check` on
    /// every lockfile change, and surface violations via a desktop
    /// notification. Designed for `launchd` / `systemd --user`.
    Watch(DepsWatchArgs),
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
    #[arg(long, short = 'p', env = "CORONARIUM_POLICY")]
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
            let exit = coronarium_core::deps::cli::run(coronarium_core::deps::cli::CliArgs {
                lockfiles: args.lockfiles,
                min_age: args.min_age,
                ignore: args.ignore,
                fail_on_missing: args.fail_on_missing,
                no_cache: args.no_cache,
                cache_path: args.cache,
                format: match args.format {
                    DepsFormat::Text => coronarium_core::deps::cli::Format::Text,
                    DepsFormat::Json => coronarium_core::deps::cli::Format::Json,
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
            coronarium_proxy::ca::ensure_ca(&ca_files)?;
            let r = coronarium_proxy::install::install_ca(&ca_files)?;
            use coronarium_proxy::install::InstallOutcome;
            match r.outcome {
                InstallOutcome::Installed => {
                    println!(
                        "✓ coronarium root CA installed into the system trust store\n  ({})",
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
            let r = coronarium_proxy::install::uninstall_ca(&ca_files)?;
            use coronarium_proxy::install::InstallOutcome;
            match r.outcome {
                InstallOutcome::Installed => {
                    println!("✓ coronarium root CA removed from the system trust store");
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
            let cfg = coronarium_proxy::ProxyConfig {
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
                user_agent: format!("coronarium-proxy/{}", env!("CARGO_PKG_VERSION")),
                oracle: None,
            };
            coronarium_proxy::run(cfg).await?;
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
            coronarium_core::deps::cli::run_watch(coronarium_core::deps::cli::WatchCliArgs {
                roots: args.roots,
                min_age: args.min_age,
                ignore: args.ignore,
                no_cache: args.no_cache,
                cache_path: args.cache,
                debounce_ms: args.debounce_ms,
                tick_ms: args.tick_ms,
                notifier: match args.notifier {
                    DepsNotifier::Mac => coronarium_core::deps::cli::WatchNotifierKind::Mac,
                    DepsNotifier::Stdout => coronarium_core::deps::cli::WatchNotifierKind::Stdout,
                },
                action: match args.action {
                    DepsAction::Notify => coronarium_core::deps::cli::WatchActionKind::Notify,
                    DepsAction::Prompt => coronarium_core::deps::cli::WatchActionKind::Prompt,
                    DepsAction::Revert => coronarium_core::deps::cli::WatchActionKind::Revert,
                },
                user_agent: None,
            })?;
            Ok(())
        }
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
    }
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
        println!(
            "coronarium: install-gate already present in {}",
            rc.display()
        );
        return Ok(());
    }
    std::fs::write(&rc, &after).with_context(|| format!("writing {}", rc.display()))?;
    println!(
        "coronarium: install-gate appended to {}\n\n\
         Open a new shell (or `source {}`) and make sure the proxy \
         is running:\n\n    coronarium proxy start &\n    coronarium proxy install-ca\n",
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
            println!(
                "coronarium: nothing to do — {} does not exist",
                rc.display()
            );
            return Ok(());
        }
    };
    if !crate::install_gate::has_block(&before) {
        println!(
            "coronarium: no install-gate block found in {}",
            rc.display()
        );
        return Ok(());
    }
    let after = crate::install_gate::strip_block(&before);
    std::fs::write(&rc, &after).with_context(|| format!("writing {}", rc.display()))?;
    println!("coronarium: install-gate removed from {}", rc.display());
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
        "starting coronarium (mode={:?}, command={:?})",
        mode,
        args.command
    );

    let supervised = loader::Supervisor::start(
        policy.clone(),
        mode,
        std::time::Duration::from_secs(args.dns_refresh_interval),
    )
    .await?;
    let exit = supervised.run_child(&args.command).await?;
    let mut stats = supervised.shutdown().await?;

    // Best-effort PTR enrichment so the HTML report shows hostnames
    // next to raw IPs. Failures are silent — the report is still
    // useful without resolved names, and we don't want to block the
    // CI step on flaky DNS.
    crate::resolve_hostnames::resolve(&mut stats).await;

    let command_str = args.command.join(" ");
    let report_args = ReportArgs {
        log: &args.log,
        summary: args.summary.as_deref(),
        html: args.html.as_deref(),
        command: command_str.as_str(),
        mode,
        policy: &policy,
    };
    coronarium_core::report::write(&report_args, &stats)?;

    if stats.denied > 0 && matches!(mode, policy::Mode::Block) {
        // GitHub Actions error annotation — renders as a red banner on the
        // step UI so block-mode failures don't hide in the log.
        eprintln!(
            "::error title=coronarium::policy violation: {} events denied in block mode",
            stats.denied
        );
        std::process::exit(1);
    }
    std::process::exit(exit);
}

fn run_install_daemon(args: ProxyDaemonArgs) -> Result<()> {
    use coronarium_proxy::daemon::{
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
        "coronarium: wrote daemon unit to {}\n\n\
         Activate it with:\n\n    {}\n\n\
         (On macOS you may be prompted by System Settings to allow \
         background items the first time.)",
        plan.unit_path.display(),
        plan.activate_command,
    );
    Ok(())
}

fn run_uninstall_daemon(args: ProxyDaemonArgs) -> Result<()> {
    use coronarium_proxy::daemon::{
        DaemonBackend, DaemonInputs, current_exe_canonical, remove_unit, render,
    };
    let backend = DaemonBackend::detect()
        .ok_or_else(|| anyhow::anyhow!("no daemon backend for this OS; see README"))?;
    let binary = args
        .binary
        .or_else(current_exe_canonical)
        .unwrap_or_else(|| PathBuf::from("coronarium"));
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
        "coronarium: removed {} (if it existed).\n\n\
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
            use coronarium_proxy::daemon::{DaemonBackend, DaemonInputs, render};
            let backend = DaemonBackend::detect()?;
            let plan = render(
                backend,
                &DaemonInputs {
                    binary_path: PathBuf::from("coronarium"),
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
    };
    let results = crate::doctor::run_checks(&inputs);
    print!("{}", crate::doctor::render_report(&results));
    std::process::exit(crate::doctor::exit_code(&results));
}
