//! Windows-specific runtime.

use std::{
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use sakimori_core::{
    Event, Policy, Stats,
    matcher::{ExecMatcher, FileMatcher},
    policy::{self, DefaultDecision, Mode},
    report::ReportArgs,
};

use crate::firewall::{FirewallGuard, resolve_program};
use ferrisetw::{
    EventRecord, parser::Parser as EtwParser, provider::Provider,
    schema_locator::SchemaLocator, trace::UserTrace,
};

// Modern public ETW providers (Windows 8+). Each UserTrace session with a
// unique name can consume them concurrently — no singleton conflicts like
// the legacy NT Kernel Logger.
const PROVIDER_KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";
const PROVIDER_KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
const PROVIDER_KERNEL_FILE: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";

#[derive(Debug, Clone, ValueEnum)]
pub enum CliMode {
    Audit,
    Block,
}

#[derive(Debug, Parser)]
#[command(
    name = "sakimori-win",
    version,
    about = "Windows ETW-based audit for sakimori policies"
)]
pub struct Cli {
    /// Policy file (YAML or JSON). Optional — missing policy means a
    /// permissive audit run (log everything, deny nothing).
    #[arg(long, short = 'p', env = "SAKIMORI_POLICY")]
    pub policy: Option<PathBuf>,

    /// Override the policy's `mode`.
    #[arg(long, value_enum)]
    pub mode: Option<CliMode>,

    /// Where to write the JSON audit log. `-` for stdout.
    #[arg(long, default_value = "-")]
    pub log: String,

    /// Optional path to write a human-readable summary (suitable for
    /// `$GITHUB_STEP_SUMMARY`).
    #[arg(long, env = "GITHUB_STEP_SUMMARY")]
    pub summary: Option<PathBuf>,

    /// Optional path to write a self-contained HTML audit report.
    #[arg(long)]
    pub html: Option<PathBuf>,

    /// Command + args to execute under supervision. Prefix with `--` if
    /// your command starts with a dash.
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

pub fn run() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Simple top-level dispatch for the `deps` subcommand — keeps the
    // existing audit-run CLI shape untouched.
    let raw: Vec<String> = std::env::args().collect();
    if raw.get(1).map(|s| s.as_str()) == Some("deps") {
        return run_deps(&raw);
    }

    let cli = Cli::parse();

    let policy = match &cli.policy {
        Some(p) => Policy::from_file(p).with_context(|| format!("loading {}", p.display()))?,
        None => Policy::permissive_audit(),
    };
    let mode = match cli.mode {
        Some(CliMode::Audit) => Mode::Audit,
        Some(CliMode::Block) => Mode::Block,
        None => policy.mode,
    };
    policy.validate(mode)?;
    for w in policy.lint() {
        log::warn!("{w}");
    }

    let file_matcher = Arc::new(FileMatcher::from_policy(&policy.file));
    let exec_matcher = Arc::new(ExecMatcher::from_policy(&policy.process));
    // Pre-resolve network.deny IPs so the connect-event callback can tag
    // matches quickly without blocking on DNS.
    let denied_addrs: Arc<Vec<String>> = Arc::new(
        policy
            .network
            .deny
            .iter()
            .flat_map(|r| crate::firewall::resolve_rule_public(r))
            .collect(),
    );
    let stats = Arc::new(Mutex::new(Stats::default()));

    // Callbacks need 'static + Send + Sync. Clone the Arcs into each closure.
    let process_cb = {
        let stats = Arc::clone(&stats);
        let exec_matcher = Arc::clone(&exec_matcher);
        move |record: &EventRecord, schema_locator: &SchemaLocator| {
            handle_process_event(record, schema_locator, &stats, &exec_matcher);
        }
    };
    let network_cb = {
        let stats = Arc::clone(&stats);
        let denied = Arc::clone(&denied_addrs);
        move |record: &EventRecord, schema_locator: &SchemaLocator| {
            handle_network_event(record, schema_locator, &stats, &denied);
        }
    };
    let file_cb = {
        let stats = Arc::clone(&stats);
        let file_matcher = Arc::clone(&file_matcher);
        move |record: &EventRecord, schema_locator: &SchemaLocator| {
            handle_file_event(record, schema_locator, &stats, &file_matcher);
        }
    };

    // `.any(0xFFFFFFFFFFFFFFFF)` = MatchAnyKeyword all-set, which enables
    // every event class the provider publishes. Without this, ETW treats
    // keyword=0 as "match nothing" for most providers and only the odd
    // event (e.g. one process start) leaks through.
    const ALL_KEYWORDS: u64 = u64::MAX;
    let process_provider = Provider::by_guid(PROVIDER_KERNEL_PROCESS)
        .any(ALL_KEYWORDS)
        .add_callback(process_cb)
        .build();
    let network_provider = Provider::by_guid(PROVIDER_KERNEL_NETWORK)
        .any(ALL_KEYWORDS)
        .add_callback(network_cb)
        .build();
    let file_provider = Provider::by_guid(PROVIDER_KERNEL_FILE)
        .any(ALL_KEYWORDS)
        .add_callback(file_cb)
        .build();

    let session_name = format!("sakimori-{}", std::process::id());
    let _trace = UserTrace::new()
        .named(session_name.clone())
        .enable(process_provider)
        .enable(network_provider)
        .enable(file_provider)
        .start_and_process()
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to start ETW session '{session_name}': {e:?} \
                 (requires Administrator)"
            )
        })?;

    // Warm-up so the first child events aren't racing provider setup.
    // ETW takes ~300ms to actually start delivering events in practice.
    thread::sleep(Duration::from_millis(500));

    log::info!(
        "starting sakimori-win (mode={:?}, command={:?})",
        mode,
        cli.command
    );
    let (program, rest) = cli
        .command
        .split_first()
        .context("empty command after arg parse")?;

    // --- network block (Windows Defender Firewall) ---
    // Only in `mode: block` do we actually install rules. Audit mode
    // tags denied events in the JSON log but doesn't touch the OS fw.
    let _fw_guard = if matches!(mode, Mode::Block) {
        if matches!(policy.network.default, DefaultDecision::Deny) {
            log::warn!(
                "network.default=deny on Windows is audit-only — Windows \
                 Defender Firewall block rules always win over allow rules, \
                 so an 'allowlist' pattern can't be expressed safely without \
                 changing the system-wide default-outbound policy. Use \
                 network.deny: [...] to block specific endpoints instead."
            );
        }
        let exe_path = resolve_program(program);
        let exe_str = exe_path.to_string_lossy().to_string();
        log::info!("installing firewall block rules for {exe_str}");
        match FirewallGuard::apply(&policy.network, &exe_str) {
            Ok(guard) => guard,
            Err(e) => {
                // ::error:: annotation so CI turns red clearly.
                eprintln!(
                    "::error title=sakimori::failed to install firewall rules in block mode: {e:#}"
                );
                return Err(e);
            }
        }
    } else {
        None
    };

    // Rust's `Command::new` on Windows does NOT honour PATHEXT, so a
    // bare `pnpm` (a `.cmd` shim from pnpm/action-setup), `yarn`,
    // `npm`, etc. would fail to spawn even though `where pnpm` finds
    // them. Resolve via `where`-backed lookup so the supervised
    // command matches what users see in their shell.
    let resolved = resolve_program(program);
    let mut child_cmd = Command::new(&resolved);
    child_cmd.args(rest);

    // Apply env policy before spawn (real prevention — child's process
    // env block is the one we hand it, not the inherited one).
    if policy.env.is_active() {
        let parent: Vec<(String, String)> = std::env::vars().collect();
        let (kept, removed) = policy.env.resolve(parent);
        child_cmd.env_clear();
        child_cmd.envs(kept);
        if !removed.is_empty() {
            log::info!(
                "env policy: stripped {} variable(s) from child env: {}",
                removed.len(),
                removed.join(", ")
            );
        }
    }

    let status = child_cmd
        .status()
        .with_context(|| {
            format!(
                "spawning {program}{}",
                if resolved.as_os_str() == std::ffi::OsStr::new(program) {
                    ": program not found on PATH (PATHEXT-aware lookup via `where` returned nothing)"
                } else {
                    ""
                }
            )
        })?;

    // Drain tail events. ETW is async; bursts take a second or so to
    // percolate through the buffering path into our callback.
    thread::sleep(Duration::from_millis(1000));

    let final_stats = stats.lock().unwrap().clone();

    let command_str = cli.command.join(" ");
    let report_args = ReportArgs {
        log: &cli.log,
        summary: cli.summary.as_deref(),
        html: cli.html.as_deref(),
        command: command_str.as_str(),
        mode,
        policy: &policy,
    };
    sakimori_core::report::write(&report_args, &final_stats)?;

    if final_stats.denied > 0 && matches!(mode, policy::Mode::Block) {
        eprintln!(
            "::error title=sakimori::policy violation: {} events denied in block mode",
            final_stats.denied
        );
        std::process::exit(1);
    }
    std::process::exit(status.code().unwrap_or(1));
}

// ---------------------------------------------------------------------------
// ETW event handlers
// ---------------------------------------------------------------------------

fn handle_process_event(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    stats: &Mutex<Stats>,
    exec_matcher: &ExecMatcher,
) {
    debug_log_event_id("process", record.event_id());
    if record.event_id() != 1 {
        return;
    }
    let Ok(schema) = schema_locator.event_schema(record) else {
        return;
    };
    let parser = EtwParser::create(record, &schema);

    // Field names vary between Windows builds. Try the ones we've seen:
    let filename = try_string(&parser, &["ImageName", "Image", "ImageFileName", "FileName"]);
    let argv0 = try_string(&parser, &["CommandLine", "Commandline", "Args"]);
    let pid: u32 = parser
        .try_parse::<u32>("ProcessID")
        .or_else(|_| parser.try_parse::<u32>("PID"))
        .unwrap_or(0);

    debug_log_process_start(&filename, &argv0, pid);

    if filename.is_empty() && argv0.is_empty() {
        return;
    }

    let denied = exec_matcher.is_denied(&filename, &argv0);
    let ev = Event::Exec {
        pid,
        uid: 0,
        comm: basename(if filename.is_empty() { &argv0 } else { &filename }),
        filename,
        argv0,
        denied,
        source: None,
    };
    stats.lock().unwrap().ingest(ev);
}

fn try_string(parser: &EtwParser, names: &[&str]) -> String {
    for n in names {
        if let Ok(s) = parser.try_parse::<String>(n) {
            if !s.is_empty() {
                return s;
            }
        }
    }
    String::new()
}

fn debug_log_process_start(filename: &str, argv0: &str, pid: u32) {
    use std::sync::OnceLock;
    static LOGGED: OnceLock<std::sync::Mutex<bool>> = OnceLock::new();
    let m = LOGGED.get_or_init(|| std::sync::Mutex::new(false));
    let mut seen = m.lock().unwrap();
    if !*seen {
        *seen = true;
        eprintln!(
            "sakimori-win: first ProcessStart event: pid={pid} filename={filename:?} argv0={argv0:?}"
        );
    }
}

fn handle_network_event(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    stats: &Mutex<Stats>,
    denied_addrs: &[String],
) {
    debug_log_event_id("network", record.event_id());
    let Ok(schema) = schema_locator.event_schema(record) else {
        return;
    };
    let parser = EtwParser::create(record, &schema);

    // Some events have "daddr", others "DestinationAddress". Try both.
    let daddr: String = parser
        .try_parse::<String>("daddr")
        .or_else(|_| parser.try_parse::<String>("DestinationAddress"))
        .unwrap_or_default();
    if daddr.is_empty() {
        return;
    }
    let pid: u32 = parser
        .try_parse::<u32>("PID")
        .or_else(|_| parser.try_parse::<u32>("ProcessID"))
        .unwrap_or(0);
    let dport: u16 = parser
        .try_parse::<u16>("dport")
        .or_else(|_| parser.try_parse::<u16>("DestinationPort"))
        .unwrap_or(0);

    // Match on the textual daddr. Good enough for IP literals (most
    // common deny target); for CIDR / hostname-resolved entries we
    // already expanded to a flat list at startup.
    let denied = denied_addrs.iter().any(|a| a == &daddr);

    let ev = Event::Connect {
        pid,
        uid: 0,
        comm: String::new(),
        daddr,
        dport,
        protocol: 6,
        denied,
        hostname: None,
        source: None,
    };
    stats.lock().unwrap().ingest(ev);
}

fn handle_file_event(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    stats: &Mutex<Stats>,
    file_matcher: &FileMatcher,
) {
    let Ok(schema) = schema_locator.event_schema(record) else {
        return;
    };
    let parser = EtwParser::create(record, &schema);

    let filename: String = parser.try_parse("FileName").unwrap_or_default();
    if filename.is_empty() {
        return;
    }
    let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);

    // Normalise Windows path to forward-slash so policy entries written
    // for Linux can optionally match (people using this cross-platform
    // tend to write POSIX-style rules in YAML).
    let filename_norm = filename.replace('\\', "/");
    let denied = file_matcher.is_denied(&filename_norm);

    let ev = Event::Open {
        pid,
        uid: 0,
        comm: String::new(),
        filename: filename_norm,
        flags: 0,
        denied,
        source: None,
    };
    stats.lock().unwrap().ingest(ev);
}

fn basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

/// `sakimori-win deps check ...` — parses a small clap struct and
/// forwards to the shared implementation in sakimori-core.
fn run_deps(raw: &[String]) -> Result<()> {
    #[derive(Debug, Parser)]
    #[command(name = "sakimori-win deps", no_binary_name = true)]
    struct DepsCli {
        #[command(subcommand)]
        cmd: DepsCmd,
    }
    #[derive(Debug, clap::Subcommand)]
    enum DepsCmd {
        /// Check publish ages against all dependencies in the given lockfile(s).
        Check(DepsCheckArgs),
        /// Resident watcher (stdout notifier on Windows — pipe to your
        /// preferred toast / Teams hook).
        Watch(DepsWatchArgs),
    }
    #[derive(Debug, Parser)]
    struct DepsCheckArgs {
        #[arg(required = true)]
        lockfiles: Vec<std::path::PathBuf>,
        #[arg(long, default_value = "7d")]
        min_age: String,
        #[arg(long)]
        ignore: Vec<String>,
        #[arg(long)]
        fail_on_missing: bool,
        #[arg(long)]
        no_cache: bool,
        #[arg(long)]
        cache: Option<std::path::PathBuf>,
        #[arg(long, value_enum, default_value = "text")]
        format: DepsFormatArg,
    }
    #[derive(Debug, Clone, ValueEnum)]
    enum DepsFormatArg {
        Text,
        Json,
    }

    #[derive(Debug, Parser)]
    struct DepsWatchArgs {
        #[arg(required = true)]
        roots: Vec<std::path::PathBuf>,
        #[arg(long, default_value = "7d")]
        min_age: String,
        #[arg(long)]
        ignore: Vec<String>,
        #[arg(long)]
        no_cache: bool,
        #[arg(long)]
        cache: Option<std::path::PathBuf>,
        #[arg(long, default_value_t = 800)]
        debounce_ms: u64,
        #[arg(long, default_value_t = 250)]
        tick_ms: u64,
    }

    // Drop argv[0] (binary) and argv[1] ("deps") so clap sees just the
    // subcommand tokens.
    let remainder: Vec<&str> = raw.iter().skip(2).map(|s| s.as_str()).collect();
    let parsed = DepsCli::try_parse_from(remainder).map_err(|e| anyhow::anyhow!("{e}"))?;
    match parsed.cmd {
        DepsCmd::Check(args) => {
            let exit = sakimori_core::deps::cli::run(sakimori_core::deps::cli::CliArgs {
                lockfiles: args.lockfiles,
                min_age: args.min_age,
                ignore: args.ignore,
                fail_on_missing: args.fail_on_missing,
                no_cache: args.no_cache,
                cache_path: args.cache,
                format: match args.format {
                    DepsFormatArg::Text => sakimori_core::deps::cli::Format::Text,
                    DepsFormatArg::Json => sakimori_core::deps::cli::Format::Json,
                },
                user_agent: None,
            })?;
            std::process::exit(exit);
        }
        DepsCmd::Watch(args) => {
            sakimori_core::deps::cli::run_watch(sakimori_core::deps::cli::WatchCliArgs {
                roots: args.roots,
                min_age: args.min_age,
                ignore: args.ignore,
                no_cache: args.no_cache,
                cache_path: args.cache,
                debounce_ms: args.debounce_ms,
                tick_ms: args.tick_ms,
                notifier: sakimori_core::deps::cli::WatchNotifierKind::Stdout,
                action: sakimori_core::deps::cli::WatchActionKind::Notify,
                user_agent: None,
            })?;
            Ok(())
        }
    }
}

/// Logs each distinct event id a provider emits exactly once. Helps debug
/// when a provider doesn't fire the events we expect — cheap and bounded.
fn debug_log_event_id(tag: &'static str, id: u16) {
    use std::sync::Mutex;
    use std::sync::OnceLock;
    type Seen = Mutex<std::collections::HashMap<&'static str, std::collections::HashSet<u16>>>;
    static SEEN: OnceLock<Seen> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(Default::default()));
    let mut guard = seen.lock().unwrap();
    let set = guard.entry(tag).or_default();
    if set.insert(id) {
        eprintln!("sakimori-win: provider={tag} first-seen event_id={id}");
    }
}
