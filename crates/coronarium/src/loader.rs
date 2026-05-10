//! Userspace supervisor: loads the eBPF object, attaches programs, creates a
//! cgroup, spawns the child inside it, and drains the shared ring buffer.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{process::Command, sync::Mutex};

pub use coronarium_core::Stats;

use coronarium_core::matcher::{ExecMatcher, FileMatcher};

use crate::{
    cgroup::Cgroup,
    events::{self, Event},
    policy::{Mode, Policy},
    resolve::Resolver,
};

#[cfg(target_os = "linux")]
use crate::enforcer::Enforcer;

pub struct Supervisor {
    policy: Policy,
    mode: Mode,
    stats: Arc<Mutex<Stats>>,
    stop: Arc<AtomicBool>,
    cgroup: Option<Cgroup>,

    // On Linux we keep the loaded BPF object alive so maps + links persist
    // for the lifetime of the supervisor.
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    bpf: Option<Arc<Mutex<aya::Ebpf>>>,

    /// Stop signal for the DNS refresh loop (Linux-only; `None` when
    /// `dns_refresh` is zero or on non-Linux platforms).
    refresh_stop: Option<crate::resolve_refresh::StopHandle>,
}

impl Supervisor {
    pub async fn start(policy: Policy, mode: Mode, dns_refresh: Duration) -> Result<Self> {
        let stats = Arc::new(Mutex::new(Stats::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let file_matcher = Arc::new(FileMatcher::from_policy(&policy.file));
        let exec_matcher = Arc::new(ExecMatcher::from_policy(&policy.process));

        // Loud warning: deny_exec is audit-only for now. Silently ignoring
        // it in block mode would be a security footgun.
        if matches!(mode, Mode::Block) && !exec_matcher.is_empty() {
            log::warn!(
                "process.deny_exec is currently audit-only — matching exec events \
                 will be tagged `denied` in the log and coronarium will exit \
                 non-zero, but the child process is NOT prevented from running. \
                 Kernel-side exec block requires bpf_override_return and is on \
                 the roadmap."
            );
        }

        let cgroup = match Cgroup::create() {
            Ok(c) => Some(c),
            Err(err) => {
                log::warn!("cgroup creation failed ({err:#}); network policy will be degraded");
                None
            }
        };

        #[cfg(target_os = "linux")]
        let bpf = {
            let resolver = Resolver::from_system()?;
            match load_bpf(&policy, mode, cgroup.as_ref(), &resolver).await {
                Ok(b) => Some(Arc::new(Mutex::new(b))),
                Err(err) => {
                    // In block mode we refuse to passthrough: the whole point
                    // is enforcement, and silently running the child without
                    // BPF protection is a security footgun. Bail hard so CI
                    // turns red with an obvious error.
                    if matches!(mode, Mode::Block) {
                        // Emit a GitHub Actions error annotation so the
                        // failure surfaces on the run UI, not just in logs.
                        eprintln!(
                            "::error title=coronarium::eBPF programs failed to attach in block mode; refusing to run unprotected. {err:#}"
                        );
                        return Err(err).context(
                            "eBPF attach failed in `mode: block`; refusing passthrough. \
                             Check kernel config / CAP_BPF / CAP_SYS_ADMIN. \
                             Re-run with `--mode audit` to diagnose without enforcement.",
                        );
                    }
                    log::warn!("eBPF attach failed, running in passthrough (audit mode): {err:#}");
                    None
                }
            }
        };

        #[cfg(not(target_os = "linux"))]
        let _ = Resolver::from_system; // silence unused warning

        // Spawn the DNS refresh loop if requested and we actually
        // have a BPF object to write into. `refresh_stop` is None
        // when the feature is off, which is the overwhelming default.
        #[cfg(target_os = "linux")]
        let refresh_stop = match (dns_refresh.is_zero(), bpf.as_ref()) {
            (false, Some(bpf_arc)) => {
                let resolver = Resolver::from_system()?;
                let sink = crate::enforcer::BpfEndpointSink::new(Arc::clone(bpf_arc));
                let loop_ = crate::resolve_refresh::RefreshLoop::new(
                    resolver,
                    sink,
                    policy.network.allow.clone(),
                    policy.network.deny.clone(),
                    dns_refresh,
                );
                let stop_handle = loop_.stop_handle();
                let mut seen = std::collections::HashSet::new();
                // Prime `seen` with the startup population so the
                // first tick doesn't rewrite every address.
                let prime = crate::enforcer::current_bpf_entries(bpf_arc).await;
                crate::resolve_refresh::RefreshLoop::<
                    Resolver,
                    crate::enforcer::BpfEndpointSink,
                >::prime_seen(&mut seen, &prime);
                tokio::task::spawn(async move {
                    let _ = loop_.run(seen).await;
                });
                log::info!(
                    "dns-refresh: scheduling re-resolution every {}s",
                    dns_refresh.as_secs()
                );
                Some(stop_handle)
            }
            _ => None,
        };
        #[cfg(not(target_os = "linux"))]
        let refresh_stop: Option<crate::resolve_refresh::StopHandle> = {
            let _ = dns_refresh;
            None
        };

        let this = Self {
            policy,
            mode,
            stats: stats.clone(),
            stop: stop.clone(),
            cgroup,
            #[cfg(target_os = "linux")]
            bpf: bpf.clone(),
            refresh_stop,
        };

        #[cfg(target_os = "linux")]
        if let Some(bpf) = bpf {
            spawn_ringbuf_drain(bpf, stats, stop, file_matcher, exec_matcher);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (file_matcher, exec_matcher);
        }

        Ok(this)
    }

    pub async fn run_child(&self, argv: &[String]) -> Result<i32> {
        let (program, rest) = argv
            .split_first()
            .context("internal error: empty command after clap parse")?;

        let cgroup_path = self.cgroup.as_ref().map(|c| c.path.clone());

        let mut cmd = Command::new(program);
        cmd.args(rest);

        // Enroll the child into our cgroup *before* it execs. On Linux we use
        // pre_exec; other platforms just run the command unconfined.
        #[cfg(target_os = "linux")]
        if let Some(path) = cgroup_path.clone() {
            // tokio::process::Command re-exports pre_exec directly — no trait
            // import needed.
            unsafe {
                cmd.pre_exec(move || {
                    let procs = path.join("cgroup.procs");
                    let pid = std::process::id();
                    std::fs::write(&procs, pid.to_string().as_bytes())?;
                    Ok(())
                });
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = cgroup_path;

        let status = cmd.status().await.with_context(|| {
            // sudo replaces PATH with secure_path even with `-E`, so a
            // non-absolute program name run under sudo will look up
            // against /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
            // and miss anything installed elsewhere (pnpm, cargo,
            // rustup-installed toolchains, …). Surface the workaround
            // in the error rather than letting users debug it raw.
            let is_relative = !std::path::Path::new(program).is_absolute();
            let under_sudo =
                std::env::var_os("SUDO_USER").is_some() || std::env::var_os("SUDO_UID").is_some();
            if is_relative && under_sudo {
                format!(
                    "spawning {program}: not found on sudo's PATH. \
                     sudo strips PATH (`-E` doesn't preserve it); pass it \
                     explicitly with `sudo -E env \"PATH=$PATH\" {} ...` \
                     or use an absolute path",
                    std::env::current_exe()
                        .ok()
                        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                        .unwrap_or_else(|| "coronarium".into()),
                )
            } else {
                format!("spawning {program}")
            }
        })?;
        Ok(status.code().unwrap_or(1))
    }

    pub async fn shutdown(self) -> Result<Stats> {
        // Give the drain task one wake-up window so it can pull any events
        // that arrived just before the child exited, then tell it to stop.
        tokio::time::sleep(Duration::from_millis(50)).await;
        self.stop.store(true, Ordering::SeqCst);
        if let Some(s) = &self.refresh_stop {
            s.stop();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(self.stats.lock().await.clone())
    }

    #[allow(dead_code)]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    #[allow(dead_code)]
    pub fn mode(&self) -> Mode {
        self.mode
    }
}

#[cfg(target_os = "linux")]
async fn load_bpf(
    policy: &Policy,
    mode: Mode,
    cgroup: Option<&Cgroup>,
    resolver: &Resolver,
) -> Result<aya::Ebpf> {
    let path = std::env::var("CORONARIUM_BPF_OBJ")
        .context("CORONARIUM_BPF_OBJ is not set; build the eBPF crate and point to the .o")?;
    let mut bpf = aya::Ebpf::load_file(&path).with_context(|| format!("loading {path}"))?;

    if let Err(err) = aya_log::EbpfLogger::init(&mut bpf) {
        log::debug!("aya_log init skipped: {err}");
    }

    if let Some(map) = bpf.map_mut("SETTINGS") {
        let mut settings_map: aya::maps::Array<_, coronarium_common::Settings> =
            aya::maps::Array::try_from(map)?;
        let encoded = coronarium_common::Settings {
            mode: match mode {
                Mode::Audit => 0,
                Mode::Block => 1,
            },
            net_default: default_to_u32(policy.network.default),
            file_default: default_to_u32(policy.file.default),
            exec_default: coronarium_common::POLICY_ALLOW as u32,
        };
        settings_map.set(0, encoded, 0)?;
    }

    Enforcer::attach(&mut bpf, policy, cgroup, resolver)
        .await
        .context("attaching programs")?;
    Ok(bpf)
}

#[cfg(target_os = "linux")]
fn default_to_u32(d: crate::policy::DefaultDecision) -> u32 {
    match d {
        crate::policy::DefaultDecision::Allow => coronarium_common::POLICY_ALLOW as u32,
        crate::policy::DefaultDecision::Deny => coronarium_common::POLICY_DENY as u32,
    }
}

#[cfg(target_os = "linux")]
fn spawn_ringbuf_drain(
    bpf: Arc<Mutex<aya::Ebpf>>,
    stats: Arc<Mutex<Stats>>,
    stop: Arc<AtomicBool>,
    file_matcher: Arc<FileMatcher>,
    exec_matcher: Arc<ExecMatcher>,
) {
    tokio::task::spawn(async move {
        let ring = {
            let mut guard = bpf.lock().await;
            match guard.take_map("EVENTS") {
                Some(m) => aya::maps::RingBuf::try_from(m).ok(),
                None => None,
            }
        };
        let Some(mut ring) = ring else {
            log::warn!("EVENTS ringbuf not found; drain task exiting");
            return;
        };

        loop {
            while let Some(item) = ring.next() {
                let bytes: &[u8] = &item;
                let mut s = stats.lock().await;
                ingest(&mut s, bytes, &file_matcher, &exec_matcher);
            }
            if stop.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
}

pub(crate) fn ingest(
    stats: &mut Stats,
    raw: &[u8],
    file_matcher: &FileMatcher,
    exec_matcher: &ExecMatcher,
) {
    let Some(mut ev) = events::decode(raw) else {
        stats.lost += 1;
        return;
    };

    // Apply userspace-side policy: the kernel ships the filename/argv0 but
    // not a verdict for file/exec kinds.
    match &mut ev {
        Event::Open {
            filename, denied, ..
        } if file_matcher.is_denied(filename) => {
            *denied = true;
        }
        Event::Exec {
            filename,
            argv0,
            denied,
            ..
        } if exec_matcher.is_denied(filename, argv0) => {
            *denied = true;
        }
        _ => {}
    }

    stats.ingest(ev);
}
