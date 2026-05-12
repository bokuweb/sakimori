//! Bridge parsed [`Policy`] → eBPF maps and attach kernel programs.
//! Linux-only; other targets compile a placeholder.

use crate::{cgroup::Cgroup, policy::Policy, resolve::Resolver};

#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use tokio::sync::Mutex;

#[cfg(target_os = "linux")]
use crate::resolve::Endpoint;
#[cfg(target_os = "linux")]
use crate::resolve_refresh::{EndpointSink, Verdict};

#[allow(dead_code)]
pub struct Enforcer;

#[cfg(target_os = "linux")]
impl Enforcer {
    pub async fn attach(
        bpf: &mut aya::Ebpf,
        policy: &Policy,
        cgroup: Option<&Cgroup>,
        resolver: &Resolver,
    ) -> anyhow::Result<()> {
        use anyhow::Context as _;

        if let Some(prog) = bpf.program_mut("sakimori_execve") {
            let tp: &mut aya::programs::TracePoint = prog.try_into()?;
            tp.load()?;
            tp.attach("syscalls", "sys_enter_execve")
                .context("attaching sys_enter_execve")?;
        }

        if let Some(prog) = bpf.program_mut("sakimori_openat") {
            let tp: &mut aya::programs::TracePoint = prog.try_into()?;
            tp.load()?;
            tp.attach("syscalls", "sys_enter_openat")
                .context("attaching sys_enter_openat")?;
        }

        // Roadmap #4: opportunistic pre-syscall block via
        // bpf_override_return on a do_sys_openat2 kprobe. Strictly
        // additive — the SIGKILL tripwire on the tracepoint stays
        // armed regardless, so any attach failure here degrades
        // silently to the existing behaviour. Gated behind an
        // opt-in env var while we collect cross-kernel field data.
        if should_attempt_kprobe_override() {
            try_attach_openat2_kprobe(bpf);
        }

        if let Some(cgroup) = cgroup {
            let fd = cgroup.as_file()?;
            for name in ["sakimori_connect4", "sakimori_connect6"] {
                if let Some(prog) = bpf.program_mut(name) {
                    let cg: &mut aya::programs::CgroupSockAddr = prog.try_into()?;
                    cg.load()?;
                    cg.attach(&fd, aya::programs::CgroupAttachMode::Single)
                        .with_context(|| format!("attaching {name}"))?;
                }
            }
        }

        populate_network_maps(bpf, policy, resolver).await?;
        populate_file_maps(bpf, policy)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn should_attempt_kprobe_override() -> bool {
    // The env-var gate is the user's opt-in switch; the detection
    // probe filters out kernels that don't have
    // CONFIG_BPF_KPROBE_OVERRIDE. We require both: an opted-in
    // user on a kernel without the support would silently fall
    // back, but on the (more common) opted-out user we don't even
    // probe.
    if !env_opt_in("SAKIMORI_ENABLE_KPROBE_OVERRIDE") {
        return false;
    }
    let status = crate::kprobe_override::detect();
    match status {
        crate::kprobe_override::KprobeOverrideStatus::Available { .. } => true,
        crate::kprobe_override::KprobeOverrideStatus::Unsupported { .. } => {
            log::info!(
                "SAKIMORI_ENABLE_KPROBE_OVERRIDE set but kernel lacks CONFIG_BPF_KPROBE_OVERRIDE; \
                 staying on SIGKILL-tripwire fallback"
            );
            false
        }
        crate::kprobe_override::KprobeOverrideStatus::Unknown { reason } => {
            log::info!(
                "SAKIMORI_ENABLE_KPROBE_OVERRIDE set but kernel-config readability is unknown \
                 ({reason}); attempting attach anyway"
            );
            true
        }
    }
}

#[cfg(target_os = "linux")]
fn env_opt_in(name: &str) -> bool {
    // Common truthy values; everything else (unset, "0", "false",
    // empty) is treated as opt-out so users can paste a `=0` into
    // CI to disable without removing the assignment.
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

#[cfg(target_os = "linux")]
fn try_attach_openat2_kprobe(bpf: &mut aya::Ebpf) {
    let Some(prog) = bpf.program_mut("sakimori_openat2_kprobe") else {
        log::debug!("sakimori_openat2_kprobe program not in object; skipping");
        return;
    };
    let kp: &mut aya::programs::KProbe = match prog.try_into() {
        Ok(k) => k,
        Err(e) => {
            log::warn!("sakimori_openat2_kprobe: not a KProbe program: {e:#}");
            return;
        }
    };
    if let Err(e) = kp.load() {
        log::warn!(
            "sakimori_openat2_kprobe: verifier rejected load ({e:#}); \
             staying on SIGKILL-tripwire fallback"
        );
        return;
    }
    match kp.attach("do_sys_openat2", 0) {
        Ok(_) => {
            log::info!(
                "sakimori_openat2_kprobe attached: file.deny is now a pre-syscall block \
                 (bpf_override_return → -EPERM)"
            );
        }
        Err(e) => {
            log::warn!(
                "sakimori_openat2_kprobe: attach to do_sys_openat2 failed ({e:#}); \
                 staying on SIGKILL-tripwire fallback. Common causes: \
                 do_sys_openat2 not in this kernel's error-injection allowlist, \
                 or missing CAP_SYS_ADMIN."
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
impl Enforcer {
    pub async fn attach(
        _bpf: &mut (),
        _policy: &Policy,
        _cgroup: Option<&Cgroup>,
        _resolver: &Resolver,
    ) -> anyhow::Result<()> {
        anyhow::bail!("Enforcer::attach only runs on Linux")
    }
}

#[cfg(target_os = "linux")]
async fn populate_network_maps(
    bpf: &mut aya::Ebpf,
    policy: &Policy,
    resolver: &Resolver,
) -> anyhow::Result<()> {
    use std::net::IpAddr;

    use anyhow::Context;
    use sakimori_common::{Ipv4Key, Ipv6Key, POLICY_ALLOW, POLICY_DENY};

    // Pre-resolve every rule's endpoints *before* touching the maps so that a
    // transient DNS failure doesn't leave half-populated state.
    let allow = resolve_all(resolver, &policy.network.allow).await;
    let deny = resolve_all(resolver, &policy.network.deny).await;

    // Pre-flight: each (addr, port) becomes one entry in the BPF map.
    // The maps are sized via `HashMap::with_max_entries(BPF_NET_MAP_CAPACITY)`
    // in the eBPF program. Going over yields a bare `bpf_map_update_elem
    // failed: Argument list too long` from aya — surface a clearly
    // diagnosable error before we even start updating instead.
    let (v4_count, v6_count) = endpoint_counts(&allow, &deny);
    if v4_count > BPF_NET_MAP_CAPACITY {
        anyhow::bail!(
            "policy network rules expand to {v4_count} IPv4 (addr,port) pairs, \
             but the eBPF NET4 map is sized for {BPF_NET_MAP_CAPACITY}. \
             Common cause: a wide CIDR like Cloudflare's /12s — sakimori \
             enumerates every host into the map and CDN ranges overflow it \
             quickly. Use hostname rules (kept fresh by --dns-refresh-interval) \
             or narrower CIDRs."
        );
    }
    if v6_count > BPF_NET_MAP_CAPACITY {
        anyhow::bail!(
            "policy network rules expand to {v6_count} IPv6 (addr,port) pairs, \
             but the eBPF NET6 map is sized for {BPF_NET_MAP_CAPACITY}. \
             Use hostname rules or narrower CIDRs (an IPv6 /112 is the \
             tightest CIDR that fits unconditionally)."
        );
    }

    // deny wins if the same (addr, port) appears on both lists.
    if let Some(map) = bpf.map_mut("NET4") {
        let mut m: aya::maps::HashMap<_, Ipv4Key, u8> = aya::maps::HashMap::try_from(map)?;
        for (ep, verdict) in allow
            .iter()
            .map(|e| (e, POLICY_ALLOW))
            .chain(deny.iter().map(|e| (e, POLICY_DENY)))
        {
            if let IpAddr::V4(v4) = ep.addr {
                let key = Ipv4Key {
                    addr: u32::from(v4).to_be(),
                    port: ep.port.to_be(),
                    _pad: 0,
                };
                m.insert(key, verdict, 0).with_context(|| {
                    format!(
                        "writing {v4}:{} to NET4 map (capacity {BPF_NET_MAP_CAPACITY}); \
                         policy may exceed map size",
                        ep.port,
                    )
                })?;
            }
        }
    }

    if let Some(map) = bpf.map_mut("NET6") {
        let mut m: aya::maps::HashMap<_, Ipv6Key, u8> = aya::maps::HashMap::try_from(map)?;
        for (ep, verdict) in allow
            .iter()
            .map(|e| (e, POLICY_ALLOW))
            .chain(deny.iter().map(|e| (e, POLICY_DENY)))
        {
            if let IpAddr::V6(v6) = ep.addr {
                let key = Ipv6Key {
                    addr: v6.octets(),
                    port: ep.port.to_be(),
                    _pad: [0; 6],
                };
                m.insert(key, verdict, 0).with_context(|| {
                    format!(
                        "writing [{v6}]:{} to NET6 map (capacity {BPF_NET_MAP_CAPACITY}); \
                         policy may exceed map size",
                        ep.port,
                    )
                })?;
            }
        }
    }
    Ok(())
}

/// Mirror of `HashMap::with_max_entries(...)` in `crates/sakimori-ebpf`'s
/// `NET4` / `NET6` declarations. Keep in sync with the eBPF side.
#[cfg(target_os = "linux")]
const BPF_NET_MAP_CAPACITY: usize = 1024;

#[cfg(target_os = "linux")]
fn endpoint_counts(
    allow: &[crate::resolve::Endpoint],
    deny: &[crate::resolve::Endpoint],
) -> (usize, usize) {
    use std::net::IpAddr;
    let mut v4 = 0usize;
    let mut v6 = 0usize;
    for ep in allow.iter().chain(deny.iter()) {
        match ep.addr {
            IpAddr::V4(_) => v4 += 1,
            IpAddr::V6(_) => v6 += 1,
        }
    }
    (v4, v6)
}

#[cfg(target_os = "linux")]
async fn resolve_all(
    resolver: &Resolver,
    rules: &[crate::policy::NetRule],
) -> Vec<crate::resolve::Endpoint> {
    let mut out = Vec::new();
    for rule in rules {
        match resolver.expand(rule).await {
            Ok(mut eps) => out.append(&mut eps),
            Err(err) => log::warn!("resolving {}: {err:#}", rule.target),
        }
    }
    out
}

/// [`EndpointSink`] implementation that writes into the live NET4 /
/// NET6 eBPF hash maps owned by the supervisor's shared `Ebpf`
/// object. Locks the async `Mutex<Ebpf>` only for the duration of one
/// insert, so it composes cleanly with the existing ringbuf drain
/// task (which doesn't hold the lock either, having taken EVENTS out
/// at startup).
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct BpfEndpointSink {
    bpf: Arc<Mutex<aya::Ebpf>>,
}

#[cfg(target_os = "linux")]
impl BpfEndpointSink {
    pub fn new(bpf: Arc<Mutex<aya::Ebpf>>) -> Self {
        Self { bpf }
    }
}

#[cfg(target_os = "linux")]
impl EndpointSink for BpfEndpointSink {
    async fn insert(&self, endpoint: Endpoint, verdict: Verdict) -> anyhow::Result<()> {
        use std::net::IpAddr;

        use sakimori_common::{Ipv4Key, Ipv6Key};

        let mut guard = self.bpf.lock().await;
        match endpoint.addr {
            IpAddr::V4(v4) => {
                let Some(map) = guard.map_mut("NET4") else {
                    return Ok(());
                };
                let mut m: aya::maps::HashMap<_, Ipv4Key, u8> = aya::maps::HashMap::try_from(map)?;
                let key = Ipv4Key {
                    addr: u32::from(v4).to_be(),
                    port: endpoint.port.to_be(),
                    _pad: 0,
                };
                m.insert(key, verdict.0, 0)?;
            }
            IpAddr::V6(v6) => {
                let Some(map) = guard.map_mut("NET6") else {
                    return Ok(());
                };
                let mut m: aya::maps::HashMap<_, Ipv6Key, u8> = aya::maps::HashMap::try_from(map)?;
                let key = Ipv6Key {
                    addr: v6.octets(),
                    port: endpoint.port.to_be(),
                    _pad: [0; 6],
                };
                m.insert(key, verdict.0, 0)?;
            }
        }
        Ok(())
    }
}

/// Read back the `(endpoint, verdict)` pairs currently populated in
/// NET4 / NET6. Used to prime the refresh loop's `seen` set at
/// startup so the very first tick doesn't re-write addresses that
/// [`populate_network_maps`] already installed.
#[cfg(target_os = "linux")]
pub async fn current_bpf_entries(bpf: &Arc<Mutex<aya::Ebpf>>) -> Vec<(Endpoint, Verdict)> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use sakimori_common::{Ipv4Key, Ipv6Key};

    let mut out = Vec::new();
    let guard = bpf.lock().await;
    if let Some(map) = guard.map("NET4")
        && let Ok(m) = aya::maps::HashMap::<_, Ipv4Key, u8>::try_from(map)
    {
        for r in m.iter().flatten() {
            let (k, v) = r;
            let addr = Ipv4Addr::from(u32::from_be(k.addr));
            out.push((
                Endpoint {
                    addr: IpAddr::V4(addr),
                    port: u16::from_be(k.port),
                },
                Verdict(v),
            ));
        }
    }
    if let Some(map) = guard.map("NET6")
        && let Ok(m) = aya::maps::HashMap::<_, Ipv6Key, u8>::try_from(map)
    {
        for r in m.iter().flatten() {
            let (k, v) = r;
            out.push((
                Endpoint {
                    addr: IpAddr::V6(Ipv6Addr::from(k.addr)),
                    port: u16::from_be(k.port),
                },
                Verdict(v),
            ));
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn populate_file_maps(bpf: &mut aya::Ebpf, policy: &Policy) -> anyhow::Result<()> {
    use sakimori_common::{FILE_DENY_MAX_ENTRIES, FILE_DENY_PREFIX_LEN, FileDenyPrefix};

    // Mirror the first `FILE_DENY_MAX_ENTRIES` policy.file.deny entries
    // into the kernel-side FILE_DENY_PREFIX map. Matches there trigger
    // bpf_send_signal(SIGKILL) on the offending process (in block mode).
    // Beyond this cap, entries still fire `denied: true` tags via the
    // userspace FileMatcher but won't kill the child.
    let Some(map) = bpf.map_mut("FILE_DENY_PREFIX") else {
        // Older BPF ELFs may not include this map; skip silently.
        return Ok(());
    };
    let mut m: aya::maps::Array<_, FileDenyPrefix> = aya::maps::Array::try_from(map)?;

    // Pre-compute zero'd entries for every slot so stale rules from a
    // re-used map don't match.
    let empty = FileDenyPrefix {
        len: 0,
        bytes: [0; FILE_DENY_PREFIX_LEN],
    };
    for i in 0..FILE_DENY_MAX_ENTRIES {
        m.set(i, empty, 0)?;
    }

    let mut idx: u32 = 0;
    for pat in &policy.file.deny {
        if idx >= FILE_DENY_MAX_ENTRIES {
            log::warn!(
                "file.deny has more than {FILE_DENY_MAX_ENTRIES} entries — remaining are \
                 audit-tagged only, not kernel-blocked."
            );
            break;
        }
        let bytes = pat.as_bytes();
        if bytes.len() > FILE_DENY_PREFIX_LEN {
            log::warn!(
                "file.deny entry {:?} exceeds kernel prefix cap ({} bytes); only the first \
                 {} bytes are enforced in-kernel (userspace match still covers the full string).",
                pat,
                bytes.len(),
                FILE_DENY_PREFIX_LEN
            );
        }
        let n = bytes.len().min(FILE_DENY_PREFIX_LEN);
        let mut entry = FileDenyPrefix {
            len: n as u32,
            bytes: [0; FILE_DENY_PREFIX_LEN],
        };
        entry.bytes[..n].copy_from_slice(&bytes[..n]);
        m.set(idx, entry, 0)?;
        idx += 1;
    }
    log::info!(
        "populated {idx}/{FILE_DENY_MAX_ENTRIES} file-deny prefix slots for kernel-side block"
    );
    Ok(())
}
