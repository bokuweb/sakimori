#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
//! Translates the human-friendly `target` field of [`NetRule`] (hostname,
//! IPv4/IPv6 literal, or CIDR) into a flat list of `(IpAddr, port)` tuples
//! ready to be written into the eBPF allow/deny map.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use hickory_resolver::{TokioAsyncResolver, config::*};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::policy::NetRule;

#[derive(Debug, Clone, Copy)]
pub struct Endpoint {
    pub addr: IpAddr,
    /// 0 means "any port".
    pub port: u16,
}

/// Cap the number of /N expansions we're willing to materialise into the map.
///
/// Note: the eBPF `NET4` / `NET6` maps in `crates/coronarium-ebpf` are
/// only sized for 1024 entries each *total*, so even one CIDR at this
/// cap will overflow the map at attach time. Enforcer-side does the
/// real bookkeeping (and bails with a friendly message) — the cap here
/// is just to keep the per-rule allocation bounded.
const MAX_CIDR_EXPANSION: usize = 65_536;

pub struct Resolver {
    inner: TokioAsyncResolver,
}

impl Resolver {
    pub fn from_system() -> Result<Self> {
        // `from_system_conf` reads /etc/resolv.conf on unix. On hosts where it
        // fails (e.g. minimal containers) we fall back to 1.1.1.1 / 8.8.8.8.
        let inner = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|err| {
            log::debug!("system resolver unavailable ({err}); falling back to cloudflare");
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default())
        });
        Ok(Self { inner })
    }

    pub async fn expand(&self, rule: &NetRule) -> Result<Vec<Endpoint>> {
        let ports: Vec<u16> = if rule.ports.is_empty() {
            vec![0]
        } else {
            rule.ports.clone()
        };

        let addrs = self.resolve_target(&rule.target).await?;

        let mut out = Vec::with_capacity(addrs.len() * ports.len());
        for addr in addrs {
            for port in &ports {
                out.push(Endpoint { addr, port: *port });
            }
        }
        Ok(out)
    }

    async fn resolve_target(&self, target: &str) -> Result<Vec<IpAddr>> {
        // 1) bare IP literal
        if let Ok(v4) = target.parse::<Ipv4Addr>() {
            return Ok(vec![IpAddr::V4(v4)]);
        }
        if let Ok(v6) = target.parse::<Ipv6Addr>() {
            return Ok(vec![IpAddr::V6(v6)]);
        }

        // 2) CIDR
        if let Ok(net) = target.parse::<IpNet>() {
            return Ok(expand_cidr(net));
        }

        // 3) hostname -- A + AAAA
        let lookup = self
            .inner
            .lookup_ip(target)
            .await
            .with_context(|| format!("resolving {target}"))?;
        Ok(lookup.iter().collect())
    }
}

fn expand_cidr(net: IpNet) -> Vec<IpAddr> {
    match net {
        IpNet::V4(v4) => expand_v4(v4),
        IpNet::V6(v6) => expand_v6(v6),
    }
}

fn expand_v4(net: Ipv4Net) -> Vec<IpAddr> {
    let hosts = 1u64 << (32 - net.prefix_len() as u64);
    if hosts as usize > MAX_CIDR_EXPANSION {
        log::warn!(
            "CIDR {net} expands to {hosts} hosts (>{MAX_CIDR_EXPANSION}); only the first {MAX_CIDR_EXPANSION} will be enforced"
        );
    }
    net.hosts()
        .take(MAX_CIDR_EXPANSION)
        .map(IpAddr::V4)
        .collect()
}

fn expand_v6(net: Ipv6Net) -> Vec<IpAddr> {
    let prefix = net.prefix_len();
    if prefix < 112 {
        log::warn!(
            "IPv6 CIDR {net} is wider than /112; only the first {MAX_CIDR_EXPANSION} addresses will be enforced"
        );
    }
    net.hosts()
        .take(MAX_CIDR_EXPANSION)
        .map(IpAddr::V6)
        .collect()
}
