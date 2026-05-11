//! Best-effort PTR lookup for `Event::Connect` samples in the report.
//!
//! The kernel/ETW decoders only know the remote IP — they never see
//! the hostname the client resolved. This module batches a reverse
//! DNS lookup across every unique IP in `stats.samples` (capped so
//! we don't hammer the resolver on pathological inputs) and stamps
//! the result back into each matching `Event::Connect.hostname`.
//!
//! Failures are swallowed: no PTR record, private-range IP, or a
//! timeout leaves `hostname = None` and the HTML report falls back
//! to the plain IP:port cell. We log at debug level only.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::TokioAsyncResolver;
use sakimori_core::events::Event;
use sakimori_core::stats::Stats;

/// Hard cap on the number of PTR lookups we issue. Typical runs have
/// under 50 unique destinations; the cap exists so a pathological
/// policy with thousands of distinct connects doesn't stall the
/// report step for minutes.
const MAX_LOOKUPS: usize = 256;

/// Per-lookup timeout. hickory's default is much longer; PTR on a
/// public resolver should come back in well under a second, and if
/// it doesn't we'd rather skip than block the CI step.
const LOOKUP_TIMEOUT: Duration = Duration::from_millis(750);

/// Mutate `stats.samples`, populating `Event::Connect.hostname` for
/// every connect whose `daddr` parses as an IP and has a PTR record.
pub async fn resolve(stats: &mut Stats) {
    // 1. Collect unique IPs to look up.
    let ips: Vec<IpAddr> = {
        let mut seen = std::collections::HashSet::new();
        stats
            .samples
            .iter()
            .filter_map(|ev| match ev {
                Event::Connect { daddr, .. } => daddr.parse::<IpAddr>().ok(),
                _ => None,
            })
            .filter(|ip| seen.insert(*ip))
            .take(MAX_LOOKUPS)
            .collect()
    };
    if ips.is_empty() {
        return;
    }

    // 2. Build a resolver from the host's /etc/resolv.conf (Linux /
    //    macOS) or system config (Windows). If construction fails we
    //    just skip the whole step — the report still renders, just
    //    without hostnames.
    let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(e) => {
            log::debug!("resolve_hostnames: skipping, resolver init failed: {e}");
            return;
        }
    };

    // 3. Issue every PTR lookup in parallel, with a per-call timeout.
    //    For hundreds of IPs, parallelism drops the total time from
    //    tens-of-seconds to well under a second.
    let lookups = ips.into_iter().map(|ip| {
        let resolver = resolver.clone();
        async move {
            let res = tokio::time::timeout(LOOKUP_TIMEOUT, resolver.reverse_lookup(ip)).await;
            let name = match res {
                Ok(Ok(rev)) => rev
                    .iter()
                    .next()
                    .map(|n| n.to_string().trim_end_matches('.').to_string()),
                Ok(Err(e)) => {
                    log::debug!("PTR for {ip} failed: {e}");
                    None
                }
                Err(_) => {
                    log::debug!("PTR for {ip} timed out");
                    None
                }
            };
            (ip, name)
        }
    });
    let results: Vec<(IpAddr, Option<String>)> = futures::future::join_all(lookups)
        .await
        .into_iter()
        .collect();

    // 4. Build the final IP -> hostname map, discarding empty answers.
    let map: HashMap<IpAddr, String> = results
        .into_iter()
        .filter_map(|(ip, n)| n.map(|n| (ip, n)))
        .collect();

    // 5. Stamp the hostnames back into every matching sample.
    for ev in stats.samples.iter_mut() {
        if let Event::Connect {
            daddr, hostname, ..
        } = ev
            && hostname.is_none()
            && let Ok(ip) = daddr.parse::<IpAddr>()
            && let Some(name) = map.get(&ip)
        {
            *hostname = Some(name.clone());
        }
    }
}
