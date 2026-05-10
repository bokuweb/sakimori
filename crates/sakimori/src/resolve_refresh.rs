//! Periodic DNS re-resolution for hostname-based `network.allow` /
//! `network.deny` rules.
//!
//! # Problem
//!
//! Hostnames in a policy are resolved **once at startup** and the
//! resulting `(IpAddr, port)` tuples are written into the NET4 / NET6
//! eBPF maps. CDN-backed origins return a different rotation of IPs
//! each time you query them, so a long-running supervised job can
//! start hitting addresses the map has never seen and, under
//! `network.default: deny`, get connections killed that the policy
//! author clearly intended to allow.
//!
//! # Design
//!
//! - **Additive only.** We never remove an address once it has been
//!   inserted — doing so would kill active connections that were
//!   admitted a moment ago. The worst case is the map gains a handful
//!   of stale entries per rotation, which the kernel looks up in O(1).
//!   Bounded by rotation cardinality × run duration / refresh interval.
//! - **Pure core + thin IO layer.** [`refresh_once`] is generic over
//!   an [`EndpointResolver`] (the DNS side) and an [`EndpointSink`]
//!   (the map writer). Both are traits so tests drive the logic with
//!   in-memory fakes. The Linux enforcer wires a real
//!   `hickory_resolver::TokioAsyncResolver` and an aya-HashMap sink.
//! - **Cooperative cancellation.** [`RefreshLoop::run`] polls a
//!   [`StopHandle`] between ticks so shutdown is prompt.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

use crate::policy::NetRule;
use crate::resolve::Endpoint;

/// Verdict byte stored in NET4 / NET6. Matches the raw constants in
/// `sakimori_common`. Held as a newtype so the sink API can't
/// confuse it with a random `u8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Verdict(pub u8);

/// Resolve a single rule to its current endpoint list. Abstracted so
/// tests can inject a scripted resolver without reaching for a real
/// hickory runtime. The real implementation is
/// [`crate::resolve::Resolver`].
pub trait EndpointResolver: Send + Sync {
    fn expand(
        &self,
        rule: &NetRule,
    ) -> impl std::future::Future<Output = anyhow::Result<Vec<Endpoint>>> + Send;
}

impl EndpointResolver for crate::resolve::Resolver {
    async fn expand(&self, rule: &NetRule) -> anyhow::Result<Vec<Endpoint>> {
        crate::resolve::Resolver::expand(self, rule).await
    }
}

/// Destination for newly-observed endpoints. The Linux enforcer
/// writes into the BPF hash maps; tests capture into a `Vec`.
pub trait EndpointSink: Send + Sync {
    /// Insert a `(endpoint, verdict)` pair. Called only for endpoints
    /// the refresher has not seen on a previous tick — the sink may
    /// still observe duplicates across restarts, so insert should be
    /// idempotent. Async so implementations can lock a
    /// `tokio::sync::Mutex` guarding shared state (the Linux sink
    /// holds the eBPF object that way).
    fn insert(
        &self,
        endpoint: Endpoint,
        verdict: Verdict,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}

/// Apply one refresh pass across a set of `(rules, verdict)` buckets.
/// Inserts only endpoints that are not already in `seen`; updates
/// `seen` on success. Resolver failures are logged and skipped so a
/// transient DNS outage doesn't poison the loop.
pub async fn refresh_once<R: EndpointResolver, S: EndpointSink>(
    resolver: &R,
    buckets: &[(Verdict, &[NetRule])],
    sink: &S,
    seen: &mut HashSet<SeenKey>,
) -> RefreshStats {
    let mut stats = RefreshStats::default();
    for (verdict, rules) in buckets {
        for rule in *rules {
            match resolver.expand(rule).await {
                Ok(eps) => {
                    for ep in eps {
                        let key = SeenKey::of(&ep, *verdict);
                        if seen.insert(key) {
                            match sink.insert(ep, *verdict).await {
                                Ok(()) => stats.added += 1,
                                Err(e) => {
                                    log::warn!(
                                        "dns-refresh: sink insert failed for {}: {e:#}",
                                        rule.target
                                    );
                                    // Roll back `seen` so a later tick retries.
                                    seen.remove(&key);
                                    stats.errors += 1;
                                }
                            }
                        } else {
                            stats.skipped += 1;
                        }
                    }
                }
                Err(e) => {
                    log::debug!("dns-refresh: resolve failed for {}: {e:#}", rule.target);
                    stats.errors += 1;
                }
            }
        }
    }
    stats
}

/// What happened during a single [`refresh_once`] pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RefreshStats {
    /// Endpoints the sink accepted for the first time.
    pub added: usize,
    /// Endpoints already present in `seen`; not forwarded to the sink.
    pub skipped: usize,
    /// Resolver or sink errors during this pass.
    pub errors: usize,
}

/// Hashable identity of a `(endpoint, verdict)` pair. Port is
/// included so the same IP allowed on 443 and denied on 80 tracks
/// two separate entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeenKey {
    pub addr: IpAddr,
    pub port: u16,
    pub verdict: u8,
}

impl SeenKey {
    pub fn of(ep: &Endpoint, v: Verdict) -> Self {
        Self {
            addr: ep.addr,
            port: ep.port,
            verdict: v.0,
        }
    }
}

/// Driver that re-runs [`refresh_once`] on an interval until the stop
/// signal fires. Cloneable via `Arc` so the supervisor can hold a
/// handle to signal shutdown.
pub struct RefreshLoop<R: EndpointResolver, S: EndpointSink> {
    resolver: R,
    sink: S,
    allow: Vec<NetRule>,
    deny: Vec<NetRule>,
    interval: Duration,
    stop: StopHandle,
}

/// Shutdown signal. Uses an [`AtomicBool`] so that `stop()` called
/// before `run()` starts waiting is not lost, plus a [`Notify`] so
/// the wait is cheap while the flag is false.
#[derive(Clone, Default)]
pub struct StopHandle {
    inner: Arc<StopInner>,
}

#[derive(Default)]
struct StopInner {
    flag: AtomicBool,
    notify: Notify,
}

impl StopHandle {
    pub fn stop(&self) {
        self.inner.flag.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    fn is_stopped(&self) -> bool {
        self.inner.flag.load(Ordering::SeqCst)
    }

    async fn notified(&self) {
        // If stop was signalled before we registered, return immediately.
        if self.is_stopped() {
            return;
        }
        self.inner.notify.notified().await;
    }
}

impl<R: EndpointResolver, S: EndpointSink> RefreshLoop<R, S> {
    pub fn new(
        resolver: R,
        sink: S,
        allow: Vec<NetRule>,
        deny: Vec<NetRule>,
        interval: Duration,
    ) -> Self {
        Self {
            resolver,
            sink,
            allow,
            deny,
            interval,
            stop: StopHandle::default(),
        }
    }

    /// Handle to the stop signal. Call
    /// `stop_handle.stop()` from another task to wind the loop down
    /// at the next tick boundary. Safe to call even before `run()`
    /// starts — the next `run()` call observes the flag immediately.
    pub fn stop_handle(&self) -> StopHandle {
        self.stop.clone()
    }

    /// Seed `seen` with the endpoints already written to the sink at
    /// startup, so the first tick doesn't re-insert everything.
    pub fn prime_seen(seen: &mut HashSet<SeenKey>, initial: &[(Endpoint, Verdict)]) {
        for (ep, v) in initial {
            seen.insert(SeenKey::of(ep, *v));
        }
    }

    /// Run forever, re-resolving and inserting new endpoints every
    /// `self.interval`, until `stop_handle()` is notified. Returns
    /// the final `seen` set for callers that want to inspect it.
    pub async fn run(&self, mut seen: HashSet<SeenKey>) -> HashSet<SeenKey> {
        if self.interval.is_zero() {
            return seen;
        }
        loop {
            if self.stop.is_stopped() {
                break;
            }
            tokio::select! {
                _ = self.stop.notified() => break,
                _ = tokio::time::sleep(self.interval) => {
                    let buckets = [
                        (Verdict(sakimori_common::POLICY_ALLOW), self.allow.as_slice()),
                        (Verdict(sakimori_common::POLICY_DENY), self.deny.as_slice()),
                    ];
                    let stats = refresh_once(&self.resolver, &buckets, &self.sink, &mut seen).await;
                    if stats.added > 0 {
                        log::info!(
                            "dns-refresh: added {} new endpoint(s), skipped {} known, {} error(s)",
                            stats.added,
                            stats.skipped,
                            stats.errors
                        );
                    }
                }
            }
        }
        seen
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    /// Scripted resolver: each rule target maps to a queue of
    /// responses returned on successive calls.
    struct ScriptedResolver {
        responses:
            Mutex<std::collections::HashMap<String, std::collections::VecDeque<Vec<IpAddr>>>>,
    }

    impl ScriptedResolver {
        fn new(script: &[(&str, Vec<Vec<IpAddr>>)]) -> Self {
            let mut m = std::collections::HashMap::new();
            for (target, rounds) in script {
                m.insert((*target).into(), rounds.iter().cloned().collect());
            }
            Self {
                responses: Mutex::new(m),
            }
        }
    }

    impl EndpointResolver for ScriptedResolver {
        async fn expand(&self, rule: &NetRule) -> anyhow::Result<Vec<Endpoint>> {
            let mut m = self.responses.lock().unwrap();
            let queue = m.get_mut(&rule.target).ok_or_else(|| {
                anyhow::anyhow!("ScriptedResolver: no script for {}", rule.target)
            })?;
            let addrs = queue
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("ScriptedResolver: script exhausted"))?;
            let ports: Vec<u16> = if rule.ports.is_empty() {
                vec![0]
            } else {
                rule.ports.clone()
            };
            let mut out = Vec::new();
            for addr in addrs {
                for port in &ports {
                    out.push(Endpoint { addr, port: *port });
                }
            }
            Ok(out)
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        inserted: Mutex<Vec<(IpAddr, u16, u8)>>,
        fail_after: Mutex<Option<usize>>,
    }

    impl EndpointSink for RecordingSink {
        async fn insert(&self, endpoint: Endpoint, verdict: Verdict) -> anyhow::Result<()> {
            if let Some(n) = *self.fail_after.lock().unwrap() {
                let mut ins = self.inserted.lock().unwrap();
                if ins.len() >= n {
                    return Err(anyhow::anyhow!("sink induced failure"));
                }
                ins.push((endpoint.addr, endpoint.port, verdict.0));
            } else {
                self.inserted
                    .lock()
                    .unwrap()
                    .push((endpoint.addr, endpoint.port, verdict.0));
            }
            Ok(())
        }
    }

    fn rule(target: &str, ports: &[u16]) -> NetRule {
        NetRule {
            target: target.into(),
            ports: ports.to_vec(),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn refresh_inserts_new_endpoints_and_skips_known_ones() {
        let resolver = ScriptedResolver::new(&[(
            "api.example.com",
            vec![
                vec![ip("1.2.3.4")],                // tick 1
                vec![ip("1.2.3.4"), ip("5.6.7.8")], // tick 2: rotation adds a new IP
                vec![ip("5.6.7.8")],                // tick 3: old IP has aged out
            ],
        )]);
        let sink = RecordingSink::default();
        let rules = [rule("api.example.com", &[443])];
        let buckets: [(Verdict, &[NetRule]); 1] =
            [(Verdict(sakimori_common::POLICY_ALLOW), &rules)];
        let mut seen = HashSet::new();

        let s1 = refresh_once(&resolver, &buckets, &sink, &mut seen).await;
        assert_eq!(s1.added, 1);
        assert_eq!(s1.skipped, 0);

        let s2 = refresh_once(&resolver, &buckets, &sink, &mut seen).await;
        assert_eq!(s2.added, 1, "1.2.3.4 already seen, 5.6.7.8 is new");
        assert_eq!(s2.skipped, 1);

        let s3 = refresh_once(&resolver, &buckets, &sink, &mut seen).await;
        assert_eq!(
            s3.added, 0,
            "5.6.7.8 already seen, 1.2.3.4 is gone (kept in map)"
        );
        assert_eq!(s3.skipped, 1);

        let ins = sink.inserted.lock().unwrap();
        assert_eq!(ins.len(), 2, "sink only saw each endpoint once");
    }

    #[tokio::test]
    async fn refresh_does_not_remove_stale_endpoints() {
        // Add-only semantics: once 1.2.3.4 is in the sink, a later
        // resolution returning only 5.6.7.8 must not cause a remove.
        let resolver = ScriptedResolver::new(&[(
            "api.example.com",
            vec![vec![ip("1.2.3.4")], vec![ip("5.6.7.8")]],
        )]);
        let sink = RecordingSink::default();
        let rules = [rule("api.example.com", &[443])];
        let buckets: [(Verdict, &[NetRule]); 1] =
            [(Verdict(sakimori_common::POLICY_ALLOW), &rules)];
        let mut seen = HashSet::new();
        let _ = refresh_once(&resolver, &buckets, &sink, &mut seen).await;
        let _ = refresh_once(&resolver, &buckets, &sink, &mut seen).await;
        let ins = sink.inserted.lock().unwrap();
        let addrs: Vec<IpAddr> = ins.iter().map(|(a, _, _)| *a).collect();
        assert!(addrs.contains(&ip("1.2.3.4")));
        assert!(addrs.contains(&ip("5.6.7.8")));
    }

    #[tokio::test]
    async fn refresh_rolls_back_seen_on_sink_failure() {
        // If the sink rejects the insert, the endpoint stays unseen
        // so the next tick retries.
        let resolver = ScriptedResolver::new(&[(
            "api.example.com",
            vec![vec![ip("1.2.3.4")], vec![ip("1.2.3.4")]],
        )]);
        let sink = RecordingSink {
            fail_after: Mutex::new(Some(0)),
            ..Default::default()
        };
        let rules = [rule("api.example.com", &[443])];
        let buckets: [(Verdict, &[NetRule]); 1] =
            [(Verdict(sakimori_common::POLICY_ALLOW), &rules)];
        let mut seen = HashSet::new();

        let s1 = refresh_once(&resolver, &buckets, &sink, &mut seen).await;
        assert_eq!(s1.added, 0);
        assert_eq!(s1.errors, 1);
        assert!(seen.is_empty(), "failed insert must not stick in seen");

        // Now let inserts succeed.
        *sink.fail_after.lock().unwrap() = None;
        let s2 = refresh_once(&resolver, &buckets, &sink, &mut seen).await;
        assert_eq!(s2.added, 1);
    }

    #[tokio::test]
    async fn refresh_handles_mixed_allow_and_deny_verdicts() {
        let resolver = ScriptedResolver::new(&[
            ("api.example.com", vec![vec![ip("1.2.3.4")]]),
            ("evil.example.com", vec![vec![ip("9.9.9.9")]]),
        ]);
        let sink = RecordingSink::default();
        let allow = [rule("api.example.com", &[443])];
        let deny = [rule("evil.example.com", &[0])];
        let buckets: [(Verdict, &[NetRule]); 2] = [
            (Verdict(sakimori_common::POLICY_ALLOW), &allow),
            (Verdict(sakimori_common::POLICY_DENY), &deny),
        ];
        let mut seen = HashSet::new();
        let _ = refresh_once(&resolver, &buckets, &sink, &mut seen).await;
        let ins = sink.inserted.lock().unwrap();
        assert_eq!(ins.len(), 2);
        assert!(
            ins.contains(&(ip("1.2.3.4"), 443, sakimori_common::POLICY_ALLOW)),
            "allow entry with correct verdict"
        );
        assert!(
            ins.contains(&(ip("9.9.9.9"), 0, sakimori_common::POLICY_DENY)),
            "deny entry with correct verdict"
        );
    }

    #[tokio::test]
    async fn refresh_counts_resolver_errors_without_aborting() {
        let resolver = ScriptedResolver::new(&[("good.example.com", vec![vec![ip("1.2.3.4")]])]);
        let sink = RecordingSink::default();
        // "bad.example.com" has no script → error on expand.
        let rules = [
            rule("good.example.com", &[443]),
            rule("bad.example.com", &[443]),
        ];
        let buckets: [(Verdict, &[NetRule]); 1] =
            [(Verdict(sakimori_common::POLICY_ALLOW), &rules)];
        let mut seen = HashSet::new();
        let s = refresh_once(&resolver, &buckets, &sink, &mut seen).await;
        assert_eq!(s.added, 1);
        assert_eq!(s.errors, 1);
    }

    #[tokio::test]
    async fn prime_seen_prevents_initial_startup_ips_from_double_inserting() {
        let resolver =
            ScriptedResolver::new(&[("api.example.com", vec![vec![ip("1.2.3.4"), ip("5.6.7.8")]])]);
        let sink = RecordingSink::default();
        let rules = [rule("api.example.com", &[443])];
        let buckets: [(Verdict, &[NetRule]); 1] =
            [(Verdict(sakimori_common::POLICY_ALLOW), &rules)];
        let mut seen = HashSet::new();
        // Pretend startup already wrote 1.2.3.4 into the map.
        RefreshLoop::<ScriptedResolver, RecordingSink>::prime_seen(
            &mut seen,
            &[(
                Endpoint {
                    addr: ip("1.2.3.4"),
                    port: 443,
                },
                Verdict(sakimori_common::POLICY_ALLOW),
            )],
        );
        let s = refresh_once(&resolver, &buckets, &sink, &mut seen).await;
        assert_eq!(s.added, 1, "only 5.6.7.8 was new");
        assert_eq!(s.skipped, 1);
    }

    #[test]
    fn seen_key_distinguishes_verdict_and_port() {
        let a = Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            port: 443,
        };
        let k1 = SeenKey::of(&a, Verdict(sakimori_common::POLICY_ALLOW));
        let k2 = SeenKey::of(&a, Verdict(sakimori_common::POLICY_DENY));
        let k3 = SeenKey::of(
            &Endpoint {
                addr: a.addr,
                port: 80,
            },
            Verdict(sakimori_common::POLICY_ALLOW),
        );
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[tokio::test]
    async fn refresh_loop_exits_promptly_on_stop_signal() {
        let resolver = ScriptedResolver::new(&[]);
        let sink = RecordingSink::default();
        let loop_ = RefreshLoop::new(resolver, sink, vec![], vec![], Duration::from_millis(50));
        let stop = loop_.stop_handle();
        // Fire the stop signal *before* spawning, to exercise the
        // race where stop() lands before run() registers a waiter.
        stop.stop();
        let handle = tokio::spawn(async move { loop_.run(HashSet::new()).await });
        let seen = tokio::time::timeout(Duration::from_millis(500), handle)
            .await
            .expect("refresh loop did not exit in time")
            .unwrap();
        assert!(seen.is_empty());
    }

    #[tokio::test]
    async fn zero_interval_makes_run_return_immediately() {
        let resolver = ScriptedResolver::new(&[]);
        let sink = RecordingSink::default();
        let loop_ = RefreshLoop::new(
            resolver,
            sink,
            vec![rule("api.example.com", &[443])],
            vec![],
            Duration::ZERO,
        );
        let seen = loop_.run(HashSet::new()).await;
        assert!(seen.is_empty());
    }
}
