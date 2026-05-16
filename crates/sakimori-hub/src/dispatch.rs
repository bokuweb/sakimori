//! Webhook dispatcher: convert `findings` rows into HTTP POSTs to
//! operator-registered targets.
//!
//! This is the "push notifications" half of CLAUDE.md roadmap #6.
//! The previous slices built the install inventory and the
//! advisory-vs-install JOIN; this one turns each new finding into a
//! delivery against every target whose `(min_severity, source_filter)`
//! the finding satisfies.
//!
//! ## Delivery contract
//!
//! For each pending `(finding, target)` pair the dispatcher
//! constructs a [`DeliveryPayload`] (JSON), signs the body with
//! HMAC-SHA256 keyed on the target's secret, and POSTs:
//!
//! ```text
//! POST <target.url>
//! Content-Type: application/json
//! X-Sakimori-Event: finding.created
//! X-Sakimori-Signature: sha256=<hex>
//! X-Sakimori-Target: <target.label>
//! User-Agent: sakimori-hub/<version>
//! ```
//!
//! Subscribers re-compute HMAC-SHA256 of the raw body with the
//! shared secret and compare to the header to prove authenticity.
//!
//! ## Replay protection
//!
//! The HMAC only proves the message was produced by someone
//! holding the shared secret — it does not prove freshness. The
//! signed body carries `dispatched_at` (RFC 3339, UTC), and
//! subscribers should:
//!
//! 1. Reject deliveries whose `dispatched_at` is more than ~5
//!    minutes in the past or future, to bound the replay window.
//! 2. Track `finding_id` as a dedupe key — the hub guarantees a
//!    given finding is delivered at most once per target
//!    successfully (the `dispatch_attempts` unique partial index
//!    on `(finding_id, target_id) WHERE success = 1` enforces
//!    this server-side), so any duplicate the subscriber sees was
//!    either a network retry or an active replay.
//!
//! Each attempt is durably recorded in `dispatch_attempts` —
//! `(finding_id, target_id, success)` is the per-attempt outcome.
//! Re-running `run_once` is idempotent: pairs that already have a
//! successful attempt are skipped, pairs that have hit the failure
//! cap are skipped, everything else is retried.
//!
//! ## What's not in this slice
//!
//! - **Exponential backoff.** The retry policy is "up to N
//!   attempts" with no inter-attempt delay enforced by the
//!   dispatcher itself. Operators who want backoff can re-run
//!   `/dispatch/run` from cron with whatever cadence they want;
//!   the failure cap stops a permanently-broken target from
//!   silently filling the attempts table.
//! - **Email and Slack adapters.** Both deliver as HTTP webhooks
//!   in practice (Slack incoming-webhook is `POST <slack-url>`;
//!   email-via-API is `POST <SES/etc>` with auth). The signed
//!   webhook is the substrate; named adapters can layer on top
//!   when there's a real user asking for them.

use std::net::ToSocketAddrs;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::Source;
use crate::advisories::Severity;
use crate::store::{
    PendingDelivery, Store, StoredAdvisory, StoredEvent, StoredFinding, TargetSpec,
};

/// Per-call result so the operator can see what fired and what
/// stayed pending. `considered` is the number of pending pairs
/// this run examined; `delivered` and `failed` partition it.
/// `over_cap_at_scan` is the count of `(finding, target)` pairs
/// that were excluded because they had already hit
/// `attempt_cap` *at the moment the JOIN ran* — operators
/// notice this as "we have N targets that are permanently stuck;
/// fix the target or bump the cap".
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DispatchReport {
    pub considered: i64,
    pub delivered: i64,
    pub failed: i64,
    pub over_cap_at_scan: i64,
}

/// Default cap on the number of attempts per `(finding, target)`
/// pair. Keeps a permanently-broken target from filling the
/// attempts table. Operators can override per-call.
pub const DEFAULT_ATTEMPT_CAP: i64 = 5;

/// Wire shape of every POST body. Stable so subscriber code can
/// rely on the field names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryPayload {
    pub event: &'static str,
    pub dispatched_at: DateTime<Utc>,
    pub finding_id: i64,
    pub finding_created_at: DateTime<Utc>,
    pub advisory: AdvisorySummary,
    pub install: InstallSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorySummary {
    pub osv_id: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSummary {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub source: Source,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_path: Option<String>,
    pub resolved_at: DateTime<Utc>,
}

impl DeliveryPayload {
    pub fn from_parts(f: &StoredFinding) -> Self {
        Self {
            event: "finding.created",
            dispatched_at: Utc::now(),
            finding_id: f.id,
            finding_created_at: f.created_at,
            advisory: summarise_adv(&f.advisory),
            install: summarise_install(&f.install),
        }
    }

    pub fn for_pending(p: &PendingDelivery) -> Self {
        Self {
            event: "finding.created",
            dispatched_at: Utc::now(),
            finding_id: p.finding_id,
            finding_created_at: p.finding_created_at,
            advisory: AdvisorySummary {
                osv_id: p.advisory_osv_id.clone(),
                severity: p.advisory_severity,
                summary: p.advisory_summary.clone(),
                published_at: p.advisory_published_at,
            },
            install: InstallSummary {
                ecosystem: p.install_ecosystem.clone(),
                name: p.install_name.clone(),
                version: p.install_version.clone(),
                source: p.install_source,
                project_path: p.install_project_path.clone(),
                resolved_at: p.install_resolved_at,
            },
        }
    }
}

fn summarise_adv(a: &StoredAdvisory) -> AdvisorySummary {
    AdvisorySummary {
        osv_id: a.osv_id.clone(),
        severity: a.severity,
        summary: a.summary.clone(),
        published_at: a.published_at,
    }
}

fn summarise_install(i: &StoredEvent) -> InstallSummary {
    InstallSummary {
        ecosystem: i.ecosystem.clone(),
        name: i.name.clone(),
        version: i.version.clone(),
        source: i.source,
        project_path: i.project_path.clone(),
        resolved_at: i.resolved_at,
    }
}

/// Pluggable HTTP client. Production uses [`UreqClient`]; tests
/// inject a stub so the dispatcher can be exercised offline.
pub trait WebhookClient: Send + Sync {
    /// POST `body` with the supplied headers and return the
    /// response status code, or a transport-level error string
    /// (e.g. DNS, TLS, connect refused).
    fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> std::result::Result<u16, String>;
}

/// Default [`WebhookClient`] backed by `ureq`. Honours a 10-second
/// timeout so a hung target can't pin the dispatcher worker.
///
/// The client also enforces the SSRF policy at *connect* time
/// — not via a separate preflight, but by installing a custom
/// `ureq::Resolver` on the `Agent`. The agent calls the resolver
/// exactly once per connection, and the resolver returns only the
/// public addresses; ureq then dials one of those addresses, so
/// the address that was *checked* is the address that's
/// *connected to*. This closes the TOCTOU between a preflight
/// lookup and ureq's own resolution that a DNS-rebinding or
/// split-DNS target could otherwise exploit.
pub struct UreqClient {
    agent: ureq::Agent,
}

impl Default for UreqClient {
    fn default() -> Self {
        Self::new(false)
    }
}

impl UreqClient {
    pub fn new(allow_private: bool) -> Self {
        let resolver = SafeResolver { allow_private };
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(10))
                .user_agent(concat!("sakimori-hub/", env!("CARGO_PKG_VERSION")))
                .resolver(resolver)
                .build(),
        }
    }
}

/// Resolver shim. Delegates DNS to `ToSocketAddrs` (libstd's
/// system resolver — same one `ureq` uses by default), filters the
/// result through [`ip_is_private`], and returns only the
/// surviving addresses. ureq picks one of those to dial, so the
/// connection lands on an address we explicitly approved.
struct SafeResolver {
    allow_private: bool,
}

impl ureq::Resolver for SafeResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        let addrs: Vec<std::net::SocketAddr> = netloc.to_socket_addrs()?.collect();
        if self.allow_private {
            return Ok(addrs);
        }
        let filtered: Vec<_> = addrs
            .iter()
            .copied()
            .filter(|sa| !ip_is_private(sa.ip()))
            .collect();
        if filtered.is_empty() && !addrs.is_empty() {
            return Err(std::io::Error::other(format!(
                "refusing to connect to {netloc}: all resolved addresses are private \
                 (set allow_private_webhooks to override)"
            )));
        }
        Ok(filtered)
    }
}

impl WebhookClient for UreqClient {
    fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> std::result::Result<u16, String> {
        let mut req = self.agent.post(url).set("content-type", "application/json");
        for (k, v) in headers {
            req = req.set(k, v);
        }
        match req.send_bytes(body) {
            Ok(resp) => Ok(resp.status()),
            // ureq's `Error::Status` carries the HTTP code even
            // though it's >=400 — that is *not* a transport error;
            // record it as a real status.
            Err(ureq::Error::Status(code, _)) => Ok(code),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Compute the `X-Sakimori-Signature` value for `body` keyed on
/// `secret`. Exposed so the subscriber side of integration tests
/// can re-derive it.
pub fn sign(secret: &[u8], body: &[u8]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Run a single dispatch pass.
///
/// Pulls up to `batch` pending deliveries from `store`, serializes
/// each payload, signs it with the target's secret, posts via
/// `client`, and records the outcome. Returns a per-call summary.
///
/// Concurrency: callers MUST serialize calls to `run_once` against
/// the same `store` so two parallel runs can't both claim the same
/// `(finding, target)` pair before either has recorded success.
/// The `AppState` in `crate::server` holds a `tokio::sync::Mutex`
/// for exactly this purpose; if you call `run_once` from elsewhere,
/// wrap it in your own equivalent.
///
/// **Deploy model is one hub process per team.** The mutex is
/// in-process only. Two `sakimori-hub` processes pointing at the
/// same SQLite file could both pull the same `(finding, target)`
/// pair, both POST, then race on the unique partial index — one
/// success-attempt insert wins, the other returns a UNIQUE
/// constraint error and is recorded as a failure, but the
/// subscriber has already received both POSTs. Operators who
/// genuinely need multi-process need to add a DB-level lease
/// (e.g. an `UPDATE … WHERE claimed_at IS NULL RETURNING …`
/// claim pass) before this scales out — out of scope here.
pub async fn run_once(
    store: Arc<Store>,
    client: Arc<dyn WebhookClient>,
    batch: u32,
    attempt_cap: i64,
) -> Result<DispatchReport> {
    let (pending, over_cap_at_scan) = store
        .pending_deliveries_with_stats(batch, attempt_cap)
        .await
        .context("listing pending deliveries")?;
    let considered = pending.len() as i64;
    let mut delivered = 0i64;
    let mut failed = 0i64;
    for p in &pending {
        let payload = DeliveryPayload::for_pending(p);
        let body = serde_json::to_vec(&payload).context("serializing dispatch payload")?;
        let sig = sign(p.target_secret.as_bytes(), &body);
        let headers = vec![
            ("X-Sakimori-Event".into(), payload.event.into()),
            ("X-Sakimori-Signature".into(), sig),
            ("X-Sakimori-Target".into(), p.target_label.clone()),
        ];
        match client.post(&p.target_url, &headers, &body) {
            Ok(status) if (200..300).contains(&status) => {
                store
                    .record_attempt(p.finding_id, p.target_id, true, Some(status as i64), None)
                    .await?;
                delivered += 1;
            }
            Ok(status) => {
                store
                    .record_attempt(
                        p.finding_id,
                        p.target_id,
                        false,
                        Some(status as i64),
                        Some(format!("non-2xx status {status}")),
                    )
                    .await?;
                failed += 1;
            }
            Err(transport) => {
                store
                    .record_attempt(p.finding_id, p.target_id, false, None, Some(transport))
                    .await?;
                failed += 1;
            }
        }
    }
    Ok(DispatchReport {
        considered,
        delivered,
        failed,
        over_cap_at_scan,
    })
}

/// Handle for a background dispatcher loop started with
/// [`spawn_loop`]. Drop the handle to keep the loop running for
/// the lifetime of the process; call [`DispatcherHandle::shutdown`]
/// to ask it to stop cleanly (it finishes whatever pass is in
/// flight and then exits).
///
/// The loop is intentionally simple: every `interval`, take the
/// shared `dispatch_lock`, call [`run_once`], release the lock.
/// Sharing the lock with the HTTP handler means a `POST
/// /dispatch/run` racing the timer can't double-fire — whichever
/// gets the lock first goes; the other waits and then either
/// runs (if there are still pending pairs) or no-ops.
pub struct DispatcherHandle {
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    join: tokio::task::JoinHandle<()>,
}

impl DispatcherHandle {
    /// Ask the loop to stop and wait for it to finish the
    /// current pass (if any) and exit. Idempotent.
    pub async fn shutdown(self) {
        // Best-effort: the receiver may already have dropped if
        // the loop crashed; that's fine, the join below tells us.
        let _ = self.shutdown_tx.send(());
        let _ = self.join.await;
    }
}

/// Spawn a background task that calls [`run_once`] every
/// `interval`. Errors from any single pass are `log::warn!`ed
/// (e.g. transient DB lock, malformed advisory) so the loop
/// keeps running rather than wedging the hub on the first hiccup.
///
/// `dispatch_lock` MUST be the same `Arc<tokio::sync::Mutex>` the
/// HTTP `/dispatch/run` handler uses, so the two paths can't
/// claim the same `(finding, target)` pair simultaneously.
pub fn spawn_loop(
    store: Arc<Store>,
    client: Arc<dyn WebhookClient>,
    dispatch_lock: Arc<tokio::sync::Mutex<()>>,
    interval: std::time::Duration,
    batch: u32,
    attempt_cap: i64,
) -> DispatcherHandle {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let join = tokio::spawn(async move {
        // `MissedTickBehavior::Delay` keeps the cadence smooth
        // when a single pass takes longer than `interval`
        // (e.g. one slow target); otherwise tokio's default
        // would fire back-to-back ticks to catch up, which is
        // exactly the wrong behaviour for a network worker.
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    // A pass that the HTTP `/dispatch/run` handler
                    // is currently holding could otherwise pin
                    // shutdown until both passes finish; this
                    // inner select lets shutdown win the race for
                    // the lock and exit straight away.
                    let _guard = tokio::select! {
                        g = dispatch_lock.lock() => g,
                        _ = &mut shutdown_rx => break,
                    };
                    // Phase 1: derive any new (advisory, install)
                    // matches. Without this the background loop
                    // would only re-deliver findings someone else
                    // produced via `POST /scan` — which is exactly
                    // *not* "set and forget". Errors are logged
                    // but don't skip the dispatch phase (a partial
                    // scan + dispatch is still useful).
                    match store.scan_findings().await {
                        Ok(report) if report.new_findings > 0 => log::info!(
                            target: "sakimori_hub::dispatch",
                            "background scan: {} new finding(s) (total {})",
                            report.new_findings, report.total_findings,
                        ),
                        Ok(_) => {}
                        Err(e) => log::warn!(
                            target: "sakimori_hub::dispatch",
                            "background scan errored: {e:#}",
                        ),
                    }
                    // Phase 2: deliver everything pending.
                    match run_once(store.clone(), client.clone(), batch, attempt_cap).await {
                        Ok(report) => {
                            if report.delivered + report.failed > 0 {
                                log::info!(
                                    target: "sakimori_hub::dispatch",
                                    "background pass: delivered={} failed={} over_cap={}",
                                    report.delivered, report.failed, report.over_cap_at_scan,
                                );
                            }
                        }
                        Err(e) => log::warn!(
                            target: "sakimori_hub::dispatch",
                            "background dispatcher pass errored: {e:#}",
                        ),
                    }
                }
                _ = &mut shutdown_rx => break,
            }
        }
    });
    DispatcherHandle { shutdown_tx, join }
}

/// Validate operator-supplied target fields before they hit the
/// store. Mirrors the advisory validator pattern.
#[derive(Debug, thiserror::Error)]
pub enum TargetValidationError {
    #[error("label is empty")]
    EmptyLabel,
    #[error("label exceeds 128 chars")]
    LabelTooLong,
    #[error("url is empty")]
    EmptyUrl,
    #[error("url must start with http:// or https://")]
    UrlScheme,
    #[error("url host is missing")]
    UrlHostMissing,
    #[error(
        "url host {0} resolves to a private / loopback / link-local address; \
         pass allow_private_webhooks if this is intentional (e.g. a localhost test receiver)"
    )]
    UrlHostPrivate(String),
    #[error("secret must be at least 16 chars")]
    SecretTooShort,
}

pub fn validate_target(
    spec: &TargetSpec,
    allow_private: bool,
) -> std::result::Result<(), TargetValidationError> {
    if spec.label.is_empty() {
        return Err(TargetValidationError::EmptyLabel);
    }
    if spec.label.len() > 128 {
        return Err(TargetValidationError::LabelTooLong);
    }
    if spec.url.is_empty() {
        return Err(TargetValidationError::EmptyUrl);
    }
    if !(spec.url.starts_with("http://") || spec.url.starts_with("https://")) {
        return Err(TargetValidationError::UrlScheme);
    }
    if !allow_private {
        let host = extract_host(&spec.url).ok_or(TargetValidationError::UrlHostMissing)?;
        if host_looks_private(host) {
            return Err(TargetValidationError::UrlHostPrivate(host.to_string()));
        }
    }
    if spec.secret.len() < 16 {
        return Err(TargetValidationError::SecretTooShort);
    }
    Ok(())
}

/// Pull the host part out of a URL without depending on a full URL
/// parser. Recognises `scheme://[user[:pass]@]host[:port]/...`.
/// Returns `None` for shapes that don't match.
fn extract_host(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://")?.1;
    let after_authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let after_userinfo = match after_authority.rsplit_once('@') {
        Some((_, rest)) => rest,
        None => after_authority,
    };
    if after_userinfo.is_empty() {
        return None;
    }
    // Strip port. IPv6 hosts are bracketed: `[::1]:8080`.
    if let Some(rest) = after_userinfo.strip_prefix('[') {
        let (host, _) = rest.split_once(']')?;
        Some(host)
    } else {
        Some(after_userinfo.split(':').next().unwrap_or(after_userinfo))
    }
}

pub(crate) fn host_looks_private(host: &str) -> bool {
    // String matches first — covers the cases that don't parse as
    // an IP literal (DNS names) cheaply.
    let lower = host.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "localhost" | "ip6-localhost" | "ip6-loopback"
    ) {
        return true;
    }
    if lower.ends_with(".localhost") || lower.ends_with(".internal") {
        return true;
    }
    if lower == "metadata.google.internal" {
        return true;
    }
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        return ip_is_private(addr);
    }
    false
}

pub(crate) fn ip_is_private(addr: std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // 169.254.169.254 is the cloud metadata IP
                || v4.octets() == [169, 254, 169, 254]
                // Carrier-grade NAT (RFC6598)
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        std::net::IpAddr::V6(v6) => {
            // IPv4-mapped IPv6 (`::ffff:10.0.0.1`,
            // `::ffff:127.0.0.1`, `::ffff:169.254.169.254`) are
            // really IPv4 — apply the v4 blocker to the unwrapped
            // form, otherwise an attacker bypasses the v4 checks
            // by writing the same address as `[::ffff:...]`.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ip_is_private(std::net::IpAddr::V4(v4));
            }
            v6.is_loopback() || v6.is_unspecified() || {
                let s = v6.segments()[0];
                // fc00::/7 ULA (fc00..fdff) or fe80::/10 link-local
                (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::TargetSpec;
    use sakimori_core::deps::Ecosystem;
    use sakimori_core::installs::{ExecutionMode, InstallEvent};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct CountingClient {
        calls: AtomicU32,
    }
    impl WebhookClient for CountingClient {
        fn post(
            &self,
            _url: &str,
            _headers: &[(String, String)],
            _body: &[u8],
        ) -> std::result::Result<u16, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(200)
        }
    }

    async fn seed_finding_and_target(store: &Store, label: &str) -> i64 {
        store
            .insert(
                InstallEvent::new(Ecosystem::Npm, "p", "1.0.0")
                    .with_mode(ExecutionMode::Persistent)
                    .into(),
            )
            .await
            .unwrap();
        let adv: crate::advisories::OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": format!("ADV-{label}"),
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"ecosystem": "npm", "name": "p"}, "versions": ["1.0.0"]}],
        }))
        .unwrap();
        store.upsert_advisory(adv, None).await.unwrap();
        store.scan_findings().await.unwrap();
        store
            .register_target(TargetSpec {
                label: label.into(),
                url: "https://t.example.com/".into(),
                secret: "0123456789abcdef0123".into(),
                min_severity: Severity::Low,
                source_filter: None,
            })
            .await
            .unwrap()
    }

    /// Variant that skips `scan_findings` so we can assert the
    /// loop itself drives the scan phase.
    async fn seed_install_and_advisory_only(store: &Store, label: &str) -> i64 {
        store
            .insert(
                InstallEvent::new(Ecosystem::Npm, "p", "1.0.0")
                    .with_mode(ExecutionMode::Persistent)
                    .into(),
            )
            .await
            .unwrap();
        let adv: crate::advisories::OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": format!("ADV-{label}"),
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"ecosystem": "npm", "name": "p"}, "versions": ["1.0.0"]}],
        }))
        .unwrap();
        store.upsert_advisory(adv, None).await.unwrap();
        // Deliberately NOT calling scan_findings — the loop must.
        store
            .register_target(TargetSpec {
                label: label.into(),
                url: "https://t.example.com/".into(),
                secret: "0123456789abcdef0123".into(),
                min_severity: Severity::Low,
                source_filter: None,
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn spawn_loop_runs_scan_then_dispatch() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        seed_install_and_advisory_only(&store, "ops").await;
        // Pre-condition: no findings yet.
        assert!(
            store
                .list_findings(Default::default())
                .await
                .unwrap()
                .is_empty()
        );
        let client = Arc::new(CountingClient {
            calls: AtomicU32::new(0),
        });
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let handle = spawn_loop(
            store.clone(),
            client.clone(),
            lock.clone(),
            std::time::Duration::from_millis(20),
            100,
            DEFAULT_ATTEMPT_CAP,
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        handle.shutdown().await;
        assert_eq!(
            client.calls.load(Ordering::SeqCst),
            1,
            "loop must scan then dispatch"
        );
    }

    #[tokio::test]
    async fn spawn_loop_delivers_pending_then_idles() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        seed_finding_and_target(&store, "ops").await;
        let client = Arc::new(CountingClient {
            calls: AtomicU32::new(0),
        });
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let handle = spawn_loop(
            store.clone(),
            client.clone(),
            lock.clone(),
            std::time::Duration::from_millis(20),
            100,
            DEFAULT_ATTEMPT_CAP,
        );
        // Give the loop several ticks to fire. The pending pair
        // should deliver on the first tick; subsequent ticks see
        // an empty queue and do nothing.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        handle.shutdown().await;
        let n = client.calls.load(Ordering::SeqCst);
        assert_eq!(
            n, 1,
            "exactly one delivery expected; got {n} (loop should idle after the queue drains)"
        );
    }

    #[tokio::test]
    async fn spawn_loop_shares_dispatch_lock_with_caller() {
        // Hold the lock outside the loop; the loop must not be
        // able to fire while it's held.
        let store = Arc::new(Store::open_in_memory().unwrap());
        seed_finding_and_target(&store, "ops").await;
        let client = Arc::new(CountingClient {
            calls: AtomicU32::new(0),
        });
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let held = lock.clone().lock_owned().await;
        let handle = spawn_loop(
            store.clone(),
            client.clone(),
            lock.clone(),
            std::time::Duration::from_millis(20),
            100,
            DEFAULT_ATTEMPT_CAP,
        );
        // Several ticks elapse while we hold the lock — no deliveries.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(
            client.calls.load(Ordering::SeqCst),
            0,
            "loop must wait for the dispatch_lock"
        );
        drop(held);
        // Give the loop a moment to acquire and deliver.
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        handle.shutdown().await;
        assert_eq!(
            client.calls.load(Ordering::SeqCst),
            1,
            "delivery should land after the external holder drops"
        );
    }

    #[tokio::test]
    async fn shutdown_returns_promptly_while_external_holds_lock() {
        // Regression: previously the loop awaited the dispatch
        // lock outside the shutdown `select!`, so shutdown was
        // pinned until whoever held the lock released it.
        let store = Arc::new(Store::open_in_memory().unwrap());
        let client = Arc::new(CountingClient {
            calls: AtomicU32::new(0),
        });
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let handle = spawn_loop(
            store,
            client,
            lock.clone(),
            std::time::Duration::from_millis(10),
            100,
            DEFAULT_ATTEMPT_CAP,
        );
        // Hold the lock so any tick that fires can't get past
        // the lock acquisition.
        let _held = lock.lock_owned().await;
        // Let at least one tick fire and block on the lock.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let start = std::time::Instant::now();
        tokio::time::timeout(std::time::Duration::from_secs(2), handle.shutdown())
            .await
            .expect("shutdown should not be pinned by a held dispatch_lock");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "shutdown took {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn shutdown_returns_promptly_even_with_long_interval() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let client = Arc::new(CountingClient {
            calls: AtomicU32::new(0),
        });
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let handle = spawn_loop(
            store,
            client,
            lock,
            std::time::Duration::from_secs(60), // long enough that we'd notice
            100,
            DEFAULT_ATTEMPT_CAP,
        );
        let start = std::time::Instant::now();
        // Wrap shutdown in a timeout to surface a regression
        // loudly rather than hanging the test runner.
        tokio::time::timeout(std::time::Duration::from_secs(2), handle.shutdown())
            .await
            .expect("shutdown should return well within the test timeout");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "shutdown took {:?}",
            start.elapsed()
        );
    }

    // Silence "unused import" when the tests above are the only
    // consumers of these — keeps the test module compiling without
    // hand-tracking every helper.
    #[allow(dead_code)]
    fn _ensure_mutex_used(_: Mutex<()>) {}

    #[test]
    fn signature_is_stable_and_keyed() {
        let a = sign(b"secret-1234567890abc", b"hello");
        let b = sign(b"secret-1234567890abc", b"hello");
        let c = sign(b"different-1234567890", b"hello");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("sha256="));
    }

    #[test]
    fn validate_rejects_obviously_bad_targets() {
        let base = TargetSpec {
            label: "ops".into(),
            url: "https://ops.example.com/hook".into(),
            secret: "0123456789abcdef".into(),
            min_severity: Severity::High,
            source_filter: None,
        };
        validate_target(&base, false).unwrap();
        let bad = TargetSpec {
            url: "ftp://nope/".into(),
            ..base.clone()
        };
        assert!(matches!(
            validate_target(&bad, false),
            Err(TargetValidationError::UrlScheme)
        ));
        let short_secret = TargetSpec {
            secret: "tiny".into(),
            ..base.clone()
        };
        assert!(matches!(
            validate_target(&short_secret, false),
            Err(TargetValidationError::SecretTooShort)
        ));
    }

    #[test]
    fn private_hosts_blocked_unless_opted_in() {
        let mk = |url: &str| TargetSpec {
            label: "t".into(),
            url: url.into(),
            secret: "0123456789abcdef".into(),
            min_severity: Severity::High,
            source_filter: None,
        };
        for url in [
            "http://127.0.0.1/hook",
            "http://localhost:9000/hook",
            "http://10.0.0.5/hook",
            "http://192.168.1.1/hook",
            "http://[::1]/hook",
            "http://169.254.169.254/latest/meta-data",
            "http://metadata.google.internal/",
            "http://internal-ops.internal/x",
        ] {
            assert!(
                matches!(
                    validate_target(&mk(url), false),
                    Err(TargetValidationError::UrlHostPrivate(_))
                ),
                "{url} should be blocked without allow_private_webhooks"
            );
            // Same URL accepted when operator opts in.
            validate_target(&mk(url), true).expect(url);
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_does_not_bypass_private_check() {
        for url in [
            "http://[::ffff:127.0.0.1]/hook",
            "http://[::ffff:10.0.0.1]/hook",
            "http://[::ffff:169.254.169.254]/latest/meta-data",
        ] {
            let spec = TargetSpec {
                label: "t".into(),
                url: url.into(),
                secret: "0123456789abcdef".into(),
                min_severity: Severity::High,
                source_filter: None,
            };
            assert!(
                matches!(
                    validate_target(&spec, false),
                    Err(TargetValidationError::UrlHostPrivate(_))
                ),
                "{url} must be blocked: IPv4-mapped IPv6 unwraps to a private v4"
            );
        }
    }

    #[test]
    fn ureq_client_refuses_dns_resolved_to_private() {
        // localhost resolves to 127.0.0.1 on every supported
        // platform; the client must refuse to POST even though
        // `localhost` was never literally registered as a target
        // URL string (this is the rebinding-style bypass).
        let client = UreqClient::new(false);
        let err = client
            .post("http://localhost:1/hook", &[], b"{}")
            .expect_err("must refuse");
        assert!(err.contains("private") || err.contains("resolved address"));
    }

    #[test]
    fn public_hosts_pass_validation() {
        for url in [
            "https://ops.example.com/hook",
            // Public IPv6 literal (Cloudflare 1.1.1.1's v6 sibling).
            // extract_host strips brackets; the validator only checks
            // whether the resulting IP is private — `2606:4700::1111`
            // is not, so this should pass.
            "https://[2606:4700::1111]/hook",
        ] {
            let spec = TargetSpec {
                label: "t".into(),
                url: url.into(),
                secret: "0123456789abcdef".into(),
                min_severity: Severity::High,
                source_filter: None,
            };
            validate_target(&spec, false).expect(url);
        }
    }
}
