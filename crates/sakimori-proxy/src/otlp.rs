//! Opt-in OTLP/HTTP log exporter for install events.
//!
//! Roadmap item #6 (CLAUDE.md): on top of the local `/ingest`
//! transport for sakimori-hub, the proxy can also emit each
//! resolved install as an OTLP `LogRecord` so users can fan
//! installs out to any existing observability backend
//! (Datadog / Honeycomb / Loki / otel-collector) without
//! standing up sakimori-hub.
//!
//! Wire format: OTLP/HTTP **JSON** (Content-Type `application/json`)
//! against an `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`-shaped URL. The
//! user provides the full URL (e.g. `https://otel.example.com/v1/logs`);
//! we don't auto-append `/v1/logs` because some collectors mount
//! OTLP on a custom path.
//!
//! Dispatch is fire-and-forget on a `spawn_blocking` worker: an
//! install must never block on the exporter, and any export
//! failure is a `log::warn!` — not a propagated error.

use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::{Value, json};

use sakimori_core::installs::{ExecutionMode, InstallEvent};

/// Best-effort OTLP/HTTP log exporter. Cheap to clone via `Arc`.
pub struct OtlpExporter {
    endpoint: String,
    headers: Vec<(String, String)>,
    user_agent: String,
    service_name: String,
    service_version: String,
}

impl OtlpExporter {
    pub fn new(endpoint: String, headers: Vec<(String, String)>, user_agent: String) -> Self {
        Self {
            endpoint,
            headers,
            user_agent,
            service_name: "sakimori-proxy".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Build the OTLP `ExportLogsServiceRequest` JSON payload for a
    /// single install event. Public for testing.
    pub fn build_payload(&self, event: &InstallEvent) -> Value {
        build_payload(event, &self.service_name, &self.service_version)
    }

    /// Fire-and-forget dispatch. Returns immediately; the actual
    /// HTTP POST runs on a `spawn_blocking` worker so the hudsucker
    /// async handler is never blocked on network I/O. Failure is
    /// logged at `warn` level — installs must not break because the
    /// observability backend is down.
    pub fn dispatch(self: &Arc<Self>, event: &InstallEvent) {
        let payload = self.build_payload(event);
        let endpoint = self.endpoint.clone();
        let headers = self.headers.clone();
        let ua = self.user_agent.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = post_otlp(&endpoint, &headers, &ua, &payload) {
                log::warn!("OTLP export to {endpoint} failed: {e:#}");
            }
        });
    }
}

fn post_otlp(
    endpoint: &str,
    headers: &[(String, String)],
    user_agent: &str,
    body: &Value,
) -> Result<()> {
    let mut req = ureq::post(endpoint)
        .set("content-type", "application/json")
        .set("user-agent", user_agent)
        .timeout(std::time::Duration::from_millis(3000));
    for (k, v) in headers {
        req = req.set(k, v);
    }
    let resp = req
        .send_json(body.clone())
        .with_context(|| format!("POST {endpoint}"))?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        anyhow::bail!("OTLP endpoint returned {status}");
    }
    Ok(())
}

fn build_payload(event: &InstallEvent, service_name: &str, service_version: &str) -> Value {
    // `timestamp_nanos_opt` returns `None` only for dates outside
    // ~1677–2262; install timestamps are always `Utc::now()` so the
    // fallback path is effectively unreachable, but degrade to 0
    // rather than panic if it ever fires.
    let nanos = event.resolved_at.timestamp_nanos_opt().unwrap_or(0);
    // OTLP JSON encodes 64-bit ints as decimal strings (per the
    // proto3 JSON mapping) so values > 2^53 round-trip safely
    // through Javascript-flavoured parsers.
    let ts = nanos.to_string();

    let mode_str = match event.execution_mode {
        ExecutionMode::Persistent => "persistent",
        ExecutionMode::Ephemeral => "ephemeral",
        ExecutionMode::Unknown => "unknown",
    };

    let mut attrs = vec![
        attr_str("package.ecosystem", &event.ecosystem),
        attr_str("package.name", &event.name),
        attr_str("package.version", &event.version),
        attr_str("package.resolved_at", &event.resolved_at.to_rfc3339()),
        attr_str("package.execution_mode", mode_str),
    ];
    if let Some(p) = event.project_path.as_deref() {
        attrs.push(attr_str("package.project_path", p));
    }
    if let Some(ua) = event.user_agent.as_deref() {
        attrs.push(attr_str("package.user_agent", ua));
    }

    json!({
        "resourceLogs": [{
            "resource": {
                "attributes": [
                    attr_str("service.name", service_name),
                    attr_str("service.version", service_version),
                ],
            },
            "scopeLogs": [{
                "scope": { "name": "sakimori-proxy", "version": service_version },
                "logRecords": [{
                    "timeUnixNano": ts,
                    "observedTimeUnixNano": ts,
                    "severityNumber": 9,
                    "severityText": "INFO",
                    "body": { "stringValue": "package install" },
                    "attributes": attrs,
                }],
            }],
        }],
    })
}

fn attr_str(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use sakimori_core::deps::Ecosystem;

    fn sample_event() -> InstallEvent {
        let mut ev = InstallEvent::new(Ecosystem::Npm, "left-pad", "1.3.0")
            .with_mode(ExecutionMode::Persistent)
            .with_user_agent("npm/10.0.0 node/20.0.0");
        // Pin the timestamp so the assertion is deterministic.
        ev.resolved_at = DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&Utc);
        ev
    }

    #[test]
    fn payload_shape_matches_otlp() {
        let exp = OtlpExporter::new(
            "https://example.invalid/v1/logs".into(),
            vec![],
            "sakimori-test/0".into(),
        );
        let p = exp.build_payload(&sample_event());

        // Top-level shape: one resourceLogs / one scopeLogs / one logRecord.
        let logs = &p["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(logs["severityText"], "INFO");
        assert_eq!(logs["body"]["stringValue"], "package install");
        let expected_ns = DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap()
            .to_string();
        assert_eq!(logs["timeUnixNano"], expected_ns);
        assert_eq!(logs["observedTimeUnixNano"], expected_ns);

        let attrs = logs["attributes"].as_array().expect("attributes array");
        let get = |k: &str| -> Option<String> {
            attrs.iter().find_map(|a| {
                if a["key"] == k {
                    a["value"]["stringValue"].as_str().map(str::to_string)
                } else {
                    None
                }
            })
        };
        assert_eq!(get("package.ecosystem").as_deref(), Some("npm"));
        assert_eq!(get("package.name").as_deref(), Some("left-pad"));
        assert_eq!(get("package.version").as_deref(), Some("1.3.0"));
        assert_eq!(get("package.execution_mode").as_deref(), Some("persistent"));
        assert_eq!(
            get("package.user_agent").as_deref(),
            Some("npm/10.0.0 node/20.0.0")
        );
        assert!(
            get("package.resolved_at")
                .unwrap()
                .starts_with("2026-01-02")
        );

        // Resource attributes carry service identity.
        let res_attrs = p["resourceLogs"][0]["resource"]["attributes"]
            .as_array()
            .unwrap();
        assert!(
            res_attrs.iter().any(
                |a| a["key"] == "service.name" && a["value"]["stringValue"] == "sakimori-proxy"
            )
        );
    }

    #[test]
    fn unknown_mode_serialises_as_unknown() {
        let exp = OtlpExporter::new("http://x".into(), vec![], "ua".into());
        let mut ev = sample_event();
        ev.execution_mode = ExecutionMode::Unknown;
        let p = exp.build_payload(&ev);
        let attrs = p["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"]
            .as_array()
            .unwrap()
            .clone();
        let mode = attrs
            .iter()
            .find(|a| a["key"] == "package.execution_mode")
            .unwrap();
        assert_eq!(mode["value"]["stringValue"], "unknown");
    }

    #[test]
    fn project_path_attribute_omitted_when_missing() {
        let exp = OtlpExporter::new("http://x".into(), vec![], "ua".into());
        let p = exp.build_payload(&sample_event());
        let attrs = p["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"]
            .as_array()
            .unwrap()
            .clone();
        assert!(
            !attrs.iter().any(|a| a["key"] == "package.project_path"),
            "absent project_path must not be serialised"
        );
    }
}
