//! npm registry client.
//!
//! Endpoint: `GET https://registry.npmjs.org/<name>` returns a JSON doc
//! where `time.{version}` is the ISO-8601 publish timestamp for that
//! version. Scoped packages need URL-encoded slashes (`/` → `%2F`).

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct PackageDoc {
    #[serde(default)]
    time: std::collections::BTreeMap<String, String>,
}

pub fn published(name: &str, version: &str, user_agent: &str) -> Result<Option<DateTime<Utc>>> {
    let encoded = if let Some(rest) = name.strip_prefix('@') {
        format!("@{}", rest.replacen('/', "%2F", 1))
    } else {
        name.to_string()
    };
    let url = format!("https://registry.npmjs.org/{encoded}");

    let resp = super::agent()
        .get(&url)
        .set("User-Agent", user_agent)
        .set("Accept", "application/json")
        .call();

    let resp = match resp {
        Ok(r) => r,
        Err(ureq::Error::Status(404, _)) => {
            log::debug!("npm: {name} 404 — treating as missing");
            return Ok(None);
        }
        Err(e) => return Err(e).with_context(|| format!("GET {url}")),
    };

    let doc: PackageDoc = resp
        .into_json()
        .with_context(|| format!("parsing npm metadata for {name}"))?;
    let ts = match doc.time.get(version) {
        Some(s) => s,
        None => return Ok(None),
    };
    let dt = DateTime::parse_from_rfc3339(ts)
        .with_context(|| format!("parsing timestamp {ts} for {name}@{version}"))?;
    Ok(Some(dt.with_timezone(&Utc)))
}
