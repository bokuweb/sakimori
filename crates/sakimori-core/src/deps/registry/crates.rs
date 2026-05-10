//! crates.io client.
//!
//! Endpoint: `GET https://crates.io/api/v1/crates/<name>` returns a JSON
//! doc with `versions: [{ num, created_at }, ...]`. We need a good
//! User-Agent per their policy (`<name> (<contact>)`).

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CrateDoc {
    versions: Vec<VersionEntry>,
}

#[derive(Debug, Deserialize)]
struct VersionEntry {
    num: String,
    created_at: String,
}

pub fn published(name: &str, version: &str, user_agent: &str) -> Result<Option<DateTime<Utc>>> {
    let url = format!("https://crates.io/api/v1/crates/{name}");
    let resp = super::agent()
        .get(&url)
        .set("User-Agent", user_agent)
        .set("Accept", "application/json")
        .call();
    let resp = match resp {
        Ok(r) => r,
        Err(ureq::Error::Status(404, _)) => {
            log::debug!("crates.io: {name} 404 — treating as missing");
            return Ok(None);
        }
        Err(e) => return Err(e).with_context(|| format!("GET {url}")),
    };

    let doc: CrateDoc = resp
        .into_json()
        .with_context(|| format!("parsing crates.io metadata for {name}"))?;
    let Some(entry) = doc.versions.into_iter().find(|v| v.num == version) else {
        return Ok(None);
    };
    let dt = DateTime::parse_from_rfc3339(&entry.created_at)
        .with_context(|| format!("parsing timestamp {}", entry.created_at))?;
    Ok(Some(dt.with_timezone(&Utc)))
}
