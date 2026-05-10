//! NuGet registration index client.
//!
//! Endpoint family: `https://api.nuget.org/v3/registration5-semver1/<name-lower>/<version>.json`.
//! The response's `catalogEntry` is either inline (has `.published`) or a
//! URL pointing at the catalog entry — both shapes are valid NuGet
//! responses, so handle both.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Leaf {
    #[serde(rename = "catalogEntry")]
    catalog_entry: CatalogEntryRef,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CatalogEntryRef {
    Inline(CatalogEntry),
    Url(String),
}

#[derive(Debug, Deserialize)]
struct CatalogEntry {
    #[serde(default)]
    published: Option<String>,
}

pub fn published(name: &str, version: &str, user_agent: &str) -> Result<Option<DateTime<Utc>>> {
    let lower = name.to_ascii_lowercase();
    let version = version.trim_start_matches('v');

    let urls = [
        format!("https://api.nuget.org/v3/registration5-semver1/{lower}/{version}.json"),
        format!("https://api.nuget.org/v3/registration5-gz-semver2/{lower}/{version}.json"),
    ];

    let agent = super::agent();
    for url in &urls {
        let resp = agent
            .get(url)
            .set("User-Agent", user_agent)
            .set("Accept", "application/json")
            .call();
        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(404, _)) => continue,
            Err(e) => return Err(e).with_context(|| format!("GET {url}")),
        };

        let leaf: Leaf = resp
            .into_json()
            .with_context(|| format!("parsing nuget leaf for {name}@{version}"))?;

        let entry = match leaf.catalog_entry {
            CatalogEntryRef::Inline(e) => e,
            CatalogEntryRef::Url(catalog_url) => {
                // Follow the indirection once.
                let r = agent
                    .get(&catalog_url)
                    .set("User-Agent", user_agent)
                    .set("Accept", "application/json")
                    .call()
                    .with_context(|| format!("GET {catalog_url}"))?;
                r.into_json::<CatalogEntry>()
                    .with_context(|| format!("parsing nuget catalog entry {catalog_url}"))?
            }
        };

        let Some(ts) = entry.published else {
            return Ok(None);
        };
        let dt = DateTime::parse_from_rfc3339(&ts)
            .with_context(|| format!("parsing nuget timestamp {ts}"))?;
        return Ok(Some(dt.with_timezone(&Utc)));
    }
    Ok(None)
}
