//! PyPI registry client.
//!
//! Endpoint: `GET https://pypi.org/pypi/<name>/<version>/json`.
//!
//! The response's `urls` array has one entry per uploaded artifact
//! (sdist + wheels); all share essentially the same
//! `upload_time_iso_8601`. We take the earliest as the publish time.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VersionDoc {
    #[serde(default)]
    urls: Vec<UploadedFile>,
}

#[derive(Debug, Deserialize)]
struct UploadedFile {
    #[serde(default)]
    upload_time_iso_8601: Option<String>,
    #[serde(default)]
    upload_time: Option<String>,
}

pub fn published(name: &str, version: &str, user_agent: &str) -> Result<Option<DateTime<Utc>>> {
    // PyPI normalises package names (PEP 503) to lowercase + `-`/`_`/`.` → `-`.
    let normalised = normalise(name);
    let url = format!("https://pypi.org/pypi/{normalised}/{version}/json");
    let resp = super::agent()
        .get(&url)
        .set("User-Agent", user_agent)
        .set("Accept", "application/json")
        .call();
    let resp = match resp {
        Ok(r) => r,
        Err(ureq::Error::Status(404, _)) => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("GET {url}")),
    };

    let doc: VersionDoc = resp
        .into_json()
        .with_context(|| format!("parsing pypi metadata for {name}@{version}"))?;

    let mut earliest: Option<DateTime<Utc>> = None;
    for u in &doc.urls {
        let ts = u
            .upload_time_iso_8601
            .as_deref()
            .or(u.upload_time.as_deref());
        let Some(ts) = ts else {
            continue;
        };
        if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
            let dt = dt.with_timezone(&Utc);
            if earliest.is_none_or(|e| dt < e) {
                earliest = Some(dt);
            }
        }
    }
    Ok(earliest)
}

fn normalise(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = false;
    for c in name.chars() {
        let c = c.to_ascii_lowercase();
        let replaced = if c == '_' || c == '.' { '-' } else { c };
        if replaced == '-' {
            if last_dash {
                continue;
            }
            last_dash = true;
        } else {
            last_dash = false;
        }
        out.push(replaced);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::normalise;

    #[test]
    fn pep503_normalisation() {
        assert_eq!(normalise("Requests"), "requests");
        assert_eq!(normalise("python_dateutil"), "python-dateutil");
        assert_eq!(normalise("typing.extensions"), "typing-extensions");
        assert_eq!(normalise("Django__auto"), "django-auto");
    }
}
