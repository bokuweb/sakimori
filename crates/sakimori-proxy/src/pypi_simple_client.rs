//! Out-of-band lookup that gives the PEP 503 HTML rewriter the
//! publish times it needs.
//!
//! The Simple HTML index (`/simple/<pkg>/` with `Accept: text/html`)
//! lists each file as a bare `<a>` tag and carries no publish time.
//! The Warehouse JSON API (`/pypi/<pkg>/json`) carries the full
//! release history with per-file `upload_time_iso_8601`. This module
//! fetches the latter on first touch, extracts a `version →
//! earliest-upload` map, and caches it for [`CACHE_TTL`].
//!
//! Cache semantics match [`crate::nuget_flatcontainer_client`]: on a
//! stale or missing lookup we return an empty map, which the HTML
//! rewriter treats as fail-open (no version filtering). For pinned
//! too-young tarballs the `files.pythonhosted.org` hard-deny path
//! still catches the install.

use std::collections::HashMap;
use std::io::Read as _;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::rewrite_pypi::extract_publish_times_from_pypi_json;

/// Max lifetime of a cached JSON-API lookup. Matches the NuGet
/// flat-container client so both silent-fallback paths have the
/// same "how quickly does a new release become visible" profile.
const CACHE_TTL: Duration = Duration::from_secs(10 * 60);

const JSON_API_BASE: &str = "https://pypi.org/pypi";

#[derive(Debug, Clone)]
struct CacheEntry {
    data: Arc<HashMap<String, DateTime<Utc>>>,
    fetched: Instant,
}

type FetchFn = dyn Fn(&str) -> Result<Vec<u8>, String> + Send + Sync;

/// Thread-safe lookup client. Clone-cheap: internally Arc-wrapped.
#[derive(Clone)]
pub struct PypiSimpleClient {
    inner: Arc<Inner>,
}

struct Inner {
    cache: Mutex<HashMap<String, CacheEntry>>,
    user_agent: String,
    fetcher: Box<FetchFn>,
}

impl PypiSimpleClient {
    pub fn new(user_agent: impl Into<String>) -> Self {
        let ua = user_agent.into();
        let ua_for_fetch = ua.clone();
        Self {
            inner: Arc::new(Inner {
                cache: Mutex::new(HashMap::new()),
                user_agent: ua,
                fetcher: Box::new(move |url| fetch_blocking(url, &ua_for_fetch)),
            }),
        }
    }

    #[cfg(test)]
    pub fn with_fetcher<F>(fetcher: F) -> Self
    where
        F: Fn(&str) -> Result<Vec<u8>, String> + Send + Sync + 'static,
    {
        Self {
            inner: Arc::new(Inner {
                cache: Mutex::new(HashMap::new()),
                user_agent: "test".into(),
                fetcher: Box::new(fetcher),
            }),
        }
    }

    /// Return the cached publish-times map for `package`, fetching
    /// from the JSON API when cache is empty or stale. On any
    /// failure returns an empty map.
    pub async fn lookup(&self, package: &str) -> Arc<HashMap<String, DateTime<Utc>>> {
        if let Some(cached) = self.get_fresh(package) {
            return cached;
        }
        let client = self.clone();
        let id = normalize_name(package);
        let map = tokio::task::spawn_blocking(move || client.refresh_now(&id))
            .await
            .unwrap_or_default();
        let arc = Arc::new(map);
        self.put(package, Arc::clone(&arc));
        arc
    }

    /// Blocking sibling of [`Self::lookup`]. Tests call this directly.
    pub fn lookup_blocking(&self, package: &str) -> Arc<HashMap<String, DateTime<Utc>>> {
        if let Some(cached) = self.get_fresh(package) {
            return cached;
        }
        let id = normalize_name(package);
        let arc = Arc::new(self.refresh_now(&id));
        self.put(package, Arc::clone(&arc));
        arc
    }

    fn get_fresh(&self, package: &str) -> Option<Arc<HashMap<String, DateTime<Utc>>>> {
        let key = normalize_name(package);
        let cache = self.inner.cache.lock().ok()?;
        let entry = cache.get(&key)?;
        if entry.fetched.elapsed() < CACHE_TTL {
            Some(Arc::clone(&entry.data))
        } else {
            None
        }
    }

    fn put(&self, package: &str, data: Arc<HashMap<String, DateTime<Utc>>>) {
        let key = normalize_name(package);
        if let Ok(mut cache) = self.inner.cache.lock() {
            cache.insert(
                key,
                CacheEntry {
                    data,
                    fetched: Instant::now(),
                },
            );
        }
    }

    fn refresh_now(&self, package_normalized: &str) -> HashMap<String, DateTime<Utc>> {
        let url = format!("{JSON_API_BASE}/{package_normalized}/json");
        match (self.inner.fetcher)(&url) {
            Ok(body) => extract_publish_times_from_pypi_json(&body),
            Err(e) => {
                log::debug!("pypi-simple: JSON API fetch failed for {package_normalized}: {e}");
                HashMap::new()
            }
        }
    }

    pub fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }
}

/// PEP 503 normalized project name: lowercase, runs of
/// `-`/`_`/`.` collapsed to a single `-`. Used for cache keying and
/// for the JSON API URL path. Both PyPI and pip apply the same rule.
fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !prev_sep && !out.is_empty() {
                out.push('-');
                prev_sep = true;
            }
        } else {
            out.push(c.to_ascii_lowercase());
            prev_sep = false;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn fetch_blocking(url: &str, ua: &str) -> Result<Vec<u8>, String> {
    let resp = ureq::get(url)
        .set("user-agent", ua)
        .set("accept", "application/json")
        .timeout(Duration::from_millis(3000))
        .call()
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn releases_body(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut rels = serde_json::Map::new();
        for (v, t) in pairs {
            rels.insert(
                (*v).into(),
                json!([{ "filename": format!("pkg-{v}.tar.gz"), "upload_time_iso_8601": t }]),
            );
        }
        serde_json::to_vec(&json!({ "info": {}, "releases": rels })).unwrap()
    }

    #[test]
    fn lookup_hits_json_api_and_returns_publish_times() {
        let client = PypiSimpleClient::with_fetcher(|url| {
            assert!(url.contains("/pypi/requests/json"), "url was {url}");
            Ok(releases_body(&[
                ("2.0.0", "2024-01-01T00:00:00Z"),
                ("2.1.0", "2024-06-01T00:00:00Z"),
            ]))
        });
        let map = client.lookup_blocking("requests");
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("2.0.0"));
        assert!(map.contains_key("2.1.0"));
    }

    #[test]
    fn lookup_caches_subsequent_calls() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = Arc::clone(&hits);
        let client = PypiSimpleClient::with_fetcher(move |_| {
            hits_c.fetch_add(1, Ordering::SeqCst);
            Ok(releases_body(&[("1.0.0", "2024-01-01T00:00:00Z")]))
        });
        let _ = client.lookup_blocking("pkg");
        let _ = client.lookup_blocking("pkg");
        let _ = client.lookup_blocking("PKG"); // normalized-same → cache hit
        let _ = client.lookup_blocking("p.k.g"); // normalized to "p-k-g" → different
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn lookup_network_failure_returns_empty_map_and_caches_it() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = Arc::clone(&hits);
        let client = PypiSimpleClient::with_fetcher(move |_| {
            hits_c.fetch_add(1, Ordering::SeqCst);
            Err("connection refused".into())
        });
        let map = client.lookup_blocking("pkg");
        assert!(map.is_empty());
        let _ = client.lookup_blocking("pkg");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn lookup_uses_normalized_name_in_url_path() {
        let client = PypiSimpleClient::with_fetcher(|url| {
            // PEP 503: `Flask-SQLAlchemy` → `flask-sqlalchemy`
            assert!(url.contains("/pypi/flask-sqlalchemy/json"), "url was {url}");
            Ok(releases_body(&[("1.0.0", "2024-01-01T00:00:00Z")]))
        });
        let _ = client.lookup_blocking("Flask_SQLAlchemy");
    }

    #[tokio::test]
    async fn async_lookup_uses_blocking_executor() {
        let client = PypiSimpleClient::with_fetcher(|_| {
            Ok(releases_body(&[("1.0.0", "2024-01-01T00:00:00Z")]))
        });
        let map = client.lookup("pkg").await;
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn normalize_collapses_separator_runs() {
        assert_eq!(normalize_name("Flask"), "flask");
        assert_eq!(normalize_name("Flask_SQLAlchemy"), "flask-sqlalchemy");
        assert_eq!(normalize_name("foo...bar"), "foo-bar");
        assert_eq!(normalize_name("foo-_.bar"), "foo-bar");
        assert_eq!(normalize_name("zope.interface"), "zope-interface");
    }
}
