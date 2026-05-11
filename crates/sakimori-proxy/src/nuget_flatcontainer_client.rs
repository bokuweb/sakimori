//! Out-of-band lookup that gives the flat-container rewriter the
//! publish times it needs.
//!
//! The flat-container endpoint (`/v3-flatcontainer/<id>/index.json`)
//! is a plain `{"versions":[…]}` with no dates. The registration
//! endpoint (`/v3/registration5-semver1/<id>/index.json`) has the
//! dates. This module fetches the latter, walks the index (following
//! separate-URL page references when necessary), and hands back a
//! `version → published` map.
//!
//! Cache policy: per-package-id, populated lazily, kept in-memory
//! for the lifetime of the proxy. NuGet's registration data only
//! gains new versions over time, so a stale cache entry can cause
//! us to miss *new* young versions (false-negative — we'd let
//! through a too-young version we should have filtered). To bound
//! that window we expire cache entries after `CACHE_TTL`. Pinned
//! `.nupkg` fetches still hard-deny at the tarball layer when our
//! cache is stale, so the worst case is "user sees a too-young
//! version in the index but install still fails when cargo/dotnet
//! tries to fetch the nupkg".

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::rewrite_nuget::extract_publish_times_from_registration;

/// Max lifetime of a cached registration lookup. 10 minutes is long
/// enough that a typical CI run doesn't re-fetch for every package
/// but short enough that newly-published versions become visible in
/// the silent-fallback filter within the same day.
const CACHE_TTL: Duration = Duration::from_secs(10 * 60);

/// Bound the number of page-reference fetches we'll chase per lookup.
/// Real packages have 1–3 pages; a pathological registry document
/// pointing at thousands of pages should not stall the proxy.
const MAX_PAGES_PER_LOOKUP: usize = 16;

/// One URL base per registration family. We only need semver1
/// (non-gz) for MVP — nuget serves the same data across families and
/// dotnet / nuget.exe pull from this base by default.
const REGISTRATION_BASE: &str = "https://api.nuget.org/v3/registration5-semver1";

#[derive(Debug, Clone)]
struct CacheEntry {
    data: Arc<HashMap<String, DateTime<Utc>>>,
    fetched: Instant,
}

/// Thread-safe lookup client. Clone-cheap: internally Arc-wrapped.
#[derive(Clone)]
pub struct NugetFlatContainerClient {
    inner: Arc<Inner>,
}

type FetchFn = dyn Fn(&str) -> Result<Vec<u8>, String> + Send + Sync;

struct Inner {
    cache: Mutex<HashMap<String, CacheEntry>>,
    user_agent: String,
    /// Fetch hook — `None` means real network (ureq). Injected in tests
    /// so we can stub responses without mocking the HTTP stack.
    fetcher: Box<FetchFn>,
}

impl NugetFlatContainerClient {
    /// Real-network constructor. Uses `ureq` on a `spawn_blocking`
    /// worker when called from async context (see [`Self::lookup`]).
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

    /// Test constructor — pass any closure that maps URL → response
    /// body bytes (or error message). Bypasses the network entirely.
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

    /// Return the cached publish-times map for `package_id`, fetching
    /// from the registration endpoint when the cache is empty or
    /// stale. On network failure returns an empty map (callers treat
    /// it as "no data → fail-open" inside the flat-container filter).
    pub async fn lookup(&self, package_id: &str) -> Arc<HashMap<String, DateTime<Utc>>> {
        if let Some(cached) = self.get_fresh(package_id) {
            return cached;
        }

        // Refresh. Done on a blocking pool because the underlying
        // fetch is sync (ureq). For the test fetcher this is still
        // correct — spawn_blocking runs the closure on a worker.
        let client = self.clone();
        let id = package_id.to_ascii_lowercase();
        let map = tokio::task::spawn_blocking(move || client.refresh_now(&id))
            .await
            .unwrap_or_default();
        let arc = Arc::new(map);
        self.put(package_id, Arc::clone(&arc));
        arc
    }

    /// Blocking sibling of [`Self::lookup`]. Tests call this directly.
    pub fn lookup_blocking(&self, package_id: &str) -> Arc<HashMap<String, DateTime<Utc>>> {
        if let Some(cached) = self.get_fresh(package_id) {
            return cached;
        }
        let id = package_id.to_ascii_lowercase();
        let arc = Arc::new(self.refresh_now(&id));
        self.put(package_id, Arc::clone(&arc));
        arc
    }

    fn get_fresh(&self, id: &str) -> Option<Arc<HashMap<String, DateTime<Utc>>>> {
        let key = id.to_ascii_lowercase();
        let cache = self.inner.cache.lock().ok()?;
        let entry = cache.get(&key)?;
        if entry.fetched.elapsed() < CACHE_TTL {
            Some(Arc::clone(&entry.data))
        } else {
            None
        }
    }

    fn put(&self, id: &str, data: Arc<HashMap<String, DateTime<Utc>>>) {
        let key = id.to_ascii_lowercase();
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

    fn refresh_now(&self, package_id_lower: &str) -> HashMap<String, DateTime<Utc>> {
        let index_url = format!("{REGISTRATION_BASE}/{package_id_lower}/index.json");
        let body = match (self.inner.fetcher)(&index_url) {
            Ok(b) => b,
            Err(e) => {
                log::debug!("nuget-flat: registration fetch failed for {package_id_lower}: {e}");
                return HashMap::new();
            }
        };
        let mut map = extract_publish_times_from_registration(&body);

        // Follow page references that didn't carry inline items. Bounded.
        let pages = collect_page_urls(&body);
        for url in pages.into_iter().take(MAX_PAGES_PER_LOOKUP) {
            match (self.inner.fetcher)(&url) {
                Ok(page_body) => {
                    for (k, v) in extract_publish_times_from_registration(&page_body) {
                        map.entry(k).or_insert(v);
                    }
                }
                Err(e) => {
                    log::debug!("nuget-flat: page fetch failed for {url}: {e}");
                }
            }
        }
        map
    }

    /// Exposed for logs / tests.
    pub fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }
}

fn collect_page_urls(body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(doc): Result<Value, _> = serde_json::from_slice(body) else {
        return out;
    };
    let Some(items) = doc.get("items").and_then(Value::as_array) else {
        return out;
    };
    for it in items {
        // A page-reference-only entry has `@id` but no inline `items`.
        let has_inline_items = it.get("items").is_some();
        if has_inline_items {
            continue;
        }
        if let Some(url) = it.get("@id").and_then(Value::as_str) {
            out.push(url.to_string());
        }
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

use std::io::Read as _;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn leaf(version: &str, published: &str) -> Value {
        json!({
            "@id": format!("https://api.nuget.org/v3/registration5-semver1/pkg/{version}.json"),
            "catalogEntry": {
                "id": "Pkg",
                "version": version,
                "published": published
            }
        })
    }

    fn paged_index(leaves: &[(&str, &str)]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "count": 1,
            "items": [{
                "count": leaves.len(),
                "items": leaves.iter().map(|(v,t)| leaf(v,t)).collect::<Vec<_>>()
            }]
        }))
        .unwrap()
    }

    #[test]
    fn lookup_hits_registration_endpoint_and_returns_publish_times() {
        let client = NugetFlatContainerClient::with_fetcher(|url| {
            assert!(url.contains("/registration5-semver1/newtonsoft.json/index.json"));
            Ok(paged_index(&[
                ("1.0.0", "2024-01-01T00:00:00Z"),
                ("1.1.0", "2024-06-01T00:00:00Z"),
            ]))
        });
        let map = client.lookup_blocking("Newtonsoft.Json");
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("1.0.0"));
        assert!(map.contains_key("1.1.0"));
    }

    #[test]
    fn lookup_caches_subsequent_calls() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = Arc::clone(&hits);
        let client = NugetFlatContainerClient::with_fetcher(move |_url| {
            hits_c.fetch_add(1, Ordering::SeqCst);
            Ok(paged_index(&[("1.0.0", "2024-01-01T00:00:00Z")]))
        });
        let _ = client.lookup_blocking("pkg");
        let _ = client.lookup_blocking("pkg");
        let _ = client.lookup_blocking("PKG"); // case-insensitive hit
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn lookup_network_failure_returns_empty_map_and_caches_it() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = Arc::clone(&hits);
        let client = NugetFlatContainerClient::with_fetcher(move |_url| {
            hits_c.fetch_add(1, Ordering::SeqCst);
            Err("connection refused".into())
        });
        let map = client.lookup_blocking("pkg");
        assert!(map.is_empty());
        // Still cached so we don't hammer a dead registry.
        let _ = client.lookup_blocking("pkg");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn lookup_follows_page_references_and_merges() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = Arc::clone(&hits);
        let client = NugetFlatContainerClient::with_fetcher(move |url| {
            hits_c.fetch_add(1, Ordering::SeqCst);
            if url.ends_with("/index.json") {
                // Index references two pages without inline items.
                Ok(serde_json::to_vec(&json!({
                    "items": [
                        { "@id": "https://api.nuget.org/page1.json", "lower": "1.0.0", "upper": "1.9.9" },
                        { "@id": "https://api.nuget.org/page2.json", "lower": "2.0.0", "upper": "2.9.9" }
                    ]
                }))
                .unwrap())
            } else if url.contains("page1") {
                Ok(paged_index(&[("1.0.0", "2024-01-01T00:00:00Z")]))
            } else if url.contains("page2") {
                Ok(paged_index(&[("2.0.0", "2024-06-01T00:00:00Z")]))
            } else {
                Err(format!("unexpected url {url}"))
            }
        });
        let map = client.lookup_blocking("pkg");
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("1.0.0"));
        assert!(map.contains_key("2.0.0"));
        assert_eq!(hits.load(Ordering::SeqCst), 3); // index + 2 pages
    }

    #[test]
    fn lookup_bounds_page_fetches() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = Arc::clone(&hits);
        // Build an index claiming 1000 separate pages; we should only
        // fetch MAX_PAGES_PER_LOOKUP of them.
        let client = NugetFlatContainerClient::with_fetcher(move |url| {
            hits_c.fetch_add(1, Ordering::SeqCst);
            if url.ends_with("/index.json") {
                let items: Vec<Value> = (0..1000)
                    .map(|i| json!({ "@id": format!("https://api.nuget.org/p{i}.json") }))
                    .collect();
                Ok(serde_json::to_vec(&json!({ "items": items })).unwrap())
            } else {
                Ok(paged_index(&[]))
            }
        });
        let _ = client.lookup_blocking("pkg");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1 + MAX_PAGES_PER_LOOKUP,
            "should stop at MAX_PAGES_PER_LOOKUP"
        );
    }

    #[tokio::test]
    async fn async_lookup_uses_blocking_executor() {
        let client = NugetFlatContainerClient::with_fetcher(|_| {
            Ok(paged_index(&[("1.0.0", "2024-01-01T00:00:00Z")]))
        });
        let map = client.lookup("pkg").await;
        assert_eq!(map.len(), 1);
    }
}
