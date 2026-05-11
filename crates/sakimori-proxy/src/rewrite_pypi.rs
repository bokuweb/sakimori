//! PyPI metadata rewriters — the pypi.org counterpart to
//! [`crate::rewrite`] (crates.io) and [`crate::rewrite_npm`] (npm).
//!
//! PyPI serves two metadata shapes we care about:
//!
//! 1. **Warehouse JSON API**: `GET /pypi/<pkg>/json` — returns
//!    `releases: { "X.Y.Z": [<file>, …], … }`. Each file carries
//!    `upload_time_iso_8601`. We drop entire version keys whose
//!    earliest file upload time is too young.
//!
//! 2. **Simple index (PEP 691 JSON)**: `GET /simple/<pkg>/` with
//!    `Accept: application/vnd.pypi.simple.v1+json` — returns
//!    `files: [{ "filename", "upload-time", "hashes", … }, …]` plus
//!    a top-level `versions: [...]` listing. We filter `files[]`
//!    per-file on `upload-time`.
//!
//! 3. **Simple index (PEP 503 HTML)**: `GET /simple/<pkg>/` with
//!    `Accept: text/html` — bare `<a href="…file…">filename</a>`
//!    rows, no publish time in the response. We drop anchors whose
//!    filename-derived version is too young per an out-of-band
//!    oracle populated from the JSON API (see
//!    [`crate::pypi_simple_client::PypiSimpleClient`]). Unknown
//!    versions are left alone — the `files.pythonhosted.org`
//!    tarball-deny path catches young pins downstream.
//!
//! Pure + synchronous; unit tests cover every branch.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PypiRewriteStats {
    pub kept: usize,
    pub dropped: usize,
}

/// Rewrite a Warehouse JSON API body (`/pypi/<pkg>/json`). Drops
/// version keys from `releases` whose earliest `upload_time_iso_8601`
/// is younger than `min_age`.
pub fn rewrite_pypi_json_api(
    body: &[u8],
    min_age: Duration,
    now: DateTime<Utc>,
) -> (Vec<u8>, PypiRewriteStats) {
    let mut stats = PypiRewriteStats::default();
    let mut doc: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            log::debug!("pypi-rewrite(json): pass-through, parse failed: {e}");
            return (body.to_vec(), stats);
        }
    };
    let Some(obj) = doc.as_object_mut() else {
        return (body.to_vec(), stats);
    };
    let cutoff = chrono::Duration::from_std(min_age).unwrap_or_default();

    if let Some(releases) = obj.get_mut("releases").and_then(Value::as_object_mut) {
        // Collect too-young version keys first to avoid borrow conflicts.
        let too_young: Vec<String> = releases
            .iter()
            .filter_map(|(vers, files)| {
                let files = files.as_array()?;
                let earliest = earliest_upload_time_json_api(files)?;
                if (now - earliest) < cutoff {
                    Some(vers.clone())
                } else {
                    None
                }
            })
            .collect();
        stats.dropped = too_young.len();
        for v in &too_young {
            releases.remove(v);
        }
        stats.kept = releases.len();
    }

    // Also blank `urls` (the "latest release's files" shortcut) if any
    // of its files were published too recently. pip/uv sometimes look
    // at `urls` directly when no version is specified.
    if let Some(urls) = obj.get_mut("urls").and_then(Value::as_array_mut) {
        urls.retain(|f| {
            f.get("upload_time_iso_8601")
                .and_then(Value::as_str)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| (now - dt.with_timezone(&Utc)) >= cutoff)
                .unwrap_or(true) // keep entries we can't parse
        });
    }

    let out = serde_json::to_vec(&doc).unwrap_or_else(|_| body.to_vec());
    (out, stats)
}

/// Extract `{version → earliest upload_time}` from a Warehouse JSON
/// API body (`/pypi/<pkg>/json`). Used by the HTML rewriter's
/// out-of-band oracle. Returns an empty map if the body can't be
/// parsed or has no `releases` object.
pub fn extract_publish_times_from_pypi_json(
    body: &[u8],
) -> std::collections::HashMap<String, DateTime<Utc>> {
    let mut out = std::collections::HashMap::new();
    let Ok(doc): Result<Value, _> = serde_json::from_slice(body) else {
        return out;
    };
    let Some(releases) = doc.get("releases").and_then(Value::as_object) else {
        return out;
    };
    for (vers, files) in releases {
        let Some(files) = files.as_array() else {
            continue;
        };
        if let Some(t) = earliest_upload_time_json_api(files) {
            out.insert(vers.clone(), t);
        }
    }
    out
}

fn earliest_upload_time_json_api(files: &[Value]) -> Option<DateTime<Utc>> {
    files
        .iter()
        .filter_map(|f| {
            f.get("upload_time_iso_8601")
                .and_then(Value::as_str)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
        })
        .min()
}

/// Rewrite a PEP 691 Simple index JSON body (`/simple/<pkg>/` with
/// `Accept: application/vnd.pypi.simple.v1+json`). Drops `files[]`
/// entries whose `upload-time` is younger than `min_age`, then
/// prunes the top-level `versions[]` so it only lists versions that
/// still have at least one file.
pub fn rewrite_pypi_simple_json(
    body: &[u8],
    min_age: Duration,
    now: DateTime<Utc>,
) -> (Vec<u8>, PypiRewriteStats) {
    let mut stats = PypiRewriteStats::default();
    let mut doc: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            log::debug!("pypi-rewrite(simple-json): pass-through, parse failed: {e}");
            return (body.to_vec(), stats);
        }
    };
    let Some(obj) = doc.as_object_mut() else {
        return (body.to_vec(), stats);
    };
    let cutoff = chrono::Duration::from_std(min_age).unwrap_or_default();

    if let Some(files) = obj.get_mut("files").and_then(Value::as_array_mut) {
        let before = files.len();
        files.retain(|f| {
            match f
                .get("upload-time")
                .and_then(Value::as_str)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
            {
                Some(t) => (now - t) >= cutoff,
                None => true, // keep entries with no / unparseable time
            }
        });
        stats.kept = files.len();
        stats.dropped = before - files.len();
    }

    // Rebuild surviving version set from remaining filenames so the
    // top-level `versions` list doesn't advertise versions with zero
    // files. Filename format per PEP 427 / sdist conventions: first
    // `-` separated segment that starts with a digit is the version.
    if stats.dropped > 0 {
        let surviving: std::collections::HashSet<String> = obj
            .get("files")
            .and_then(Value::as_array)
            .map(|files| {
                files
                    .iter()
                    .filter_map(|f| f.get("filename").and_then(Value::as_str))
                    .filter_map(extract_version_from_filename)
                    .collect()
            })
            .unwrap_or_default();
        if let Some(versions) = obj.get_mut("versions").and_then(Value::as_array_mut) {
            versions.retain(|v| v.as_str().map(|s| surviving.contains(s)).unwrap_or(true));
        }
    }

    let out = serde_json::to_vec(&doc).unwrap_or_else(|_| body.to_vec());
    (out, stats)
}

/// Rewrite a PEP 503 Simple HTML index (`/simple/<pkg>/` with
/// `Accept: text/html`). For each `<a href="…">filename</a>` entry,
/// consult `oracle(version)` for the publish time and drop the
/// entire anchor (plus one optional trailing `<br>`/`<br/>` and
/// newline) when it is younger than `min_age`. All other HTML —
/// doctype, head, wrapping body, PEP 691 data-* attributes — is
/// left byte-for-byte identical so pip's tolerant parser sees the
/// exact same document minus the filtered rows.
///
/// `oracle` is expected to be populated out-of-band (see
/// [`crate::pypi_simple_client::PypiSimpleClient`]) by hitting
/// `/pypi/<pkg>/json` once per package. Entries whose version the
/// oracle doesn't know are left alone — the files.pythonhosted.org
/// tarball-deny path catches young pins downstream.
pub fn rewrite_pypi_simple_html<F>(
    body: &[u8],
    min_age: Duration,
    now: DateTime<Utc>,
    oracle: F,
) -> (Vec<u8>, PypiRewriteStats)
where
    F: Fn(&str) -> Option<DateTime<Utc>>,
{
    let mut stats = PypiRewriteStats::default();
    let Ok(s) = std::str::from_utf8(body) else {
        log::debug!("pypi-rewrite(html): pass-through, body not UTF-8");
        return (body.to_vec(), stats);
    };
    let cutoff = chrono::Duration::from_std(min_age).unwrap_or_default();
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // Look for the start of the next anchor element. Case-
        // insensitive match on `<a` followed by whitespace or `>`.
        if let Some(anchor_start) = find_anchor_start(&bytes[i..]) {
            let abs = i + anchor_start;
            out.extend_from_slice(&bytes[i..abs]);
            // Find the closing `</a>` (also case-insensitive).
            let remainder = &bytes[abs..];
            let Some(close_rel) = find_case_insensitive(remainder, b"</a>") else {
                // Malformed — emit the rest and stop scanning for anchors.
                out.extend_from_slice(remainder);
                break;
            };
            let anchor_end = abs + close_rel + b"</a>".len();
            let anchor = std::str::from_utf8(&bytes[abs..anchor_end]).unwrap_or("");

            // Extract href + filename + version. Unknown / malformed
            // entries default to keep.
            let drop = anchor_drop_decision(anchor, &oracle, now, cutoff);
            if drop {
                stats.dropped += 1;
                // Eat one optional trailing `<br>` or `<br/>` plus
                // up to one newline so we don't leave stray markup.
                let mut next = anchor_end;
                next = eat_optional_br(bytes, next);
                next = eat_optional_newline(bytes, next);
                i = next;
            } else {
                stats.kept += 1;
                out.extend_from_slice(&bytes[abs..anchor_end]);
                i = anchor_end;
            }
        } else {
            out.extend_from_slice(&bytes[i..]);
            i = bytes.len();
        }
    }
    (out, stats)
}

fn anchor_drop_decision<F>(
    anchor: &str,
    oracle: &F,
    now: DateTime<Utc>,
    cutoff: chrono::Duration,
) -> bool
where
    F: Fn(&str) -> Option<DateTime<Utc>>,
{
    let Some(href) = extract_href_value(anchor) else {
        return false;
    };
    let filename = url_basename_no_fragment(&href);
    let Some(version) = extract_version_from_filename(filename) else {
        return false;
    };
    let Some(t) = oracle(&version) else {
        return false;
    };
    (now - t) < cutoff
}

/// Find the first `<a` that starts an anchor tag (followed by
/// whitespace or `>`). Returns byte offset or None.
fn find_anchor_start(hay: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 2 <= hay.len() {
        if hay[i] == b'<'
            && (hay[i + 1] == b'a' || hay[i + 1] == b'A')
            && i + 2 < hay.len()
            && (hay[i + 2].is_ascii_whitespace() || hay[i + 2] == b'>')
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_case_insensitive(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    'outer: for i in 0..=hay.len() - needle.len() {
        for (k, nb) in needle.iter().enumerate() {
            if !hay[i + k].eq_ignore_ascii_case(nb) {
                continue 'outer;
            }
        }
        return Some(i);
    }
    None
}

fn eat_optional_br(bytes: &[u8], start: usize) -> usize {
    let rest = &bytes[start..];
    // Skip a run of ASCII spaces/tabs between `</a>` and `<br>`.
    let mut k = 0;
    while k < rest.len() && (rest[k] == b' ' || rest[k] == b'\t') {
        k += 1;
    }
    // Match `<br`, any attributes up to `>`, optional `/` before `>`.
    if rest.len() >= k + 3
        && rest[k] == b'<'
        && (rest[k + 1] == b'b' || rest[k + 1] == b'B')
        && (rest[k + 2] == b'r' || rest[k + 2] == b'R')
        && let Some(gt) = rest[k + 3..].iter().position(|&b| b == b'>')
    {
        return start + k + 3 + gt + 1;
    }
    start
}

fn eat_optional_newline(bytes: &[u8], start: usize) -> usize {
    if start < bytes.len() && bytes[start] == b'\r' {
        if start + 1 < bytes.len() && bytes[start + 1] == b'\n' {
            return start + 2;
        }
        return start + 1;
    }
    if start < bytes.len() && bytes[start] == b'\n' {
        return start + 1;
    }
    start
}

/// Pull the `href` attribute value out of an anchor element string.
/// Supports both double- and single-quoted values. Returns the raw
/// attribute value without any HTML-entity decoding (PEP 503 URLs
/// don't contain entity-encoded characters in practice).
fn extract_href_value(anchor: &str) -> Option<String> {
    let bytes = anchor.as_bytes();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        // Match `href` case-insensitively at a word boundary.
        let at_boundary = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if at_boundary
            && bytes[i..].len() >= 4
            && bytes[i].eq_ignore_ascii_case(&b'h')
            && bytes[i + 1].eq_ignore_ascii_case(&b'r')
            && bytes[i + 2].eq_ignore_ascii_case(&b'e')
            && bytes[i + 3].eq_ignore_ascii_case(&b'f')
        {
            let mut j = i + 4;
            // Skip whitespace then `=`.
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j >= bytes.len() || bytes[j] != b'=' {
                i += 1;
                continue;
            }
            j += 1;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let quote = bytes.get(j).copied()?;
            if quote != b'"' && quote != b'\'' {
                return None;
            }
            j += 1;
            let start = j;
            while j < bytes.len() && bytes[j] != quote {
                j += 1;
            }
            if j >= bytes.len() {
                return None;
            }
            return Some(std::str::from_utf8(&bytes[start..j]).ok()?.to_string());
        }
        i += 1;
    }
    None
}

/// Extract the filename portion of a PyPI file URL: path basename,
/// stripped of any `#sha256=…` fragment and `?query`.
fn url_basename_no_fragment(url: &str) -> &str {
    let before_fragment = url.split('#').next().unwrap_or(url);
    let before_query = before_fragment.split('?').next().unwrap_or(before_fragment);
    before_query.rsplit('/').next().unwrap_or(before_query)
}

/// Cheap-and-cheerful "pull the version out of a PyPI filename":
/// strip the recognised archive extension, split on `-`, return the
/// first segment starting with a digit. Mirrors the logic already in
/// [`crate::parser::PypiParser::parse`].
fn extract_version_from_filename(filename: &str) -> Option<String> {
    let stem = filename
        .strip_suffix(".whl")
        .or_else(|| filename.strip_suffix(".tar.gz"))
        .or_else(|| filename.strip_suffix(".zip"))
        .or_else(|| filename.strip_suffix(".egg"))?;
    let parts: Vec<&str> = stem.split('-').collect();
    parts
        .iter()
        .skip(1)
        .find(|p| p.starts_with(|c: char| c.is_ascii_digit()))
        .map(|p| (*p).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    fn min_age_hours(h: u64) -> Duration {
        Duration::from_secs(h * 3600)
    }

    fn parse(body: &[u8]) -> Value {
        serde_json::from_slice(body).unwrap()
    }

    // ---------- JSON API ----------

    fn json_api(releases: &[(&str, &[&str])]) -> String {
        let mut rels = serde_json::Map::new();
        for (vers, times) in releases {
            let files: Vec<Value> = times
                .iter()
                .map(|t| {
                    let mut m = serde_json::Map::new();
                    m.insert(
                        "filename".into(),
                        Value::String(format!("pkg-{vers}.tar.gz")),
                    );
                    m.insert("upload_time_iso_8601".into(), Value::String((*t).into()));
                    Value::Object(m)
                })
                .collect();
            rels.insert((*vers).into(), Value::Array(files));
        }
        let mut doc = serde_json::Map::new();
        doc.insert("info".into(), Value::Object(serde_json::Map::new()));
        doc.insert("releases".into(), Value::Object(rels));
        doc.insert("urls".into(), Value::Array(vec![]));
        serde_json::to_string(&doc).unwrap()
    }

    #[test]
    fn json_api_drops_too_young_version_keys() {
        let now = utc(2025, 1, 10);
        let body = json_api(&[
            ("1.0.0", &["2024-12-01T00:00:00Z"]),
            ("1.1.0", &["2025-01-09T23:00:00Z"]), // too young
        ]);
        let (out, stats) = rewrite_pypi_json_api(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        let releases = doc["releases"].as_object().unwrap();
        assert!(releases.contains_key("1.0.0"));
        assert!(!releases.contains_key("1.1.0"));
        assert_eq!(stats.kept, 1);
        assert_eq!(stats.dropped, 1);
    }

    #[test]
    fn json_api_keeps_version_if_any_file_is_old_enough() {
        // A version with one old file + one young file is judged by
        // the earliest (= oldest) upload_time. A real PyPI release
        // uploads all files close together, so this case is rare,
        // but it's the honest behaviour.
        let now = utc(2025, 1, 10);
        let body = json_api(&[("1.0.0", &["2024-06-01T00:00:00Z", "2025-01-09T23:00:00Z"])]);
        let (out, stats) = rewrite_pypi_json_api(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        assert!(doc["releases"].as_object().unwrap().contains_key("1.0.0"));
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn json_api_prunes_urls_shortcut() {
        // urls[] lists the latest release's files; if those are young
        // we strip them so tools that consult urls don't get a young
        // pin.
        let now = utc(2025, 1, 10);
        let body = r#"{
            "info": {},
            "releases": {},
            "urls": [
                {"upload_time_iso_8601": "2024-01-01T00:00:00Z", "filename": "old.tar.gz"},
                {"upload_time_iso_8601": "2025-01-09T23:00:00Z", "filename": "new.tar.gz"}
            ]
        }"#;
        let (out, _) = rewrite_pypi_json_api(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        let urls = doc["urls"].as_array().unwrap();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0]["filename"], "old.tar.gz");
    }

    #[test]
    fn json_api_malformed_body_passes_through() {
        let (out, stats) = rewrite_pypi_json_api(b"not json", min_age_hours(168), utc(2025, 1, 10));
        assert_eq!(out, b"not json");
        assert_eq!(stats.dropped, 0);
    }

    // ---------- Simple JSON ----------

    fn simple_json(files: &[(&str, &str)], versions: &[&str]) -> String {
        let files_v: Vec<Value> = files
            .iter()
            .map(|(filename, t)| {
                let mut m = serde_json::Map::new();
                m.insert("filename".into(), Value::String((*filename).into()));
                m.insert("upload-time".into(), Value::String((*t).into()));
                Value::Object(m)
            })
            .collect();
        let mut doc = serde_json::Map::new();
        doc.insert("name".into(), Value::String("pkg".into()));
        doc.insert("files".into(), Value::Array(files_v));
        doc.insert(
            "versions".into(),
            Value::Array(
                versions
                    .iter()
                    .map(|v| Value::String((*v).into()))
                    .collect(),
            ),
        );
        serde_json::to_string(&doc).unwrap()
    }

    #[test]
    fn simple_json_drops_young_files_and_prunes_versions() {
        let now = utc(2025, 1, 10);
        let body = simple_json(
            &[
                ("pkg-1.0.0.tar.gz", "2024-06-01T00:00:00Z"),
                ("pkg-2.0.0.tar.gz", "2025-01-09T00:00:00Z"), // young
                ("pkg-2.0.0-py3-none-any.whl", "2025-01-09T00:00:01Z"), // young
            ],
            &["1.0.0", "2.0.0"],
        );
        let (out, stats) = rewrite_pypi_simple_json(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        let files = doc["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["filename"], "pkg-1.0.0.tar.gz");
        let versions: Vec<&str> = doc["versions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(versions, vec!["1.0.0"]);
        assert_eq!(stats.dropped, 2);
        assert_eq!(stats.kept, 1);
    }

    #[test]
    fn simple_json_keeps_files_with_no_upload_time() {
        // Some older index entries have no upload-time. We keep them
        // — the tarball deny path catches them downstream if needed.
        let now = utc(2025, 1, 10);
        let body =
            r#"{"name":"pkg","files":[{"filename":"pkg-0.0.1.tar.gz"}],"versions":["0.0.1"]}"#;
        let (out, stats) = rewrite_pypi_simple_json(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        assert_eq!(doc["files"].as_array().unwrap().len(), 1);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn simple_json_malformed_body_passes_through() {
        let (out, _) = rewrite_pypi_simple_json(
            b"<!doctype html>\n<body>not json</body>",
            min_age_hours(168),
            utc(2025, 1, 10),
        );
        assert_eq!(out, b"<!doctype html>\n<body>not json</body>");
    }

    // ---------- filename → version ----------

    #[test]
    fn filename_version_extraction_covers_common_shapes() {
        assert_eq!(
            extract_version_from_filename("requests-2.32.4.tar.gz").as_deref(),
            Some("2.32.4")
        );
        assert_eq!(
            extract_version_from_filename("requests-2.32.4-py3-none-any.whl").as_deref(),
            Some("2.32.4")
        );
        assert_eq!(
            extract_version_from_filename("my-cool-pkg-1.0.0.tar.gz").as_deref(),
            Some("1.0.0"),
            "hyphen-separated package name"
        );
        assert_eq!(extract_version_from_filename("weird.txt"), None);
        assert_eq!(extract_version_from_filename(""), None);
    }

    // ---------- Simple HTML (PEP 503) ----------

    fn simple_html(rows: &[&str]) -> String {
        let mut s = String::from(
            "<!DOCTYPE html>\n<html><head><title>Links for pkg</title></head><body>\n",
        );
        for r in rows {
            s.push_str(r);
            s.push('\n');
        }
        s.push_str("</body></html>\n");
        s
    }

    fn oracle_from(
        pairs: &[(&str, DateTime<Utc>)],
    ) -> impl Fn(&str) -> Option<DateTime<Utc>> + use<> {
        let map: std::collections::HashMap<String, DateTime<Utc>> =
            pairs.iter().map(|(v, t)| ((*v).into(), *t)).collect();
        move |v| map.get(v).copied()
    }

    #[test]
    fn simple_html_drops_young_anchors_keeps_old() {
        let now = utc(2025, 1, 10);
        let oracle = oracle_from(&[
            ("1.0.0", utc(2024, 1, 1)),
            ("2.0.0", utc(2025, 1, 9)), // young
        ]);
        let body = simple_html(&[
            r#"<a href="https://files.pythonhosted.org/packages/aa/pkg-1.0.0.tar.gz#sha256=abc">pkg-1.0.0.tar.gz</a><br/>"#,
            r#"<a href="https://files.pythonhosted.org/packages/bb/pkg-2.0.0.tar.gz#sha256=def">pkg-2.0.0.tar.gz</a><br/>"#,
        ]);
        let (out, stats) =
            rewrite_pypi_simple_html(body.as_bytes(), min_age_hours(168), now, oracle);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("pkg-1.0.0.tar.gz"));
        assert!(!s.contains("pkg-2.0.0.tar.gz"));
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.kept, 1);
        // Surrounding markup intact.
        assert!(s.contains("<!DOCTYPE html>"));
        assert!(s.contains("</body></html>"));
    }

    #[test]
    fn simple_html_keeps_anchors_with_unknown_version() {
        // Oracle returns None → we can't judge, leave it. The
        // tarball-deny path catches these downstream.
        let now = utc(2025, 1, 10);
        let oracle = oracle_from(&[]);
        let body = simple_html(&[
            r#"<a href="https://files.pythonhosted.org/packages/aa/pkg-2.0.0.tar.gz">pkg-2.0.0.tar.gz</a><br/>"#,
        ]);
        let (out, stats) =
            rewrite_pypi_simple_html(body.as_bytes(), min_age_hours(168), now, oracle);
        assert!(String::from_utf8(out).unwrap().contains("pkg-2.0.0.tar.gz"));
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.kept, 1);
    }

    #[test]
    fn simple_html_keeps_anchors_without_parseable_filename() {
        // href points to something that isn't an sdist/wheel — we
        // can't extract a version, so keep it.
        let now = utc(2025, 1, 10);
        let oracle = oracle_from(&[("1.0.0", utc(2025, 1, 9))]);
        let body = simple_html(&[r#"<a href="https://example.com/weird.txt">weird.txt</a>"#]);
        let (out, stats) =
            rewrite_pypi_simple_html(body.as_bytes(), min_age_hours(168), now, oracle);
        assert!(String::from_utf8(out).unwrap().contains("weird.txt"));
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn simple_html_handles_single_quoted_and_mixed_case_attrs() {
        let now = utc(2025, 1, 10);
        let oracle = oracle_from(&[("2.0.0", utc(2025, 1, 9))]);
        let body = "<!DOCTYPE html>\n<HTML><BODY>\n<A HREF='https://files.pythonhosted.org/packages/xx/pkg-2.0.0.tar.gz'>pkg-2.0.0.tar.gz</A>\n</BODY></HTML>\n";
        let (out, stats) =
            rewrite_pypi_simple_html(body.as_bytes(), min_age_hours(168), now, oracle);
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("pkg-2.0.0.tar.gz"));
        assert!(s.contains("</BODY></HTML>"));
        assert_eq!(stats.dropped, 1);
    }

    #[test]
    fn simple_html_preserves_pep691_data_attrs_on_kept_anchors() {
        // PEP 691 adds data-* attributes (data-dist-info-metadata,
        // data-requires-python, data-yanked). They must survive on
        // anchors we keep.
        let now = utc(2025, 1, 10);
        let oracle = oracle_from(&[("1.0.0", utc(2024, 1, 1))]);
        let body = simple_html(&[
            r#"<a href="https://files.pythonhosted.org/packages/aa/pkg-1.0.0.tar.gz" data-requires-python="&gt;=3.8" data-yanked="">pkg-1.0.0.tar.gz</a>"#,
        ]);
        let (out, _) = rewrite_pypi_simple_html(body.as_bytes(), min_age_hours(168), now, oracle);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("data-requires-python"));
        assert!(s.contains("data-yanked"));
    }

    #[test]
    fn simple_html_empty_body_passes_through() {
        let (out, stats) =
            rewrite_pypi_simple_html(b"", min_age_hours(168), utc(2025, 1, 10), oracle_from(&[]));
        assert_eq!(out, b"");
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.kept, 0);
    }

    #[test]
    fn simple_html_malformed_anchor_does_not_lose_trailing_content() {
        // `<a ...` without `</a>` — we stop anchor scanning but keep
        // the rest of the body verbatim.
        let body = "<body>\n<a href=\"x.tar.gz\">oops (never closed)\n</body>";
        let (out, stats) = rewrite_pypi_simple_html(
            body.as_bytes(),
            min_age_hours(168),
            utc(2025, 1, 10),
            oracle_from(&[]),
        );
        assert_eq!(String::from_utf8(out).unwrap(), body);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn simple_html_non_utf8_body_passes_through() {
        let body = b"\xff\xfe\xfa garbage";
        let (out, stats) =
            rewrite_pypi_simple_html(body, min_age_hours(168), utc(2025, 1, 10), oracle_from(&[]));
        assert_eq!(out, body);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn url_basename_strips_fragment_and_query() {
        assert_eq!(
            url_basename_no_fragment(
                "https://files.pythonhosted.org/packages/aa/pkg-1.0.0.tar.gz#sha256=abc"
            ),
            "pkg-1.0.0.tar.gz"
        );
        assert_eq!(
            url_basename_no_fragment("https://x/y/pkg-2.0.0.tar.gz?foo=bar"),
            "pkg-2.0.0.tar.gz"
        );
        assert_eq!(
            url_basename_no_fragment("pkg-1.0.0.tar.gz"),
            "pkg-1.0.0.tar.gz"
        );
    }

    #[test]
    fn extract_href_handles_both_quote_styles_and_whitespace() {
        assert_eq!(
            extract_href_value(r#"<a href="x">y</a>"#).as_deref(),
            Some("x")
        );
        assert_eq!(
            extract_href_value(r#"<a href = 'z'>y</a>"#).as_deref(),
            Some("z")
        );
        assert_eq!(
            extract_href_value(r#"<a HREF="ALLCAPS">y</a>"#).as_deref(),
            Some("ALLCAPS")
        );
        // No href at all.
        assert_eq!(extract_href_value(r#"<a class="foo">y</a>"#), None);
    }
}
