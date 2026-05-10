#!/usr/bin/env python3
"""
Build `typosquat-data/top.json` — the sakimori typosquat
reference list. Fetches the current top-N package names from each
ecosystem's public "most downloaded" surface and emits a compact
JSON the proxy consumes at runtime.

Runs weekly (see `.github/workflows/typosquat-data.yml`). Weekly
rather than OSV-mirror's 10min because download rankings shift
glacially — `react` / `lodash` / `requests` have been at the top
for years, and today's rank 1,000 was yesterday's rank 1,001.

### Why auto-rebuild at all?
v0.28 ships with a frozen, hand-curated top-100 per ecosystem.
Real-world typosquats target the **next tier down** (rank 100–
1,000) too — packages that have enough users to be worth
imitating but don't make the hand-curated shortlist. Extending
to top-1,000 at mirror-time bumps recall from ~40-50% to ~60-70%
(rough, eyeballed estimate) with negligible precision cost,
because 1-edit collisions between legitimate packages stay rare
even at 4,000-row comparisons.

### Sources
- **PyPI**: `hugovk/top-pypi-packages` — well-maintained, daily
  rebuild from BigQuery download stats.
- **crates.io**: `crates.io/api/v1/crates?sort=downloads` —
  official, paged.
- **npm**: `anvaka/npmrank` — community but longest-running.
  No official npm API for top-N downloads.
- **NuGet**: `api-v2v3search-0.nuget.org/query?take=N` — official
  search API, sorted by total installs by default.

### Output
`typosquat-data/top.json`:

    {
      "schema":     1,
      "updated_at": "2026-01-01T00:00:00Z",
      "entries": {
        "npm":    ["react", "lodash", "axios", ...],
        "crates": ["serde", "tokio", ...],
        "pypi":   ["requests", "numpy", ...],
        "nuget":  ["Newtonsoft.Json", ...]
      }
    }

Ecosystem keys match `sakimori_core::deps::Ecosystem::label`.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

# Top count per ecosystem. Empirically 1000 feels right — captures
# the tail of widely-installed libs without bloating the wire
# download past ~80 kB. Too few: recall tanks. Too many:
# edit-distance scan cost grows; at 10k names the inner loop is
# measurable on tight hot paths.
TARGET_COUNT = 1000

UA = "sakimori-typosquat-mirror/0.1 (https://github.com/bokuweb/sakimori)"


def http_get(url: str, accept: str = "application/json") -> bytes:
    """Plain GET with a sakimori user-agent and a 60s timeout.
    Raises the same exceptions urllib does — caller logs + fails."""
    print(f"  GET {url}", file=sys.stderr)
    req = urllib.request.Request(url, headers={"user-agent": UA, "accept": accept})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


# ---------- per-ecosystem fetchers ---------------------------------

def fetch_pypi() -> list[str]:
    """hugovk/top-pypi-packages — daily-rebuilt JSON, stable URL."""
    url = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
    doc = json.loads(http_get(url))
    rows = doc.get("rows") or doc.get("last_update") and doc.get("rows") or []
    # Some versions of the file nest differently; the canonical
    # shape is {"rows": [{"project": "requests", "download_count": ...}, ...]}
    if not rows and isinstance(doc, list):
        rows = doc
    names: list[str] = []
    for row in rows[:TARGET_COUNT]:
        name = row.get("project") if isinstance(row, dict) else None
        if name:
            names.append(name)
    return names


def fetch_crates() -> list[str]:
    """crates.io official API, paged at 100 per page."""
    names: list[str] = []
    page = 1
    while len(names) < TARGET_COUNT:
        per_page = min(100, TARGET_COUNT - len(names))
        url = (
            f"https://crates.io/api/v1/crates?"
            f"sort=downloads&per_page={per_page}&page={page}"
        )
        doc = json.loads(http_get(url))
        batch = [c.get("name") for c in doc.get("crates", [])]
        batch = [n for n in batch if isinstance(n, str)]
        if not batch:
            break
        names.extend(batch)
        page += 1
        # crates.io rate-limits at ~1 req/s for unauthenticated
        # traffic. A polite 1-sec gap keeps us well under.
        time.sleep(1.0)
    return names[:TARGET_COUNT]


def fetch_npm() -> list[str]:
    """npm has no first-party top-N-downloads API — the public
    `-/v1/search` requires a non-empty `text=` query and ranks by
    relevance-to-query, not pure popularity. Community aggregates
    (anvaka/npmrank etc.) come and go, so we ship a curated
    baseline file at `scripts/npm-top-baseline.json` instead.

    Producer reads the baseline and returns it verbatim. Manual
    bumps happen via PR when notable new packages rise (e.g. the
    next `vite`-class framework). This is less lively than a
    true weekly rebuild but avoids hitching the whole pipeline to
    a third-party that may disappear.

    When a reliable npm top-N source appears upstream, swap this
    function for the real fetch — producer contract unchanged."""
    baseline_path = pathlib.Path(__file__).parent / "npm-top-baseline.json"
    if not baseline_path.exists():
        print(
            f"::warning::npm baseline {baseline_path} missing; emitting empty list",
            file=sys.stderr,
        )
        return []
    doc = json.loads(baseline_path.read_text(encoding="utf-8"))
    if isinstance(doc, list):
        return [n for n in doc if isinstance(n, str)][:TARGET_COUNT]
    names = doc.get("entries") or doc.get("names") or []
    return [n for n in names if isinstance(n, str)][:TARGET_COUNT]


def fetch_nuget() -> list[str]:
    """NuGet's search API — default sort is by total downloads."""
    names: list[str] = []
    skip = 0
    # NuGet search API caps `take` at 1000 per request. One call is
    # usually enough; guard with a loop in case they tighten it.
    while len(names) < TARGET_COUNT:
        take = min(1000, TARGET_COUNT - len(names))
        url = (
            f"https://azuresearch-usnc.nuget.org/query?"
            f"take={take}&skip={skip}&prerelease=false&semVerLevel=2.0.0"
        )
        doc = json.loads(http_get(url))
        batch = [c.get("id") for c in doc.get("data", [])]
        batch = [n for n in batch if isinstance(n, str)]
        if not batch:
            break
        names.extend(batch)
        skip += take
    return names[:TARGET_COUNT]


# ---------- driver -------------------------------------------------

def main() -> int:
    entries: dict[str, list[str]] = {}
    for label, fetch in [
        ("npm", fetch_npm),
        ("crates", fetch_crates),
        ("pypi", fetch_pypi),
        ("nuget", fetch_nuget),
    ]:
        print(f"fetching {label}", file=sys.stderr)
        try:
            names = fetch()
        except Exception as e:  # noqa: BLE001
            # On failure, preserve an empty list — consumer falls
            # back to the hard-coded top-100 for that ecosystem.
            print(f"::warning::{label} fetch failed: {e}", file=sys.stderr)
            names = []
        # Deduplicate while preserving order, then sort lexically
        # for stable diffs in the data branch.
        seen: set[str] = set()
        dedup: list[str] = []
        for n in names:
            low = n.lower()
            if low in seen:
                continue
            seen.add(low)
            dedup.append(n)
        dedup.sort(key=str.lower)
        entries[label] = dedup
        print(
            f"  -> {label}: {len(dedup)} unique names",
            file=sys.stderr,
        )

    # Fail hard if we got nothing for ANY ecosystem — a deploy-time
    # misconfiguration (DNS, proxy, CDN 500) would otherwise
    # silently overwrite a good mirror with an empty one.
    if all(not v for v in entries.values()):
        print(
            "::error::every ecosystem fetch failed; refusing to publish empty mirror",
            file=sys.stderr,
        )
        return 2

    doc = {
        "schema": 1,
        "updated_at": dt.datetime.now(dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "source": {
            "npm": "https://anvaka.github.io/npmrank/online/npmrank.json",
            "crates": "https://crates.io/api/v1/crates?sort=downloads",
            "pypi": "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json",
            "nuget": "https://azuresearch-usnc.nuget.org/query?prerelease=false",
        },
        "entries": entries,
    }

    output = pathlib.Path("typosquat-data/top.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    output.write_text(text, encoding="utf-8")
    print(
        f"wrote {output} ({sum(len(v) for v in entries.values())} names, "
        f"{output.stat().st_size // 1024} KiB)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
