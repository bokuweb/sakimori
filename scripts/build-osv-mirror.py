#!/usr/bin/env python3
"""
Build `osv-mirror/mal.json` — the sakimori known-malicious mirror.

Runs as a scheduled GitHub Action (see .github/workflows/osv-mirror.yml).
Downloads OSV.dev's per-ecosystem bulk zip from
`https://storage.googleapis.com/osv-vulnerabilities/` (public, no auth),
filters to malicious-package advisories, and writes a compact JSON
file the sakimori proxy consumes at runtime.

Why pre-filter?  OSV ships thousands of ordinary CVEs / GHSAs per
ecosystem; our proxy only wants the malicious ones (MAL-* IDs +
"Malicious Package in …" GHSAs). Doing the filter once on the
producer side keeps the distributed file under ~1 MB and the
consumer loop O(n) over a handful of entries instead of tens of
thousands.

Output schema — compact flat-array form, optimised for on-the-wire
size: the npm half of OSV's malicious feed alone is >200k entries,
so we amortise every byte per row.

    {
      "schema":     2,
      "updated_at": "2025-01-01T00:00:00Z",
      "source":     "https://storage.googleapis.com/osv-vulnerabilities/",
      "entries": [
        ["npm",  "flatmap-stream",    "0.1.1", "MAL-2025-20690"],
        ["npm",  "flatmap-stream",    "0.1.1", "GHSA-9x64-5r7x-2q53"],
        ["pypi", "colorsama",         "*",     "MAL-2024-123"]
      ]
    }

Each entry is `[eco, name, version, id]`:
- `eco`  uses the sakimori ecosystem labels
  (`crates | npm | pypi | nuget` — matches
  `sakimori_core::deps::Ecosystem::label`).
- `version` is a single affected version, or `"*"` for
  "every version" when the advisory didn't list specifics. The
  consumer's lookup uses `(eco, name, version)` exact match or falls
  back to `(eco, name, "*")`.
- `id` is the OSV advisory ID. One entry per (version, id) pair; a
  single version flagged by both GHSA and MAL-* shows up twice.

Large-feed reality: at time of writing the npm bulk has ~213k
malicious entries (OSV now ingests OpenSSF Package Analysis
auto-detections — mostly typosquat / brandjacking). The compact
form plus gzip-on-the-wire keeps this under ~3 MB for the consumer
to pull.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import pathlib
import re
import sys
import urllib.request
import zipfile

ECOSYSTEMS = {
    # OSV bucket folder → sakimori ecosystem label
    "npm": "npm",
    "PyPI": "pypi",
    "crates.io": "crates",
    "NuGet": "nuget",
}
BUCKET = "https://storage.googleapis.com/osv-vulnerabilities"


def is_malicious(advisory: dict) -> bool:
    """Same rule as sakimori_proxy::osv::is_malicious in Rust — keep
    them aligned. An advisory counts as a malicious-package flag if
    any of:
      1. ID starts with `MAL-`, OR
      2. summary/details contain the substring "malicious"
         (case-insensitive).
    Ordinary CVEs / DoS-style advisories don't trip it; blocking
    every package with an unfixed CVE would be unusable."""
    if advisory.get("id", "").startswith("MAL-"):
        return True
    haystack = (advisory.get("summary", "") + "\n" + advisory.get("details", "")).lower()
    return "malicious" in haystack


def extract_versions(advisory: dict, eco_folder: str) -> list[str]:
    """Pull the set of exact affected versions from an OSV advisory.

    OSV's `affected[].versions` is the denormalised list we want.
    `affected[].ranges` exists too but resolves to the same universe
    for published ecosystems. We union across every `affected` entry
    that matches this ecosystem — a handful of advisories list
    cross-ecosystem duplicates and we only want the one scoped to
    `eco_folder`."""
    out: set[str] = set()
    for aff in advisory.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != eco_folder:
            continue
        for v in aff.get("versions", []) or []:
            if isinstance(v, str):
                out.add(v)
    return sorted(out)


def extract_name(advisory: dict, eco_folder: str) -> str | None:
    for aff in advisory.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") == eco_folder:
            name = pkg.get("name")
            if isinstance(name, str):
                return name
    return None


def download_zip(eco_folder: str) -> zipfile.ZipFile:
    # Spaces and "+" aren't in any of the ecosystem folders we use,
    # but url-encoding the "/" is load-bearing for literal folder
    # names like "crates.io" that contain a dot (urllib is fine with
    # that too; we just keep it simple).
    url = f"{BUCKET}/{eco_folder}/all.zip"
    print(f"fetching {url}", file=sys.stderr)
    req = urllib.request.Request(url, headers={"user-agent": "sakimori-osv-mirror/0.1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    return zipfile.ZipFile(io.BytesIO(data))


def collect(eco_folder: str, eco_label: str) -> list[list[str]]:
    """Stream every malicious advisory in this ecosystem into the
    flat `[eco, name, version, id]` schema."""
    zf = download_zip(eco_folder)
    out: list[list[str]] = []
    total_advisories = 0
    malicious_advisories = 0
    for info in zf.infolist():
        if not info.filename.endswith(".json"):
            continue
        total_advisories += 1
        with zf.open(info) as fh:
            try:
                adv = json.load(fh)
            except json.JSONDecodeError:
                continue
        if not is_malicious(adv):
            continue
        malicious_advisories += 1
        name = extract_name(adv, eco_folder)
        if not name:
            continue
        aid = adv.get("id", "")
        versions = extract_versions(adv, eco_folder)
        if not versions:
            # Advisory has no explicit version enumeration — flag
            # every version of the package. Consumer matches on
            # `"*"` after an exact miss.
            out.append([eco_label, name, "*", aid])
            continue
        for v in versions:
            out.append([eco_label, name, v, aid])

    # Deterministic order so `git diff` between two snapshots is
    # reviewable. Inner comparators are stable across Python runs.
    out.sort(key=lambda r: (r[0], r[1].lower(), r[2], r[3]))
    print(
        f"  {eco_folder}: {malicious_advisories}/{total_advisories} malicious, "
        f"{len(out)} flat entries",
        file=sys.stderr,
    )
    return out


def main() -> int:
    output_path = pathlib.Path("osv-mirror/mal.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    entries: list[list[str]] = []
    for eco_folder, eco_label in ECOSYSTEMS.items():
        entries.extend(collect(eco_folder, eco_label))

    doc = {
        "schema": 2,
        "updated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": BUCKET,
        "ecosystems": list(ECOSYSTEMS.values()),
        "entries": entries,
    }

    # Compact one-entry-per-line representation: still stable,
    # diff-friendly, but ~3x smaller than `indent=2` on a 200k-row
    # array. We keep the outer meta fields on their own lines.
    head = {k: v for k, v in doc.items() if k != "entries"}
    head_str = json.dumps(head, indent=2, ensure_ascii=False, sort_keys=True)
    # Strip the final `}` so we can append the entries block.
    head_body = head_str.rstrip().rstrip("}").rstrip().rstrip(",")
    lines = [head_body + ",", '  "entries": [']
    for i, row in enumerate(entries):
        sep = "," if i < len(entries) - 1 else ""
        lines.append("    " + json.dumps(row, ensure_ascii=False) + sep)
    lines.append("  ]")
    lines.append("}")
    text = "\n".join(lines) + "\n"
    output_path.write_text(text, encoding="utf-8")
    size_kb = output_path.stat().st_size / 1024
    print(
        f"wrote {output_path} ({len(entries)} entries, {size_kb:.1f} KiB)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
