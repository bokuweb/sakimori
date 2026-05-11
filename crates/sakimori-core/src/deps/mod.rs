//! Supply-chain "minimum release age" check.
//!
//! Reads one or more lockfiles, queries the relevant registry for each
//! resolved `(name, version)` tuple, and fails if any package was
//! published less than `--min-age` ago. The idea (borrowed from pnpm's
//! `minimumReleaseAge`): give the community a fixed window to detect
//! malicious / typosquat releases before our CI pulls them.
//!
//! Supported ecosystems (v0.8):
//! - `package-lock.json` (npm)
//! - `Cargo.lock` (crates.io)
//!
//! Everything here is synchronous I/O (`ureq`) on a single thread.
//! Typical lockfiles with ≲500 unique packages resolve in a few seconds
//! with the on-disk cache warmed; rate-limit politeness matters more
//! than raw throughput.

pub mod cache;
pub mod cli;
pub mod lockfile;
pub mod registry;
pub mod watch;

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;

use cache::Cache;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Npm,
    Crates,
    Pypi,
    Nuget,
}

impl Ecosystem {
    pub fn label(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Crates => "crates",
            Ecosystem::Pypi => "pypi",
            Ecosystem::Nuget => "nuget",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Package {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct PackageReport {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
    pub published: Option<DateTime<Utc>>,
    pub age_hours: Option<i64>,
    pub too_new: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub min_age_hours: i64,
    pub checked: usize,
    pub violations: usize,
    pub errors: usize,
    pub packages: Vec<PackageReport>,
}

pub struct CheckArgs<'a> {
    pub lockfiles: &'a [std::path::PathBuf],
    pub min_age: Duration,
    pub ignore: &'a [String],
    pub fail_on_missing: bool,
    pub cache: Option<&'a Path>,
    pub user_agent: &'a str,
}

pub fn check(args: CheckArgs<'_>) -> Result<CheckReport> {
    // 1. Parse lockfiles → flat package list (deduped).
    let mut packages: Vec<Package> = Vec::new();
    for lf in args.lockfiles {
        let eco = lockfile::detect(lf)
            .with_context(|| format!("detecting lockfile type for {}", lf.display()))?;
        let parsed =
            lockfile::parse(eco, lf).with_context(|| format!("parsing {}", lf.display()))?;
        packages.extend(parsed);
    }
    packages.sort_by(|a, b| {
        (a.ecosystem as u8, &a.name, &a.version).cmp(&(b.ecosystem as u8, &b.name, &b.version))
    });
    packages
        .dedup_by(|a, b| a.ecosystem == b.ecosystem && a.name == b.name && a.version == b.version);

    // 2. Optional cache (on-disk, infinite TTL since publish dates don't change).
    let mut cache = match args.cache {
        Some(p) => Some(Cache::open(p)?),
        None => None,
    };

    // 3. Query each (name, version) → publish date. Apply ignore list.
    let now = Utc::now();
    let mut report = CheckReport {
        min_age_hours: args.min_age.as_secs() as i64 / 3600,
        checked: 0,
        violations: 0,
        errors: 0,
        packages: Vec::with_capacity(packages.len()),
    };

    for pkg in &packages {
        if args.ignore.iter().any(|pat| ignore_matches(pat, &pkg.name)) {
            continue;
        }
        report.checked += 1;
        let eco_label = pkg.ecosystem.label();

        let fetched = fetch_published(
            &pkg.ecosystem,
            &pkg.name,
            &pkg.version,
            cache.as_mut(),
            args.user_agent,
        );
        let entry = match fetched {
            Ok(Some(published)) => {
                let age = now - published;
                let age_hours = age.num_hours();
                let too_new = age < chrono::Duration::from_std(args.min_age).unwrap_or_default();
                if too_new {
                    report.violations += 1;
                }
                PackageReport {
                    ecosystem: eco_label,
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    published: Some(published),
                    age_hours: Some(age_hours),
                    too_new,
                    error: None,
                }
            }
            Ok(None) => {
                report.errors += 1;
                if args.fail_on_missing {
                    report.violations += 1;
                }
                PackageReport {
                    ecosystem: eco_label,
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    published: None,
                    age_hours: None,
                    too_new: args.fail_on_missing,
                    error: Some("publish date not found".into()),
                }
            }
            Err(e) => {
                report.errors += 1;
                if args.fail_on_missing {
                    report.violations += 1;
                }
                PackageReport {
                    ecosystem: eco_label,
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    published: None,
                    age_hours: None,
                    too_new: args.fail_on_missing,
                    error: Some(format!("{e:#}")),
                }
            }
        };
        report.packages.push(entry);
    }

    if let Some(c) = cache {
        c.save()?;
    }
    Ok(report)
}

fn fetch_published(
    eco: &Ecosystem,
    name: &str,
    version: &str,
    cache: Option<&mut Cache>,
    user_agent: &str,
) -> Result<Option<DateTime<Utc>>> {
    // cache hit → skip network
    if let Some(c) = cache.as_deref()
        && let Some(dt) = c.get(eco, name, version)
    {
        return Ok(Some(dt));
    }
    let result = match eco {
        Ecosystem::Npm => registry::npm::published(name, version, user_agent)?,
        Ecosystem::Crates => registry::crates::published(name, version, user_agent)?,
        Ecosystem::Pypi => registry::pypi::published(name, version, user_agent)?,
        Ecosystem::Nuget => registry::nuget::published(name, version, user_agent)?,
    };
    if let (Some(dt), Some(c)) = (result, cache) {
        c.put(eco, name, version, dt);
    }
    Ok(result)
}

fn ignore_matches(pattern: &str, name: &str) -> bool {
    // Support plain names, `*foo` / `foo*` wildcards, and scopes like `@types/*`.
    if pattern == name {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*')
        && name.starts_with(prefix)
    {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*')
        && name.ends_with(suffix)
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignore_matches_plain_and_wildcards() {
        assert!(ignore_matches("serde", "serde"));
        assert!(!ignore_matches("serde", "serde_json"));
        assert!(ignore_matches("serde*", "serde_json"));
        assert!(ignore_matches("@types/*", "@types/node"));
        assert!(ignore_matches("*-internal", "my-internal"));
        assert!(!ignore_matches("foo", "bar"));
    }
}
