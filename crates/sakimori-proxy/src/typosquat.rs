//! Detect likely typosquats — packages whose names are suspiciously
//! close to widely-installed legitimate ones (`colurs` vs `colors`,
//! `reqeusts` vs `requests`, `webpack-loader-x` vs `webpack-loader`).
//!
//! The actual mechanics: a small hard-coded list of "top" packages
//! per ecosystem + Levenshtein edit distance. When an incoming
//! package name is 1–2 edits away from a top name *but not an exact
//! match*, we flag it.
//!
//! Why a hard-coded list?
//!
//! - It's small: 4 × ~100 names = ~400 entries, well under 10 kB of
//!   embedded data. Rebuilding weekly from download rankings is a
//!   roadmap item, but the actually-typosquatted names (lodash,
//!   requests, tokio, Newtonsoft.Json, …) don't churn week-to-week.
//! - It's offline. No runtime fetch, no DNS, no bulk download.
//! - It's auditable in a PR — bumps to the list are reviewed like
//!   any other code change.
//!
//! Policy:
//!
//! - Distance = 0 ⇒ exact match ⇒ legitimate top package ⇒ allow.
//! - Distance in 1..=threshold ⇒ suspicious typosquat ⇒ return the
//!   candidate to the caller, who decides to warn, deny, or ignore.
//! - Distance > threshold ⇒ no signal.
//!
//! The default threshold (1) catches typical single-character
//! typosquats without flooding the user on commonly-prefixed
//! packages (`@types/*` on npm would otherwise collide with every
//! other `@types/…` name). Callers can raise it if they want more
//! aggressive detection.

use sakimori_core::deps::Ecosystem;

/// Max edit distance, inclusive, to call something a typosquat. A
/// value of 0 disables detection (nothing can be 0-close without
/// being identical). We use 1 by default — anything further tends
/// to produce false positives on genuinely distinct packages.
pub const DEFAULT_THRESHOLD: usize = 1;

/// One match. `suggested` is the legitimate top-N name that the
/// input is uncomfortably close to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub input: String,
    pub suggested: &'static str,
    pub distance: usize,
}

/// Detector wrapping the per-ecosystem top-N lists. Lifetimes are
/// `'static` because the lists live in the binary.
#[derive(Debug, Clone, Copy)]
pub struct Detector {
    pub threshold: usize,
}

impl Detector {
    pub fn new() -> Self {
        Self {
            threshold: DEFAULT_THRESHOLD,
        }
    }

    pub fn with_threshold(threshold: usize) -> Self {
        Self { threshold }
    }

    /// Check `name` against the top-N list for `eco`. Returns the
    /// closest legitimate name if it's within the detector's
    /// threshold *and* not the same string (an exact match means
    /// the input IS the top package, which is fine).
    pub fn suggest(&self, eco: Ecosystem, name: &str) -> Option<Match> {
        if self.threshold == 0 || name.is_empty() {
            return None;
        }
        let list = top_list_for(eco);
        // Fast exact-match exit: if the input is itself a top name,
        // return None immediately. Avoids the full distance loop for
        // the common case.
        if list.iter().any(|top| top.eq_ignore_ascii_case(name)) {
            return None;
        }
        let lc_name = name.to_ascii_lowercase();
        // Scan for the closest top name. Early-exit as soon as we
        // find a distance-1 hit — for typosquat purposes, any
        // 1-close top name is a strong enough signal.
        let mut best: Option<(&'static str, usize)> = None;
        for top in list {
            let lc_top = top.to_ascii_lowercase();
            // Cheap pre-filter: if the lengths differ by more than
            // the threshold, no way the distance is within it.
            if lc_name.len().abs_diff(lc_top.len()) > self.threshold {
                continue;
            }
            let d = edit_distance_bounded(&lc_name, &lc_top, self.threshold);
            match (d, best) {
                (Some(0), _) => return None, // exact (case-insensitive)
                (Some(d), None) => best = Some((top, d)),
                (Some(d), Some((_, bd))) if d < bd => best = Some((top, d)),
                _ => {}
            }
        }
        best.map(|(suggested, distance)| Match {
            input: name.to_string(),
            suggested,
            distance,
        })
    }
}

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

/// Bounded Damerau-Levenshtein (OSA variant) edit distance.
/// Returns `None` if the distance exceeds `max`; `Some(d)` otherwise.
///
/// We use the OSA (Optimal String Alignment) variant of
/// Damerau-Levenshtein rather than plain Levenshtein because the
/// most common class of typosquat — *transposed adjacent letters*
/// like `raect`/`react`, `pytohn`/`python`, `ngninx`/`nginx` — is
/// 1 edit under OSA but 2 edits under plain Levenshtein. Raising
/// plain Levenshtein's threshold to catch those then brings in a
/// flood of false positives (any two-letter-different packages).
///
/// "OSA" means: each substring can be edited at most once. True
/// Damerau-Levenshtein allows unlimited transpositions of
/// arbitrary substrings which is slower and rarely-useful here.
/// The output agrees with Damerau-Levenshtein on all 1-edit
/// typosquats, which is what we care about.
///
/// Implementation: three-row DP (prev-prev, prev, curr), O(min(m,n))
/// memory, early-exit when the row minimum exceeds `max`.
pub fn edit_distance_bounded(a: &str, b: &str, max: usize) -> Option<usize> {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let m = a.len();
    let n = b.len();
    // Symmetry: keep `b` as the longer string.
    if m > n {
        return edit_distance_bounded(
            std::str::from_utf8(b).unwrap_or(""),
            std::str::from_utf8(a).unwrap_or(""),
            max,
        );
    }
    if n - m > max {
        return None;
    }

    // Three rolling rows: `pp` = d[j-2], `p` = d[j-1], `c` = d[j].
    let mut pp: Vec<usize> = vec![0; m + 1];
    let mut p: Vec<usize> = (0..=m).collect();
    let mut c: Vec<usize> = vec![0; m + 1];

    for j in 1..=n {
        c[0] = j;
        let mut row_min = c[0];
        for i in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            let mut v = (p[i] + 1) // deletion
                .min(c[i - 1] + 1) // insertion
                .min(p[i - 1] + cost); // substitution
            // Transposition: if a[i-1]a[i-2] = b[j-2]b[j-1] (i.e.
            // a swap of adjacent chars would align them), we can
            // take d[i-2][j-2] + 1.
            if i >= 2 && j >= 2 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(pp[i - 2] + 1);
            }
            c[i] = v;
            if c[i] < row_min {
                row_min = c[i];
            }
        }
        if row_min > max {
            return None;
        }
        // Rotate: pp ← p, p ← c, c (new scratch) ← pp
        std::mem::swap(&mut pp, &mut p);
        std::mem::swap(&mut p, &mut c);
    }
    // After the final rotation, `p` holds the last completed row.
    let d = p[m];
    (d <= max).then_some(d)
}

fn top_list_for(eco: Ecosystem) -> &'static [&'static str] {
    match eco {
        Ecosystem::Crates => CRATES_TOP,
        Ecosystem::Npm => NPM_TOP,
        Ecosystem::Pypi => PYPI_TOP,
        Ecosystem::Nuget => NUGET_TOP,
    }
}

// --- mirrored detector (v0.29) ----------------------------------

use std::sync::Arc;
use std::sync::RwLock;

use anyhow::{Context, Result};

/// Default URL the consumer pulls from. Populated weekly by the
/// repo's `typosquat-data.yml` workflow; clients override via
/// [`MirroredDetector::with_url`].
pub const DEFAULT_TYPOSQUAT_MIRROR_URL: &str =
    "https://raw.githubusercontent.com/bokuweb/sakimori/typosquat-data/top.json";

/// Background refresh cadence. Daily is plenty — download rankings
/// barely move week to week; sub-hour would just churn GitHub's CDN.
pub const MIRROR_REFRESH_EVERY: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

const MIRROR_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// One snapshot of the mirror — per-ecosystem name lists plus
/// ETag / updated_at for conditional-GET bookkeeping.
#[derive(Debug, Default, Clone)]
pub struct MirrorLists {
    pub npm: Vec<String>,
    pub crates: Vec<String>,
    pub pypi: Vec<String>,
    pub nuget: Vec<String>,
    pub etag: Option<String>,
    pub updated_at: Option<String>,
}

impl MirrorLists {
    fn lookup(&self, eco: Ecosystem) -> &[String] {
        match eco {
            Ecosystem::Crates => &self.crates,
            Ecosystem::Npm => &self.npm,
            Ecosystem::Pypi => &self.pypi,
            Ecosystem::Nuget => &self.nuget,
        }
    }

    fn is_empty_for(&self, eco: Ecosystem) -> bool {
        self.lookup(eco).is_empty()
    }
}

/// Parse the producer's `top.json` payload.
///
/// Schema 1 shape:
/// ```json
/// { "schema": 1, "updated_at": "…",
///   "entries": { "npm": [...], "crates": [...], "pypi": [...], "nuget": [...] } }
/// ```
///
/// Unknown ecosystem keys are silently ignored so the producer can
/// add new lists without breaking old consumers.
pub fn parse_mirror_lists(body: &[u8]) -> Result<MirrorLists> {
    let doc: serde_json::Value =
        serde_json::from_slice(body).context("typosquat mirror body is not JSON")?;
    let entries = doc
        .get("entries")
        .and_then(|v| v.as_object())
        .context("mirror body has no `entries` object")?;
    let take = |key: &str| -> Vec<String> {
        entries
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(MirrorLists {
        npm: take("npm"),
        crates: take("crates"),
        pypi: take("pypi"),
        nuget: take("nuget"),
        etag: None,
        updated_at: doc
            .get("updated_at")
            .and_then(|v| v.as_str())
            .map(String::from),
    })
}

/// Detector that prefers the live mirror lists and falls back to
/// the hard-coded baseline per-ecosystem. Clone cheaply — state
/// lives behind `Arc<RwLock<_>>`.
#[derive(Debug, Clone)]
pub struct MirroredDetector {
    pub threshold: usize,
    url: String,
    user_agent: String,
    state: Arc<RwLock<MirrorLists>>,
}

impl MirroredDetector {
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self::with_url(user_agent, DEFAULT_TYPOSQUAT_MIRROR_URL)
    }

    pub fn with_url(user_agent: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            threshold: DEFAULT_THRESHOLD,
            url: url.into(),
            user_agent: user_agent.into(),
            state: Arc::new(RwLock::new(MirrorLists::default())),
        }
    }

    pub fn with_threshold(mut self, t: usize) -> Self {
        self.threshold = t;
        self
    }

    /// One-shot fetch + swap. Returns `true` on update, `false` on
    /// HTTP 304. Errors bubble up so the refresh loop can log.
    pub fn refresh_once(&self) -> Result<bool> {
        let etag_before = self.state.read().ok().and_then(|s| s.etag.clone());
        let mut req = ureq::get(&self.url)
            .set("user-agent", &self.user_agent)
            .set("accept", "application/json")
            .timeout(MIRROR_FETCH_TIMEOUT);
        if let Some(etag) = &etag_before {
            req = req.set("if-none-match", etag);
        }
        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(304, _)) => return Ok(false),
            Err(e) => return Err(anyhow::anyhow!("fetch {}: {e:#}", self.url)),
        };
        let new_etag = resp.header("etag").map(String::from);
        let body = resp.into_string().context("mirror body unreadable")?;
        let mut parsed = parse_mirror_lists(body.as_bytes())?;
        parsed.etag = new_etag;
        if let Ok(mut w) = self.state.write() {
            log::info!(
                "typosquat-mirror: refreshed — npm={} crates={} pypi={} nuget={}",
                parsed.npm.len(),
                parsed.crates.len(),
                parsed.pypi.len(),
                parsed.nuget.len(),
            );
            *w = parsed;
        }
        Ok(true)
    }

    /// Fire-and-forget background refresh. Immediate call then
    /// every [`MIRROR_REFRESH_EVERY`].
    pub fn spawn_refresh_loop(&self) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let ours = this.clone();
                let res = tokio::task::spawn_blocking(move || ours.refresh_once()).await;
                match res {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => log::warn!("typosquat-mirror: refresh failed: {e:#}"),
                    Err(e) => log::warn!("typosquat-mirror: task panicked: {e}"),
                }
                tokio::time::sleep(MIRROR_REFRESH_EVERY).await;
            }
        })
    }

    /// Suggest the closest typosquat candidate, preferring the
    /// mirror; fall back to the hard-coded baseline per-ecosystem
    /// when the mirror has no entries for that ecosystem.
    pub fn suggest(&self, eco: Ecosystem, name: &str) -> Option<Match> {
        if self.threshold == 0 || name.is_empty() {
            return None;
        }
        let lc_name = name.to_ascii_lowercase();

        // Tier 1: mirror.
        let from_mirror = {
            let s = self.state.read().ok();
            s.as_ref()
                .filter(|s| !s.is_empty_for(eco))
                .and_then(|s| scan_mirror(s.lookup(eco), &lc_name, name, self.threshold))
        };
        match from_mirror {
            Some(Outcome::Exact) => return None,
            Some(Outcome::Match(m)) => return Some(m),
            None => {}
        }

        // Tier 2: baseline fallback (identical to `Detector::suggest`).
        Detector::with_threshold(self.threshold).suggest(eco, name)
    }
}

/// Result of scanning one mirror list: either the input was an
/// exact match (legitimate top package — suppress all warnings),
/// or we found the closest neighbour within the threshold.
enum Outcome {
    Exact,
    Match(Match),
}

fn scan_mirror(
    list: &[String],
    lc_name: &str,
    original: &str,
    threshold: usize,
) -> Option<Outcome> {
    // Fast exact-match exit (case-insensitive).
    if list.iter().any(|top| top.eq_ignore_ascii_case(original)) {
        return Some(Outcome::Exact);
    }
    let mut best: Option<(String, usize)> = None;
    for top in list {
        let lc_top = top.to_ascii_lowercase();
        if lc_name.len().abs_diff(lc_top.len()) > threshold {
            continue;
        }
        let d = edit_distance_bounded(lc_name, &lc_top, threshold);
        match (d, best.as_ref()) {
            (Some(0), _) => return Some(Outcome::Exact),
            (Some(d), None) => best = Some((top.clone(), d)),
            (Some(d), Some((_, bd))) if d < *bd => best = Some((top.clone(), d)),
            _ => {}
        }
    }
    best.map(|(suggested, distance)| {
        // Intern the String into a leaked &'static so it fits the
        // existing `Match.suggested: &'static str` field. Leaks
        // are bounded — one per distinct typosquat-hit suggestion,
        // which is a handful per proxy lifetime in practice.
        Outcome::Match(Match {
            input: original.to_string(),
            suggested: Box::leak(suggested.into_boxed_str()),
            distance,
        })
    })
}

// --- hard-coded top lists ---------------------------------------
//
// Derived from recent download rankings (npm Registry stats, PyPI
// downloads via BigQuery, crates.io `?sort=downloads`, NuGet stats).
// Names are case-preserved as the registry lists them; the matcher
// does case-insensitive comparison.
//
// These are deliberately small (~100 per ecosystem). The goal isn't
// coverage — it's to catch typosquats of the *commonly-targeted*
// big packages. Adding a niche library here gains nothing; a
// typosquat of it is unlikely. The roadmap includes an automated
// weekly rebuild from live ranking data; this MVP uses frozen
// lists so the first release doesn't depend on a separate cron.

/// Top ~100 npm package names.
pub const NPM_TOP: &[&str] = &[
    "react",
    "lodash",
    "axios",
    "express",
    "chalk",
    "debug",
    "tslib",
    "vue",
    "next",
    "webpack",
    "babel-core",
    "babel-runtime",
    "typescript",
    "eslint",
    "prettier",
    "mocha",
    "jest",
    "chai",
    "underscore",
    "moment",
    "request",
    "bluebird",
    "commander",
    "yargs",
    "fs-extra",
    "minimist",
    "glob",
    "rimraf",
    "semver",
    "rxjs",
    "tsconfig-paths",
    "uuid",
    "dotenv",
    "ws",
    "ms",
    "cheerio",
    "body-parser",
    "cors",
    "passport",
    "mongoose",
    "redis",
    "ioredis",
    "sequelize",
    "knex",
    "pg",
    "mysql",
    "mysql2",
    "sqlite3",
    "socket.io",
    "socket.io-client",
    "form-data",
    "node-fetch",
    "cross-env",
    "cross-spawn",
    "concurrently",
    "nodemon",
    "ts-node",
    "react-dom",
    "react-router",
    "react-router-dom",
    "redux",
    "react-redux",
    "@reduxjs/toolkit",
    "styled-components",
    "tailwindcss",
    "postcss",
    "autoprefixer",
    "vite",
    "rollup",
    "esbuild",
    "parcel",
    "gulp",
    "grunt",
    "handlebars",
    "ejs",
    "pug",
    "sass",
    "less",
    "node-sass",
    "jquery",
    "bootstrap",
    "three",
    "d3",
    "chart.js",
    "leaflet",
    "yarn",
    "pnpm",
    "npm",
    "colors",
    "ansi-styles",
    "supports-color",
    "color",
    "kleur",
    "picocolors",
    "inquirer",
    "ora",
    "chalk-template",
    "got",
    "ky",
    "superagent",
    "undici",
    "graphql",
    "apollo-client",
    "@apollo/client",
    "prisma",
    "@prisma/client",
];

/// Top ~100 crates.io crate names.
pub const CRATES_TOP: &[&str] = &[
    "serde",
    "serde_json",
    "tokio",
    "anyhow",
    "thiserror",
    "clap",
    "reqwest",
    "regex",
    "log",
    "env_logger",
    "tracing",
    "tracing-subscriber",
    "futures",
    "futures-util",
    "async-trait",
    "rand",
    "chrono",
    "time",
    "uuid",
    "url",
    "bytes",
    "once_cell",
    "lazy_static",
    "itertools",
    "rayon",
    "parking_lot",
    "crossbeam",
    "crossbeam-channel",
    "dashmap",
    "hashbrown",
    "indexmap",
    "smallvec",
    "num",
    "num-traits",
    "num-bigint",
    "hex",
    "base64",
    "sha2",
    "md5",
    "blake3",
    "ring",
    "rustls",
    "openssl",
    "native-tls",
    "hyper",
    "tower",
    "tower-http",
    "axum",
    "actix-web",
    "warp",
    "rocket",
    "diesel",
    "sqlx",
    "redis",
    "mongodb",
    "bson",
    "yaml",
    "serde_yaml",
    "toml",
    "ron",
    "postcard",
    "bincode",
    "rmp",
    "rmp-serde",
    "flate2",
    "tar",
    "zip",
    "walkdir",
    "ignore",
    "notify",
    "fs-err",
    "dirs",
    "directories",
    "which",
    "tempfile",
    "proptest",
    "criterion",
    "mockall",
    "pretty_assertions",
    "insta",
    "assert_cmd",
    "predicates",
    "strum",
    "strum_macros",
    "derive_more",
    "paste",
    "pin-project",
    "pin-project-lite",
    "async-std",
    "smol",
    "tokio-util",
    "tokio-stream",
    "async-channel",
    "flume",
    "color-eyre",
    "eyre",
    "miette",
    "nom",
    "combine",
    "winnow",
];

/// Top ~100 PyPI package names.
pub const PYPI_TOP: &[&str] = &[
    "requests",
    "urllib3",
    "numpy",
    "pandas",
    "flask",
    "django",
    "fastapi",
    "uvicorn",
    "gunicorn",
    "werkzeug",
    "jinja2",
    "sqlalchemy",
    "pydantic",
    "pydantic-core",
    "typing-extensions",
    "click",
    "rich",
    "tqdm",
    "pytest",
    "pytest-cov",
    "coverage",
    "black",
    "flake8",
    "isort",
    "mypy",
    "ruff",
    "pylint",
    "pillow",
    "matplotlib",
    "seaborn",
    "plotly",
    "bokeh",
    "scipy",
    "scikit-learn",
    "tensorflow",
    "torch",
    "keras",
    "transformers",
    "huggingface-hub",
    "datasets",
    "tokenizers",
    "openai",
    "anthropic",
    "langchain",
    "langchain-core",
    "boto3",
    "botocore",
    "s3transfer",
    "pyyaml",
    "toml",
    "tomli",
    "tomli_w",
    "python-dotenv",
    "pytz",
    "python-dateutil",
    "six",
    "setuptools",
    "wheel",
    "pip",
    "virtualenv",
    "poetry",
    "pipenv",
    "hatchling",
    "build",
    "twine",
    "keyring",
    "cryptography",
    "bcrypt",
    "passlib",
    "pyjwt",
    "oauthlib",
    "requests-oauthlib",
    "google-auth",
    "google-auth-oauthlib",
    "protobuf",
    "grpcio",
    "grpcio-tools",
    "celery",
    "redis",
    "kombu",
    "billiard",
    "amqp",
    "vine",
    "marshmallow",
    "attrs",
    "cattrs",
    "structlog",
    "loguru",
    "colorlog",
    "httpx",
    "aiohttp",
    "asyncio",
    "trio",
    "anyio",
    "websockets",
    "aioredis",
    "asyncpg",
    "psycopg2",
    "psycopg2-binary",
    "mysqlclient",
    "pymysql",
    "sqlite3-binary",
    "alembic",
];

/// Top ~100 NuGet package names. NuGet names are case-sensitive in
/// listing but case-insensitive in lookup — we keep the canonical
/// casing here.
pub const NUGET_TOP: &[&str] = &[
    "Newtonsoft.Json",
    "Microsoft.Extensions.Logging",
    "Microsoft.Extensions.Logging.Abstractions",
    "Microsoft.Extensions.DependencyInjection",
    "Microsoft.Extensions.DependencyInjection.Abstractions",
    "Microsoft.Extensions.Configuration",
    "Microsoft.Extensions.Configuration.Abstractions",
    "Microsoft.Extensions.Configuration.Binder",
    "Microsoft.Extensions.Configuration.EnvironmentVariables",
    "Microsoft.Extensions.Configuration.FileExtensions",
    "Microsoft.Extensions.Configuration.Json",
    "Microsoft.Extensions.Options",
    "Microsoft.Extensions.Primitives",
    "Microsoft.Extensions.Hosting",
    "Microsoft.Extensions.Http",
    "Microsoft.AspNetCore.App",
    "Microsoft.NETCore.App",
    "System.Text.Json",
    "System.Text.Encodings.Web",
    "System.Memory",
    "System.Threading.Tasks.Extensions",
    "System.Buffers",
    "System.Runtime.CompilerServices.Unsafe",
    "System.Net.Http.Json",
    "System.IdentityModel.Tokens.Jwt",
    "Microsoft.IdentityModel.Tokens",
    "Microsoft.IdentityModel.Logging",
    "Microsoft.Bcl.AsyncInterfaces",
    "Serilog",
    "Serilog.AspNetCore",
    "Serilog.Sinks.Console",
    "Serilog.Sinks.File",
    "Serilog.Formatting.Compact",
    "Serilog.Settings.Configuration",
    "NLog",
    "NLog.Web.AspNetCore",
    "log4net",
    "AutoMapper",
    "AutoMapper.Extensions.Microsoft.DependencyInjection",
    "FluentValidation",
    "FluentValidation.AspNetCore",
    "FluentValidation.DependencyInjectionExtensions",
    "Polly",
    "Polly.Extensions.Http",
    "Moq",
    "Moq.AutoMock",
    "xunit",
    "xunit.runner.visualstudio",
    "xunit.analyzers",
    "NUnit",
    "NUnit3TestAdapter",
    "MSTest.TestAdapter",
    "MSTest.TestFramework",
    "Microsoft.NET.Test.Sdk",
    "FluentAssertions",
    "Shouldly",
    "coverlet.collector",
    "coverlet.msbuild",
    "EntityFramework",
    "Microsoft.EntityFrameworkCore",
    "Microsoft.EntityFrameworkCore.Design",
    "Microsoft.EntityFrameworkCore.SqlServer",
    "Microsoft.EntityFrameworkCore.InMemory",
    "Microsoft.EntityFrameworkCore.Sqlite",
    "Microsoft.EntityFrameworkCore.Tools",
    "Dapper",
    "RestSharp",
    "Refit",
    "MediatR",
    "MediatR.Extensions.Microsoft.DependencyInjection",
    "MassTransit",
    "RabbitMQ.Client",
    "StackExchange.Redis",
    "Azure.Storage.Blobs",
    "Azure.Identity",
    "Azure.Core",
    "AWSSDK.S3",
    "AWSSDK.Core",
    "Swashbuckle.AspNetCore",
    "Swashbuckle.AspNetCore.Swagger",
    "Swashbuckle.AspNetCore.SwaggerGen",
    "Swashbuckle.AspNetCore.SwaggerUI",
    "Hangfire",
    "Hangfire.AspNetCore",
    "Hangfire.SqlServer",
    "Quartz",
    "Quartz.Extensions.Hosting",
    "CsvHelper",
    "BenchmarkDotNet",
    "CommandLineParser",
    "Microsoft.AspNetCore.Authentication.JwtBearer",
    "Microsoft.AspNetCore.Mvc.NewtonsoftJson",
    "Microsoft.AspNetCore.Mvc.Versioning",
    "Microsoft.AspNetCore.Authentication.OpenIdConnect",
    "Npgsql",
    "Npgsql.EntityFrameworkCore.PostgreSQL",
    "MongoDB.Driver",
    "MongoDB.Bson",
    "Google.Protobuf",
    "Grpc.Net.Client",
    "Grpc.AspNetCore",
    "Grpc.Tools",
    "System.CommandLine",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_returns_none() {
        let d = Detector::new();
        // Installing `react` itself is legitimate.
        assert!(d.suggest(Ecosystem::Npm, "react").is_none());
        // Case-insensitive on npm / crates / nuget.
        assert!(d.suggest(Ecosystem::Npm, "REACT").is_none());
        assert!(d.suggest(Ecosystem::Nuget, "newtonsoft.json").is_none());
    }

    #[test]
    fn common_typosquats_are_flagged() {
        let d = Detector::new();
        let cases = [
            (Ecosystem::Npm, "raect", "react"),
            (Ecosystem::Npm, "lodas", "lodash"),
            (Ecosystem::Pypi, "reqeusts", "requests"),
            (Ecosystem::Pypi, "numpya", "numpy"),
            (Ecosystem::Crates, "serde_jsn", "serde_json"),
            (Ecosystem::Crates, "tokyo", "tokio"),
        ];
        for (eco, input, expected) in cases {
            let m = d
                .suggest(eco, input)
                .unwrap_or_else(|| panic!("{input} should have been flagged near {expected}"));
            assert_eq!(
                m.suggested, expected,
                "typo {input:?}: expected suggestion {expected:?}, got {:?}",
                m.suggested
            );
            assert!(m.distance <= d.threshold);
        }
    }

    #[test]
    fn distance_beyond_threshold_is_ignored() {
        // "asdf" is far from anything in the lists — should not
        // trigger a suggestion at threshold=1.
        let d = Detector::with_threshold(1);
        assert!(d.suggest(Ecosystem::Npm, "asdf").is_none());
        assert!(d.suggest(Ecosystem::Npm, "my-private-pkg").is_none());
    }

    #[test]
    fn threshold_zero_disables() {
        // threshold=0 effectively disables detection — the only
        // name within 0 is the exact match itself, which the early
        // exit already rejects.
        let d = Detector::with_threshold(0);
        assert!(d.suggest(Ecosystem::Npm, "raect").is_none());
        assert!(d.suggest(Ecosystem::Npm, "anything").is_none());
    }

    #[test]
    fn empty_name_returns_none() {
        let d = Detector::new();
        assert!(d.suggest(Ecosystem::Npm, "").is_none());
    }

    #[test]
    fn higher_threshold_catches_more_but_with_false_positives_risk() {
        // At threshold=2, common substring-edit typosquats start
        // triggering. We don't ship this as default precisely because
        // the false-positive rate on short names goes up.
        let d = Detector::with_threshold(2);
        // Two edits away from "react".
        assert!(d.suggest(Ecosystem::Npm, "ryect").is_some());
    }

    #[test]
    fn osa_distance_edge_cases() {
        // Identical.
        assert_eq!(edit_distance_bounded("react", "react", 1), Some(0));
        // Adjacent transposition counts as 1 under OSA (vs 2 under
        // pure Levenshtein). This is load-bearing for typosquat UX.
        assert_eq!(edit_distance_bounded("raect", "react", 1), Some(1));
        assert_eq!(edit_distance_bounded("pytohn", "python", 1), Some(1));
        // "raet" → "react" needs insert + transpose = 2 edits.
        assert_eq!(edit_distance_bounded("raet", "react", 1), None);
        assert_eq!(edit_distance_bounded("raet", "react", 2), Some(2));
        // Length difference already exceeds bound → bail early.
        assert_eq!(edit_distance_bounded("", "react", 1), None);
        assert_eq!(edit_distance_bounded("", "", 0), Some(0));
        // Single substitution.
        assert_eq!(edit_distance_bounded("colors", "colars", 1), Some(1));
    }

    #[test]
    fn osa_symmetric() {
        // distance(a, b) == distance(b, a)
        assert_eq!(
            edit_distance_bounded("foo", "barbaz", 10),
            edit_distance_bounded("barbaz", "foo", 10)
        );
    }

    #[test]
    fn lists_are_nonempty_per_ecosystem() {
        // Sanity: no ecosystem should ship with an empty top list;
        // would silently disable typosquat detection there.
        assert!(!NPM_TOP.is_empty());
        assert!(!CRATES_TOP.is_empty());
        assert!(!PYPI_TOP.is_empty());
        assert!(!NUGET_TOP.is_empty());
        // Also: no duplicates within a list.
        for list in [NPM_TOP, CRATES_TOP, PYPI_TOP, NUGET_TOP] {
            let mut seen = std::collections::HashSet::new();
            for n in list {
                assert!(seen.insert(n.to_ascii_lowercase()), "dup: {n}");
            }
        }
    }
}
