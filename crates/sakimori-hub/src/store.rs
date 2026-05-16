//! SQLite-backed install inventory.
//!
//! One row per `InstallEvent`. We do not de-duplicate at insert time
//! — two distinct `npm install`s of the same `(name, version)` are
//! two separate inventory events, both worth surfacing (different
//! timestamps, possibly different project paths). De-duplication for
//! the advisory-JOIN dispatcher will happen at query time.
//!
//! ## Connection model
//!
//! Single [`rusqlite::Connection`] behind a `Mutex`. SQLite's own
//! per-process locking would let us hand out multiple connections,
//! but the ingest rate is bounded by HTTP request volume — a single
//! writer is plenty for the foreseeable team-size deploy target. We
//! run the connection's blocking calls inside
//! [`tokio::task::spawn_blocking`] so the tokio runtime stays
//! responsive under load.
//!
//! ## Time representation
//!
//! `resolved_at` and `ingested_at` are stored **twice** per row:
//!
//! - `*_ms` (`INTEGER NOT NULL`) — epoch milliseconds, UTC. This is
//!   the column used for `ORDER BY` and the `since` filter. Storing
//!   as a fixed-width integer side-steps text-comparison hazards
//!   (mixed offsets, missing/varying fractional seconds, `Z` vs
//!   `+00:00`) and is what we add the time-range index on.
//! - `*_text` (`TEXT NOT NULL`) — RFC3339 rendering of the same
//!   instant, normalised to UTC at write time. Kept for human-
//!   readable inspection of the DB and for the JSON read API,
//!   which deserialises straight to [`chrono::DateTime<Utc>`].
//!
//! Both are written from the same `DateTime<Utc>` value so they can
//! never disagree.
//!
//! ## Durability
//!
//! Pragmas are `journal_mode=WAL` + `synchronous=NORMAL`. Under
//! crash/power loss the most-recent commit *may* be lost; longer
//! WAL state remains safe. This is a deliberate trade-off for an
//! inventory: one missed proxy-side event is a tiny gap in history
//! the proxy can re-emit, while `synchronous=FULL` would dominate
//! per-insert latency. Operators who need strict durability can
//! flip the pragma via `PRAGMA synchronous=FULL` against the open
//! file.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use rusqlite::types::Type as SqlType;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::sync::Mutex;

use sakimori_core::installs::{ExecutionMode, InstallEvent};

use crate::classify::{Source, classify};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub id: i64,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub resolved_at: DateTime<Utc>,
    pub execution_mode: ExecutionMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub source: Source,
    /// Wall-clock time the hub received the event. Distinct from
    /// `resolved_at` (which is when the proxy resolved the fetch) so
    /// a delayed batch upload of older events is detectable.
    pub ingested_at: DateTime<Utc>,
}

/// An event submitted via the ingest API, paired with an optional
/// explicit `source` override. When present the override wins over
/// the heuristic classifier — the proxy knows its own runtime
/// context more reliably than we can infer from `(project_path,
/// user_agent)` alone.
#[derive(Debug, Clone)]
pub struct IngestRecord {
    pub event: InstallEvent,
    pub source: Option<Source>,
}

impl From<InstallEvent> for IngestRecord {
    fn from(event: InstallEvent) -> Self {
        Self {
            event,
            source: None,
        }
    }
}

/// Query filters for [`Store::list`]. All fields are AND-combined;
/// `None` means "no filter on this axis".
#[derive(Debug, Default, Clone)]
pub struct ListFilter {
    pub ecosystem: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub source: Option<Source>,
    pub since: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
}

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

impl Store {
    /// Open (and migrate, if needed) the SQLite file at `path`. Use
    /// `":memory:"` for an ephemeral test store.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening sqlite at {}", path.display()))?;
        Self::from_conn(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("opening in-memory sqlite")?;
        Self::from_conn(conn)
    }

    fn from_conn(mut conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )
        .context("setting sqlite pragmas")?;
        migrate(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Insert one event and return its assigned row id.
    pub async fn insert(&self, record: IngestRecord) -> Result<i64> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            insert_blocking(&guard, &record)
        })
        .await
        .context("spawn_blocking insert join")?
    }

    /// Atomic batch insert. All rows commit together or the
    /// transaction is rolled back and no rows are visible. Returns
    /// the assigned ids in input order.
    pub async fn insert_many(&self, records: Vec<IngestRecord>) -> Result<Vec<i64>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.blocking_lock();
            let tx = guard.transaction().context("opening insert tx")?;
            let mut ids = Vec::with_capacity(records.len());
            for rec in &records {
                ids.push(insert_blocking(&tx, rec)?);
            }
            tx.commit().context("committing insert tx")?;
            Ok(ids)
        })
        .await
        .context("spawn_blocking insert_many join")?
    }

    /// List events matching `filter`, newest `resolved_at` first.
    pub async fn list(&self, filter: ListFilter) -> Result<Vec<StoredEvent>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            list_blocking(&guard, &filter)
        })
        .await
        .context("spawn_blocking list join")?
    }

    /// Total row count — small, cheap helper for the HTML view.
    pub async fn count(&self) -> Result<i64> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let n: i64 = guard
                .query_row("SELECT COUNT(*) FROM installs", [], |r| r.get(0))
                .context("counting installs")?;
            Ok(n)
        })
        .await
        .context("spawn_blocking count join")?
    }

    /// Current `schema_version` value. Exposed so the next slice
    /// can guard its dispatcher against an unknown future schema.
    pub async fn schema_version(&self) -> Result<i32> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let v: i32 = guard
                .query_row("SELECT version FROM schema_version WHERE id = 1", [], |r| {
                    r.get(0)
                })
                .context("reading schema_version")?;
            Ok(v)
        })
        .await
        .context("spawn_blocking schema_version join")?
    }
}

const CURRENT_SCHEMA_VERSION: i32 = 9;

/// Numbered migration registry. New entries append at the end and
/// run inside a transaction; the `schema_version` row is then
/// bumped. We keep it as an in-source `&[Migration]` rather than
/// embedding SQL files so the compiler enforces that every shipped
/// build carries every migration.
struct Migration {
    version: i32,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: "CREATE TABLE installs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ecosystem       TEXT NOT NULL,
            name            TEXT NOT NULL,
            version         TEXT NOT NULL,
            resolved_at_ms  INTEGER NOT NULL,
            resolved_at_text TEXT NOT NULL,
            execution_mode  TEXT NOT NULL,
            project_path    TEXT,
            user_agent      TEXT,
            source          TEXT NOT NULL,
            ingested_at_ms  INTEGER NOT NULL,
            ingested_at_text TEXT NOT NULL
         );
         CREATE INDEX idx_installs_eco_name_ver
             ON installs(ecosystem, name, version);
         CREATE INDEX idx_installs_resolved_at_ms
             ON installs(resolved_at_ms);
         CREATE INDEX idx_installs_source
             ON installs(source);",
    },
    Migration {
        version: 2,
        sql: "CREATE TABLE advisories (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            osv_id          TEXT NOT NULL UNIQUE,
            summary         TEXT,
            severity        TEXT NOT NULL,
            published_at_ms INTEGER,
            raw_json        TEXT NOT NULL,
            ingested_at_ms  INTEGER NOT NULL
         );
         CREATE TABLE advisory_affected (
            advisory_id     INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
            ecosystem       TEXT NOT NULL,
            name            TEXT NOT NULL,
            version         TEXT NOT NULL,
            PRIMARY KEY (advisory_id, ecosystem, name, version)
         );
         CREATE INDEX idx_advisory_affected_lookup
             ON advisory_affected(ecosystem, name, version);
         CREATE TABLE findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_id     INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
            install_id      INTEGER NOT NULL REFERENCES installs(id) ON DELETE CASCADE,
            created_at_ms   INTEGER NOT NULL,
            UNIQUE (advisory_id, install_id)
         );
         CREATE INDEX idx_findings_advisory   ON findings(advisory_id);
         CREATE INDEX idx_findings_install    ON findings(install_id);
         CREATE INDEX idx_findings_created_at ON findings(created_at_ms);",
    },
    Migration {
        version: 3,
        sql: "CREATE TABLE dispatch_targets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            label           TEXT NOT NULL UNIQUE,
            url             TEXT NOT NULL,
            secret          TEXT NOT NULL,
            min_severity    TEXT NOT NULL,
            source_filter   TEXT,
            enabled         INTEGER NOT NULL DEFAULT 1,
            created_at_ms   INTEGER NOT NULL
         );
         CREATE TABLE dispatch_attempts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id      INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            target_id       INTEGER NOT NULL REFERENCES dispatch_targets(id) ON DELETE CASCADE,
            attempt_at_ms   INTEGER NOT NULL,
            success         INTEGER NOT NULL,
            http_status     INTEGER,
            error           TEXT
         );
         CREATE INDEX idx_dispatch_attempts_lookup
             ON dispatch_attempts(finding_id, target_id, success);
         CREATE INDEX idx_dispatch_attempts_target
             ON dispatch_attempts(target_id, attempt_at_ms);",
    },
    Migration {
        version: 4,
        sql: "ALTER TABLE dispatch_targets ADD COLUMN deleted_at_ms INTEGER;
         -- Defence in depth against the application-level dedupe: even
         -- if a future bug double-fires `record_attempt(.., true, ..)`,
         -- the second insert hits this index and errors out instead of
         -- silently double-counting a delivered finding.
         CREATE UNIQUE INDEX idx_dispatch_attempts_success_unique
             ON dispatch_attempts(finding_id, target_id) WHERE success = 1;",
    },
    Migration {
        version: 5,
        sql: "CREATE TABLE advisory_ranges (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_id      INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
            ecosystem        TEXT NOT NULL,
            name             TEXT NOT NULL,
            -- Interval is `[introduced, upper)` when
            -- upper_inclusive=0 (came from a `fixed` / `limit`
            -- close), `[introduced, upper]` when upper_inclusive=1
            -- (came from `last_affected`). Storing the bound's
            -- inclusivity lets the scanner use < vs <= rather
            -- than fabricating an exclusive bound by bumping the
            -- patch, which would over-match prereleases.
            -- `upper` is NULL when the range is explicitly
            -- unbounded above.
            introduced       TEXT NOT NULL,
            upper            TEXT,
            upper_inclusive  INTEGER NOT NULL DEFAULT 0
         );
         CREATE INDEX idx_advisory_ranges_lookup
             ON advisory_ranges(ecosystem, name);",
    },
    Migration {
        version: 6,
        sql: "CREATE TABLE users (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            github_user_id    INTEGER NOT NULL UNIQUE,
            github_login      TEXT NOT NULL,
            display_name      TEXT,
            avatar_url        TEXT,
            created_at_ms     INTEGER NOT NULL,
            last_login_at_ms  INTEGER NOT NULL
         );
         CREATE INDEX idx_users_github_login ON users(github_login);
         -- Sessions: we store a SHA-256 hash of the cookie value,
         -- never the cleartext, so a DB dump can't impersonate
         -- live users. The cookie itself is HMAC-signed
         -- (see `crate::auth::session`) so even the hash lookup
         -- requires a valid signature.
         CREATE TABLE sessions (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash        BLOB NOT NULL UNIQUE,
            user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at_ms     INTEGER NOT NULL,
            expires_at_ms     INTEGER NOT NULL,
            revoked_at_ms     INTEGER,
            user_agent        TEXT
         );
         CREATE INDEX idx_sessions_user ON sessions(user_id);
         CREATE INDEX idx_sessions_expires ON sessions(expires_at_ms);",
    },
    Migration {
        version: 7,
        sql: "CREATE TABLE api_tokens (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            -- Cleartext token never persisted; only its SHA-256
            -- hash. A DB dump can revoke but not impersonate.
            token_hash        BLOB NOT NULL UNIQUE,
            -- First 12 chars of the cleartext token (including
            -- the `shp_` prefix), so the list UI can show
            -- `shp_AbCdEfGh…` for human recognition without ever
            -- revealing the full secret again. NOT sensitive on
            -- its own — even the full prefix is ~6 bytes of
            -- entropy, far short of brute-forceable.
            prefix            TEXT NOT NULL,
            -- Operator-supplied human label (e.g. \"laptop-CI\",
            -- \"github-actions-ci-bootstrap\").
            label             TEXT NOT NULL,
            created_at_ms     INTEGER NOT NULL,
            -- Best-effort `last seen at` for the list UI. Updated
            -- async on successful auth so request latency isn't
            -- coupled to a DB write.
            last_used_at_ms   INTEGER,
            -- Optional expiry. NULL = never expires (operator
            -- has to revoke explicitly).
            expires_at_ms     INTEGER,
            -- Set on revoke; NULL while active.
            revoked_at_ms     INTEGER
         );
         CREATE INDEX idx_api_tokens_user ON api_tokens(user_id);",
    },
    Migration {
        version: 8,
        sql: "CREATE TABLE actions_tokens (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            -- SHA-256 of the cleartext `sha_<...>` token; the
            -- cleartext only lives in the workflow's memory and
            -- never reaches the DB.
            token_hash        BLOB NOT NULL UNIQUE,
            -- First 12 chars (`sha_AbCdEfGh`) for the audit view.
            -- Not sensitive on its own.
            prefix            TEXT NOT NULL,
            -- `org/repo` exactly as `repository` was in the OIDC
            -- JWT. The `repository_owner`/`workflow_ref` columns
            -- below are observability — the auth decision was
            -- already taken when the token was minted, so they're
            -- not load-bearing for middleware.
            repository        TEXT NOT NULL,
            repository_owner  TEXT NOT NULL,
            workflow_ref      TEXT,
            -- JWT `sub` claim, kept for audit (it encodes
            -- environment / ref / pull-request context).
            subject           TEXT NOT NULL,
            created_at_ms     INTEGER NOT NULL,
            -- Required for actions tokens — they are explicitly
            -- short-lived, no \"forever\" path.
            expires_at_ms     INTEGER NOT NULL,
            last_used_at_ms   INTEGER,
            revoked_at_ms     INTEGER
         );
         CREATE INDEX idx_actions_tokens_repository
             ON actions_tokens(repository, created_at_ms DESC);",
    },
    Migration {
        version: 9,
        sql: "CREATE TABLE device_codes (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            -- Random 32-byte secret the CLI keeps. UNIQUE so a
            -- duplicate collision (~astronomically unlikely with
            -- 256 bits) becomes a loud DB error, not a silent
            -- account-swap.
            device_code       TEXT NOT NULL UNIQUE,
            -- Short human-readable code the operator types in
            -- the browser. UNIQUE constraint enforces the
            -- one-active-code property — colliding mint retries
            -- on the application side (see store::mint_device_code).
            user_code         TEXT NOT NULL UNIQUE,
            -- pending | approved | denied | consumed | expired
            status            TEXT NOT NULL,
            -- Operator-supplied label that gets carried onto the
            -- minted api_tokens row at consume time.
            label             TEXT NOT NULL,
            -- Populated at approval time; the consume step mints
            -- the personal token under this user.
            approving_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            -- Populated at consume time. After consume, this row
            -- is dead weight — the polled CLI now holds the
            -- cleartext token; subsequent polls see `consumed`.
            consumed_token_id INTEGER REFERENCES api_tokens(id) ON DELETE SET NULL,
            created_at_ms     INTEGER NOT NULL,
            expires_at_ms     INTEGER NOT NULL,
            -- Rate-limits the CLI's poll cadence — see the
            -- store::lookup_device_code `slow_down` rule. NULL
            -- before the first poll.
            last_polled_at_ms INTEGER,
            approved_at_ms    INTEGER,
            consumed_at_ms    INTEGER
         );
         CREATE INDEX idx_device_codes_user_code ON device_codes(user_code);
         CREATE INDEX idx_device_codes_expires  ON device_codes(expires_at_ms);",
    },
];

fn migrate(conn: &mut Connection) -> Result<()> {
    // schema_version is a CHECKed singleton so a manual repair or a
    // half-applied migration can't leave two rows that race the
    // "current version?" read. The CHECK clause does the work of
    // a `UNIQUE`-on-1 + `NOT NULL` constraint in one line.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
             id            INTEGER PRIMARY KEY CHECK (id = 1),
             version       INTEGER NOT NULL,
             applied_at_ms INTEGER NOT NULL
         );",
    )
    .context("creating schema_version table")?;

    // Distinguish "no row yet" from "query errored". `.ok()` would
    // silently swallow corruption / wrong-shape-table problems.
    let current: Option<i32> = conn
        .query_row("SELECT version FROM schema_version WHERE id = 1", [], |r| {
            r.get(0)
        })
        .optional()
        .context("reading schema_version")?;
    let from = current.unwrap_or(0);
    if from > CURRENT_SCHEMA_VERSION {
        anyhow::bail!(
            "schema_version {from} is newer than this binary supports ({CURRENT_SCHEMA_VERSION}); \
             refusing to downgrade"
        );
    }

    // Each migration + its schema_version bump runs inside one
    // transaction. A crash before commit leaves the DB at the
    // *previous* version, and `migrate()` on the next open retries
    // the same migration cleanly.
    for m in MIGRATIONS {
        if m.version > from {
            let tx = conn
                .transaction()
                .with_context(|| format!("opening tx for migration v{}", m.version))?;
            tx.execute_batch(m.sql)
                .with_context(|| format!("running migration v{}", m.version))?;
            tx.execute(
                "INSERT INTO schema_version (id, version, applied_at_ms) VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET version = excluded.version,
                                               applied_at_ms = excluded.applied_at_ms",
                params![m.version, Utc::now().timestamp_millis()],
            )
            .with_context(|| format!("bumping schema_version to v{}", m.version))?;
            tx.commit()
                .with_context(|| format!("committing migration v{}", m.version))?;
        }
    }
    Ok(())
}

fn insert_blocking(conn: &Connection, record: &IngestRecord) -> Result<i64> {
    let event = &record.event;
    let source = record
        .source
        .unwrap_or_else(|| classify(event.project_path.as_deref(), event.user_agent.as_deref()));
    let resolved_ms = event.resolved_at.timestamp_millis();
    let ingested_at = Utc::now();
    let ingested_ms = ingested_at.timestamp_millis();
    conn.execute(
        "INSERT INTO installs
            (ecosystem, name, version,
             resolved_at_ms, resolved_at_text,
             execution_mode, project_path, user_agent, source,
             ingested_at_ms, ingested_at_text)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            event.ecosystem,
            event.name,
            event.version,
            resolved_ms,
            event.resolved_at.to_rfc3339(),
            execution_mode_to_str(event.execution_mode),
            event.project_path,
            event.user_agent,
            source.as_str(),
            ingested_ms,
            ingested_at.to_rfc3339(),
        ],
    )
    .context("inserting install event")?;
    Ok(conn.last_insert_rowid())
}

fn list_blocking(conn: &Connection, filter: &ListFilter) -> Result<Vec<StoredEvent>> {
    let mut sql = String::from(
        "SELECT id, ecosystem, name, version,
                resolved_at_ms, execution_mode, project_path, user_agent,
                source, ingested_at_ms
           FROM installs
          WHERE 1=1",
    );
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(eco) = &filter.ecosystem {
        sql.push_str(" AND ecosystem = ?");
        binds.push(Box::new(eco.clone()));
    }
    if let Some(name) = &filter.name {
        sql.push_str(" AND name = ?");
        binds.push(Box::new(name.clone()));
    }
    if let Some(ver) = &filter.version {
        sql.push_str(" AND version = ?");
        binds.push(Box::new(ver.clone()));
    }
    if let Some(source) = filter.source {
        sql.push_str(" AND source = ?");
        binds.push(Box::new(source.as_str().to_string()));
    }
    if let Some(since) = filter.since {
        sql.push_str(" AND resolved_at_ms >= ?");
        binds.push(Box::new(since.timestamp_millis()));
    }
    sql.push_str(" ORDER BY resolved_at_ms DESC, id DESC");
    let limit = filter.limit.unwrap_or(1000).min(10_000);
    sql.push_str(" LIMIT ?");
    binds.push(Box::new(limit as i64));

    let bind_refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
    let mut stmt = conn.prepare(&sql).context("preparing list query")?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(bind_refs), row_to_event)
        .context("executing list query")?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.context("decoding install row")?);
    }
    Ok(out)
}

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEvent> {
    let resolved_ms: i64 = row.get(4)?;
    let exec_mode: String = row.get(5)?;
    let source: String = row.get(8)?;
    let ingested_ms: i64 = row.get(9)?;
    Ok(StoredEvent {
        id: row.get(0)?,
        ecosystem: row.get(1)?,
        name: row.get(2)?,
        version: row.get(3)?,
        resolved_at: ms_to_utc(resolved_ms).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(4, SqlType::Integer, e.into())
        })?,
        execution_mode: execution_mode_from_str(&exec_mode).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                SqlType::Text,
                format!("unknown execution_mode {exec_mode}").into(),
            )
        })?,
        project_path: row.get(6)?,
        user_agent: row.get(7)?,
        source: Source::parse(&source).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                8,
                SqlType::Text,
                format!("unknown source {source}").into(),
            )
        })?,
        ingested_at: ms_to_utc(ingested_ms).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(9, SqlType::Integer, e.into())
        })?,
    })
}

fn ms_to_utc(ms: i64) -> Result<DateTime<Utc>> {
    Utc.timestamp_millis_opt(ms)
        .single()
        .ok_or_else(|| anyhow::anyhow!("epoch ms {ms} out of range"))
}

fn execution_mode_to_str(m: ExecutionMode) -> &'static str {
    match m {
        ExecutionMode::Persistent => "persistent",
        ExecutionMode::Ephemeral => "ephemeral",
        ExecutionMode::Unknown => "unknown",
    }
}

fn execution_mode_from_str(s: &str) -> Option<ExecutionMode> {
    match s {
        "persistent" => Some(ExecutionMode::Persistent),
        "ephemeral" => Some(ExecutionMode::Ephemeral),
        "unknown" => Some(ExecutionMode::Unknown),
        _ => None,
    }
}

// ---------------- advisory / findings ----------------

use crate::advisories::{OsvAdvisory, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAdvisory {
    pub id: i64,
    pub osv_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_at: Option<DateTime<Utc>>,
    pub ingested_at: DateTime<Utc>,
    /// Number of `affected_versions` rows attached. Range-only
    /// advisories will be zero here — see `affected_ranges_count`
    /// for those.
    pub affected_count: i64,
    /// Number of `advisory_ranges` rows attached (SemVer ranges).
    /// A non-zero value means the advisory can still produce
    /// findings even when `affected_count` is zero.
    pub affected_ranges_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFinding {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub advisory: StoredAdvisory,
    pub install: StoredEvent,
}

#[derive(Debug, Default, Clone)]
pub struct FindingFilter {
    pub min_severity: Option<Severity>,
    pub source: Option<Source>,
    pub limit: Option<u32>,
}

/// Result of a scan pass — how much was JOINed and how many NEW
/// `(advisory, install)` pairs landed (existing pairs are
/// idempotent thanks to the `UNIQUE` constraint). `matching_mode`
/// is a stable string identifying *how* the JOIN was decided so
/// consumers don't mistake "no match" for "definitely not
/// vulnerable" — currently `"exact_versions_and_semver_ranges"`,
/// covering both `affected[].versions[]` literal matches and
/// SemVer 2.0 `affected[].ranges[]` (npm + crates only; PyPI's
/// PEP 440 and NuGet's variant are not yet evaluated).
///
/// ## Consistency model
///
/// `scan_findings` runs the entire `INSERT OR IGNORE ... SELECT
/// JOIN` plus its surrounding count snapshots inside one SQLite
/// transaction. Installs/advisories committed by other writers
/// *after* the transaction opens won't be visible to this scan
/// (they'll roll into the next one). `new_findings` therefore
/// counts rows this scan created, not rows that exist in the
/// table at wall-clock "now".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub installs_scanned: i64,
    pub advisories_considered: i64,
    pub new_findings: i64,
    pub total_findings: i64,
    pub matching_mode: &'static str,
}

impl Default for ScanReport {
    fn default() -> Self {
        Self {
            installs_scanned: 0,
            advisories_considered: 0,
            new_findings: 0,
            total_findings: 0,
            matching_mode: MATCHING_MODE,
        }
    }
}

/// Stable identifier for the JOIN strategy. Surfaced in scan
/// responses and `/healthz` so consumers can branch on what kind
/// of "no match" they're looking at.
pub const MATCHING_MODE: &str = "exact_versions_and_semver_ranges";

impl Store {
    /// Upsert an advisory by its OSV id, optionally with the
    /// literal incoming JSON bytes for audit/replay. When
    /// `raw_json` is `None`, the store falls back to re-serialising
    /// the parsed shape (which loses any fields outside the modelled
    /// subset). Returns `(id, is_new)`.
    pub async fn upsert_advisory(
        &self,
        adv: OsvAdvisory,
        raw_json: Option<serde_json::Value>,
    ) -> Result<(i64, bool)> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.blocking_lock();
            let tx = guard.transaction().context("opening advisory tx")?;
            let result = upsert_advisory_blocking(&tx, &adv, raw_json.as_ref())?;
            tx.commit().context("committing advisory tx")?;
            Ok(result)
        })
        .await
        .context("spawn_blocking upsert_advisory join")?
    }

    /// Bulk upsert. Each tuple is `(parsed_advisory, optional raw
    /// incoming JSON)`. All rows commit in one transaction. Returns
    /// `(created, refreshed)` counts.
    pub async fn upsert_advisories(
        &self,
        advs: Vec<(OsvAdvisory, Option<serde_json::Value>)>,
    ) -> Result<(usize, usize)> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.blocking_lock();
            let tx = guard.transaction().context("opening advisories tx")?;
            let mut created = 0;
            let mut refreshed = 0;
            for (adv, raw) in &advs {
                let (_, is_new) = upsert_advisory_blocking(&tx, adv, raw.as_ref())?;
                if is_new {
                    created += 1;
                } else {
                    refreshed += 1;
                }
            }
            tx.commit().context("committing advisories tx")?;
            Ok((created, refreshed))
        })
        .await
        .context("spawn_blocking upsert_advisories join")?
    }

    /// JOIN installs × advisory_affected on
    /// `(ecosystem, name, version)`. Inserts the matching pairs
    /// into `findings` with `INSERT OR IGNORE`, so re-running scan
    /// only adds the *new* matches that have appeared since last
    /// pass. Cheap to run repeatedly.
    pub async fn scan_findings(&self) -> Result<ScanReport> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.blocking_lock();
            let tx = guard.transaction().context("opening scan tx")?;
            let installs_scanned: i64 =
                tx.query_row("SELECT COUNT(*) FROM installs", [], |r| r.get(0))?;
            let advisories_considered: i64 =
                tx.query_row("SELECT COUNT(*) FROM advisories", [], |r| r.get(0))?;
            let before: i64 = tx.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))?;
            // Phase A: exact-version JOIN. `INSERT OR IGNORE`
            // keeps it idempotent against the `UNIQUE(advisory_id,
            // install_id)` constraint, so re-scans are cheap.
            let now_ms = Utc::now().timestamp_millis();
            tx.execute(
                "INSERT OR IGNORE INTO findings (advisory_id, install_id, created_at_ms)
                 SELECT aff.advisory_id, i.id, ?1
                   FROM installs i
                   JOIN advisory_affected aff
                     ON aff.ecosystem = i.ecosystem
                    AND aff.name      = i.name
                    AND aff.version   = i.version",
                params![now_ms],
            )
            .context("running exact-version JOIN insert")?;
            // Phase B: SemVer range JOIN. SQLite can't evaluate
            // semver comparisons natively, so we pull the (range,
            // install) candidates pre-filtered to matching
            // (ecosystem, name) and decide membership in Rust.
            // Bounded by the *index* on advisory_ranges so we
            // don't materialise the cartesian product.
            range_match_insert(&tx, now_ms)?;
            let after: i64 = tx.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))?;
            tx.commit().context("committing scan tx")?;
            Ok(ScanReport {
                installs_scanned,
                advisories_considered,
                new_findings: after - before,
                total_findings: after,
                matching_mode: MATCHING_MODE,
            })
        })
        .await
        .context("spawn_blocking scan_findings join")?
    }

    pub async fn list_advisories(&self, limit: Option<u32>) -> Result<Vec<StoredAdvisory>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let limit = limit.unwrap_or(1000).min(10_000) as i64;
            let mut stmt = guard
                .prepare(
                    "SELECT a.id, a.osv_id, a.summary, a.severity, a.published_at_ms,
                            a.ingested_at_ms,
                            (SELECT COUNT(*) FROM advisory_affected WHERE advisory_id = a.id),
                            (SELECT COUNT(*) FROM advisory_ranges   WHERE advisory_id = a.id)
                       FROM advisories a
                       ORDER BY a.ingested_at_ms DESC, a.id DESC
                       LIMIT ?1",
                )
                .context("preparing list_advisories")?;
            let rows = stmt
                .query_map(params![limit], row_to_advisory)
                .context("executing list_advisories")?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.context("decoding advisory row")?);
            }
            Ok(out)
        })
        .await
        .context("spawn_blocking list_advisories join")?
    }

    pub async fn list_findings(&self, filter: FindingFilter) -> Result<Vec<StoredFinding>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            list_findings_blocking(&guard, &filter)
        })
        .await
        .context("spawn_blocking list_findings join")?
    }
}

/// Field-length caps. Out of an abundance of caution we trim the
/// upper bound of any single advisory field to keep a single
/// malicious payload from amplifying into a multi-MB row. The
/// numbers are deliberately generous (the 1 MiB body limit is the
/// hard ceiling) but tight enough that an attacker can't stuff a
/// 900 KiB summary into one row.
const MAX_OSV_ID_LEN: usize = 256;
const MAX_ECOSYSTEM_LEN: usize = 64;
const MAX_NAME_LEN: usize = 256;
const MAX_VERSION_LEN: usize = 256;
const MAX_SUMMARY_LEN: usize = 8192;
const MAX_AFFECTED_ROWS: usize = 10_000;

/// Surface validation failures separately from storage errors so
/// the HTTP layer can map them to `400` instead of `500`.
#[derive(Debug, thiserror::Error)]
pub enum AdvisoryValidationError {
    #[error("advisory id is empty")]
    EmptyId,
    #[error("advisory id exceeds {MAX_OSV_ID_LEN} chars")]
    OsvIdTooLong,
    #[error("advisory summary exceeds {MAX_SUMMARY_LEN} chars")]
    SummaryTooLong,
    #[error("advisory has {0} affected versions (cap {MAX_AFFECTED_ROWS})")]
    TooManyAffected(usize),
    #[error("affected.ecosystem exceeds {MAX_ECOSYSTEM_LEN} chars")]
    EcosystemTooLong,
    #[error("affected.name length out of range (1..={MAX_NAME_LEN})")]
    NameOutOfRange,
    #[error("affected.version length out of range (1..={MAX_VERSION_LEN})")]
    VersionOutOfRange,
}

pub fn validate_advisory(adv: &OsvAdvisory) -> std::result::Result<(), AdvisoryValidationError> {
    validate_advisory_inner(adv)
}

fn validate_advisory_inner(adv: &OsvAdvisory) -> std::result::Result<(), AdvisoryValidationError> {
    if adv.id.is_empty() {
        return Err(AdvisoryValidationError::EmptyId);
    }
    if adv.id.len() > MAX_OSV_ID_LEN {
        return Err(AdvisoryValidationError::OsvIdTooLong);
    }
    if let Some(s) = &adv.summary
        && s.len() > MAX_SUMMARY_LEN
    {
        return Err(AdvisoryValidationError::SummaryTooLong);
    }
    let avs = adv.affected_versions();
    let ars = adv.affected_ranges();
    // Total = exact rows + range rows. A range-only advisory
    // that ships 50k bounded intervals would otherwise sneak past
    // the cap because it has zero exact `versions[]`.
    let total = avs.len().saturating_add(ars.len());
    if total > MAX_AFFECTED_ROWS {
        return Err(AdvisoryValidationError::TooManyAffected(total));
    }
    for av in &avs {
        if av.ecosystem.len() > MAX_ECOSYSTEM_LEN {
            return Err(AdvisoryValidationError::EcosystemTooLong);
        }
        if av.name.is_empty() || av.name.len() > MAX_NAME_LEN {
            return Err(AdvisoryValidationError::NameOutOfRange);
        }
        if av.version.is_empty() || av.version.len() > MAX_VERSION_LEN {
            return Err(AdvisoryValidationError::VersionOutOfRange);
        }
    }
    for ar in &ars {
        if ar.ecosystem.len() > MAX_ECOSYSTEM_LEN {
            return Err(AdvisoryValidationError::EcosystemTooLong);
        }
        if ar.name.is_empty() || ar.name.len() > MAX_NAME_LEN {
            return Err(AdvisoryValidationError::NameOutOfRange);
        }
    }
    Ok(())
}

/// App-side range matcher. Runs after the SQL exact-version JOIN
/// inside `scan_findings`. The flow is:
///
/// 1. Read every `(advisory_id, ecosystem, name, introduced,
///    fixed)` from `advisory_ranges` (one SQL pass, bounded by
///    the index lookup `(ecosystem, name)` on the install side).
/// 2. For each install whose `(ecosystem, name)` has at least one
///    range, parse the install version and test membership.
/// 3. Insert matches into `findings` via the same
///    `INSERT OR IGNORE` so the partial unique index keeps it
///    idempotent against the exact-version path.
///
/// Versions that fail to parse on either side are silently
/// skipped (logged at `trace`) — we'd rather under-detect than
/// fabricate a match.
fn range_match_insert(tx: &rusqlite::Transaction<'_>, now_ms: i64) -> Result<()> {
    // Pull only the (eco, name) pairs that any range targets, plus
    // the matching installs in one go. JOIN happens in SQL on the
    // cheap text-equality keys; the semver compare happens in
    // Rust on the small filtered set.
    let mut stmt = tx
        .prepare(
            "SELECT r.advisory_id, r.introduced, r.upper, r.upper_inclusive,
                    i.id, i.version
               FROM advisory_ranges r
               JOIN installs i
                 ON i.ecosystem = r.ecosystem
                AND i.name      = r.name",
        )
        .context("preparing range_match query")?;
    let mut rows = stmt.query([]).context("executing range_match query")?;
    // Re-use one prepared INSERT across all candidate rows.
    let mut ins = tx
        .prepare(
            "INSERT OR IGNORE INTO findings (advisory_id, install_id, created_at_ms)
             VALUES (?1, ?2, ?3)",
        )
        .context("preparing range_match insert")?;
    while let Some(row) = rows.next().context("walking range_match candidates")? {
        let advisory_id: i64 = row.get(0)?;
        let introduced_s: String = row.get(1)?;
        let upper_s: Option<String> = row.get(2)?;
        let upper_inclusive: i64 = row.get(3)?;
        let install_id: i64 = row.get(4)?;
        let version_s: String = row.get(5)?;
        if !version_in_range(
            &version_s,
            &introduced_s,
            upper_s.as_deref(),
            upper_inclusive != 0,
        ) {
            continue;
        }
        ins.execute(params![advisory_id, install_id, now_ms])
            .context("inserting range-match finding")?;
    }
    Ok(())
}

/// Shared membership predicate so the scan and the prune apply
/// the same inclusivity rules. Returns `false` when *anything*
/// fails to parse — that's the conservative "no match" stance the
/// matcher promises.
fn version_in_range(
    version: &str,
    introduced: &str,
    upper: Option<&str>,
    upper_inclusive: bool,
) -> bool {
    let Ok(v) = semver::Version::parse(version) else {
        return false;
    };
    let Ok(intro) = semver::Version::parse(introduced) else {
        return false;
    };
    if v < intro {
        return false;
    }
    if let Some(upper_s) = upper {
        let Ok(upper) = semver::Version::parse(upper_s) else {
            return false;
        };
        if upper_inclusive {
            if v > upper {
                return false;
            }
        } else if v >= upper {
            return false;
        }
    }
    true
}

fn upsert_advisory_blocking(
    tx: &rusqlite::Transaction<'_>,
    adv: &OsvAdvisory,
    raw_json: Option<&serde_json::Value>,
) -> Result<(i64, bool)> {
    // Defence in depth — the server pre-validates, but if a future
    // caller forgets, we still reject before touching disk.
    validate_advisory(adv).map_err(anyhow::Error::from)?;
    let severity = adv.severity().as_str();
    // Prefer the literal incoming bytes so future parser
    // improvements can re-derive fields (e.g. SEMVER range
    // matching) without re-fetching from OSV. Fall back to a
    // re-serialised projection when the caller didn't have the
    // original — documented in the public method as a lossy mode.
    let raw = match raw_json {
        Some(v) => serde_json::to_string(v).context("serialising raw advisory JSON")?,
        None => serde_json::to_string(&serde_advisory_for_storage(adv))
            .context("re-serialising advisory for storage")?,
    };
    let published_at_ms = adv.published.map(|d| d.timestamp_millis());
    let ingested_at_ms = Utc::now().timestamp_millis();
    let existing: Option<i64> = tx
        .query_row(
            "SELECT id FROM advisories WHERE osv_id = ?1",
            params![adv.id],
            |r| r.get(0),
        )
        .optional()
        .context("looking up existing advisory")?;
    let (id, is_new) = match existing {
        Some(id) => {
            tx.execute(
                "UPDATE advisories
                    SET summary = ?1,
                        severity = ?2,
                        published_at_ms = ?3,
                        raw_json = ?4,
                        ingested_at_ms = ?5
                  WHERE id = ?6",
                params![
                    adv.summary,
                    severity,
                    published_at_ms,
                    raw,
                    ingested_at_ms,
                    id
                ],
            )
            .context("updating advisory")?;
            // Replace affected rows + ranges: cheaper and clearer
            // than computing a diff, and the (advisory, eco, name,
            // ver) PK keeps it small.
            tx.execute(
                "DELETE FROM advisory_affected WHERE advisory_id = ?1",
                params![id],
            )
            .context("clearing prior affected rows")?;
            tx.execute(
                "DELETE FROM advisory_ranges WHERE advisory_id = ?1",
                params![id],
            )
            .context("clearing prior advisory ranges")?;
            (id, false)
        }
        None => {
            tx.execute(
                "INSERT INTO advisories
                    (osv_id, summary, severity, published_at_ms, raw_json, ingested_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    adv.id,
                    adv.summary,
                    severity,
                    published_at_ms,
                    raw,
                    ingested_at_ms
                ],
            )
            .context("inserting advisory")?;
            (tx.last_insert_rowid(), true)
        }
    };
    {
        let mut stmt = tx
            .prepare(
                "INSERT OR IGNORE INTO advisory_affected
                    (advisory_id, ecosystem, name, version)
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .context("preparing affected insert")?;
        for av in adv.affected_versions() {
            stmt.execute(params![id, av.ecosystem, av.name, av.version])
                .context("inserting affected row")?;
        }
    }
    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO advisory_ranges
                    (advisory_id, ecosystem, name, introduced, upper, upper_inclusive)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .context("preparing range insert")?;
        for r in adv.affected_ranges() {
            stmt.execute(params![
                id,
                r.ecosystem,
                r.name,
                r.introduced.to_string(),
                r.upper.as_ref().map(|v| v.to_string()),
                if r.upper_inclusive { 1 } else { 0 },
            ])
            .context("inserting advisory range row")?;
        }
    }
    // Prune stale findings: for this advisory, drop any finding
    // whose install no longer matches under the *refreshed*
    // affected set (exact-version OR semver range). This keeps
    // `findings` honest about "what would the current rules say?"
    // when a publisher narrows their advisory. Notification
    // history (whether we already *delivered* a finding) lives
    // in `dispatch_attempts` and is protected by the
    // `UNIQUE WHERE success=1` index, so pruning here does not
    // re-fire alerts that already went out.
    prune_stale_findings_for_advisory(tx, id)?;
    Ok((id, is_new))
}

/// Walk every finding currently attached to `advisory_id`; drop
/// the ones whose install doesn't satisfy the refreshed
/// affected/range set. Done in Rust rather than pure SQL because
/// the range check needs `semver::Version` comparison.
fn prune_stale_findings_for_advisory(
    tx: &rusqlite::Transaction<'_>,
    advisory_id: i64,
) -> Result<()> {
    // Read current ranges into memory once.
    let mut range_stmt = tx
        .prepare(
            "SELECT ecosystem, name, introduced, upper, upper_inclusive
               FROM advisory_ranges
              WHERE advisory_id = ?1",
        )
        .context("preparing prune range read")?;
    let ranges: Vec<(String, String, String, Option<String>, i64)> = range_stmt
        .query_map(params![advisory_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .context("executing prune range read")?
        .collect::<rusqlite::Result<_>>()
        .context("decoding prune range rows")?;
    // Walk findings + their installs.
    let mut fstmt = tx
        .prepare(
            "SELECT f.id, i.ecosystem, i.name, i.version
               FROM findings f
               JOIN installs i ON i.id = f.install_id
              WHERE f.advisory_id = ?1",
        )
        .context("preparing prune findings read")?;
    let findings: Vec<(i64, String, String, String)> = fstmt
        .query_map(params![advisory_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .context("executing prune findings read")?
        .collect::<rusqlite::Result<_>>()
        .context("decoding prune findings rows")?;
    let mut del = tx
        .prepare("DELETE FROM findings WHERE id = ?1")
        .context("preparing prune findings delete")?;
    for (fid, eco, name, version) in findings {
        // Exact-version match?
        let exact: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM advisory_affected
                  WHERE advisory_id = ?1
                    AND ecosystem  = ?2
                    AND name       = ?3
                    AND version    = ?4",
                params![advisory_id, eco, name, version],
                |r| r.get(0),
            )
            .context("counting exact match in prune")?;
        if exact > 0 {
            continue;
        }
        // Range match? Reuse the same inclusivity-aware predicate
        // as scan_findings so prune and scan can never disagree.
        let in_range = ranges
            .iter()
            .filter(|(e, n, _, _, _)| e == &eco && n == &name)
            .any(|(_, _, intro_s, upper_s, upper_inclusive)| {
                version_in_range(&version, intro_s, upper_s.as_deref(), *upper_inclusive != 0)
            });
        if !in_range {
            del.execute(params![fid])
                .context("deleting stale finding")?;
        }
    }
    Ok(())
}

/// Lossy fallback used **only** when `upsert_advisory` is called
/// without the original incoming JSON value. Re-shapes the parsed
/// `OsvAdvisory` into a JSON projection covering just the modelled
/// fields. The HTTP `POST /advisories` handler always supplies the
/// original `serde_json::Value` so unmodelled OSV fields survive
/// the round-trip; this helper is only reached by callers that
/// genuinely don't have the source bytes (e.g. tests, future
/// internal sync paths).
fn serde_advisory_for_storage(adv: &OsvAdvisory) -> serde_json::Value {
    serde_json::json!({
        "id": adv.id,
        "summary": adv.summary,
        "published": adv.published,
        "severity": adv.severity().as_str(),
        "affected_versions": adv.affected_versions().iter().map(|v| {
            serde_json::json!({"ecosystem": v.ecosystem, "name": v.name, "version": v.version})
        }).collect::<Vec<_>>(),
        "affected_ranges": adv.affected_ranges().iter().map(|r| {
            serde_json::json!({
                "ecosystem": r.ecosystem,
                "name": r.name,
                "introduced": r.introduced.to_string(),
                "upper": r.upper.as_ref().map(|v| v.to_string()),
                "upper_inclusive": r.upper_inclusive,
            })
        }).collect::<Vec<_>>(),
    })
}

fn row_to_advisory(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAdvisory> {
    let severity: String = row.get(3)?;
    let published_at_ms: Option<i64> = row.get(4)?;
    let ingested_at_ms: i64 = row.get(5)?;
    let affected_count: i64 = row.get(6)?;
    let affected_ranges_count: i64 = row.get(7)?;
    Ok(StoredAdvisory {
        id: row.get(0)?,
        osv_id: row.get(1)?,
        summary: row.get(2)?,
        severity: Severity::parse(&severity).unwrap_or(Severity::Unknown),
        published_at: match published_at_ms {
            Some(ms) => Some(ms_to_utc(ms).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(4, SqlType::Integer, e.into())
            })?),
            None => None,
        },
        ingested_at: ms_to_utc(ingested_at_ms).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, SqlType::Integer, e.into())
        })?,
        affected_count,
        affected_ranges_count,
    })
}

fn list_findings_blocking(conn: &Connection, filter: &FindingFilter) -> Result<Vec<StoredFinding>> {
    let limit = filter.limit.unwrap_or(1000).min(10_000) as i64;
    let mut sql = String::from(
        "SELECT f.id, f.created_at_ms,
                a.id, a.osv_id, a.summary, a.severity, a.published_at_ms, a.ingested_at_ms,
                (SELECT COUNT(*) FROM advisory_affected WHERE advisory_id = a.id),
                (SELECT COUNT(*) FROM advisory_ranges   WHERE advisory_id = a.id),
                i.id, i.ecosystem, i.name, i.version, i.resolved_at_ms, i.execution_mode,
                i.project_path, i.user_agent, i.source, i.ingested_at_ms
           FROM findings f
           JOIN advisories a ON a.id = f.advisory_id
           JOIN installs   i ON i.id = f.install_id
          WHERE 1=1",
    );
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(source) = filter.source {
        sql.push_str(" AND i.source = ?");
        binds.push(Box::new(source.as_str().to_string()));
    }
    // Push severity filtering into SQL so it applies *before* the
    // ORDER BY/LIMIT — a Rust-side filter would skip older
    // high-severity findings whenever they sat behind a page of
    // newer low-severity rows.
    if let Some(min) = filter.min_severity {
        sql.push_str(
            " AND (CASE a.severity \
                       WHEN 'critical' THEN 4 \
                       WHEN 'high'     THEN 3 \
                       WHEN 'moderate' THEN 2 \
                       WHEN 'low'      THEN 1 \
                       ELSE 0 END) >= ?",
        );
        binds.push(Box::new(severity_rank(min) as i64));
    }
    sql.push_str(" ORDER BY f.created_at_ms DESC, f.id DESC LIMIT ?");
    binds.push(Box::new(limit));
    let bind_refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
    let mut stmt = conn.prepare(&sql).context("preparing list_findings")?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(bind_refs), |row| {
            let created_at_ms: i64 = row.get(1)?;
            let adv_severity: String = row.get(5)?;
            let adv_published: Option<i64> = row.get(6)?;
            let adv_ingested: i64 = row.get(7)?;
            let install = StoredEvent {
                id: row.get(10)?,
                ecosystem: row.get(11)?,
                name: row.get(12)?,
                version: row.get(13)?,
                resolved_at: ms_to_utc(row.get::<_, i64>(14)?).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(14, SqlType::Integer, e.into())
                })?,
                execution_mode: execution_mode_from_str(&row.get::<_, String>(15)?).ok_or_else(
                    || {
                        rusqlite::Error::FromSqlConversionFailure(
                            15,
                            SqlType::Text,
                            "unknown execution_mode".into(),
                        )
                    },
                )?,
                project_path: row.get(16)?,
                user_agent: row.get(17)?,
                source: Source::parse(&row.get::<_, String>(18)?).ok_or_else(|| {
                    rusqlite::Error::FromSqlConversionFailure(
                        18,
                        SqlType::Text,
                        "unknown source".into(),
                    )
                })?,
                ingested_at: ms_to_utc(row.get::<_, i64>(19)?).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(19, SqlType::Integer, e.into())
                })?,
            };
            let affected_count: i64 = row.get(8)?;
            let affected_ranges_count: i64 = row.get(9)?;
            Ok(StoredFinding {
                id: row.get(0)?,
                created_at: ms_to_utc(created_at_ms).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(1, SqlType::Integer, e.into())
                })?,
                advisory: StoredAdvisory {
                    id: row.get(2)?,
                    osv_id: row.get(3)?,
                    summary: row.get(4)?,
                    severity: Severity::parse(&adv_severity).unwrap_or(Severity::Unknown),
                    published_at: match adv_published {
                        Some(ms) => Some(ms_to_utc(ms).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(6, SqlType::Integer, e.into())
                        })?),
                        None => None,
                    },
                    ingested_at: ms_to_utc(adv_ingested).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(7, SqlType::Integer, e.into())
                    })?,
                    affected_count,
                    affected_ranges_count,
                },
                install,
            })
        })
        .context("executing list_findings")?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.context("decoding finding row")?);
    }
    Ok(out)
}

fn severity_rank(s: Severity) -> i32 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Moderate => 2,
        Severity::Low => 1,
        Severity::Unknown => 0,
    }
}

// ---------------- dispatch targets / pending deliveries ----------------

/// Operator-supplied target spec for registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSpec {
    pub label: String,
    pub url: String,
    pub secret: String,
    pub min_severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_filter: Option<Source>,
}

/// Stored target as returned by `list_targets`. We deliberately
/// *redact* the secret on read so a leaked DB dump and a leaked
/// `/dispatch-targets` response don't expose the same field —
/// operators looking it up should fetch from the DB directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTarget {
    pub id: i64,
    pub label: String,
    pub url: String,
    pub min_severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_filter: Option<Source>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

/// Flat projection of a `(finding, advisory, install, target)`
/// JOIN that the dispatcher needs to construct a payload without
/// re-querying. Keeps the dispatcher I/O bounded to one SELECT
/// per `run_once` regardless of batch size.
#[derive(Debug, Clone)]
pub struct PendingDelivery {
    pub finding_id: i64,
    pub finding_created_at: DateTime<Utc>,
    pub target_id: i64,
    pub target_label: String,
    pub target_url: String,
    pub target_secret: String,
    pub advisory_osv_id: String,
    pub advisory_severity: Severity,
    pub advisory_summary: Option<String>,
    pub advisory_published_at: Option<DateTime<Utc>>,
    pub install_ecosystem: String,
    pub install_name: String,
    pub install_version: String,
    pub install_source: Source,
    pub install_project_path: Option<String>,
    pub install_resolved_at: DateTime<Utc>,
}

impl Store {
    pub async fn register_target(&self, spec: TargetSpec) -> Result<i64> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO dispatch_targets
                        (label, url, secret, min_severity, source_filter, enabled, created_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)",
                    params![
                        spec.label,
                        spec.url,
                        spec.secret,
                        spec.min_severity.as_str(),
                        spec.source_filter.map(|s| s.as_str().to_string()),
                        Utc::now().timestamp_millis(),
                    ],
                )
                .context("inserting dispatch target")?;
            Ok(guard.last_insert_rowid())
        })
        .await
        .context("spawn_blocking register_target join")?
    }

    pub async fn list_targets(&self) -> Result<Vec<StoredTarget>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(
                    "SELECT id, label, url, min_severity, source_filter, enabled, created_at_ms
                       FROM dispatch_targets
                      WHERE deleted_at_ms IS NULL
                       ORDER BY id ASC",
                )
                .context("preparing list_targets")?;
            let rows = stmt
                .query_map([], |row| {
                    let sev: String = row.get(3)?;
                    let src: Option<String> = row.get(4)?;
                    let enabled: i64 = row.get(5)?;
                    let created_at_ms: i64 = row.get(6)?;
                    Ok(StoredTarget {
                        id: row.get(0)?,
                        label: row.get(1)?,
                        url: row.get(2)?,
                        min_severity: Severity::parse(&sev).unwrap_or(Severity::Unknown),
                        source_filter: src.and_then(|s| Source::parse(&s)),
                        enabled: enabled != 0,
                        created_at: ms_to_utc(created_at_ms).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(6, SqlType::Integer, e.into())
                        })?,
                    })
                })
                .context("executing list_targets")?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.context("decoding target row")?);
            }
            Ok(out)
        })
        .await
        .context("spawn_blocking list_targets join")?
    }

    /// Soft-delete: stamps `deleted_at_ms`, the target stops
    /// appearing in `list_targets` and `pending_deliveries`, but
    /// its `dispatch_attempts` rows survive for audit/forensics
    /// (with a foreign-key still pointing at the now-hidden row).
    /// Returns true if any active target with this id existed.
    pub async fn delete_target(&self, id: i64) -> Result<bool> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let n = guard
                .execute(
                    "UPDATE dispatch_targets
                        SET deleted_at_ms = ?1
                      WHERE id = ?2 AND deleted_at_ms IS NULL",
                    params![Utc::now().timestamp_millis(), id],
                )
                .context("soft-deleting target")?;
            Ok(n > 0)
        })
        .await
        .context("spawn_blocking delete_target join")?
    }

    /// Up to `batch` pending `(finding, target)` deliveries:
    /// targets are enabled (and not soft-deleted), the advisory's
    /// severity rank meets the target's `min_severity`, the
    /// install's source matches the target's `source_filter` (or
    /// that filter is unset), no successful attempt exists yet,
    /// and the attempt count is below `attempt_cap`. Oldest
    /// findings first. The companion count of `(finding, target)`
    /// pairs that *would* have qualified except for hitting the
    /// attempt cap is returned alongside, computed inside the
    /// same connection-lock critical section so the two numbers
    /// agree.
    pub async fn pending_deliveries_with_stats(
        &self,
        batch: u32,
        attempt_cap: i64,
    ) -> Result<(Vec<PendingDelivery>, i64)> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let pending = pending_deliveries_blocking(&guard, batch, attempt_cap)?;
            let over_cap: i64 = guard
                .query_row(
                    "SELECT COUNT(*) FROM (
                       SELECT 1
                         FROM findings f
                         JOIN advisories     a ON a.id = f.advisory_id
                         JOIN installs       i ON i.id = f.install_id
                         CROSS JOIN dispatch_targets t
                        WHERE t.enabled = 1
                          AND t.deleted_at_ms IS NULL
                          AND (CASE a.severity
                                    WHEN 'critical' THEN 4
                                    WHEN 'high'     THEN 3
                                    WHEN 'moderate' THEN 2
                                    WHEN 'low'      THEN 1
                                    ELSE 0 END)
                              >=
                              (CASE t.min_severity
                                    WHEN 'critical' THEN 4
                                    WHEN 'high'     THEN 3
                                    WHEN 'moderate' THEN 2
                                    WHEN 'low'      THEN 1
                                    ELSE 0 END)
                          AND (t.source_filter IS NULL OR t.source_filter = i.source)
                          AND NOT EXISTS (
                                SELECT 1 FROM dispatch_attempts da
                                 WHERE da.finding_id = f.id
                                   AND da.target_id  = t.id
                                   AND da.success    = 1
                              )
                          AND (
                                SELECT COUNT(*) FROM dispatch_attempts da2
                                 WHERE da2.finding_id = f.id
                                   AND da2.target_id  = t.id
                              ) >= ?1
                     )",
                    params![attempt_cap],
                    |r| r.get(0),
                )
                .context("counting over-cap pairs")?;
            Ok((pending, over_cap))
        })
        .await
        .context("spawn_blocking pending_deliveries_with_stats join")?
    }

    pub async fn pending_deliveries(
        &self,
        batch: u32,
        attempt_cap: i64,
    ) -> Result<Vec<PendingDelivery>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            pending_deliveries_blocking(&guard, batch, attempt_cap)
        })
        .await
        .context("spawn_blocking pending_deliveries join")?
    }
}

fn pending_deliveries_blocking(
    conn: &Connection,
    batch: u32,
    attempt_cap: i64,
) -> Result<Vec<PendingDelivery>> {
    let limit = batch.min(10_000) as i64;
    let mut stmt = conn
        .prepare(
            "SELECT f.id, f.created_at_ms,
                            t.id, t.label, t.url, t.secret,
                            a.osv_id, a.severity, a.summary, a.published_at_ms,
                            i.ecosystem, i.name, i.version, i.source, i.project_path,
                            i.resolved_at_ms
                       FROM findings f
                       JOIN advisories     a ON a.id = f.advisory_id
                       JOIN installs       i ON i.id = f.install_id
                       CROSS JOIN dispatch_targets t
                      WHERE t.enabled = 1
                        AND t.deleted_at_ms IS NULL
                        AND (CASE a.severity
                                  WHEN 'critical' THEN 4
                                  WHEN 'high'     THEN 3
                                  WHEN 'moderate' THEN 2
                                  WHEN 'low'      THEN 1
                                  ELSE 0 END)
                            >=
                            (CASE t.min_severity
                                  WHEN 'critical' THEN 4
                                  WHEN 'high'     THEN 3
                                  WHEN 'moderate' THEN 2
                                  WHEN 'low'      THEN 1
                                  ELSE 0 END)
                        AND (t.source_filter IS NULL OR t.source_filter = i.source)
                        AND NOT EXISTS (
                              SELECT 1 FROM dispatch_attempts da
                               WHERE da.finding_id = f.id
                                 AND da.target_id  = t.id
                                 AND da.success    = 1
                            )
                        AND (
                              SELECT COUNT(*) FROM dispatch_attempts da2
                               WHERE da2.finding_id = f.id
                                 AND da2.target_id  = t.id
                            ) < ?1
                      ORDER BY f.created_at_ms ASC, f.id ASC, t.id ASC
                      LIMIT ?2",
        )
        .context("preparing pending_deliveries")?;
    let rows = stmt
        .query_map(params![attempt_cap, limit], |row| {
            let sev: String = row.get(7)?;
            let pub_ms: Option<i64> = row.get(9)?;
            let src: String = row.get(13)?;
            Ok(PendingDelivery {
                finding_id: row.get(0)?,
                finding_created_at: ms_to_utc(row.get::<_, i64>(1)?).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(1, SqlType::Integer, e.into())
                })?,
                target_id: row.get(2)?,
                target_label: row.get(3)?,
                target_url: row.get(4)?,
                target_secret: row.get(5)?,
                advisory_osv_id: row.get(6)?,
                advisory_severity: Severity::parse(&sev).unwrap_or(Severity::Unknown),
                advisory_summary: row.get(8)?,
                advisory_published_at: match pub_ms {
                    Some(ms) => Some(ms_to_utc(ms).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(9, SqlType::Integer, e.into())
                    })?),
                    None => None,
                },
                install_ecosystem: row.get(10)?,
                install_name: row.get(11)?,
                install_version: row.get(12)?,
                install_source: Source::parse(&src).ok_or_else(|| {
                    rusqlite::Error::FromSqlConversionFailure(
                        13,
                        SqlType::Text,
                        "unknown source".into(),
                    )
                })?,
                install_project_path: row.get(14)?,
                install_resolved_at: ms_to_utc(row.get::<_, i64>(15)?).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(15, SqlType::Integer, e.into())
                })?,
            })
        })
        .context("executing pending_deliveries")?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.context("decoding pending row")?);
    }
    Ok(out)
}

impl Store {
    pub async fn record_attempt(
        &self,
        finding_id: i64,
        target_id: i64,
        success: bool,
        http_status: Option<i64>,
        error: Option<String>,
    ) -> Result<()> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO dispatch_attempts
                        (finding_id, target_id, attempt_at_ms, success, http_status, error)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        finding_id,
                        target_id,
                        Utc::now().timestamp_millis(),
                        if success { 1 } else { 0 },
                        http_status,
                        error,
                    ],
                )
                .context("inserting dispatch attempt")?;
            Ok(())
        })
        .await
        .context("spawn_blocking record_attempt join")?
    }

    /// Set / clear the enabled flag on a target. Returns whether
    /// any row was affected.
    pub async fn set_target_enabled(&self, id: i64, enabled: bool) -> Result<bool> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let n = guard
                .execute(
                    "UPDATE dispatch_targets
                        SET enabled = ?1
                      WHERE id = ?2 AND deleted_at_ms IS NULL",
                    params![if enabled { 1 } else { 0 }, id],
                )
                .context("updating target enabled flag")?;
            Ok(n > 0)
        })
        .await
        .context("spawn_blocking set_target_enabled join")?
    }
}

// ---------------- users + sessions ----------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub id: i64,
    pub github_user_id: i64,
    pub github_login: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_login_at: DateTime<Utc>,
}

/// Profile fields the OAuth callback hands the store. Kept
/// separate from `StoredUser` so callers can't accidentally pass
/// a `created_at` from the GitHub side (we always stamp our own).
#[derive(Debug, Clone)]
pub struct UpsertUserSpec {
    pub github_user_id: i64,
    pub github_login: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

impl Store {
    /// Insert-or-update on `github_user_id`. Returns the row id;
    /// updates `last_login_at_ms` on every call so a subsequent
    /// `last_login_at` lookup is meaningful.
    pub async fn upsert_user(&self, spec: UpsertUserSpec) -> Result<i64> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let now = Utc::now().timestamp_millis();
            guard
                .execute(
                    "INSERT INTO users
                        (github_user_id, github_login, display_name, avatar_url,
                         created_at_ms, last_login_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                     ON CONFLICT(github_user_id) DO UPDATE SET
                         github_login   = excluded.github_login,
                         display_name   = excluded.display_name,
                         avatar_url     = excluded.avatar_url,
                         last_login_at_ms = excluded.last_login_at_ms",
                    params![
                        spec.github_user_id,
                        spec.github_login,
                        spec.display_name,
                        spec.avatar_url,
                        now,
                    ],
                )
                .context("upsert user")?;
            let id: i64 = guard
                .query_row(
                    "SELECT id FROM users WHERE github_user_id = ?1",
                    params![spec.github_user_id],
                    |r| r.get(0),
                )
                .context("looking up upserted user")?;
            Ok(id)
        })
        .await
        .context("spawn_blocking upsert_user join")?
    }

    pub async fn create_session(
        &self,
        user_id: i64,
        token_hash: [u8; 32],
        ttl_secs: i64,
        user_agent: Option<String>,
    ) -> Result<i64> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let now = Utc::now().timestamp_millis();
            let expires = now + ttl_secs * 1000;
            guard
                .execute(
                    "INSERT INTO sessions
                        (token_hash, user_id, created_at_ms, expires_at_ms, user_agent)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![token_hash.as_slice(), user_id, now, expires, user_agent],
                )
                .context("inserting session")?;
            Ok(guard.last_insert_rowid())
        })
        .await
        .context("spawn_blocking create_session join")?
    }

    /// Resolve a session by token hash. Returns `Some(user)` iff
    /// the session exists, isn't revoked, and hasn't expired. We
    /// re-shape the query so a single round-trip joins users to
    /// avoid a separate `find_user` call from every middleware
    /// invocation.
    pub async fn session_user(&self, token_hash: [u8; 32]) -> Result<Option<StoredUser>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let now = Utc::now().timestamp_millis();
            let row = guard
                .query_row(
                    "SELECT u.id, u.github_user_id, u.github_login, u.display_name,
                            u.avatar_url, u.created_at_ms, u.last_login_at_ms
                       FROM sessions s
                       JOIN users    u ON u.id = s.user_id
                      WHERE s.token_hash = ?1
                        AND s.revoked_at_ms IS NULL
                        AND s.expires_at_ms > ?2",
                    params![token_hash.as_slice(), now],
                    |row| {
                        let created_ms: i64 = row.get(5)?;
                        let last_ms: i64 = row.get(6)?;
                        Ok(StoredUser {
                            id: row.get(0)?,
                            github_user_id: row.get(1)?,
                            github_login: row.get(2)?,
                            display_name: row.get(3)?,
                            avatar_url: row.get(4)?,
                            created_at: ms_to_utc(created_ms).map_err(|e| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    5,
                                    SqlType::Integer,
                                    e.into(),
                                )
                            })?,
                            last_login_at: ms_to_utc(last_ms).map_err(|e| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    6,
                                    SqlType::Integer,
                                    e.into(),
                                )
                            })?,
                        })
                    },
                )
                .optional()
                .context("session_user query")?;
            Ok(row)
        })
        .await
        .context("spawn_blocking session_user join")?
    }

    pub async fn revoke_session(&self, token_hash: [u8; 32]) -> Result<bool> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let n = guard
                .execute(
                    "UPDATE sessions
                        SET revoked_at_ms = ?1
                      WHERE token_hash = ?2 AND revoked_at_ms IS NULL",
                    params![Utc::now().timestamp_millis(), token_hash.as_slice()],
                )
                .context("revoking session")?;
            Ok(n > 0)
        })
        .await
        .context("spawn_blocking revoke_session join")?
    }
}

// ---------------- personal api tokens ----------------

/// Returned by [`Store::list_api_tokens`] / hand-back of
/// [`Store::create_api_token`]. The cleartext token is NEVER on
/// this struct — `create_api_token` returns it separately and the
/// caller must show it to the user immediately because the
/// server never sees it again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredApiToken {
    pub id: i64,
    pub user_id: i64,
    /// Human-readable first 12 chars of the cleartext token
    /// (always starts `shp_`). Safe to show in any list UI.
    pub prefix: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// All-prefix marker for personal tokens. The middleware fast-
/// fails any bearer value that doesn't start with `shp_` so the
/// hash lookup never touches attacker-controlled prefixes that
/// would otherwise force a DB round-trip per noise request.
pub const API_TOKEN_PREFIX: &str = "shp_";
const API_TOKEN_BYTES: usize = 32;
/// Length of the public-safe prefix recorded for the list UI
/// (`shp_` + 8 chars of the base64url body). Long enough to be
/// distinguishable in a list view, short enough to leak negligible
/// entropy.
const API_TOKEN_PREFIX_DISPLAY_LEN: usize = 12;

/// One-shot newly-minted token. `cleartext` is what we show the
/// user once; `record` is what's persisted.
#[derive(Debug)]
pub struct MintedApiToken {
    pub cleartext: String,
    pub record: StoredApiToken,
}

impl Store {
    /// Mint and persist a fresh personal API token. The cleartext
    /// returned here is the only chance to capture it; the DB
    /// only stores its SHA-256 hash.
    pub async fn create_api_token(
        &self,
        user_id: i64,
        label: String,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<MintedApiToken> {
        if label.is_empty() {
            anyhow::bail!("api token label is empty");
        }
        if label.len() > 128 {
            anyhow::bail!("api token label exceeds 128 chars");
        }
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            use base64::Engine;
            use rand::RngCore;
            let mut raw = [0u8; API_TOKEN_BYTES];
            rand::thread_rng().fill_bytes(&mut raw);
            let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
            let cleartext = format!("{API_TOKEN_PREFIX}{body}");
            let prefix = cleartext
                .chars()
                .take(API_TOKEN_PREFIX_DISPLAY_LEN)
                .collect::<String>();
            let mut h = sha2::Sha256::new();
            h.update(cleartext.as_bytes());
            let hash: [u8; 32] = h.finalize().into();
            let now = Utc::now().timestamp_millis();
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO api_tokens
                        (user_id, token_hash, prefix, label,
                         created_at_ms, last_used_at_ms,
                         expires_at_ms, revoked_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, NULL)",
                    params![
                        user_id,
                        hash.as_slice(),
                        prefix,
                        label,
                        now,
                        expires_at.map(|d| d.timestamp_millis()),
                    ],
                )
                .context("inserting api token")?;
            let id = guard.last_insert_rowid();
            Ok(MintedApiToken {
                cleartext,
                record: StoredApiToken {
                    id,
                    user_id,
                    prefix,
                    label,
                    created_at: ms_to_utc(now)?,
                    last_used_at: None,
                    expires_at,
                    revoked_at: None,
                },
            })
        })
        .await
        .context("spawn_blocking create_api_token join")?
    }

    pub async fn list_api_tokens(&self, user_id: i64) -> Result<Vec<StoredApiToken>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(
                    "SELECT id, user_id, prefix, label, created_at_ms,
                            last_used_at_ms, expires_at_ms, revoked_at_ms
                       FROM api_tokens
                      WHERE user_id = ?1
                      ORDER BY created_at_ms DESC, id DESC",
                )
                .context("preparing list_api_tokens")?;
            let rows = stmt
                .query_map(params![user_id], row_to_api_token)
                .context("executing list_api_tokens")?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.context("decoding api token row")?);
            }
            Ok(out)
        })
        .await
        .context("spawn_blocking list_api_tokens join")?
    }

    /// Soft-revoke by id, scoped to the calling user so one user
    /// can't yank another user's tokens. Returns true iff an
    /// active row matching both `(id, user_id)` was revoked.
    pub async fn revoke_api_token(&self, id: i64, user_id: i64) -> Result<bool> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let n = guard
                .execute(
                    "UPDATE api_tokens
                        SET revoked_at_ms = ?1
                      WHERE id = ?2 AND user_id = ?3 AND revoked_at_ms IS NULL",
                    params![Utc::now().timestamp_millis(), id, user_id],
                )
                .context("revoking api token")?;
            Ok(n > 0)
        })
        .await
        .context("spawn_blocking revoke_api_token join")?
    }

    /// Look up the user behind a presented token hash. Returns
    /// `Some((user, token_id))` iff a matching row exists and is
    /// not revoked / not expired. The token_id is used by the
    /// caller to async-update `last_used_at_ms`.
    pub async fn api_token_user(&self, token_hash: [u8; 32]) -> Result<Option<(StoredUser, i64)>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let now = Utc::now().timestamp_millis();
            let row = guard
                .query_row(
                    "SELECT u.id, u.github_user_id, u.github_login, u.display_name,
                            u.avatar_url, u.created_at_ms, u.last_login_at_ms,
                            t.id
                       FROM api_tokens t
                       JOIN users      u ON u.id = t.user_id
                      WHERE t.token_hash    = ?1
                        AND t.revoked_at_ms IS NULL
                        AND (t.expires_at_ms IS NULL OR t.expires_at_ms > ?2)",
                    params![token_hash.as_slice(), now],
                    |row| {
                        let created_ms: i64 = row.get(5)?;
                        let last_ms: i64 = row.get(6)?;
                        let token_id: i64 = row.get(7)?;
                        Ok((
                            StoredUser {
                                id: row.get(0)?,
                                github_user_id: row.get(1)?,
                                github_login: row.get(2)?,
                                display_name: row.get(3)?,
                                avatar_url: row.get(4)?,
                                created_at: ms_to_utc(created_ms).map_err(|e| {
                                    rusqlite::Error::FromSqlConversionFailure(
                                        5,
                                        SqlType::Integer,
                                        e.into(),
                                    )
                                })?,
                                last_login_at: ms_to_utc(last_ms).map_err(|e| {
                                    rusqlite::Error::FromSqlConversionFailure(
                                        6,
                                        SqlType::Integer,
                                        e.into(),
                                    )
                                })?,
                            },
                            token_id,
                        ))
                    },
                )
                .optional()
                .context("api_token_user query")?;
            Ok(row)
        })
        .await
        .context("spawn_blocking api_token_user join")?
    }

    /// Best-effort `last_used_at` bump. Fire-and-forget — the
    /// caller spawns this and does NOT await for the request
    /// path, so a slow DB write can't add latency. Errors are
    /// `log::warn!`'d.
    pub async fn touch_api_token(&self, token_id: i64) -> Result<()> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "UPDATE api_tokens SET last_used_at_ms = ?1 WHERE id = ?2",
                    params![Utc::now().timestamp_millis(), token_id],
                )
                .context("touching api token")?;
            Ok(())
        })
        .await
        .context("spawn_blocking touch_api_token join")?
    }
}

fn row_to_api_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredApiToken> {
    let created_ms: i64 = row.get(4)?;
    let last_ms: Option<i64> = row.get(5)?;
    let exp_ms: Option<i64> = row.get(6)?;
    let rev_ms: Option<i64> = row.get(7)?;
    Ok(StoredApiToken {
        id: row.get(0)?,
        user_id: row.get(1)?,
        prefix: row.get(2)?,
        label: row.get(3)?,
        created_at: ms_to_utc(created_ms).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(4, SqlType::Integer, e.into())
        })?,
        last_used_at: last_ms
            .map(|m| {
                ms_to_utc(m).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(5, SqlType::Integer, e.into())
                })
            })
            .transpose()?,
        expires_at: exp_ms
            .map(|m| {
                ms_to_utc(m).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(6, SqlType::Integer, e.into())
                })
            })
            .transpose()?,
        revoked_at: rev_ms
            .map(|m| {
                ms_to_utc(m).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(7, SqlType::Integer, e.into())
                })
            })
            .transpose()?,
    })
}

/// Hash a presented cleartext API token. Caller is responsible
/// for first verifying the [`API_TOKEN_PREFIX`] before calling
/// this — passing arbitrary attacker bytes through SHA-256 and
/// then through the DB still works correctly, but the
/// fast-fail prefix check keeps `noise` traffic out of the DB.
pub fn hash_api_token(cleartext: &str) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(cleartext.as_bytes());
    h.finalize().into()
}

// ---------------- actions tokens ----------------

/// Bearer-namespace marker for tokens minted via the GitHub
/// Actions OIDC exchange. Distinguishable from `shp_` (per-user
/// personal tokens) at the middleware's fast-fail step.
pub const ACTIONS_TOKEN_PREFIX: &str = "sha_";
const ACTIONS_TOKEN_BYTES: usize = 32;
const ACTIONS_TOKEN_PREFIX_DISPLAY_LEN: usize = 12;

#[derive(Debug, Clone)]
pub struct ActionsTokenSpec {
    pub repository: String,
    pub repository_owner: String,
    pub workflow_ref: Option<String>,
    pub subject: String,
    pub ttl_secs: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredActionsToken {
    pub id: i64,
    pub prefix: String,
    pub repository: String,
    pub repository_owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_ref: Option<String>,
    pub subject: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Principal information surfaced by the middleware when an
/// actions token authenticates a request. Used by the future
/// team/RBAC slice to scope writes to the matching repository's
/// team; today the writes don't read this back out, but exposing
/// the struct now keeps the lookup signature stable.
#[derive(Debug, Clone)]
pub struct ActionsPrincipal {
    pub token_id: i64,
    pub repository: String,
    pub repository_owner: String,
}

#[derive(Debug)]
pub struct MintedActionsToken {
    pub cleartext: String,
    pub record: StoredActionsToken,
}

impl Store {
    pub async fn mint_actions_token(&self, spec: ActionsTokenSpec) -> Result<MintedActionsToken> {
        if spec.ttl_secs < 1 {
            anyhow::bail!("actions token ttl must be >= 1 second");
        }
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            use base64::Engine;
            use rand::RngCore;
            let mut raw = [0u8; ACTIONS_TOKEN_BYTES];
            rand::thread_rng().fill_bytes(&mut raw);
            let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
            let cleartext = format!("{ACTIONS_TOKEN_PREFIX}{body}");
            let prefix = cleartext
                .chars()
                .take(ACTIONS_TOKEN_PREFIX_DISPLAY_LEN)
                .collect::<String>();
            let mut h = sha2::Sha256::new();
            h.update(cleartext.as_bytes());
            let hash: [u8; 32] = h.finalize().into();
            let now = Utc::now().timestamp_millis();
            let expires_at_ms = now + spec.ttl_secs * 1000;
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO actions_tokens
                        (token_hash, prefix, repository, repository_owner,
                         workflow_ref, subject,
                         created_at_ms, expires_at_ms, last_used_at_ms,
                         revoked_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL)",
                    params![
                        hash.as_slice(),
                        prefix,
                        spec.repository,
                        spec.repository_owner,
                        spec.workflow_ref,
                        spec.subject,
                        now,
                        expires_at_ms,
                    ],
                )
                .context("inserting actions token")?;
            let id = guard.last_insert_rowid();
            Ok(MintedActionsToken {
                cleartext,
                record: StoredActionsToken {
                    id,
                    prefix,
                    repository: spec.repository,
                    repository_owner: spec.repository_owner,
                    workflow_ref: spec.workflow_ref,
                    subject: spec.subject,
                    created_at: ms_to_utc(now)?,
                    expires_at: ms_to_utc(expires_at_ms)?,
                },
            })
        })
        .await
        .context("spawn_blocking mint_actions_token join")?
    }

    pub async fn actions_token_principal(
        &self,
        token_hash: [u8; 32],
    ) -> Result<Option<ActionsPrincipal>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let now = Utc::now().timestamp_millis();
            let row = guard
                .query_row(
                    "SELECT id, repository, repository_owner
                       FROM actions_tokens
                      WHERE token_hash    = ?1
                        AND revoked_at_ms IS NULL
                        AND expires_at_ms > ?2",
                    params![token_hash.as_slice(), now],
                    |row| {
                        Ok(ActionsPrincipal {
                            token_id: row.get(0)?,
                            repository: row.get(1)?,
                            repository_owner: row.get(2)?,
                        })
                    },
                )
                .optional()
                .context("actions_token_principal query")?;
            Ok(row)
        })
        .await
        .context("spawn_blocking actions_token_principal join")?
    }

    pub async fn touch_actions_token(&self, token_id: i64) -> Result<()> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "UPDATE actions_tokens SET last_used_at_ms = ?1 WHERE id = ?2",
                    params![Utc::now().timestamp_millis(), token_id],
                )
                .context("touching actions token")?;
            Ok(())
        })
        .await
        .context("spawn_blocking touch_actions_token join")?
    }
}

pub fn hash_actions_token(cleartext: &str) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(cleartext.as_bytes());
    h.finalize().into()
}

// ---------------- device authorization flow ----------------

/// User-code alphabet — uppercase A–Z minus the four "looks-like-
/// something-else" characters (I/O confuse with 1/0, S/Z confuse
/// in some fonts). 22 chars; 8-position user codes give ~35 bits
/// of entropy which is plenty for the 10-minute window with the
/// slow-down poll throttle.
const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRTUVWXY";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceCodeStatus {
    Pending,
    Approved,
    Denied,
    /// CLI successfully polled and got the token. Further polls
    /// look like `expired` to the caller.
    Consumed,
    Expired,
}

impl DeviceCodeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            "consumed" => Some(Self::Consumed),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredDeviceCode {
    pub id: i64,
    pub user_code: String,
    pub label: String,
    pub status: DeviceCodeStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct MintedDeviceCode {
    /// Secret the CLI keeps and polls with.
    pub device_code: String,
    /// Short human-readable code shown to the user (e.g. "ABCD-EFGH").
    pub user_code: String,
    pub expires_at: DateTime<Utc>,
}

/// Outcome of a `poll_device_code` call. Maps onto the RFC 8628
/// error codes the CLI returns to the user.
pub enum DevicePollOutcome {
    /// CLI should keep polling. `slow_down` if the poll cadence
    /// is too fast; otherwise plain `pending`.
    Pending { slow_down: bool },
    /// Operator denied the device. Final.
    Denied,
    /// CLI polled too late (or never showed up). Final.
    Expired,
    /// Already consumed. Final — repeat polls after success.
    AlreadyConsumed,
    /// First post-approval poll. Cleartext token is in the body;
    /// the CLI should immediately stop polling.
    Approved { cleartext: String },
}

impl Store {
    /// Mint a device + user code pair. Retries up to 5 times if
    /// `user_code` collides — uniqueness violations are
    /// astronomically rare in a 10-min window with 22^8 codes,
    /// but the retry keeps a worst-case duplicate-mint loud.
    pub async fn mint_device_code(&self, label: String, ttl_secs: i64) -> Result<MintedDeviceCode> {
        if label.is_empty() {
            anyhow::bail!("device code label is empty");
        }
        if label.len() > 128 {
            anyhow::bail!("device code label exceeds 128 chars");
        }
        if ttl_secs < 60 {
            anyhow::bail!("device code ttl must be >= 60 seconds");
        }
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            use base64::Engine;
            use rand::RngCore;
            let now = Utc::now().timestamp_millis();
            let expires_at_ms = now + ttl_secs * 1000;
            let guard = conn.blocking_lock();
            // Opportunistic GC of long-expired rows. The endpoint
            // is unauthenticated and rows live for 10 minutes; a
            // background loop would be cleaner but this keeps the
            // table bounded without one. 24h grace is enough to
            // debug after-the-fact.
            guard
                .execute(
                    "DELETE FROM device_codes
                      WHERE expires_at_ms < ?1
                        AND created_at_ms < ?2",
                    params![now - 24 * 3600 * 1000, now - 24 * 3600 * 1000],
                )
                .context("GC'ing expired device codes")?;
            // Active-row cap. Unauthenticated endpoints need a
            // ceiling — a quick-and-dirty 10_000 lets a real
            // operator never see it, but stops a pathological
            // flood from filling the disk.
            let pending: i64 = guard
                .query_row(
                    "SELECT COUNT(*) FROM device_codes
                      WHERE status = 'pending' AND expires_at_ms > ?1",
                    params![now],
                    |r| r.get(0),
                )
                .context("counting pending device codes")?;
            if pending >= 10_000 {
                anyhow::bail!("too many pending device codes ({pending}); retry shortly");
            }
            for _ in 0..5 {
                let mut raw = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut raw);
                let device_code = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
                // 8 chars from USER_CODE_ALPHABET, formatted
                // `XXXX-XXXX` for readability.
                let mut chars = [0u8; 8];
                rand::thread_rng().fill_bytes(&mut chars);
                let mut buf = String::with_capacity(9);
                for (i, b) in chars.iter().enumerate() {
                    if i == 4 {
                        buf.push('-');
                    }
                    let idx = (*b as usize) % USER_CODE_ALPHABET.len();
                    buf.push(USER_CODE_ALPHABET[idx] as char);
                }
                let user_code = buf;
                let res = guard.execute(
                    "INSERT INTO device_codes
                        (device_code, user_code, status, label,
                         created_at_ms, expires_at_ms)
                     VALUES (?1, ?2, 'pending', ?3, ?4, ?5)",
                    params![device_code, user_code, label, now, expires_at_ms],
                );
                match res {
                    Ok(_) => {
                        return Ok(MintedDeviceCode {
                            device_code,
                            user_code,
                            expires_at: ms_to_utc(expires_at_ms)?,
                        });
                    }
                    Err(rusqlite::Error::SqliteFailure(e, _))
                        if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                    {
                        continue; // retry on collision
                    }
                    Err(e) => return Err(anyhow::Error::from(e).context("inserting device code")),
                }
            }
            anyhow::bail!("device_code generation failed after 5 retries")
        })
        .await
        .context("spawn_blocking mint_device_code join")?
    }

    /// Look up a device_codes row by the human-friendly user_code.
    /// Normalises by uppercasing + stripping the `-` separator so
    /// `abcd-efgh`, `ABCDEFGH`, `ABCD-EFGH` all hit. Returns
    /// `Ok(None)` for any not-found / not-pending shape — same
    /// uniform-failure stance as session lookup.
    pub async fn find_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<StoredDeviceCode>> {
        let norm = normalise_user_code(user_code);
        if norm.is_empty() {
            return Ok(None);
        }
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            // Compare against the canonical stored form
            // (`XXXX-XXXX`); but the operator probably typed
            // without the dash, so we re-insert it before
            // comparing.
            let formatted = if norm.len() == 8 {
                format!("{}-{}", &norm[..4], &norm[4..])
            } else {
                norm
            };
            let row = guard
                .query_row(
                    "SELECT id, user_code, label, status, created_at_ms, expires_at_ms
                       FROM device_codes
                      WHERE user_code = ?1",
                    params![formatted],
                    decode_device_code_row,
                )
                .optional()
                .context("find_device_code_by_user_code query")?;
            Ok(row)
        })
        .await
        .context("spawn_blocking find_device_code_by_user_code join")?
    }

    /// Approve a pending device_code on behalf of `user_id` (the
    /// browser-authenticated operator). Returns `false` if the
    /// row isn't pending (already approved/denied/expired/etc.)
    /// or doesn't exist.
    pub async fn approve_device_code(&self, id: i64, user_id: i64) -> Result<bool> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let now = Utc::now().timestamp_millis();
            let n = guard
                .execute(
                    "UPDATE device_codes
                        SET status = 'approved',
                            approving_user_id = ?1,
                            approved_at_ms = ?2
                      WHERE id = ?3
                        AND status = 'pending'
                        AND expires_at_ms > ?2",
                    params![user_id, now, id],
                )
                .context("approving device code")?;
            Ok(n > 0)
        })
        .await
        .context("spawn_blocking approve_device_code join")?
    }

    pub async fn deny_device_code(&self, id: i64) -> Result<bool> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let now = Utc::now().timestamp_millis();
            let n = guard
                .execute(
                    "UPDATE device_codes
                        SET status = 'denied'
                      WHERE id = ?1
                        AND status = 'pending'
                        AND expires_at_ms > ?2",
                    params![id, now],
                )
                .context("denying device code")?;
            Ok(n > 0)
        })
        .await
        .context("spawn_blocking deny_device_code join")?
    }

    /// CLI poll. Implements the RFC-8628 state machine:
    ///
    /// - row absent / expired → `Expired`
    /// - status = pending → `Pending { slow_down }` where
    ///   `slow_down=true` iff the previous poll was less than
    ///   `min_interval_secs` ago.
    /// - status = denied → `Denied`
    /// - status = consumed → `AlreadyConsumed`
    /// - status = approved → mint personal token for the
    ///   approving user, transition to `consumed`, return
    ///   `Approved { cleartext }`. This is the only path that
    ///   returns the cleartext — and only once.
    pub async fn poll_device_code(
        &self,
        device_code: String,
        min_interval_secs: i64,
    ) -> Result<DevicePollOutcome> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.blocking_lock();
            let now = Utc::now().timestamp_millis();
            let tx = guard.transaction().context("opening poll tx")?;
            #[allow(clippy::type_complexity)]
            let row: Option<(i64, String, i64, Option<i64>, Option<i64>, String)> = tx
                .query_row(
                    "SELECT id, status, expires_at_ms, last_polled_at_ms,
                            approving_user_id, label
                       FROM device_codes
                      WHERE device_code = ?1",
                    params![device_code],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                        ))
                    },
                )
                .optional()
                .context("poll_device_code lookup")?;
            let Some((id, status_s, expires_at_ms, last_polled, approving_user_id, label)) = row
            else {
                tx.commit().ok();
                return Ok(DevicePollOutcome::Expired);
            };
            // Stamp the poll time first (regardless of outcome)
            // so subsequent polls see the throttle even when this
            // one returns `pending`.
            tx.execute(
                "UPDATE device_codes SET last_polled_at_ms = ?1 WHERE id = ?2",
                params![now, id],
            )
            .context("updating last_polled_at_ms")?;
            if expires_at_ms <= now {
                tx.execute(
                    "UPDATE device_codes SET status = 'expired' WHERE id = ?1 AND status = 'pending'",
                    params![id],
                )
                .ok();
                tx.commit().context("committing expired-flip")?;
                return Ok(DevicePollOutcome::Expired);
            }
            let status = DeviceCodeStatus::parse(&status_s).unwrap_or(DeviceCodeStatus::Expired);
            match status {
                DeviceCodeStatus::Pending => {
                    let too_fast = last_polled
                        .map(|t| (now - t) < min_interval_secs * 1000)
                        .unwrap_or(false);
                    tx.commit().context("committing pending poll")?;
                    Ok(DevicePollOutcome::Pending { slow_down: too_fast })
                }
                DeviceCodeStatus::Denied => {
                    tx.commit().context("committing denied poll")?;
                    Ok(DevicePollOutcome::Denied)
                }
                DeviceCodeStatus::Consumed => {
                    tx.commit().context("committing consumed poll")?;
                    Ok(DevicePollOutcome::AlreadyConsumed)
                }
                DeviceCodeStatus::Expired => {
                    tx.commit().context("committing expired poll")?;
                    Ok(DevicePollOutcome::Expired)
                }
                DeviceCodeStatus::Approved => {
                    let user_id = approving_user_id.ok_or_else(|| {
                        anyhow::anyhow!("approved device_code without approving_user_id")
                    })?;
                    // Mint cleartext + insert api_token row.
                    use base64::Engine;
                    use rand::RngCore;
                    let mut raw = [0u8; 32];
                    rand::thread_rng().fill_bytes(&mut raw);
                    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
                    let cleartext = format!("{API_TOKEN_PREFIX}{body}");
                    let prefix = cleartext
                        .chars()
                        .take(12)
                        .collect::<String>();
                    let mut h = sha2::Sha256::new();
                    h.update(cleartext.as_bytes());
                    let hash: [u8; 32] = h.finalize().into();
                    tx.execute(
                        "INSERT INTO api_tokens
                            (user_id, token_hash, prefix, label,
                             created_at_ms, last_used_at_ms,
                             expires_at_ms, revoked_at_ms)
                         VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, NULL)",
                        params![user_id, hash.as_slice(), prefix, label, now],
                    )
                    .context("minting api token from device approval")?;
                    let token_id = tx.last_insert_rowid();
                    tx.execute(
                        "UPDATE device_codes
                            SET status = 'consumed',
                                consumed_token_id = ?1,
                                consumed_at_ms = ?2
                          WHERE id = ?3",
                        params![token_id, now, id],
                    )
                    .context("marking device code consumed")?;
                    tx.commit().context("committing approve+consume")?;
                    Ok(DevicePollOutcome::Approved { cleartext })
                }
            }
        })
        .await
        .context("spawn_blocking poll_device_code join")?
    }
}

fn decode_device_code_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredDeviceCode> {
    let status_s: String = row.get(3)?;
    let created_ms: i64 = row.get(4)?;
    let expires_ms: i64 = row.get(5)?;
    Ok(StoredDeviceCode {
        id: row.get(0)?,
        user_code: row.get(1)?,
        label: row.get(2)?,
        status: DeviceCodeStatus::parse(&status_s).unwrap_or(DeviceCodeStatus::Expired),
        created_at: ms_to_utc(created_ms).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(4, SqlType::Integer, e.into())
        })?,
        expires_at: ms_to_utc(expires_ms).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, SqlType::Integer, e.into())
        })?,
    })
}

fn normalise_user_code(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sakimori_core::deps::Ecosystem;

    fn rec(ev: InstallEvent) -> IngestRecord {
        ev.into()
    }

    #[tokio::test]
    async fn insert_then_list_roundtrips() {
        let s = Store::open_in_memory().unwrap();
        let ev = InstallEvent::new(Ecosystem::Npm, "left-pad", "1.3.0")
            .with_mode(ExecutionMode::Persistent)
            .with_project_path("/Users/alice/proj")
            .with_user_agent("npm/10.0.0 node/20.0.0");
        let id = s.insert(rec(ev)).await.unwrap();
        assert!(id > 0);

        let rows = s.list(ListFilter::default()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "left-pad");
        assert_eq!(rows[0].source, Source::Desktop);
        assert_eq!(rows[0].execution_mode, ExecutionMode::Persistent);
    }

    #[tokio::test]
    async fn explicit_source_overrides_heuristic() {
        let s = Store::open_in_memory().unwrap();
        // Path *looks* like Desktop, but the proxy already knows
        // (e.g.) it's running on a GitLab runner and supplies the
        // override.
        let ev = InstallEvent::new(Ecosystem::Npm, "a", "1").with_project_path("/Users/alice/p");
        s.insert(IngestRecord {
            event: ev,
            source: Some(Source::Actions),
        })
        .await
        .unwrap();
        let rows = s.list(ListFilter::default()).await.unwrap();
        assert_eq!(rows[0].source, Source::Actions);
    }

    #[tokio::test]
    async fn filters_compose() {
        let s = Store::open_in_memory().unwrap();
        for (name, ver, mode, path) in [
            ("a", "1", ExecutionMode::Persistent, "/Users/alice/p"),
            ("a", "2", ExecutionMode::Ephemeral, "/home/runner/work/r/r"),
            ("b", "1", ExecutionMode::Persistent, "/Users/alice/p"),
        ] {
            let ev = InstallEvent::new(Ecosystem::Npm, name, ver)
                .with_mode(mode)
                .with_project_path(path);
            s.insert(rec(ev)).await.unwrap();
        }
        let only_a = s
            .list(ListFilter {
                name: Some("a".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(only_a.len(), 2);
        let only_actions = s
            .list(ListFilter {
                source: Some(Source::Actions),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(only_actions.len(), 1);
        assert_eq!(only_actions[0].version, "2");
    }

    #[tokio::test]
    async fn list_orders_newest_first() {
        let s = Store::open_in_memory().unwrap();
        let mut older = InstallEvent::new(Ecosystem::Npm, "a", "1");
        older.resolved_at = Utc::now() - chrono::Duration::hours(1);
        let newer = InstallEvent::new(Ecosystem::Npm, "a", "2");
        s.insert(rec(older)).await.unwrap();
        s.insert(rec(newer)).await.unwrap();
        let rows = s.list(ListFilter::default()).await.unwrap();
        assert_eq!(rows[0].version, "2");
        assert_eq!(rows[1].version, "1");
    }

    #[tokio::test]
    async fn mixed_offset_timestamps_order_correctly() {
        // Two instants 1 hour apart, but the *older* one is rendered
        // in a +09:00 offset and the *newer* one in `Z`. A naive
        // lexicographic TEXT comparison would put the +09:00 string
        // first; the epoch-ms storage gets it right.
        let s = Store::open_in_memory().unwrap();
        let base = Utc::now();
        let older = base - chrono::Duration::hours(2);
        let newer = base - chrono::Duration::hours(1);
        let mut e_older = InstallEvent::new(Ecosystem::Npm, "a", "old");
        e_older.resolved_at = older
            .with_timezone(&chrono::FixedOffset::east_opt(9 * 3600).unwrap())
            .with_timezone(&Utc);
        let mut e_newer = InstallEvent::new(Ecosystem::Npm, "a", "new");
        e_newer.resolved_at = newer;
        s.insert(rec(e_older)).await.unwrap();
        s.insert(rec(e_newer)).await.unwrap();
        let rows = s.list(ListFilter::default()).await.unwrap();
        assert_eq!(rows[0].version, "new");
        assert_eq!(rows[1].version, "old");
    }

    #[tokio::test]
    async fn count_reflects_inserts() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.count().await.unwrap(), 0);
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "a", "1")))
            .await
            .unwrap();
        assert_eq!(s.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn since_filter_excludes_older() {
        let s = Store::open_in_memory().unwrap();
        let mut old = InstallEvent::new(Ecosystem::Npm, "a", "1");
        old.resolved_at = Utc::now() - chrono::Duration::days(2);
        let new = InstallEvent::new(Ecosystem::Npm, "a", "2");
        s.insert(rec(old)).await.unwrap();
        s.insert(rec(new)).await.unwrap();
        let rows = s
            .list(ListFilter {
                since: Some(Utc::now() - chrono::Duration::hours(1)),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].version, "2");
    }

    #[tokio::test]
    async fn insert_many_is_atomic_and_returns_ids() {
        let s = Store::open_in_memory().unwrap();
        let batch = vec![
            rec(InstallEvent::new(Ecosystem::Npm, "a", "1")),
            rec(InstallEvent::new(Ecosystem::Npm, "b", "2")),
            rec(InstallEvent::new(Ecosystem::Npm, "c", "3")),
        ];
        let ids = s.insert_many(batch).await.unwrap();
        assert_eq!(ids.len(), 3);
        assert!(ids[0] < ids[1] && ids[1] < ids[2]);
        assert_eq!(s.count().await.unwrap(), 3);
    }

    #[tokio::test]
    async fn schema_version_is_seeded() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.schema_version().await.unwrap(), CURRENT_SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn reopening_an_existing_file_does_not_re_run_migrations() {
        // Catches the "CREATE TABLE installs lacks IF NOT EXISTS so a
        // second open re-runs v1 and fails" regression: open, write,
        // drop, re-open the same file path, assert the data is still
        // visible and schema_version is unchanged.
        let dir = tempdir();
        let path = dir.join("hub.sqlite");
        {
            let s = Store::open(&path).unwrap();
            s.insert(rec(InstallEvent::new(Ecosystem::Npm, "a", "1")))
                .await
                .unwrap();
            assert_eq!(s.schema_version().await.unwrap(), CURRENT_SCHEMA_VERSION);
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(s.count().await.unwrap(), 1);
        assert_eq!(s.schema_version().await.unwrap(), CURRENT_SCHEMA_VERSION);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn refuses_to_open_db_with_newer_schema() {
        let dir = tempdir();
        let path = dir.join("hub.sqlite");
        // Seed a file claiming schema_version=999, then try to open
        // it with the current binary.
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (
                     id INTEGER PRIMARY KEY CHECK (id = 1),
                     version INTEGER NOT NULL,
                     applied_at_ms INTEGER NOT NULL
                 );
                 INSERT INTO schema_version (id, version, applied_at_ms) VALUES (1, 999, 0);",
            )
            .unwrap();
        }
        let err = Store::open(&path).err().expect("should refuse");
        assert!(format!("{err:#}").contains("refusing to downgrade"));
        std::fs::remove_dir_all(&dir).ok();
    }

    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("sakimori-hub-test-{id}-{seq}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    // ---------- advisory + scan tests ----------

    fn osv_adv(id: &str, eco: &str, name: &str, versions: &[&str]) -> OsvAdvisory {
        let body = serde_json::json!({
            "id": id,
            "summary": format!("test advisory {id}"),
            "database_specific": {"severity": "HIGH"},
            "affected": [{
                "package": {"ecosystem": eco, "name": name},
                "versions": versions,
            }],
        });
        serde_json::from_value(body).unwrap()
    }

    #[tokio::test]
    async fn advisory_upsert_then_scan_creates_finding() {
        let s = Store::open_in_memory().unwrap();
        // Install first, then a matching advisory.
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "left-pad", "1.3.0")))
            .await
            .unwrap();
        let (_, new) = s
            .upsert_advisory(osv_adv("GHSA-1", "npm", "left-pad", &["1.3.0"]), None)
            .await
            .unwrap();
        assert!(new);

        let report = s.scan_findings().await.unwrap();
        assert_eq!(report.installs_scanned, 1);
        assert_eq!(report.advisories_considered, 1);
        assert_eq!(report.new_findings, 1);
        assert_eq!(report.total_findings, 1);

        let findings = s.list_findings(FindingFilter::default()).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].advisory.osv_id, "GHSA-1");
        assert_eq!(findings[0].install.name, "left-pad");
        assert_eq!(findings[0].install.version, "1.3.0");
    }

    #[tokio::test]
    async fn scan_is_idempotent() {
        let s = Store::open_in_memory().unwrap();
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "a", "1")))
            .await
            .unwrap();
        s.upsert_advisory(osv_adv("A", "npm", "a", &["1"]), None)
            .await
            .unwrap();
        let first = s.scan_findings().await.unwrap();
        let second = s.scan_findings().await.unwrap();
        assert_eq!(first.new_findings, 1);
        assert_eq!(second.new_findings, 0);
        assert_eq!(second.total_findings, 1);
    }

    #[tokio::test]
    async fn scan_finds_advisory_published_after_install() {
        // The whole point of retroactive notification: install
        // pre-dates the advisory's existence.
        let s = Store::open_in_memory().unwrap();
        s.insert(rec(InstallEvent::new(Ecosystem::Pypi, "django", "4.2.0")))
            .await
            .unwrap();
        let pre = s.scan_findings().await.unwrap();
        assert_eq!(pre.new_findings, 0);

        s.upsert_advisory(osv_adv("GHSA-late", "PyPI", "django", &["4.2.0"]), None)
            .await
            .unwrap();
        let post = s.scan_findings().await.unwrap();
        assert_eq!(post.new_findings, 1);
    }

    #[tokio::test]
    async fn shrinking_advisory_prunes_stale_findings() {
        // The "publisher narrowed the advisory" case: an install
        // that previously matched should disappear from /findings
        // once the advisory's affected set no longer covers it.
        let s = Store::open_in_memory().unwrap();
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "p", "1.0.0")))
            .await
            .unwrap();
        s.upsert_advisory(
            osv_adv("GHSA-narrow", "npm", "p", &["1.0.0", "1.0.1"]),
            None,
        )
        .await
        .unwrap();
        s.scan_findings().await.unwrap();
        assert_eq!(
            s.list_findings(FindingFilter::default())
                .await
                .unwrap()
                .len(),
            1
        );
        // Narrow: only 1.0.1 remains affected — our 1.0.0 install
        // is no longer covered.
        s.upsert_advisory(osv_adv("GHSA-narrow", "npm", "p", &["1.0.1"]), None)
            .await
            .unwrap();
        let after = s.list_findings(FindingFilter::default()).await.unwrap();
        assert_eq!(
            after.len(),
            0,
            "stale finding for 1.0.0 should be pruned after narrowing"
        );
    }

    #[tokio::test]
    async fn raw_json_round_trips_extra_fields() {
        let s = Store::open_in_memory().unwrap();
        let raw = serde_json::json!({
            "id": "GHSA-raw",
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": "npm", "name": "p"}, "versions": ["1"]}],
            "extra_we_do_not_model": {"foo": "bar"},
        });
        let parsed: OsvAdvisory = serde_json::from_value(raw.clone()).unwrap();
        s.upsert_advisory(parsed, Some(raw.clone())).await.unwrap();
        // Pull the literal raw_json back via a direct SELECT to
        // prove the "extra" field survived storage.
        let conn = s.conn.clone();
        let stored: String = tokio::task::spawn_blocking(move || {
            let g = conn.blocking_lock();
            g.query_row(
                "SELECT raw_json FROM advisories WHERE osv_id = 'GHSA-raw'",
                [],
                |r| r.get::<_, String>(0),
            )
            .unwrap()
        })
        .await
        .unwrap();
        let parsed_back: serde_json::Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(parsed_back["extra_we_do_not_model"]["foo"], "bar");
    }

    #[tokio::test]
    async fn validation_rejects_empty_id() {
        let s = Store::open_in_memory().unwrap();
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({"id": ""})).unwrap();
        let err = s.upsert_advisory(adv, None).await.err().unwrap();
        assert!(format!("{err:#}").contains("advisory id is empty"));
    }

    #[tokio::test]
    async fn validation_rejects_oversized_summary() {
        let s = Store::open_in_memory().unwrap();
        let huge = "x".repeat(9000);
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "GHSA-1",
            "summary": huge,
        }))
        .unwrap();
        let err = s.upsert_advisory(adv, None).await.err().unwrap();
        assert!(format!("{err:#}").contains("summary exceeds"));
    }

    #[tokio::test]
    async fn upsert_replaces_affected_rows() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_advisory(osv_adv("GHSA-x", "npm", "p", &["1.0.0", "1.0.1"]), None)
            .await
            .unwrap();
        // Second upsert with a smaller set — the JOIN should not
        // match the removed version.
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "p", "1.0.1")))
            .await
            .unwrap();
        s.upsert_advisory(osv_adv("GHSA-x", "npm", "p", &["1.0.0"]), None)
            .await
            .unwrap();
        let report = s.scan_findings().await.unwrap();
        assert_eq!(report.new_findings, 0, "1.0.1 was removed from affected");
    }

    #[tokio::test]
    async fn min_severity_is_applied_before_limit() {
        // Regression: with the previous Rust-side filter, asking for
        // min_severity=high with limit=5 against a DB whose newest 5
        // findings are low would return zero rows — even when older
        // critical findings existed. SQL-side filtering must surface
        // them.
        let s = Store::open_in_memory().unwrap();
        // Critical finding goes in FIRST, so its findings.id and
        // findings.created_at_ms are the smallest in the table.
        // ORDER BY f.created_at_ms DESC, f.id DESC then surfaces
        // the low ones first — exactly the ordering that would
        // hide the critical under a Rust-side post-LIMIT filter.
        let ev = InstallEvent::new(Ecosystem::Npm, "boom", "1");
        s.insert(rec(ev)).await.unwrap();
        let crit: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "CRIT-OLD",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"ecosystem": "npm", "name": "boom"}, "versions": ["1"]}],
        }))
        .unwrap();
        s.upsert_advisory(crit, None).await.unwrap();
        s.scan_findings().await.unwrap();
        // Now 10 newer low-severity findings on top.
        for i in 0..10 {
            let ev = InstallEvent::new(Ecosystem::Npm, format!("low{i}"), "1");
            s.insert(rec(ev)).await.unwrap();
            let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
                "id": format!("LOW-{i}"),
                "database_specific": {"severity": "LOW"},
                "affected": [{"package": {"ecosystem": "npm", "name": format!("low{i}")},
                              "versions": ["1"]}],
            }))
            .unwrap();
            s.upsert_advisory(adv, None).await.unwrap();
        }
        s.scan_findings().await.unwrap();

        let high_only = s
            .list_findings(FindingFilter {
                min_severity: Some(Severity::High),
                limit: Some(5),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(high_only.len(), 1, "limit must not hide CRIT-OLD");
        assert_eq!(high_only[0].advisory.osv_id, "CRIT-OLD");
    }

    #[tokio::test]
    async fn semver_range_advisory_matches_install_in_range() {
        let s = Store::open_in_memory().unwrap();
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "lodash", "4.17.20")))
            .await
            .unwrap();
        // Range-only advisory (no `versions[]`).
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "GHSA-range",
            "database_specific": {"severity": "HIGH"},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "0"}, {"fixed": "4.17.21"}
                ]}]
            }],
        }))
        .unwrap();
        s.upsert_advisory(adv, None).await.unwrap();
        let report = s.scan_findings().await.unwrap();
        assert_eq!(report.new_findings, 1, "4.17.20 is inside [0, 4.17.21)");
        let findings = s.list_findings(FindingFilter::default()).await.unwrap();
        assert_eq!(findings[0].advisory.osv_id, "GHSA-range");
    }

    #[tokio::test]
    async fn semver_range_excludes_install_above_fixed() {
        let s = Store::open_in_memory().unwrap();
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "lodash", "4.17.21")))
            .await
            .unwrap();
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "GHSA-range",
            "database_specific": {"severity": "HIGH"},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "0"}, {"fixed": "4.17.21"}
                ]}]
            }],
        }))
        .unwrap();
        s.upsert_advisory(adv, None).await.unwrap();
        let report = s.scan_findings().await.unwrap();
        assert_eq!(
            report.new_findings, 0,
            "4.17.21 == fixed bound, must not match"
        );
    }

    #[tokio::test]
    async fn semver_range_unbounded_upper_matches() {
        let s = Store::open_in_memory().unwrap();
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "p", "9.9.9")))
            .await
            .unwrap();
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "GHSA-unbounded",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "p"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}]}]
            }],
        }))
        .unwrap();
        s.upsert_advisory(adv, None).await.unwrap();
        assert_eq!(s.scan_findings().await.unwrap().new_findings, 1);
    }

    #[tokio::test]
    async fn semver_range_prune_drops_finding_after_narrow() {
        // Advisory initially covers [0, 4.17.21); install at
        // 4.17.20 matches. Then the advisory is narrowed to
        // [4.17.18, 4.17.19) — 4.17.20 no longer in range, so the
        // stale finding must be pruned by upsert.
        let s = Store::open_in_memory().unwrap();
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "lodash", "4.17.20")))
            .await
            .unwrap();
        let wide: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "GHSA-narrow",
            "database_specific": {"severity": "HIGH"},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "0"}, {"fixed": "4.17.21"}
                ]}]
            }],
        }))
        .unwrap();
        s.upsert_advisory(wide, None).await.unwrap();
        s.scan_findings().await.unwrap();
        assert_eq!(
            s.list_findings(FindingFilter::default())
                .await
                .unwrap()
                .len(),
            1
        );
        let narrow: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "GHSA-narrow",
            "database_specific": {"severity": "HIGH"},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "4.17.18"}, {"fixed": "4.17.19"}
                ]}]
            }],
        }))
        .unwrap();
        s.upsert_advisory(narrow, None).await.unwrap();
        assert!(
            s.list_findings(FindingFilter::default())
                .await
                .unwrap()
                .is_empty(),
            "4.17.20 no longer in the narrowed range — must be pruned"
        );
    }

    #[tokio::test]
    async fn semver_range_last_affected_is_inclusive_at_scan() {
        // last_affected = 1.2.3 ⇒ stable 1.2.3 IS a match, 1.2.4
        // is NOT, and 1.2.4-rc.1 also is NOT (the bug bump would
        // have wrongly matched 1.2.3 stable when last_affected
        // pointed at a prerelease).
        let s = Store::open_in_memory().unwrap();
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "p", "1.2.3")))
            .await
            .unwrap();
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "p", "1.2.4")))
            .await
            .unwrap();
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "GHSA-incl",
            "database_specific": {"severity": "HIGH"},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "p"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "1.0.0"}, {"last_affected": "1.2.3"}
                ]}]
            }],
        }))
        .unwrap();
        s.upsert_advisory(adv, None).await.unwrap();
        s.scan_findings().await.unwrap();
        let findings = s.list_findings(FindingFilter::default()).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].install.version, "1.2.3");
    }

    #[tokio::test]
    async fn semver_range_malformed_close_does_not_fabricate_matches() {
        // Regression: previously a malformed `fixed`/`last_affected`
        // could degrade to "unbounded above" and silently match
        // installs the advisory never named.
        let s = Store::open_in_memory().unwrap();
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "p", "9.9.9")))
            .await
            .unwrap();
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "GHSA-bad",
            "database_specific": {"severity": "HIGH"},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "p"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "1.0.0"}, {"fixed": "not-a-version"}
                ]}]
            }],
        }))
        .unwrap();
        s.upsert_advisory(adv, None).await.unwrap();
        let report = s.scan_findings().await.unwrap();
        assert_eq!(
            report.new_findings, 0,
            "malformed close ⇒ drop the open ⇒ no fabricated matches"
        );
    }

    #[tokio::test]
    async fn list_advisories_splits_versions_and_ranges_counts() {
        let s = Store::open_in_memory().unwrap();
        // Range-only advisory: zero versions, one range.
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "RNG",
            "database_specific": {"severity": "HIGH"},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "p"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "1.0.0"}, {"fixed": "2.0.0"}
                ]}]
            }],
        }))
        .unwrap();
        s.upsert_advisory(adv, None).await.unwrap();
        let listed = s.list_advisories(None).await.unwrap();
        assert_eq!(listed[0].affected_count, 0);
        assert_eq!(listed[0].affected_ranges_count, 1);
    }

    #[tokio::test]
    async fn semver_range_does_not_double_count_with_exact() {
        // An advisory that lists BOTH the exact version AND a
        // covering range must still produce only ONE finding per
        // (advisory, install) pair (UNIQUE constraint).
        let s = Store::open_in_memory().unwrap();
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "p", "1.0.5")))
            .await
            .unwrap();
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "GHSA-both",
            "database_specific": {"severity": "HIGH"},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "p"},
                "versions": ["1.0.5"],
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "1.0.0"}, {"fixed": "2.0.0"}
                ]}]
            }],
        }))
        .unwrap();
        s.upsert_advisory(adv, None).await.unwrap();
        let report = s.scan_findings().await.unwrap();
        assert_eq!(report.new_findings, 1);
        assert_eq!(report.total_findings, 1);
    }

    #[tokio::test]
    async fn list_findings_filters_by_min_severity() {
        let s = Store::open_in_memory().unwrap();
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "a", "1")))
            .await
            .unwrap();
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, "b", "1")))
            .await
            .unwrap();
        // Two advisories with different severities.
        let low: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "LOW", "database_specific": {"severity": "LOW"},
            "affected": [{"package": {"ecosystem": "npm", "name": "a"}, "versions": ["1"]}],
        }))
        .unwrap();
        let critical: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": "CRIT", "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"ecosystem": "npm", "name": "b"}, "versions": ["1"]}],
        }))
        .unwrap();
        s.upsert_advisory(low, None).await.unwrap();
        s.upsert_advisory(critical, None).await.unwrap();
        s.scan_findings().await.unwrap();

        let all = s.list_findings(FindingFilter::default()).await.unwrap();
        assert_eq!(all.len(), 2);
        let high_only = s
            .list_findings(FindingFilter {
                min_severity: Some(Severity::High),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(high_only.len(), 1);
        assert_eq!(high_only[0].advisory.osv_id, "CRIT");
    }

    #[tokio::test]
    async fn list_advisories_returns_affected_count() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_advisory(osv_adv("GHSA-1", "npm", "p", &["1", "2", "3"]), None)
            .await
            .unwrap();
        let advs = s.list_advisories(None).await.unwrap();
        assert_eq!(advs.len(), 1);
        assert_eq!(advs[0].affected_count, 3);
    }

    #[tokio::test]
    async fn schema_version_is_current() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.schema_version().await.unwrap(), CURRENT_SCHEMA_VERSION);
    }

    // ---------- dispatch targets / pending ----------

    fn target_spec(label: &str, min: Severity) -> TargetSpec {
        TargetSpec {
            label: label.into(),
            url: "https://ops.example.com/hook".into(),
            secret: "0123456789abcdef0123".into(),
            min_severity: min,
            source_filter: None,
        }
    }

    async fn seeded_finding(s: &Store, name: &str, ver: &str, sev: &str) {
        s.insert(rec(InstallEvent::new(Ecosystem::Npm, name, ver)))
            .await
            .unwrap();
        let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
            "id": format!("ADV-{name}-{ver}"),
            "database_specific": {"severity": sev},
            "affected": [{"package": {"ecosystem": "npm", "name": name}, "versions": [ver]}],
        }))
        .unwrap();
        s.upsert_advisory(adv, None).await.unwrap();
        s.scan_findings().await.unwrap();
    }

    #[tokio::test]
    async fn pending_deliveries_respects_severity_filter() {
        let s = Store::open_in_memory().unwrap();
        seeded_finding(&s, "a", "1", "LOW").await;
        seeded_finding(&s, "b", "1", "CRITICAL").await;
        // Target is High+
        s.register_target(target_spec("high-only", Severity::High))
            .await
            .unwrap();
        let pending = s.pending_deliveries(100, DEFAULT_CAP).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].install_name, "b");
    }

    #[tokio::test]
    async fn pending_deliveries_respects_source_filter() {
        let s = Store::open_in_memory().unwrap();
        // Install with desktop-y path; the heuristic classifies as Desktop.
        let ev_desktop =
            InstallEvent::new(Ecosystem::Npm, "a", "1").with_project_path("/Users/alice/p");
        s.insert(rec(ev_desktop)).await.unwrap();
        // Install with runner-y path; classifies as Actions.
        let ev_actions =
            InstallEvent::new(Ecosystem::Npm, "b", "1").with_project_path("/home/runner/work/r/r");
        s.insert(rec(ev_actions)).await.unwrap();
        for name in ["a", "b"] {
            let adv: OsvAdvisory = serde_json::from_value(serde_json::json!({
                "id": format!("X-{name}"),
                "database_specific": {"severity": "CRITICAL"},
                "affected": [{"package": {"ecosystem": "npm", "name": name}, "versions": ["1"]}],
            }))
            .unwrap();
            s.upsert_advisory(adv, None).await.unwrap();
        }
        s.scan_findings().await.unwrap();
        s.register_target(TargetSpec {
            source_filter: Some(Source::Actions),
            ..target_spec("actions-only", Severity::Low)
        })
        .await
        .unwrap();
        let pending = s.pending_deliveries(100, DEFAULT_CAP).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].install_source, Source::Actions);
    }

    #[tokio::test]
    async fn record_attempt_then_pending_excludes_success() {
        let s = Store::open_in_memory().unwrap();
        seeded_finding(&s, "a", "1", "CRITICAL").await;
        let tid = s
            .register_target(target_spec("t", Severity::Low))
            .await
            .unwrap();
        let pending = s.pending_deliveries(10, DEFAULT_CAP).await.unwrap();
        assert_eq!(pending.len(), 1);
        s.record_attempt(pending[0].finding_id, tid, true, Some(200), None)
            .await
            .unwrap();
        assert!(
            s.pending_deliveries(10, DEFAULT_CAP)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn attempt_cap_excludes_repeat_failures() {
        let s = Store::open_in_memory().unwrap();
        seeded_finding(&s, "a", "1", "CRITICAL").await;
        let tid = s
            .register_target(target_spec("t", Severity::Low))
            .await
            .unwrap();
        let pending = s.pending_deliveries(10, DEFAULT_CAP).await.unwrap();
        let fid = pending[0].finding_id;
        for _ in 0..3 {
            s.record_attempt(fid, tid, false, Some(500), Some("nope".into()))
                .await
                .unwrap();
        }
        // Cap=3 ⇒ excluded.
        assert!(s.pending_deliveries(10, 3).await.unwrap().is_empty());
        // Cap=4 ⇒ one more attempt allowed.
        assert_eq!(s.pending_deliveries(10, 4).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn disabled_target_is_excluded() {
        let s = Store::open_in_memory().unwrap();
        seeded_finding(&s, "a", "1", "CRITICAL").await;
        let tid = s
            .register_target(target_spec("t", Severity::Low))
            .await
            .unwrap();
        s.set_target_enabled(tid, false).await.unwrap();
        assert!(
            s.pending_deliveries(10, DEFAULT_CAP)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn delete_target_preserves_attempts() {
        let s = Store::open_in_memory().unwrap();
        seeded_finding(&s, "a", "1", "CRITICAL").await;
        let tid = s
            .register_target(target_spec("t", Severity::Low))
            .await
            .unwrap();
        let pending = s.pending_deliveries(10, DEFAULT_CAP).await.unwrap();
        let fid = pending[0].finding_id;
        s.record_attempt(fid, tid, true, Some(200), None)
            .await
            .unwrap();
        assert!(s.delete_target(tid).await.unwrap());
        // Target no longer surfaces in list_targets, but the
        // attempt row survives for audit. Read it via a direct
        // query through the conn mutex.
        assert!(s.list_targets().await.unwrap().is_empty());
        let conn = s.conn.clone();
        let attempts: i64 = tokio::task::spawn_blocking(move || {
            let g = conn.blocking_lock();
            g.query_row(
                "SELECT COUNT(*) FROM dispatch_attempts WHERE target_id = ?1",
                params![tid],
                |r| r.get(0),
            )
            .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(attempts, 1, "attempt row should survive soft-delete");
    }

    #[tokio::test]
    async fn unique_partial_index_prevents_duplicate_success() {
        // Defence-in-depth: even if `record_attempt(.., true, ..)`
        // is invoked twice for the same (finding, target), the
        // second one must fail rather than silently double-count.
        let s = Store::open_in_memory().unwrap();
        seeded_finding(&s, "a", "1", "CRITICAL").await;
        let tid = s
            .register_target(target_spec("t", Severity::Low))
            .await
            .unwrap();
        let pending = s.pending_deliveries(10, DEFAULT_CAP).await.unwrap();
        let fid = pending[0].finding_id;
        s.record_attempt(fid, tid, true, Some(200), None)
            .await
            .unwrap();
        let err = s
            .record_attempt(fid, tid, true, Some(200), None)
            .await
            .expect_err("second success attempt should error");
        assert!(format!("{err:#}").to_ascii_lowercase().contains("unique"));
    }

    #[tokio::test]
    async fn delete_target_returns_bool() {
        let s = Store::open_in_memory().unwrap();
        let id = s
            .register_target(target_spec("gone", Severity::High))
            .await
            .unwrap();
        assert!(s.delete_target(id).await.unwrap());
        assert!(!s.delete_target(id).await.unwrap());
    }

    const DEFAULT_CAP: i64 = 5;

    #[tokio::test]
    async fn parallel_ingest_and_list_under_load() {
        // Spawn several writers + a reader against the same Store
        // and assert nothing wedges and the final count is right.
        let s = std::sync::Arc::new(Store::open_in_memory().unwrap());
        let mut handles = Vec::new();
        for w in 0..4 {
            let s = s.clone();
            handles.push(tokio::spawn(async move {
                for i in 0..25 {
                    let ev = InstallEvent::new(Ecosystem::Npm, format!("p{w}"), format!("{i}"));
                    s.insert(rec(ev)).await.unwrap();
                }
            }));
        }
        let reader = {
            let s = s.clone();
            tokio::spawn(async move {
                for _ in 0..10 {
                    let _ = s.list(ListFilter::default()).await.unwrap();
                    tokio::task::yield_now().await;
                }
            })
        };
        for h in handles {
            h.await.unwrap();
        }
        reader.await.unwrap();
        assert_eq!(s.count().await.unwrap(), 4 * 25);
    }
}
