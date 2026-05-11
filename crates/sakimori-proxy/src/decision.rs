//! "Given this (ecosystem, name, version), should we let the fetch
//! through or return 403?"
//!
//! The trait exists so tests can inject a deterministic age-lookup
//! function instead of hitting the real registry.

use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use sakimori_core::deps::Ecosystem;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Let the request through.
    Allow,
    /// Return 403 to the client with `reason` in the body.
    Deny { reason: String },
}

/// Plug-in point so the MITM proxy doesn't have to know where publish
/// dates come from. Production wires this to the existing
/// `sakimori-core::deps::registry` HTTP clients; tests pass a
/// canned-response implementation.
pub trait AgeOracle: Send + Sync {
    fn published(&self, eco: Ecosystem, name: &str, version: &str)
    -> Result<Option<DateTime<Utc>>>;
}

pub struct Decider<O: AgeOracle + ?Sized> {
    pub oracle: Box<O>,
    pub min_age: Duration,
    /// If `true`, treat lookup failures (network error, unknown crate,
    /// …) as Deny. If `false`, fail-open and Allow so a flaky registry
    /// doesn't brick the developer's install flow.
    pub fail_on_missing: bool,
    /// Optional hook for "this package version is known malicious"
    /// lookups (OSV / GHSA). When set, checked *before* the age
    /// filter so that a 7-year-old-but-still-poisonous package
    /// (e.g. event-stream 3.3.6) gets denied regardless of
    /// `--min-age`. Errors during lookup are logged and treated
    /// as "no match" — OSV downtime shouldn't block installs.
    pub known_bad: Option<Box<dyn crate::osv::KnownBadOracle>>,
    /// Optional typosquat detector. When set, every decide() call
    /// runs the package name through the detector; matches trigger
    /// `log::warn!` (in `Warn` mode) or a hard deny (`Block` mode).
    pub typosquat: Option<TyposquatHook>,
}

/// How to react to a typosquat hit. Separate from the detector
/// itself so we can hold one `Detector` and vary policy per
/// `Decider` (useful in tests and in the future for per-ecosystem
/// overrides).
/// Two detector variants (v0.28 vs v0.29):
/// - `Static` — hard-coded top-100 lists baked into the binary.
///   No network; deterministic behaviour.
/// - `Mirrored` — up to top-1000 per ecosystem fetched weekly
///   from the sakimori-hosted mirror, refreshed in the
///   background. Better recall; falls back to the Static list
///   per-ecosystem when the mirror is unavailable / empty.
#[derive(Debug, Clone)]
pub enum TyposquatDetector {
    Static(crate::typosquat::Detector),
    Mirrored(crate::typosquat::MirroredDetector),
}

impl TyposquatDetector {
    pub fn suggest(&self, eco: Ecosystem, name: &str) -> Option<crate::typosquat::Match> {
        match self {
            Self::Static(d) => d.suggest(eco, name),
            Self::Mirrored(d) => d.suggest(eco, name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TyposquatHook {
    pub detector: TyposquatDetector,
    pub mode: TyposquatMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TyposquatMode {
    /// Log a warning with the suggested legitimate name; let the
    /// request proceed to the age check.
    Warn,
    /// Return `Deny` immediately with a message naming the
    /// suggested legitimate package.
    Block,
}

impl<O: AgeOracle + ?Sized> Decider<O> {
    pub fn decide(
        &self,
        eco: Ecosystem,
        name: &str,
        version: &str,
        now: DateTime<Utc>,
    ) -> Decision {
        // Typosquat check — cheapest to run first (pure in-memory
        // edit-distance), and if we're in Block mode we skip every
        // downstream network lookup.
        if let Some(hook) = &self.typosquat
            && let Some(m) = hook.detector.suggest(eco, name)
        {
            match hook.mode {
                TyposquatMode::Warn => {
                    log::warn!(
                        "typosquat: {}/{name} looks like a typo of {} (edit-distance {}). \
                         Allowing — pass --typosquat block to deny.",
                        eco.label(),
                        m.suggested,
                        m.distance,
                    );
                }
                TyposquatMode::Block => {
                    return Decision::Deny {
                        reason: format!(
                            "sakimori: {}/{name} looks like a typosquat of {}@({} edit(s) away). \
                             Did you mean `{}`?",
                            eco.label(),
                            m.suggested,
                            m.distance,
                            m.suggested,
                        ),
                    };
                }
            }
        }
        // Known-malicious check — hard-deny regardless of age.
        if let Some(kb) = &self.known_bad {
            match kb.lookup(eco, name, version) {
                Ok(Some(ids)) if !ids.is_empty() => {
                    let head = ids.iter().take(2).cloned().collect::<Vec<_>>().join(", ");
                    let more = if ids.len() > 2 {
                        format!(" (+{} more)", ids.len() - 2)
                    } else {
                        String::new()
                    };
                    return Decision::Deny {
                        reason: format!(
                            "sakimori: {}/{}@{} is listed as malicious: {head}{more}",
                            eco.label(),
                            name,
                            version
                        ),
                    };
                }
                Ok(_) => {}
                Err(e) => log::warn!(
                    "known-bad lookup for {}/{}@{} failed: {e:#} — proceeding with age check",
                    eco.label(),
                    name,
                    version
                ),
            }
        }
        match self.oracle.published(eco, name, version) {
            Ok(Some(published)) => {
                let age = now - published;
                let cutoff = chrono::Duration::from_std(self.min_age).unwrap_or_default();
                if age < cutoff {
                    Decision::Deny {
                        reason: format!(
                            "sakimori: {}/{}@{} was published {} ago (< min-age {}h)",
                            eco.label(),
                            name,
                            version,
                            human_duration(age),
                            self.min_age.as_secs() / 3600,
                        ),
                    }
                } else {
                    Decision::Allow
                }
            }
            Ok(None) => {
                if self.fail_on_missing {
                    Decision::Deny {
                        reason: format!(
                            "sakimori: {}/{}@{} publish date unknown (--fail-on-missing)",
                            eco.label(),
                            name,
                            version
                        ),
                    }
                } else {
                    Decision::Allow
                }
            }
            Err(e) => {
                log::warn!(
                    "age lookup for {}/{}@{} failed: {e:#}",
                    eco.label(),
                    name,
                    version
                );
                if self.fail_on_missing {
                    Decision::Deny {
                        reason: "sakimori: age lookup failed (--fail-on-missing)".into(),
                    }
                } else {
                    Decision::Allow
                }
            }
        }
    }
}

fn human_duration(d: chrono::Duration) -> String {
    let h = d.num_hours();
    if h < 48 {
        format!("{h}h")
    } else {
        format!("{}d", d.num_days())
    }
}

/// Production oracle: delegates to the existing per-ecosystem registry
/// clients in `sakimori-core::deps::registry`. The proxy sits in
/// front of the same registries these clients query, so for the MITM
/// case we need to reach the real registry via an OS socket that
/// bypasses the proxy — done here simply by calling into the blocking
/// `ureq` clients which don't honour `HTTPS_PROXY`.
pub struct RegistryOracle {
    pub user_agent: String,
}

impl RegistryOracle {
    pub fn new(user_agent: String) -> Self {
        Self { user_agent }
    }
}

impl AgeOracle for RegistryOracle {
    fn published(
        &self,
        eco: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<Option<DateTime<Utc>>> {
        use sakimori_core::deps::registry;
        match eco {
            Ecosystem::Crates => registry::crates::published(name, version, &self.user_agent),
            Ecosystem::Npm => registry::npm::published(name, version, &self.user_agent),
            Ecosystem::Pypi => registry::pypi::published(name, version, &self.user_agent),
            Ecosystem::Nuget => registry::nuget::published(name, version, &self.user_agent),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    struct FixedOracle(Option<DateTime<Utc>>);
    impl AgeOracle for FixedOracle {
        fn published(&self, _: Ecosystem, _: &str, _: &str) -> Result<Option<DateTime<Utc>>> {
            Ok(self.0)
        }
    }

    struct ErrOracle;
    impl AgeOracle for ErrOracle {
        fn published(&self, _: Ecosystem, _: &str, _: &str) -> Result<Option<DateTime<Utc>>> {
            Err(anyhow::anyhow!("network is down"))
        }
    }

    fn decider(
        oracle: impl AgeOracle + 'static,
        min_age_hours: u64,
        fail_on_missing: bool,
    ) -> Decider<dyn AgeOracle> {
        Decider {
            oracle: Box::new(oracle) as Box<dyn AgeOracle>,
            min_age: Duration::from_secs(min_age_hours * 3600),
            fail_on_missing,
            known_bad: None,
            typosquat: None,
        }
    }

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    #[test]
    fn too_new_is_denied_with_reason() {
        // Published 2h ago, cutoff = 168h (7d).
        let now = utc(2025, 1, 10);
        let pub_time = now - chrono::Duration::hours(2);
        let d = decider(FixedOracle(Some(pub_time)), 168, false);
        match d.decide(Ecosystem::Crates, "serde", "99.99.99", now) {
            Decision::Deny { reason } => {
                assert!(reason.contains("crates/serde@99.99.99"));
                assert!(reason.contains("2h ago"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn old_enough_is_allowed() {
        let now = utc(2025, 1, 10);
        let pub_time = now - chrono::Duration::days(30);
        let d = decider(FixedOracle(Some(pub_time)), 168, false);
        assert_eq!(
            d.decide(Ecosystem::Crates, "serde", "1.0.0", now),
            Decision::Allow
        );
    }

    #[test]
    fn unknown_publish_date_fails_open_by_default() {
        let d = decider(FixedOracle(None), 168, false);
        assert_eq!(
            d.decide(Ecosystem::Crates, "mystery", "0.1.0", utc(2025, 1, 1)),
            Decision::Allow
        );
    }

    #[test]
    fn unknown_publish_date_fails_closed_when_requested() {
        let d = decider(FixedOracle(None), 168, true);
        match d.decide(Ecosystem::Crates, "mystery", "0.1.0", utc(2025, 1, 1)) {
            Decision::Deny { reason } => {
                assert!(reason.contains("fail-on-missing"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn network_error_follows_fail_on_missing_flag() {
        // fail_on_missing=false → allow
        let d = decider(ErrOracle, 168, false);
        assert_eq!(
            d.decide(Ecosystem::Npm, "x", "1.0.0", utc(2025, 1, 1)),
            Decision::Allow
        );
        // fail_on_missing=true → deny
        let d = decider(ErrOracle, 168, true);
        assert!(matches!(
            d.decide(Ecosystem::Npm, "x", "1.0.0", utc(2025, 1, 1)),
            Decision::Deny { .. }
        ));
    }

    /// Fake `KnownBadOracle` for Decider-level tests.
    struct FixedBad(Option<Vec<String>>);
    impl crate::osv::KnownBadOracle for FixedBad {
        fn lookup(&self, _: Ecosystem, _: &str, _: &str) -> Result<Option<Vec<String>>> {
            Ok(self.0.clone())
        }
    }

    struct BadErr;
    impl crate::osv::KnownBadOracle for BadErr {
        fn lookup(&self, _: Ecosystem, _: &str, _: &str) -> Result<Option<Vec<String>>> {
            Err(anyhow::anyhow!("OSV down"))
        }
    }

    #[test]
    fn known_malicious_hard_denies_even_for_old_packages() {
        // Published 10 years ago — age filter would allow this.
        // But known-bad lookup returns a MAL id → hard deny.
        let now = utc(2025, 1, 10);
        let ancient = now - chrono::Duration::days(10 * 365);
        let mut d = decider(FixedOracle(Some(ancient)), 168, false);
        d.known_bad = Some(Box::new(FixedBad(Some(vec!["MAL-2025-1".into()]))));
        match d.decide(Ecosystem::Npm, "event-stream", "3.3.6", now) {
            Decision::Deny { reason } => {
                assert!(reason.contains("listed as malicious"));
                assert!(reason.contains("MAL-2025-1"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn known_bad_none_response_falls_through_to_age_check() {
        let now = utc(2025, 1, 10);
        let ancient = now - chrono::Duration::days(10 * 365);
        let mut d = decider(FixedOracle(Some(ancient)), 168, false);
        d.known_bad = Some(Box::new(FixedBad(None))); // clean
        assert_eq!(
            d.decide(Ecosystem::Npm, "safe", "1.0.0", now),
            Decision::Allow
        );
    }

    #[test]
    fn known_bad_lookup_error_falls_through() {
        // OSV downtime must never block developer installs on a
        // known-safe-enough package.
        let now = utc(2025, 1, 10);
        let ancient = now - chrono::Duration::days(10 * 365);
        let mut d = decider(FixedOracle(Some(ancient)), 168, false);
        d.known_bad = Some(Box::new(BadErr));
        assert_eq!(
            d.decide(Ecosystem::Npm, "safe", "1.0.0", now),
            Decision::Allow
        );
    }

    #[test]
    fn exactly_at_cutoff_is_allowed() {
        let now = utc(2025, 1, 10);
        // published exactly min_age ago
        let pub_time = now - chrono::Duration::hours(168);
        let d = decider(FixedOracle(Some(pub_time)), 168, false);
        assert_eq!(d.decide(Ecosystem::Crates, "x", "1", now), Decision::Allow);
    }
}
