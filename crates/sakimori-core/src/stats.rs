//! Aggregate stats + sample buffer populated by the event drain loop.

use crate::events::Event;

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub observed: u64,
    pub denied: u64,
    pub lost: u64,
    pub samples: Vec<Event>,
}

/// How many samples per kind we keep in the buffer so a flood of one
/// kind (e.g. openat) doesn't crowd the others out of the UI.
pub const PER_KIND_CAP: usize = 64;
/// Overall cap on the sample buffer to bound memory.
pub const TOTAL_SAMPLE_CAP: usize = 256;

impl Stats {
    /// Merge an already-parsed event into the stats. Returns whether the
    /// event was kept in the sample buffer (for callers that want to know).
    ///
    /// Denied events are prioritised: if the per-kind or total cap is
    /// already full, an incoming denied event displaces the oldest
    /// non-denied sample (preferring same-kind) so the offending paths
    /// still surface in the report. Without this, a flood of benign
    /// events early in a run (e.g. pnpm install's first thousand
    /// openat()s) crowds out the actual offenders that fired the
    /// block-mode exit, leaving operators with "N denied" and no clue
    /// which paths.
    pub fn ingest(&mut self, ev: Event) -> bool {
        self.observed += 1;
        let denied = ev.denied();
        if denied {
            self.denied += 1;
        }
        let kind = ev.kind_tag();
        let same_kind = self.samples.iter().filter(|s| s.kind_tag() == kind).count();
        let kind_room = same_kind < PER_KIND_CAP;
        let total_room = self.samples.len() < TOTAL_SAMPLE_CAP;
        if kind_room && total_room {
            self.samples.push(ev);
            return true;
        }

        if denied {
            // Prefer evicting an older non-denied sample of the same
            // kind (keeps inter-kind ratios honest). If the total cap
            // is the binding constraint, fall back to any non-denied.
            let victim = self
                .samples
                .iter()
                .position(|s| !s.denied() && s.kind_tag() == kind)
                .or_else(|| {
                    if !total_room {
                        self.samples.iter().position(|s| !s.denied())
                    } else {
                        None
                    }
                });
            if let Some(idx) = victim {
                self.samples.remove(idx);
                self.samples.push(ev);
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(filename: &str, denied: bool) -> Event {
        Event::Open {
            pid: 1,
            uid: 0,
            comm: "x".into(),
            filename: filename.into(),
            flags: 0,
            denied,
        }
    }
    fn exec() -> Event {
        Event::Exec {
            pid: 2,
            uid: 0,
            comm: "x".into(),
            filename: "/bin/x".into(),
            argv0: "x".into(),
            denied: false,
        }
    }

    #[test]
    fn ingest_increments_observed_and_denied() {
        let mut s = Stats::default();
        s.ingest(open("/a", false));
        s.ingest(open("/b", true));
        s.ingest(exec());
        assert_eq!(s.observed, 3);
        assert_eq!(s.denied, 1);
        assert_eq!(s.samples.len(), 3);
    }

    #[test]
    fn per_kind_cap_prevents_flood_by_one_kind() {
        let mut s = Stats::default();
        for i in 0..1000 {
            s.ingest(open(&format!("/f{i}"), false));
        }
        // All 1000 are observed, but samples are capped.
        assert_eq!(s.observed, 1000);
        assert_eq!(s.samples.len(), PER_KIND_CAP);
        // Later-kind events can still get a sample slot up to their cap.
        s.ingest(exec());
        assert_eq!(s.samples.len(), PER_KIND_CAP + 1);
    }

    #[test]
    fn denied_events_displace_older_non_denied_when_kind_full() {
        // Simulate a flood of benign opens followed by a real deny.
        // Without prioritisation the deny would be dropped on the
        // floor and the report would say "1 denied" with no path.
        let mut s = Stats::default();
        for i in 0..PER_KIND_CAP {
            s.ingest(open(&format!("/benign/{i}"), false));
        }
        // Cap full — next benign drops.
        assert!(!s.ingest(open("/benign/extra", false)));
        // But a denied open displaces an older benign of the same kind.
        assert!(s.ingest(open("/etc/shadow", true)));
        assert_eq!(s.samples.len(), PER_KIND_CAP);
        assert!(
            s.samples
                .iter()
                .any(|e| matches!(e, Event::Open { filename, denied: true, .. } if filename == "/etc/shadow")),
            "denied sample must survive — operators need the offender path"
        );
        assert_eq!(s.denied, 1);
        assert_eq!(s.observed, PER_KIND_CAP as u64 + 2);
    }

    #[test]
    fn denied_events_dropped_only_when_no_non_denied_to_evict() {
        // Pathological: every sample slot is already a denied event.
        // We don't unbound memory, so the new denied event is dropped.
        let mut s = Stats::default();
        for i in 0..PER_KIND_CAP {
            s.ingest(open(&format!("/x/{i}"), true));
        }
        assert_eq!(s.samples.len(), PER_KIND_CAP);
        assert!(!s.ingest(open("/y", true)));
        // But the denied counter still increments — it tracks all
        // denials, regardless of whether the sample buffer kept one.
        assert_eq!(s.denied, PER_KIND_CAP as u64 + 1);
    }

    #[test]
    fn total_sample_cap_respected_across_kinds() {
        let mut s = Stats::default();
        // Fill with just-enough of each kind to exceed the total cap.
        for _ in 0..PER_KIND_CAP {
            s.ingest(open("/x", false));
        }
        for _ in 0..PER_KIND_CAP {
            s.ingest(exec());
        }
        // Connect samples then. open + exec = 2 * PER_KIND_CAP = 128.
        // TOTAL_SAMPLE_CAP = 256 > 128, so all connect can join.
        for _ in 0..PER_KIND_CAP {
            s.ingest(Event::Connect {
                pid: 3,
                uid: 0,
                comm: "x".into(),
                daddr: "1.2.3.4".into(),
                dport: 80,
                protocol: 6,
                denied: false,
                hostname: None,
            });
        }
        assert_eq!(s.samples.len(), 3 * PER_KIND_CAP);
        assert!(s.samples.len() <= TOTAL_SAMPLE_CAP);
    }
}
