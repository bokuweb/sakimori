//! Coalesce bursts of FS events for the same path.
//!
//! `npm install` tends to rewrite `package-lock.json` a few times in
//! rapid succession (parse → install → dedupe). Without debouncing
//! we'd run `deps check` 3× per install. The debouncer records
//! `(path, timestamp)` tuples and tells the caller which paths are now
//! "settled" (last change older than `window`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub struct Debouncer {
    window: Duration,
    pending: HashMap<PathBuf, Instant>,
}

impl Debouncer {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            pending: HashMap::new(),
        }
    }

    /// Record a change event for `path` at `now`.
    pub fn touch(&mut self, path: &Path, now: Instant) {
        self.pending.insert(path.to_path_buf(), now);
    }

    /// Drain paths whose last touch is older than `window` at `now`.
    pub fn drain_settled(&mut self, now: Instant) -> Vec<PathBuf> {
        let settled: Vec<PathBuf> = self
            .pending
            .iter()
            .filter_map(|(p, t)| {
                if now.duration_since(*t) >= self.window {
                    Some(p.clone())
                } else {
                    None
                }
            })
            .collect();
        for p in &settled {
            self.pending.remove(p);
        }
        settled
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_is_not_settled_until_window_elapses() {
        let mut d = Debouncer::new(Duration::from_millis(500));
        let t0 = Instant::now();
        d.touch(Path::new("/x"), t0);
        assert!(d.drain_settled(t0 + Duration::from_millis(400)).is_empty());
        assert_eq!(d.pending_len(), 1);
    }

    #[test]
    fn event_becomes_settled_after_window() {
        let mut d = Debouncer::new(Duration::from_millis(500));
        let t0 = Instant::now();
        d.touch(Path::new("/x"), t0);
        let out = d.drain_settled(t0 + Duration::from_millis(600));
        assert_eq!(out, vec![PathBuf::from("/x")]);
        assert_eq!(d.pending_len(), 0);
    }

    #[test]
    fn bursts_for_same_path_coalesce() {
        let mut d = Debouncer::new(Duration::from_millis(500));
        let t0 = Instant::now();
        d.touch(Path::new("/a"), t0);
        d.touch(Path::new("/a"), t0 + Duration::from_millis(100));
        d.touch(Path::new("/a"), t0 + Duration::from_millis(200));
        // Not settled at 400ms from last touch, still 300ms away.
        assert!(
            d.drain_settled(t0 + Duration::from_millis(500)).is_empty(),
            "expected burst to still be pending"
        );
        // Settled once window elapses from the *last* touch.
        let out = d.drain_settled(t0 + Duration::from_millis(800));
        assert_eq!(out, vec![PathBuf::from("/a")]);
    }

    #[test]
    fn different_paths_are_independent() {
        let mut d = Debouncer::new(Duration::from_millis(500));
        let t0 = Instant::now();
        d.touch(Path::new("/a"), t0);
        d.touch(Path::new("/b"), t0 + Duration::from_millis(400));
        let out = d.drain_settled(t0 + Duration::from_millis(600));
        assert_eq!(out, vec![PathBuf::from("/a")]);
        assert_eq!(d.pending_len(), 1);
    }
}
