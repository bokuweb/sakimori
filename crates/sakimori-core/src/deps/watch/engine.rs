//! The actual watch loop: takes a stream of "lockfile changed" events,
//! runs `deps check`, and posts notifications through a [`Notifier`].
//!
//! The loop is written as a pure-function iteration around a trait
//! (`EventSource`) so it can be driven either by real FS events or by
//! a deterministic in-memory source in tests.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::deps::{CheckArgs, CheckReport, check};

use super::{Debouncer, Notifier, ViolationHandler, format::format_violation};

/// A pluggable source of "this lockfile may have changed" events.
pub trait EventSource {
    /// Block for at most `timeout`, return zero or more paths that
    /// recently changed. Implementations should return promptly when
    /// there's nothing to report so the caller can run periodic work.
    fn poll(&mut self, timeout: Duration) -> Vec<PathBuf>;
}

pub struct WatchLoop<'a, S: EventSource, N: Notifier + ?Sized, H: ViolationHandler + ?Sized> {
    pub source: S,
    pub notifier: &'a N,
    pub handler: &'a H,
    pub debouncer: Debouncer,
    pub min_age: Duration,
    pub ignore: Vec<String>,
    pub cache_path: Option<PathBuf>,
    pub user_agent: String,
    pub tick: Duration,
    /// Test hook: clock source, so tests can advance time deterministically.
    pub now: fn() -> Instant,
}

impl<'a, S: EventSource, N: Notifier + ?Sized, H: ViolationHandler + ?Sized>
    WatchLoop<'a, S, N, H>
{
    /// Run exactly one iteration: poll the source, debounce, check any
    /// settled lockfiles, notify on violations. Returns how many
    /// notifications were emitted in this tick (useful for tests).
    pub fn tick_once(&mut self) -> Result<usize> {
        for p in self.source.poll(self.tick) {
            self.debouncer.touch(&p, (self.now)());
        }
        let settled = self.debouncer.drain_settled((self.now)());
        let mut emitted = 0;
        for lockfile in settled {
            emitted += self.check_and_notify(&lockfile)?;
        }
        Ok(emitted)
    }

    fn check_and_notify(&self, lockfile: &Path) -> Result<usize> {
        let lockfiles = [lockfile.to_path_buf()];
        let args = CheckArgs {
            lockfiles: &lockfiles,
            min_age: self.min_age,
            ignore: &self.ignore,
            fail_on_missing: false,
            cache: self.cache_path.as_deref(),
            user_agent: &self.user_agent,
        };
        let report: CheckReport = check(args)?;
        if report.violations == 0 {
            return Ok(0);
        }

        // Always try the handler first so the notification body can
        // report what (if anything) was done.
        let outcome = match self.handler.handle(lockfile, &report) {
            Ok(o) => o,
            Err(e) => super::action::HandlerOutcome {
                reverted: false,
                message: format!("handler error: {e:#}"),
            },
        };

        let mut n = format_violation(lockfile, &report);
        n.body.push('\n');
        n.body.push_str(&outcome.message);
        if outcome.reverted {
            n.title = format!("sakimori: reverted {}", short_name(lockfile));
        }
        self.notifier.notify(&n.title, &n.body)?;
        Ok(1)
    }
}

fn short_name(p: &Path) -> String {
    p.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("(lockfile)")
        .to_string()
}

/// An [`EventSource`] backed by the `notify` crate's FS-event stream.
pub struct NotifyEventSource {
    rx: std::sync::mpsc::Receiver<notify::Result<notify::Event>>,
    _watcher: Box<dyn notify::Watcher + Send>,
}

impl NotifyEventSource {
    pub fn new(roots: &[PathBuf]) -> Result<Self> {
        use notify::{RecommendedWatcher, RecursiveMode, Watcher};
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher: RecommendedWatcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            notify::Config::default(),
        )?;
        for r in roots {
            watcher.watch(r, RecursiveMode::Recursive)?;
        }
        Ok(Self {
            rx,
            _watcher: Box::new(watcher),
        })
    }
}

impl EventSource for NotifyEventSource {
    fn poll(&mut self, timeout: Duration) -> Vec<PathBuf> {
        use super::discover::LOCKFILE_NAMES;
        let mut out = Vec::new();
        let Ok(res) = self.rx.recv_timeout(timeout) else {
            return out;
        };
        let Ok(ev) = res else {
            return out;
        };
        // Only surface events on files we actually care about.
        for p in ev.paths {
            if p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| LOCKFILE_NAMES.contains(&s))
            {
                out.push(p);
            }
        }
        // Drain anything else queued up so a burst doesn't serialise
        // across many `poll` calls.
        while let Ok(Ok(ev)) = self.rx.try_recv() {
            for p in ev.paths {
                if p.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| LOCKFILE_NAMES.contains(&s))
                {
                    out.push(p);
                }
            }
        }
        out
    }
}

/// Silence unused-Arc warning when some consumers want atomic shared
/// ownership but the current type signature doesn't need it.
#[allow(dead_code)]
fn _assert_arc_usable() {
    let _: Arc<dyn Notifier + Send + Sync> = Arc::new(super::StdoutNotifier);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::watch::CollectingNotifier;
    use std::collections::VecDeque;

    // --- deterministic test fixtures -------------------------------------

    /// An `EventSource` that yields prearranged path lists on successive
    /// `poll()` calls.
    struct FakeSource {
        chunks: VecDeque<Vec<PathBuf>>,
    }
    impl EventSource for FakeSource {
        fn poll(&mut self, _timeout: Duration) -> Vec<PathBuf> {
            self.chunks.pop_front().unwrap_or_default()
        }
    }

    fn write_cargo_lock(dir: &Path) -> PathBuf {
        // A lockfile with zero registry deps — `deps check` will yield
        // a CheckReport with checked=0, violations=0 (no network needed).
        let p = dir.join("Cargo.lock");
        std::fs::write(&p, "version = 3\n").unwrap();
        p
    }

    fn tmpdir(tag: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("sakimori-watch-engine-{tag}-{id}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn clean_report_does_not_notify() {
        let d = tmpdir("clean");
        let lf = write_cargo_lock(&d);

        let notifier = CollectingNotifier::new();
        let handler = crate::deps::watch::NotifyOnly;
        let base = Instant::now();
        let mut wl = WatchLoop::<FakeSource, CollectingNotifier, crate::deps::watch::NotifyOnly> {
            source: FakeSource {
                chunks: vec![vec![lf.clone()]].into(),
            },
            notifier: &notifier,
            handler: &handler,
            debouncer: Debouncer::new(Duration::from_millis(0)),
            min_age: Duration::from_secs(0),
            ignore: vec![],
            cache_path: None,
            user_agent: "sakimori-test".into(),
            tick: Duration::from_millis(0),
            now: Instant::now,
        };
        let emitted = wl.tick_once().unwrap();
        assert_eq!(emitted, 0);
        assert!(notifier.take().is_empty());
        let _ = base;
    }

    #[test]
    fn touches_below_window_stay_pending_across_ticks() {
        let d = tmpdir("window");
        let lf = write_cargo_lock(&d);

        let notifier = CollectingNotifier::new();
        let handler = crate::deps::watch::NotifyOnly;
        let mut wl = WatchLoop::<FakeSource, CollectingNotifier, crate::deps::watch::NotifyOnly> {
            source: FakeSource {
                chunks: vec![vec![lf.clone()], vec![], vec![]].into(),
            },
            notifier: &notifier,
            handler: &handler,
            // Very long debounce — events should never settle in this test.
            debouncer: Debouncer::new(Duration::from_secs(3600)),
            min_age: Duration::from_secs(0),
            ignore: vec![],
            cache_path: None,
            user_agent: "sakimori-test".into(),
            tick: Duration::from_millis(0),
            now: Instant::now,
        };
        for _ in 0..3 {
            let emitted = wl.tick_once().unwrap();
            assert_eq!(emitted, 0);
        }
        // Even though the lockfile was "touched", the window never
        // elapsed, so no check / no notification.
        assert!(notifier.take().is_empty());
    }
}
