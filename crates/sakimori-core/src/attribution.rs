//! Per-event source attribution — walk the PPid chain of an event's
//! pid and find the package manager (or other interesting root)
//! that ultimately spawned it.
//!
//! Why: today the audit log says "pid 1234 (sh) connected to evil.example".
//! The interesting fact is "pid 1234 was spawned by `npm install
//! foo@1.2.3`'s postinstall script". With attribution attached, that
//! shows up directly in the JSON log and the step summary, no manual
//! tree-walking required by the operator.
//!
//! Architecture: a [`Lookup`] trait abstracts the OS proc-table read so
//! the logic is fully testable with a fake. Linux ships [`ProcFs`]
//! reading `/proc/<pid>/{status,cmdline}`. Other targets get [`Null`]
//! and [`attribute`] returns `None` — non-Linux supervisors (Windows
//! ETW) keep working unchanged; attribution is a Linux-first add-on
//! we can extend later.
//!
//! Edge cases the design accepts:
//! - The event's pid may have **already exited** by the time the
//!   userspace drain reads it from the ringbuf. `cmdline` returns
//!   `None`, attribution yields `None`. Best-effort by design.
//! - A pid whose parent reparented to PID 1 (orphan) loses the
//!   chain — same as above.
//! - Walk depth is capped at [`MAX_CHAIN_DEPTH`] to avoid pathological
//!   loops if `/proc` is in a weird state.

use serde::{Deserialize, Serialize};

/// How far up the PPid chain we'll walk before giving up. 32 is
/// well past anything CI will ever produce — bash → make → cargo →
/// rustc rarely exceeds 8 — and short enough that pathological
/// `/proc` reads can't stall the drain task.
pub const MAX_CHAIN_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
    Cargo,
    Pip,
    Uv,
    Poetry,
    Dotnet,
    Go,
    Maven,
    Gradle,
    Bundler,
    Composer,
}

impl PackageManager {
    /// Match against the basename of an `argv[0]` (after stripping
    /// any trailing version suffix like `pip3.11`). Returns `None`
    /// for anything we don't know how to attribute.
    pub fn from_argv0(argv0: &str) -> Option<Self> {
        // Take basename — `/usr/bin/npm` and `npm` should both match.
        let base = argv0.rsplit('/').next().unwrap_or(argv0);
        // Strip trailing version digits/dots: `pip3` → `pip`,
        // `pip3.11` → `pip`. Conservative: only digits and dots
        // after a recognised prefix.
        let stem = trim_version_suffix(base);
        let pm = match stem {
            "npm" => Self::Npm,
            "pnpm" => Self::Pnpm,
            "yarn" => Self::Yarn,
            "cargo" => Self::Cargo,
            "pip" => Self::Pip,
            "uv" => Self::Uv,
            "poetry" => Self::Poetry,
            "dotnet" => Self::Dotnet,
            "go" => Self::Go,
            "mvn" | "maven" => Self::Maven,
            "gradle" => Self::Gradle,
            "bundle" | "bundler" => Self::Bundler,
            "composer" => Self::Composer,
            _ => return None,
        };
        Some(pm)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Cargo => "cargo",
            Self::Pip => "pip",
            Self::Uv => "uv",
            Self::Poetry => "poetry",
            Self::Dotnet => "dotnet",
            Self::Go => "go",
            Self::Maven => "maven",
            Self::Gradle => "gradle",
            Self::Bundler => "bundler",
            Self::Composer => "composer",
        }
    }
}

fn trim_version_suffix(name: &str) -> &str {
    // `pip3` → `pip`, `pip3.11` → `pip`. Walk back until we hit a
    // non-digit, non-dot. We only do this for short names; `cargo`
    // doesn't end in a digit so it's a no-op there.
    let bytes = name.as_bytes();
    let mut end = bytes.len();
    while end > 0 {
        let b = bytes[end - 1];
        if b.is_ascii_digit() || b == b'.' {
            end -= 1;
        } else {
            break;
        }
    }
    if end == 0 {
        // All-numeric name — implausible; leave as-is.
        return name;
    }
    &name[..end]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcInfo {
    pub pid: u32,
    /// `argv[0]` as the kernel saw it (could be a full path or just
    /// a basename, depending on how the process was exec'd).
    pub argv0: String,
    /// Full argv joined by space — what a human would recognise as
    /// "the command line".
    pub argv: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attribution {
    /// Walk from the event's pid up the PPid chain. First entry is
    /// the event's own pid; subsequent entries are ancestors.
    /// Truncated when `cmdline` reads start failing or at
    /// [`MAX_CHAIN_DEPTH`].
    pub chain: Vec<ProcInfo>,
    /// First chain entry whose argv0 basename matches a
    /// [`PackageManager`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_manager: Option<PackageManager>,
    /// Joined argv of the package-manager process — the headline
    /// "this came from `npm install foo@1.2.3`" string. `None`
    /// when no package manager was found in the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_argv: Option<String>,
}

/// Abstracts the OS proc-table reads so [`attribute`] can be
/// covered by deterministic tests.
pub trait Lookup {
    /// Parent pid for `pid`, or `None` if the process has gone (or
    /// is PID 1 — the chain ends there).
    fn parent(&self, pid: u32) -> Option<u32>;
    /// `(argv0, full_argv_joined)` for `pid`, or `None` if the
    /// process is gone / unreadable.
    fn cmdline(&self, pid: u32) -> Option<(String, String)>;
}

/// No-op lookup — always returns `None`. Used on platforms without a
/// proc filesystem so `attribute` is callable everywhere.
pub struct Null;
impl Lookup for Null {
    fn parent(&self, _: u32) -> Option<u32> {
        None
    }
    fn cmdline(&self, _: u32) -> Option<(String, String)> {
        None
    }
}

/// Walk `pid` up the PPid chain and produce an [`Attribution`].
///
/// Returns `None` only if we couldn't read the event pid itself
/// (the most useful "we know nothing" signal). Otherwise we always
/// return at least a one-entry `chain` with whatever we did get.
///
/// Stops when:
/// - `lookup.parent` returns `None` (orphan / kernel thread / PID 1),
/// - the chain hits [`MAX_CHAIN_DEPTH`],
/// - or the next pid is in `stop_pids` (typically the supervisor's
///   own pid — keeps the chain from including sakimori itself).
pub fn attribute(pid: u32, lookup: &dyn Lookup, stop_pids: &[u32]) -> Option<Attribution> {
    let (argv0, argv) = lookup.cmdline(pid)?;
    let mut chain = vec![ProcInfo {
        pid,
        argv0: argv0.clone(),
        argv,
    }];
    let mut package_manager = PackageManager::from_argv0(&argv0);

    let mut cur = pid;
    for _ in 0..MAX_CHAIN_DEPTH {
        let parent = match lookup.parent(cur) {
            Some(p) if !stop_pids.contains(&p) && p != 0 => p,
            _ => break,
        };
        let (parg0, parg) = match lookup.cmdline(parent) {
            Some(c) => c,
            // Parent vanished mid-walk — record that we tried, but
            // don't synthesise. The chain we have is still useful.
            None => break,
        };
        if package_manager.is_none() {
            package_manager = PackageManager::from_argv0(&parg0);
        }
        chain.push(ProcInfo {
            pid: parent,
            argv0: parg0,
            argv: parg,
        });
        cur = parent;
    }

    let root_argv = package_manager.and_then(|pm| {
        chain
            .iter()
            .find(|e| PackageManager::from_argv0(&e.argv0) == Some(pm))
            .map(|e| e.argv.clone())
    });

    Some(Attribution {
        chain,
        package_manager,
        root_argv,
    })
}

// --- Linux /proc reader ----------------------------------------------------

#[cfg(target_os = "linux")]
pub use linux::ProcFs;

#[cfg(target_os = "linux")]
mod linux {
    use super::Lookup;
    use std::fs;

    /// Reads `/proc/<pid>/{status,cmdline}` to satisfy [`Lookup`].
    /// All errors are folded into `None` — attribution is always
    /// best-effort. Designed to be cheap enough to call on every
    /// event in the drain loop; reads are sequential, no blocking
    /// network or sync IO beyond procfs.
    #[derive(Default)]
    pub struct ProcFs;

    impl ProcFs {
        pub fn new() -> Self {
            Self
        }
    }

    impl Lookup for ProcFs {
        fn parent(&self, pid: u32) -> Option<u32> {
            let text = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("PPid:") {
                    return rest.trim().parse().ok();
                }
            }
            None
        }

        fn cmdline(&self, pid: u32) -> Option<(String, String)> {
            let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
            // /proc/<pid>/cmdline is NUL-separated, with a trailing
            // NUL. Split, trim empties, decode as UTF-8 lossy.
            let parts: Vec<String> = raw
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            if parts.is_empty() {
                // Kernel threads have an empty cmdline — fall back
                // to comm so the chain entry isn't blank. Slight
                // correctness loss (comm is truncated to 15 chars)
                // but better than dropping the entry.
                let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
                let comm = comm.trim().to_string();
                return Some((comm.clone(), comm));
            }
            let argv0 = parts[0].clone();
            let argv = parts.join(" ");
            Some((argv0, argv))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Lookup backed by a static map — perfect for chain-walking tests.
    #[derive(Default)]
    struct FakeLookup {
        parents: HashMap<u32, u32>,
        cmdlines: HashMap<u32, (String, String)>,
    }
    impl FakeLookup {
        fn add(&mut self, pid: u32, parent: Option<u32>, argv0: &str, argv: &str) {
            if let Some(p) = parent {
                self.parents.insert(pid, p);
            }
            self.cmdlines
                .insert(pid, (argv0.to_string(), argv.to_string()));
        }
    }
    impl Lookup for FakeLookup {
        fn parent(&self, pid: u32) -> Option<u32> {
            self.parents.get(&pid).copied()
        }
        fn cmdline(&self, pid: u32) -> Option<(String, String)> {
            self.cmdlines.get(&pid).cloned()
        }
    }

    #[test]
    fn from_argv0_recognises_basename_and_strips_path() {
        assert_eq!(PackageManager::from_argv0("npm"), Some(PackageManager::Npm));
        assert_eq!(
            PackageManager::from_argv0("/usr/bin/npm"),
            Some(PackageManager::Npm)
        );
        assert_eq!(
            PackageManager::from_argv0("/opt/cargo/bin/cargo"),
            Some(PackageManager::Cargo)
        );
        assert_eq!(PackageManager::from_argv0("bash"), None);
    }

    #[test]
    fn from_argv0_strips_pip_version_suffix() {
        assert_eq!(
            PackageManager::from_argv0("pip3"),
            Some(PackageManager::Pip)
        );
        assert_eq!(
            PackageManager::from_argv0("pip3.11"),
            Some(PackageManager::Pip)
        );
        assert_eq!(
            PackageManager::from_argv0("/usr/local/bin/pip3.12"),
            Some(PackageManager::Pip)
        );
    }

    #[test]
    fn attribute_walks_chain_and_finds_package_manager() {
        let mut f = FakeLookup::default();
        // pid 100 (curl) ← 99 (sh) ← 98 (node, postinstall script)
        // ← 97 (npm install left-pad@1.0.0) ← 1
        f.add(100, Some(99), "curl", "curl https://evil.example");
        f.add(99, Some(98), "sh", "sh -c curl …");
        f.add(98, Some(97), "node", "node /tmp/postinstall.js");
        f.add(97, Some(1), "npm", "npm install left-pad@1.0.0");
        f.add(1, None, "init", "/sbin/init");

        let attr = attribute(100, &f, &[]).expect("event pid is readable");
        assert_eq!(attr.chain.len(), 5);
        assert_eq!(attr.chain[0].argv0, "curl");
        assert_eq!(attr.chain[3].argv0, "npm");
        assert_eq!(attr.package_manager, Some(PackageManager::Npm));
        assert_eq!(
            attr.root_argv.as_deref(),
            Some("npm install left-pad@1.0.0")
        );
    }

    #[test]
    fn attribute_returns_none_when_event_pid_already_gone() {
        // Process exited between ringbuf push and our drain. The
        // attribution layer must shrug rather than abort the drain.
        let f = FakeLookup::default();
        assert!(attribute(42, &f, &[]).is_none());
    }

    #[test]
    fn attribute_with_no_package_manager_returns_chain_but_no_pm() {
        let mut f = FakeLookup::default();
        f.add(50, Some(1), "bash", "bash");
        f.add(1, None, "init", "init");
        let a = attribute(50, &f, &[]).unwrap();
        assert_eq!(a.chain.len(), 2);
        assert!(a.package_manager.is_none());
        assert!(a.root_argv.is_none());
    }

    #[test]
    fn attribute_stops_at_supervisor_pid() {
        // The sakimori supervisor itself shouldn't appear in the
        // chain — pass its pid in `stop_pids` so we cut the walk.
        let mut f = FakeLookup::default();
        f.add(200, Some(150), "make", "make test");
        f.add(150, Some(99), "sakimori", "sakimori run -- make test");
        f.add(99, Some(1), "bash", "bash");
        f.add(1, None, "init", "init");
        let a = attribute(200, &f, &[150]).unwrap();
        // make is included; sakimori / bash / init are not.
        assert_eq!(a.chain.len(), 1);
        assert_eq!(a.chain[0].argv0, "make");
    }

    #[test]
    fn attribute_caps_walk_at_max_depth() {
        // Synthesise a chain longer than MAX_CHAIN_DEPTH to make
        // sure we don't loop forever or blow the stack.
        let mut f = FakeLookup::default();
        let depth = MAX_CHAIN_DEPTH + 10;
        for i in 0..depth {
            let pid = (i + 1) as u32;
            let parent = if i + 1 < depth {
                Some((i + 2) as u32)
            } else {
                None
            };
            f.add(pid, parent, "p", "p");
        }
        let a = attribute(1, &f, &[]).unwrap();
        // chain[0] is the event pid itself, then up to MAX_CHAIN_DEPTH
        // ancestors. Total upper bound: MAX_CHAIN_DEPTH + 1.
        assert!(a.chain.len() <= MAX_CHAIN_DEPTH + 1);
    }

    #[test]
    fn root_argv_picks_first_pm_found_walking_up() {
        // When two package managers are nested (e.g. cargo invoked
        // from a make rule, then make invoked from a pnpm script),
        // the *closest to the event* wins — that's the one whose
        // postinstall actually opened the connection.
        let mut f = FakeLookup::default();
        f.add(10, Some(9), "rustc", "rustc foo.rs");
        f.add(9, Some(8), "cargo", "cargo build");
        f.add(8, Some(7), "make", "make");
        f.add(7, Some(1), "pnpm", "pnpm run build");
        f.add(1, None, "init", "init");

        let a = attribute(10, &f, &[]).unwrap();
        // cargo is closer to rustc than pnpm, so cargo wins.
        assert_eq!(a.package_manager, Some(PackageManager::Cargo));
        assert_eq!(a.root_argv.as_deref(), Some("cargo build"));
    }

    #[test]
    fn null_lookup_always_returns_none() {
        let l = Null;
        assert!(l.parent(1).is_none());
        assert!(l.cmdline(1).is_none());
        assert!(attribute(1, &l, &[]).is_none());
    }

    #[test]
    fn trim_version_suffix_handles_edge_cases() {
        assert_eq!(trim_version_suffix("pip"), "pip");
        assert_eq!(trim_version_suffix("pip3"), "pip");
        assert_eq!(trim_version_suffix("pip3.11"), "pip");
        assert_eq!(trim_version_suffix("npm"), "npm");
        // All-digit name — leave alone (we'd otherwise return "")
        assert_eq!(trim_version_suffix("123"), "123");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn procfs_reads_self_and_finds_a_known_ancestor() {
        // Exercise the real ProcFs against this test process.
        // We don't know our exact ppid chain but we know:
        //  - cmdline for self is non-empty
        //  - parent(self) is something > 1
        let pf = linux::ProcFs::new();
        let me = std::process::id();
        let (argv0, argv) = pf.cmdline(me).expect("self cmdline readable");
        assert!(!argv0.is_empty());
        assert!(!argv.is_empty());
        let parent = pf.parent(me).expect("self has a parent");
        assert!(parent > 0);
    }
}
