//! cgroup v2 helper for confining the supervised process so that our
//! `cgroup/connect4` / `connect6` programs only see *its* network syscalls.
//!
//! Two construction modes:
//!
//! 1. [`Cgroup::create`] — the supervised-run case. We own a fresh cgroup at
//!    `/sys/fs/cgroup/sakimori.slice/<uuid>`, enrol the child into it via
//!    `pre_exec`, and rmdir it on Drop.
//! 2. [`Cgroup::observe_existing`] — the job-scoped daemon case. We discover
//!    the cgroup v2 path of an existing pid (typically the GitHub Actions
//!    runner's worker process) and attach the BPF programs *there*, without
//!    migrating anyone. cgroup v2 BPF programs cascade to descendants
//!    automatically, so every step the runner spawns from then on is
//!    observed. We don't own the dir, so Drop is a no-op.
//!
//! Linux-only; on other targets the type degrades to a no-op placeholder so
//! the rest of the crate can still compile for local development.

use std::path::{Path, PathBuf};

use anyhow::Result;

pub struct Cgroup {
    pub path: PathBuf,
    /// True if we created this cgroup and should rmdir it on Drop. False
    /// when we're attached to a cgroup someone else (systemd, GitHub
    /// Actions runner) owns — touching it then would break their
    /// accounting.
    owned: bool,
}

#[cfg(target_os = "linux")]
impl Cgroup {
    /// Create a fresh cgroup under `/sys/fs/cgroup/sakimori.slice/<id>`.
    /// Falls back to `/sys/fs/cgroup/sakimori-<id>` if the unified hierarchy
    /// is not writable (e.g. running as non-root in a dev container) — in
    /// that case the cgroup program simply won't see traffic, but the
    /// supervisor still works in audit/exec/file mode.
    pub fn create() -> Result<Self> {
        use anyhow::Context as _;

        let id = uuid::Uuid::new_v4().simple().to_string();
        let root = Path::new("/sys/fs/cgroup/sakimori.slice");
        let path = root.join(&id);

        if std::fs::create_dir_all(&path).is_ok() {
            return Ok(Self { path, owned: true });
        }

        // Fallback — try the unified root directly (single-cgroup systems).
        let fallback = Path::new("/sys/fs/cgroup").join(format!("sakimori-{id}"));
        std::fs::create_dir_all(&fallback)
            .with_context(|| format!("creating cgroup {}", fallback.display()))?;
        Ok(Self {
            path: fallback,
            owned: true,
        })
    }

    /// Attach to the existing cgroup v2 of `pid`. Reads
    /// `/proc/<pid>/cgroup`, parses the unified-hierarchy line (`0::<path>`),
    /// and returns a [`Cgroup`] pointing at `/sys/fs/cgroup<path>`.
    ///
    /// Refuses to return the root cgroup (`"/"`) unless `allow_root` is set
    /// — attaching to root means every process on the host fires our BPF
    /// programs, which is almost never what you want.
    pub fn observe_existing(pid: u32, allow_root: bool) -> Result<Self> {
        let cgroup_file = format!("/proc/{pid}/cgroup");
        let contents = std::fs::read_to_string(&cgroup_file)
            .map_err(|e| anyhow::anyhow!("reading {cgroup_file}: {e}"))?;
        let rel = parse_v2_cgroup_path(&contents).ok_or_else(|| {
            anyhow::anyhow!(
                "no cgroup v2 unified-hierarchy line (`0::<path>`) for pid {pid}; \
                 sakimori daemon requires cgroup v2 (cgroupv1-only hosts unsupported)"
            )
        })?;
        if rel == "/" && !allow_root {
            anyhow::bail!(
                "pid {pid} is in the root cgroup (`/`); attaching there would observe \
                 every process on the host. Run the daemon with --allow-root-cgroup \
                 if you really mean it, or pick a pid inside a namespaced cgroup."
            );
        }
        // Strip leading slash before joining so PathBuf::join doesn't
        // replace the prefix.
        let stripped = rel.trim_start_matches('/');
        let abs = Path::new("/sys/fs/cgroup").join(stripped);
        if !abs.is_dir() {
            anyhow::bail!(
                "resolved cgroup path {} for pid {pid} is not a directory; \
                 cgroup may have been removed",
                abs.display()
            );
        }
        Ok(Self {
            path: abs,
            owned: false,
        })
    }

    /// Add a pid to `cgroup.procs`. Writing a single pid is atomic.
    #[allow(dead_code)] // currently enrolled via pre_exec; kept for future use
    pub fn add_pid(&self, pid: u32) -> Result<()> {
        use std::io::Write as _;

        let procs = self.path.join("cgroup.procs");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&procs)
            .map_err(|e| anyhow::anyhow!("opening {}: {e}", procs.display()))?;
        write!(f, "{pid}").map_err(|e| anyhow::anyhow!("writing pid: {e}"))?;
        Ok(())
    }

    /// Open the cgroup dir as an O_PATH fd for `CgroupSockAddr::attach`.
    pub fn as_file(&self) -> Result<std::fs::File> {
        std::fs::File::open(&self.path)
            .map_err(|e| anyhow::anyhow!("opening cgroup dir {}: {e}", self.path.display()))
    }
}

#[cfg(target_os = "linux")]
impl Drop for Cgroup {
    fn drop(&mut self) {
        if !self.owned {
            return;
        }
        // Best-effort: rmdir fails if tasks remain, which is fine — the
        // kernel will reap it once the last process exits.
        let _ = std::fs::remove_dir(&self.path);
    }
}

#[cfg(not(target_os = "linux"))]
impl Cgroup {
    pub fn create() -> Result<Self> {
        Ok(Self {
            path: PathBuf::from("/tmp/sakimori-noop"),
            owned: false,
        })
    }

    pub fn observe_existing(_pid: u32, _allow_root: bool) -> Result<Self> {
        anyhow::bail!("Cgroup::observe_existing only runs on Linux")
    }

    pub fn add_pid(&self, _pid: u32) -> Result<()> {
        Ok(())
    }
}

/// Parse a `/proc/<pid>/cgroup` blob and return the cgroup v2 unified-
/// hierarchy path (the line starting with `0::`). Returns `None` if no such
/// line exists (cgroup v1-only host).
pub(crate) fn parse_v2_cgroup_path(contents: &str) -> Option<String> {
    for line in contents.lines() {
        // Format: <hierarchy-id>:<controllers>:<path>
        // v2 unified is identified by hierarchy-id == 0 and empty controllers,
        // i.e. lines starting with `0::`.
        if let Some(rest) = line.strip_prefix("0::") {
            return Some(rest.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unified_cgroup_line() {
        let sample = "12:pids:/user.slice\n0::/system.slice/runner.service\n";
        assert_eq!(
            parse_v2_cgroup_path(sample).as_deref(),
            Some("/system.slice/runner.service")
        );
    }

    #[test]
    fn parses_root_unified_cgroup() {
        assert_eq!(parse_v2_cgroup_path("0::/\n").as_deref(), Some("/"));
    }

    #[test]
    fn returns_none_for_v1_only_host() {
        let sample = "1:cpu:/user.slice\n2:memory:/user.slice\n";
        assert_eq!(parse_v2_cgroup_path(sample), None);
    }

    #[test]
    fn handles_unified_line_at_top() {
        let sample = "0::/foo/bar\n1:cpu:/legacy\n";
        assert_eq!(parse_v2_cgroup_path(sample).as_deref(), Some("/foo/bar"));
    }
}
