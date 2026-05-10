//! cgroup v2 helper for confining the supervised process so that our
//! `cgroup/connect4` / `connect6` programs only see *its* network syscalls.
//!
//! Layout:
//!     /sys/fs/cgroup/sakimori.slice/<session-uuid>
//!
//! The path is both where we attach the BPF program (via its O_PATH fd) and
//! where we append the child's PID to `cgroup.procs`.
//!
//! Linux-only; on other targets the type degrades to a no-op placeholder so
//! the rest of the crate can still compile for local development.

use std::path::{Path, PathBuf};

use anyhow::Result;

pub struct Cgroup {
    pub path: PathBuf,
}

#[cfg(target_os = "linux")]
impl Cgroup {
    /// Create a fresh cgroup under `/sys/fs/cgroup/sakimori.slice/<id>`.
    /// Falls back to `$TMPDIR/sakimori-<id>` if the unified hierarchy is not
    /// writable (e.g. running as non-root in a dev container) — in that case
    /// the cgroup program simply won't see traffic, but the supervisor still
    /// works in audit/exec/file mode.
    pub fn create() -> Result<Self> {
        use anyhow::Context as _;

        let id = uuid::Uuid::new_v4().simple().to_string();
        let root = Path::new("/sys/fs/cgroup/sakimori.slice");
        let path = root.join(&id);

        if std::fs::create_dir_all(&path).is_ok() {
            return Ok(Self { path });
        }

        // Fallback — try the unified root directly (single-cgroup systems).
        let fallback = Path::new("/sys/fs/cgroup").join(format!("sakimori-{id}"));
        std::fs::create_dir_all(&fallback)
            .with_context(|| format!("creating cgroup {}", fallback.display()))?;
        Ok(Self { path: fallback })
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
        })
    }

    pub fn add_pid(&self, _pid: u32) -> Result<()> {
        Ok(())
    }
}
