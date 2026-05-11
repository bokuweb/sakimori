//! Install / uninstall `sakimori proxy start` as a user-level
//! background service, so `install-gate` users don't have to
//! remember to launch the proxy manually in a spare terminal.
//!
//! Two backends:
//!
//! - **macOS** — writes a launchd plist under
//!   `~/Library/LaunchAgents/com.sakimori.proxy.plist` and runs
//!   `launchctl bootstrap gui/<uid>` on it. `launchctl bootout`
//!   reverses it.
//! - **Linux** — writes a systemd user unit under
//!   `~/.config/systemd/user/sakimori-proxy.service` and enables
//!   it via `systemctl --user enable --now`.
//!
//! - **Windows** — generates a Task Scheduler XML and installs it
//!   with `schtasks.exe /Create /TN sakimori-proxy /XML <path>`.
//!   Runs at logon with the user's own token (no service account /
//!   UAC prompt).
//!
//! The rendered unit/plist text is **pure** and snapshot-testable;
//! the IO (writing files, shelling out to `launchctl`/`systemctl`) is
//! in one thin function at the end of this module.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Rendered daemon artefacts for the given invocation. Returned as
/// strings so the caller can write-and-shell-out, and so we can snapshot
/// the content in unit tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonPlan {
    pub label: String,
    pub unit_path: PathBuf,
    pub unit_body: String,
    /// Exact shell command that activates the unit (for the install
    /// confirmation print).
    pub activate_command: String,
    /// Exact shell command that deactivates the unit (for `uninstall`).
    pub deactivate_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonBackend {
    Launchd,
    SystemdUser,
    /// Windows Task Scheduler. Installed via `schtasks.exe /Create
    /// /XML <path>`; runs at user logon with the user's own token.
    WindowsTaskScheduler,
}

impl DaemonBackend {
    /// Best guess from the current OS. Callers can override.
    pub fn detect() -> Option<Self> {
        #[cfg(target_os = "macos")]
        {
            return Some(DaemonBackend::Launchd);
        }
        #[cfg(target_os = "linux")]
        {
            return Some(DaemonBackend::SystemdUser);
        }
        #[cfg(target_os = "windows")]
        {
            return Some(DaemonBackend::WindowsTaskScheduler);
        }
        #[allow(unreachable_code)]
        None
    }
}

/// Inputs needed to render a daemon unit. `binary_path` should be an
/// absolute path — the daemon has no shell-like `$PATH` lookup.
#[derive(Debug, Clone)]
pub struct DaemonInputs {
    pub binary_path: PathBuf,
    pub listen: SocketAddr,
    /// Same grammar as the `--min-age` CLI flag.
    pub min_age: String,
    /// `$HOME` — used to locate the user's LaunchAgents / systemd dir.
    pub home: PathBuf,
}

pub fn render(backend: DaemonBackend, inp: &DaemonInputs) -> DaemonPlan {
    match backend {
        DaemonBackend::Launchd => render_launchd(inp),
        DaemonBackend::SystemdUser => render_systemd(inp),
        DaemonBackend::WindowsTaskScheduler => render_windows_task(inp),
    }
}

const LABEL: &str = "com.sakimori.proxy";

fn render_launchd(inp: &DaemonInputs) -> DaemonPlan {
    let unit_path = inp
        .home
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"));
    let log_dir = inp.home.join("Library/Logs/sakimori");
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>proxy</string>
        <string>start</string>
        <string>--listen</string>
        <string>{listen}</string>
        <string>--min-age</string>
        <string>{min_age}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{logs}/proxy.out.log</string>
    <key>StandardErrorPath</key>
    <string>{logs}/proxy.err.log</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#,
        bin = inp.binary_path.display(),
        listen = inp.listen,
        min_age = inp.min_age,
        logs = log_dir.display(),
    );
    DaemonPlan {
        label: LABEL.into(),
        unit_path: unit_path.clone(),
        unit_body: body,
        // `bootstrap gui/<uid>` is the modern (macOS 10.10+)
        // equivalent of `launchctl load`; we keep the command in the
        // install hint so the user can re-run it manually if needed.
        activate_command: format!(
            "launchctl bootstrap gui/$(id -u) {unit}",
            unit = unit_path.display()
        ),
        deactivate_command: format!(
            "launchctl bootout gui/$(id -u)/{LABEL}; rm {unit}",
            unit = unit_path.display()
        ),
    }
}

fn render_systemd(inp: &DaemonInputs) -> DaemonPlan {
    let unit_path = inp
        .home
        .join(".config/systemd/user")
        .join("sakimori-proxy.service");
    let body = format!(
        r#"[Unit]
Description=sakimori registry proxy (minimumReleaseAge enforcement)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin} proxy start --listen {listen} --min-age {min_age}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"#,
        bin = inp.binary_path.display(),
        listen = inp.listen,
        min_age = inp.min_age,
    );
    DaemonPlan {
        label: "sakimori-proxy.service".into(),
        unit_path,
        unit_body: body,
        activate_command:
            "systemctl --user daemon-reload && systemctl --user enable --now sakimori-proxy.service"
                .into(),
        deactivate_command: "systemctl --user disable --now sakimori-proxy.service".into(),
    }
}

fn render_windows_task(inp: &DaemonInputs) -> DaemonPlan {
    // Task Scheduler XML schema 1.4. This task:
    //
    // - registers at user logon (no admin / service account needed),
    // - runs with the user's own token (InteractLogonTrigger) so the
    //   proxy has access to the same cert directories install-ca /
    //   install-gate wrote under %LOCALAPPDATA%,
    // - restarts on failure up to 99 times with a short delay — the
    //   practical equivalent of systemd's `Restart=on-failure`,
    // - hides the console window (no flashing terminal on login).
    //
    // The XML is stored next to the other config files we manage so
    // `uninstall-daemon` knows where to find it without re-deriving
    // from scratch.
    let unit_path = inp
        .home
        .join("AppData/Local/sakimori")
        .join("sakimori-proxy.task.xml");
    let exe = inp.binary_path.display().to_string();
    // Task Scheduler XML is picky about escaping; & and <, > must be
    // entity-encoded. Our inputs are well-typed paths and numeric
    // ports so the only interesting escape is `&` inside a pathname
    // like `C:\Program Files & Co\…`.
    let exe_xml = xml_escape(&exe);
    let args_xml = xml_escape(&format!(
        "proxy start --listen {} --min-age {}",
        inp.listen, inp.min_age
    ));
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>sakimori registry proxy (minimumReleaseAge enforcement)</Description>
    <URI>\sakimori-proxy</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>99</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe_xml}</Command>
      <Arguments>{args_xml}</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    );
    DaemonPlan {
        label: "sakimori-proxy".into(),
        unit_path: unit_path.clone(),
        unit_body: body,
        // `schtasks.exe /Create /XML` imports the XML literally. `/F`
        // forces overwrite so re-running install-daemon is idempotent.
        activate_command: format!(
            "schtasks.exe /Create /TN sakimori-proxy /XML \"{}\" /F",
            unit_path.display()
        ),
        deactivate_command: "schtasks.exe /Delete /TN sakimori-proxy /F".into(),
    }
}

/// Minimal XML attribute-value / text-body escaper. Task Scheduler
/// XML is UTF-16 and picky, so only the XML-critical five get
/// encoded.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Best-effort absolute path to the current binary. Callers should
/// pass this into [`DaemonInputs::binary_path`] so the daemon unit
/// doesn't need `$PATH`.
pub fn current_exe_canonical() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
}

/// Write the unit body to `plan.unit_path`, creating parent
/// directories as needed. Idempotent and doesn't try to run the
/// activation command — the caller does that after inspecting
/// `plan.activate_command`.
pub fn write_unit(plan: &DaemonPlan) -> std::io::Result<()> {
    if let Some(parent) = plan.unit_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&plan.unit_path, &plan.unit_body)
}

pub fn remove_unit(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> DaemonInputs {
        DaemonInputs {
            binary_path: PathBuf::from("/opt/sakimori/bin/sakimori"),
            listen: "127.0.0.1:8910".parse().unwrap(),
            min_age: "7d".into(),
            home: PathBuf::from("/Users/example"),
        }
    }

    #[test]
    fn launchd_plist_has_required_keys_and_correct_label() {
        let plan = render(DaemonBackend::Launchd, &inputs());
        assert_eq!(plan.label, "com.sakimori.proxy");
        assert!(plan.unit_body.contains("<key>Label</key>"));
        assert!(
            plan.unit_body
                .contains("<string>com.sakimori.proxy</string>")
        );
        assert!(
            plan.unit_body
                .contains("<string>/opt/sakimori/bin/sakimori</string>")
        );
        assert!(plan.unit_body.contains("<string>--listen</string>"));
        assert!(plan.unit_body.contains("<string>127.0.0.1:8910</string>"));
        assert!(plan.unit_body.contains("<key>KeepAlive</key>"));
        assert!(plan.unit_body.contains("<key>RunAtLoad</key>"));
        assert!(
            plan.unit_path
                .ends_with("Library/LaunchAgents/com.sakimori.proxy.plist")
        );
        assert!(plan.activate_command.contains("launchctl bootstrap"));
        assert!(plan.deactivate_command.contains("launchctl bootout"));
    }

    #[test]
    fn systemd_unit_is_user_scoped_and_restart_on_failure() {
        let plan = render(DaemonBackend::SystemdUser, &inputs());
        assert!(plan.unit_body.starts_with("[Unit]"));
        assert!(plan.unit_body.contains(
            "ExecStart=/opt/sakimori/bin/sakimori proxy start --listen 127.0.0.1:8910 --min-age 7d"
        ));
        assert!(plan.unit_body.contains("Restart=on-failure"));
        // User scope — must NOT use multi-user.target.
        assert!(plan.unit_body.contains("WantedBy=default.target"));
        assert!(!plan.unit_body.contains("multi-user.target"));
        assert!(
            plan.unit_path
                .ends_with(".config/systemd/user/sakimori-proxy.service")
        );
        assert!(plan.activate_command.contains("systemctl --user"));
        assert!(plan.deactivate_command.contains("systemctl --user"));
    }

    #[test]
    fn windows_task_xml_is_schema_v1_4_and_logon_triggered() {
        let mut inp = inputs();
        inp.binary_path = PathBuf::from(r"C:\Program Files\sakimori\sakimori.exe");
        inp.home = PathBuf::from(r"C:\Users\example");
        let plan = render(DaemonBackend::WindowsTaskScheduler, &inp);
        assert_eq!(plan.label, "sakimori-proxy");
        assert!(
            plan.unit_body
                .starts_with("<?xml version=\"1.0\" encoding=\"UTF-16\"?>")
        );
        assert!(plan.unit_body.contains("<Task version=\"1.4\""));
        assert!(plan.unit_body.contains("<LogonTrigger>"));
        assert!(
            plan.unit_body
                .contains("<RunLevel>LeastPrivilege</RunLevel>")
        );
        assert!(plan.unit_body.contains("<RestartOnFailure>"));
        assert!(
            plan.unit_body
                .contains(r"C:\Program Files\sakimori\sakimori.exe")
        );
        assert!(
            plan.unit_body
                .contains("proxy start --listen 127.0.0.1:8910 --min-age 7d")
        );
        // Unit file lives under %LOCALAPPDATA% where our other config goes.
        assert!(
            plan.unit_path
                .ends_with("AppData/Local/sakimori/sakimori-proxy.task.xml")
        );
        assert!(plan.activate_command.contains("schtasks.exe /Create"));
        assert!(plan.deactivate_command.contains("schtasks.exe /Delete"));
    }

    #[test]
    fn xml_escape_handles_ampersand_and_angle_brackets() {
        // Ampersands appear in paths like `C:\Program Files & Co\...`.
        assert_eq!(xml_escape("a & b"), "a &amp; b");
        assert_eq!(xml_escape("<foo>"), "&lt;foo&gt;");
        assert_eq!(xml_escape("\"quoted\""), "&quot;quoted&quot;");
        // Plain ASCII passes through byte-for-byte.
        assert_eq!(xml_escape("plain/path:123"), "plain/path:123");
    }

    #[test]
    fn different_listen_address_shows_up_in_unit() {
        let mut inp = inputs();
        inp.listen = "0.0.0.0:19999".parse().unwrap();
        let plist = render(DaemonBackend::Launchd, &inp);
        let unit = render(DaemonBackend::SystemdUser, &inp);
        let task = render(DaemonBackend::WindowsTaskScheduler, &inp);
        assert!(plist.unit_body.contains("0.0.0.0:19999"));
        assert!(unit.unit_body.contains("0.0.0.0:19999"));
        assert!(task.unit_body.contains("0.0.0.0:19999"));
    }

    #[test]
    fn write_and_remove_unit_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("sakimori-daemon-test-{}", std::process::id()));
        let mut inp = inputs();
        inp.home = tmp.clone();
        let plan = render(DaemonBackend::SystemdUser, &inp);

        write_unit(&plan).expect("write");
        assert!(plan.unit_path.exists());
        assert_eq!(
            std::fs::read_to_string(&plan.unit_path).unwrap(),
            plan.unit_body
        );

        remove_unit(&plan.unit_path).expect("remove");
        assert!(!plan.unit_path.exists());
        // Double-remove is a no-op.
        remove_unit(&plan.unit_path).expect("idempotent remove");

        std::fs::remove_dir_all(&tmp).ok();
    }
}
