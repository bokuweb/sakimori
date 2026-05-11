// Pre-step of bokuweb/sakimori/job: installs sakimori, then spawns the
// daemon attached to the runner-worker's cgroup so every subsequent step
// in this job is observed by a single eBPF supervisor.
//
// Linux only. Windows job-scoping needs Job Objects, which is a separate
// architecture; for Windows or single-step supervision use bokuweb/sakimori.

"use strict";

const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

function input(name, dflt = "") {
  // GitHub Actions exposes `with:` keys as INPUT_<UPPER> with `-` → `_`.
  const key = "INPUT_" + name.toUpperCase().replace(/-/g, "_");
  const v = process.env[key];
  return v == null ? dflt : v;
}

function fail(msg) {
  process.stderr.write(`::error title=sakimori::${msg}\n`);
  process.exit(1);
}

function notice(msg) {
  process.stdout.write(`::notice::${msg}\n`);
}

function setOutput(name, value) {
  const f = process.env.GITHUB_OUTPUT;
  if (!f) return;
  fs.appendFileSync(f, `${name}=${value}\n`);
}

function setEnv(name, value) {
  const f = process.env.GITHUB_ENV;
  if (!f) return;
  fs.appendFileSync(f, `${name}=${value}\n`);
}

if (process.platform !== "linux") {
  // A step-level `if: runner.os == 'Linux'` on the consumer side only
  // gates this action's `main`; pre/post still fire on every matrix
  // entry by default (the GitHub Actions `pre-if` / `post-if` controls
  // are action-side, not consumer-side). So a workflow with a Linux +
  // macOS + Windows matrix would hard-fail the macOS and Windows
  // entries here if we exited non-zero. Silently no-op instead —
  // matches the composite `bokuweb/sakimori@v0` behaviour, which
  // simply skips its `if: runner.os == 'Linux'` install step on
  // other platforms.
  console.log(
    `bokuweb/sakimori/job: no-op on ${process.platform} ` +
      "(this action is Linux-only; use bokuweb/sakimori with `run:` " +
      "for Windows / single-step supervision).",
  );
  process.exit(0);
}

function detectContainer() {
  // `/.dockerenv` — written by docker (and most OCI runtimes) into every
  // container's rootfs. Cheap and reliable for hosted-runner cases.
  if (fs.existsSync("/.dockerenv")) return "docker";
  // `/proc/1/cgroup` shows the cgroup membership of pid 1 from the
  // namespace's view. Inside a container that line typically contains
  // a slug like `/docker/<id>`, `/kubepods/...`, or `/system.slice/
  // docker-<id>.scope`. Outside a container it's the host's path.
  try {
    const cg = fs.readFileSync("/proc/1/cgroup", "utf8");
    if (/\b(docker|containerd|kubepods|libpod|crio)\b/.test(cg)) {
      return "cgroup-pattern";
    }
  } catch {
    // /proc/1/cgroup not readable → assume host
  }
  return null;
}

const container = detectContainer();
if (container) {
  // Warn-and-continue: the daemon will fail at attach time with a
  // precise error (root cgroup refused, or no v2 hierarchy visible)
  // and that's the actually-useful diagnostic. We just give the user
  // a heads-up so they aren't surprised.
  process.stdout.write(
    `::warning title=sakimori::detected container environment (${container}). ` +
      "bokuweb/sakimori/job observes processes via the host's cgroup v2 hierarchy " +
      "and is not designed for `jobs.<id>.container:` workflows — steps run " +
      "inside the container and are isolated from the host-side BPF attach. " +
      "Either drop the `container:` key or run sakimori on a host job that " +
      "spawns the container as a child step.\n",
  );
}

const runnerTemp = process.env.RUNNER_TEMP || os.tmpdir();
const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
const installDir = path.join(runnerTemp, "sakimori");

// Honour pre-installed binaries — primarily so our own CI can exercise
// the action against a locally-built sakimori, but also useful for
// air-gapped runners that mirror the binary themselves. Both SAKIMORI_BIN
// and SAKIMORI_BPF_OBJ must be set AND point at existing files; partial
// configuration falls through to the normal download path.
const presetBin = process.env.SAKIMORI_BIN || "";
const presetBpf = process.env.SAKIMORI_BPF_OBJ || "";
const preInstalled =
  presetBin.length > 0 &&
  presetBpf.length > 0 &&
  fs.existsSync(presetBin) &&
  fs.existsSync(presetBpf);

const binPath = preInstalled ? presetBin : path.join(installDir, "sakimori");
const bpfPath = preInstalled
  ? presetBpf
  : path.join(installDir, "sakimori.bpf.o");
const pidFile = path.join(runnerTemp, "sakimori-job.pid");
const daemonStdout = path.join(runnerTemp, "sakimori-daemon.stdout.log");
const daemonStderr = path.join(runnerTemp, "sakimori-daemon.stderr.log");

function resolveOutput(p) {
  if (!p) return "";
  return path.isAbsolute(p) ? p : path.join(workspace, p);
}

function installBinary() {
  const explicitVersion = input("version");
  const refVersion = process.env.GITHUB_ACTION_REF || "";
  // Empty / `main` / `latest` → resolve via `gh release view`.
  const versionExpr =
    explicitVersion && explicitVersion.length > 0 ? explicitVersion : refVersion;

  const arch = os.arch() === "arm64" ? "aarch64" : "x86_64";
  const target = `${arch}-unknown-linux-musl`;
  const asset = `sakimori-${target}.tar.gz`;

  // Bash for the heavy lifting — sha256sum + tar + gh are all available
  // on the standard GitHub-hosted runner image, and replicating them in
  // node would be 50 lines of boilerplate for no win.
  //
  // Version resolution handles three flavours of ${GITHUB_ACTION_REF}:
  //   empty / "main" / "latest"   → newest release overall
  //   "v<MAJOR>" (e.g. "v0")      → newest "v<MAJOR>.*" release. This is
  //                                 the floating tag a `uses: bokuweb/
  //                                 sakimori/job@v0` reference resolves
  //                                 to; the moving git tag exists but
  //                                 there's no Release object with that
  //                                 literal name, so `gh release download
  //                                 v0` 404s. Map to latest-in-major.
  //   anything else               → used verbatim (concrete release tag).
  const script = `
set -euo pipefail
version="${versionExpr}"
if [[ -z "$version" || "$version" == "main" || "$version" == "latest" ]]; then
  version=$(gh release view --repo bokuweb/sakimori --json tagName -q .tagName)
elif [[ "$version" =~ ^v[0-9]+$ ]]; then
  # "v0", "v1", ... moving tags don't have matching Release objects
  # (release.yml's moving-tag job only force-pushes the git ref).
  # Walk the release list and pick the newest entry whose tag starts
  # with "v<MAJOR>." — this is what users mean when they pin to @v<MAJOR>.
  major="\${version#v}"
  version=$(gh api "repos/bokuweb/sakimori/releases" \\
    --jq "[.[] | select(.tag_name | startswith(\\"v\${major}.\\")) | .tag_name] | first")
  if [[ -z "$version" || "$version" == "null" ]]; then
    echo "::error::no v\${major}.* release found on bokuweb/sakimori" >&2
    exit 1
  fi
fi
echo "Installing sakimori $version ($target) into ${installDir}"
workdir=$(mktemp -d)
cd "$workdir"
gh release download "$version" \\
  --repo bokuweb/sakimori \\
  --pattern "${asset}" \\
  --pattern "${asset}.sha256"
sha256sum -c "${asset}.sha256"
tar -xzf "${asset}"
mkdir -p "${installDir}"
mv "sakimori-${target}/sakimori" "${binPath}"
mv "sakimori-${target}/sakimori.bpf.o" "${bpfPath}"
chmod +x "${binPath}"
`;

  const token = input("token");
  const r = spawnSync("bash", ["-c", script], {
    stdio: "inherit",
    env: { ...process.env, GH_TOKEN: token, target, asset, installDir, binPath, bpfPath },
  });
  if (r.status !== 0) {
    fail(`sakimori install failed (bash exited ${r.status ?? r.signal})`);
  }
}

function startDaemon() {
  const policy = input("policy");
  const mode = input("mode");
  const log = resolveOutput(input("log"));
  const htmlIn = input("html");
  const html = htmlIn ? resolveOutput(htmlIn) : "";
  const summaryIn = input("summary");
  const summary = summaryIn
    ? resolveOutput(summaryIn)
    : process.env.GITHUB_STEP_SUMMARY || "";
  const allowRoot = input("allow-root-cgroup") === "true";

  // Tamper detection wiring. Baseline file is read at SIGTERM time so
  // it's fine that it doesn't exist yet at start (the user takes it
  // after checkout in a separate step). See action.yml for the
  // recipe. snapshot-skip is newline-separated since YAML `with:`
  // doesn't have a clean way to pass a list of strings.
  const snapshotDirIn = input("snapshot-workspace");
  const snapshotDir = snapshotDirIn ? resolveOutput(snapshotDirIn) : "";
  const baselinePath = snapshotDir
    ? path.join(runnerTemp, "sakimori-workspace-baseline.json")
    : "";
  const snapshotSkip = (input("snapshot-skip") || "")
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  // process.ppid is the GitHub Actions runner worker that spawned `node
  // pre.js`. It's the common ancestor cgroup we need to attach to: every
  // subsequent step the worker spawns inherits its cgroup, so attaching
  // there catches the lot.
  const observePid = process.ppid;

  const daemonArgs = [
    "-n",
    "-E",
    binPath,
    "daemon",
    "start",
    "--observe-cgroup-of",
    String(observePid),
    "--pid-file",
    pidFile,
    "--log",
    log,
  ];
  if (policy && fs.existsSync(policy)) {
    daemonArgs.push("--policy", policy);
  } else if (policy) {
    notice(
      `policy file '${policy}' not found — starting daemon with the built-in permissive audit policy.`,
    );
  }
  if (mode) {
    daemonArgs.push("--mode", mode);
  }
  if (html) {
    daemonArgs.push("--html", html);
  }
  if (summary) {
    daemonArgs.push("--summary", summary);
  }
  if (allowRoot) {
    daemonArgs.push("--allow-root-cgroup");
  }
  if (snapshotDir) {
    daemonArgs.push(
      "--workspace-baseline",
      baselinePath,
      "--workspace-dir",
      snapshotDir,
    );
    for (const skip of snapshotSkip) {
      daemonArgs.push("--workspace-skip", skip);
    }
  }

  // Fresh log files each run — append would mix stale daemon output
  // from a previous job that ran on this same runner image (rare on
  // hosted runners, common on self-hosted).
  const stdoutFd = fs.openSync(daemonStdout, "w");
  const stderrFd = fs.openSync(daemonStderr, "w");

  const child = spawn("sudo", daemonArgs, {
    detached: true,
    stdio: ["ignore", stdoutFd, stderrFd],
    env: { ...process.env, SAKIMORI_BPF_OBJ: bpfPath },
  });
  child.on("error", (err) => {
    fail(`spawning sudo: ${err.message}`);
  });
  child.unref();

  // Poll for the pid-file. The daemon writes it only after eBPF
  // programs have attached successfully, so its appearance is our
  // "ready" signal.
  const deadlineMs = Date.now() + 20_000;
  while (Date.now() < deadlineMs) {
    if (fs.existsSync(pidFile)) {
      const daemonPid = fs.readFileSync(pidFile, "utf8").trim();
      notice(
        `sakimori daemon ready (pid ${daemonPid}, observing cgroup of runner pid ${observePid}). Job-wide audit active.`,
      );
      setEnv("SAKIMORI_BIN", binPath);
      setEnv("SAKIMORI_BPF_OBJ", bpfPath);
      setEnv("SAKIMORI_JOB_PIDFILE", pidFile);
      // post.js needs these to decide whether to fail the job when the
      // daemon flagged denied events in block mode.
      setEnv("SAKIMORI_JOB_LOG", log);
      setEnv("SAKIMORI_JOB_MODE", mode || "audit");
      // Tamper-detection wiring: expose the resolved paths so the
      // user's post-checkout snapshot step can find them.
      if (snapshotDir) {
        setEnv("SAKIMORI_WORKSPACE_DIR", snapshotDir);
        setEnv("SAKIMORI_BASELINE_PATH", baselinePath);
        notice(
          `tamper detection armed — take the baseline with: ` +
            `sudo -E "$SAKIMORI_BIN" workspace snapshot ` +
            `"$SAKIMORI_WORKSPACE_DIR" -o "$SAKIMORI_BASELINE_PATH"`,
        );
      }
      setOutput("bin", binPath);
      setOutput("log", log);
      setOutput("pidfile", pidFile);
      return;
    }
    // 200 ms busy-wait via spawnSync — pre.js is short-lived and a
    // dedicated event-loop dance for this isn't worth the code.
    spawnSync("sleep", ["0.2"]);
  }

  // Surface whatever stderr the daemon wrote so the caller can see why.
  try {
    const stderr = fs.readFileSync(daemonStderr, "utf8");
    if (stderr.trim().length > 0) {
      process.stderr.write("---- sakimori daemon stderr ----\n");
      process.stderr.write(stderr);
      process.stderr.write("--------------------------------\n");
    }
  } catch {
    // ignore — stderr file may not exist if spawn itself failed
  }
  fail(
    "sakimori daemon did not become ready within 20s. " +
      "Common causes: sudo prompts for a password (unsupported), kernel " +
      "lacks CAP_BPF / cgroup v2, or the runner's cgroup hierarchy is unwritable.",
  );
}

if (preInstalled) {
  notice(`using pre-installed sakimori at ${binPath} (bpf=${bpfPath})`);
} else {
  installBinary();
}
startDaemon();
