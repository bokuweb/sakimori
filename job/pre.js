// Pre-step of bokuweb/sakimori/job: installs sakimori, then spawns the
// daemon attached to the runner-worker's cgroup so every subsequent step
// in this job is observed by a single eBPF supervisor.
//
// Linux only. Windows job-scoping needs Job Objects, which is a separate
// architecture; for Windows or single-step supervision use bokuweb/sakimori.

"use strict";

const { spawn, spawnSync } = require("child_process");
const crypto = require("crypto");
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
const runtimeDir = fs.mkdtempSync(path.join(runnerTemp, "sakimori-job-"));
fs.chmodSync(runtimeDir, 0o700);
const installDir = path.join(runtimeDir, "install");

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
const pidFile = path.join(runtimeDir, "daemon.pid");
const daemonStdout = path.join(runtimeDir, "daemon.stdout.log");
const daemonStderr = path.join(runtimeDir, "daemon.stderr.log");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: "inherit", ...options });
  if (result.status !== 0) {
    fail(`${command} failed (exit ${result.status ?? result.signal})`);
  }
  return result;
}

function resolveVersion(versionExpr, token) {
  const env = { ...process.env, GH_TOKEN: token };
  if (!versionExpr || versionExpr === "main" || versionExpr === "latest") {
    const result = spawnSync(
      "gh",
      ["release", "view", "--repo", "bokuweb/sakimori", "--json", "tagName", "-q", ".tagName"],
      { encoding: "utf8", env },
    );
    if (result.status !== 0) {
      fail(`gh release view failed: ${(result.stderr || "").trim() || result.error?.message}`);
    }
    return result.stdout.trim();
  }
  if (/^v[0-9]+$/.test(versionExpr)) {
    const major = versionExpr.slice(1);
    const result = spawnSync(
      "gh",
      [
        "api",
        "repos/bokuweb/sakimori/releases",
        "--jq",
        `[.[] | select(.tag_name | startswith("v${major}.")) | .tag_name] | first`,
      ],
      { encoding: "utf8", env },
    );
    if (result.status !== 0) {
      fail(`gh api failed: ${(result.stderr || "").trim() || result.error?.message}`);
    }
    const version = result.stdout.trim();
    if (!version || version === "null") {
      fail(`no v${major}.* release found on bokuweb/sakimori`);
    }
    return version;
  }
  return versionExpr;
}

function sha256File(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function openPrivateFile(file) {
  const flags = fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR;
  return fs.openSync(file, flags, 0o600);
}

function readFdUtf8(fd) {
  const size = fs.fstatSync(fd).size;
  if (size === 0) return "";
  const buffer = Buffer.alloc(size);
  const bytesRead = fs.readSync(fd, buffer, 0, size, 0);
  return buffer.subarray(0, bytesRead).toString("utf8");
}

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


  const token = input("token");
  const version = resolveVersion(versionExpr, token);
  const workdir = fs.mkdtempSync(path.join(runtimeDir, "download-"));
  fs.chmodSync(workdir, 0o700);
  console.log(`Installing sakimori ${version} (${target}) into ${installDir}`);

  run(
    "gh",
    [
      "release",
      "download",
      version,
      "--repo",
      "bokuweb/sakimori",
      "--pattern",
      asset,
      "--pattern",
      `${asset}.sha256`,
      "--dir",
      workdir,
    ],
    { env: { ...process.env, GH_TOKEN: token } },
  );

  const archive = path.join(workdir, asset);
  const expected = fs
    .readFileSync(`${archive}.sha256`, "utf8")
    .trim()
    .split(/\s+/)[0]
    .toLowerCase();
  const actual = sha256File(archive);
  if (!/^[0-9a-f]{64}$/.test(expected) || actual !== expected) {
    fail(`checksum mismatch for ${asset}`);
  }

  run("tar", ["-xzf", archive, "-C", workdir]);
  fs.mkdirSync(installDir, { recursive: true, mode: 0o700 });
  fs.renameSync(path.join(workdir, `sakimori-${target}`, "sakimori"), binPath);
  fs.renameSync(path.join(workdir, `sakimori-${target}`, "sakimori.bpf.o"), bpfPath);
  fs.chmodSync(binPath, 0o755);
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
    ? path.join(runtimeDir, "workspace-baseline.json")
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
  const stdoutFd = openPrivateFile(daemonStdout);
  const stderrFd = openPrivateFile(daemonStderr);

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
      setEnv("SAKIMORI_JOB_STDERR", daemonStderr);
      setEnv("SAKIMORI_JOB_TMP", runtimeDir);
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
      fs.closeSync(stdoutFd);
      fs.closeSync(stderrFd);
      return;
    }
    // 200 ms busy-wait via spawnSync — pre.js is short-lived and a
    // dedicated event-loop dance for this isn't worth the code.
    spawnSync("sleep", ["0.2"]);
  }

  // Surface whatever stderr the daemon wrote so the caller can see why.
  try {
    const stderr = readFdUtf8(stderrFd);
    if (stderr.trim().length > 0) {
      process.stderr.write("---- sakimori daemon stderr ----\n");
      process.stderr.write(stderr);
      process.stderr.write("--------------------------------\n");
    }
  } catch {
    // ignore — stderr file may not exist if spawn itself failed
  }
  fs.closeSync(stdoutFd);
  fs.closeSync(stderrFd);
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
