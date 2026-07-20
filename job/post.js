// Post-step of bokuweb/sakimori/job: tell the daemon to flush its report
// and exit. Runs even when the job's main steps failed, so the audit log
// is always written.

"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

if (process.platform !== "linux") {
  process.exit(0);
}

const runnerTemp = process.env.RUNNER_TEMP || os.tmpdir();
const runtimeDir = process.env.SAKIMORI_JOB_TMP || "";
const pidFile = process.env.SAKIMORI_JOB_PIDFILE || "";
const binPath = process.env.SAKIMORI_BIN || "";

function cleanupRuntime() {
  if (!runtimeDir) return;
  const resolved = path.resolve(runtimeDir);
  if (
    path.dirname(resolved) === path.resolve(runnerTemp) &&
    path.basename(resolved).startsWith("sakimori-job-")
  ) {
    fs.rmSync(resolved, { recursive: true, force: true });
  }
}

if (!fs.existsSync(pidFile)) {
  console.log(
    `sakimori daemon stop: no pid-file at ${pidFile} — pre-step likely failed before the daemon started; nothing to flush.`,
  );
  cleanupRuntime();
  process.exit(0);
}

const stopResult = spawnSync(
  "sudo",
  ["-n", "-E", binPath, "daemon", "stop", "--pid-file", pidFile],
  {
    stdio: "inherit",
    env: process.env,
  },
);
// `daemon stop` exits non-zero only on timeout / unreachable daemon.
// Block-mode policy violations exit non-zero from the *daemon* process
// itself at SIGTERM time, which doesn't propagate through stop's exit
// code — we re-check the log below and fail the job if needed.

// Drain the daemon's stderr log so late warnings (ringbuf overflow,
// block-mode `::error::` annotations) show up on the run page.
const daemonStderr = process.env.SAKIMORI_JOB_STDERR || "";
try {
  const text = daemonStderr ? fs.readFileSync(daemonStderr, "utf8") : "";
  if (text.trim().length > 0) {
    process.stderr.write("---- sakimori daemon stderr ----\n");
    process.stderr.write(text);
    process.stderr.write("--------------------------------\n");
  }
} catch {
  // ignore
}

// daemon stop failed (timeout / pid-file unreadable) → surface that.
if (stopResult.status != null && stopResult.status !== 0) {
  cleanupRuntime();
  process.exit(stopResult.status);
}

// Block-mode failure detection: read the JSON log the daemon just wrote
// and fail the job if `denied > 0` AND mode was block. The daemon also
// re-emits the `::error::` annotation to its stderr, which we just
// drained above, so the run UI shows the count.
const mode = process.env.SAKIMORI_JOB_MODE || "audit";
const logPath = process.env.SAKIMORI_JOB_LOG;
if (mode === "block" && logPath && logPath !== "-" && fs.existsSync(logPath)) {
  try {
    // The daemon appends one JSON document per shutdown. The "last
    // wins" semantics matches `sakimori run`, which also appends.
    const raw = fs.readFileSync(logPath, "utf8").trim();
    // Multiple newline-separated JSON objects → take the last one. A
    // single object is the common case.
    const lastObjStart = raw.lastIndexOf("\n{");
    const lastJson = lastObjStart >= 0 ? raw.slice(lastObjStart + 1) : raw;
    const stats = JSON.parse(lastJson);
    if (typeof stats.denied === "number" && stats.denied > 0) {
      process.stderr.write(
        `::error title=sakimori::policy violation: ${stats.denied} events denied in block mode\n`,
      );
      cleanupRuntime();
      process.exit(1);
    }
  } catch (e) {
    process.stderr.write(
      `::warning title=sakimori::could not parse audit log at ${logPath} to check for block-mode violations: ${e.message}\n`,
    );
  }
}

cleanupRuntime();
process.exit(0);
