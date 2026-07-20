// Post step of bokuweb/sakimori/proxy: kill the proxy we spawned in
// main.js. Runs at end-of-job regardless of whether other steps
// passed or failed (default post-if is `always()`).

"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

const runnerTemp = process.env.RUNNER_TEMP || os.tmpdir();
const tmpDir = process.env.SAKIMORI_PROXY_TMP || "";

function cleanupRuntime() {
  if (!tmpDir) return;
  const resolved = path.resolve(tmpDir);
  if (
    path.dirname(resolved) === path.resolve(runnerTemp) &&
    path.basename(resolved).startsWith("sakimori-proxy-action-")
  ) {
    fs.rmSync(resolved, { recursive: true, force: true });
  }
}

const pidFile = process.env.SAKIMORI_PROXY_PIDFILE;
if (!pidFile || !fs.existsSync(pidFile)) {
  console.log("sakimori-proxy: no pid-file to clean up — main step likely didn't run");
  cleanupRuntime();
  process.exit(0);
}

const raw = fs.readFileSync(pidFile, "utf8").trim();
const pid = parseInt(raw, 10);
if (!Number.isFinite(pid) || pid <= 0) {
  console.log(`sakimori-proxy: pid-file ${pidFile} unreadable: ${raw}`);
  cleanupRuntime();
  process.exit(0);
}

try {
  // SIGTERM on POSIX, taskkill-equivalent on Windows. Node's process.kill
  // is cross-platform: on Windows it's mapped to a graceful termination
  // request followed by force-kill.
  process.kill(pid);
  console.log(`sakimori-proxy: killed pid ${pid}`);
} catch (e) {
  // ESRCH = already gone, which is fine.
  if (e && e.code === "ESRCH") {
    console.log(`sakimori-proxy: pid ${pid} already exited`);
  } else {
    console.log(`sakimori-proxy: could not kill pid ${pid}: ${e && e.message}`);
  }
}

cleanupRuntime();
