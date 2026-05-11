// Main step of bokuweb/sakimori/proxy: download the sakimori binary
// for the current OS, spawn `sakimori proxy start` in the background,
// wait for the listener to come up, and export the proxy env vars
// (HTTPS_PROXY + per-tool CA bundle paths) via $GITHUB_ENV so
// subsequent steps route their HTTPS traffic through us.
//
// Works on Linux, macOS, and Windows. The background process survives
// across steps via Node's `detached: true` + `unref()` — the same
// pattern bokuweb/sakimori/job uses to keep its daemon alive across
// step boundaries. The post-step (post.js) kills it at end-of-job.

"use strict";

const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const net = require("net");

// -------- helpers --------

function input(name, dflt = "") {
  const key = "INPUT_" + name.toUpperCase().replace(/-/g, "_");
  const v = process.env[key];
  return v == null ? dflt : v;
}

function fail(msg) {
  process.stderr.write(`::error title=sakimori-proxy::${msg}\n`);
  process.exit(1);
}

function notice(msg) {
  process.stdout.write(`::notice::${msg}\n`);
}

function setEnv(name, value) {
  const f = process.env.GITHUB_ENV;
  if (!f) return;
  fs.appendFileSync(f, `${name}=${value}\n`);
}

function setOutput(name, value) {
  const f = process.env.GITHUB_OUTPUT;
  if (!f) return;
  fs.appendFileSync(f, `${name}=${value}\n`);
}

// Resolve (triple, binName) for the current OS/arch. Matches the
// release-artefact naming in release.yml.
//
// Windows note: we ask for `sakimori.exe`, NOT `sakimori-win.exe`.
// The two are different binaries: sakimori-win is the ETW
// supervisor (no proxy subcommand); sakimori is the main binary
// that ships the proxy. Both are packed in the Windows tarball
// from v0.34.3+. For older releases see the docs — the proxy
// subcommand isn't available on Windows there.
function platformAsset() {
  const arch = os.arch();
  if (process.platform === "linux") {
    const a = arch === "arm64" ? "aarch64" : "x86_64";
    return { triple: `${a}-unknown-linux-musl`, binName: "sakimori" };
  }
  if (process.platform === "darwin") {
    const a = arch === "arm64" ? "aarch64" : "x86_64";
    return { triple: `${a}-apple-darwin`, binName: "sakimori" };
  }
  if (process.platform === "win32") {
    return { triple: "x86_64-pc-windows-msvc", binName: "sakimori.exe" };
  }
  fail(`unsupported platform: ${process.platform}`);
}

// Resolve the install version. Handles three flavours:
//   empty / "main" / "latest"  → newest release overall
//   "v<MAJOR>" (e.g. "v0")     → newest "v<MAJOR>.*" release (moving
//                                git tag has no matching Release
//                                object; resolve via the API).
//   anything else              → used verbatim.
function resolveVersion(versionExpr, token) {
  if (!versionExpr || versionExpr === "main" || versionExpr === "latest") {
    const r = spawnSync(
      "gh",
      ["release", "view", "--repo", "bokuweb/sakimori", "--json", "tagName", "-q", ".tagName"],
      { encoding: "utf8", env: { ...process.env, GH_TOKEN: token } },
    );
    if (r.status !== 0) {
      fail(`gh release view failed: ${(r.stderr || "").trim() || r.error?.message}`);
    }
    return r.stdout.trim();
  }
  if (/^v[0-9]+$/.test(versionExpr)) {
    const major = versionExpr.slice(1);
    const r = spawnSync(
      "gh",
      [
        "api",
        "repos/bokuweb/sakimori/releases",
        "--jq",
        `[.[] | select(.tag_name | startswith("v${major}.")) | .tag_name] | first`,
      ],
      { encoding: "utf8", env: { ...process.env, GH_TOKEN: token } },
    );
    if (r.status !== 0) {
      fail(`gh api failed: ${(r.stderr || "").trim() || r.error?.message}`);
    }
    const v = r.stdout.trim();
    if (!v || v === "null") {
      fail(`no v${major}.* release found on bokuweb/sakimori`);
    }
    return v;
  }
  return versionExpr;
}

function downloadAndExtract(version, triple, tmpDir, token) {
  const asset = `sakimori-${triple}.tar.gz`;
  console.log(`Downloading ${asset} from release ${version}`);
  const dl = spawnSync(
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
      tmpDir,
      "--clobber",
    ],
    { stdio: "inherit", env: { ...process.env, GH_TOKEN: token } },
  );
  if (dl.status !== 0) {
    fail(`gh release download failed for ${asset} of ${version}`);
  }

  // tar.exe is available out of the box on Windows 10 / 2019+, on
  // every supported macOS, and on every Linux runner image. The
  // archive lays out as `sakimori-<triple>/<binName>` (plus
  // sakimori.bpf.o on Linux, which we don't need here).
  console.log(`Extracting ${asset}`);
  const tar = spawnSync("tar", ["-xzf", path.join(tmpDir, asset), "-C", tmpDir], {
    stdio: "inherit",
  });
  if (tar.status !== 0) {
    fail(`tar -xzf ${asset} failed`);
  }
}

// Async TCP probe to confirm the proxy actually opened its port.
// `sakimori proxy doctor` would also work but adds an extra
// dependency on the binary's behaviour; a plain connect is simpler.
async function waitForListen(host, port, deadlineMs) {
  const end = Date.now() + deadlineMs;
  while (Date.now() < end) {
    const ok = await new Promise((resolve) => {
      const s = net.createConnection({ host, port }, () => {
        s.destroy();
        resolve(true);
      });
      s.on("error", () => resolve(false));
    });
    if (ok) return true;
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

// -------- main --------

(async () => {
  const { triple, binName } = platformAsset();
  const token = input("token") || process.env.GITHUB_TOKEN || "";
  const listen = input("listen", "127.0.0.1:8910");
  const minAge = input("min-age", "7d");
  const failOnMissing = input("fail-on-missing") === "true";

  const runnerTemp = process.env.RUNNER_TEMP || os.tmpdir();
  const tmpDir = path.join(runnerTemp, "sakimori-proxy-action");
  fs.mkdirSync(tmpDir, { recursive: true });
  // Explicit --config-dir means we know where the CA lands without
  // having to guess at the platform's XDG-equivalent.
  const configDir = path.join(tmpDir, "config");
  fs.mkdirSync(configDir, { recursive: true });

  // SAKIMORI_BIN escape hatch — skip download when a caller (the
  // CI smoke matrix, an air-gapped runner, …) has already placed a
  // working binary on disk and set the env. Matches the pattern
  // bokuweb/sakimori/job@v0 already uses.
  const presetBin = process.env.SAKIMORI_BIN || "";
  let binPath;
  if (presetBin && fs.existsSync(presetBin)) {
    notice(`sakimori-proxy: using pre-installed sakimori at ${presetBin}`);
    binPath = presetBin;
  } else {
    const versionExpr = input("version") || process.env.GITHUB_ACTION_REF || "";
    const version = resolveVersion(versionExpr, token);
    console.log(
      `sakimori-proxy: installing ${version} (${triple}) into ${tmpDir}`,
    );
    downloadAndExtract(version, triple, tmpDir, token);
    binPath = path.join(tmpDir, `sakimori-${triple}`, binName);
    if (!fs.existsSync(binPath)) {
      // Help debug layout issues if the release tarball ever changes shape.
      let listing = "";
      try {
        listing = fs.readdirSync(tmpDir).join(", ");
      } catch {
        /* ignore */
      }
      fail(
        `expected binary at ${binPath} but not found; tmpDir contains: ${listing}`,
      );
    }
  }
  if (process.platform !== "win32") {
    fs.chmodSync(binPath, 0o755);
  }

  const stdoutLog = path.join(tmpDir, "proxy.stdout.log");
  const stderrLog = path.join(tmpDir, "proxy.stderr.log");
  const stdoutFd = fs.openSync(stdoutLog, "w");
  const stderrFd = fs.openSync(stderrLog, "w");

  const proxyArgs = [
    "proxy",
    "start",
    "--listen",
    listen,
    "--min-age",
    minAge,
    "--config-dir",
    configDir,
  ];
  if (failOnMissing) proxyArgs.push("--fail-on-missing");

  console.log(`sakimori-proxy: spawning ${binPath} ${proxyArgs.join(" ")}`);
  // detached + unref + stdio→files lets the process survive Node's
  // exit at end-of-step and keep serving subsequent steps.
  const child = spawn(binPath, proxyArgs, {
    detached: true,
    stdio: ["ignore", stdoutFd, stderrFd],
    // Windows: don't open a console window for the proxy.
    windowsHide: true,
  });
  child.on("error", (err) => fail(`spawn ${binPath}: ${err.message}`));
  child.unref();

  // Stash PID so the post step can kill it.
  const pidFile = path.join(tmpDir, "proxy.pid");
  fs.writeFileSync(pidFile, String(child.pid));

  // Wait for the listener.
  const [host, portStr] = listen.split(":");
  const port = parseInt(portStr, 10);
  if (!Number.isFinite(port)) {
    fail(`--listen ${listen} is not host:port`);
  }
  const up = await waitForListen(host, port, 15000);
  if (!up) {
    try {
      const errText = fs.readFileSync(stderrLog, "utf8");
      if (errText.trim()) {
        process.stderr.write("---- proxy stderr ----\n");
        process.stderr.write(errText);
        process.stderr.write("----------------------\n");
      }
    } catch {
      /* ignore */
    }
    fail(`proxy did not open ${listen} within 15s`);
  }

  const caPath = path.join(configDir, "sakimori", "ca.pem");
  if (!fs.existsSync(caPath)) {
    fail(`CA cert missing at ${caPath} — proxy started but didn't write the CA?`);
  }

  // Export env for subsequent steps. Mirrors `install-gate shellenv`.
  const proxyUrl = `http://${listen}`;
  setEnv("HTTPS_PROXY", proxyUrl);
  setEnv("HTTP_PROXY", proxyUrl);
  setEnv("https_proxy", proxyUrl);
  setEnv("http_proxy", proxyUrl);
  setEnv("CARGO_HTTP_CAINFO", caPath);
  setEnv("PIP_CERT", caPath);
  setEnv("NODE_EXTRA_CA_CERTS", caPath);
  setEnv("REQUESTS_CA_BUNDLE", caPath);
  setEnv("SSL_CERT_FILE", caPath);
  // For post.js cleanup.
  setEnv("SAKIMORI_PROXY_PIDFILE", pidFile);
  setEnv("SAKIMORI_PROXY_TMP", tmpDir);

  setOutput("ca-cert", caPath);

  notice(
    `sakimori-proxy: ready on ${proxyUrl} (CA ${caPath}, pid ${child.pid})`,
  );
})().catch((err) => {
  fail(`unexpected: ${err && err.stack ? err.stack : err}`);
});
