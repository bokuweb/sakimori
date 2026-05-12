// Main step of bokuweb/sakimori/verify-cache: download the sakimori
// binary, run `sakimori deps verify-cache` against the user's
// lockfile, propagate the exit code. Re-hashes every blob in the
// package manager's cache against the lockfile's `integrity:` fields
// — catches GitHub Actions cache poisoning (TanStack 2025) where a
// restored tarball doesn't match what the lockfile pinned.
//
// No background process, no post step. Pure foreground check.

"use strict";

const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

// -------- helpers --------

function input(name, dflt = "") {
  const key = "INPUT_" + name.toUpperCase().replace(/-/g, "_");
  const v = process.env[key];
  return v == null ? dflt : v;
}

function fail(msg) {
  process.stderr.write(`::error title=sakimori-verify-cache::${msg}\n`);
  process.exit(1);
}

function notice(msg) {
  process.stdout.write(`::notice::${msg}\n`);
}

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

// `v<MAJOR>` floating tags don't have a Release object; resolve via
// the API. Anything else is used verbatim.
function resolveVersion(versionExpr, token) {
  if (!versionExpr || versionExpr === "main" || versionExpr === "latest") {
    return "latest";
  }
  const m = /^v(\d+)$/.exec(versionExpr);
  if (m) {
    const major = m[1];
    const r = spawnSync(
      "gh",
      [
        "api",
        "repos/bokuweb/sakimori/releases",
        "--paginate",
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
  const args = [
    "release",
    "download",
    ...(version === "latest" ? [] : [version]),
    "--repo",
    "bokuweb/sakimori",
    "--pattern",
    asset,
    "--dir",
    tmpDir,
    "--clobber",
  ];
  const dl = spawnSync("gh", args, {
    stdio: "inherit",
    env: { ...process.env, GH_TOKEN: token },
  });
  if (dl.status !== 0) {
    fail(`gh release download failed for ${asset} of ${version}`);
  }
  console.log(`Extracting ${asset}`);
  const tar = spawnSync("tar", ["-xzf", path.join(tmpDir, asset), "-C", tmpDir], {
    stdio: "inherit",
  });
  if (tar.status !== 0) {
    fail(`tar -xzf ${asset} failed`);
  }
}

// -------- main --------

(async () => {
  const lockfile = input("lockfile");
  if (!lockfile) {
    fail("`lockfile` input is required");
  }
  if (!fs.existsSync(lockfile)) {
    fail(`lockfile ${lockfile} does not exist`);
  }

  const { triple, binName } = platformAsset();
  const token = input("token") || process.env.GITHUB_TOKEN || "";

  const runnerTemp = process.env.RUNNER_TEMP || os.tmpdir();
  const tmpDir = path.join(runnerTemp, "sakimori-verify-cache-action");
  fs.mkdirSync(tmpDir, { recursive: true });

  // SAKIMORI_BIN escape hatch — same convention as the proxy/job
  // sub-actions, used by the CI smoke matrix and air-gapped runners.
  const presetBin = process.env.SAKIMORI_BIN || "";
  let binPath;
  if (presetBin && fs.existsSync(presetBin)) {
    notice(`sakimori-verify-cache: using pre-installed sakimori at ${presetBin}`);
    binPath = presetBin;
  } else {
    const versionExpr = input("version") || process.env.GITHUB_ACTION_REF || "";
    const version = resolveVersion(versionExpr, token);
    console.log(
      `sakimori-verify-cache: installing ${version} (${triple}) into ${tmpDir}`,
    );
    downloadAndExtract(version, triple, tmpDir, token);
    binPath = path.join(tmpDir, `sakimori-${triple}`, binName);
    if (!fs.existsSync(binPath)) {
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

  const args = ["deps", "verify-cache", "--lockfile", lockfile];
  const cache = input("cache");
  if (cache) args.push("--cache", cache);
  const format = input("format", "text");
  if (format) args.push("--format", format);

  console.log(`sakimori-verify-cache: running ${binPath} ${args.join(" ")}`);
  const child = spawn(binPath, args, { stdio: "inherit" });
  child.on("error", (err) => fail(`spawn ${binPath}: ${err.message}`));
  child.on("exit", (code, signal) => {
    if (signal) {
      fail(`sakimori was killed by ${signal}`);
    }
    // Non-zero from sakimori means at least one mismatch or missing
    // blob — propagate verbatim so the job fails.
    process.exit(code ?? 1);
  });
})();
