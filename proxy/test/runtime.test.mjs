import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const source = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "../main.js"), "utf8");
const currentHelp = "--hub-ingest-url --hub-ingest-token --hub-access-client-id --hub-access-client-secret";

async function runAction(inputs, { help = currentHelp, download = false, corrupt = false, releases } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sakimori-action-test-"));
  const bin = path.join(root, "sakimori");
  fs.writeFileSync(bin, "fixture");
  const env = { RUNNER_TEMP: root, GITHUB_ENV: path.join(root, "env"), GITHUB_OUTPUT: path.join(root, "output"), ...inputs };
  if (!download) env.SAKIMORI_BIN = bin;
  const calls = [];
  const logs = [];
  const children = [];
  const proc = { env, platform: process.platform, stdout: { write: s => logs.push(s) }, stderr: { write: s => logs.push(s) }, exit: code => { throw new Error(`exit ${code}`); } };
  const childProcess = {
    spawnSync(command, args, options) {
      calls.push({ command, args, options });
      if (command === "gh" && args[0] === "api" && releases) {
        // Original --jq selection picked the first matching major regardless
        // of draft/prerelease state. Raw API mode returns the full fixture.
        return { status: 0, stdout: args.includes("--jq") ? releases[0].tag_name : JSON.stringify(releases) };
      }
      if (command === "gh" && args[0] === "release" && args[1] === "download") {
        const dir = args[args.indexOf("--dir") + 1];
        const asset = args[args.indexOf("--pattern") + 1];
        const bytes = Buffer.from("fixture archive");
        fs.writeFileSync(path.join(dir, asset), bytes);
        const digest = corrupt ? "0".repeat(64) : crypto.createHash("sha256").update(bytes).digest("hex");
        fs.writeFileSync(path.join(dir, `${asset}.sha256`), `${digest}  ${asset}\n`);
        return { status: 0 };
      }
      if (command === "tar") {
        const dir = args[args.indexOf("-C") + 1];
        const archive = path.basename(args[args.indexOf("-xzf") + 1], ".tar.gz");
        fs.mkdirSync(path.join(dir, archive));
        fs.writeFileSync(path.join(dir, archive, process.platform === "win32" ? "sakimori.exe" : "sakimori"), "fixture");
        return { status: 0 };
      }
      return { status: 0, stdout: help };
    },
    spawn(command, args, options) {
      children.push({ command, args, options, logCount: logs.length });
      const config = args[args.indexOf("--config-dir") + 1];
      fs.mkdirSync(path.join(config, "sakimori"));
      fs.writeFileSync(path.join(config, "sakimori", "ca.pem"), "fixture CA");
      return { pid: 12345, on() {}, unref() {} };
    },
  };
  const context = vm.createContext({
    require: name => name === "child_process" ? childProcess : name === "net" ? {
      createConnection(_options, callback) { queueMicrotask(callback); return { on() {}, destroy() {} }; },
    } : require(name),
    process: proc, console: { log: s => logs.push(`${s}\n`) }, Buffer, setTimeout,
  });
  let failure;
  try {
    vm.runInContext(source.replace("(async () => {", "globalThis.actionRun = (async () => {"), context);
    await context.actionRun;
  } catch (e) { failure = e; }
  const exports = fs.existsSync(env.GITHUB_ENV) ? fs.readFileSync(env.GITHUB_ENV, "utf8") : "";
  fs.rmSync(root, { recursive: true, force: true });
  return { calls, children, logs, exports, failure };
}

test("GitHub runner hyphenated inputs reach the proxy and Access secrets stay in child env", async () => {
  const r = await runAction({
    "INPUT_MIN-AGE": "12h", "INPUT_FAIL-ON-MISSING": "true",
    "INPUT_INGEST-URL": "https://hub.example/v1/demo/_team/events", "INPUT_INGEST-TOKEN": "hub-secret",
    "INPUT_CF-ACCESS-CLIENT-ID": "access-id", "INPUT_CF-ACCESS-CLIENT-SECRET": "access-secret",
  });
  assert.ifError(r.failure);
  const child = r.children[0];
  assert.equal(child.options.env.SAKIMORI_TOKEN, "hub-secret");
  assert.equal(child.options.env.SAKIMORI_CF_ACCESS_CLIENT_ID, "access-id");
  assert.equal(child.options.env.SAKIMORI_CF_ACCESS_CLIENT_SECRET, "access-secret");
  assert.equal(child.args[child.args.indexOf("--min-age") + 1], "12h");
  assert.ok(child.args.includes("--fail-on-missing"));
  assert.ok(!Object.keys(child.options.env).some(key => key.startsWith("INPUT_")));
  for (const value of ["hub-secret", "access-id", "access-secret"]) {
    assert.ok(r.logs.slice(0, child.logCount).some(line => line === `::add-mask::${value}\n`));
    assert.ok(!child.args.includes(value));
    assert.ok(!r.exports.includes(value));
    assert.ok(!r.logs.filter(line => !line.startsWith("::add-mask::")).join("").includes(value));
  }
});

test("canonical runner input takes precedence over the legacy underscore alias", async () => {
  const r = await runAction({ "INPUT_MIN-AGE": "12h", INPUT_MIN_AGE: "99d" });
  assert.ifError(r.failure);
  assert.equal(r.children[0].args[r.children[0].args.indexOf("--min-age") + 1], "12h");
});

test("incomplete Access credential pair fails before download or spawn", async () => {
  const r = await runAction({ "INPUT_CF-ACCESS-CLIENT-SECRET": "sensitive\nvalue" });
  assert.ok(r.failure);
  assert.equal(r.children.length, 0);
  assert.equal(r.calls.length, 0);
  assert.match(r.logs.join(""), /both.*cf-access-client/);
  assert.ok(r.logs.includes("::add-mask::sensitive%0Avalue\n"));
});

test("old released binary cannot silently ignore opted-in Hub delivery", async () => {
  const r = await runAction({ "INPUT_INGEST-URL": "https://hub.example/v1/demo/_team/events", "INPUT_INGEST-TOKEN": "secret" }, { help: "--min-age --listen" });
  assert.ok(r.failure);
  assert.equal(r.children.length, 0);
  assert.match(r.logs.join(""), /release.*Hub|Hub.*release/);
});

test("downloaded archive checksum is verified before extraction", async () => {
  const r = await runAction({ INPUT_VERSION: "v0.99.0" }, { download: true, corrupt: true });
  assert.ok(r.failure);
  assert.ok(!r.calls.some(call => call.command === "tar"));
  assert.match(r.logs.join(""), /checksum/i);
});

test("matching release archive checksum permits extraction and startup", async () => {
  const r = await runAction({ INPUT_VERSION: "v0.99.0" }, { download: true });
  assert.ifError(r.failure);
  assert.equal(r.children.length, 1);
  assert.ok(r.calls.some(call => call.command === "tar"));
});

test("published consumer downloads retain the workflow GH_TOKEN", async () => {
  const r = await runAction({ INPUT_VERSION: "v0.99.0", GH_TOKEN: "workflow-download-token" }, { download: true });
  assert.ifError(r.failure);
  const download = r.calls.find(call => call.command === "gh");
  assert.equal(download.options.env.GH_TOKEN, "workflow-download-token");
  assert.ok(r.logs.includes("::add-mask::workflow-download-token\n"));
});

test("floating major version excludes draft and prerelease archives before downloading", async () => {
  const releases = [
    { tag_name: "v0.99.0", draft: true, prerelease: false },
    { tag_name: "v0.98.1-rc.1", draft: false, prerelease: false },
    { tag_name: "v0.98.0-rc.1", draft: false, prerelease: true },
    { tag_name: "v1.0.0", draft: false, prerelease: false },
    { tag_name: "v0.34.4", draft: false, prerelease: false },
  ];
  const r = await runAction({ INPUT_VERSION: "v0" }, { download: true, releases });
  assert.ifError(r.failure);
  const download = r.calls.find(call => call.command === "gh" && call.args[0] === "release");
  assert.equal(download.args[2], "v0.34.4");
});

test("floating major with only a draft fails before archive download", async () => {
  const r = await runAction({ INPUT_VERSION: "v0" }, { download: true, releases: [{ tag_name: "v0.99.0", draft: true, prerelease: false }] });
  assert.ok(r.failure);
  assert.ok(!r.calls.some(call => call.command === "gh" && call.args[0] === "release"));
});

test("stable build metadata with a hyphen remains eligible for a floating major", async () => {
  const r = await runAction({ INPUT_VERSION: "v0" }, { download: true, releases: [{ tag_name: "v0.34.4+build-linux", draft: false, prerelease: false }] });
  assert.ifError(r.failure);
  const download = r.calls.find(call => call.command === "gh" && call.args[0] === "release");
  assert.equal(download.args[2], "v0.34.4+build-linux");
});
