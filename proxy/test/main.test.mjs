// Contract tests for `bokuweb/sakimori/proxy`'s composite-action
// wiring. Runs under plain Node — `node --test proxy/test/main.test.mjs`
// — so the CI's existing lint job can add a single line without
// pulling vitest / jest in for a JS-action this small.
//
// These tests stop short of spawning the real `sakimori proxy`
// binary (the proxy-action-smoke matrix in ci.yml does that
// end-to-end). They pin the SURFACE: input names, env-variable
// propagation, and the `::add-mask::` discipline that keeps the
// hub-ingest token out of subsequent step logs.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const proxyDir = path.resolve(here, "..");
const actionYml = fs.readFileSync(path.join(proxyDir, "action.yml"), "utf8");
const mainJs = fs.readFileSync(path.join(proxyDir, "main.js"), "utf8");

test("main.js creates a private unpredictable runtime directory", () => {
  assert.match(mainJs, /fs\.mkdtempSync\(/);
  assert.match(mainJs, /fs\.chmodSync\([^,]+,\s*0o700\)/);
  assert.doesNotMatch(
    mainJs,
    /path\.join\(runnerTemp,\s*["']sakimori-proxy-action["']\)/,
  );
});

test("main.js creates logs and pid file exclusively with owner-only permissions", () => {
  assert.match(mainJs, /O_CREAT[\s\S]*O_EXCL/);
  assert.match(mainJs, /openSync\([^\n]+0o600\)/);
  assert.match(mainJs, /writeFileSync\([^\n]+flag:\s*["']wx["']/);
});

test("main.js reads startup diagnostics from its open descriptor", () => {
  assert.match(mainJs, /fs\.readSync\(\s*fd\b/);
  assert.match(mainJs, /readFdUtf8\(\s*stderrFd\s*\)/);
  assert.doesNotMatch(mainJs, /fs\.readFileSync\(\s*stderrLog\b/);
});

// ---------------------------------------------------------------
// action.yml input declarations
// ---------------------------------------------------------------
//
// We grep rather than parse YAML because the file is tiny and a
// regex-level pin gives a sharper failure message ("ingest-url
// input missing") than a structural assertion would. If the
// grammar ever gets more complex, swap in a real YAML parser.

test("action.yml declares the ingest-url input", () => {
  assert.match(
    actionYml,
    /^\s{2}ingest-url:\s*$/m,
    "ingest-url input must be declared under `inputs:`",
  );
});

test("action.yml declares the ingest-token input", () => {
  assert.match(
    actionYml,
    /^\s{2}ingest-token:\s*$/m,
    "ingest-token input must be declared under `inputs:`",
  );
});

test("ingest inputs default to empty (opt-in, not required)", () => {
  // Both inputs must default to "" so callers who don't want hub
  // upload see no behavioural change. A non-empty default would
  // surprise an existing user.
  const urlBlock = actionYml.match(/ingest-url:[\s\S]*?(?=\n\s{2}\S|\noutputs:)/);
  assert.ok(urlBlock, "could not locate ingest-url block");
  assert.match(urlBlock[0], /required:\s*false/);
  assert.match(urlBlock[0], /default:\s*""/);

  const tokBlock = actionYml.match(/ingest-token:[\s\S]*?(?=\n\s{2}\S|\noutputs:)/);
  assert.ok(tokBlock, "could not locate ingest-token block");
  assert.match(tokBlock[0], /required:\s*false/);
  assert.match(tokBlock[0], /default:\s*""/);
});

// ---------------------------------------------------------------
// main.js wiring
// ---------------------------------------------------------------

test("main.js reads both inputs", () => {
  // Pin the exact `input("ingest-url")` / `input("ingest-token")`
  // call shape because that's how composite-action inputs become
  // `INPUT_*` env vars (see helper at top of main.js).
  assert.match(mainJs, /input\(\s*["']ingest-url["']\s*\)/);
  assert.match(mainJs, /input\(\s*["']ingest-token["']\s*\)/);
});

test("main.js masks the ingest token via ::add-mask::", () => {
  // The token MUST be registered with the GH Actions log scrubber
  // before any subsequent log line could echo it (proxy logs,
  // supervised `set -x` traces, spawn-error paths). This pin
  // catches a regression where the mask call moves below the
  // spawn or gets dropped.
  assert.match(mainJs, /add-mask/);
  assert.match(mainJs, /addMask\s*\(\s*ingestToken\s*\)/);
});

test("addMask is called before childEnv assembly and spawn (ordering)", () => {
  // Codex round-1: the bare presence of addMask is insufficient —
  // a regression that moves it below the spawn would still pass
  // the substring test above. Pin file-order so the mask is
  // registered with the runner BEFORE any later code path could
  // echo the bytes (childEnv assembly, spawn-stderr dump, …).
  const idxMask = mainJs.indexOf("addMask(ingestToken)");
  const idxChildEnv = mainJs.indexOf("const childEnv");
  const idxSpawn = mainJs.search(/\bspawn\(binPath/);
  assert.ok(idxMask >= 0, "addMask(ingestToken) call must exist");
  assert.ok(idxChildEnv >= 0, "childEnv assembly must exist");
  assert.ok(idxSpawn >= 0, "spawn(binPath, …) must exist");
  assert.ok(
    idxMask < idxChildEnv && idxChildEnv < idxSpawn,
    `expected addMask < childEnv < spawn (got ${idxMask}, ${idxChildEnv}, ${idxSpawn})`,
  );
});

test("addMask escapes CR/LF/% so a multiline token can't break the workflow-command line", () => {
  // Codex round-1: a token containing `\r` or `\n` would terminate
  // `::add-mask::<token>\n` early and leak the trailing bytes.
  // Mirror @actions/core's command escaping: `%` → %25, `\r` → %0D,
  // `\n` → %0A. The function is internal so pin the regex shape
  // here.
  assert.match(mainJs, /replace\(\s*\/%\/g\s*,\s*["']%25["']\s*\)/);
  assert.match(mainJs, /replace\(\s*\/\\r\/g\s*,\s*["']%0D["']\s*\)/);
  assert.match(mainJs, /replace\(\s*\/\\n\/g\s*,\s*["']%0A["']\s*\)/);
});

test("INPUT_* env vars are stripped from the spawned proxy env", () => {
  // Codex round-1: childEnv = {...process.env} would otherwise
  // forward INPUT_INGEST_TOKEN to the proxy alongside the
  // explicit SAKIMORI_TOKEN, doubling the leak surface. Pin the
  // explicit strip.
  assert.match(mainJs, /key\.startsWith\(["']INPUT_["']\)/);
  assert.match(mainJs, /delete\s+childEnv\[\s*key\s*\]/);
});

test("main.js propagates the credentials to the spawned proxy env", () => {
  // The proxy binary reads SAKIMORI_INGEST_URL / SAKIMORI_TOKEN
  // via clap's `env =` binding. The wire from action input →
  // proxy is: `process.env` of the spawned child carries
  // SAKIMORI_INGEST_URL + SAKIMORI_TOKEN. Pin both keys
  // verbatim so a typo (e.g. SAKIMORI_HUB_URL) doesn't silently
  // disable ingest.
  assert.match(mainJs, /SAKIMORI_INGEST_URL\s*=\s*ingestUrl/);
  assert.match(mainJs, /SAKIMORI_TOKEN\s*=\s*ingestToken/);
  // And the spawn site receives an explicit `env:` field — the
  // default of "inherit current process env" would also work for
  // the simple case, but only the explicit form lets us set
  // SAKIMORI_TOKEN without also leaking it into Node's own env
  // for accidental child spawns from later code.
  assert.match(mainJs, /\bspawn\([^)]*?\benv:\s*childEnv/s);
});

test("main.js only sets ingest env when BOTH url and token are present", () => {
  // Half-configured ingest is a likely operator mistake (e.g.
  // forgot to wire the secret). The proxy itself logs a warn for
  // the half-set case; the action should not silently set just
  // one half on the child env (that would be a no-op anyway, but
  // a bare URL with no Authorization would also let the child
  // attempt and fail every install).
  assert.match(mainJs, /if\s*\(\s*ingestUrl\s*&&\s*ingestToken\s*\)\s*{/);
});

test("main.js does not pass the token via argv (env-only)", () => {
  // Tokens on argv leak through `ps`, error messages that dump
  // argv, etc. Pin that the proxy spawn line builds `proxyArgs`
  // from public flags only — no `--hub-ingest-token` or
  // `ingestToken` reference inside the args array literal.
  const argsBlock = mainJs.match(/const\s+proxyArgs\s*=\s*\[[\s\S]*?\];/);
  assert.ok(argsBlock, "could not locate proxyArgs block");
  assert.doesNotMatch(argsBlock[0], /ingestToken|hub-ingest-token/i);
});
