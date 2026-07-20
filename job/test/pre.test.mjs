import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const preJs = fs.readFileSync(path.resolve(here, "..", "pre.js"), "utf8");

test("job pre-step creates a private unpredictable runtime directory", () => {
  assert.match(preJs, /fs\.mkdtempSync\(/);
  assert.match(preJs, /fs\.chmodSync\([^,]+,\s*0o700\)/);
  assert.doesNotMatch(preJs, /path\.join\(runnerTemp,\s*["']sakimori-job\.pid["']\)/);
});

test("job pre-step creates daemon logs exclusively with owner-only permissions", () => {
  assert.match(preJs, /O_CREAT[\s\S]*O_EXCL/);
  assert.match(preJs, /openSync\([^\n]+0o600\)/);
});

test("job pre-step never passes inputs through bash -c", () => {
  assert.doesNotMatch(preJs, /spawnSync\(\s*["']bash["'][\s\S]*?["']-c["']/);
});

test("job pre-step reads startup diagnostics from its open descriptor", () => {
  assert.match(preJs, /fs\.readSync\(\s*fd\b/);
  assert.match(preJs, /readFdUtf8\(\s*stderrFd\s*\)/);
  assert.doesNotMatch(preJs, /fs\.readFileSync\(\s*daemonStderr\b/);
});
