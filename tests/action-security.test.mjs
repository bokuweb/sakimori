import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function read(relative) {
  return fs.readFileSync(path.join(root, relative), "utf8");
}

function runBodies(yaml) {
  const lines = yaml.split("\n");
  const bodies = [];
  for (let i = 0; i < lines.length; i += 1) {
    const match = lines[i].match(/^(\s*)run:\s*\|\s*$/);
    if (!match) continue;
    const indent = match[1].length;
    const body = [];
    for (i += 1; i < lines.length; i += 1) {
      const line = lines[i];
      const lineIndent = line.match(/^\s*/)[0].length;
      if (line.trim() && lineIndent <= indent) {
        i -= 1;
        break;
      }
      body.push(line);
    }
    bodies.push(body.join("\n"));
  }
  return bodies;
}

test("composite actions keep untrusted expressions out of run scripts", () => {
  for (const file of ["action.yml", "comment/action.yml"]) {
    const scripts = runBodies(read(file)).join("\n");
    assert.doesNotMatch(scripts, /\$\{\{\s*inputs\./, `${file} interpolates an input in run:`);
    assert.doesNotMatch(
      scripts,
      /\$\{\{\s*github\.event\.pull_request\.number\s*\}\}/,
      `${file} interpolates the PR number in run:`,
    );
  }
});

test("security-sensitive workflows pin every external action by commit SHA", () => {
  for (const file of [".github/workflows/consumer-smoke.yml", ".github/workflows/docker.yml"]) {
    const refs = [...read(file).matchAll(/^\s*-?\s*uses:\s*([^\s#]+)/gm)].map((m) => m[1]);
    assert.ok(refs.length > 0, `${file} must contain actions to verify`);
    for (const ref of refs) {
      if (ref.startsWith("./") || ref.startsWith("docker://")) continue;
      assert.match(ref, /@[0-9a-f]{40}$/, `${file}: ${ref} is mutable`);
    }
  }
});
