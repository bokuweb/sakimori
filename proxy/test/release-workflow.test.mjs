import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const workflow = fs.readFileSync(new URL("../../.github/workflows/release.yml", import.meta.url), "utf8");
function scriptAfter(name) {
  const section = workflow.slice(workflow.indexOf(`- name: ${name}`)).split(/\n      - name:/)[0];
  const script = section.split("        run: |\n")[1];
  assert.ok(script, `missing workflow script: ${name}`);
  return script.split("\n").map(line => line.replace(/^          /, "")).join("\n");
}

test("real release scripts classify prerelease suffixes separately from build metadata", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sakimori-release-script-test-"));
  try {
    for (const tool of ["gh", "git"]) {
      fs.writeFileSync(path.join(root, tool), `#!/bin/sh\nprintf '%s\\n' '${tool}' "$@" >> "$FIXTURE_CALLS"\n`, { mode: 0o700 });
    }
    for (const [tag, prerelease] of [
      ["v0.34.4", false], ["v0.34.4+build-linux", false],
      ["v0.35.0-rc.1", true], ["v0.35.0-rc.1+build-linux", true],
    ]) {
      for (const step of ["Create draft GitHub Release for authenticated consumer verification", "Update v<MAJOR> tag"]) {
        const calls = path.join(root, "calls");
        fs.writeFileSync(calls, "");
        const run = spawnSync("bash", ["-c", scriptAfter(step)], {
          cwd: root, encoding: "utf8",
          env: { PATH: `${root}${path.delimiter}${process.env.PATH}`, TAG: tag, FIXTURE_CALLS: calls },
        });
        assert.equal(run.status, 0, `${step} ${tag}: ${run.stderr}`);
        const args = fs.readFileSync(calls, "utf8").split("\n");
        if (step.startsWith("Create")) {
          assert.ok(args.includes("--draft"));
          assert.equal(args.includes("--prerelease"), prerelease, tag);
        } else {
          assert.equal(args.includes("tag"), !prerelease, tag);
        }
      }
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
