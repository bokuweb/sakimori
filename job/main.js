// Main of bokuweb/sakimori/job. The supervisor is already running (it
// was started by pre.js and is detached from this node process), so the
// "main" step has nothing to do other than print a status line.

"use strict";

if (process.platform !== "linux") {
  process.exit(0);
}

console.log(
  "sakimori daemon is supervising this job. The JSON log / step summary / " +
    "HTML report are flushed when the post-step calls `sakimori daemon stop`.",
);
