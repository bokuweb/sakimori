# CLAUDE.md — project context for Claude

This file exists so future Claude sessions (or other LLM agents) can
pick up work on this repo without re-deriving context from scratch.
Human readers may find it useful too — it's deliberately written in
plain English, no agent-only jargon.

## What this project is

**sakimori** is a cross-platform supply-chain guard with two main
surfaces:

1. **A supervised-run mode** for CI (`sakimori run -- <cmd>`):
   wraps your build/test command with an eBPF (Linux) or ETW (Windows)
   agent that audits and optionally blocks network / file / exec
   syscalls.
2. **A lockfile supply-chain guard** (`sakimori deps check` and
   `sakimori deps watch`): runs a "minimum release age" check across
   4 ecosystems (npm, cargo, pypi, nuget), flagging recently-published
   dependencies so you can sit out the window in which malicious
   releases typically live.

## Known limitations (read these before changing behaviour)

These are **accepted** limitations — not bugs. The architecture
has them on purpose, and the docs are honest about each.

### `deps watch` is detection, not prevention

The watch mode subscribes to FS events on lockfiles. It fires
*after* the package manager has finished writing the lockfile,
which means:

- **npm / pnpm / yarn**: `preinstall` / `install` / `postinstall`
  scripts have already executed by the time the lockfile changes.
  Any .ssh / env / crontab / launchd-service mischief from a
  malicious package **cannot be undone** by reverting the lockfile.
- **pypi (pip / uv / poetry)**: `setup.py` / build-backend hooks
  execute during install. Same story as npm.
- **cargo / dotnet**: the initial `add`/`restore` just updates
  the lockfile and extracts the crate — code doesn't run until
  the next `cargo build` / `dotnet build`. In principle watch has
  a window between those two points… **but** rust-analyzer,
  OmniSharp, file-save hooks in IDEs, and other background
  tooling often invoke the build automatically, closing that
  window quickly. In practice: treat cargo/dotnet the same as
  npm/pypi for threat-model purposes.

**Practical consequence**: `deps watch` is most useful as a
passive audit alarm ("hey, you just pulled in a 2-hour-old crate")
rather than as a wall against script-based attacks. The only way
to reliably *prevent* those is to check BEFORE install happens
(see `deps check` in CI, or the planned `install-gate` wrapper).

### Auto-fallback (pnpm-style): crates.io only, via the proxy

pnpm 10.x's `minimumReleaseAge` teaches its resolver to **filter
versions younger than the threshold out of its candidate set**,
silently resolving to the newest in-range version that also meets
the age requirement. Builds don't break; they just use slightly
older deps.

**Status (v0.17):**
- **crates.io** — ✅ implemented via the proxy. `sakimori
  proxy serve` rewrites `index.crates.io` sparse-index responses on
  the fly, dropping JSONL lines whose `(name, vers)` publish time is
  < `--min-age`. cargo's resolver sees only acceptable versions and
  naturally picks the newest older-in-range.
- **npm** — ✅ implemented. The proxy rewrites the packument
  endpoint (`registry.npmjs.org/<pkg>`): too-young entries are
  removed from both `versions` and `time`, and any `dist-tags`
  (notably `latest`) that pointed at a removed version is
  retargeted to the highest remaining semver. npm's resolver then
  picks the newest in-range surviving version — no error.
- **pypi** — ✅ implemented for all three metadata shapes pip / uv /
  legacy tools consult:
  - Warehouse JSON API (`pypi.org/pypi/<pkg>/json`) — drops version
    keys from `releases` whose earliest `upload_time_iso_8601` is
    too young, plus stripping the `urls` shortcut.
  - PEP 691 Simple JSON (`pypi.org/simple/<pkg>/` with
    `Accept: application/vnd.pypi.simple.v1+json`) — drops
    too-young `files[]`, prunes `versions[]` to only those with
    surviving files.
  - PEP 503 Simple HTML (`pypi.org/simple/<pkg>/` with
    `Accept: text/html`) — carries no inline publish time, so the
    rewriter consults an out-of-band lookup to the Warehouse JSON
    API via `PypiSimpleClient` (cached per-package for 10 min).
    Anchors whose filename-derived version is too young are dropped
    byte-for-byte from the HTML; surrounding markup is preserved so
    pip's tolerant parser sees the exact same document minus the
    filtered rows. Failed lookups yield an empty map → fail-open,
    but pinned `files.pythonhosted.org` fetches still hard-deny at
    the tarball layer.
- **nuget** — ✅ implemented for the **registration** endpoints
  (`api.nuget.org/v3/registration<X>*/<id>/index.json` and the
  paged `.../page/<lower>/<upper>.json`). Leaves whose
  `catalogEntry.published` is too young are dropped from every
  page's `items[]`; `count` fields are rewritten so they stay
  consistent. Pages that reference a separate URL instead of
  carrying inline items are left alone — the re-fetch is a new
  request and goes through the same rewriter.

  The **flat-container index** (`/v3-flatcontainer/<id>/index.json`
  — a plain `{"versions":[...]}` with no dates) is silently filtered
  via an out-of-band lookup to the registration endpoint. The
  `NugetFlatContainerClient` fetches
  `/v3/registration5-semver1/<id>/index.json`, extracts version→
  publish-time pairs (walking page references up to a bounded
  depth), caches the map per-package for 10 minutes, and feeds the
  rewriter's oracle. Failed lookups yield an empty map → fail-open,
  but pinned `.nupkg` fetches still hard-deny at the tarball layer
  so stale cache can't silently admit young versions.

For ecosystems without rewriting, `deps check` (CI) or the proxy's
hard-deny (desktop) is still the defense — just not silent.

### file block is "tripwire", not pre-open block

On Linux, `file.deny` in `mode: block` triggers
`bpf_send_signal(SIGKILL)` on the process that opened a
matching file. The file descriptor may briefly exist; the
process dies before it can consume its contents. This is
honest "after-the-open block" — for a truly pre-open block we
need `bpf_override_return` on a kprobe'd `do_sys_openat2`, which
is CONFIG_BPF_KPROBE_OVERRIDE dependent. Roadmap.

### exec block is audit-only

`process.deny_exec` stamps `denied: true` on matching events and
makes block-mode exit non-zero, but the child process does exec.
See above about `bpf_override_return`.

### Windows network default:deny is audit-only

Windows Defender Firewall evaluates block rules as winning over
allow. An "allowlist" pattern (`default: deny` + `allow: […]`)
would require flipping the system-wide default-outbound to Block,
which we won't do silently on a shared runner. `network.deny` is
kernel-enforced; `network.default: deny` is audit-only + warn.

## Roadmap (what to build next, in priority order)

1. **`sakimori install-gate`** — ✅ implemented in v0.19. Three
   subcommands:
   - `shellenv` — emits a shell-specific snippet that exports
     `HTTPS_PROXY` + `CARGO_HTTP_CAINFO` / `PIP_CERT` /
     `NODE_EXTRA_CA_CERTS` / `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`
     pointing at the proxy's CA bundle, so tools that don't honour
     the system trust store still validate the MITM certs.
   - `install` — appends `eval "$(sakimori install-gate shellenv)"`
     to the detected shell rc file, bracketed with idempotent
     sentinels so repeated runs don't duplicate.
   - `uninstall` — strips the block.

   After this, every `npm install` / `cargo add` / `pip install` /
   `dotnet add package` in a new shell routes through
   `sakimori proxy`. Because the proxy now does pnpm-style
   silent fallback for all four ecosystems (v0.15–0.18), the user
   sees no error on "install something young" — they just get the
   newest safe version. For an unhandled path or a tarball pin to
   a young version, the proxy returns 403 and the install stops.

   Caveat: the proxy has to be running. `install-gate install`
   prints a reminder; long-term we'll wire launchd / systemd
   user units so the proxy auto-starts.
2. **HTTPS registry proxy** — same idea but transparent: set
   `HTTPS_PROXY` system-wide, filter fetch traffic. No shell
   aliasing required, but MITM cert management is a UX chore.
3. ~~**NuGet flat-container auto-fallback**~~ — done.
   `NugetFlatContainerClient` fetches the registration endpoint
   out-of-band, caches the version→publish-time map per package,
   and feeds the flat-container rewriter. All four ecosystems
   now have silent fallback.
4. **Linux file/exec block via `bpf_override_return`** — clean
   pre-syscall block, requires runtime detection of
   CONFIG_BPF_KPROBE_OVERRIDE and a well-timed kprobe.
5. **macOS live block** — either a Network Extension (heavy, needs
   signing) or an HTTPS proxy (see #2).
6. **Retroactive CVE notification for past installs** — local-first
   half landed: the proxy's pinned-install path now appends every
   resolved fetch to `~/.sakimori/installs.jsonl`
   (`InstallEvent { ecosystem, name, version, resolved_at,
   execution_mode, user_agent }` — `project_path` and richer
   attribution come next), and `sakimori advisories scan` reads
   that log, dedupes by `(eco, name, version)`, and batch-queries
   [OSV.dev](https://osv.dev)'s `POST /v1/querybatch` for matching
   advisories. Hits exit non-zero so it slots into cron / CI.
   `execution_mode` classification is currently best-effort from
   the User-Agent (`npx` / `pipx` / `uvx` / `cargo-install` →
   ephemeral; known package managers → persistent; everything
   else → unknown). The proxy logger is on by default; opt out
   with `sakimori proxy start --no-install-log`. Local-first: no
   server, no upload, private dep trees never leave the machine —
   only `(eco, name, version)` tuples are sent to OSV.

   For team-wide push notifications, we ship **`sakimori-hub`** as
   an optional self-hostable companion: a small Rust service with
   a native `POST /ingest` endpoint that accepts the
   `InstallEvent` JSON schema, keeps an OSV mirror, runs the
   advisory-vs-install JOIN server-side, and dispatches webhooks
   / email / Slack when a past install matches a newly-published
   advisory. It is **strictly opt-in self-host** — there will be
   no Anthropic/coronarium-operated instance. Centralised SaaS
   remains out of scope; sakimori-hub is "here's the server you
   can run yourself if you want push notifications across a team."

   On top of (not instead of) the native `/ingest`, the proxy
   also offers an **opt-in OTLP exporter** (`sakimori proxy start
   --otlp-endpoint <url>`) that emits each install as an OTLP
   LogRecord with `package.*` attributes (`package.ecosystem`,
   `package.name`, `package.version`, `package.resolved_at`,
   `package.project_path`). This lets users fan installs out to
   any existing observability backend — Datadog / Honeycomb / Loki
   / a self-run otel-collector — without standing up sakimori-hub.
   The two transports coexist: pick `/ingest` for advisory push
   notifications, OTLP for general observability, both for either.

   **npx** works for free here (same `registry.npmjs.org` path
   the npm rewriter already handles); **Homebrew** does *not* fit
   minimumReleaseAge (formula updates are PRs to a git repo, not
   registry publishes with structured publish-time per version)
   but its installs can still be logged via HTTPS_PROXY for the
   advisory-scan side.

   **`InstallEvent.execution_mode`** — the schema distinguishes
   two install shapes, because retroactive CVE notification means
   different things for each:

   - `persistent` (`npm install`, `cargo add`, `pip install`,
     `dotnet add package`, etc.) — the package lands in a lockfile
     and stays there. Advisory notification → "bump and re-install"
     remediation. Standard SCA model.
   - `ephemeral` (`npx`, `pnpm dlx`, `yarn dlx`, `uvx`,
     `pipx run`, `cargo install`, `go run <remote>`, etc.) — the
     package is fetched, executed once, and (often) cached but not
     pinned in any project lockfile. Advisory notification cannot
     mean "bump"; it means **"this code ran on your machine on
     <date> with the running user's privileges — investigate
     potential compromise"**. The host UI must surface these
     differently (different colour / different recommended action)
     so reviewers don't try to "fix" them by editing a lockfile
     that doesn't reference them.

   Classification happens at proxy time from the User-Agent and
   the URL path shape (e.g. `npm` UA + a fetch under
   `/<pkg>/-/<pkg>-<ver>.tgz` without a preceding packument GET
   pattern matching a project resolution → `ephemeral`; same fetch
   following a packument GET from `node` + `npm-cli` context →
   `persistent`). When ambiguous, default to `persistent` and let
   the host UI mark it `mode: unknown` rather than mis-categorise
   as ephemeral and hide a real dependency.

   This is one of sakimori-hub's strongest differentiators —
   Dependabot / Snyk / Socket only see what's committed to a repo
   lockfile, so they fundamentally cannot notify on `npx` /
   `pipx run` / `cargo install` history. sakimori is positioned
   at the fetch layer, so it can.

   **Competitive landscape note**: no shipped product covers all
   four axes simultaneously — *package-aware* + *execution
   history* + *developer endpoint* + *retroactive advisory JOIN*.
   SCA tools (Snyk / Socket / Phylum / Dependabot) are
   package-aware but lockfile-scoped, so ephemeral runs are
   invisible. EDR / XDR (CrowdStrike, SentinelOne, Defender for
   Endpoint, Elastic Security) record every exec but see only
   `node` + argv, not "this was `npx leftpad@1.2.3`" — the
   advisory→exec correlation is manual threat-hunting, not a
   product feature. Registry firewalls (Sonatype Nexus Firewall,
   JFrog Xray) sit at the right layer but target enterprise
   artifact repos, not developer laptops. The gap exists because
   SCA is repo-bound and EDR's abstraction stops at the process
   tree; bridging them needs a fetch-layer agent on the endpoint,
   which is exactly where sakimori already lives.

   **Alert-fatigue caveat** (don't ship this naïvely): if every
   low-severity advisory triggers a "you may have executed this 3
   weeks ago" notification, the signal drowns immediately. The
   ephemeral-mode notifier must be gated on at least:
   (a) severity ≥ High or known-exploited (KEV / GHSA `actively
   exploited`),
   (b) the advisory implicates install-time or run-time code paths
   (postinstall script, build-backend hook, or RCE in the imported
   surface — not e.g. a ReDoS in a code path the one-shot never
   touched),
   (c) package-popularity / typosquat heuristics to deprioritise
   obvious noise.
   These filters should be tunable and default conservative; the
   "investigate compromise" framing is high-cost-per-alert and
   loses credibility fast if it cries wolf.

### harden-runner parity gaps (tracked but not yet scheduled)

These are features `step-security/harden-runner` ships that
coronarium currently does not. Listed roughly in descending order
of value-per-implementation-cost.

6. **Enriched `$GITHUB_STEP_SUMMARY`** — ✅ implemented in v0.20.
   The supervisor now writes per-host (Connect), per-path (Open),
   and per-binary (Exec) top-N tables into the step summary,
   marking denied rows with ❌ so reviewers can spot the offending
   destinations directly on the run page without downloading the
   JSON log.
7. **`coronarium policy suggest <audit-log.json>`** — ✅ implemented
   in v0.20. Reads a JSON audit log (typically produced by an
   audit-mode run) and emits a starter `policy.yml` with every
   observed host/port pair on `network.allow`, observed file
   parents on `file.allow`, and observed exec'd binaries listed
   under a commented `# observed_exec` block. Reduces the "stare
   at the log and hand-craft the policy" friction that today
   blocks teams from flipping `mode: audit` → `mode: block`.
8. **SNI / hostname-based egress in the proxy** — ✅ implemented
   in v0.33. New `--network-allow <pattern>` (repeatable) and
   `--network-allow-file <path>` flags on `sakimori proxy start`
   configure a default-deny hostname allow-list enforced at
   `handle_request`. CONNECT requests pull the target from
   `req.uri().authority()`; plain HTTP from the `Host:` header; a
   missing Host with the policy active is treated as deny (no
   silent slip-through). Pattern grammar in `host_allow.rs`:
   `host.example.com` (exact, case-insensitive), `*.example.com`
   (any subdomain, excludes the apex by design); embedded `*` is
   a parse error. Off by default. Closes the eBPF-by-IP weakness
   against CDN rotation — every `*.githubusercontent.com` IP that
   happens to be live this minute resolves correctly because we
   filter by the SNI/Host name the client actually asked for.
9. **Workspace tamper detection** — ✅ implemented in v0.22 as
   standalone `coronarium workspace snapshot <dir>` +
   `coronarium workspace diff <baseline.json> <dir>`. Walks every
   regular file under the root, hashes with SHA-256, skips a
   hardcoded build-artefact list (`.git`, `node_modules`, `target`,
   `dist`, `build`, `vendor`, `__pycache__`, `.venv`, `venv`,
   `.next`, `.turbo`, `.cache` — deliberately not honouring
   `.gitignore`, since an attacker can write into it). Symlinks are
   recorded by target string, not followed. Files over 64 MiB
   default to size-only entries (configurable). Diff exits non-zero
   on drift unless `--allow-drift`. Also wired into `sakimori run`
   via `--snapshot-workspace <DIR>` (v0.34): supervisor takes the
   baseline before exec'ing the supervised command, takes a fresh
   snapshot at exit, attaches the diff to the JSON log under
   `workspace_drift`, surfaces it as a "Workspace drift" section in
   the step summary, and (in `mode: block`) exits non-zero on any
   drift the same way denied events do.
10. **Floating-tag → SHA-pin static check** — ✅ implemented in v0.21
    as `coronarium actions audit <workflow.yml...>`. Walks every
    `uses:` in `jobs.<id>.steps[]` and `jobs.<id>.uses` (reusable
    workflow callers) and classifies each as Ok (40-char hex SHA,
    local action, or docker `@sha256:` digest), Warn (first-party
    `actions/*` / `github/*` with a mutable tag — risky but lower
    blast radius), or Error (third-party with a mutable tag/branch).
    Text + JSON output, `--strict` escalates Warn → Error. Opt-in
    Tag→SHA auto-resolution via `--resolve` (v0.34): `GithubResolver`
    hits `GET /repos/{o}/{r}/commits/{ref}`, caches per
    `(owner, repo, ref)`, surfaces the resolved SHA as `→ resolved:
    <sha>` in text mode and `resolved_sha` in JSON. Failures
    (rate-limit, removed action) populate `resolve_error` per
    finding without aborting the audit. Reads `GITHUB_TOKEN` from
    the env to lift the rate limit from 60/hour to 5000/hour.
11. **Per-step / per-PID source attribution** — ✅ implemented in
    v0.23. Linux drain task walks the PPid chain via
    `/proc/<pid>/{status,cmdline}` for each event and attaches an
    `attribution::Attribution` (full chain + first matching
    package-manager argv) to the event before it's stored in
    Stats. Recognised package managers: npm, pnpm, yarn, cargo,
    pip (incl. `pip3.x`), uv, poetry, dotnet, go, maven, gradle,
    bundler, composer. The supervisor's own pid is excluded from
    the chain. Surfaces in the JSON log as a `source` field on
    every event and in the step summary as a "Sources" top-N
    table grouping events by originating package manager — the
    "wait, what's `npm install foo@1.2.3` doing connecting to
    that?" answer harden-runner gives. Best-effort: if the event
    pid has already exited by drain time the attribution is
    `None` and the event is unaffected. Non-Linux supervisors
    (Windows ETW) leave `source: None` for now.
12. **Job-scoped supervised mode** — ✅ implemented across two surfaces.
    - **Binary** (v0.35): `sakimori daemon start` / `daemon stop`.
      `start --observe-cgroup-of <pid>` reads `/proc/<pid>/cgroup`,
      finds the v2 unified path, and attaches connect4/connect6 +
      tracepoint programs to *that existing cgroup* — no process
      migration. The runner's own cgroup management is left untouched
      and cgroup v2 descendant inheritance does the cross-step work
      for free. Daemon parks until SIGTERM, then writes the same
      JSON / step-summary / HTML report `sakimori run` produces.
      `stop` sends SIGTERM via the pid-file and waits for clean
      exit; idempotent on missing / stale pid-files. Block-mode
      denial surfaces via `::error::` annotations from the daemon's
      stderr + a non-zero post-step exit code parsed back from the
      JSON log (the daemon's own exit code can't propagate through
      `stop`).
    - **Action** (`bokuweb/sakimori/job@v0`): subpath JS action with
      pre/main/post hooks. `pre.js` installs sakimori, spawns
      `sudo sakimori daemon start --observe-cgroup-of $PPID`
      detached with stdio→files, and polls for the pid-file before
      letting other steps run. `post.js` issues `daemon stop`,
      drains the daemon's stderr, and re-parses the JSON log to
      fail the job in block mode. Zero JS deps — pre/main/post read
      `INPUT_*` straight from env and shell out for the heavy
      lifting. Linux only. The original composite
      `bokuweb/sakimori@v0` (single-step + Windows) is untouched.

      `pre.js` honours pre-set `SAKIMORI_BIN` + `SAKIMORI_BPF_OBJ`
      env to skip the `gh release download` path — used by the
      `job-scoped-smoke` CI job to test the action against a
      locally-built binary, also useful for air-gapped mirrors.

      Sub-action `bokuweb/sakimori/job/stop@v0` (composite, one
      step) is a 1-line shortcut for the "flush the daemon early
      before `actions/upload-artifact` inside the same job"
      pattern. Replaces the previous 4-line `sudo -n -E
      $SAKIMORI_BIN daemon stop --pid-file $SAKIMORI_JOB_PIDFILE`
      snippet so consumer workflows don't have to know about
      pid-files or sudo. Idempotent + Linux-only-no-op so it can
      be dropped into cross-OS matrices unchanged.

      **Out of scope for this iteration**: container jobs
      (`jobs.<id>.container:`) — the host-side cgroup attach can't
      reach steps that run inside the container. `pre.js` detects
      `/.dockerenv` and known container-y `/proc/1/cgroup` patterns
      and emits a `::warning::` rather than hard-failing, since the
      daemon's own attach error is the real source of truth. Also
      out of scope: matrix / reusable-workflow shards (each is its
      own Runner.Worker = its own job = needs its own
      `bokuweb/sakimori/job@v0`).

Explicitly **out of scope** (different product philosophy, not
a missing feature):

- Centralised SaaS dashboard / cross-runner correlation. coronarium
  is local-first; the JSON log + HTML report are the artefacts.
- Automatic runner hardening (sudo disabling, immutable rootfs).
  We don't take destructive actions on the runner without an
  explicit opt-in.

## Crate layout

```
crates/
├── sakimori-common/   no_std + std types shared with eBPF (ring
│                        buffer records, map keys, POD structs).
├── sakimori-core/     Platform-neutral Rust: events, policy,
│                        matcher, stats, html, report, deps::*, watch.
├── sakimori-ebpf/     Linux kernel programs (tracepoint / cgroup
│                        hooks). Compiled to bpfel-unknown-none with
│                        nightly; excluded from the main workspace.
├── sakimori/          Linux userspace binary (eBPF loader +
│                        supervisor).
└── sakimori-win/      Windows binary (ETW subscriber, Defender
│                        Firewall driver). Its own workspace so
│                        ferrisetw doesn't pollute the Linux side.
```

`sakimori-core::deps` houses the per-ecosystem lockfile parsers
and registry clients. To add a new ecosystem:

1. `deps::lockfile::<name>` parser (input: path → `Vec<Package>`).
2. `deps::registry::<name>` client (input: `(name, version)` →
   `DateTime<Utc>`).
3. Add the variant to `deps::Ecosystem` + label.
4. Extend `deps::lockfile::detect` for the basename.
5. Fixture under `tests/fixtures/` and CI assertion in
   `.github/workflows/ci.yml`.
6. Bump the "supported" table in README.

## Pre-commit gate (non-negotiable)

Every commit pushed to a branch — by a human or an agent — must pass
all three of the following, with no warnings or failures:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

This is the same set CI runs, just locally. Fix the cause; don't
push red and don't `#[allow(...)]` away a clippy lint without a
comment explaining why the lint is wrong for that code. If a test
is genuinely flaky (e.g. nanos-based tmpdir collisions under
parallel runs) re-run once and, if it still fails, fix the flake
in a separate commit rather than ignoring it.

## Testing conventions

- **Test-first whenever possible.** Handler traits are specifically
  designed to be mockable (see `action::Prompter`, `watch::Notifier`,
  `watch::EventSource`) so the interesting logic sits behind a
  deterministic fake and doesn't need real IO.
- Use `cargo test -p sakimori-core` for fast iteration; the full
  workspace runs eBPF + aya code that only builds meaningfully on
  Linux.
- Use real `git` in tests (not a mock) when that's cheaper than
  faking. `GitRevert` tests set up a real tmp repo — fast enough.
- Don't assert on exact error messages; search for substrings. CI
  runs across kernels and libc versions that differ in phrasing.

## Release process

Any push of a `v*` tag triggers `.github/workflows/release.yml`:
cross-compiles Linux (musl x86_64 + aarch64), macOS (both archs on
a single macos-14 runner), and Windows, then publishes a GitHub
Release with SHA-256 sidecars. The `v<MAJOR>` floating tag is
force-pushed to the newest release so consumers can pin `@v0`.

If you need to skip the floating tag update (e.g. for a prerelease
containing a hyphen like `v0.13.0-rc1`), the `moving-tag` job is
already gated on `!contains(github.ref_name, '-')`.

## Never do these

- Don't add `println!`/`eprintln!` on the hot event-ingest path
  — it serialises on the stdout mutex and tanks throughput.
- Don't put secrets in `log::` output. The JSON log is routinely
  uploaded as an artifact and surfaced in PR comments.
- Don't quietly change semantics (eg. make `watch` destructive by
  default). If the behaviour is potentially surprising, require
  an explicit `--action=…` opt-in and document the rationale.
- Don't auto-update the `v0` tag from a human workflow. Let
  `release.yml`'s `moving-tag` job own that.
