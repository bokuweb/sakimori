# sakimori

[![CI](https://github.com/bokuweb/sakimori/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/bokuweb/sakimori/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/bokuweb/sakimori?sort=semver)](https://github.com/bokuweb/sakimori/releases/latest)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Cross-platform supply-chain guard for every package manager on your
machine.** Silently blocks too-young versions, known-malicious packages
and unsigned publishes — across **npm, cargo, pypi, nuget** — without
touching your build tools.

```bash
# Three commands, once.
$ sakimori proxy install-ca       # trust the proxy's root CA
$ sakimori proxy install-daemon   # auto-run in the background
$ sakimori install-gate install   # route your shell through it

# Business as usual, permanently safer.
$ npm install react
# → proxy silently drops versions < 7d old
# → npm picks the newest older version
# → no error, no broken build, just a measurably safer dependency
```

Works on **macOS, Linux, and Windows**. Also ships a CI mode
(`deps check` + eBPF/ETW supervisor) for pipelines.

- [Why this exists](#why-this-exists)
- [How it works](#how-it-works) — proxy architecture, 4 ecosystems
- [Install](#install)
- [Desktop quick start](#desktop-quick-start)
- [Feature reference](#feature-reference) — every subcommand with examples
- [CI usage (GitHub Actions)](#ci-usage-github-actions)
- [Docker image](#docker-image)
- [Configuration reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations) — what this honestly can't do
- [Development](#development)

---

## Why this exists

Supply-chain attacks follow a predictable timeline:

1. Attacker publishes a malicious version at `T+0`
2. Community notices, yanks it at `T+12–72h`

Most victims install between hours 0–12. **pnpm 10.x** introduced
[`minimumReleaseAge`](https://pnpm.io/next/settings#minimumreleaseage)
to solve this for npm only — versions younger than the threshold
become invisible to the resolver, which silently falls back to the
newest older one.

**sakimori brings the same behaviour to all four major ecosystems**
(crates.io, npm, pypi, nuget) and any package manager that talks to
them, by sitting as an HTTPS proxy and rewriting the registry's
metadata responses in-flight. No resolver integration. No config in
your package manifests.

## How it works

```
            ┌───────────────────┐       ┌────────────────────┐
            │  npm / cargo /    │       │                    │
  user ───► │  pip / uv /       │ ─────►│  sakimori proxy  │ ──► real registry
            │  dotnet / poetry  │  HTTPS│  (localhost:8910)  │     (metadata + tarball)
            └───────────────────┘       └─────────┬──────────┘
                                                  │
                                                  ▼
                                         rewrites metadata:
                                         - drop versions < --min-age
                                         - drop unsigned versions (--require-provenance)
                                         - retarget npm dist-tags.latest
                                         - returns 403 for pinned tarball fetches
                                           to too-young versions
```

The proxy's root CA is installed into the system trust store once;
from then on, every HTTPS request your package managers make through
`HTTPS_PROXY=http://127.0.0.1:8910` gets transparently filtered.

### Ecosystem coverage

| ecosystem | silent auto-fallback | hard deny on pinned fetch |
|---|---|---|
| **crates.io** | ✅ sparse-index JSONL rewrite (drops too-young lines from `/<prefix>/<name>`) | ✅ `403` on `.crate` download to a denied version |
| **npm** | ✅ packument rewrite (drops versions + retargets `dist-tags.latest`) | ✅ `403` on `.tgz` download |
| **pypi** | ✅ Warehouse JSON API (`/pypi/<pkg>/json`) + PEP 691 Simple JSON + PEP 503 Simple HTML via JSON-API lookup | ✅ `403` on `files.pythonhosted.org` tarball download |
| **nuget** | ✅ registration-page rewrite (`/v3/registration*/...`) + flat-container index via registration lookup | ✅ `403` on `.nupkg` download |

All four ecosystems' metadata paths now rewrite silently — pnpm-style
`minimumReleaseAge` across the board, no fail-hard in the common case.

---

## Install

Pick whichever fits your setup.

### Homebrew (macOS / Linux)

```bash
brew install bokuweb/sakimori/sakimori
# ↑ the repo-is-its-own-tap convention; no separate `brew tap` needed.
```

Auto-updated on every release via the `homebrew-formula.yml`
workflow — the formula lives at
[`HomebrewFormula/sakimori.rb`](HomebrewFormula/sakimori.rb)
in this repo.

### Pre-built binary (macOS / Linux / Windows)

```bash
# macOS (Apple Silicon)
curl -fsSL https://github.com/bokuweb/sakimori/releases/latest/download/sakimori-aarch64-apple-darwin.tar.gz \
  | sudo tar -xz -C /usr/local/bin

# macOS (Intel)
curl -fsSL https://github.com/bokuweb/sakimori/releases/latest/download/sakimori-x86_64-apple-darwin.tar.gz \
  | sudo tar -xz -C /usr/local/bin

# Linux (x86_64 musl static)
curl -fsSL https://github.com/bokuweb/sakimori/releases/latest/download/sakimori-x86_64-unknown-linux-musl.tar.gz \
  | sudo tar -xz -C /usr/local/bin

# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/bokuweb/sakimori/releases/latest/download/sakimori-x86_64-pc-windows-msvc.tar.gz -OutFile c.tgz
tar -xzf c.tgz -C "$env:USERPROFILE\.local\bin"
```

Every release also ships a `.sha256` sidecar. The archive contains
the `sakimori` binary (Linux also ships `sakimori.bpf.o` for the
supervised-run mode).

### Docker / OCI

```bash
docker run --rm -p 8910:8910 \
    -v sakimori-conf:/etc/sakimori-xdg \
    ghcr.io/bokuweb/sakimori-proxy:v0 \
    --listen 0.0.0.0:8910 --min-age 7d
```

Mount `/etc/sakimori-xdg` as a volume to persist the generated
root CA across container restarts. See [Docker image](#docker-image).

### From source

```bash
cargo install --git https://github.com/bokuweb/sakimori sakimori
```

The Linux eBPF supervised-run mode additionally needs
`rustup toolchain install nightly --component rust-src` +
`cargo install bpf-linker`. Not required for proxy / deps / install-gate.

---

## Desktop quick start

Three commands, once per machine. Each is idempotent.

```bash
# 1. Generate the proxy's root CA and install it into the system
#    trust store. macOS uses `security`, Linux uses
#    `update-ca-certificates`, Windows uses elevated
#    `Import-Certificate` (triggers one UAC prompt).
sakimori proxy install-ca

# 2. Register the proxy as a background service so it's always up.
#    macOS: ~/Library/LaunchAgents/com.sakimori.proxy.plist
#    Linux: ~/.config/systemd/user/sakimori-proxy.service
#    Windows: Task Scheduler /sakimori-proxy
sakimori proxy install-daemon
# Follow the printed `launchctl bootstrap …` / `systemctl --user enable --now`
# / `schtasks.exe /Create …` line.

# 3. Append HTTPS_PROXY + CA bundle env vars to your shell rc.
#    Detects zsh / bash / fish / PowerShell from $SHELL (or your OS).
sakimori install-gate install
```

Open a new shell — everything's wired:

```
$ env | grep -E 'HTTPS_PROXY|CARGO_HTTP_CAINFO'
HTTPS_PROXY=http://127.0.0.1:8910
CARGO_HTTP_CAINFO=/Users/you/.config/sakimori/ca.pem

$ sakimori doctor
sakimori doctor
────────────────────────────────────────────────────────────
✓ CA certificate               /Users/you/.config/sakimori/ca.pem (644 bytes)
✓ CA private key               /Users/you/.config/sakimori/ca.key
✓ Proxy reachable              accepted TCP on 127.0.0.1:8910
✓ $HTTPS_PROXY                 http://127.0.0.1:8910
✓ install-gate rc              /Users/you/.zshrc
✓ Daemon unit                  /Users/you/Library/LaunchAgents/com.sakimori.proxy.plist
────────────────────────────────────────────────────────────
6 check(s): 0 fail, 0 warn
```

From here, `npm install` / `pnpm add` / `yarn add` / `cargo add` /
`cargo build` / `pip install` / `uv add` / `poetry add` /
`dotnet add package` / `dotnet restore` all flow through the proxy.

### Observable proof that it works

```bash
$ curl -s https://index.crates.io/se/rd/serde | wc -l           # direct
315

$ curl -sx http://127.0.0.1:8910 https://index.crates.io/se/rd/serde | wc -l
306     # the 9 most recent versions are invisible to cargo's resolver
```

cargo picks the newest remaining in-range version — no error, just
safer. Same shape on the other three ecosystems.

### Uninstall

Reverse each step (same flags):

```bash
sakimori install-gate uninstall    # strip block from shell rc
sakimori proxy uninstall-daemon    # remove launchd / systemd / Task Scheduler unit
sakimori proxy uninstall-ca        # remove CA from system trust store
rm -rf ~/.config/sakimori          # delete CA + key (optional)
```

---

## Feature reference

### `proxy start`

Start the MITM HTTPS proxy in the foreground. `install-daemon`
wraps this for background use; run it directly when you want logs
on stdout or you're running the proxy yourself in Docker.

```
sakimori proxy start [OPTIONS]

Options:
  --listen <ADDR>              [default: 127.0.0.1:8910]
  --min-age <DURATION>         [default: 7d]
      Grammar: `<N>{d,h,m,s}`. Versions younger than this are
      invisible to the resolver.
  --fail-on-missing            Treat unknown publish dates as deny
                               (default: fail-open / allow through).
  --require-provenance         Strict mode. Drop every npm package
                               version without a Sigstore provenance
                               claim. Forces publishers to have gone
                               through OIDC-authenticated CI.
                               (npm only for now.)
  --osv                        Consult OSV.dev on every decision.
                               Versions flagged as malicious
                               packages (MAL-* or advisories
                               mentioning "malicious") are hard-
                               denied regardless of --min-age.
                               Live API, per-version cached.
  --osv-mirror                 Same blocking rule as --osv, but
                               consumed from the sakimori-hosted
                               pre-filtered snapshot. O(1) in-memory
                               lookup after a single ~10-minute
                               background refresh. ~10 min behind
                               OSV publish time in exchange for
                               not hitting api.osv.dev per request.
                               Combine with --osv to additionally
                               fall back to the live API for
                               entries the mirror hasn't indexed.
  --osv-mirror-url <URL>       Override mirror URL (e.g. self-hosted).
  --network-allow <HOST>       Hostname egress allow-list (repeatable).
                               Patterns: `host.example.com` (exact) or
                               `*.example.com` (any subdomain, excludes
                               apex). When set, the proxy default-denies
                               every CONNECT/HTTP whose target host
                               doesn't match, returning 403. Off by
                               default — without any flag, every host
                               passes through.
  --network-allow-file <PATH>  Read additional `--network-allow`
                               patterns from a file (one per line;
                               `#` comments / blank lines skipped).
  --config-dir <PATH>          Override CA / config directory.
                               Defaults to $XDG_CONFIG_HOME/sakimori
                               on Unix, %LOCALAPPDATA%\sakimori on
                               Windows.
```

**First-run side effect**: generates a self-signed root CA at the
config dir and prints the OS-specific trust command. Subsequent runs
reuse the existing CA.

**Egress allow-list** closes the eBPF-by-IP gap: when you also run
`sakimori run` with a network policy, the kernel layer enforces by
resolved IP and loses against CDN rotation. The proxy's hostname
filter sees the SNI / `Host:` value the client actually asked for,
so an entry like `*.githubusercontent.com` matches every rotating
CDN IP automatically — the same convention `step-security/harden-runner`
users are used to:

```bash
sakimori proxy start \
    --network-allow api.github.com \
    --network-allow '*.githubusercontent.com' \
    --network-allow registry.npmjs.org
```

### `proxy install-ca` / `uninstall-ca`

Add / remove the root CA from the OS trust store. Cross-platform:

| OS | Mechanism | Privilege prompt |
|---|---|---|
| macOS | `security add-trusted-cert -k /Library/Keychains/System.keychain` | `sudo` |
| Linux | copy to `/usr/local/share/ca-certificates/` + `update-ca-certificates` | `sudo` |
| Windows | `Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root` | UAC via `Start-Process -Verb RunAs` |

If you're not elevated, sakimori prints the exact shell command
and exits — no silent reruns with privileges.

```
sakimori proxy install-ca [--config-dir <PATH>]
sakimori proxy uninstall-ca [--config-dir <PATH>]
```

### `proxy install-daemon` / `uninstall-daemon`

Write a user-level service unit so the proxy runs in the
background at login and restarts on failure.

| OS | Unit | Location |
|---|---|---|
| macOS | launchd plist (`KeepAlive`, `RunAtLoad`, `Background` ProcessType) | `~/Library/LaunchAgents/com.sakimori.proxy.plist` |
| Linux | systemd `--user` unit (`Restart=on-failure`, `WantedBy=default.target`) | `~/.config/systemd/user/sakimori-proxy.service` |
| Windows | Task Scheduler v1.4 XML (`LogonTrigger`, `RestartOnFailure 99×1m`, `Hidden`) | `%LOCALAPPDATA%\sakimori\sakimori-proxy.task.xml` |

```
sakimori proxy install-daemon [OPTIONS]

Options:
  --listen <ADDR>         [default: 127.0.0.1:8910]
  --min-age <DURATION>    [default: 7d]
  --binary <PATH>         Override the sakimori binary path baked
                          into the unit. Defaults to the canonical
                          path of the currently-running executable.
```

The command prints the exact activation line (`launchctl bootstrap`
/ `systemctl --user enable --now` / `schtasks.exe /Create`) — run
that to start the service.

### `install-gate`

Edit the user's shell rc file so every new shell exports
`HTTPS_PROXY` + CA-bundle env vars pointing at the proxy. Idempotent
via `# >>> sakimori install-gate >>>` sentinels.

```
sakimori install-gate shellenv [--listen <ADDR>] [--shell {bash,zsh,fish,powershell}]
sakimori install-gate install  [--rc <PATH>]     [--shell ...]
sakimori install-gate uninstall [--rc <PATH>]    [--shell ...]
```

Environment variables set (per shell):

| var | who uses it |
|---|---|
| `HTTPS_PROXY` / `HTTP_PROXY` (+ lowercase variants) | curl, npm, pip, cargo, dotnet, git |
| `CARGO_HTTP_CAINFO` | cargo (uses libcurl; doesn't honour system trust store on Linux) |
| `PIP_CERT` | pip |
| `NODE_EXTRA_CA_CERTS` | npm, yarn, pnpm |
| `REQUESTS_CA_BUNDLE` | Python `requests`, poetry, uv |
| `SSL_CERT_FILE` | generic OpenSSL-using tools |

Default rc file per shell:

| shell | path |
|---|---|
| bash | `~/.bashrc` |
| zsh  | `~/.zshrc` |
| fish | `~/.config/fish/config.fish` |
| powershell | `$PROFILE` = `~/Documents/PowerShell/Microsoft.PowerShell_profile.ps1` |

### `doctor`

One-command diagnostic. Checks:

1. CA certificate exists + non-empty
2. CA private key exists + `chmod 600` (Unix)
3. Proxy is accepting TCP on `--listen`
4. `$HTTPS_PROXY` in the current shell matches the proxy address
5. Shell rc file contains the install-gate sentinel
6. Daemon unit file exists at the expected location

Exits `0` on no failures (warnings are informational), `1` otherwise.

```
sakimori doctor [--listen <ADDR>] [--config-dir <PATH>] [--rc <PATH>]
```

Sample output when the proxy is down:

```
✓ CA certificate               /Users/you/.config/sakimori/ca.pem (644 bytes)
✓ CA private key               /Users/you/.config/sakimori/ca.key
✗ Proxy reachable              no listener on 127.0.0.1:8910: Connection refused
  ↳ start it: `sakimori proxy start` (or, for background: `sakimori proxy install-daemon`)
! $HTTPS_PROXY                 unset in this shell
  ↳ run `sakimori install-gate install` and open a new shell
```

### `deps check`

Lockfile-level age gate, usable standalone (no proxy required). Good
for a **pre-install CI step** that fails the build before the
malicious package is even fetched.

```bash
sakimori deps check --min-age 7d Cargo.lock package-lock.json

# Different thresholds per ecosystem? Run twice.
sakimori deps check --min-age 14d Cargo.lock
sakimori deps check --min-age  3d package-lock.json

# Ignore first-party packages.
sakimori deps check --min-age 7d --ignore '@my-org/*' package-lock.json

# Machine-readable output for CI gating.
sakimori deps check --min-age 7d --format json Cargo.lock
```

Supported lockfile formats:

| ecosystem | lockfile | registry endpoint consulted |
|---|---|---|
| cargo | `Cargo.lock` | `crates.io/api/v1/crates/<name>` |
| npm | `package-lock.json` (lockfileVersion ≥ 2) | `registry.npmjs.org` |
| pypi | `uv.lock`, `poetry.lock`, `requirements.txt` (exact `==` pins only) | `pypi.org/pypi/<name>/<version>/json` |
| nuget | `packages.lock.json` (central-package-management) | `api.nuget.org/v3/registration5-{semver1,gz-semver2}/…` |

Exit codes:

| code | meaning |
|---|---|
| 0 | all packages meet the threshold |
| 1 | at least one violation |
| 2 | parse or I/O error |

Cache location: `$XDG_CACHE_HOME/sakimori/deps-cache.json`
(`%LOCALAPPDATA%\sakimori\…` on Windows). Publish dates are
immutable, so there's no TTL.

### `deps verify-cache`

Re-hash the package manager's local cache against the lockfile's
`integrity:` fields and fail if any byte doesn't match what the
lockfile pinned. This catches the *content* half of the **TanStack
2025 npm supply-chain attack**: a tarball restored from `actions/
cache` whose bytes have been swapped, while the lockfile entry
itself looks untouched.

Run it right after install, in the brief moment when the store is
fully populated but nothing has built against it yet:

```bash
# npm cacache (uses ~/.npm/_cacache by default)
sakimori deps verify-cache --lockfile package-lock.json

# pnpm store v3 (auto-picks ~/.local/share/pnpm/store/v3 on Linux,
# ~/Library/pnpm/store/v3 on macOS)
sakimori deps verify-cache --lockfile pnpm-lock.yaml

# cargo registry cache (walks $CARGO_HOME/registry/cache/*/)
sakimori deps verify-cache --lockfile Cargo.lock

# Override the store path (monorepos with isolated stores, corporate
# runners with non-standard layouts). Windows defaults are auto-
# detected (`%LOCALAPPDATA%\npm-cache\_cacache`, `%LOCALAPPDATA%\pnpm\store\v3`).
sakimori deps verify-cache --lockfile pnpm-lock.yaml --cache /opt/pnpm-store/v3

# Machine-readable for CI gating
sakimori deps verify-cache --lockfile package-lock.json --format json
```

Supported stores:

| ecosystem | lockfile | store walked |
|---|---|---|
| npm | `package-lock.json` (v2/v3) | `~/.npm/_cacache/content-v2/<algo>/<aa>/<bb>/<rest>` |
| pnpm | `pnpm-lock.yaml` (v6–v9) | `<store>/v3/files/<aa>/<rest>[-exec]` + per-tarball `-index.json` |
| cargo | `Cargo.lock` | `$CARGO_HOME/registry/cache/<reg>/<name>-<version>.crate` |

Exit codes:

| code | meaning |
|---|---|
| 0 | every lockfile entry verifies cleanly against the store |
| 1 | at least one mismatch or missing-from-store entry |
| 2 | parse / I/O error |

> ⚠️ **Honest limitations.** The pnpm verifier reads the on-disk
> `<rest>-index.json` to find per-file hashes — pnpm discards the
> tarball after extraction, so a fully coordinated rewrite of both
> the index and every blob it references would verify clean. The
> realistic single-file tampering pattern is caught. **pnpm v11+**
> (the next major after v10 — v10 itself still uses JSON) replaces
> the per-package JSON index with a single SQLite `index.db` whose
> BLOB values use msgpackr's non-standard `useRecords: true`
> extension. v11 stores are not yet supported and `verify-cache`
> will surface a clear `Unsupported` error rather than silently
> passing. Workaround until the reader lands: pin pnpm to `<11`.

The same check is wrapped as a one-line GitHub Actions step —
see [CI usage](#ci-usage-github-actions) below.

### `deps watch`

Long-running FS-event watcher for lockfile changes. Designed for
launchd at login.

```bash
# One-off (Ctrl-C to quit)
sakimori deps watch ~/code --min-age 7d

# With modal prompts (Keep / Revert via osascript)
sakimori deps watch ~/code --min-age 7d --action prompt

# Stdout logging, e.g. for tmux / screen
sakimori deps watch ~/code --min-age 7d --notifier stdout
```

`--action` controls what happens on violation:

| value | behaviour |
|---|---|
| `notify` (default) | Desktop notification. Lockfile untouched, nothing blocked. |
| `prompt` (macOS only) | Keep / Revert modal via osascript. Revert runs `git checkout HEAD -- <lockfile>`. |
| `revert` | Silently restore the lockfile to `HEAD` via git. Destructive; file must be tracked. |

> ⚠️ **Watch is detection, not prevention.** FS events fire *after*
> the package manager finishes writing the lockfile — so
> `preinstall` / `install` / `postinstall` scripts have already
> run. To actually *prevent* attacks, use the proxy (which sees
> every fetch) or `deps check` before install.

See [packaging/macos/README.md](packaging/macos/README.md) for the
launchd plist.

### `workspace snapshot` / `workspace diff`

Detect unexpected file edits made during a build — the supply-chain
analogue of "did this `npm install` rewrite my source files /
`.git/config` / CI configuration?". Pure offline; no network.

```bash
# Before the build
coronarium workspace snapshot $GITHUB_WORKSPACE -o /tmp/before.json

cargo build               # …or whatever you actually want to audit

# After the build — exits non-zero on any drift
coronarium workspace diff /tmp/before.json $GITHUB_WORKSPACE
```

What the diff reports: files **added**, **modified** (size or
SHA-256 changed), or **removed** between the two snapshots.

Always-skipped directory basenames (anywhere in the tree):
`.git`, `node_modules`, `target`, `dist`, `build`, `vendor`,
`__pycache__`, `.venv`, `venv`, `.next`, `.turbo`, `.cache`.
The list is hardcoded — `.gitignore` is **not** honoured because
an attacker can write into it. Pass `--skip <name>` (repeatable)
to extend the list for your own build artefacts.

Symlinks are recorded by target string; the link target is not
dereferenced. Files larger than 64 MiB default to a size-only
entry (no SHA), so two oversized files with identical sizes but
different contents will read as unchanged — bump
`--max-file-bytes` if that matters for your repo.

`--format json` for machine-readable output. `--allow-drift`
suppresses the non-zero exit when you only want the report.

### `actions audit`

Static analysis for `.github/workflows/*.yml`. Walks every `uses:`
in the workflow and flags any reference that isn't pinned to a
40-char commit SHA — the supply-chain analogue of an unpinned
dependency. Offline by default; opt into the GitHub API with
`--resolve` when you want the suggested replacement SHA inline.

```bash
sakimori actions audit .github/workflows/*.yml

# Machine-readable.
sakimori actions audit --format json .github/workflows/ci.yml

# Treat first-party (actions/*, github/*) mutable refs as blocking
# too — useful once you've already pinned all your third-party deps.
sakimori actions audit --strict .github/workflows/*.yml

# Look up the current SHA each mutable @<ref> resolves to via the
# GitHub REST API. Reads $GITHUB_TOKEN from the env to lift the
# rate limit from 60/hour to 5000/hour. The output gets a
# `→ resolved: <sha>` line per finding (text) or a `resolved_sha`
# field (JSON) so you can copy-paste the right pinned form.
sakimori actions audit --resolve .github/workflows/*.yml
```

Severity:

| | when |
|---|---|
| **error** | third-party action with mutable tag/branch (`foo/bar@v1`, `foo/bar@main`) |
| **warn**  | first-party (`actions/*`, `github/*`) mutable tag, or docker image without `@sha256:` digest |
| **ok**    | 40-char SHA pin, local action (`./...`), docker image with digest |

Exit code: `1` when at least one error is present (or any warn,
under `--strict`); `0` otherwise. Composite-action `action.yml`
files are ignored — only workflow files (those with a top-level
`jobs:` block) are walked. Resolution failures (rate-limit, removed
action) appear as `→ resolve failed: …` per finding without
aborting the audit.

**Workflow-level lint** (in addition to per-`uses:` SHA pinning):
the auditor also flags the `pull_request_target` + writable Actions
cache pattern — the TanStack 2025 cache-poisoning vector. If a
workflow runs on `pull_request_target` (or `workflow_run`) **and**
any job step writes to the GitHub Actions cache, that's an Error.

```bash
sakimori actions audit .github/workflows/bundle-size.yml
# .github/workflows/bundle-size.yml  (1 ok, 0 warn, 0 error)
#   ERROR  [pull_request_target_with_cache_write] workflow runs on
#          `pull_request_target` and writes to the Actions cache —
#          an untrusted fork PR can poison the cache that a later
#          trusted workflow restores (TanStack-style npm supply-chain
#          compromise). …
#          · size (actions/cache@v4): actions/cache writes via post-step on cache miss
```

Detected cache writers: `actions/cache@*`, `actions/cache/save@*`,
`actions/setup-{node,python,java,dotnet,ruby}` with `with.cache:`,
`actions/setup-go` (caches by default), `Swatinem/rust-cache`,
`mozilla-actions/sccache-action`, `astral-sh/setup-uv` with
`enable-cache: true`. Cache writes use a runner-internal token, not
the workflow `GITHUB_TOKEN`, so `permissions: contents: read` does
**not** block them. Split cache-writing steps into a separate
workflow that doesn't run on fork PRs, or gate the offending job
behind `if: github.event.pull_request.head.repo.full_name ==
github.repository`. JSON output puts these under a top-level
`workflow_findings` array alongside the per-`uses:` `findings`.

### `run`

Wraps a command under eBPF (Linux) / ETW (Windows) supervision and
observes — optionally denies — its syscalls:

- `connect(2)` on IPv4 / IPv6
- `openat(2)`
- `execve(2)`

```bash
sakimori run \
  --policy .github/sakimori.yml \
  --mode audit \
  --log sakimori.log.json \
  --html sakimori-report.html \
  -- cargo test
```

Flags:

| flag | env | default | description |
|---|---|---|---|
| `--policy` / `-p` | `SAKIMORI_POLICY` | — | policy file (YAML or JSON) |
| `--mode` | — | from policy | `audit` or `block` — overrides the policy's `mode:` |
| `--log` | — | `-` (stdout) | JSON audit log destination |
| `--summary` | `GITHUB_STEP_SUMMARY` | — | markdown summary |
| `--html` | — | — | self-contained HTML report (dark-mode aware, filterable) |
| `--snapshot-workspace` | — | — | dir to hash before/after the run; drift goes into the JSON log + step summary, and (in block mode) makes the run fail |
| `--snapshot-skip` | — | — | extra dir basenames to skip during the snapshot (repeatable) |

Exit code: child's exit code, unless `mode=block` and **either**:
- at least one event was denied, **or**
- a `--snapshot-workspace` baseline was taken and the post-run diff is non-empty

→ exits `1` either way.

Policy format:

```yaml
# .github/sakimori.yml
mode: block                    # audit | block

network:
  # default is `deny`, so only listed destinations can be reached.
  allow:
    - target: api.github.com   # A+AAAA resolved at startup
      ports: [443]
    - target: 140.82.112.0/20  # CIDR expanded (up to /16 for v4)
      ports: [22, 443]
    - target: 2606:4700::/48   # IPv6 CIDRs work too
      ports: [443]

file:
  default: allow               # most builds open hundreds of files
  deny:
    - /etc/shadow
    - /root/.ssh

process:
  deny_exec:
    - /usr/bin/nc

env:
  # Scrub the env block before the child execs. Real prevention,
  # not a tripwire — `Command::env_clear()` happens before
  # `execve`, so the child (and its postinstall grandchildren)
  # literally cannot read what's been stripped.
  default: pass                  # `pass` keeps everything not on `deny`;
                                 # `clear` flips it to allowlist mode
  allow: [PATH, HOME, "GITHUB_*"]
  deny: ["AWS_*", "*_TOKEN", "*_SECRET", NPM_TOKEN]
```

**First-time setup pattern** — run in `mode: audit` once, then let
`policy suggest` turn the log into a starter policy, prune by hand,
and flip to `mode: block`:

```bash
coronarium run --mode audit --log audit.json -- cargo test
coronarium policy suggest audit.json -o .github/coronarium.yml
$EDITOR .github/coronarium.yml      # remove anything you don't want allowed
coronarium run -p .github/coronarium.yml --mode block -- cargo test
```

`suggest` populates `network.allow` (one entry per host:port observed,
hostnames preferred over raw IPs) and `file.allow` (one entry per
parent directory observed). Exec targets are surfaced as a
commented `# observed_exec:` block — `process.deny_exec` is
deliberately left empty because the suggester can't know which of
the binaries the build actually wanted.

**Curated rule packs (`policy preset`):** ready-to-merge YAML blocks
for known supply-chain attack patterns. Currently shipped:

- `sakimori policy preset persistence` — `file.deny` tripwire for
  OS-level persistence writes (launchd / systemd / cron / shell rc
  / `~/.ssh`). Per-user paths expand from `$HOME` (override with
  `--home /path`); system paths always included.
- `sakimori policy preset cloud-secret-egress` — `network.deny`
  tripwire for AWS / GCP / Azure IMDS and STS-style secret
  endpoints. Pairs with `sakimori proxy start --network-allow ...`
  for SNI-level enforcement.

Both presets print to stdout (or `-o policy.yml`) with explanatory
comment headers so the operator can pick the entries that fit their
threat model and merge into an existing policy. The persistence
preset ships in `mode: audit` because its full list exceeds the
Linux 8-entry kernel cap on `file.deny` under `mode: block`; to
enforce, prune to your 8 most critical paths and flip the `mode:`
field to `block`. The cloud-secret-egress preset ships in
`mode: block` (no cap on `network.deny`).

**Known-IOC workspace scan (`workspace scan-iocs`):** walk a
workspace and flag files whose existence is a known supply-chain
compromise marker (e.g. `.claude/setup.mjs` dropped by the
Shai-Hulud npm worm). Distinct from `workspace diff` — diff catches
"something changed during the build," scan-iocs catches "this file
exists at all, which it shouldn't." The catalog is shipped bundled
in the binary (versioned YAML); override with `--index <file>` for
private feeds, suppress a triaged false positive with `--allow-id
<id>`. Exits non-zero on any Error-severity hit so it composes with
CI gates; Warn-severity hits surface but don't gate.

```bash
sakimori workspace scan-iocs $GITHUB_WORKSPACE
sakimori workspace scan-iocs . --json
```

The HTML report includes:
- verdict (ALLOW / DENY), kind, pid, comm
- **host column** (PTR-resolved reverse DNS for connect events)
- detail (IP:port / filename / exec argv)
- filter box matching across all fields
- dark-mode aware, self-contained (no external CSS/JS)

**Per-event source attribution (Linux):** the supervisor walks
`/proc/<pid>/{status,cmdline}` PPid chains at event time and tags
each event with the originating package manager (npm, pnpm, yarn,
cargo, pip, uv, poetry, dotnet, go, maven, gradle, bundler,
composer). That shows up as a `source: { package_manager, root_argv,
chain }` field on every JSON-log event and as a "Sources" top-N
table in the step summary, so a connect to `evil.example` reads as
"came from `npm install foo@1.2.3`" rather than just "from pid
12345 (sh)". Best-effort — pids that have already exited by the
time the userspace drain reads the ringbuf get `source: null` and
fall into the `(unattributed)` row. Windows ETW supervisor doesn't
attach attribution yet.

---

## CI usage (GitHub Actions)

### Minimal: run every install through the proxy

Works on **Linux, macOS, and Windows** GitHub-hosted runners (Windows
requires sakimori v0.34.3 or newer — earlier Windows release tarballs
ship only `sakimori-win.exe`, the ETW supervisor, which has no proxy
subcommand). The proxy starts in the background as the action's main
step, exports `HTTPS_PROXY` + the CA bundle for every common HTTPS
client via `$GITHUB_ENV`, and survives across `run:` step boundaries
until the post-step kills it at end-of-job.

```yaml
jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4

      # Spawns `sakimori proxy start` detached and appends
      # HTTPS_PROXY / CARGO_HTTP_CAINFO / NODE_EXTRA_CA_CERTS /
      # PIP_CERT / REQUESTS_CA_BUNDLE / SSL_CERT_FILE to $GITHUB_ENV
      # for every step after this one.
      - uses: bokuweb/sakimori/proxy@v0
        with:
          min-age: 7d

      - run: npm ci          # routed through the proxy
      - run: cargo test      # routed through the proxy
      - run: pip install -r requirements.txt   # routed through the proxy
```

Inputs:

| input | default | description |
|---|---|---|
| `min-age` | `7d` | Minimum package age. Same grammar as `--min-age`. |
| `listen` | `127.0.0.1:8910` | Proxy listen address. |
| `fail-on-missing` | `false` | Treat unknown publish dates as deny. |
| `version` | `v0` | sakimori release tag to download. |
| `token` | `${{ github.token }}` | Used by `gh release download`. |

Outputs:

| output | description |
|---|---|
| `ca-cert` | Absolute path to the proxy's root CA PEM. Also exported via `$GITHUB_ENV` as `CARGO_HTTP_CAINFO`, `PIP_CERT`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, and `SSL_CERT_FILE`. |

### Alternative: lockfile-only pre-flight check

Cheaper (no proxy), but fails loudly on any too-young dep instead
of silently falling back.

```yaml
- uses: bokuweb/sakimori@v0
- run: $SAKIMORI_BIN deps check --min-age 7d Cargo.lock package-lock.json
- run: cargo test   # only reached if the check passed
```

### Cache-poisoning guard: `bokuweb/sakimori/verify-cache@v0`

The proxy filters at **fetch** time — it can't see bytes restored
from `actions/cache`. If your workflow uses `actions/cache` (or
`actions/setup-node` with `cache:`, `Swatinem/rust-cache`, etc.) a
poisoned restore happens between cache-restore and install, behind
the proxy's back.

Drop this step in **right after install** to re-hash every blob in
the local store against the lockfile's `integrity:` fields:

```yaml
- uses: bokuweb/sakimori/proxy@v0
  with: { min-age: 7d }

- uses: actions/cache@v4
  with: { path: ~/.local/share/pnpm/store, key: ... }
- run: pnpm install        # populates / hits the cache

# ↓ catches TanStack-style cache poisoning: cache restored a
# tarball whose bytes don't match what the lockfile pinned.
- uses: bokuweb/sakimori/verify-cache@v0
  with:
    lockfile: pnpm-lock.yaml
```

Supports `package-lock.json`, `pnpm-lock.yaml`, and `Cargo.lock`;
auto-picks the cache root for the runner OS. Inputs:

| input | default | description |
|---|---|---|
| `lockfile` | (required) | Path to `package-lock.json`, `pnpm-lock.yaml`, or `Cargo.lock`. |
| `cache` | (auto) | Override the store root. Auto-detected from the runner OS — `~/.npm/_cacache` (Linux/macOS) or `%LOCALAPPDATA%\npm-cache\_cacache` (Windows) for npm; `~/.local/share/pnpm/store/v3` / `~/Library/pnpm/store/v3` / `%LOCALAPPDATA%\pnpm\store\v3` for pnpm; `$CARGO_HOME` (default `~/.cargo` or `%USERPROFILE%\.cargo`) for cargo. |
| `format` | `text` | `text` or `json`. |
| `version` | `v0` | sakimori release tag. |
| `token` | `${{ github.token }}` | Used by `gh release download`. |

Exit codes match the CLI: `0` clean, `1` on any mismatch / missing
entry. **pnpm v11+ SQLite stores are not yet supported** — the
action exits with a clear `Unsupported` error rather than passing
silently. (v10 still uses the JSON layout and works fine.)

### eBPF-supervised test run — job-scoped form (Linux only)

Use `bokuweb/sakimori/job@v0` when you want a single audit log covering
**every step in the job** instead of just one wrapped command. The
action's pre-hook spawns a background eBPF supervisor attached to the
runner-worker's cgroup; cgroup v2 inheritance means every step the
runner forks afterwards (`actions/checkout`, your `run:` blocks,
`actions/upload-artifact`, ...) is observed by the same supervisor.
The post-hook flushes the JSON log / step summary / HTML report and
fails the job if `mode: block` denied anything.

```yaml
runs-on: ubuntu-latest
steps:
  - uses: bokuweb/sakimori/job@v0   # MUST come before checkout so the
    with:                           # supervisor is up first
      policy: .github/sakimori.yml
      mode: block
      html: sakimori-report.html

  - uses: actions/checkout@v4
  - run: corepack enable
  - run: pnpm install --frozen-lockfile
  - run: pnpm build
  - run: pnpm test
  # post-hook of bokuweb/sakimori/job runs here automatically
```

Limitations: Linux runners only (Windows needs a different kernel
hook), and **container jobs** (`jobs.<id>.container:`) are unsupported
because the host-side cgroup attach can't reach steps that run inside
the container. Matrix shards and reusable-workflow callers are each
their own job and need their own `bokuweb/sakimori/job@v0`.

**Uploading the audit log from the same job**: the daemon writes
its JSON / HTML / step-summary at end-of-job (the post-hook), which
is too late for an `actions/upload-artifact` step inside the same
job. Drop in `bokuweb/sakimori/job/stop@v0` right before the
upload to flush the daemon early:

```yaml
- uses: bokuweb/sakimori/job@v0
  with: { policy: .github/sakimori.yml, mode: block }

- uses: actions/checkout@v4
- run: pnpm test

- uses: bokuweb/sakimori/job/stop@v0       # flush + stop
- uses: actions/upload-artifact@v4
  with:
    name: sakimori-report
    path: |
      sakimori.log.json
      sakimori-report.html
```

It's idempotent — the daemon's own post-hook turns into a no-op on
the missing pid-file. On non-Linux matrix entries the sub-action
no-ops silently, so it's safe to drop into a cross-OS workflow.

**Tamper detection**: pass `snapshot-workspace: <DIR>` to also catch
on-disk tampering. The daemon can't take the baseline itself (it
starts before checkout), so add a tiny step right after checkout that
records the baseline — the action exports the paths for you:

```yaml
- uses: bokuweb/sakimori/job@v0
  with:
    policy: .github/sakimori.yml
    mode: block
    snapshot-workspace: .

- uses: actions/checkout@v4
- run: sudo -E "$SAKIMORI_BIN" workspace snapshot
       "$SAKIMORI_WORKSPACE_DIR" -o "$SAKIMORI_BASELINE_PATH"
- run: pnpm install --frozen-lockfile
- run: pnpm build
```

The daemon re-snapshots `$SAKIMORI_WORKSPACE_DIR` at post-time, diffs
against the baseline, and surfaces drift in the JSON log + step
summary. Forgetting the snapshot step is non-fatal (the daemon logs a
warning and the drift section is omitted).

### eBPF-supervised test run — one-step form (Linux + Windows)

The simplest form: pass the command you want supervised via the
`run:` input. The action installs sakimori AND wraps the command
with `sakimori run` for you — no separate `sudo -E env "PATH=$PATH"
"$SAKIMORI_BIN" run …` step required.

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest]
runs-on: ${{ matrix.os }}
steps:
  - uses: actions/checkout@v4
  - uses: bokuweb/sakimori@v0
    with:
      policy: .github/sakimori.yml
      mode: audit
      html: sakimori-report.html
      run: |
        corepack enable
        cargo test
        pnpm install --frozen-lockfile
        pnpm test
```

On Linux the script runs under
`sudo -E env "PATH=$PATH" "$SAKIMORI_BIN" run … -- bash -euxo pipefail -c '<run>'`;
on Windows under `& $env:SAKIMORI_BIN … -- pwsh -NoProfile -Command "<run>"`.
`--summary` defaults to `$GITHUB_STEP_SUMMARY` and `--log` defaults
to the `log:` input (`sakimori.log.json`). Add `snapshot-workspace:
<dir>` to also catch on-disk tampering.

### eBPF-supervised test run — explicit form (Linux + Windows)

If you need more control over the wrapper invocation, omit `run:`
and write the `sakimori run` step yourself. The action exports
`$SAKIMORI_BIN`, `$SAKIMORI_POLICY`, `$SAKIMORI_MODE`, and
`$SAKIMORI_LOG` for you.

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest]
runs-on: ${{ matrix.os }}
steps:
  - uses: actions/checkout@v4
  - uses: bokuweb/sakimori@v0
    with:
      policy: .github/sakimori.yml
      mode: audit

  - if: runner.os == 'Linux'
    run: |
      # `sudo -E` preserves env *except* PATH (sudo always replaces
      # it with secure_path). `env "PATH=$PATH"` re-injects the
      # runner user's PATH so the supervised child can find tools
      # installed outside /usr/bin (pnpm, cargo, rustup toolchains).
      sudo -E env "PATH=$PATH" "$SAKIMORI_BIN" run \
        --policy  "$SAKIMORI_POLICY" \
        --mode    "$SAKIMORI_MODE" \
        --log     "$SAKIMORI_LOG" \
        --html    sakimori-report.html \
        --summary "$GITHUB_STEP_SUMMARY" \
        -- cargo test

  - if: runner.os == 'Windows'
    shell: pwsh
    run: |
      & $env:SAKIMORI_BIN `
        --policy $env:SAKIMORI_POLICY `
        --log    sakimori.log.json `
        --html   sakimori-report.html `
        -- cargo test

  - uses: actions/upload-artifact@v4
    if: always()
    with:
      name: sakimori-report-${{ runner.os }}
      path: |
        sakimori-report.html
        sakimori.log.json
```

### PR comment with the HTML report

`bokuweb/sakimori/comment@v0` reads the JSON log and upserts a
single PR comment (keyed by an HTML marker, re-runs edit in place).
Embeds a `gh run download` one-liner to view the full HTML on your
machine.

```yaml
- uses: bokuweb/sakimori/comment@v0
  if: github.event_name == 'pull_request'
  with:
    log: sakimori.log.json
    artifact-name: sakimori-report
    html-filename: sakimori-report.html
    # fail-on-denied: "true"                # optional
```

### Runner support matrix

| runner | proxy | supervised run | notes |
|---|---|---|---|
| `ubuntu-latest`, `ubuntu-22.04`, `ubuntu-24.04` | ✅ | ✅ | canonical Linux target, eBPF + tracepoints |
| `ubuntu-24.04-arm` | ✅ | ✅ | aarch64 binary ships in each release |
| `windows-latest` | ✅ | ✅ | ETW public providers; elevated by default |
| `windows-2022`, `windows-2019` | ✅ | ⚠️ | probably works but not smoke-tested |
| `macos-latest` | ✅ | ❌ | supervised mode is Linux/Windows only |
| container jobs (`container:` on Linux) | ✅ | ⚠️ | needs `--privileged` + host cgroup mount |
| self-hosted Linux | ✅ | ⚠️ | needs passwordless sudo, kernel ≥ 5.13 |
| self-hosted Windows | ✅ | ⚠️ | needs Administrator for ETW |

---

## Docker image

Prebuilt multi-arch image on GHCR:

```bash
docker pull ghcr.io/bokuweb/sakimori-proxy:v0
```

Tags: `v0` (floating), `v0.N`, `v0.N.M`, `latest`. Available archs:
`linux/amd64`, `linux/arm64`.

Run with a named volume so the CA persists across restarts:

```bash
docker run --rm -p 8910:8910 \
    -v sakimori-conf:/etc/sakimori-xdg \
    ghcr.io/bokuweb/sakimori-proxy:v0 \
    --listen 0.0.0.0:8910 --min-age 7d

# One-shot: grab the generated CA so hosts can trust it.
docker run --rm -v sakimori-conf:/etc/sakimori-xdg \
    --entrypoint cat ghcr.io/bokuweb/sakimori-proxy:v0 \
    /etc/sakimori-xdg/sakimori/ca.pem > /tmp/sakimori-ca.pem
```

Then on each host:

```bash
export HTTPS_PROXY=http://<container-host>:8910
export CARGO_HTTP_CAINFO=/tmp/sakimori-ca.pem
# (or install-ca into your OS trust store with the CA you just copied)
```

---

## Configuration reference

### Duration grammar (`--min-age`, policy `age`)

Integer + unit. Bare numbers default to days.

| suffix | unit |
|---|---|
| `d` | days |
| `h` | hours |
| `m` | minutes |
| `s` | seconds |

Examples: `7d`, `72h`, `30m`, `3600s`, `7` (= 7 days).

### File locations

| OS | CA + key | Cache | Daemon unit |
|---|---|---|---|
| macOS | `~/.config/sakimori/ca.{pem,key}` (or `$XDG_CONFIG_HOME`) | `~/Library/Caches/sakimori/deps-cache.json` | `~/Library/LaunchAgents/com.sakimori.proxy.plist` |
| Linux | `$XDG_CONFIG_HOME/sakimori/ca.{pem,key}` | `$XDG_CACHE_HOME/sakimori/deps-cache.json` | `~/.config/systemd/user/sakimori-proxy.service` |
| Windows | `%LOCALAPPDATA%\sakimori\ca.{pem,key}` | `%LOCALAPPDATA%\sakimori\deps-cache.json` | `%LOCALAPPDATA%\sakimori\sakimori-proxy.task.xml` |

### Environment variables read

| var | purpose |
|---|---|
| `SAKIMORI_POLICY` | Default policy file for `run` / `check-policy` |
| `SAKIMORI_MODE` | Override policy `mode` in `run` |
| `SAKIMORI_LOG` | Default log destination in `run` |
| `SAKIMORI_BIN` | Set by the GH Action install step |
| `SAKIMORI_BPF_OBJ` | Path to `sakimori.bpf.o` (Linux only) |
| `GITHUB_STEP_SUMMARY` | Default `--summary` target |
| `XDG_CONFIG_HOME` / `XDG_CACHE_HOME` | Override default config/cache dir |

---

## Troubleshooting

### `sakimori doctor` says the proxy is unreachable

- Check it's actually running: `pgrep -f 'sakimori proxy'`
- On macOS: `launchctl list | grep sakimori`
- On Linux: `systemctl --user status sakimori-proxy`
- On Windows: `schtasks /Query /TN sakimori-proxy`
- Try `sakimori proxy start` in the foreground — see the log.

### TLS errors from cargo / npm / pip

Cargo on Linux uses libcurl which doesn't read the system trust
store — `CARGO_HTTP_CAINFO` must point at the sakimori CA.
Likewise `PIP_CERT` for pip and `NODE_EXTRA_CA_CERTS` for npm.

`install-gate install` sets all of these. If you skipped that,
either install-gate now or set them manually.

### `install-ca` on macOS says "needs privilege"

macOS keychain writes need `sudo`. Re-run with sudo, or copy the
printed `security add-trusted-cert …` line and run it yourself.

### `npm install` still pulls a too-young version

1. Is the proxy running? `sakimori doctor`
2. Is `HTTPS_PROXY` set in **this** shell? (install-gate only
   applies to new shells.) `echo $HTTPS_PROXY`
3. Is the package being downloaded from a host sakimori
   intercepts? Only crates.io, registry.npmjs.org,
   files.pythonhosted.org, pypi.org, api.nuget.org are intercepted.
   Custom registries pass through unchanged.

### Container / remote Docker usage

Run the proxy on a separate host and point client env at it:

```bash
export HTTPS_PROXY=http://proxy.corp.internal:8910
export CARGO_HTTP_CAINFO=/etc/sakimori/ca.pem  # copy from the proxy container
```

---

## Known limitations

Honest assessment. Full details in [CLAUDE.md](CLAUDE.md).

### Proxy

<!-- pypi HTML Simple index (PEP 503) and nuget flat-container are
     now silently filtered via out-of-band JSON-API / registration
     lookups (cached in-proxy for 10 min). No limitation to document
     here anymore. -->
- **Sigstore bundle verification** (not just claim presence) is a
  roadmap item. `--require-provenance` currently checks that the
  `dist.attestations.provenance.predicateType` field is non-empty,
  which is already meaningful (npm refuses to attach it unless
  the publish came from OIDC-authenticated CI) but the bundle
  itself isn't cryptographically verified.
<!-- DNS round-robin drift: addressed by `--dns-refresh-interval <secs>`
     on `sakimori run`. Re-resolves hostname rules on the given
     interval and additively inserts any newly-observed IPs into the
     eBPF maps. Default is 0 (off); set to 60–300 for long-running
     CDN-heavy jobs. Entries are never removed, so increasing the
     rate is safe and won't kill active connections. -->
- **CDN IP rotation across long runs**: handled by
  `sakimori run --dns-refresh-interval <secs>`, which re-resolves
  `network.allow` / `network.deny` hostnames every N seconds and
  additively inserts new IPs. Off by default (0); 60–300 is typical
  for CI jobs that run for hours behind round-robin DNS.

### Linux supervised run

- **Network block works at the kernel** (EPERM from
  cgroup/connect4|6).
- **File block is "tripwire"** — `bpf_send_signal(SIGKILL)` on a
  matching `openat`. The fd may briefly exist; the process dies
  before consuming it. For a truly pre-open block we'd need
  `bpf_override_return`, which is CONFIG_BPF_KPROBE_OVERRIDE
  dependent (roadmap).
- **Exec deny is audit-only** — events get `denied: true` in the
  log and block-mode exits non-zero, but the exec itself happens.
  Same roadmap item as file block.
- **deps watch** is detection, not prevention — FS events fire
  after the package manager has already run `postinstall`.

### Windows supervised run

- `network.default: deny` is **audit-only** — Windows Defender
  Firewall evaluates block over allow, so an allowlist pattern
  would require flipping the system-wide default-outbound to
  Block, which we won't do silently. `network.deny: […]` is
  kernel-enforced.

### macOS

- No supervised run mode. `run` is Linux/Windows only — on macOS
  sakimori is a desktop-level tool (proxy + deps + watch).

---

## Development

```bash
# Full test suite (core + proxy + install-gate + daemon + doctor)
cargo test --workspace

# Lint
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# Build the eBPF object (Linux only, requires nightly + bpf-linker)
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cd crates/sakimori-ebpf
RUSTUP_TOOLCHAIN=nightly cargo build --release \
    --target bpfel-unknown-none -Z build-std=core
```

Crates:

- `sakimori-common` — `no_std` POD types shared with eBPF (ring
  buffer records, map keys)
- `sakimori-core` — platform-neutral: events, policy, matcher,
  stats, HTML report, `deps::*`, watch
- `sakimori-ebpf` — Linux kernel programs (cgroup/connect
  tracepoints). Excluded from the main workspace.
- `sakimori-proxy` — HTTPS MITM proxy (hudsucker + rustls),
  registry parsers, rewriters (crates/npm/pypi/nuget), CA
  management, daemon unit generators
- `sakimori` — userspace CLI and Linux supervisor
- `sakimori-win` — Windows ETW supervisor + Defender Firewall
  integration (separate workspace for dep isolation)

Architecture notes live in [CLAUDE.md](CLAUDE.md).

---

## Commercial support

sakimori is free to use under MIT/Apache-2.0. If your team needs
any of the following, the maintainer offers paid engagements:

- Onboarding help (writing/auditing your `policy.yml`, integrating
  with your CI, tuning per-runner thresholds).
- Priority bug fixes and feature requests.
- Private Slack/Discord channel for questions.
- Custom ecosystem support or proprietary registry adapters.

Contact: **bokuweb12@gmail.com**

For non-commercial appreciation, [GitHub Sponsors](https://github.com/sponsors/bokuweb)
is also welcome.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All commits must be signed off
([DCO](https://developercertificate.org/)) — `git commit -s`.

## License

MIT. See [LICENSE](LICENSE).
