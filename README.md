# coronarium

**Cross-platform supply-chain guard for every package manager on your
machine.** Silently blocks too-young versions, known-malicious packages
and unsigned publishes — across **npm, cargo, pypi, nuget** — without
touching your build tools.

```bash
# Three commands, once.
$ coronarium proxy install-ca       # trust the proxy's root CA
$ coronarium proxy install-daemon   # auto-run in the background
$ coronarium install-gate install   # route your shell through it

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

**coronarium brings the same behaviour to all four major ecosystems**
(crates.io, npm, pypi, nuget) and any package manager that talks to
them, by sitting as an HTTPS proxy and rewriting the registry's
metadata responses in-flight. No resolver integration. No config in
your package manifests.

## How it works

```
            ┌───────────────────┐       ┌────────────────────┐
            │  npm / cargo /    │       │                    │
  user ───► │  pip / uv /       │ ─────►│  coronarium proxy  │ ──► real registry
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
brew install bokuweb/coronarium/coronarium
# ↑ the repo-is-its-own-tap convention; no separate `brew tap` needed.
```

Auto-updated on every release via the `homebrew-formula.yml`
workflow — the formula lives at
[`HomebrewFormula/coronarium.rb`](HomebrewFormula/coronarium.rb)
in this repo.

### Pre-built binary (macOS / Linux / Windows)

```bash
# macOS (Apple Silicon)
curl -fsSL https://github.com/bokuweb/coronarium/releases/latest/download/coronarium-aarch64-apple-darwin.tar.gz \
  | sudo tar -xz -C /usr/local/bin

# macOS (Intel)
curl -fsSL https://github.com/bokuweb/coronarium/releases/latest/download/coronarium-x86_64-apple-darwin.tar.gz \
  | sudo tar -xz -C /usr/local/bin

# Linux (x86_64 musl static)
curl -fsSL https://github.com/bokuweb/coronarium/releases/latest/download/coronarium-x86_64-unknown-linux-musl.tar.gz \
  | sudo tar -xz -C /usr/local/bin

# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/bokuweb/coronarium/releases/latest/download/coronarium-x86_64-pc-windows-msvc.tar.gz -OutFile c.tgz
tar -xzf c.tgz -C "$env:USERPROFILE\.local\bin"
```

Every release also ships a `.sha256` sidecar. The archive contains
the `coronarium` binary (Linux also ships `coronarium.bpf.o` for the
supervised-run mode).

### Docker / OCI

```bash
docker run --rm -p 8910:8910 \
    -v coronarium-conf:/etc/coronarium-xdg \
    ghcr.io/bokuweb/coronarium-proxy:v0 \
    --listen 0.0.0.0:8910 --min-age 7d
```

Mount `/etc/coronarium-xdg` as a volume to persist the generated
root CA across container restarts. See [Docker image](#docker-image).

### From source

```bash
cargo install --git https://github.com/bokuweb/coronarium coronarium
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
coronarium proxy install-ca

# 2. Register the proxy as a background service so it's always up.
#    macOS: ~/Library/LaunchAgents/com.coronarium.proxy.plist
#    Linux: ~/.config/systemd/user/coronarium-proxy.service
#    Windows: Task Scheduler /coronarium-proxy
coronarium proxy install-daemon
# Follow the printed `launchctl bootstrap …` / `systemctl --user enable --now`
# / `schtasks.exe /Create …` line.

# 3. Append HTTPS_PROXY + CA bundle env vars to your shell rc.
#    Detects zsh / bash / fish / PowerShell from $SHELL (or your OS).
coronarium install-gate install
```

Open a new shell — everything's wired:

```
$ env | grep -E 'HTTPS_PROXY|CARGO_HTTP_CAINFO'
HTTPS_PROXY=http://127.0.0.1:8910
CARGO_HTTP_CAINFO=/Users/you/.config/coronarium/ca.pem

$ coronarium doctor
coronarium doctor
────────────────────────────────────────────────────────────
✓ CA certificate               /Users/you/.config/coronarium/ca.pem (644 bytes)
✓ CA private key               /Users/you/.config/coronarium/ca.key
✓ Proxy reachable              accepted TCP on 127.0.0.1:8910
✓ $HTTPS_PROXY                 http://127.0.0.1:8910
✓ install-gate rc              /Users/you/.zshrc
✓ Daemon unit                  /Users/you/Library/LaunchAgents/com.coronarium.proxy.plist
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
coronarium install-gate uninstall    # strip block from shell rc
coronarium proxy uninstall-daemon    # remove launchd / systemd / Task Scheduler unit
coronarium proxy uninstall-ca        # remove CA from system trust store
rm -rf ~/.config/coronarium          # delete CA + key (optional)
```

---

## Feature reference

### `proxy start`

Start the MITM HTTPS proxy in the foreground. `install-daemon`
wraps this for background use; run it directly when you want logs
on stdout or you're running the proxy yourself in Docker.

```
coronarium proxy start [OPTIONS]

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
                               consumed from the coronarium-hosted
                               pre-filtered snapshot. O(1) in-memory
                               lookup after a single ~10-minute
                               background refresh. ~10 min behind
                               OSV publish time in exchange for
                               not hitting api.osv.dev per request.
                               Combine with --osv to additionally
                               fall back to the live API for
                               entries the mirror hasn't indexed.
  --osv-mirror-url <URL>       Override mirror URL (e.g. self-hosted).
  --config-dir <PATH>          Override CA / config directory.
                               Defaults to $XDG_CONFIG_HOME/coronarium
                               on Unix, %LOCALAPPDATA%\coronarium on
                               Windows.
```

**First-run side effect**: generates a self-signed root CA at the
config dir and prints the OS-specific trust command. Subsequent runs
reuse the existing CA.

### `proxy install-ca` / `uninstall-ca`

Add / remove the root CA from the OS trust store. Cross-platform:

| OS | Mechanism | Privilege prompt |
|---|---|---|
| macOS | `security add-trusted-cert -k /Library/Keychains/System.keychain` | `sudo` |
| Linux | copy to `/usr/local/share/ca-certificates/` + `update-ca-certificates` | `sudo` |
| Windows | `Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root` | UAC via `Start-Process -Verb RunAs` |

If you're not elevated, coronarium prints the exact shell command
and exits — no silent reruns with privileges.

```
coronarium proxy install-ca [--config-dir <PATH>]
coronarium proxy uninstall-ca [--config-dir <PATH>]
```

### `proxy install-daemon` / `uninstall-daemon`

Write a user-level service unit so the proxy runs in the
background at login and restarts on failure.

| OS | Unit | Location |
|---|---|---|
| macOS | launchd plist (`KeepAlive`, `RunAtLoad`, `Background` ProcessType) | `~/Library/LaunchAgents/com.coronarium.proxy.plist` |
| Linux | systemd `--user` unit (`Restart=on-failure`, `WantedBy=default.target`) | `~/.config/systemd/user/coronarium-proxy.service` |
| Windows | Task Scheduler v1.4 XML (`LogonTrigger`, `RestartOnFailure 99×1m`, `Hidden`) | `%LOCALAPPDATA%\coronarium\coronarium-proxy.task.xml` |

```
coronarium proxy install-daemon [OPTIONS]

Options:
  --listen <ADDR>         [default: 127.0.0.1:8910]
  --min-age <DURATION>    [default: 7d]
  --binary <PATH>         Override the coronarium binary path baked
                          into the unit. Defaults to the canonical
                          path of the currently-running executable.
```

The command prints the exact activation line (`launchctl bootstrap`
/ `systemctl --user enable --now` / `schtasks.exe /Create`) — run
that to start the service.

### `install-gate`

Edit the user's shell rc file so every new shell exports
`HTTPS_PROXY` + CA-bundle env vars pointing at the proxy. Idempotent
via `# >>> coronarium install-gate >>>` sentinels.

```
coronarium install-gate shellenv [--listen <ADDR>] [--shell {bash,zsh,fish,powershell}]
coronarium install-gate install  [--rc <PATH>]     [--shell ...]
coronarium install-gate uninstall [--rc <PATH>]    [--shell ...]
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
coronarium doctor [--listen <ADDR>] [--config-dir <PATH>] [--rc <PATH>]
```

Sample output when the proxy is down:

```
✓ CA certificate               /Users/you/.config/coronarium/ca.pem (644 bytes)
✓ CA private key               /Users/you/.config/coronarium/ca.key
✗ Proxy reachable              no listener on 127.0.0.1:8910: Connection refused
  ↳ start it: `coronarium proxy start` (or, for background: `coronarium proxy install-daemon`)
! $HTTPS_PROXY                 unset in this shell
  ↳ run `coronarium install-gate install` and open a new shell
```

### `deps check`

Lockfile-level age gate, usable standalone (no proxy required). Good
for a **pre-install CI step** that fails the build before the
malicious package is even fetched.

```bash
coronarium deps check --min-age 7d Cargo.lock package-lock.json

# Different thresholds per ecosystem? Run twice.
coronarium deps check --min-age 14d Cargo.lock
coronarium deps check --min-age  3d package-lock.json

# Ignore first-party packages.
coronarium deps check --min-age 7d --ignore '@my-org/*' package-lock.json

# Machine-readable output for CI gating.
coronarium deps check --min-age 7d --format json Cargo.lock
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

Cache location: `$XDG_CACHE_HOME/coronarium/deps-cache.json`
(`%LOCALAPPDATA%\coronarium\…` on Windows). Publish dates are
immutable, so there's no TTL.

### `deps watch`

Long-running FS-event watcher for lockfile changes. Designed for
launchd at login.

```bash
# One-off (Ctrl-C to quit)
coronarium deps watch ~/code --min-age 7d

# With modal prompts (Keep / Revert via osascript)
coronarium deps watch ~/code --min-age 7d --action prompt

# Stdout logging, e.g. for tmux / screen
coronarium deps watch ~/code --min-age 7d --notifier stdout
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

### `run`

Wraps a command under eBPF (Linux) / ETW (Windows) supervision and
observes — optionally denies — its syscalls:

- `connect(2)` on IPv4 / IPv6
- `openat(2)`
- `execve(2)`

```bash
coronarium run \
  --policy .github/coronarium.yml \
  --mode audit \
  --log coronarium.log.json \
  --html coronarium-report.html \
  -- cargo test
```

Flags:

| flag | env | default | description |
|---|---|---|---|
| `--policy` / `-p` | `CORONARIUM_POLICY` | — | policy file (YAML or JSON) |
| `--mode` | — | from policy | `audit` or `block` — overrides the policy's `mode:` |
| `--log` | — | `-` (stdout) | JSON audit log destination |
| `--summary` | `GITHUB_STEP_SUMMARY` | — | markdown summary |
| `--html` | — | — | self-contained HTML report (dark-mode aware, filterable) |

Exit code: child's exit code, unless `mode=block` and at least one
event was denied → exits `1`.

Policy format:

```yaml
# .github/coronarium.yml
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

**First-time setup pattern** — run in `mode: audit` once, inspect
the JSON log, add actually-needed entries to `allow:`, flip to
`mode: block` when the log is clean.

The HTML report includes:
- verdict (ALLOW / DENY), kind, pid, comm
- **host column** (PTR-resolved reverse DNS for connect events)
- detail (IP:port / filename / exec argv)
- filter box matching across all fields
- dark-mode aware, self-contained (no external CSS/JS)

---

## CI usage (GitHub Actions)

### Minimal: run every install through the proxy

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Starts coronarium proxy in the background and appends
      # HTTPS_PROXY + CA-bundle env vars to $GITHUB_ENV for later steps.
      - uses: bokuweb/coronarium/proxy@v0
        with:
          min-age: 7d

      - run: npm ci          # flows through the proxy
      - run: cargo test      # flows through the proxy
```

Inputs:

| input | default | description |
|---|---|---|
| `min-age` | `7d` | Minimum package age. Same grammar as `--min-age`. |
| `listen` | `127.0.0.1:8910` | Proxy listen address. |
| `fail-on-missing` | `false` | Treat unknown publish dates as deny. |
| `version` | `v0` | coronarium release tag to download. |

### Alternative: lockfile-only pre-flight check

Cheaper (no proxy), but fails loudly on any too-young dep instead
of silently falling back.

```yaml
- uses: bokuweb/coronarium@v0
- run: $CORONARIUM_BIN deps check --min-age 7d Cargo.lock package-lock.json
- run: cargo test   # only reached if the check passed
```

### eBPF-supervised test run (Linux + Windows)

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest]
runs-on: ${{ matrix.os }}
steps:
  - uses: actions/checkout@v4
  - uses: bokuweb/coronarium@v0
    with:
      policy: .github/coronarium.yml
      mode: audit

  - if: runner.os == 'Linux'
    run: |
      # `sudo -E` preserves env *except* PATH (sudo always replaces
      # it with secure_path). `env "PATH=$PATH"` re-injects the
      # runner user's PATH so the supervised child can find tools
      # installed outside /usr/bin (pnpm, cargo, rustup toolchains).
      sudo -E env "PATH=$PATH" "$CORONARIUM_BIN" run \
        --policy  "$CORONARIUM_POLICY" \
        --mode    "$CORONARIUM_MODE" \
        --log     "$CORONARIUM_LOG" \
        --html    coronarium-report.html \
        --summary "$GITHUB_STEP_SUMMARY" \
        -- cargo test

  - if: runner.os == 'Windows'
    shell: pwsh
    run: |
      & $env:CORONARIUM_BIN `
        --policy $env:CORONARIUM_POLICY `
        --log    coronarium.log.json `
        --html   coronarium-report.html `
        -- cargo test

  - uses: actions/upload-artifact@v4
    if: always()
    with:
      name: coronarium-report-${{ runner.os }}
      path: |
        coronarium-report.html
        coronarium.log.json
```

### PR comment with the HTML report

`bokuweb/coronarium/comment@v0` reads the JSON log and upserts a
single PR comment (keyed by an HTML marker, re-runs edit in place).
Embeds a `gh run download` one-liner to view the full HTML on your
machine.

```yaml
- uses: bokuweb/coronarium/comment@v0
  if: github.event_name == 'pull_request'
  with:
    log: coronarium.log.json
    artifact-name: coronarium-report
    html-filename: coronarium-report.html
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
docker pull ghcr.io/bokuweb/coronarium-proxy:v0
```

Tags: `v0` (floating), `v0.N`, `v0.N.M`, `latest`. Available archs:
`linux/amd64`, `linux/arm64`.

Run with a named volume so the CA persists across restarts:

```bash
docker run --rm -p 8910:8910 \
    -v coronarium-conf:/etc/coronarium-xdg \
    ghcr.io/bokuweb/coronarium-proxy:v0 \
    --listen 0.0.0.0:8910 --min-age 7d

# One-shot: grab the generated CA so hosts can trust it.
docker run --rm -v coronarium-conf:/etc/coronarium-xdg \
    --entrypoint cat ghcr.io/bokuweb/coronarium-proxy:v0 \
    /etc/coronarium-xdg/coronarium/ca.pem > /tmp/coronarium-ca.pem
```

Then on each host:

```bash
export HTTPS_PROXY=http://<container-host>:8910
export CARGO_HTTP_CAINFO=/tmp/coronarium-ca.pem
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
| macOS | `~/.config/coronarium/ca.{pem,key}` (or `$XDG_CONFIG_HOME`) | `~/Library/Caches/coronarium/deps-cache.json` | `~/Library/LaunchAgents/com.coronarium.proxy.plist` |
| Linux | `$XDG_CONFIG_HOME/coronarium/ca.{pem,key}` | `$XDG_CACHE_HOME/coronarium/deps-cache.json` | `~/.config/systemd/user/coronarium-proxy.service` |
| Windows | `%LOCALAPPDATA%\coronarium\ca.{pem,key}` | `%LOCALAPPDATA%\coronarium\deps-cache.json` | `%LOCALAPPDATA%\coronarium\coronarium-proxy.task.xml` |

### Environment variables read

| var | purpose |
|---|---|
| `CORONARIUM_POLICY` | Default policy file for `run` / `check-policy` |
| `CORONARIUM_MODE` | Override policy `mode` in `run` |
| `CORONARIUM_LOG` | Default log destination in `run` |
| `CORONARIUM_BIN` | Set by the GH Action install step |
| `CORONARIUM_BPF_OBJ` | Path to `coronarium.bpf.o` (Linux only) |
| `GITHUB_STEP_SUMMARY` | Default `--summary` target |
| `XDG_CONFIG_HOME` / `XDG_CACHE_HOME` | Override default config/cache dir |

---

## Troubleshooting

### `coronarium doctor` says the proxy is unreachable

- Check it's actually running: `pgrep -f 'coronarium proxy'`
- On macOS: `launchctl list | grep coronarium`
- On Linux: `systemctl --user status coronarium-proxy`
- On Windows: `schtasks /Query /TN coronarium-proxy`
- Try `coronarium proxy start` in the foreground — see the log.

### TLS errors from cargo / npm / pip

Cargo on Linux uses libcurl which doesn't read the system trust
store — `CARGO_HTTP_CAINFO` must point at the coronarium CA.
Likewise `PIP_CERT` for pip and `NODE_EXTRA_CA_CERTS` for npm.

`install-gate install` sets all of these. If you skipped that,
either install-gate now or set them manually.

### `install-ca` on macOS says "needs privilege"

macOS keychain writes need `sudo`. Re-run with sudo, or copy the
printed `security add-trusted-cert …` line and run it yourself.

### `npm install` still pulls a too-young version

1. Is the proxy running? `coronarium doctor`
2. Is `HTTPS_PROXY` set in **this** shell? (install-gate only
   applies to new shells.) `echo $HTTPS_PROXY`
3. Is the package being downloaded from a host coronarium
   intercepts? Only crates.io, registry.npmjs.org,
   files.pythonhosted.org, pypi.org, api.nuget.org are intercepted.
   Custom registries pass through unchanged.

### Container / remote Docker usage

Run the proxy on a separate host and point client env at it:

```bash
export HTTPS_PROXY=http://proxy.corp.internal:8910
export CARGO_HTTP_CAINFO=/etc/coronarium/ca.pem  # copy from the proxy container
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
     on `coronarium run`. Re-resolves hostname rules on the given
     interval and additively inserts any newly-observed IPs into the
     eBPF maps. Default is 0 (off); set to 60–300 for long-running
     CDN-heavy jobs. Entries are never removed, so increasing the
     rate is safe and won't kill active connections. -->
- **CDN IP rotation across long runs**: handled by
  `coronarium run --dns-refresh-interval <secs>`, which re-resolves
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
  coronarium is a desktop-level tool (proxy + deps + watch).

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
cd crates/coronarium-ebpf
RUSTUP_TOOLCHAIN=nightly cargo build --release \
    --target bpfel-unknown-none -Z build-std=core
```

Crates:

- `coronarium-common` — `no_std` POD types shared with eBPF (ring
  buffer records, map keys)
- `coronarium-core` — platform-neutral: events, policy, matcher,
  stats, HTML report, `deps::*`, watch
- `coronarium-ebpf` — Linux kernel programs (cgroup/connect
  tracepoints). Excluded from the main workspace.
- `coronarium-proxy` — HTTPS MITM proxy (hudsucker + rustls),
  registry parsers, rewriters (crates/npm/pypi/nuget), CA
  management, daemon unit generators
- `coronarium` — userspace CLI and Linux supervisor
- `coronarium-win` — Windows ETW supervisor + Defender Firewall
  integration (separate workspace for dep isolation)

Architecture notes live in [CLAUDE.md](CLAUDE.md).

---

## Commercial support

coronarium is free to use under MIT/Apache-2.0. If your team needs
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
