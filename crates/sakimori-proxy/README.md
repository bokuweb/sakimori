# sakimori-proxy

Transparent HTTPS MITM proxy that enforces `minimumReleaseAge` at the
**registry fetch layer**, before any package manager runs install
scripts.

## Why this exists

`sakimori deps watch` is detection-only — by the time fsevents
delivers, preinstall/postinstall scripts have already run (see
`CLAUDE.md` § "Known limitations"). A git pre-commit hook only fires
at commit time. The only layer that can *actually* prevent a malicious
install is the HTTP round-trip to the registry.

This proxy sits in front of `registry.npmjs.org`, `crates.io`,
`pypi.org`, `api.nuget.org` and friends. For each package fetch it
derives `(name, version)`, asks sakimori's existing
`deps::registry` module for the publish date, and returns `403
Forbidden` when the version is younger than `--min-age`. Package
managers see a normal registry error, fall back to an older in-range
version, or fail fast — but no tarball is ever downloaded.

## Architecture

```
         ┌──────────────┐      set HTTPS_PROXY=http://127.0.0.1:xxxx
         │ npm/cargo/pip│ ────────────────────────────┐
         └──────┬───────┘                             ▼
                │                     ┌──────────────────────────┐
                │     TLS MITM        │ sakimori-proxy         │
                ├─────────────────────┤ - rcgen root CA          │
                │                     │ - per-host leaf cert     │
                │                     │ - URL parser per registry│
                │                     │ - age decision           │
                └─────────────────────┤ - plain pipe on allow    │
                                      │ - 403 on deny            │
                                      └──────────┬───────────────┘
                                                 │ upstream
                                                 ▼
                                         ┌──────────────────┐
                                         │  registry.*.org  │
                                         └──────────────────┘
```

## Status

Early. This session ships:

- crates.io URL parser (`GET /api/v1/crates/<name>/<version>/download`,
  sparse index `/<N>/<shard>/<name>`)
- `rcgen`-based root CA auto-generated on first run, persisted at
  `~/.config/sakimori/ca.{pem,key}`
- `hudsucker`-based MITM loop
- `sakimori proxy start` subcommand

Next session: npm / pypi / nuget URL parsers + installer UX for
trusting the CA + tests using mock registries.

## Trust prompt

The proxy asks the user to add its root CA to the system trust store
on first run:

```
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \
    ~/.config/sakimori/ca.pem

# Linux
sudo cp ~/.config/sakimori/ca.pem /usr/local/share/ca-certificates/sakimori-ca.crt
sudo update-ca-certificates

# Windows (admin PowerShell)
Import-Certificate -FilePath "$env:USERPROFILE\.config\sakimori\ca.pem" `
    -CertStoreLocation Cert:\LocalMachine\Root
```

The CA is **scoped to your user's sakimori install** — it's not a
publicly-trusted cert and can't be used by anyone else. Remove it any
time by running `sakimori proxy uninstall-ca` (also todo).

## Non-goals

- We do NOT intercept general HTTPS traffic — only traffic to the
  registries we know about. Everything else passes through un-MITM'd
  (CONNECT tunnelled).
- We do NOT attempt pnpm-style resolver rewrites (the proxy says
  "403 for this version", the package manager's solver picks
  something else). See CLAUDE.md roadmap.
