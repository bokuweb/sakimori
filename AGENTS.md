# AGENTS.md — guide for automated agents

Companion to [CLAUDE.md](CLAUDE.md). That file is long-form context
and rationale; this one is the short checklist an agent follows
when acting on the repo.

## Before touching anything

1. Read `CLAUDE.md` §"Known limitations". Changing those requires
   a design discussion with the human, not a drive-by patch.
2. Skim `.github/workflows/ci.yml` to see what the smoke job
   asserts — if your change risks one of those assertions, flag it
   in the PR description.
3. **Are you about to add `sakimori-hub` code here?** Stop.
   `sakimori-hub` lives in the sibling repo
   [`bokuweb/sakimori-hub`](https://github.com/bokuweb/sakimori-hub)
   (local checkout: `../sakimori-hub`). It has its own deploy
   target (Cloudflare Workers + D1 + R2 + Queues via Alchemy v2),
   its own WASM-compatible deps, its own Cargo workspace. This repo only owns the `InstallEvent` wire shape
   and the `bokuweb/sakimori@v0` action that emits it.
   A previous PR (#76) added `crates/sakimori-hub` here by
   mistake and was reverted — if a future change tempts you to
   re-add it, open it in the hub repo instead.

## Preferred workflow

1. `git checkout -b <kind>/<short-desc>` — e.g. `feat/install-gate`,
   `fix/watch-debounce`, `chore/deps`.
2. **Write tests first.** The codebase intentionally designs IO
   behind traits (Prompter, Notifier, EventSource, ViolationHandler)
   so unit tests can pin behaviour without spawning real processes.
3. **Mandatory before every commit / PR push.** All three must
   pass cleanly — no warnings, no skipped tests, no "I'll fix it
   in a follow-up". If any of them fail, fix the cause before
   committing; do not push red.
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
   Tip: run `cargo fmt --all` (without `--check`) first to apply
   the formatter, then re-run with `--check` to confirm. Clippy is
   gated with `-D warnings` so a new lint blocks merge — don't
   silence with `#[allow(...)]` unless the lint is genuinely wrong
   for the code in question, and explain why in a comment.
4. Open a PR, let CI cover the Linux+Windows+consumer-smoke runs.
5. Tag `v0.X.Y` on main to release; `release.yml` owns the rest.

## Conventions

- **Commits**: conventional-ish (`feat:`, `fix:`, `chore:`, `test:`,
  `docs:`, `refactor:`). Body in the imperative mood. Include a
  `Co-Authored-By: Claude …` trailer when an LLM authored most of it.
- **No cowboy destructive defaults.** Anything that mutates user
  files (like `GitRevert`) ships behind an opt-in flag and posts a
  notification explaining what happened.
- **Honest docs > aspirational docs.** README/CLAUDE.md call out
  known gaps (`deps watch` timing, pnpm auto-fallback, etc.). When
  you change behaviour, update the matching limitation text.
- **Error strings**: prefer actionable ("pass `--fail-on-missing`…")
  over pretty.

## What NOT to do autonomously

- Don't delete branches that aren't yours (`git push --delete`).
- Don't edit the `v0` floating tag. Let `release.yml` own it.
- Don't upgrade `aya` / `aya-ebpf` without a paired bump in
  `sakimori-ebpf/Cargo.toml` and a full Linux smoke run.
- Don't add a new registry integration without a fixture and a
  per-ecosystem CI assertion.

## Quick ecosystem-add checklist

If adding a new package ecosystem to `deps check`:

- [ ] Parser under `crates/sakimori-core/src/deps/lockfile/<name>.rs`
- [ ] Registry client under `.../registry/<name>.rs`
- [ ] Wire both into `deps::lockfile::detect` and `deps::check`
- [ ] Fixture at `tests/fixtures/` (a small, real, stable lockfile)
- [ ] Per-ecosystem json-shape assertion in `.github/workflows/ci.yml`
- [ ] Update the "supported ecosystems" table in README
- [ ] Add a row to CLAUDE.md's "Known limitations" if the
      ecosystem has install-time script execution (pretty much
      everything except cargo/nuget).
