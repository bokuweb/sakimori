#!/usr/bin/env python3
"""
Rewrite `HomebrewFormula/sakimori.rb` to point at a new release
tag. Called from `.github/workflows/homebrew-formula.yml` after a
`v*` release is published; the workflow computes the sha256 of
each platform's tarball and passes them in via flags.

Pure-Python, no external deps — runs on any stock GH runner.

Why not just `sed`? The formula uses `on_arm` / `on_intel` blocks,
so we need *positional* substitution (the N-th `sha256 "..."` line
maps to a specific target triple). A structured rewrite is less
fragile than positional sed regex.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

# Order matches the formula file top-to-bottom: each tuple is
# (target-triple, argparse-attr). Keep in sync with the formula
# AND the workflow step that fetches these.
TARGETS = [
    ("aarch64-apple-darwin", "sha_aarch64_apple_darwin"),
    ("x86_64-apple-darwin", "sha_x86_64_apple_darwin"),
    ("aarch64-unknown-linux-musl", "sha_aarch64_unknown_linux_musl"),
    ("x86_64-unknown-linux-musl", "sha_x86_64_unknown_linux_musl"),
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--file", required=True, type=pathlib.Path)
    p.add_argument("--version", required=True, help='e.g. "0.27.0"')
    p.add_argument("--tag", required=True, help='e.g. "v0.27.0"')
    for t, attr in TARGETS:
        p.add_argument(f"--sha-{t}", dest=attr, required=True)
    return p.parse_args()


def rewrite(text: str, args: argparse.Namespace) -> str:
    # 1. `version "..."` — single line, anywhere in the file.
    text = re.sub(
        r'(^\s*version\s+)"[^"]+"',
        lambda m: f'{m.group(1)}"{args.version}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )

    # 2. URLs — one per target triple, in the order declared in
    #    TARGETS. We replace ALL url lines in place, matched
    #    positionally, so the `on_arm` / `on_intel` blocks each
    #    get their correct tarball.
    urls_iter = iter(
        f'url "https://github.com/bokuweb/sakimori/releases/download/{args.tag}/sakimori-{t}.tar.gz"'
        for t, _ in TARGETS
    )

    def url_sub(_match: re.Match) -> str:
        return next(urls_iter)

    text, url_count = re.subn(
        r'url\s+"[^"]+"',
        url_sub,
        text,
    )
    if url_count != len(TARGETS):
        raise SystemExit(f"expected {len(TARGETS)} url lines, rewrote {url_count}")

    # 3. sha256 — same positional story.
    shas_iter = iter(
        f'sha256 "{getattr(args, attr)}"' for _, attr in TARGETS
    )

    def sha_sub(_match: re.Match) -> str:
        return next(shas_iter)

    text, sha_count = re.subn(
        r'sha256\s+"[^"]+"',
        sha_sub,
        text,
    )
    if sha_count != len(TARGETS):
        raise SystemExit(f"expected {len(TARGETS)} sha256 lines, rewrote {sha_count}")

    return text


def main() -> int:
    args = parse_args()
    text = args.file.read_text(encoding="utf-8")
    out = rewrite(text, args)
    args.file.write_text(out, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
