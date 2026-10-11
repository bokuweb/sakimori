#!/usr/bin/env python3
"""Exercise Cargo's real static download, including a warm-index deny.

Usage: python3 scripts/smoke-cargo-download.py /path/to/sakimori
Uses an isolated CA, Cargo home and install log. Does not change trust stores.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

binary = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix="sakimori-cargo-smoke-") as directory:
    work = Path(directory)
    (work / "src").mkdir()
    (work / "src/lib.rs").write_text("pub fn fixture() {}\n")
    (work / "Cargo.toml").write_text(
        '[package]\nname="cargo-download-smoke"\nversion="0.1.0"\n'
        'edition="2021"\n[dependencies]\nitoa="=1.0.15"\n'
    )
    for mode, age in [("allow", "0s"), ("deny", "36500d")]:
        cargo_home = work / ("cargo-" + mode)
        cargo_home.mkdir()
        if mode == "deny":
            # Keep the lockfile and sparse index, but no cached artifacts.
            shutil.copytree(work / "cargo-allow/registry/index", cargo_home / "registry/index")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        env = {k: v for k, v in os.environ.items() if k not in {
            "SAKIMORI_INGEST_URL", "SAKIMORI_TOKEN", "SAKIMORI_CF_ACCESS_CLIENT_ID",
            "SAKIMORI_CF_ACCESS_CLIENT_SECRET", "ALL_PROXY", "all_proxy",
            "NO_PROXY", "no_proxy", "https_proxy", "http_proxy",
        }}
        env.update(CARGO_HOME=str(cargo_home), CARGO_HTTP_MULTIPLEXING="false",
                   CARGO_HTTP_CAINFO=str(work / "ca/sakimori/ca.pem"),
                   HTTPS_PROXY=f"http://127.0.0.1:{port}", HTTP_PROXY=f"http://127.0.0.1:{port}",
                   SAKIMORI_CONFIG_DIR=str(work / "credentials"))
        install_log = work / (mode + ".jsonl")
        with (work / (mode + "-proxy.log")).open("w") as log:
            proxy = subprocess.Popen([
                binary, "proxy", "start", "--listen", f"127.0.0.1:{port}",
                "--config-dir", str(work / "ca"), "--install-log", str(install_log),
                "--min-age", age,
            ], env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    if proxy.poll() is not None:
                        raise AssertionError("proxy exited before opening the listener")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise AssertionError("proxy did not open the listener")
                result = subprocess.run(
                    ["cargo", "fetch"] + (["--locked"] if mode == "deny" else []),
                    cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=120, text=True,
                )
            finally:
                proxy.terminate()
                proxy.wait(timeout=10)
        rows = [json.loads(line) for line in install_log.read_text().splitlines()] if install_log.exists() else []
        if mode == "allow":
            assert result.returncode == 0, result.stdout
            assert any(r["name"] == "itoa" and r["version"] == "1.0.15" for r in rows), rows
        else:
            assert result.returncode != 0 and "403" in result.stdout, result.stdout
            assert not rows, rows
        print(f"Cargo {mode}: passed (exit={result.returncode}, observations={len(rows)})")
