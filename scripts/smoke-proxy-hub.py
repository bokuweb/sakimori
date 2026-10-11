#!/usr/bin/env python3
"""Exercise the Action with an extracted release archive and a local Hub receiver.

Downloads a harmless npm archive without executing it. No Hub or Access secret
is required. This tests delivery/diagnostics, not Cloudflare persistence.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request


def candidate(archive, directory):
    archive = Path(archive).resolve()
    fields = Path(str(archive) + ".sha256").read_text().strip().split()
    assert len(fields) == 2 and fields[1].lstrip("*") == archive.name, "invalid checksum sidecar"
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == fields[0].lower(), "archive checksum mismatch"
    filename = "sakimori.exe" if os.name == "nt" else "sakimori"
    # Extract only the ordinary binary file; never follow archive symlinks.
    with tarfile.open(archive) as package:
        member = package.getmember(archive.name.removesuffix(".tar.gz") + "/" + filename)
        assert member.isfile(), "candidate binary is not a regular file"
        assert member.size < 300_000_000, "candidate binary exceeds size limit"
        with package.extractfile(member) as source:
            binary = directory / filename
            binary.write_bytes(source.read())
    binary.chmod(0o700)
    return str(binary)


def exercise(binary, version, mode, root, action):
    received = []
    login_requests = []

    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            pass

        def do_GET(self):
            login_requests.append(self.path)
            self.send_response(200)
            self.end_headers()

        def do_POST(self):
            assert self.path == "/v1/smoke/_team/events", "incorrect ingest route"
            assert self.headers.get("Authorization") == "Bearer smoke-hub-secret", "missing Hub bearer"
            assert self.headers.get("CF-Access-Client-Id") == "smoke-access-id", "missing Access ID"
            assert self.headers.get("CF-Access-Client-Secret") == "smoke-access-secret", "missing Access secret"
            batch = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if mode == "redirect":
                self.send_response(302)
                self.send_header("Location", "/login")
                body = b""
            elif mode == "html":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                body = b"<html>login</html>"
            else:
                self.send_response(202)
                self.send_header("Content-Type", "application/json")
                body = json.dumps({"accepted": len(batch), "rejected": []}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            received.extend(batch)

    receiver = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=receiver.serve_forever, daemon=True)
    thread.start()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        proxy_port = listener.getsockname()[1]
    work = root / mode
    work.mkdir()
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("SAKIMORI_", "INPUT_")) and not key.lower().endswith("_proxy")}
    env.update({
        "INPUT_MIN-AGE": "0s", "INPUT_LISTEN": f"127.0.0.1:{proxy_port}",
        "INPUT_INGEST-URL": f"http://127.0.0.1:{receiver.server_port}/v1/smoke/_team/events",
        "INPUT_INGEST-TOKEN": "smoke-hub-secret", "INPUT_CF-ACCESS-CLIENT-ID": "smoke-access-id",
        "INPUT_CF-ACCESS-CLIENT-SECRET": "smoke-access-secret", "INPUT_VERSION": version or "v0",
        "GITHUB_ENV": str(work / "github-env"), "GITHUB_OUTPUT": str(work / "github-output"),
        "GITHUB_ACTIONS": "true", "RUNNER_TEMP": str(work), "GITHUB_WORKSPACE": str(work),
        "SAKIMORI_CONFIG_DIR": str(work / "credentials"),
    })
    if binary:
        env["SAKIMORI_BIN"] = binary
    exports = {}
    try:
        with (work / "action.log").open("w") as log:
            started = subprocess.run(["node", str(action / "main.js")], env=env, stdout=log,
                                     stderr=subprocess.STDOUT, timeout=45)
        assert started.returncode == 0, "Action startup failed; inspect selected binary support"
        exports = dict(line.split("=", 1) for line in (work / "github-env").read_text().splitlines())
        for secret in ("smoke-hub-secret", "smoke-access-id", "smoke-access-secret"):
            assert secret not in (work / "github-env").read_text(), "credential exported to later steps"
        ca = ssl.create_default_context(cafile=exports["NODE_EXTRA_CA_CERTS"])
        client = urllib.request.build_opener(urllib.request.ProxyHandler({"https": exports["HTTPS_PROXY"]}),
                                             urllib.request.HTTPSHandler(context=ca))
        request = urllib.request.Request("https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz",
                                         headers={"User-Agent": "npm/10.0.0 smoke-fixture"})
        with client.open(request, timeout=30) as response:
            assert response.status == 200 and len(response.read()) > 100, "npm acquisition failed"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            proxy_logs = list(work.glob("sakimori-proxy-action-*/proxy.stderr.log"))
            output = "\n".join(log.read_text(errors="replace") for log in proxy_logs)
            if received and (mode == "accepted" or "hub ingest POST" in output):
                break
            time.sleep(0.1)
        assert received, "no Hub acquisition delivered by the release candidate"
        event = next(row for row in received if row["name"] == "is-odd")
        assert event["ecosystem"] == "npm" and event["version"] == "3.0.1", "incorrect coordinates"
        assert "ci=github-actions" in event["user_agent"], "CI marker lost to package-manager UA"
        assert not login_requests, "credentials were forwarded to an authentication redirect"
        if mode != "accepted":
            assert "hub ingest POST" in output and "failed" in output, "false-success receipt lacked warning"
        else:
            assert "hub ingest POST" not in output, "accepted receipt was reported as failure"
        print(json.dumps({"case": mode, "acquisitions": len(received), "ci_marker": True,
                          "access_headers": True, "login_redirect_followed": False}))
    finally:
        env.update(exports)
        # Also clean up a proxy that started but failed before env export.
        for pidfile in work.glob("sakimori-proxy-action-*/proxy.pid"):
            env["SAKIMORI_PROXY_PIDFILE"] = str(pidfile)
            env["SAKIMORI_PROXY_TMP"] = str(pidfile.parent)
            subprocess.run(["node", str(action / "post.js")], env=env,
                           stdout=subprocess.DEVNULL, timeout=15, check=True)
        receiver.shutdown()
        receiver.server_close()
        thread.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive", help="release candidate archive with its .sha256 sidecar")
    source.add_argument("--version", help="download this published release through the Action")
    args = parser.parse_args()
    action = Path(__file__).resolve().parents[1] / "proxy"
    with tempfile.TemporaryDirectory(prefix="sakimori-hub-consumer-") as directory:
        root = Path(directory)
        binary = candidate(args.archive, root) if args.archive else None
        for mode in ("accepted", "redirect", "html"):
            exercise(binary, args.version, mode, root, action)


if __name__ == "__main__":
    main()
