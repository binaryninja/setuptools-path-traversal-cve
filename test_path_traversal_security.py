#!/usr/bin/env python
"""
Standalone security tests for path traversal vulnerability in package_index.py

Run with: python -m pytest test_path_traversal_security.py -v

These tests verify the behavior of filename sanitization in _download_url()
and egg_info_for_url() to detect path traversal vulnerabilities.

Vulnerability: setuptools/package_index.py:810-823
The _download_url() function sanitizes ".." sequences but does NOT check
for absolute paths. When os.path.join(tmpdir, absolute_path) is called,
the tmpdir is ignored and the file is written to the absolute path.
"""

import os
import sys
import tempfile
import urllib.parse

import pytest

# Import the module under test
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import setuptools.package_index


class TestEggInfoForUrlSecurity:
    """Test URL filename extraction for path traversal vectors."""

    @pytest.mark.parametrize(
        "url,expected_base",
        [
            # Normal cases
            ("http://example.com/package-1.0.tar.gz", "package-1.0.tar.gz"),
            ("http://example.com/path/to/package.zip", "package.zip"),
            ("http://example.com/simple/foo/", ""),
            # URL-encoded normal filename
            ("http://example.com/my%20package-1.0.tar.gz", "my package-1.0.tar.gz"),
            # URL-encoded absolute paths (potential vulnerability vectors)
            ("http://evil.com/%2Fetc%2Fpasswd", "/etc/passwd"),
            ("http://evil.com/%2ftmp%2fmalicious.tar.gz", "/tmp/malicious.tar.gz"),
            ("http://evil.com/%2Fvar%2Fwww%2Fshell.php", "/var/www/shell.php"),
            # Double-encoded should NOT decode twice (safe)
            ("http://evil.com/%252Fetc%252Fpasswd", "%2Fetc%2Fpasswd"),
            # Windows absolute paths (URL-encoded)
            ("http://evil.com/C%3A%5CWindows%5Ctest.exe", "C:\\Windows\\test.exe"),
            ("http://evil.com/C%3A%2FWindows%2Ftest.exe", "C:/Windows/test.exe"),
        ],
    )
    def test_egg_info_extracts_filename(self, url, expected_base):
        """
        Verify what egg_info_for_url returns for various URLs.

        This documents the current behavior where URL-decoded filenames
        may contain absolute paths or path traversal sequences.
        """
        base, _fragment = setuptools.package_index.egg_info_for_url(url)
        assert base == expected_base


class TestDownloadUrlSanitization:
    """Test the sanitization logic in _download_url path construction."""

    @pytest.mark.parametrize(
        "input_name,expected_after_sanitize",
        [
            # Current sanitization handles ".." sequences
            ("..", "."),
            ("../..", "./."),
            ("foo/../bar", "foo/./bar"),
            ("../../../etc/passwd", "./././etc/passwd"),
            # Multiple passes: "...." contains ".." so loop runs
            ("....//", ".//"),  # "...." -> "." + "." = ".." -> "." (loop continues)
            # Backslash replacement ONLY happens when ".." is present
            # If no "..", the while loop never executes
            ("foo\\bar", "foo\\bar"),  # No ".." so no backslash replacement!
            ("..\\..\\etc", "._._etc"),  # Has ".." so backslash replaced too
            # These are NOT sanitized (vulnerability)
            ("/etc/passwd", "/etc/passwd"),
            ("/tmp/malicious", "/tmp/malicious"),
            ("C:\\Windows", "C:\\Windows"),  # No ".." so no sanitization at all!
            ("C:/Windows/System32", "C:/Windows/System32"),  # No ".." - unchanged
        ],
    )
    def test_current_sanitization_behavior(self, input_name, expected_after_sanitize):
        """
        Document the current sanitization behavior in _download_url.

        IMPORTANT: The sanitization loop ONLY runs when ".." is present.
        The backslash replacement happens inside the while loop, so if there's
        no ".." in the filename, backslashes are NOT replaced either.

        This means the sanitization is even weaker than it appears!
        """
        name = input_name
        if name:
            while '..' in name:
                name = name.replace('..', '.').replace('\\', '_')
        assert name == expected_after_sanitize


class TestPathTraversalVulnerability:
    """
    Tests demonstrating the absolute path bypass vulnerability.

    These tests show that absolute paths in URLs can cause os.path.join()
    to ignore the target directory entirely.
    """

    def _simulate_download_path(self, url, tmpdir):
        """
        Simulate the path construction logic from _download_url.

        This replicates lines 810-823 of package_index.py.
        """
        name, _fragment = setuptools.package_index.egg_info_for_url(url)
        if name:
            while '..' in name:
                name = name.replace('..', '.').replace('\\', '_')
        else:
            name = "__downloaded__"

        if name.endswith('.egg.zip'):
            name = name[:-4]

        return os.path.join(tmpdir, name)

    def _path_escapes_directory(self, path, directory):
        """Check if resolved path escapes the target directory."""
        try:
            resolved_path = os.path.realpath(path)
            resolved_dir = os.path.realpath(directory)
            # Path should start with directory + separator
            return not (
                resolved_path == resolved_dir
                or resolved_path.startswith(resolved_dir + os.sep)
            )
        except (ValueError, OSError):
            return True

    @pytest.mark.parametrize(
        "url,should_escape",
        [
            # Normal URLs - should NOT escape
            ("http://example.com/package-1.0.tar.gz", False),
            ("http://example.com/path/to/package.zip", False),
            # Relative traversal - sanitized, should NOT escape
            ("http://evil.com/../../../etc/passwd", False),
            ("http://evil.com/foo/../../../etc/passwd", False),
            # VULNERABILITY: Absolute paths escape the target directory
            ("http://evil.com/%2Fetc%2Fpasswd", True),
            ("http://evil.com/%2Ftmp%2Fmalicious.tar.gz", True),
            ("http://evil.com/%2Fvar%2Flog%2Ftest", True),
        ],
    )
    def test_path_containment_posix(self, tmp_path, url, should_escape):
        """
        Test whether constructed download paths escape the target directory.

        VULNERABILITY: URLs with URL-encoded absolute paths (e.g., %2Fetc)
        cause the download to write outside the intended directory.
        """
        if sys.platform == 'win32' and should_escape:
            pytest.skip("POSIX absolute paths don't escape on Windows")

        tmpdir = str(tmp_path / "downloads")
        os.makedirs(tmpdir, exist_ok=True)

        result_path = self._simulate_download_path(url, tmpdir)
        escapes = self._path_escapes_directory(result_path, tmpdir)

        if should_escape:
            assert escapes, (
                f"VULNERABILITY: Expected path to escape target directory.\n"
                f"  URL: {url}\n"
                f"  Target dir: {tmpdir}\n"
                f"  Result path: {result_path}"
            )
        else:
            assert not escapes, (
                f"Path should stay within target directory.\n"
                f"  URL: {url}\n"
                f"  Target dir: {tmpdir}\n"
                f"  Result path: {result_path}"
            )

    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    @pytest.mark.parametrize(
        "url,should_escape",
        [
            # Windows drive letter with forward slash - ESCAPES
            ("http://evil.com/C%3A%2FWindows%2Ftest.exe", True),
            ("http://evil.com/D%3A%2Fmalicious.bat", True),
            # Windows drive letter with backslash - backslash sanitized to _
            # Results in "C:_Windows_test.exe" which is relative (doesn't escape)
            ("http://evil.com/C%3A%5CWindows%5Ctest.exe", False),
        ],
    )
    def test_path_containment_windows(self, tmp_path, url, should_escape):
        """
        Test Windows-specific path escape scenarios.

        On Windows, drive letters with forward slashes can escape the
        target directory, while backslashes get sanitized to underscores.
        """
        tmpdir = str(tmp_path / "downloads")
        os.makedirs(tmpdir, exist_ok=True)

        result_path = self._simulate_download_path(url, tmpdir)
        escapes = self._path_escapes_directory(result_path, tmpdir)

        if should_escape:
            assert escapes, f"Expected {result_path} to escape {tmpdir}"
        else:
            assert not escapes, f"Expected {result_path} to stay within {tmpdir}"

    def test_os_path_join_absolute_path_behavior(self, tmp_path):
        """
        Demonstrate that os.path.join ignores the base when given an absolute path.

        This is the root cause of the vulnerability.
        """
        tmpdir = str(tmp_path / "target")

        # When second argument is absolute, first argument is ignored
        result = os.path.join(tmpdir, "/etc/passwd")
        assert result == "/etc/passwd", "os.path.join ignores base for absolute paths"

        # When second argument is relative, both are combined
        result = os.path.join(tmpdir, "relative/path")
        assert result == os.path.join(tmpdir, "relative/path")

    def test_url_encoded_absolute_path_decoded(self):
        """
        Show that URL-encoded absolute paths are decoded by egg_info_for_url.

        The path %2Fetc%2Fpasswd becomes /etc/passwd after URL decoding.
        """
        url = "http://evil.com/packages/%2Fetc%2Fpasswd"
        base, _fragment = setuptools.package_index.egg_info_for_url(url)
        assert base == "/etc/passwd", "URL decoding produces absolute path"


class TestPathTraversalEdgeCases:
    """Edge cases and boundary conditions for path traversal."""

    @pytest.mark.parametrize(
        "filename",
        [
            # Empty or special names
            "",
            ".",
            "..",
            # Names that look suspicious but are safe after sanitization
            "..foo",
            "foo..",
            "foo..bar",
            # Unicode edge cases
            "package\u2024name.tar.gz",  # One dot leader
            "package\uff0e\uff0ename.tar.gz",  # Fullwidth dots
        ],
    )
    def test_edge_case_filenames(self, tmp_path, filename):
        """Test various edge case filenames don't escape target directory."""
        tmpdir = str(tmp_path / "downloads")
        os.makedirs(tmpdir, exist_ok=True)

        # Simulate sanitization
        name = filename
        if name:
            while '..' in name:
                name = name.replace('..', '.').replace('\\', '_')
        else:
            name = "__downloaded__"

        result = os.path.join(tmpdir, name)

        # Verify path doesn't escape (for these cases it shouldn't)
        resolved = os.path.realpath(result)
        resolved_base = os.path.realpath(tmpdir)
        # These edge cases should all be contained
        assert resolved.startswith(resolved_base) or resolved == resolved_base

    def test_multiple_traversal_sequences(self, tmp_path):
        """Test that multiple ../  sequences are all sanitized."""
        tmpdir = str(tmp_path)

        # Many traversal sequences
        malicious = "../" * 20 + "etc/passwd"

        name = malicious
        while '..' in name:
            name = name.replace('..', '.').replace('\\', '_')

        result = os.path.join(tmpdir, name)

        # Should be sanitized to something like "./././.../etc/passwd"
        assert ".." not in result
        # And should stay within tmpdir
        resolved = os.path.realpath(result)
        assert resolved.startswith(os.path.realpath(tmpdir))

    def test_mixed_traversal_and_absolute(self, tmp_path):
        """
        Test URL with both traversal sequences AND absolute path.

        The traversal sequences get sanitized but the absolute path
        still escapes.
        """
        if sys.platform == 'win32':
            pytest.skip("POSIX path test")

        tmpdir = str(tmp_path / "downloads")
        os.makedirs(tmpdir, exist_ok=True)

        # URL-encoded: /../../../etc/passwd
        url = "http://evil.com/%2F..%2F..%2F..%2Fetc%2Fpasswd"
        base, _ = setuptools.package_index.egg_info_for_url(url)
        # Decodes to: /../../../etc/passwd

        name = base
        if name:
            while '..' in name:
                name = name.replace('..', '.').replace('\\', '_')

        # After sanitization: /./././etc/passwd (still absolute!)
        result = os.path.join(tmpdir, name)

        # VULNERABILITY: Still escapes because it starts with /
        assert result.startswith("/"), "Absolute path not stripped"
        assert not result.startswith(tmpdir), "Path escapes target directory"


class TestSecurityFix:
    """
    Tests that will PASS once the vulnerability is fixed.

    These tests define the expected secure behavior. Currently they fail
    (marked xfail) to document the vulnerability.
    """

    @pytest.mark.xfail(reason="Vulnerability: absolute paths not sanitized")
    def test_absolute_path_should_be_sanitized(self, tmp_path):
        """After fix: absolute paths should be stripped or rejected."""
        tmpdir = str(tmp_path / "downloads")
        os.makedirs(tmpdir, exist_ok=True)

        url = "http://evil.com/%2Fetc%2Fpasswd"
        base, _ = setuptools.package_index.egg_info_for_url(url)

        # Current behavior: base = "/etc/passwd"
        # Expected after fix: base should be sanitized to "etc/passwd"
        # or _download_url should strip the leading /

        name = base
        if name:
            while '..' in name:
                name = name.replace('..', '.').replace('\\', '_')

        result = os.path.join(tmpdir, name)

        # This assertion currently fails - after fix it should pass
        resolved = os.path.realpath(result)
        assert resolved.startswith(os.path.realpath(tmpdir) + os.sep), (
            f"Path {result} should be contained within {tmpdir}"
        )

    @pytest.mark.xfail(
        sys.platform == 'win32',
        reason="Vulnerability: Windows drive letters with / not sanitized",
    )
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_windows_drive_letter_should_be_sanitized(self, tmp_path):
        """After fix: Windows drive letters should be sanitized."""
        tmpdir = str(tmp_path / "downloads")
        os.makedirs(tmpdir, exist_ok=True)

        # C:/Windows/test.exe - forward slash variant
        url = "http://evil.com/C%3A%2FWindows%2Ftest.exe"
        base, _ = setuptools.package_index.egg_info_for_url(url)

        name = base
        if name:
            while '..' in name:
                name = name.replace('..', '.').replace('\\', '_')

        result = os.path.join(tmpdir, name)

        # This should pass after fix
        resolved = os.path.realpath(result)
        assert resolved.startswith(os.path.realpath(tmpdir) + os.sep)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
