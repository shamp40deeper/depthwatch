"""Tests for depthwatch.resolver module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depthwatch.resolver import (
    PackageInfo,
    parse_requirements,
    resolve,
)


# ---------------------------------------------------------------------------
# PackageInfo unit tests
# ---------------------------------------------------------------------------

class TestPackageInfo:
    def test_is_installed_true(self):
        pkg = PackageInfo(name="requests", required_version="==2.28.0", installed_version="2.28.0")
        assert pkg.is_installed is True

    def test_is_installed_false(self):
        pkg = PackageInfo(name="requests", required_version="==2.28.0", installed_version=None)
        assert pkg.is_installed is False

    def test_has_drift_exact_match(self):
        pkg = PackageInfo(name="requests", required_version="==2.28.0", installed_version="2.28.0")
        assert pkg.has_drift is False

    def test_has_drift_version_mismatch(self):
        pkg = PackageInfo(name="requests", required_version="==2.27.0", installed_version="2.28.0")
        assert pkg.has_drift is True

    def test_has_drift_no_pin(self):
        pkg = PackageInfo(name="requests", required_version=">=2.0", installed_version="2.28.0")
        assert pkg.has_drift is False

    def test_has_drift_no_required_version(self):
        pkg = PackageInfo(name="requests", required_version=None, installed_version="2.28.0")
        assert pkg.has_drift is False


# ---------------------------------------------------------------------------
# parse_requirements tests
# ---------------------------------------------------------------------------

class TestParseRequirements:
    def test_parses_pinned_versions(self, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\nflask>=2.0\n")
        result = parse_requirements(req)
        assert result["requests"] == "==2.28.0"
        assert result["flask"] == ">=2.0"

    def test_ignores_comments_and_blank_lines(self, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text("# a comment\n\nrequests==2.28.0\n")
        result = parse_requirements(req)
        assert list(result.keys()) == ["requests"]

    def test_package_without_specifier(self, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests\n")
        result = parse_requirements(req)
        assert result["requests"] == ""

    def test_ignores_index_url_flags(self, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text("-i https://pypi.org/simple\nrequests==2.28.0\n")
        result = parse_requirements(req)
        assert "requests" in result
        assert len(result) == 1


# ---------------------------------------------------------------------------
# resolve integration-style tests (mocked)
# ---------------------------------------------------------------------------

class TestResolve:
    @patch("depthwatch.resolver._get_dependencies", return_value=["urllib3", "certifi"])
    @patch("depthwatch.resolver._get_installed_version", return_value="2.28.0")
    def test_resolve_returns_package_info(self, mock_ver, mock_deps, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\n")
        result = resolve(req)
        assert "requests" in result
        pkg = result["requests"]
        assert pkg.installed_version == "2.28.0"
        assert pkg.required_version == "==2.28.0"
        assert "urllib3" in pkg.dependencies

    @patch("depthwatch.resolver._get_installed_version", return_value=None)
    def test_resolve_missing_package(self, mock_ver, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text("nonexistent-pkg==1.0.0\n")
        result = resolve(req)
        pkg = result["nonexistent-pkg"]
        assert not pkg.is_installed
        assert pkg.dependencies == []
