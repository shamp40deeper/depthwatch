"""Tests for depthwatch.scanner module."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from depthwatch.advisories import Advisory
from depthwatch.resolver import PackageInfo
from depthwatch.scanner import (
    ScanResult,
    _find_requirements_file,
    _parse_requirements,
    scan_multiple,
    scan_project,
)


# ---------------------------------------------------------------------------
# ScanResult unit tests
# ---------------------------------------------------------------------------

class TestScanResult:
    def _make_pkg(self, name: str, required: str, installed: str | None) -> PackageInfo:
        return PackageInfo(name=name, required_version=required, installed_version=installed)

    def test_drifted_packages_detects_mismatch(self):
        pkg_ok = self._make_pkg("requests", "2.28.0", "2.28.0")
        pkg_drift = self._make_pkg("flask", "2.0.0", "1.9.0")
        result = ScanResult(project_path=Path("."), packages=[pkg_ok, pkg_drift])
        assert result.drifted_packages == [pkg_drift]

    def test_drifted_packages_empty_when_all_match(self):
        pkg = self._make_pkg("requests", "2.28.0", "2.28.0")
        result = ScanResult(project_path=Path("."), packages=[pkg])
        assert result.drifted_packages == []

    def test_vulnerable_packages_returns_names_with_advisories(self):
        adv = Advisory(package="flask", vuln_id="CVE-2023-0001", summary="XSS", severity="HIGH")
        result = ScanResult(project_path=Path("."), advisories={"flask": [adv], "requests": []})
        assert result.vulnerable_packages == ["flask"]

    def test_has_issues_false_when_clean(self):
        pkg = self._make_pkg("requests", "2.28.0", "2.28.0")
        result = ScanResult(project_path=Path("."), packages=[pkg], advisories={"requests": []})
        assert result.has_issues is False

    def test_has_issues_true_when_drift_present(self):
        pkg = self._make_pkg("flask", "2.0.0", "1.9.0")
        result = ScanResult(project_path=Path("."), packages=[pkg])
        assert result.has_issues is True


# ---------------------------------------------------------------------------
# _parse_requirements
# ---------------------------------------------------------------------------

def test_parse_requirements_skips_comments_and_blank_lines(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("# comment\n\nrequests==2.28.0\nflask>=2.0\n-r other.txt\n")
    result = _parse_requirements(req)
    assert result == ["requests==2.28.0", "flask>=2.0"]


# ---------------------------------------------------------------------------
# _find_requirements_file
# ---------------------------------------------------------------------------

def test_find_requirements_file_finds_root_requirements(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0")
    assert _find_requirements_file(tmp_path) == req


def test_find_requirements_file_returns_none_when_missing(tmp_path):
    assert _find_requirements_file(tmp_path) is None


# ---------------------------------------------------------------------------
# scan_project integration-style tests (mocked IO)
# ---------------------------------------------------------------------------

@pytest.fixture()
def fake_project(tmp_path) -> Path:
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\n")
    return tmp_path


def test_scan_project_returns_error_when_no_requirements(tmp_path):
    result = asyncio.get_event_loop().run_until_complete(scan_project(tmp_path, include_advisories=False))
    assert result.errors
    assert "No requirements file" in result.errors[0]


@patch("depthwatch.scanner.fetch_advisories", new_callable=AsyncMock)
@patch("depthwatch.scanner.resolve_dependencies")
def test_scan_project_populates_packages_and_advisories(mock_resolve, mock_fetch, fake_project):
    pkg = PackageInfo(name="requests", required_version="2.28.0", installed_version="2.28.0")
    mock_resolve.return_value = [pkg]
    mock_fetch.return_value = []

    result = asyncio.get_event_loop().run_until_complete(scan_project(fake_project))

    assert result.packages == [pkg]
    assert "requests" in result.advisories
    assert result.errors == []


@patch("depthwatch.scanner.scan_project", new_callable=AsyncMock)
def test_scan_multiple_returns_list_of_results(mock_scan, tmp_path):
    fake_result = ScanResult(project_path=tmp_path)
    mock_scan.return_value = fake_result
    paths = [tmp_path, tmp_path]
    results = asyncio.get_event_loop().run_until_complete(scan_multiple(paths))
    assert len(results) == 2
    assert all(r is fake_result for r in results)
