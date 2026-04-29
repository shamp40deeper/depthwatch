"""Tests for depthwatch.report, including snapshot diff formatting."""

import json
import pytest

from depthwatch.report import (
    format_advisory_report,
    format_json_report,
    format_baseline_diff,
    format_snapshot_diff,
)
from depthwatch.scanner import ScanResult
from depthwatch.resolver import PackageInfo
from depthwatch.advisories import Advisory


def _make_pkg(name, required="1.0", installed="1.0", advisories=None):
    return PackageInfo(
        name=name,
        required_version=required,
        installed_version=installed,
        advisories=advisories or [],
    )


class TestFormatAdvisoryReport:
    def setUp(self):
        pass

    def test_vulnerable_package_shown(self):
        adv = Advisory(package="requests", vuln_id="CVE-2023-001", summary="Bad")
        pkg = _make_pkg("requests", advisories=[adv])
        result = ScanResult(packages=[pkg])
        out = format_advisory_report(result)
        assert "VULNERABLE" in out
        assert "requests" in out

    def test_clean_package_hidden_by_default(self):
        pkg = _make_pkg("flask")
        result = ScanResult(packages=[pkg])
        out = format_advisory_report(result)
        assert "flask" not in out

    def test_clean_package_shown_with_flag(self):
        pkg = _make_pkg("flask")
        result = ScanResult(packages=[pkg])
        out = format_advisory_report(result, show_clean=True)
        assert "OK" in out and "flask" in out

    def test_no_issues_message(self):
        result = ScanResult(packages=[_make_pkg("click")])
        out = format_advisory_report(result)
        assert out == "No issues found."


class TestFormatJsonReport:
    def test_returns_valid_json(self):
        pkg = _make_pkg("requests", required="2.28.0", installed="2.31.0")
        result = ScanResult(packages=[pkg])
        out = format_json_report(result)
        data = json.loads(out)
        assert isinstance(data, list)
        assert data[0]["name"] == "requests"


class TestFormatBaselineDiff:
    def test_added(self):
        diff = {"flask": (None, "3.0.0")}
        out = format_baseline_diff(diff)
        assert "ADDED" in out and "flask" in out

    def test_removed(self):
        diff = {"flask": ("3.0.0", None)}
        out = format_baseline_diff(diff)
        assert "REMOVED" in out

    def test_changed(self):
        diff = {"requests": ("2.28.0", "2.31.0")}
        out = format_baseline_diff(diff)
        assert "CHANGED" in out and "2.28.0" in out and "2.31.0" in out

    def test_no_changes(self):
        out = format_baseline_diff({})
        assert "No changes" in out


class TestFormatSnapshotDiff:
    def test_added_package(self):
        diff = {"added": [{"name": "flask", "version": "3.0.0"}], "removed": [], "changed": []}
        out = format_snapshot_diff(diff)
        assert "ADDED" in out and "flask" in out

    def test_removed_package(self):
        diff = {"added": [], "removed": [{"name": "flask", "version": "3.0.0"}], "changed": []}
        out = format_snapshot_diff(diff)
        assert "REMOVED" in out

    def test_changed_package(self):
        diff = {"added": [], "removed": [], "changed": [{"name": "requests", "old_version": "2.28.0", "new_version": "2.31.0"}]}
        out = format_snapshot_diff(diff)
        assert "CHANGED" in out and "2.28.0" in out

    def test_no_diff_message(self):
        diff = {"added": [], "removed": [], "changed": []}
        out = format_snapshot_diff(diff)
        assert "No differences" in out

    def test_header_includes_labels(self):
        diff = {"added": [], "removed": [], "changed": []}
        out = format_snapshot_diff(diff, old_label="v1", new_label="v2")
        assert "v1" in out and "v2" in out
