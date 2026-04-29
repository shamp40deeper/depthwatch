"""Tests for depthwatch.report (advisory + baseline diff formatting)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from depthwatch.advisories import Advisory
from depthwatch.report import format_advisory_report, format_baseline_diff, format_json_report
from depthwatch.scanner import ScanResult


def _make_pkg(name: str, required: str, installed: str, advisories=None):
    pkg = MagicMock()
    pkg.name = name
    pkg.required_version = required
    pkg.installed_version = installed
    pkg.advisories = advisories or []
    return pkg


class TestFormatAdvisoryReport:
    def setUp(self):
        pass

    def test_vulnerable_package_shown(self):
        adv = Advisory(id="CVE-1", package="requests", summary="Bad", severity="HIGH")
        pkg = _make_pkg("requests", "2.28.0", "2.28.0", advisories=[adv])
        result = MagicMock(spec=ScanResult)
        result.packages = [pkg]
        output = format_advisory_report(result)
        assert "VULNERABLE" in output
        assert "requests" in output

    def test_clean_package_hidden_by_default(self):
        pkg = _make_pkg("flask", "3.0.0", "3.0.0")
        result = MagicMock(spec=ScanResult)
        result.packages = [pkg]
        output = format_advisory_report(result)
        assert "flask" not in output

    def test_clean_package_shown_when_flag_set(self):
        pkg = _make_pkg("flask", "3.0.0", "3.0.0")
        result = MagicMock(spec=ScanResult)
        result.packages = [pkg]
        output = format_advisory_report(result, show_clean=True)
        assert "flask" in output
        assert "OK" in output

    def test_no_issues_message(self):
        result = MagicMock(spec=ScanResult)
        result.packages = []
        output = format_advisory_report(result)
        assert "No issues found" in output


class TestFormatBaselineDiff:
    def test_no_changes(self):
        output = format_baseline_diff({})
        assert "no changes" in output

    def test_added_package(self):
        changes = {"click": {"baseline": None, "current": "8.1.0"}}
        output = format_baseline_diff(changes)
        assert "ADDED" in output
        assert "click" in output

    def test_removed_package(self):
        changes = {"gunicorn": {"baseline": "21.0.0", "current": None}}
        output = format_baseline_diff(changes)
        assert "REMOVED" in output
        assert "gunicorn" in output

    def test_changed_package(self):
        changes = {"requests": {"baseline": "2.28.0", "current": "2.31.0"}}
        output = format_baseline_diff(changes)
        assert "CHANGED" in output
        assert "2.28.0" in output
        assert "2.31.0" in output

    def test_custom_label(self):
        output = format_baseline_diff({}, label="Weekly check")
        assert "Weekly check" in output

    def test_change_count_in_header(self):
        changes = {
            "a": {"baseline": "1.0", "current": "2.0"},
            "b": {"baseline": None, "current": "0.1"},
        }
        output = format_baseline_diff(changes)
        assert "2 change(s)" in output
