"""Tests for the depthwatch CLI entry point."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depthwatch.cli import build_parser, run
from depthwatch.scanner import ScanResult
from depthwatch.advisories import Advisory
from depthwatch.resolver import PackageInfo


DUMMY_PKG = PackageInfo(name="requests", required_version="2.28.0", installed_version="2.28.0")
CLEAN_RESULT = ScanResult(package=DUMMY_PKG, advisories=[])
DIRTY_RESULT = ScanResult(
    package=PackageInfo(name="urllib3", required_version="1.26.0", installed_version="1.25.0"),
    advisories=[Advisory(package="urllib3", vuln_id="GHSA-xxxx", summary="Test vuln", severity="HIGH")],
)


def _make_req_file(tmp_path: Path, content: str = "requests==2.28.0\n") -> Path:
    req = tmp_path / "requirements.txt"
    req.write_text(content)
    return req


class TestBuildParser:
    def test_defaults(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.requirements == Path("requirements.txt")
        assert args.show_clean is False
        assert args.json is False
        assert args.exit_zero is False

    def test_custom_requirements_path(self):
        parser = build_parser()
        args = parser.parse_args(["custom/reqs.txt"])
        assert args.requirements == Path("custom/reqs.txt")

    def test_flags_set(self):
        parser = build_parser()
        args = parser.parse_args(["--show-clean", "--json", "--exit-zero"])
        assert args.show_clean is True
        assert args.json is True
        assert args.exit_zero is True


class TestRun:
    def test_missing_requirements_file_returns_1(self, tmp_path):
        result = run([str(tmp_path / "nonexistent.txt")])
        assert result == 1

    @patch("depthwatch.cli.scan_requirements", return_value=[CLEAN_RESULT])
    @patch("depthwatch.cli.format_advisory_report", return_value="report output")
    def test_clean_run_returns_0(self, mock_report, mock_scan, tmp_path, capsys):
        req = _make_req_file(tmp_path)
        result = run([str(req)])
        assert result == 0
        captured = capsys.readouterr()
        assert "report output" in captured.out

    @patch("depthwatch.cli.scan_requirements", return_value=[DIRTY_RESULT])
    @patch("depthwatch.cli.format_advisory_report", return_value="issues found")
    def test_issues_return_2(self, mock_report, mock_scan, tmp_path):
        req = _make_req_file(tmp_path)
        result = run([str(req)])
        assert result == 2

    @patch("depthwatch.cli.scan_requirements", return_value=[DIRTY_RESULT])
    @patch("depthwatch.cli.format_advisory_report", return_value="issues found")
    def test_exit_zero_flag_overrides(self, mock_report, mock_scan, tmp_path):
        req = _make_req_file(tmp_path)
        result = run([str(req), "--exit-zero"])
        assert result == 0

    @patch("depthwatch.cli.scan_requirements", return_value=[CLEAN_RESULT])
    @patch("depthwatch.cli.format_json_report", return_value='{"packages": []}')
    def test_json_flag_calls_json_formatter(self, mock_json, mock_scan, tmp_path, capsys):
        req = _make_req_file(tmp_path)
        run([str(req), "--json"])
        mock_json.assert_called_once()
        captured = capsys.readouterr()
        assert "{" in captured.out
