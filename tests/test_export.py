"""Tests for depthwatch.export module."""

from __future__ import annotations

import csv
import io
import json

import pytest

from depthwatch.advisories import Advisory
from depthwatch.resolver import PackageInfo
from depthwatch.scanner import ScanResult
from depthwatch.export import export_csv, export_json, export_markdown


def _make_pkg(
    name: str,
    required: str = "1.0.0",
    installed: str = "1.0.0",
    advisories=None,
) -> PackageInfo:
    return PackageInfo(
        name=name,
        required_version=required,
        installed_version=installed,
        advisories=advisories or [],
    )


@pytest.fixture()
def clean_result() -> ScanResult:
    pkgs = [_make_pkg("requests", "2.28.0", "2.28.0")]
    return ScanResult(packages=pkgs, requirements_file="requirements.txt")


@pytest.fixture()
def drift_result() -> ScanResult:
    pkgs = [
        _make_pkg("requests", "2.28.0", "2.27.0"),
        _make_pkg(
            "flask",
            "2.0.0",
            "2.0.0",
            advisories=[Advisory(id="GHSA-1234", summary="XSS", severity="HIGH")],
        ),
    ]
    return ScanResult(packages=pkgs, requirements_file="requirements.txt")


class TestExportJson:
    def test_returns_valid_json(self, clean_result):
        output = export_json(clean_result)
        data = json.loads(output)
        assert "packages" in data

    def test_package_fields_present(self, clean_result):
        data = json.loads(export_json(clean_result))
        pkg = data["packages"][0]
        assert pkg["name"] == "requests"
        assert pkg["drifted"] is False
        assert pkg["advisories"] == []

    def test_drifted_count(self, drift_result):
        data = json.loads(export_json(drift_result))
        assert data["drifted_count"] == 1

    def test_vulnerable_count(self, drift_result):
        data = json.loads(export_json(drift_result))
        assert data["vulnerable_count"] == 1

    def test_advisory_fields_in_output(self, drift_result):
        data = json.loads(export_json(drift_result))
        flask_pkg = next(p for p in data["packages"] if p["name"] == "flask")
        assert flask_pkg["advisories"][0]["id"] == "GHSA-1234"
        assert flask_pkg["advisories"][0]["severity"] == "HIGH"


class TestExportCsv:
    def test_returns_string(self, clean_result):
        output = export_csv(clean_result)
        assert isinstance(output, str)

    def test_header_row_present(self, clean_result):
        reader = csv.reader(io.StringIO(export_csv(clean_result)))
        header = next(reader)
        assert "name" in header
        assert "drifted" in header

    def test_data_row_values(self, clean_result):
        reader = csv.reader(io.StringIO(export_csv(clean_result)))
        next(reader)  # skip header
        row = next(reader)
        assert row[0] == "requests"
        assert row[3] == "False"

    def test_advisory_ids_pipe_separated(self, drift_result):
        reader = csv.reader(io.StringIO(export_csv(drift_result)))
        next(reader)
        rows = list(reader)
        flask_row = next(r for r in rows if r[0] == "flask")
        assert "GHSA-1234" in flask_row[4]


class TestExportMarkdown:
    def test_contains_header(self, clean_result):
        output = export_markdown(clean_result)
        assert "# DepthWatch Scan Report" in output

    def test_table_header_present(self, clean_result):
        output = export_markdown(clean_result)
        assert "| Package |" in output

    def test_package_row_present(self, clean_result):
        output = export_markdown(clean_result)
        assert "requests" in output

    def test_drifted_indicator(self, drift_result):
        output = export_markdown(drift_result)
        assert "⚠️" in output

    def test_summary_counts(self, drift_result):
        output = export_markdown(drift_result)
        assert "Drifted packages:** 1" in output
        assert "Vulnerable packages:** 1" in output
