"""Tests for depthwatch.advisories module."""

from unittest.mock import patch, MagicMock
import json

import pytest

from depthwatch.advisories import (
    Advisory,
    _build_osv_payload,
    _parse_osv_response,
    fetch_advisories,
)


class TestAdvisory:
    def test_str_with_severity(self):
        adv = Advisory("CVE-2023-1234", "A bad bug", severity="HIGH")
        assert str(adv) == "CVE-2023-1234 [HIGH]: A bad bug"

    def test_str_without_severity(self):
        adv = Advisory("GHSA-xxxx", "Minor issue")
        assert str(adv) == "GHSA-xxxx: Minor issue"


class TestBuildOsvPayload:
    def test_payload_structure(self):
        payload = _build_osv_payload(["requests==2.28.0"])
        assert "queries" in payload
        assert payload["queries"][0]["package"]["name"] == "requests"
        assert payload["queries"][0]["version"] == "2.28.0"

    def test_payload_without_version(self):
        payload = _build_osv_payload(["flask"])
        assert "version" not in payload["queries"][0]

    def test_multiple_packages(self):
        payload = _build_osv_payload(["django==4.2", "pillow==9.0"])
        assert len(payload["queries"]) == 2

    def test_ecosystem_is_pypi(self):
        payload = _build_osv_payload(["numpy==1.24"])
        assert payload["queries"][0]["package"]["ecosystem"] == "PyPI"


class TestParseOsvResponse:
    _RAW = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-abcd",
                        "summary": "Dangerous bug",
                        "severity": [{"score": "CRITICAL"}],
                        "aliases": ["CVE-2023-9999"],
                    }
                ]
            },
            {"vulns": []},
        ]
    }

    def test_returns_advisory_objects(self):
        result = _parse_osv_response(["requests==2.28", "flask==2.0"], self._RAW)
        assert len(result["requests"]) == 1
        assert result["requests"][0].vuln_id == "GHSA-abcd"

    def test_clean_package_returns_empty_list(self):
        result = _parse_osv_response(["requests==2.28", "flask==2.0"], self._RAW)
        assert result["flask"] == []

    def test_aliases_parsed(self):
        result = _parse_osv_response(["requests==2.28", "flask==2.0"], self._RAW)
        assert "CVE-2023-9999" in result["requests"][0].aliases


class TestFetchAdvisories:
    _RAW_RESP = {"results": [{"vulns": []}]}

    def _mock_urlopen(self, raw):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps(raw).encode()
        return mock_resp

    def test_returns_dict_of_advisories(self, tmp_path):
        with patch("depthwatch.advisories._cache.get", return_value=None), \
             patch("depthwatch.advisories._cache.set"), \
             patch("urllib.request.urlopen", return_value=self._mock_urlopen(self._RAW_RESP)):
            result = fetch_advisories(["requests==2.28"])
        assert "requests" in result

    def test_uses_cache_when_available(self):
        with patch("depthwatch.advisories._cache.get", return_value=self._RAW_RESP) as mock_get:
            result = fetch_advisories(["requests==2.28"], use_cache=True)
        mock_get.assert_called_once()
        assert "requests" in result

    def test_skips_cache_when_disabled(self):
        with patch("depthwatch.advisories._cache.get") as mock_get, \
             patch("depthwatch.advisories._cache.set"), \
             patch("urllib.request.urlopen", return_value=self._mock_urlopen(self._RAW_RESP)):
            fetch_advisories(["requests==2.28"], use_cache=False)
        mock_get.assert_not_called()
