"""Tests for depthwatch.advisories module."""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

from depthwatch.advisories import (
    Advisory,
    _build_osv_payload,
    _parse_osv_response,
    fetch_advisories,
)


class TestAdvisory(unittest.TestCase):
    def test_str_with_severity(self):
        adv = Advisory("CVE-2023-1234", "Remote code execution", severity="CVSS_V3")
        self.assertIn("CVE-2023-1234", str(adv))
        self.assertIn("CVSS_V3", str(adv))

    def test_str_without_severity(self):
        adv = Advisory("GHSA-xxxx-yyyy-zzzz", "Denial of service")
        result = str(adv)
        self.assertIn("GHSA-xxxx-yyyy-zzzz", result)
        self.assertNotIn("[", result)


class TestBuildOsvPayload(unittest.TestCase):
    def test_payload_structure(self):
        payload = json.loads(_build_osv_payload("requests", "2.28.0"))
        self.assertEqual(payload["version"], "2.28.0")
        self.assertEqual(payload["package"]["name"], "requests")
        self.assertEqual(payload["package"]["ecosystem"], "PyPI")


class TestParseOsvResponse(unittest.TestCase):
    def test_empty_response(self):
        result = _parse_osv_response({})
        self.assertEqual(result, [])

    def test_single_vulnerability(self):
        data = {
            "vulns": [
                {
                    "id": "GHSA-1234",
                    "summary": "Test vulnerability",
                    "aliases": ["CVE-2023-9999"],
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                }
            ]
        }
        result = _parse_osv_response(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].advisory_id, "GHSA-1234")
        self.assertEqual(result[0].severity, "CVSS_V3")
        self.assertIn("CVE-2023-9999", result[0].aliases)

    def test_no_severity_field(self):
        data = {"vulns": [{"id": "GHSA-0000", "summary": "Minor issue"}]}
        result = _parse_osv_response(data)
        self.assertIsNone(result[0].severity)


class TestFetchAdvisories(unittest.TestCase):
    @patch("depthwatch.advisories.urllib.request.urlopen")
    def test_successful_fetch(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {"vulns": [{"id": "CVE-2023-0001", "summary": "Test"}]}
        ).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = fetch_advisories("somepackage", "1.0.0")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].advisory_id, "CVE-2023-0001")

    @patch("depthwatch.advisories.urllib.request.urlopen", side_effect=OSError)
    def test_network_error_returns_empty(self, _mock):
        result = fetch_advisories("somepackage", "1.0.0")
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
