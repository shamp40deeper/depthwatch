"""Tests for depthwatch.report module."""

from __future__ import annotations

import json
import unittest

from depthwatch.advisories import Advisory
from depthwatch.report import format_advisory_report, format_json_report


class TestFormatAdvisoryReport(unittest.TestCase):
    def setUp(self):
        self.adv = Advisory(
            advisory_id="CVE-2023-1111",
            summary="SQL injection vulnerability",
            severity="CVSS_V3",
            aliases=["GHSA-aaaa-bbbb-cccc"],
        )

    def test_vulnerable_package_shown(self):
        results = {"django==3.2.0": [self.adv]}
        report = format_advisory_report(results)
        self.assertIn("django==3.2.0", report)
        self.assertIn("CVE-2023-1111", report)
        self.assertIn("VULNERABLE", report)

    def test_clean_package_hidden_by_default(self):
        results = {"requests==2.28.0": []}
        report = format_advisory_report(results)
        self.assertNotIn("requests==2.28.0", report)

    def test_clean_package_shown_when_flag_set(self):
        results = {"requests==2.28.0": []}
        report = format_advisory_report(results, show_clean=True)
        self.assertIn("requests==2.28.0", report)
        self.assertIn("[OK]", report)

    def test_summary_counts(self):
        results = {
            "django==3.2.0": [self.adv],
            "requests==2.28.0": [],
        }
        report = format_advisory_report(results)
        self.assertIn("Scanned 2 package(s)", report)
        self.assertIn("1 vulnerable", report)
        self.assertIn("1 clean", report)

    def test_aliases_displayed(self):
        results = {"pkg==1.0": [self.adv]}
        report = format_advisory_report(results)
        self.assertIn("GHSA-aaaa-bbbb-cccc", report)


class TestFormatJsonReport(unittest.TestCase):
    def test_json_output_structure(self):
        adv = Advisory("CVE-2023-2222", "Buffer overflow", severity="CVSS_V2")
        results = {"numpy==1.21.0": [adv]}
        output = json.loads(format_json_report(results))
        self.assertIn("numpy==1.21.0", output)
        entry = output["numpy==1.21.0"][0]
        self.assertEqual(entry["id"], "CVE-2023-2222")
        self.assertEqual(entry["severity"], "CVSS_V2")

    def test_empty_results(self):
        output = json.loads(format_json_report({}))
        self.assertEqual(output, {})

    def test_clean_package_in_json(self):
        results = {"flask==2.0.0": []}
        output = json.loads(format_json_report(results))
        self.assertEqual(output["flask==2.0.0"], [])


if __name__ == "__main__":
    unittest.main()
