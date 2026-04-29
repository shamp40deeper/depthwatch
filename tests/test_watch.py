"""Tests for depthwatch.watch module."""

from __future__ import annotations

from unittest.mock import MagicMock, call

import pytest

from depthwatch.advisories import Advisory
from depthwatch.resolver import PackageInfo
from depthwatch.scanner import ScanResult
from depthwatch.watch import WatchConfig, _result_changed, watch


def _make_result(drifted_names: list[str], vuln_names: list[str]) -> ScanResult:
    packages = []
    for name in drifted_names:
        packages.append(
            PackageInfo(name=name, required_version="1.0", installed_version="0.9")
        )
    for name in vuln_names:
        if name not in drifted_names:
            packages.append(
                PackageInfo(
                    name=name,
                    required_version="1.0",
                    installed_version="1.0",
                    advisories=[Advisory(id="CVE-X", summary="bug", severity=None)],
                )
            )
    return ScanResult(packages=packages, requirements_file="req.txt")


class TestWatchConfig:
    def test_default_interval(self):
        cfg = WatchConfig()
        assert cfg.interval == 60

    def test_custom_interval(self):
        cfg = WatchConfig(interval=30)
        assert cfg.interval == 30

    def test_invalid_interval_raises(self):
        with pytest.raises(ValueError, match="interval"):
            WatchConfig(interval=0)

    def test_max_iterations_default_none(self):
        assert WatchConfig().max_iterations is None


class TestResultChanged:
    def test_identical_results_not_changed(self):
        r = _make_result(["requests"], [])
        assert _result_changed(r, r) is False

    def test_new_drift_detected(self):
        prev = _make_result([], [])
        curr = _make_result(["requests"], [])
        assert _result_changed(prev, curr) is True

    def test_drift_resolved_detected(self):
        prev = _make_result(["requests"], [])
        curr = _make_result([], [])
        assert _result_changed(prev, curr) is True

    def test_new_vuln_detected(self):
        prev = _make_result([], [])
        curr = _make_result([], ["flask"])
        assert _result_changed(prev, curr) is True


class TestWatch:
    def _no_sleep(self, _: float) -> None:
        pass

    def test_on_change_called_when_result_differs(self):
        results = [
            _make_result([], []),
            _make_result(["requests"], []),
        ]
        scan_fn = MagicMock(side_effect=results)
        on_change = MagicMock()
        cfg = WatchConfig(interval=1, max_iterations=2)
        watch(scan_fn, on_change, cfg, _sleep=self._no_sleep)
        on_change.assert_called_once()

    def test_on_change_not_called_when_stable(self):
        result = _make_result([], [])
        scan_fn = MagicMock(return_value=result)
        on_change = MagicMock()
        cfg = WatchConfig(interval=1, max_iterations=3)
        watch(scan_fn, on_change, cfg, _sleep=self._no_sleep)
        on_change.assert_not_called()

    def test_stops_after_max_iterations(self):
        result = _make_result([], [])
        scan_fn = MagicMock(return_value=result)
        cfg = WatchConfig(interval=1, max_iterations=4)
        watch(scan_fn, MagicMock(), cfg, _sleep=self._no_sleep)
        assert scan_fn.call_count == 4

    def test_sleep_called_between_iterations(self):
        result = _make_result([], [])
        scan_fn = MagicMock(return_value=result)
        sleep_mock = MagicMock()
        cfg = WatchConfig(interval=5, max_iterations=3)
        watch(scan_fn, MagicMock(), cfg, _sleep=sleep_mock)
        assert sleep_mock.call_count == 2
        sleep_mock.assert_called_with(5)
