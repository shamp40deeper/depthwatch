"""Tests for depthwatch.notify."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from depthwatch.notify import (
    NotifyConfig,
    _build_message,
    send_notification,
)
from depthwatch.scanner import ScanResult
from depthwatch.resolver import PackageInfo
from depthwatch.advisories import Advisory


def _make_pkg(name, req="1.0.0", inst="1.0.0", advisories=None):
    return PackageInfo(
        name=name,
        required_version=req,
        installed_version=inst,
        dependencies=[],
        advisories=advisories or [],
    )


def _make_result(packages):
    return ScanResult(packages=packages, requirements_file="requirements.txt")


class TestNotifyConfig:
    def test_default_severity(self):
        cfg = NotifyConfig(channel="slack", target="http://example.com")
        assert cfg.min_severity == "LOW"

    def test_severity_threshold_index_known(self):
        cfg = NotifyConfig(channel="slack", target="x", min_severity="HIGH")
        assert cfg.severity_threshold_index() == 2

    def test_severity_threshold_index_unknown_defaults_zero(self):
        cfg = NotifyConfig(channel="slack", target="x", min_severity="BOGUS")
        assert cfg.severity_threshold_index() == 0


class TestBuildMessage:
    def test_includes_drifted_package(self):
        pkg = _make_pkg("requests", req="2.0.0", inst="1.9.0")
        result = _make_result([pkg])
        msg = _build_message(result)
        assert "requests" in msg
        assert "2.0.0" in msg
        assert "1.9.0" in msg

    def test_includes_vulnerable_package(self):
        adv = Advisory(id="CVE-2023-0001", package="flask", summary="XSS", severity="HIGH")
        pkg = _make_pkg("flask", advisories=[adv])
        result = _make_result([pkg])
        msg = _build_message(result)
        assert "flask" in msg
        assert "Vulnerable" in msg

    def test_no_issues_produces_header_only(self):
        pkg = _make_pkg("boto3")
        result = _make_result([pkg])
        msg = _build_message(result)
        assert "depthwatch alert" in msg
        assert "Drifted" not in msg
        assert "Vulnerable" not in msg


class TestSendNotification:
    def test_no_notification_when_no_issues(self):
        pkg = _make_pkg("clean")
        result = _make_result([pkg])
        cfg = NotifyConfig(channel="slack", target="http://hook")
        with patch("depthwatch.notify.notify_slack") as mock_slack:
            send_notification(cfg, result)
            mock_slack.assert_not_called()

    def test_slack_called_when_issues(self):
        adv = Advisory(id="CVE-X", package="pkg", summary="bad", severity="HIGH")
        pkg = _make_pkg("pkg", advisories=[adv])
        result = _make_result([pkg])
        cfg = NotifyConfig(channel="slack", target="http://hook")
        with patch("depthwatch.notify.notify_slack") as mock_slack:
            send_notification(cfg, result)
            mock_slack.assert_called_once_with(cfg, result)

    def test_webhook_called_when_issues(self):
        pkg = _make_pkg("pkg", req="2.0", inst="1.0")
        result = _make_result([pkg])
        cfg = NotifyConfig(channel="webhook", target="http://hook")
        with patch("depthwatch.notify.notify_webhook") as mock_wh:
            send_notification(cfg, result)
            mock_wh.assert_called_once_with(cfg, result)

    def test_email_called_when_issues(self):
        pkg = _make_pkg("pkg", req="2.0", inst="1.0")
        result = _make_result([pkg])
        cfg = NotifyConfig(channel="email", target="ops@example.com")
        with patch("depthwatch.notify.notify_email") as mock_email:
            send_notification(cfg, result)
            mock_email.assert_called_once()

    def test_unknown_channel_raises(self):
        pkg = _make_pkg("pkg", req="2.0", inst="1.0")
        result = _make_result([pkg])
        cfg = NotifyConfig(channel="carrier_pigeon", target="roof")
        with pytest.raises(ValueError, match="carrier_pigeon"):
            send_notification(cfg, result)
