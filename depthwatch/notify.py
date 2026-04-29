"""Notification backends for depthwatch alerts."""

from __future__ import annotations

import smtplib
import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Optional

from depthwatch.scanner import ScanResult


@dataclass
class NotifyConfig:
    """Configuration for a notification channel."""

    channel: str  # 'email' | 'slack' | 'webhook'
    target: str   # email address, Slack webhook URL, or generic URL
    min_severity: str = "LOW"
    extra: dict = field(default_factory=dict)

    _SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def severity_threshold_index(self) -> int:
        try:
            return self._SEVERITY_ORDER.index(self.min_severity.upper())
        except ValueError:
            return 0


def _build_message(result: ScanResult) -> str:
    """Build a plain-text summary of scan issues."""
    lines = [f"depthwatch alert for scan result"]
    drifted = result.drifted_packages()
    if drifted:
        lines.append(f"\nDrifted packages ({len(drifted)}):")
        for pkg in drifted:
            lines.append(f"  - {pkg.name}: required {pkg.required_version}, installed {pkg.installed_version}")
    vuln = result.vulnerable_packages()
    if vuln:
        lines.append(f"\nVulnerable packages ({len(vuln)}):")
        for name in vuln:
            lines.append(f"  - {name}")
    return "\n".join(lines)


def notify_email(config: NotifyConfig, result: ScanResult, smtp_host: str = "localhost", smtp_port: int = 25) -> None:
    """Send a scan-result notification via SMTP."""
    msg = EmailMessage()
    msg["Subject"] = "depthwatch: dependency issues detected"
    msg["From"] = config.extra.get("from", "depthwatch@localhost")
    msg["To"] = config.target
    msg.set_content(_build_message(result))
    with smtplib.SMTP(smtp_host, smtp_port) as smtp:
        smtp.send_message(msg)


def notify_webhook(config: NotifyConfig, result: ScanResult) -> None:
    """POST a JSON payload to a generic webhook URL."""
    payload = {
        "drifted": [p.name for p in result.drifted_packages()],
        "vulnerable": result.vulnerable_packages(),
        "has_issues": result.has_issues(),
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        config.target,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def notify_slack(config: NotifyConfig, result: ScanResult) -> None:
    """Send a Slack message via an incoming webhook URL."""
    text = _build_message(result)
    payload = {"text": text}
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        config.target,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def send_notification(config: NotifyConfig, result: ScanResult, **kwargs) -> None:
    """Dispatch a notification to the configured channel."""
    if not result.has_issues():
        return
    if config.channel == "email":
        notify_email(config, result, **kwargs)
    elif config.channel == "slack":
        notify_slack(config, result)
    elif config.channel == "webhook":
        notify_webhook(config, result)
    else:
        raise ValueError(f"Unknown notification channel: {config.channel!r}")
