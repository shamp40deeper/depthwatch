"""Security advisory checker for installed packages."""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import List, Optional

OSV_API_URL = "https://api.osv.dev/v1/query"


@dataclass
class Advisory:
    """Represents a single security advisory."""

    advisory_id: str
    summary: str
    severity: Optional[str] = None
    aliases: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        severity_label = f"[{self.severity}] " if self.severity else ""
        return f"{severity_label}{self.advisory_id}: {self.summary}"


def _build_osv_payload(package_name: str, version: str) -> bytes:
    """Build the JSON payload for an OSV query."""
    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": "PyPI",
        },
    }
    return json.dumps(payload).encode("utf-8")


def _parse_osv_response(data: dict) -> List[Advisory]:
    """Parse the OSV API response into Advisory objects."""
    advisories = []
    for vuln in data.get("vulns", []):
        severity = None
        if vuln.get("severity"):
            severity = vuln["severity"][0].get("type", None)
        advisories.append(
            Advisory(
                advisory_id=vuln.get("id", "UNKNOWN"),
                summary=vuln.get("summary", "No summary available."),
                severity=severity,
                aliases=vuln.get("aliases", []),
            )
        )
    return advisories


def fetch_advisories(
    package_name: str, version: str, timeout: int = 10
) -> List[Advisory]:
    """Fetch security advisories for a package version from OSV.

    Args:
        package_name: The PyPI package name.
        version: The installed version string.
        timeout: HTTP request timeout in seconds.

    Returns:
        A list of Advisory objects (empty if none found or on error).
    """
    payload = _build_osv_payload(package_name, version)
    req = urllib.request.Request(
        OSV_API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
            return _parse_osv_response(data)
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return []
