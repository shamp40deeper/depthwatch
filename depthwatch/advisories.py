"""Fetch security advisories from the OSV API with optional caching."""

from __future__ import annotations

import urllib.request
import json
from dataclasses import dataclass, field
from typing import List, Optional

from depthwatch import cache as _cache

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_CACHE_NS = "advisory"
_CACHE_TTL = 3600


@dataclass
class Advisory:
    vuln_id: str
    summary: str
    severity: Optional[str] = None
    aliases: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        severity_tag = f" [{self.severity}]" if self.severity else ""
        return f"{self.vuln_id}{severity_tag}: {self.summary}"


def _build_osv_payload(packages: List[str]) -> dict:
    """Build the OSV querybatch request body."""
    queries = []
    for pkg_spec in packages:
        name, _, version = pkg_spec.partition("==")
        query: dict = {"package": {"name": name.strip(), "ecosystem": "PyPI"}}
        if version:
            query["version"] = version.strip()
        queries.append(query)
    return {"queries": queries}


def _parse_osv_response(packages: List[str], raw: dict) -> dict[str, List[Advisory]]:
    """Parse the OSV batch response into a mapping of package -> advisories."""
    results: dict[str, List[Advisory]] = {}
    for pkg_spec, result in zip(packages, raw.get("results", [])):
        name = pkg_spec.partition("==")[0].strip()
        advisories: List[Advisory] = []
        for vuln in result.get("vulns", []):
            severity = None
            if vuln.get("severity"):
                severity = vuln["severity"][0].get("score")
            advisories.append(
                Advisory(
                    vuln_id=vuln.get("id", "UNKNOWN"),
                    summary=vuln.get("summary", "No summary available."),
                    severity=severity,
                    aliases=vuln.get("aliases", []),
                )
            )
        results[name] = advisories
    return results


def fetch_advisories(
    packages: List[str],
    use_cache: bool = True,
    ttl: int = _CACHE_TTL,
) -> dict[str, List[Advisory]]:
    """Return advisory data for each package, using cache when available."""
    cache_key = "|".join(sorted(packages))
    if use_cache:
        cached = _cache.get(_CACHE_NS, cache_key, ttl=ttl)
        if cached is not None:
            return _parse_osv_response(packages, cached)

    payload = json.dumps(_build_osv_payload(packages)).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        raw = json.loads(resp.read())

    if use_cache:
        _cache.set(_CACHE_NS, cache_key, raw)

    return _parse_osv_response(packages, raw)
