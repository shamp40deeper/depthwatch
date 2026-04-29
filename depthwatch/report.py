"""Reporting helpers for depthwatch scan results and baseline diffs."""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from depthwatch.scanner import ScanResult


def format_advisory_report(result: ScanResult, show_clean: bool = False) -> str:
    lines: List[str] = []
    for pkg in result.packages:
        advisories = pkg.advisories
        if not advisories and not show_clean:
            continue
        status = "VULNERABLE" if advisories else "OK"
        lines.append(f"  [{status}] {pkg.name} {pkg.installed_version or '?'}")
        for adv in advisories:
            lines.append(f"      - {adv}")
    if not lines:
        return "No issues found.\n"
    return "\n".join(lines) + "\n"


def format_json_report(result: ScanResult) -> str:
    data = [
        {
            "name": pkg.name,
            "required": pkg.required_version,
            "installed": pkg.installed_version,
            "drift": pkg.installed_version != pkg.required_version,
            "advisories": [str(a) for a in pkg.advisories],
        }
        for pkg in result.packages
    ]
    return json.dumps(data, indent=2)


def format_baseline_diff(
    changes: Dict[str, Dict[str, Optional[str]]],
    label: str = "Baseline diff",
) -> str:
    """Render a human-readable summary of baseline vs current differences."""
    if not changes:
        return f"{label}: no changes detected.\n"

    lines: List[str] = [f"{label}: {len(changes)} change(s) detected"]
    for name, versions in sorted(changes.items()):
        b = versions["baseline"]
        c = versions["current"]
        if b is None:
            lines.append(f"  [ADDED]   {name} -> {c}")
        elif c is None:
            lines.append(f"  [REMOVED] {name} (was {b})")
        else:
            lines.append(f"  [CHANGED] {name}: {b} -> {c}")
    return "\n".join(lines) + "\n"
