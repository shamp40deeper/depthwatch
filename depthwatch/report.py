"""Formatting helpers for depthwatch scan and snapshot reports."""

from __future__ import annotations

import json
from typing import Optional

from depthwatch.scanner import ScanResult


def format_advisory_report(result: ScanResult, show_clean: bool = False) -> str:
    lines: list[str] = []
    for pkg in result.packages:
        if pkg.advisories:
            lines.append(f"[VULNERABLE] {pkg.name}=={pkg.installed_version}")
            for adv in pkg.advisories:
                lines.append(f"  - {adv}")
        elif show_clean:
            lines.append(f"[OK]         {pkg.name}=={pkg.installed_version}")
    return "\n".join(lines) if lines else "No issues found."


def format_json_report(result: ScanResult) -> str:
    data = [
        {
            "name": pkg.name,
            "required": pkg.required_version,
            "installed": pkg.installed_version,
            "drift": pkg.drift,
            "advisories": [str(a) for a in pkg.advisories],
        }
        for pkg in result.packages
    ]
    return json.dumps(data, indent=2)


def format_baseline_diff(diff: dict) -> str:
    lines: list[str] = []
    for name, (old, new) in diff.items():
        if old is None:
            lines.append(f"[ADDED]   {name}=={new}")
        elif new is None:
            lines.append(f"[REMOVED] {name}=={old}")
        else:
            lines.append(f"[CHANGED] {name}: {old} -> {new}")
    return "\n".join(lines) if lines else "No changes from baseline."


def format_snapshot_diff(diff: dict, old_label: Optional[str] = None, new_label: Optional[str] = None) -> str:
    """Render a human-readable diff between two snapshots."""
    header = "Snapshot diff"
    if old_label or new_label:
        header += f" ({old_label or '?'} -> {new_label or '?'})"

    lines: list[str] = [header, "-" * len(header)]

    for pkg in diff.get("added", []):
        lines.append(f"[ADDED]   {pkg['name']}=={pkg['version']}")
    for pkg in diff.get("removed", []):
        lines.append(f"[REMOVED] {pkg['name']}=={pkg['version']}")
    for pkg in diff.get("changed", []):
        lines.append(f"[CHANGED] {pkg['name']}: {pkg['old_version']} -> {pkg['new_version']}")

    if len(lines) == 2:
        lines.append("No differences between snapshots.")

    return "\n".join(lines)
