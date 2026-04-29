"""Export scan results to various output formats (JSON, CSV, Markdown)."""

from __future__ import annotations

import csv
import io
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from depthwatch.scanner import ScanResult


def export_json(result: "ScanResult", indent: int = 2) -> str:
    """Serialize a ScanResult to a JSON string."""
    data = {
        "packages": [
            {
                "name": pkg.name,
                "required_version": pkg.required_version,
                "installed_version": pkg.installed_version,
                "drifted": pkg.has_drift(),
                "advisories": [
                    {
                        "id": adv.id,
                        "summary": adv.summary,
                        "severity": adv.severity,
                    }
                    for adv in (pkg.advisories or [])
                ],
            }
            for pkg in result.packages
        ],
        "drifted_count": len(result.drifted_packages()),
        "vulnerable_count": len(result.vulnerable_packages()),
    }
    return json.dumps(data, indent=indent)


def export_csv(result: "ScanResult") -> str:
    """Serialize a ScanResult to a CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["name", "required_version", "installed_version", "drifted", "advisory_ids"])
    for pkg in result.packages:
        advisory_ids = "|".join(adv.id for adv in (pkg.advisories or []))
        writer.writerow([
            pkg.name,
            pkg.required_version or "",
            pkg.installed_version or "",
            str(pkg.has_drift()),
            advisory_ids,
        ])
    return output.getvalue()


def export_markdown(result: "ScanResult") -> str:
    """Serialize a ScanResult to a Markdown table string."""
    lines: list[str] = []
    lines.append("# DepthWatch Scan Report\n")
    lines.append("| Package | Required | Installed | Drifted | Advisories |")
    lines.append("|---------|----------|-----------|---------|------------|")
    for pkg in result.packages:
        advisory_ids = ", ".join(adv.id for adv in (pkg.advisories or []))
        drifted = "⚠️" if pkg.has_drift() else "✅"
        lines.append(
            f"| {pkg.name} "
            f"| {pkg.required_version or '-'} "
            f"| {pkg.installed_version or '-'} "
            f"| {drifted} "
            f"| {advisory_ids or 'none'} |"
        )
    lines.append("")
    lines.append(f"**Drifted packages:** {len(result.drifted_packages())}  ")
    lines.append(f"**Vulnerable packages:** {len(result.vulnerable_packages())}")
    return "\n".join(lines)
