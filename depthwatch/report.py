"""Report formatting utilities for depthwatch advisory results."""

from __future__ import annotations

from typing import Dict, List

from depthwatch.advisories import Advisory


def format_advisory_report(
    results: Dict[str, List[Advisory]], show_clean: bool = False
) -> str:
    """Format advisory scan results into a human-readable report.

    Args:
        results: Mapping of "package==version" to list of advisories.
        show_clean: If True, include packages with no advisories.

    Returns:
        A formatted string report.
    """
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append(" DepthWatch — Security Advisory Report")
    lines.append("=" * 60)

    vulnerable_count = 0
    for pkg_key, advisories in sorted(results.items()):
        if advisories:
            vulnerable_count += 1
            lines.append(f"\n[VULNERABLE] {pkg_key}")
            for adv in advisories:
                lines.append(f"  • {adv}")
                if adv.aliases:
                    lines.append(f"    Aliases: {', '.join(adv.aliases)}")
        elif show_clean:
            lines.append(f"\n[OK]         {pkg_key}")

    lines.append("\n" + "-" * 60)
    total = len(results)
    lines.append(
        f"Scanned {total} package(s). "
        f"{vulnerable_count} vulnerable, {total - vulnerable_count} clean."
    )
    lines.append("=" * 60)
    return "\n".join(lines)


def format_json_report(results: Dict[str, List[Advisory]]) -> str:
    """Format advisory scan results as a JSON string.

    Args:
        results: Mapping of "package==version" to list of advisories.

    Returns:
        A JSON-encoded string.
    """
    import json

    output = {}
    for pkg_key, advisories in results.items():
        output[pkg_key] = [
            {
                "id": adv.advisory_id,
                "summary": adv.summary,
                "severity": adv.severity,
                "aliases": adv.aliases,
            }
            for adv in advisories
        ]
    return json.dumps(output, indent=2)
