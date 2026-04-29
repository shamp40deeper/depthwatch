"""CLI entry point for depthwatch."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from depthwatch.baseline import (
    delete_baseline,
    diff_baseline,
    load_baseline,
    save_baseline,
)
from depthwatch.report import format_advisory_report, format_baseline_diff, format_json_report

DEFAULT_REQUIREMENTS = "requirements.txt"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="depthwatch",
        description="Monitor Python dependency trees for version drift and advisories.",
    )
    parser.add_argument(
        "-r", "--requirements",
        default=DEFAULT_REQUIREMENTS,
        help="Path to requirements file (default: requirements.txt)",
    )
    parser.add_argument(
        "--show-clean",
        action="store_true",
        default=False,
        help="Include packages with no issues in the report.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output report as JSON.",
    )

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("baseline", help="Save current versions as baseline.")
    sub.add_parser("diff", help="Compare current versions against saved baseline.")
    sub.add_parser("clear-baseline", help="Delete the saved baseline.")

    return parser


def run(args: argparse.Namespace) -> int:
    from depthwatch.scanner import scan  # local import to keep startup fast

    req_path = Path(args.requirements)
    if not req_path.exists():
        print(f"Error: requirements file not found: {req_path}", file=sys.stderr)
        return 1

    if args.command == "baseline":
        result = scan(req_path)
        current = {p.name: p.installed_version for p in result.packages if p.installed_version}
        path = save_baseline(current)
        print(f"Baseline saved to {path}")
        return 0

    if args.command == "diff":
        baseline = load_baseline()
        if baseline is None:
            print("No baseline found. Run `depthwatch baseline` first.", file=sys.stderr)
            return 1
        result = scan(req_path)
        current = {p.name: p.installed_version for p in result.packages if p.installed_version}
        changes = diff_baseline(baseline, current)
        print(format_baseline_diff(changes))
        return 0

    if args.command == "clear-baseline":
        deleted = delete_baseline()
        print("Baseline deleted." if deleted else "No baseline to delete.")
        return 0

    # Default: advisory / drift scan
    result = scan(req_path)
    if getattr(args, "json", False):
        print(format_json_report(result))
    else:
        print(format_advisory_report(result, show_clean=args.show_clean))
    return 1 if result.has_issues else 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(run(args))
