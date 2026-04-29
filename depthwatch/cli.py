"""CLI entry point for depthwatch."""

import argparse
import sys
from pathlib import Path

from depthwatch.scanner import scan_requirements
from depthwatch.report import format_advisory_report, format_json_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="depthwatch",
        description="Monitor Python dependency trees for version drift and security advisories.",
    )
    parser.add_argument(
        "requirements",
        type=Path,
        nargs="?",
        default=Path("requirements.txt"),
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
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        default=False,
        help="Always exit with code 0 even when issues are found.",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    req_path: Path = args.requirements
    if not req_path.exists():
        print(f"error: requirements file not found: {req_path}", file=sys.stderr)
        return 1

    results = scan_requirements(req_path)

    if args.json:
        print(format_json_report(results, show_clean=args.show_clean))
    else:
        print(format_advisory_report(results, show_clean=args.show_clean))

    has_issues = any(r.has_issues for r in results)
    if has_issues and not args.exit_zero:
        return 2
    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
