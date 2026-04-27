"""Scanner module for scanning project dependency files and aggregating results."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from depthwatch.advisories import Advisory, fetch_advisories
from depthwatch.resolver import PackageInfo, has_drift, resolve_dependencies


@dataclass
class ScanResult:
    """Aggregated result for a single scanned project."""

    project_path: Path
    packages: List[PackageInfo] = field(default_factory=list)
    advisories: dict[str, List[Advisory]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    @property
    def drifted_packages(self) -> List[PackageInfo]:
        """Return packages whose installed version differs from the required version."""
        return [p for p in self.packages if has_drift(p)]

    @property
    def vulnerable_packages(self) -> List[str]:
        """Return package names that have at least one advisory."""
        return [name for name, advs in self.advisories.items() if advs]

    @property
    def has_issues(self) -> bool:
        """Return True if any drift or vulnerabilities were detected."""
        return bool(self.drifted_packages or self.vulnerable_packages)


def _parse_requirements(requirements_path: Path) -> List[str]:
    """Parse a requirements.txt file and return a list of package specifiers."""
    packages: List[str] = []
    for line in requirements_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("-"):
            packages.append(line)
    return packages


def _find_requirements_file(project_path: Path) -> Optional[Path]:
    """Locate a requirements file within the given project directory."""
    candidates = ["requirements.txt", "requirements/base.txt", "requirements/prod.txt"]
    for candidate in candidates:
        req_file = project_path / candidate
        if req_file.exists():
            return req_file
    return None


async def scan_project(project_path: Path, include_advisories: bool = True) -> ScanResult:
    """Scan a single project directory for dependency drift and security advisories."""
    result = ScanResult(project_path=project_path)

    req_file = _find_requirements_file(project_path)
    if req_file is None:
        result.errors.append(f"No requirements file found in {project_path}")
        return result

    try:
        specifiers = _parse_requirements(req_file)
    except OSError as exc:
        result.errors.append(f"Failed to read {req_file}: {exc}")
        return result

    result.packages = resolve_dependencies(specifiers)

    if include_advisories and result.packages:
        tasks = {pkg.name: fetch_advisories(pkg.name, pkg.installed_version) for pkg in result.packages if pkg.installed_version}
        advisory_results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for pkg_name, adv_result in zip(tasks.keys(), advisory_results):
            if isinstance(adv_result, Exception):
                result.errors.append(f"Advisory fetch failed for {pkg_name}: {adv_result}")
            else:
                result.advisories[pkg_name] = adv_result  # type: ignore[assignment]

    return result


async def scan_multiple(project_paths: List[Path], include_advisories: bool = True) -> List[ScanResult]:
    """Scan multiple projects concurrently and return their results."""
    return await asyncio.gather(*(scan_project(p, include_advisories) for p in project_paths))
