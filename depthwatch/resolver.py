"""Dependency tree resolver for depthwatch.

Parses requirements files and resolves installed package metadata
to build a flat dependency map with version information.
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class PackageInfo:
    """Holds resolved metadata for a single package."""

    name: str
    required_version: Optional[str]  # version specifier from requirements file
    installed_version: Optional[str]  # version currently installed in the env
    dependencies: list[str] = field(default_factory=list)

    @property
    def is_installed(self) -> bool:
        return self.installed_version is not None

    @property
    def has_drift(self) -> bool:
        """True when the requirement pins an exact version that differs from installed."""
        if not self.required_version or not self.installed_version:
            return False
        if self.required_version.startswith("=="):
            pinned = self.required_version.lstrip("==").strip()
            return pinned != self.installed_version
        return False


def _get_installed_version(package_name: str) -> Optional[str]:
    """Return the installed version of *package_name*, or None if not found."""
    try:
        return importlib_metadata.version(package_name)
    except importlib_metadata.PackageNotFoundError:
        return None


def _get_dependencies(package_name: str) -> list[str]:
    """Return direct dependency names declared by *package_name*."""
    try:
        dist = importlib_metadata.distribution(package_name)
        requires = dist.metadata.get_all("Requires-Dist") or []
        return [r.split()[0].split(";")[0].strip() for r in requires]
    except importlib_metadata.PackageNotFoundError:
        return []


def parse_requirements(requirements_path: Path) -> dict[str, str]:
    """Parse a requirements.txt file into {package_name: version_specifier}."""
    packages: dict[str, str] = {}
    for line in requirements_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        for op in ("==", ">=", "<=", "!=", "~=", ">", "<"):
            if op in line:
                name, specifier = line.split(op, 1)
                packages[name.strip()] = op + specifier.strip()
                break
        else:
            packages[line] = ""
    return packages


def resolve(requirements_path: Path) -> dict[str, PackageInfo]:
    """Resolve a requirements file into a map of package name -> PackageInfo."""
    raw = parse_requirements(requirements_path)
    resolved: dict[str, PackageInfo] = {}
    for name, specifier in raw.items():
        installed = _get_installed_version(name)
        deps = _get_dependencies(name) if installed else []
        resolved[name] = PackageInfo(
            name=name,
            required_version=specifier or None,
            installed_version=installed,
            dependencies=deps,
        )
    return resolved
