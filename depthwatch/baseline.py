"""Baseline snapshot management for dependency drift tracking."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

DEFAULT_BASELINE_DIR = Path(".depthwatch")
BASELINE_FILENAME = "baseline.json"


def _baseline_path(directory: Path = DEFAULT_BASELINE_DIR) -> Path:
    return directory / BASELINE_FILENAME


def save_baseline(
    packages: Dict[str, str],
    directory: Path = DEFAULT_BASELINE_DIR,
) -> Path:
    """Persist a snapshot of {package: version} pairs to disk."""
    directory.mkdir(parents=True, exist_ok=True)
    path = _baseline_path(directory)
    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "packages": packages,
    }
    path.write_text(json.dumps(payload, indent=2))
    return path


def load_baseline(
    directory: Path = DEFAULT_BASELINE_DIR,
) -> Optional[Dict[str, str]]:
    """Load a previously saved baseline. Returns None if none exists."""
    path = _baseline_path(directory)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return data.get("packages", {})
    except (json.JSONDecodeError, KeyError):
        return None


def diff_baseline(
    baseline: Dict[str, str],
    current: Dict[str, str],
) -> Dict[str, Dict[str, Optional[str]]]:
    """Compare baseline to current versions.

    Returns a dict of changed packages with 'baseline' and 'current' versions.
    Includes added and removed packages.
    """
    changes: Dict[str, Dict[str, Optional[str]]] = {}
    all_keys = set(baseline) | set(current)
    for name in all_keys:
        b_ver = baseline.get(name)
        c_ver = current.get(name)
        if b_ver != c_ver:
            changes[name] = {"baseline": b_ver, "current": c_ver}
    return changes


def delete_baseline(directory: Path = DEFAULT_BASELINE_DIR) -> bool:
    """Remove an existing baseline file. Returns True if deleted."""
    path = _baseline_path(directory)
    if path.exists():
        path.unlink()
        return True
    return False
