"""Snapshot management for dependency state across time."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_SNAPSHOT_DIR = ".depthwatch/snapshots"


def _snapshot_dir(base: Optional[str] = None) -> Path:
    return Path(base or DEFAULT_SNAPSHOT_DIR)


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def save_snapshot(
    packages: list[dict],
    label: Optional[str] = None,
    base: Optional[str] = None,
) -> Path:
    """Persist a dependency snapshot to disk. Returns the snapshot path."""
    snap_dir = _snapshot_dir(base)
    snap_dir.mkdir(parents=True, exist_ok=True)

    ts = _timestamp()
    name = f"{label}-{ts}.json" if label else f"{ts}.json"
    path = snap_dir / name

    payload = {
        "created_at": ts,
        "label": label,
        "packages": packages,
    }
    path.write_text(json.dumps(payload, indent=2))
    return path


def list_snapshots(base: Optional[str] = None) -> list[Path]:
    """Return all snapshot paths sorted by creation time (oldest first)."""
    snap_dir = _snapshot_dir(base)
    if not snap_dir.exists():
        return []
    return sorted(snap_dir.glob("*.json"))


def load_snapshot(path: Path) -> Optional[dict]:
    """Load a snapshot from *path*. Returns None if file is missing."""
    if not path.exists():
        return None
    return json.loads(path.read_text())


def diff_snapshots(old: dict, new: dict) -> dict:
    """Compare two snapshots and return added, removed, and changed packages."""
    old_pkgs = {p["name"]: p["version"] for p in old.get("packages", [])}
    new_pkgs = {p["name"]: p["version"] for p in new.get("packages", [])}

    added = [
        {"name": n, "version": v}
        for n, v in new_pkgs.items()
        if n not in old_pkgs
    ]
    removed = [
        {"name": n, "version": v}
        for n, v in old_pkgs.items()
        if n not in new_pkgs
    ]
    changed = [
        {"name": n, "old_version": old_pkgs[n], "new_version": new_pkgs[n]}
        for n in new_pkgs
        if n in old_pkgs and old_pkgs[n] != new_pkgs[n]
    ]

    return {"added": added, "removed": removed, "changed": changed}


def delete_snapshot(path: Path) -> bool:
    """Delete a snapshot file. Returns True if deleted, False if not found."""
    if path.exists():
        os.remove(path)
        return True
    return False
