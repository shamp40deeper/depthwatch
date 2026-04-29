"""Tests for depthwatch.snapshot."""

import json
import pytest
from pathlib import Path

from depthwatch.snapshot import (
    save_snapshot,
    list_snapshots,
    load_snapshot,
    diff_snapshots,
    delete_snapshot,
)


@pytest.fixture
def snap_dir(tmp_path):
    return str(tmp_path / "snapshots")


PKGS = [{"name": "requests", "version": "2.31.0"}, {"name": "flask", "version": "3.0.0"}]


def test_save_snapshot_creates_file(snap_dir):
    path = save_snapshot(PKGS, base=snap_dir)
    assert path.exists()


def test_save_snapshot_content(snap_dir):
    path = save_snapshot(PKGS, label="ci", base=snap_dir)
    data = json.loads(path.read_text())
    assert data["label"] == "ci"
    assert len(data["packages"]) == 2
    assert data["created_at"] is not None


def test_save_snapshot_filename_includes_label(snap_dir):
    path = save_snapshot(PKGS, label="prod", base=snap_dir)
    assert "prod" in path.name


def test_list_snapshots_empty_when_no_dir(tmp_path):
    result = list_snapshots(base=str(tmp_path / "nonexistent"))
    assert result == []


def test_list_snapshots_returns_sorted_paths(snap_dir):
    p1 = save_snapshot(PKGS, label="a", base=snap_dir)
    p2 = save_snapshot(PKGS, label="b", base=snap_dir)
    paths = list_snapshots(base=snap_dir)
    assert len(paths) == 2
    assert paths[0] <= paths[1]


def test_load_snapshot_returns_data(snap_dir):
    path = save_snapshot(PKGS, base=snap_dir)
    data = load_snapshot(path)
    assert data is not None
    assert "packages" in data


def test_load_snapshot_returns_none_when_missing(tmp_path):
    result = load_snapshot(tmp_path / "ghost.json")
    assert result is None


def test_diff_snapshots_detects_added():
    old = {"packages": [{"name": "requests", "version": "2.28.0"}]}
    new = {"packages": [{"name": "requests", "version": "2.28.0"}, {"name": "flask", "version": "3.0.0"}]}
    diff = diff_snapshots(old, new)
    assert any(p["name"] == "flask" for p in diff["added"])
    assert diff["removed"] == []
    assert diff["changed"] == []


def test_diff_snapshots_detects_removed():
    old = {"packages": [{"name": "requests", "version": "2.28.0"}, {"name": "flask", "version": "3.0.0"}]}
    new = {"packages": [{"name": "requests", "version": "2.28.0"}]}
    diff = diff_snapshots(old, new)
    assert any(p["name"] == "flask" for p in diff["removed"])


def test_diff_snapshots_detects_changed():
    old = {"packages": [{"name": "requests", "version": "2.28.0"}]}
    new = {"packages": [{"name": "requests", "version": "2.31.0"}]}
    diff = diff_snapshots(old, new)
    assert diff["changed"][0]["old_version"] == "2.28.0"
    assert diff["changed"][0]["new_version"] == "2.31.0"


def test_delete_snapshot_removes_file(snap_dir):
    path = save_snapshot(PKGS, base=snap_dir)
    assert delete_snapshot(path) is True
    assert not path.exists()


def test_delete_snapshot_returns_false_when_missing(tmp_path):
    assert delete_snapshot(tmp_path / "nope.json") is False
