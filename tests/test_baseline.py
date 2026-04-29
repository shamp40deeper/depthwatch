"""Tests for depthwatch.baseline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depthwatch.baseline import (
    delete_baseline,
    diff_baseline,
    load_baseline,
    save_baseline,
)


@pytest.fixture()
def tmp_dir(tmp_path: Path) -> Path:
    return tmp_path / ".depthwatch_test"


def test_save_baseline_creates_file(tmp_dir: Path) -> None:
    packages = {"requests": "2.31.0", "flask": "3.0.0"}
    path = save_baseline(packages, directory=tmp_dir)
    assert path.exists()


def test_save_baseline_content(tmp_dir: Path) -> None:
    packages = {"requests": "2.31.0"}
    path = save_baseline(packages, directory=tmp_dir)
    data = json.loads(path.read_text())
    assert data["packages"] == packages
    assert "created_at" in data


def test_load_baseline_returns_packages(tmp_dir: Path) -> None:
    packages = {"numpy": "1.26.0"}
    save_baseline(packages, directory=tmp_dir)
    loaded = load_baseline(directory=tmp_dir)
    assert loaded == packages


def test_load_baseline_returns_none_when_missing(tmp_dir: Path) -> None:
    result = load_baseline(directory=tmp_dir)
    assert result is None


def test_load_baseline_returns_none_on_corrupt_file(tmp_dir: Path) -> None:
    tmp_dir.mkdir(parents=True, exist_ok=True)
    (tmp_dir / "baseline.json").write_text("not valid json")
    result = load_baseline(directory=tmp_dir)
    assert result is None


def test_diff_baseline_detects_upgrade(tmp_dir: Path) -> None:
    baseline = {"requests": "2.28.0"}
    current = {"requests": "2.31.0"}
    changes = diff_baseline(baseline, current)
    assert "requests" in changes
    assert changes["requests"] == {"baseline": "2.28.0", "current": "2.31.0"}


def test_diff_baseline_detects_added_package() -> None:
    baseline = {"flask": "3.0.0"}
    current = {"flask": "3.0.0", "click": "8.1.0"}
    changes = diff_baseline(baseline, current)
    assert "click" in changes
    assert changes["click"] == {"baseline": None, "current": "8.1.0"}


def test_diff_baseline_detects_removed_package() -> None:
    baseline = {"flask": "3.0.0", "gunicorn": "21.0.0"}
    current = {"flask": "3.0.0"}
    changes = diff_baseline(baseline, current)
    assert "gunicorn" in changes
    assert changes["gunicorn"] == {"baseline": "21.0.0", "current": None}


def test_diff_baseline_empty_when_no_changes() -> None:
    packages = {"requests": "2.31.0"}
    changes = diff_baseline(packages, packages)
    assert changes == {}


def test_delete_baseline_removes_file(tmp_dir: Path) -> None:
    save_baseline({"x": "1.0"}, directory=tmp_dir)
    result = delete_baseline(directory=tmp_dir)
    assert result is True
    assert not (tmp_dir / "baseline.json").exists()


def test_delete_baseline_returns_false_when_missing(tmp_dir: Path) -> None:
    result = delete_baseline(directory=tmp_dir)
    assert result is False
