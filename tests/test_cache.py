"""Tests for depthwatch.cache module."""

import json
import time
from pathlib import Path

import pytest

import depthwatch.cache as cache


@pytest.fixture()
def tmp_cache(tmp_path):
    """Return a temporary cache directory."""
    return tmp_path / "cache"


def test_set_and_get_returns_value(tmp_cache):
    cache.set("advisory", "requests==2.28.0", ["CVE-1234"], cache_dir=tmp_cache)
    result = cache.get("advisory", "requests==2.28.0", cache_dir=tmp_cache)
    assert result == ["CVE-1234"]


def test_get_returns_none_when_missing(tmp_cache):
    result = cache.get("advisory", "nonexistent", cache_dir=tmp_cache)
    assert result is None


def test_get_returns_none_after_ttl_expired(tmp_cache):
    cache.set("advisory", "flask==2.0", {"data": 1}, cache_dir=tmp_cache)
    result = cache.get("advisory", "flask==2.0", ttl=0, cache_dir=tmp_cache)
    assert result is None


def test_get_removes_stale_file(tmp_cache):
    cache.set("advisory", "stale_pkg", "value", cache_dir=tmp_cache)
    cache.get("advisory", "stale_pkg", ttl=0, cache_dir=tmp_cache)
    key = cache._cache_key("advisory", "stale_pkg")
    assert not (tmp_cache / key).exists()


def test_invalidate_existing_entry(tmp_cache):
    cache.set("resolver", "numpy==1.24", ["dep1"], cache_dir=tmp_cache)
    removed = cache.invalidate("resolver", "numpy==1.24", cache_dir=tmp_cache)
    assert removed is True
    assert cache.get("resolver", "numpy==1.24", cache_dir=tmp_cache) is None


def test_invalidate_missing_entry_returns_false(tmp_cache):
    result = cache.invalidate("resolver", "ghost==0.0", cache_dir=tmp_cache)
    assert result is False


def test_clear_all_entries(tmp_cache):
    cache.set("advisory", "pkg_a", 1, cache_dir=tmp_cache)
    cache.set("resolver", "pkg_b", 2, cache_dir=tmp_cache)
    removed = cache.clear(cache_dir=tmp_cache)
    assert removed == 2
    assert list(tmp_cache.glob("*.json")) == []


def test_clear_by_namespace(tmp_cache):
    cache.set("advisory", "pkg_a", 1, cache_dir=tmp_cache)
    cache.set("resolver", "pkg_b", 2, cache_dir=tmp_cache)
    removed = cache.clear(namespace="advisory", cache_dir=tmp_cache)
    assert removed == 1
    assert cache.get("resolver", "pkg_b", cache_dir=tmp_cache) == 2


def test_clear_nonexistent_dir_returns_zero(tmp_path):
    missing = tmp_path / "no_such_dir"
    result = cache.clear(cache_dir=missing)
    assert result == 0


def test_corrupted_cache_file_returns_none(tmp_cache):
    tmp_cache.mkdir(parents=True, exist_ok=True)
    key = cache._cache_key("advisory", "bad_pkg")
    (tmp_cache / key).write_text("not valid json{{")
    result = cache.get("advisory", "bad_pkg", cache_dir=tmp_cache)
    assert result is None
