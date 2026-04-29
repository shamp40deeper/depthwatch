"""Simple file-based cache for advisory and resolver results."""

import json
import hashlib
import time
from pathlib import Path
from typing import Any, Optional

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "depthwatch"
DEFAULT_TTL_SECONDS = 3600  # 1 hour


def _cache_key(namespace: str, identifier: str) -> str:
    """Return a filesystem-safe cache key."""
    digest = hashlib.sha256(identifier.encode()).hexdigest()[:16]
    return f"{namespace}_{digest}.json"


def get(
    namespace: str,
    identifier: str,
    ttl: int = DEFAULT_TTL_SECONDS,
    cache_dir: Path = DEFAULT_CACHE_DIR,
) -> Optional[Any]:
    """Return cached value if present and not expired, else None."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / _cache_key(namespace, identifier)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        if time.time() - data["timestamp"] > ttl:
            path.unlink(missing_ok=True)
            return None
        return data["value"]
    except (KeyError, json.JSONDecodeError):
        path.unlink(missing_ok=True)
        return None


def set(
    namespace: str,
    identifier: str,
    value: Any,
    cache_dir: Path = DEFAULT_CACHE_DIR,
) -> None:
    """Persist a value to the cache."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / _cache_key(namespace, identifier)
    payload = {"timestamp": time.time(), "value": value}
    path.write_text(json.dumps(payload))


def invalidate(
    namespace: str,
    identifier: str,
    cache_dir: Path = DEFAULT_CACHE_DIR,
) -> bool:
    """Remove a single cache entry. Returns True if it existed."""
    path = cache_dir / _cache_key(namespace, identifier)
    if path.exists():
        path.unlink()
        return True
    return False


def clear(namespace: Optional[str] = None, cache_dir: Path = DEFAULT_CACHE_DIR) -> int:
    """Delete all cache entries, optionally filtered by namespace. Returns count."""
    if not cache_dir.exists():
        return 0
    pattern = f"{namespace}_*.json" if namespace else "*.json"
    removed = 0
    for entry in cache_dir.glob(pattern):
        entry.unlink()
        removed += 1
    return removed
