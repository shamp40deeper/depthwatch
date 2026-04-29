"""Simple plugin registry for custom advisory fetchers and exporters."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

# Type aliases
AdvisoryFetcher = Callable[[str, str], list[Any]]
Exporter = Callable[[Any], str]

_advisory_fetchers: dict[str, AdvisoryFetcher] = {}
_exporters: dict[str, Exporter] = {}


def register_advisory_fetcher(name: str, fn: AdvisoryFetcher) -> None:
    """Register a custom advisory fetcher under *name*."""
    if not callable(fn):
        raise TypeError(f"Expected callable, got {type(fn)}")
    _advisory_fetchers[name] = fn


def register_exporter(name: str, fn: Exporter) -> None:
    """Register a custom exporter under *name*."""
    if not callable(fn):
        raise TypeError(f"Expected callable, got {type(fn)}")
    _exporters[name] = fn


def get_advisory_fetcher(name: str) -> AdvisoryFetcher:
    """Return the advisory fetcher registered as *name*.

    Raises
    ------
    KeyError
        If no fetcher with that name has been registered.
    """
    if name not in _advisory_fetchers:
        raise KeyError(f"No advisory fetcher registered as '{name}'")
    return _advisory_fetchers[name]


def get_exporter(name: str) -> Exporter:
    """Return the exporter registered as *name*.

    Raises
    ------
    KeyError
        If no exporter with that name has been registered.
    """
    if name not in _exporters:
        raise KeyError(f"No exporter registered as '{name}'")
    return _exporters[name]


def list_advisory_fetchers() -> list[str]:
    """Return sorted names of all registered advisory fetchers."""
    return sorted(_advisory_fetchers)


def list_exporters() -> list[str]:
    """Return sorted names of all registered exporters."""
    return sorted(_exporters)


def clear_all() -> None:
    """Remove all registered plugins (useful in tests)."""
    _advisory_fetchers.clear()
    _exporters.clear()
