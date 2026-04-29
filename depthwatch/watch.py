"""Continuous watch mode: poll for changes on a fixed interval."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Optional

from depthwatch.scanner import ScanResult


class WatchConfig:
    """Configuration for watch-mode polling."""

    def __init__(
        self,
        interval: int = 60,
        max_iterations: Optional[int] = None,
    ) -> None:
        if interval < 1:
            raise ValueError("interval must be >= 1 second")
        self.interval = interval
        self.max_iterations = max_iterations


def watch(
    scan_fn: Callable[[], ScanResult],
    on_change: Callable[[ScanResult, ScanResult], None],
    config: Optional[WatchConfig] = None,
    *,
    _sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Poll *scan_fn* repeatedly; call *on_change* when the result differs.

    Parameters
    ----------
    scan_fn:
        Zero-argument callable that returns a fresh :class:`ScanResult`.
    on_change:
        Called with ``(previous_result, current_result)`` whenever the set of
        drifted or vulnerable packages changes between iterations.
    config:
        Polling configuration.  Defaults to :class:`WatchConfig` defaults.
    _sleep:
        Injection point for tests; defaults to :func:`time.sleep`.
    """
    cfg = config or WatchConfig()
    previous: Optional[ScanResult] = None
    iterations = 0

    while True:
        current = scan_fn()
        if previous is not None and _result_changed(previous, current):
            on_change(previous, current)
        previous = current
        iterations += 1
        if cfg.max_iterations is not None and iterations >= cfg.max_iterations:
            break
        _sleep(cfg.interval)


def _result_changed(prev: ScanResult, curr: ScanResult) -> bool:
    """Return True if drifted or vulnerable package sets differ."""
    return (
        set(prev.drifted_packages()) != set(curr.drifted_packages())
        or set(prev.vulnerable_packages()) != set(curr.vulnerable_packages())
    )
