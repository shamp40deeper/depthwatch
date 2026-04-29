"""Load and validate notification configuration from TOML/dict sources."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import List

from depthwatch.notify import NotifyConfig

_VALID_CHANNELS = {"email", "slack", "webhook"}
_VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_DEFAULT_CONFIG_PATH = Path(".depthwatch") / "notify.toml"


class NotifyConfigError(ValueError):
    """Raised when a notification config entry is invalid."""


def _validate_entry(entry: dict, index: int) -> None:
    channel = entry.get("channel", "")
    if channel not in _VALID_CHANNELS:
        raise NotifyConfigError(
            f"notify[{index}]: 'channel' must be one of {sorted(_VALID_CHANNELS)}, got {channel!r}"
        )
    if not entry.get("target"):
        raise NotifyConfigError(f"notify[{index}]: 'target' is required")
    severity = entry.get("min_severity", "LOW").upper()
    if severity not in _VALID_SEVERITIES:
        raise NotifyConfigError(
            f"notify[{index}]: 'min_severity' must be one of {sorted(_VALID_SEVERITIES)}, got {severity!r}"
        )


def load_notify_configs(path: Path | None = None) -> List[NotifyConfig]:
    """Load notification configs from a TOML file.

    The file should contain a top-level ``[[notify]]`` array, e.g.::

        [[notify]]
        channel = "slack"
        target = "https://hooks.slack.com/..."
        min_severity = "HIGH"
    """
    resolved = path or _DEFAULT_CONFIG_PATH
    if not resolved.exists():
        return []
    with open(resolved, "rb") as fh:
        data = tomllib.load(fh)
    entries = data.get("notify", [])
    configs: List[NotifyConfig] = []
    for i, entry in enumerate(entries):
        _validate_entry(entry, i)
        configs.append(
            NotifyConfig(
                channel=entry["channel"],
                target=entry["target"],
                min_severity=entry.get("min_severity", "LOW").upper(),
                extra={k: v for k, v in entry.items() if k not in {"channel", "target", "min_severity"}},
            )
        )
    return configs


def configs_from_dict(data: dict) -> List[NotifyConfig]:
    """Build NotifyConfig objects from a plain dict (useful for programmatic use)."""
    entries = data.get("notify", [])
    configs: List[NotifyConfig] = []
    for i, entry in enumerate(entries):
        _validate_entry(entry, i)
        configs.append(
            NotifyConfig(
                channel=entry["channel"],
                target=entry["target"],
                min_severity=entry.get("min_severity", "LOW").upper(),
                extra={k: v for k, v in entry.items() if k not in {"channel", "target", "min_severity"}},
            )
        )
    return configs
