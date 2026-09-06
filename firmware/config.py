"""Configuration loading and validation for X8 NIDS.

Reads a YAML configuration file (``config/nids.yaml`` by default). YAML is
parsed with an optional import; when PyYAML is unavailable a minimal built-in
fallback parser is used so the tool remains fully offline-testable without
external dependencies.
"""

from __future__ import annotations

import os
from copy import deepcopy
from typing import Any, Dict

try:  # pragma: no cover - depends on environment
    import yaml

    _HAVE_YAML = True
except Exception:  # pragma: no cover
    yaml = None
    _HAVE_YAML = False


class ConfigError(Exception):
    """Raised when configuration is missing or invalid."""


# ---------------------------------------------------------------------------
# Schema / reasonable defaults
# ---------------------------------------------------------------------------
CONFIG_KEY = (
    "iface",
    "thresholds",
    "alert",
    "logging",
    "flows",
    "lab",
)


def default_config() -> Dict[str, Any]:
    """Return the default configuration dict (matches config/nids.yaml)."""
    return {
        "iface": "any",
        "thresholds": {
            "scan": {
                "max_ports_per_source": 30,
                "window_seconds": 10.0,
            },
            "brute": {
                "max_auth_failures": 5,
                "window_seconds": 60.0,
                "auth_ports": [22, 21, 23, 3389, 5900, 1433, 3306],
            },
            "c2_beacon": {
                "min_beacons": 5,
                "max_jitter_ratio": 0.20,
                "window_seconds": 300.0,
                "min_interval_seconds": 1.0,
            },
            "exfil": {
                "min_bytes": 1_000_000,
                "min_duration_seconds": 30.0,
            },
        },
        "alert": {
            "stream_path": "logs/alerts.jsonl",
            "api_host": "127.0.0.1",
            "api_port": 8488,
            "api_enabled": True,
        },
        "logging": {
            "level": "INFO",
            "file_path": "logs/nids.log",
        },
        "flows": {
            "snapshot_path": "flows/flows.jsonl",
            "max_snapshot_lines": 10000,
        },
        "lab": {
            "home_ranges": [
                "192.0.2.0/24",
                "198.51.100.0/24",
                "203.0.113.0/24",
            ],
            "note": (
                "Documentation-only lab placeholders. Replace these RFC-5737 "
                "TEST-NET ranges with your own authorized lab ranges before "
                "going live. Never monitor networks you do not own."
            ),
        },
    }


def _simple_yaml_load(text: str) -> Dict[str, Any]:
    """Minimal fallback YAML-subset parser (no external deps).

    Supports nested maps via indentation, scalar values (int, float, bool,
    null, strings), inline ``[a, b]`` lists, and block-style lists (``- item``).
    Used only when PyYAML is absent.
    """
    tokens: list = []
    for raw_line in text.splitlines():
        line = raw_line.split(" #", 1)[0].rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        tokens.append((indent, line.strip()))
    if not tokens:
        return {}
    node, _ = _assemble(tokens, 0, 0)
    if isinstance(node, dict):
        return node
    raise ConfigError("config root must be a mapping")


def _assemble(tokens, index: int, indent: int):
    """Recursively build a node from the token list starting at ``index``.

    Returns ``(node, next_index)``.
    """
    if index >= len(tokens):
        return None, index
    token_indent, token = tokens[index]

    # Block list: a sequence of "- item" lines.
    if token.startswith("-"):
        items = []
        while index < len(tokens) and tokens[index][0] == indent and tokens[index][1].startswith("-"):
            items.append(_parse_scalar(tokens[index][1][1:].strip()))
            index += 1
        return items, index

    node: Dict[str, Any] = {}
    while index < len(tokens):
        cur_indent, cur = tokens[index]
        if cur_indent < indent:
            break
        if cur_indent > indent:
            # Deeper indentation belongs to the previous key's value.
            break
        if cur.startswith("-"):
            break
        key_part, sep, value_part = cur.partition(":")
        if not sep:
            raise ConfigError(f"invalid YAML line: {cur!r}")
        key = key_part.strip().strip('"').strip("'")
        value_part = value_part.strip()
        index += 1
        if value_part == "":
            if index < len(tokens) and tokens[index][0] > indent:
                child, index = _assemble(tokens, index, tokens[index][0])
            else:
                child = None
            node[key] = child
        else:
            node[key] = _parse_scalar(value_part)
    return node, index


def _parse_scalar(value: str) -> Any:
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(item.strip()) for item in inner.split(",")]
    lowered = value.lower()
    if lowered in ("null", "~", "none"):
        return None
    if lowered in ("true", "yes"):
        return True
    if lowered in ("false", "no"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value.strip('"')


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = deepcopy(value)
    return out


def load_config(path: str | None = None) -> Dict[str, Any]:
    """Load config from ``path`` (else env ``X8_CONFIG``, else config/nids.yaml).

    Missing optional fields are filled with defaults. Raises :class:`ConfigError`
    if a required top-level key is absent and no default exists.
    """
    cfg = default_config()

    if path is None:
        path = os.environ.get("X8_CONFIG", "config/nids.yaml")

    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        if _HAVE_YAML:
            parsed = yaml.safe_load(text) or {}
        else:
            parsed = _simple_yaml_load(text)
        if not isinstance(parsed, dict):
            raise ConfigError(f"config root must be a mapping, got {type(parsed).__name__}")
        cfg = _deep_merge(cfg, parsed)
    elif os.environ.get("X8_CONFIG") or path != "config/nids.yaml":
        raise ConfigError(f"config file not found: {path}")

    validate_config(cfg)
    return cfg


def validate_config(cfg: Dict[str, Any]) -> None:
    """Validate threshold and config types; raise ConfigError on problems."""
    # Lab ranges must be documentation placeholders, never real networks.
    for cidr in cfg.get("lab", {}).get("home_ranges", []):
        if not isinstance(cidr, str) or "/" not in cidr:
            raise ConfigError(f"invalid lab range: {cidr!r}")
    # Expand relative output paths relative to project root.
    for section, keys in (
        ("alert", ("stream_path",)),
        ("logging", ("file_path",)),
        ("flows", ("snapshot_path",)),
    ):
        for key in keys:
            val = cfg.get(section, {}).get(key, "")
            if val and not os.path.isabs(val):
                cfg[section][key] = os.path.join(_project_root(), val)

    th = cfg.get("thresholds", {})
    for mod in ("scan", "brute", "c2_beacon", "exfil"):
        if mod not in th:
            raise ConfigError(f"missing thresholds.{mod}")

    def require_positive(mod: str, key: str) -> None:
        val = th[mod].get(key)
        if val is None or not isinstance(val, (int, float)) or val <= 0:
            raise ConfigError(f"thresholds.{mod}.{key} must be a positive number")

    require_positive("scan", "max_ports_per_source")
    require_positive("scan", "window_seconds")
    require_positive("brute", "max_auth_failures")
    require_positive("brute", "window_seconds")
    require_positive("c2_beacon", "min_beacons")
    require_positive("exfil", "min_bytes")

    req_type = cfg.get("alert", {}).get("api_enabled")
    if not isinstance(req_type, bool):
        raise ConfigError("alert.api_enabled must be a boolean")


def _project_root() -> str:
    """Project root (two levels up from this module's package parent)."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(here)
