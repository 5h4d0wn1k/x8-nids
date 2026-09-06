"""Unit tests for configuration loading and validation."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from firmware.config import ConfigError, default_config, load_config, validate_config


class ConfigTest(unittest.TestCase):
    def test_default_config_complete(self):
        cfg = default_config()
        for key in ("iface", "thresholds", "alert", "logging", "flows", "lab"):
            self.assertIn(key, cfg)
        for mod in ("scan", "brute", "c2_beacon", "exfil"):
            self.assertIn(mod, cfg["thresholds"])

    def test_load_missing_default_path(self):
        # A missing explicit config path raises ConfigError (so typos are
        # caught), while defaults still carry required keys.
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError):
                load_config(path=os.path.join(tmp, "does_not_exist.yaml"))

    def test_defaults_when_file_missing_in_cwd(self):
        # When the default config/nids.yaml is absent and no path is given,
        # built-in defaults apply and are valid.
        with tempfile.TemporaryDirectory() as tmp:
            old = os.getcwd()
            os.chdir(tmp)
            try:
                cfg = load_config(path=None)
                self.assertIn("thresholds", cfg)
            finally:
                os.chdir(old)

    def test_invalid_lab_range_raises(self):
        cfg = default_config()
        cfg["lab"]["home_ranges"] = ["10.0.0.1"]  # not a CIDR
        with self.assertRaises(ConfigError):
            validate_config(cfg)

    def test_negative_threshold_raises(self):
        cfg = default_config()
        cfg["thresholds"]["scan"]["max_ports_per_source"] = -5
        with self.assertRaises(ConfigError):
            validate_config(cfg)

    def test_missing_module_raises(self):
        cfg = default_config()
        del cfg["thresholds"]["exfil"]
        with self.assertRaises(ConfigError):
            validate_config(cfg)

    def test_api_enabled_type_check(self):
        cfg = default_config()
        cfg["alert"]["api_enabled"] = "yes"
        with self.assertRaises(ConfigError):
            validate_config(cfg)

    def test_custom_file_merged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nids.yaml"
            path.write_text("thresholds:\n  scan:\n    max_ports_per_source: 77\n")
            # Point config at this file; defaults merged.
            cfg = load_config(path=str(path))
            self.assertEqual(cfg["thresholds"]["scan"]["max_ports_per_source"], 77)
            self.assertIn("brute", cfg["thresholds"])


class FallbackYamlTest(unittest.TestCase):
    """The no-dependency YAML fallback must parse block lists + nesting."""

    def test_block_list_and_nesting(self):
        from firmware.config import _simple_yaml_load

        text = (
            "iface: any\n"
            "thresholds:\n"
            "  brute:\n"
            "    auth_ports:\n"
            "      - 22\n"
            "      - 3389\n"
            "    max_auth_failures: 5\n"
            "  scan:\n"
            "    window_seconds: 10.0\n"
        )
        parsed = _simple_yaml_load(text)
        self.assertEqual(parsed["iface"], "any")
        self.assertEqual(parsed["thresholds"]["brute"]["auth_ports"], [22, 3389])
        self.assertEqual(parsed["thresholds"]["brute"]["max_auth_failures"], 5)
        self.assertEqual(parsed["thresholds"]["scan"]["window_seconds"], 10.0)

    def test_inline_list_and_scalars(self):
        from firmware.config import _parse_scalar, _simple_yaml_load

        self.assertEqual(_parse_scalar("[1, 2, 3]"), [1, 2, 3])
        self.assertEqual(_parse_scalar("true"), True)
        self.assertEqual(_parse_scalar("false"), False)
        self.assertEqual(_parse_scalar("10.5"), 10.5)
        self.assertEqual(_parse_scalar("null"), None)
        parsed = _simple_yaml_load("ports: [80, 443, 53]\nname: edge\n")
        self.assertEqual(parsed["ports"], [80, 443, 53])
        self.assertEqual(parsed["name"], "edge")


if __name__ == "__main__":
    unittest.main()
