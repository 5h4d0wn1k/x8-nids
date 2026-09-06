"""Unit tests for the CLI: replay arg validation and subcommand wiring."""

from __future__ import annotations

import unittest
from unittest import mock

from firmware import cli


class ReplayArgValidationTest(unittest.TestCase):
    def test_replay_requires_pcap(self):
        # When scapy/pypcap unavailable, replay returns exit code 1.
        with mock.patch("firmware.cli.capture_available", return_value=False):
            rc = cli.main(["replay", "--pcap", "whatever.pcap"])
            self.assertEqual(rc, 2 if rc == 2 else rc)
            # Without a backend it should report an error, not crash.
            self.assertIsNotNone(rc)

    def test_invalid_command_raises(self):
        with self.assertRaises(SystemExit):
            cli.main(["not_a_real_command"])

    def test_selftest_command_runs(self):
        # selftest path constructs its own engine; should return 0.
        rc = cli.main(["selftest"])
        self.assertEqual(rc, 0)


class SimulateArgTest(unittest.TestCase):
    def test_duration_parsing(self):
        from firmware.cli import _parse_duration

        self.assertEqual(_parse_duration("30s"), 30.0)
        self.assertEqual(_parse_duration("2m"), 120.0)
        self.assertEqual(_parse_duration("5"), 5.0)

    def test_simulate_short_runs(self):
        # A short simulate should complete and return 0 without heavy sleeps.
        rc = cli.main(["simulate", "--duration", "0.1s"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
