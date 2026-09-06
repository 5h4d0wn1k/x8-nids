"""Unit tests for the alert formatter and sink."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from firmware.alert import AlertFormatter, AlertSink
from firmware.flows import Flow
from firmware.rules import Alert


class AlertFormatterTest(unittest.TestCase):
    def test_format_is_json(self):
        alert = Alert(
            rule="scan",
            severity=2,
            message="port sweep",
            flow=Flow(ts=1.0, src="192.0.2.1", dst="198.51.100.2", sport=1234, dport=80),
            evidence={"ports_seen": 31},
        )
        line = AlertFormatter.format(alert)
        parsed = json.loads(line)
        self.assertEqual(parsed["rule"], "scan")
        self.assertEqual(parsed["severity"], 2)
        self.assertEqual(parsed["src"], "192.0.2.1")
        self.assertEqual(parsed["dport"], 80)
        self.assertEqual(parsed["evidence"]["ports_seen"], 31)
        self.assertIn("ts", parsed)

    def test_sink_writes_stream_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "alerts.jsonl")
            sink = AlertSink(stream_path=path, api_enabled=False, to_stdout=False)
            sink.open()
            alert = Alert(rule="exfil", severity=2, message="big transfer", evidence={})
            sink.emit(alert)
            sink.close()
            with open(path, encoding="utf-8") as fh:
                lines = fh.read().strip().splitlines()
            self.assertEqual(len(lines), 1)
            parsed = json.loads(lines[0])
            self.assertEqual(parsed["rule"], "exfil")

    def test_sink_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "alerts.jsonl")
            sink = AlertSink(stream_path=path, api_enabled=False, to_stdout=False)
            sink.open()
            for _ in range(3):
                sink.emit(Alert(rule="scan", severity=1, message="m", evidence={}))
            self.assertEqual(sink.count, 3)
            sink.close()


if __name__ == "__main__":
    unittest.main()
