"""Unit tests for the rules engine detection modules.

Each rule is exercised with synthetic flows: it must fire on its planted
signature pattern and not fire on clean baseline flows.
"""

from __future__ import annotations

import unittest

from firmware.config import default_config
from firmware.flows import Flow
from firmware.rules import (
    Alert,
    BruteRule,
    C2BeaconRule,
    ExfilRule,
    RuleEngine,
    ScanRule,
)


def _cfg():
    return default_config()["thresholds"]


def _flow(ts, src, dst, dport, rev=False, **kw):
    return Flow(
        ts=ts,
        src=src,
        dst=dst,
        sport=kw.pop("sport", 12345),
        dport=dport,
        proto=kw.pop("proto", "tcp"),
        is_reply=rev,
        **kw,
    )


class ScanRuleTest(unittest.TestCase):
    def setUp(self):
        self.rule = ScanRule(_cfg()["scan"])

    def test_fires_on_port_sweep(self):
        fired = False
        for i in range(40):
            flow = _flow(1000.0 + i * 0.001, "192.0.2.10", "198.51.100.20", 1000 + i)
            if self.rule.check(flow) is not None:
                fired = True
        self.assertTrue(fired)

    def test_no_fire_on_few_ports(self):
        for i in range(5):
            self.assertIsNone(self.rule.check(_flow(1000.0 + i, "192.0.2.10", "198.51.100.20", 443 + i)))

    def test_window_slides(self):
        rule = ScanRule({"max_ports_per_source": 5, "window_seconds": 2.0})
        fired = False
        for i in range(10):
            if rule.check(_flow(1000.0 + i * 0.1, "s", "d", 1000 + i)) is not None:
                fired = True
        self.assertTrue(fired)
        # After a window of quiescence, a fresh burst fires again.
        rule.age_out(1005.0)
        boosted = False
        for i in range(6):
            if rule.check(_flow(1005.0 + i * 0.05, "s", "d", 3000 + i)) is not None:
                boosted = True
        self.assertTrue(boosted)


class BruteRuleTest(unittest.TestCase):
    def setUp(self):
        self.rule = BruteRule(_cfg()["brute"])

    def test_fires_on_repeated_failures(self):
        fired = False
        for i in range(6):
            base = _flow(2000.0 + i * 0.2, "192.0.2.11", "198.51.100.20", 22)
            self.rule.check(base)
            reply = _flow(base.ts + 0.01, "198.51.100.20", "192.0.2.11", base.sport,
                          rev=True, sport=22)
            reply.meta["auth_fail"] = True
            reply.meta["payload"] = "Permission denied (password)."
            if self.rule.check(reply) is not None:
                fired = True
        self.assertTrue(fired)

    def test_no_fire_on_successful_auth(self):
        for i in range(10):
            base = _flow(3000.0 + i, "192.0.2.11", "198.51.100.20", 22)
            self.rule.check(base)
            reply = _flow(base.ts + 0.01, "198.51.100.20", "192.0.2.11", base.sport,
                          rev=True, sport=22)
            reply.meta["auth_fail"] = False
            reply.meta["payload"] = "Welcome to Ubuntu"
            self.assertIsNone(self.rule.check(reply))

    def test_ignores_non_auth_ports(self):
        for i in range(10):
            base = _flow(4000.0 + i, "192.0.2.11", "198.51.100.20", 8080)
            self.rule.check(base)
            reply = _flow(base.ts + 0.01, "198.51.100.20", "192.0.2.11", base.sport,
                          rev=True, sport=8080)
            reply.meta["auth_fail"] = True
            self.assertIsNone(self.rule.check(reply))


class C2BeaconRuleTest(unittest.TestCase):
    def setUp(self):
        self.rule = C2BeaconRule(_cfg()["c2_beacon"])

    def test_fires_on_periodic_beacons(self):
        fired = False
        fired_rule = None
        base = 5000.0
        for i in range(8):
            alert = self.rule.check(_flow(base + i * 5.0, "192.0.2.10", "203.0.113.60", 443))
            if alert is not None:
                fired = True
                fired_rule = alert.rule
        self.assertTrue(fired)
        self.assertEqual(fired_rule, "c2-beacon")

    def test_no_fire_on_jittery_traffic(self):
        import random

        rng = random.Random(7)
        for i in range(30):
            jitter = rng.uniform(0, 3.0)
            fired = self.rule.check(
                _flow(6000.0 + i * 1.0 + jitter, "192.0.2.10", "203.0.113.60", 443)
            )
            self.assertIsNone(fired)

    def test_no_fire_on_missing_beacons(self):
        for i in range(4):
            self.assertIsNone(self.rule.check(_flow(7000.0 + i * 5.0, "192.0.2.10", "203.0.113.60", 443)))


class ExfilRuleTest(unittest.TestCase):
    def setUp(self):
        self.rule = ExfilRule(_cfg()["exfil"])

    def test_fires_on_large_long_flow(self):
        fired = self.rule.check(
            _flow(8000.0, "192.0.2.10", "203.0.113.50", 443, bytes_in=20_000_000, duration=90.0)
        )
        self.assertIsNotNone(fired)
        self.assertEqual(fired.rule, "exfil")

    def test_no_fire_on_small_flow(self):
        self.assertIsNone(
            self.rule.check(_flow(8100.0, "192.0.2.10", "203.0.113.50", 443, bytes_in=5000, duration=5.0))
        )


class RuleEngineTest(unittest.TestCase):
    def test_enabled_filter(self):
        engine = RuleEngine(thresholds=_cfg(), enabled=["scan"])
        self.assertEqual(engine.rule_names, ["scan"])

    def test_default_all_enabled(self):
        engine = RuleEngine(thresholds=_cfg())
        self.assertEqual(sorted(engine.rule_names), ["brute", "c2-beacon", "exfil", "scan"])

    def test_check_returns_alerts(self):
        engine = RuleEngine(thresholds=_cfg())
        flow = _flow(9000.0, "192.0.2.10", "203.0.113.50", 443, bytes_in=20_000_000, duration=90.0)
        alerts = engine.check(flow)
        self.assertTrue(any(a.rule == "exfil" for a in alerts))
        self.assertTrue(all(isinstance(a, Alert) for a in alerts))

    def test_reset_clears_state(self):
        engine = RuleEngine(thresholds=_cfg(), enabled=["scan"])
        for i in range(40):
            engine.check(_flow(9200.0 + i * 0.001, "s", "d", 1000 + i))
        engine.reset()
        # No residual state -> a single new flow should not fire.
        self.assertEqual(engine.check(_flow(9300.0, "s", "d", 2000)), [])


if __name__ == "__main__":
    unittest.main()
