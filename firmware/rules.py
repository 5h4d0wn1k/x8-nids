"""Rules engine for X8 NIDS.

Each detection module is a class that accepts ``Flow`` objects via
:meth:`Rule.check` and, when enough evidence accumulates, fires an alert via
the engine. Thresholds are read from the configuration dict and may be tuned
in ``config/nids.yaml``.

Detection modules:
    * ``scan``        — SYN / port-sweep thresholds per source IP.
    * ``brute``       — repeated failed-auth signatures on common service ports.
    * ``c2-beacon``   — periodic-isochronous outbound connections (timing
      regularity) to a single destination.
    * ``exfil``       — high-byte-count, long-lived flows to a single peer.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .flows import Flow


class Alert:
    """A discrete detection event raised by a rule engine."""

    def __init__(
        self,
        rule: str,
        severity: int,
        message: str,
        flow: Optional[Flow] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.ts = time.time()
        self.rule = rule
        self.severity = severity
        self.message = message
        self.flow = flow
        self.evidence = evidence or {}

    def as_dict(self) -> Dict[str, Any]:
        data = {
            "ts": self.ts,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
        }
        if self.flow is not None:
            data["src"] = self.flow.src
            data["dst"] = self.flow.dst
            data["sport"] = self.flow.sport
            data["dport"] = self.flow.dport
            data["proto"] = self.flow.proto
        return data


class Rule:
    """Base class for detection modules.

    Subclasses override :meth:`check` and (optionally) :meth:`reset` /
    :meth:`flush`. Each rule keeps its own per-source/per-all statistics in
    ``self.state`` added by :meth:`new_state`.
    """

    name = "base"

    def __init__(self, thresholds: Dict[str, Any]) -> None:
        self.thresholds = thresholds
        self.state: Dict[str, Any] = {}

    def new_state(self) -> Dict[str, Any]:
        """Return a fresh state structure for a tracked key."""
        raise NotImplementedError

    def check(self, flow: Flow) -> Optional[Alert]:
        """Inspect a flow; return an Alert when the rule fires, else None."""
        raise NotImplementedError

    def reset(self) -> None:
        """Clear per-source state (used between corpus runs in the self-test)."""
        self.state = {}

    def age_out(self, now: Optional[float] = None) -> None:
        """Optional: prune stale state (only where a window is tracked)."""


# ---------------------------------------------------------------------------
# scan — SYN / port-sweep per source
# ---------------------------------------------------------------------------
class ScanRule(Rule):
    """Fires when a single source contacts an excessive number of distinct
    destination ports within the configured window."""

    name = "scan"

    def __init__(self, thresholds: Dict[str, Any]) -> None:
        super().__init__(thresholds)
        self.max_ports = int(self.thresholds.get("max_ports_per_source", 30))
        self.window = float(self.thresholds.get("window_seconds", 10.0))

    def new_state(self) -> Dict[str, Any]:
        return {"events": deque(), "last_fire": None}

    def _windowed_ports(self, st: Dict[str, Any]) -> int:
        ports = {p for _, p in st["events"]}
        return len(ports)

    def age_out(self, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        for st in self.state.values():
            if isinstance(st, dict) and isinstance(st.get("events"), deque):
                while st["events"] and now - st["events"][0][0] > self.window:
                    st["events"].popleft()

    def check(self, flow: Flow) -> Optional[Alert]:
        key = flow.src
        if key not in self.state:
            self.state[key] = self.new_state()
        st = self.state[key]
        st["events"].append((flow.ts, flow.dport))
        while st["events"] and flow.ts - st["events"][0][0] > self.window:
            st["events"].popleft()
        if self._windowed_ports(st) <= self.max_ports:
            return None
        # Fire at most once per window per source to avoid alert flooding.
        if st["last_fire"] is not None and flow.ts - st["last_fire"] < self.window:
            return None
        st["last_fire"] = flow.ts
        return Alert(
            self.name,
            2,
            f"port scan/sweep from {key}: {self._windowed_ports(st)} distinct "
            f"ports within {self.window:.1f}s window",
            flow,
            {
                "ports_seen": self._windowed_ports(st),
                "window": self.window,
            },
        )


# ---------------------------------------------------------------------------
# brute — repeated failed-auth signatures
# ---------------------------------------------------------------------------
BRUTE_FAIL_MARKERS = ("failed", "failure", "auth fail", "login incorrect", "530", "denied")


class BruteRule(Rule):
    """Fires when a single source produces repeated failed-authentication
    signatures toward common service ports within the window."""

    name = "brute"

    def __init__(self, thresholds: Dict[str, Any]) -> None:
        super().__init__(thresholds)
        self.max_failures = int(self.thresholds.get("max_auth_failures", 5))
        self.window = float(self.thresholds.get("window_seconds", 60.0))
        self.auth_ports = set(self.thresholds.get(
            "auth_ports", [22, 21, 23, 3389, 5900, 1433, 3306]
        ))

    def new_state(self) -> Dict[str, Any]:
        return {"fails": 0, "timestamps": deque(), "markers": [], "last_fire": None}

    def age_out(self, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        for st in self.state.values():
            ts = st.get("timestamps")
            while ts and now - ts[0] > self.window:
                ts.popleft()
                st["fails"] = max(0, st["fails"] - 1)
                if st["markers"]:
                    st["markers"].pop(0)

    def check(self, flow: Flow) -> Optional[Alert]:
        # Determine the service port being attacked. For a client->server flow
        # it's the destination port; for a server->client reply it's the
        # source port.
        auth_port = flow.sport if flow.is_reply else flow.dport
        if auth_port not in self.auth_ports:
            return None
        # Failure signatures are typically found in the reply payload/service
        # description. If no payload, we require the flow be flagged as a failed
        # auth reply by the decoder/simulator.
        payload = flow.meta.get("payload", "")
        failed = False
        if payload:
            bl = payload.lower()
            failed = any(m in bl for m in BRUTE_FAIL_MARKERS)
        elif flow.meta.get("auth_fail"):
            failed = True
        if not failed:
            return None
        # Attribute the attack to the requester: the client for request flows,
        # and the recipient of the failure reply for reply flows.
        attacker = flow.dst if flow.is_reply else flow.src
        key = attacker
        if key not in self.state:
            self.state[key] = self.new_state()
        st = self.state[key]
        st["fails"] += 1
        st["timestamps"].append(flow.ts)
        st["markers"].append(payload or "(empty)")
        while st["timestamps"] and flow.ts - st["timestamps"][0] > self.window:
            st["timestamps"].popleft()
            st["fails"] = max(0, st["fails"] - 1)
            if st["markers"]:
                st["markers"].pop(0)
        if st["fails"] >= self.max_failures:
            # Fire at most once per window per source to avoid flooding while
            # the brute-force continues beating on the same service.
            if st["last_fire"] is not None and flow.ts - st["last_fire"] < self.window:
                return None
            st["last_fire"] = flow.ts
            return Alert(
                self.name,
                3,
                f"brute-force authentication failure from {attacker} to port "
                f"{auth_port}: {st['fails']} failures within {self.window:.0f}s",
                flow,
                {"failures": st["fails"], "port": auth_port, "window": self.window},
            )
        return None


# ---------------------------------------------------------------------------
# c2-beacon — periodic-isochronous outbound connections
# ---------------------------------------------------------------------------
class C2BeaconRule(Rule):
    """Detects timing regularity in repeated outbound connections to a single
    destination (beaconing). Uses coefficient of variation of inter-arrival
    intervals, and a configurable max jitter ratio."""

    name = "c2-beacon"

    def __init__(self, thresholds: Dict[str, Any]) -> None:
        super().__init__(thresholds)
        self.min_beacons = int(self.thresholds.get("min_beacons", 5))
        self.max_jitter = float(self.thresholds.get("max_jitter_ratio", 0.20))
        self.window = float(self.thresholds.get("window_seconds", 300.0))
        self.min_interval = float(self.thresholds.get("min_interval_seconds", 1.0))

    def new_state(self) -> Dict[str, Any]:
        return {"times": [], "dst": None, "dport": None, "fired": False}

    def age_out(self, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        for key in list(self.state.keys()):
            st = self.state[key]
            if isinstance(st, dict) and st.get("times"):
                st["times"] = [t for t in st["times"] if now - t <= self.window]

    @staticmethod
    def _periodicity(times: List[float], max_jitter: float) -> Tuple[bool, Optional[float]]:
        """Return (is_periodic, median_interval) for a sorted list of times."""
        if len(times) < 2:
            return False, None
        intervals = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
        if not intervals:
            return False, None
        median = sorted(intervals)[len(intervals) // 2]
        if median <= 0:
            return False, None
        max_dev = max(abs(i - median) / median for i in intervals)
        return max_dev <= max_jitter, median

    def check(self, flow: Flow) -> Optional[Alert]:
        # Beaconing is repeated small outbound connections to a single dst.
        if flow.is_reply:
            return None
        key = (flow.src, flow.dst, flow.dport)
        if key not in self.state:
            self.state[key] = self.new_state()
        st = self.state[key]
        st["times"].append(flow.ts)
        st["dst"] = flow.dst
        st["dport"] = flow.dport
        st["times"] = [t for t in st["times"] if flow.ts - t <= self.window]
        if st["fired"] or len(st["times"]) < self.min_beacons:
            return None
        periodic, interval = self._periodicity(st["times"], self.max_jitter)
        if periodic and interval is not None and interval >= self.min_interval:
            st["fired"] = True
            return Alert(
                self.name,
                2,
                f"periodic outbound beacon from {flow.src} to {flow.dst}:{flow.dport} "
                f"(interval ~{interval:.2f}s, {len(st['times'])} hits)",
                flow,
                {"interval": round(interval, 3), "hits": len(st["times"])},
            )
        return None


# ---------------------------------------------------------------------------
# exfil — high-byte-count, long-lived flows
# ---------------------------------------------------------------------------
class ExfilRule(Rule):
    """Fires when a single peer pair sustains a flow with high byte count and
    long duration (potential data exfiltration)."""

    name = "exfil"

    def __init__(self, thresholds: Dict[str, Any]) -> None:
        super().__init__(thresholds)
        self.min_bytes = float(self.thresholds.get("min_bytes", 1_000_000))
        self.min_duration = float(self.thresholds.get("min_duration_seconds", 30.0))

    def new_state(self) -> Dict[str, Any]:
        return {"bytes_in": 0, "bytes_out": 0, "start": None, "peer": None, "duration": 0.0, "fired": False}

    def check(self, flow: Flow) -> Optional[Alert]:
        # Aggregate all traffic for the (src,dst) peer pair over the capture.
        key = (flow.src, flow.dst)
        if key not in self.state:
            self.state[key] = self.new_state()
        st = self.state[key]
        st["bytes_in"] += flow.bytes_in
        st["bytes_out"] += flow.bytes_out
        if st["start"] is None:
            st["start"] = flow.ts
        st["peer"] = (flow.src, flow.dst)
        # Duration is the max of the flow's own duration and the elapsed span.
        accounted = max(st.get("duration", 0.0), flow.duration)
        elapsed = max(0.0, flow.ts - (st["start"] or flow.ts))
        st["duration"] = max(accounted, elapsed)
        total = st["bytes_in"] + st["bytes_out"]
        if st["fired"]:
            return None
        if total >= self.min_bytes and st["duration"] >= self.min_duration:
            st["fired"] = True
            return Alert(
                self.name,
                2,
                f"possible exfiltration: {flow.src}->{flow.dst} "
                f"{int(total)} bytes over {st['duration']:.1f}s",
                flow,
                {"total_bytes": int(total), "duration": round(st["duration"], 2)},
            )
        return None


_RULE_CLASSES = {
    "scan": ScanRule,
    "brute": BruteRule,
    "c2-beacon": C2BeaconRule,
    "exfil": ExfilRule,
}


class RuleEngine:
    """Runs a set of Rule instances against a stream of flows."""

    def __init__(
        self,
        thresholds: Optional[Dict[str, Any]] = None,
        enabled: Optional[Iterable[str]] = None,
    ) -> None:
        thresholds = thresholds or {}
        self.rules: Dict[str, Rule] = {}
        for name, cls in _RULE_CLASSES.items():
            if enabled is not None and name not in set(enabled):
                continue
            self.rules[name] = cls(thresholds.get(name, {}))
        self._last_flush: Dict[str, float] = {}

    @property
    def rule_names(self) -> List[str]:
        return list(self.rules.keys())

    @classmethod
    def factory(cls):
        return cls

    def check(self, flow: Flow) -> List[Alert]:
        """Run all rules against one flow; return fired alerts (maybe empty)."""
        alerts: List[Alert] = []
        for rule in self.rules.values():
            try:
                alert = rule.check(flow)
            except Exception:  # defensive: a rule must never crash the engine
                continue
            if alert is not None:
                alerts.append(alert)
        return alerts

    def reset(self) -> None:
        for rule in self.rules.values():
            rule.reset()

    def age_out(self, now: Optional[float] = None) -> None:
        for rule in self.rules.values():
            rule.age_out(now)
