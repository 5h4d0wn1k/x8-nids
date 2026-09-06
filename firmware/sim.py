"""Offline simulation engine for X8 NIDS.

Generates synthetic network flows — port scans, brute-force login attempts,
periodic C2 beacons, exfiltration, and clean baseline traffic — into a loop
that feeds the same detection core used for live/replay capture. Everything is
deterministic given a fixed seed, so the self-test can assert each detection
module fires on planted traffic and does not fire on clean baseline.

Planting uses documentation-only lab addresses (RFC 5737 TEST-NET ranges) and
never real routable IPs.
"""

from __future__ import annotations

import random
import time
from typing import Any, Callable, Dict, List

from .flows import Flow

LAB_SRC = "192.0.2.10"      # our lab host
LAB_DST = "198.51.100.20"   # a lab server
EXT_DST = "203.0.113.50"    # external lab target (used by clean traffic)
C2_DST = "203.0.113.60"     # dedicated external peer for planted C2 beacon/exfil
ANOTHER_SRC = "192.0.2.11"

CLEAN_PORTS = [80, 443, 53]


class SimWorld:
    """Deterministic generator of a labeled flow corpus for a given seed.

    Attributes:
        flows:   List of :class:`Flow` (the synthetic corpus).
        labels:  Mapping from Flow ``ts`` key to ground-truth label so tests
                 can score precision/recall.
    """

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.rng = random.Random(seed)
        self.flows: List[Flow] = []
        self.labels: Dict[float, str] = {}
        self._t = 1000.0  # synthetic clock (seconds)

    def _advance(self, amount: float) -> float:
        self._t += amount
        return self._t

    # -- generators ----------------------------------------------------------

    def clean(self, count: int) -> None:
        """Baseline benign traffic: normal web/DNS flows, no suspicious shape."""
        for _ in range(count):
            port = self.rng.choice(CLEAN_PORTS)
            src = self.rng.choice([LAB_SRC, ANOTHER_SRC])
            flow = Flow(
                ts=self._advance(self.rng.uniform(0.05, 0.5)),
                src=src,
                dst=EXT_DST if port == 443 else self.rng.choice([LAB_DST, EXT_DST]),
                sport=self.rng.randint(1024, 65535),
                dport=port,
                proto=self.rng.choice(["tcp", "udp"]),
                bytes_in=self.rng.randint(200, 4000),
                bytes_out=self.rng.randint(200, 4000),
                duration=self.rng.uniform(0.05, 2.0),
                flags="SF",
                service={80: "http", 443: "https", 53: "dns"}[port],
            )
            weather = self.rng.choice(["clean", "clean", "clean", "clean"])
            flow.meta["label"] = "clean"
            flow.meta["weather"] = weather
            self.flows.append(flow)
            self.labels[flow.ts] = "clean"

    def port_scan(self, source: str, ports: int = 40) -> None:
        """SYN sweep: one source hitting many distinct ports quickly."""
        for i in range(ports):
            flow = Flow(
                ts=self._advance(self.rng.uniform(0.001, 0.020)),
                src=source,
                dst=LAB_DST,
                sport=self.rng.randint(1024, 65535),
                dport=1000 + i,
                proto="tcp",
                bytes_in=0,
                bytes_out=0,
                duration=0.001,
                flags="S0",
                service="",
            )
            flow.meta["label"] = "scan"
            self.flows.append(flow)
            self.labels[flow.ts] = "scan"

    def brute_force(self, source: str, port: int = 22, attempts: int = 8) -> None:
        """Repeated failed-auth signatures toward one service port."""
        for _ in range(attempts):
            flow = Flow(
                ts=self._advance(self.rng.uniform(0.1, 0.4)),
                src=source,
                dst=LAB_DST,
                sport=self.rng.randint(1024, 65535),
                dport=port,
                proto="tcp",
                bytes_in=self.rng.randint(40, 120),
                bytes_out=self.rng.randint(40, 160),
                duration=0.3,
                flags="SF",
                service={22: "ssh", 21: "ftp", 23: "telnet"}.get(port, "ssh"),
                is_reply=False,
            )
            flow.meta["label"] = "brute"
            flow.meta["payload"] = "ssh: from x user y password"
            self.flows.append(flow)
            self.labels[flow.ts] = "brute"
            # The failed-auth signature arrives in the server's reply.
            reply = Flow(
                ts=flow.ts + 0.01,
                src=LAB_DST,
                dst=source,
                sport=port,
                dport=flow.sport,
                proto="tcp",
                bytes_in=0,
                bytes_out=self.rng.randint(60, 140),
                duration=0.01,
                flags="SF",
                service=flow.service,
                is_reply=True,
            )
            reply.meta["label"] = "brute"
            reply.meta["auth_fail"] = True
            reply.meta["payload"] = "Permission denied (publickey,password)."
            self.flows.append(reply)
            self.labels[reply.ts] = "brute"

    def c2_beacon(self, source: str, interval: float = 5.0, hits: int = 8) -> None:
        """Periodic-isochronous outbound connections with low jitter."""
        t = self._t
        for i in range(hits):
            jitter = self.rng.uniform(-0.02, 0.02) * interval
            self._t = t + i * interval + jitter
            flow = Flow(
                ts=self._t,
                src=source,
                dst=C2_DST,
                sport=self.rng.randint(1024, 65535),
                dport=443,
                proto="tcp",
                bytes_in=self.rng.randint(80, 200),
                bytes_out=self.rng.randint(40, 120),
                duration=self.rng.uniform(0.1, 0.4),
                flags="SF",
                service="https",
            )
            flow.meta["label"] = "c2-beacon"
            self.flows.append(flow)
            self.labels[flow.ts] = "c2-beacon"
        self._t = t + hits * interval

    def exfiltration(self, source: str, duration: float = 60.0, total_bytes: int = 20_000_000) -> None:
        """One high-byte-count long-lived flow to a single peer."""
        flow = Flow(
            ts=self._advance(0.1),
            src=source,
            dst=C2_DST,
            sport=self.rng.randint(1024, 65535),
            dport=443,
            proto="tcp",
            bytes_in=total_bytes,
            bytes_out=8000,
            duration=duration,
            flags="SF",
            service="https",
        )
        flow.meta["label"] = "exfil"
        self.flows.append(flow)
        self.labels[flow.ts] = "exfil"

    # -- corpus builders -----------------------------------------------------

    def build_attack_corpus(self) -> List[Flow]:
        """Full corpus with all detection modules planted + clean baseline."""
        self.flows = []
        self.labels = {}
        self._t = 1000.0
        self.clean(12)
        self.port_scan(LAB_SRC, ports=40)
        self.clean(6)
        self.brute_force(ANOTHER_SRC, port=22, attempts=8)
        self.clean(4)
        self.c2_beacon(LAB_SRC, interval=5.0, hits=8)
        self.exfiltration(LAB_SRC, duration=90.0, total_bytes=20_000_000)
        self.clean(3)
        # Sort by timestamp for realistic sequential processing.
        self.flows.sort(key=lambda f: f.ts)
        return self.flows

    def build_clean_corpus(self) -> List[Flow]:
        """Baseline-only corpus (no planted attacks) to check for false alarms."""
        self.flows = []
        self.labels = {}
        self._t = 1000.0
        self.clean(40)
        return self.flows


def run_simulation(
    duration_seconds: float,
    seed: int,
    on_flow: Callable[[Flow], None],
    check: Callable[[Flow], Any],
) -> int:
    """Replay a synthetic mixed corpus as a live-feeling stream.

    Feeds each flow into ``on_flow`` and ``check`` while pacing wall-clock so
    the run spans approximately ``duration_seconds`` (simulated time is scaled
    to wall clock). Returns the number of flows replayed.
    """
    world = SimWorld(seed)
    world.build_attack_corpus()
    world.flows.sort(key=lambda f: f.ts)
    if not world.flows:
        return 0

    start_wall = time.time()
    start_sim = world.flows[0].ts
    end_sim = world.flows[-1].ts
    sim_span = max(end_sim - start_sim, 1.0)
    scale = duration_seconds / sim_span  # seconds wall per second of sim time

    for flow in world.flows:
        flow = flow
        target = (flow.ts - start_sim) * scale
        now = time.time() - start_wall
        delay = target - now
        if delay > 0:
            time.sleep(delay)
        if on_flow is not None:
            on_flow(flow)
        if check is not None:
            check(flow)
    return len(world.flows)
