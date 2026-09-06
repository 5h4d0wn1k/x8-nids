#!/usr/bin/env python3
"""X8 NIDS command-line interface.

Detection-only (blue team) network intrusion detection for monitoring networks
you own. Provides live capture, pcap replay, offline simulation, rules
listing, and status verification.

Commands:
    nids live     --iface any            Live capture/detection (needs scapy).
    nids replay   --pcap file.pcap       Replay a pcap through detection.
    nids simulate --duration 30s         Offline demo: synthetic traffic.
    nids rules    --list                 List detection modules and thresholds.
    nids status                          Show runtime status / config.
    nids selftest                        Run the offline self-test (exit 0).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Dict, List, Optional

from . import __version__
from .alert import AlertSink
from .capture import CaptureError, iter_pcap, live_capture, capture_available
from .config import ConfigError, load_config
from .flows import Flow
from .logging_util import get_logger
from .rules import RuleEngine
from .sim import run_simulation
from .selftest import run_selftest  # noqa: F401  (documented programmatic entry)


def _build_engine(cfg: Dict[str, Any]) -> RuleEngine:
    return RuleEngine(thresholds=cfg.get("thresholds", {}))


def _process_flow(flow: Flow, engine: RuleEngine, sink: AlertSink) -> None:
    for alert in engine.check(flow):
        sink.emit(alert)


def _flows_snapshot(cfg: Dict[str, Any], flow: Flow, lines: List[str]) -> None:
    path = cfg.get("flows", {}).get("snapshot_path")
    if not path:
        return
    max_lines = int(cfg.get("flows", {}).get("max_snapshot_lines", 10000))
    rec = flow.as_dict()
    rec["ts"] = flow.ts
    lines.append(json.dumps(rec, sort_keys=True))
    if len(lines) >= max_lines:
        _flush_snapshot(cfg, lines)


def _flush_snapshot(cfg: Dict[str, Any], lines: List[str]) -> None:
    path = cfg.get("flows", {}).get("snapshot_path")
    if not path or not lines:
        lines.clear()
        return
    parent = path.rsplit("/", 1)[0] if "/" in path else "."
    import os

    os.makedirs(parent, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    lines.clear()


def cmd_live(args: argparse.Namespace, cfg: Dict[str, Any], log) -> int:
    engine = _build_engine(cfg)
    sink = AlertSink(
        stream_path=cfg["alert"]["stream_path"],
        api_enabled=cfg["alert"]["api_enabled"],
        api_host=cfg["alert"]["api_host"],
        api_port=cfg["alert"]["api_port"],
    )
    sink.open()
    sink.start_listener()
    iface = getattr(args, "iface", None) or cfg.get("iface", "any")
    log.info(f"live capture starting on iface={iface}")
    if not capture_available():
        sink.close()
        log.error("live capture requires scapy or pypcap; run 'nids simulate' instead")
        return 1
    try:
        flows = live_capture(iface)
        _run_stream(flows, engine, sink, cfg, log)
    except CaptureError as exc:
        log.error(str(exc))
        sink.close()
        return 1
    sink.close()
    return 0


def cmd_replay(args: argparse.Namespace, cfg: Dict[str, Any], log) -> int:
    if not getattr(args, "pcap", None):
        log.error("replay requires --pcap file.pcap")
        return 2
    if not capture_available():
        log.error("replay requires scapy; run 'nids simulate' for offline demo")
        return 1
    engine = _build_engine(cfg)
    sink = AlertSink(
        stream_path=cfg["alert"]["stream_path"],
        api_enabled=cfg["alert"]["api_enabled"],
        api_host=cfg["alert"]["api_host"],
        api_port=cfg["alert"]["api_port"],
    )
    sink.open()
    sink.start_listener()
    log.info(f"replaying pcap={args.pcap}")
    try:
        flows = iter_pcap(args.pcap)
        _run_stream(flows, engine, sink, cfg, log)
    except CaptureError as exc:
        log.error(str(exc))
        sink.close()
        return 1
    sink.close()
    log.info(f"replay finished, alerts={sink.count}")
    return 0


def _run_stream(flows, engine: RuleEngine, sink: AlertSink, cfg: Dict[str, Any], log) -> None:
    lines: List[str] = []
    start = time.time()
    n = 0
    for flow in flows:
        n += 1
        _process_flow(flow, engine, sink)
        _flows_snapshot(cfg, flow, lines)
    _flush_snapshot(cfg, lines)
    elapsed = time.time() - start
    log.info(f"processed flows={n} alerts={sink.count} elapsed={elapsed:.2f}s")


def cmd_simulate(args: argparse.Namespace, cfg: Dict[str, Any], log) -> int:
    duration = _parse_duration(getattr(args, "duration", None) or "30s")
    seed = int(getattr(args, "seed", 20260101))
    engine = _build_engine(cfg)
    sink = AlertSink(
        stream_path=cfg["alert"]["stream_path"],
        api_enabled=cfg["alert"]["api_enabled"],
        api_host=cfg["alert"]["api_host"],
        api_port=cfg["alert"]["api_port"],
    )
    sink.open()
    sink.start_listener()
    log.info(f"simulation starting duration={duration}s seed={seed}")
    snap_lines: List[str] = []
    start = time.time()

    def on_flow(flow: Flow) -> None:
        _process_flow(flow, engine, sink)
        _flows_snapshot(cfg, flow, snap_lines)

    count = run_simulation(duration, seed, on_flow, None)
    _flush_snapshot(cfg, snap_lines)
    sink.close()
    elapsed = time.time() - start
    rate = count / elapsed if elapsed else 0.0
    log.info(f"simulation complete flows={count} alerts={sink.count} flows/s={rate:.1f}")
    return 0


def cmd_rules(args: argparse.Namespace, cfg: Dict[str, Any], log) -> int:
    th = cfg.get("thresholds", {})
    print("Detection modules (rules engine):")
    print(f"{'module':<10} {'enabled':<8} description")
    print("-" * 78)
    descriptions = {
        "scan": "SYN / port-sweep thresholds per source IP",
        "brute": "repeated failed-auth signatures on common ports",
        "c2-beacon": "periodic-isochronous outbound connections (timing regularity)",
        "exfil": "high-byte-count, long-lived flows",
    }
    for name, desc in descriptions.items():
        print(f"{name:<10} {'yes':<8} {desc}")
    if getattr(args, "list", False):
        print()
        print("Thresholds (from config/nids.yaml):")
        print(json.dumps(th, indent=4, sort_keys=True))
    return 0


def cmd_status(args: argparse.Namespace, cfg: Dict[str, Any], log) -> int:
    print("X8 NIDS status")
    print(f"  version        : {__version__}")
    print(f"  config         : {cfg.get('iface')}")
    print(f"  iface          : {cfg.get('iface')}")
    print(f"  pcap available : {capture_available()}")
    print(f"  alert stream   : {cfg['alert']['stream_path']}")
    print(f"  flows snapshot : {cfg['flows']['snapshot_path']}")
    print(f"  log file       : {cfg['logging']['file_path']}")
    print(f"  api            : http://{cfg['alert']['api_host']}:{cfg['alert']['api_port']} "
          f"(enabled={cfg['alert']['api_enabled']})")
    print(f"  lab ranges     : {' '.join(cfg['lab']['home_ranges'])}")
    return 0


def _parse_duration(raw: str) -> float:
    raw = raw.strip().lower()
    if raw.endswith("s"):
        return float(raw[:-1])
    if raw.endswith("m"):
        return float(raw[:-1]) * 60
    return float(raw)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nids",
        description="X8 NIDS — detection-only network intrusion detection (monitor your own networks).",
        epilog=(
            "This is a BLUE-TEAM, detection-only tool. It contains no injection or "
            "attack primitives. Use only on networks you own or are authorized to monitor."
        ),
    )
    parser.add_argument("--version", action="version", version=f"x8-nids {__version__}")
    parser.add_argument("--config", default=None, help="path to config YAML (default config/nids.yaml)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_live = sub.add_parser("live", help="live capture/detection")
    p_live.add_argument("--iface", default=None)

    p_replay = sub.add_parser("replay", help="replay a pcap")
    p_replay.add_argument("--pcap", required=True)

    p_sim = sub.add_parser("simulate", help="offline synthetic demo")
    p_sim.add_argument("--duration", default="30s")
    p_sim.add_argument("--seed", type=int, default=20260101)

    p_rules = sub.add_parser("rules", help="list detection modules")
    p_rules.add_argument("--list", action="store_true", help="also print thresholds")

    p_status = sub.add_parser("status", help="show runtime status")

    sub.add_parser("selftest", help="run offline self-test (exit 0 on pass)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "selftest":
        return _run_selftest_cli()

    try:
        cfg = load_config(getattr(args, "config", None))
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    log = get_logger(
        level=cfg["logging"]["level"],
        file_path=cfg["logging"]["file_path"],
    )

    handlers = {
        "live": cmd_live,
        "replay": cmd_replay,
        "simulate": cmd_simulate,
        "rules": cmd_rules,
        "status": cmd_status,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 2
    return int(handler(args, cfg, log) or 0)


def _run_selftest_cli() -> int:
    from .selftest import main as selftest_main
    return selftest_main()


if __name__ == "__main__":
    raise SystemExit(main())
