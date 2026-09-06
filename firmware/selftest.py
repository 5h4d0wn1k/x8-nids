"""Offline self-test for X8 NIDS.

Runs the simulation with a fixed seed, feeds both an attack corpus and a clean
baseline through the detection core, and asserts:
    * every enabled detection module fires on its planted traffic, and
    * no module fires on the clean baseline.
It reports precision/recall over the synthetic corpus and exits 0.

This validation has no dependency on live capture or external tools, so it can
be run in CI or on a fresh machine.
"""

from __future__ import annotations

import time
from typing import Dict, Tuple

from .config import default_config
from .rules import Alert, RuleEngine
from .sim import SimWorld

SELF_TEST_SEED = 20260101


def _run_module(name: str) -> Tuple[int, int]:
    """(true_positive, false_positive) for one module over attack+clean corp.

    A module is considered to have "fired" on a planted flow if it produced at
    least one alert while processing that flow. Because some rules need context
    (a burst of flows), TP is counted at the level of planted groups keyed by
    label.
    """
    cfg = default_config()
    enabled = [name]
    engine = RuleEngine(thresholds=cfg["thresholds"], enabled=enabled)
    world = SimWorld(SELF_TEST_SEED)
    attack = world.build_attack_corpus()

    planted_labels = set()
    for flow in attack:
        if flow.label():
            planted_labels.add(flow.label())

    fired_labels = set()
    alerts = 0
    for flow in attack:
        for alert in engine.check(flow):
            alerts += 1
            lbl = flow.label()
            if lbl:
                fired_labels.add(lbl)

    # Clean baseline: reset engine and process clean corpus only.
    engine.reset()
    clean = world.build_clean_corpus()
    clean_fires = 0
    for flow in clean:
        fired = engine.check(flow)
        clean_fires += len([a for a in fired])

    # A module fires on its planted traffic if its own label produced an alert.
    true_positive = 1 if name in fired_labels else 0
    false_positive = 1 if clean_fires > 0 else 0
    return true_positive, false_positive


def run_selftest() -> Dict[str, object]:
    """Run full self-test; return a metrics dict."""
    started = time.time()
    cfg = default_config()
    modules = ["scan", "brute", "c2-beacon", "exfil"]
    per_module: Dict[str, Dict[str, int]] = {}
    all_tp = 0
    all_fp = 0
    for mod in modules:
        tp, fp = _run_module(mod)
        per_module[mod] = {"tp": tp, "fp": fp, "fires": tp == 1}
        all_tp += tp
        all_fp += fp

    # Total attacks planted across all modules (once each).
    world = SimWorld(SELF_TEST_SEED)
    attack = world.build_attack_corpus()
    total_attacks = len({f.label() for f in attack if f.label() and f.label() != "clean"})

    # Precision / recall across the modules (module-level).
    precision = all_tp / (all_tp + all_fp) if (all_tp + all_fp) else 0.0
    recall = all_tp / total_attacks if total_attacks else 0.0

    elapsed = time.time() - started
    passed = all_tp == len(modules) and all_fp == 0
    return {
        "elapsed_seconds": round(elapsed, 3),
        "modules": per_module,
        "total_attacks": total_attacks,
        "true_positives": all_tp,
        "false_positives": all_fp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "passed": bool(passed),
    }


def main() -> int:
    metrics = run_selftest()
    print("X8 NIDS offline self-test")
    print(f"  elapsed            : {metrics['elapsed_seconds']}s")
    print(f"  total attacks      : {metrics['total_attacks']}")
    for name, m in metrics["modules"].items():
        status = "OK " if m["fires"] and not m["fp"] else "FAIL"
        print(f"  [{status}] {name:<10} tp={m['tp']} fp={m['fp']}")
    print(f"  precision          : {metrics['precision']:.4f}")
    print(f"  recall             : {metrics['recall']:.4f}")
    print(f"  result             : {'PASSED' if metrics['passed'] else 'FAILED'}")
    return 0 if metrics["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
