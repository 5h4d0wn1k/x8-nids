# X8 — Network Intrusion Detection System

**Detection-only (blue team)** live network intrusion detection for monitoring
networks you **own**. Ships a rules engine for port-scan / brute-force /
C2-beacon / exfiltration detection, an alert stream (JSONL + HTTP API), and a
deterministic offline simulation engine so the whole stack is testable with no
packet capture.

> This is a BLUE-TEAM defensive tool. It contains **no** injection or attack
> primitives. Use only on networks you own or are explicitly authorized to
> monitor.

## Overview

- **Rules engine** — four detection modules with configurable thresholds:
  `scan`, `brute`, `c2-beacon`, `exfil`. Each module is a class with a
  `check(flow)` interface; thresholds are read from `config/nids.yaml`.
- **Live capture** — via Scapy/pypcap when available (`nids live`), plus pcap
  replay (`nids replay`).
- **Offline simulation** — `nids simulate` generates synthetic scans, brute
  forces, C2 beacons, exfil, and clean baseline traffic into the same
  detection core (no root, no capture, fully deterministic with a fixed seed).
- **Alert stream** — JSONL to stdout + `logs/alerts.jsonl`, plus a built-in
  HTTP/JSON listener for downstream SIEM-style ingestion.
- **Structured logging** — JSONL log file `logs/nids.log` + readable stdout.
- **Flows snapshot** — bounded JSONL flow log (`flows/flows.jsonl`).
- **Offline self-test** — `nids selftest` asserts each module fires on its
  planted traffic and does not fire on clean baseline; reports precision and
  recall over the synthetic corpus; exits 0.

## Installation

Requires Python 3.9+. The simulation/self-test path is **pure standard
library** and needs nothing installed.

```bash
# From the repo root — editable install (optional; needed for the `nids` script)
pip install -e .

# live capture / pcap replay support (optional)
pip install -e ".[pcap]"   # or: pip install scapy
```

Without scapy, `nids simulate`, `nids rules`, `nids status`, and
`nids selftest` all work normally; `live`/`replay` print a clear error.

## Configuration

`config/nids.yaml` — interface, detection thresholds, alert output paths,
logging level, and home-lab observation ranges.

```yaml
iface: any

thresholds:
  scan:
    max_ports_per_source: 30     # ports per source within window -> alert
    window_seconds: 10.0
  brute:
    max_auth_failures: 5
    window_seconds: 60.0
    auth_ports: [22, 21, 23, 3389, 5900, 1433, 3306]
  c2_beacon:
    min_beacons: 5
    max_jitter_ratio: 0.20       # max relative deviation of intervals
    window_seconds: 300.0
    min_interval_seconds: 1.0
  exfil:
    min_bytes: 1000000
    min_duration_seconds: 30.0

alert:
  stream_path: logs/alerts.jsonl
  api_host: 127.0.0.1
  api_port: 8488
  api_enabled: true

logging:
  level: INFO
  file_path: logs/nids.log

flows:
  snapshot_path: flows/flows.jsonl
  max_snapshot_lines: 10000

lab:
  home_ranges: [192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24]
```

**Lab ranges are documentation placeholders only** (RFC 5737 TEST-NET values).
Replace them with your own authorized lab ranges before live use. The config
validator refuses to guess; it only checks that ranges are CIDR-form. Never
point the tool at networks you do not own.

## Usage

```
nids live     [--iface any]           Live capture + detection
nids replay   --pcap file.pcap        Replay a pcap through detection
nids simulate [--duration 30s] [--seed N]   Offline synthetic demo
nids rules    [--list]                List detection modules (+thresholds)
nids status                           Show runtime status/config
nids selftest                         Offline self-test (exit 0 on pass)
```

### `nids live --iface any`

Capture packets on the given interface (`any` = all), decode flows, run the
rules engine, and stream alerts as JSONL to stdout and `logs/alerts.jsonl`.
Requires scapy and capture privileges. Stop with `Ctrl-C`.

### `nids replay --pcap file.pcap`

Replay a previously recorded pcap through the same detection core. Alerts are
streamed identically. Requires scapy.

### `nids simulate --duration 30s`

Offline demo. Generates synthetic traffic (port scan, brute-force login
attempts, periodic C2 beacons, exfiltration, plus clean baseline) and runs
detection live. Deterministic for a given `--seed` (default `20260101`).

```bash
nids simulate --duration 30s
```

### `nids rules --list`

Print the detection module table and the effective thresholds from config.

### `nids status`

Print version, configured interface, alert/flow/log paths, API endpoint, and
whether a pcap backend is present.

### `nids selftest`

Runs the planted-corpus self-test and prints precision/recall. Exits `0` when
all modules fire on planted traffic and none fires on the clean baseline.

### Programmatic use

```bash
python -m unittest discover -v   # run the full unit test suite
```

```python
from firmware.config import load_config
from firmware.rules import RuleEngine
from firmware.flows import Flow

cfg = load_config()
engine = RuleEngine(thresholds=cfg["thresholds"])
for alert in engine.check(Flow(ts=..., src=..., dst=..., sport=..., dport=...)):
    print(alert.message)
```

## Detection Modules

| Module      | Class          | Signature                                                 | Key thresholds                     |
|-------------|----------------|------------------------------------------------------------|------------------------------------|
| `scan`      | `ScanRule`     | SYN / port-sweep thresholds per source IP                  | `max_ports_per_source`, `window_seconds` |
| `brute`     | `BruteRule`    | Repeated failed-auth signatures on common ports            | `max_auth_failures`, `auth_ports`       |
| `c2-beacon` | `C2BeaconRule` | Periodic-isochronous outbound connections (timing regularity) | `min_beacons`, `max_jitter_ratio`  |
| `exfil`     | `ExfilRule`    | High-byte-count, long-lived flows to a single peer         | `min_bytes`, `min_duration_seconds`     |

Thresholds are configurable per module from `config/nids.yaml`; each rule
implements `check(flow)`.

## Metrics

Measured with the built-in offline self-test over a fixed-seed synthetic
corpus (planted scan/brute/C2-beacon/exfil + clean baseline):

```text
X8 NIDS offline self-test
  total attacks      : 4
  [OK ] scan       tp=1 fp=0
  [OK ] brute      tp=1 fp=0
  [OK ] c2-beacon  tp=1 fp=0
  [OK ] exfil      tp=1 fp=0
  precision          : 1.0000
  recall             : 1.0000
```

- **Precision (module-level)**: true-positives / (true-positives +
  false-positives) over the synthetic attack + clean corpus.
- **Recall (module-level)**: modules that fired on their planted traffic /
  total planted attack families.
- **Alerts under load**: `nids simulate` reports flows/s and alerts processed,
  e.g. `flows=90 alerts=4 flows/s=60` on a modest laptop (pure Python, no
  capture I/O). Full-scale packet capture throughput depends on the capture
  backend (scapy) and NIC.
- The self-test and unit suite both complete in well under 20s
  (typically <1s).

## Live Lab Test Plan

Verify detection against your own network (owned/authorized lab targets only)
and measure alert latency.

1. **Setup**: run `nids status`; confirm `iface` and lab ranges in
   `config/nids.yaml` point at your lab (replace the 192.0.2.x placeholders).
   Start the detector: `sudo nids live --iface any` (or `sudo` equivalent for
   the capture interface).
2. **Generate a scan** against a lab host from a lab source, e.g. an NMAP SYN
   sweep of >30 ports in <10s to your own host. Expect a `scan` alert; measure
   detection latency (alert timestamp − last SYN).
3. **Generate a brute-force** on your lab host: >5 failed SSH/other service
   logins within 60s from one source (e.g. a short credential-stuffing loop
   against your own lab box). Expect a `brute` alert on the failed-auth
   markers.
4. **Generate a C2 beacon**: a script on a lab host opens an outbound TCP
   connection to a lab listener every ~5s, 5+ times. Expect a `c2-beacon`
   alert with the observed interval.
5. **Generate an exfil** pattern: a lab host pushing >1 MB over a >30s single
   flow (e.g. `dd if=/dev/urandom bs=1M count=20 | nc -q 60 lab-listener 443`).
   Expect an `exfil` alert.
6. **Clean baseline**: run normal browsing/DNS from lab hosts; verify no
   `scan`/`brute`/`c2-beacon`/`exfil` alerts on the baseline corpus
   (self-test probes this offline as a proxy).
7. **Record metrics** into `METRICS.md`: detection latency per alert type,
   alerts/sec under load, and precision/recall from `nids selftest`.

Only run the generating tools against your **own** hosts. All example
addresses above are RFC 5737 documentation ranges.

## IMPORTANT: Read before use.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized network monitoring and intrusion detection deployment is illegal
- This tool should ONLY be used on networks you own or have written authorization to monitor
- Deploying honeypots or IDS on shared networks requires administrator approval

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized interception of network traffic is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Prohibits intentional interception of electronic communications
- **Electronic Communications Privacy Act (ECPA)**: Regulates access to stored and transmitted communications
- **State Laws**: Many states have additional wiretapping and computer crime statutes
- **GDPR/CCPA**: Network traffic may contain personal data subject to privacy regulations

### Acceptable Use
- Monitoring your own network infrastructure for intrusions
- Authorized penetration testing with explicit written scope
- Academic research in controlled lab environments with isolated test networks
- Security education and training with synthetic or your own network data
- Incident response on networks you administer

### Prohibited Use
- Monitoring networks without authorization from the owner
- Intercepting communications without legal authority
- Deploying on production networks without change management approval
- Any activity that violates applicable wiretapping or computer crime laws
- Commercial use without proper licensing and legal review

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software. Detection results may contain false positives and false negatives.

### Responsible Disclosure
If you discover network intrusions using this tool, follow responsible disclosure practices:
1. Notify the affected network owner privately
2. Document the intrusion without modifying evidence
3. Allow reasonable time for remediation
4. Report to appropriate authorities (CERT, law enforcement) if warranted
5. Do not exploit or escalate beyond proof of concept

## License

MIT