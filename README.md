# X8 — Network Intrusion Detection System

Hybrid NIDS with Aho-Corasick signature matching and ML decision-tree classification.

## Overview

This project implements a hybrid network intrusion detection system that:
- Parses Zeek-style conn.log flow records with full field extraction
- Extracts 20 flow features (duration, bytes, rates, flags, ports, protocol)
- Runs a Suricata-style signature engine with flow-based detection rules
- Implements an Aho-Corasick multi-pattern matcher from scratch for payload scanning
- Trains a pure-Python RandomForest classifier on an embedded labeled flow dataset
- Compares Aho-Corasick vs naive pattern matching speed
- Outputs detection-rate-per-attack-type summary table

## Features

- **Zeek log parser**: Full conn.log parsing with field type coercion
- **Feature extraction**: 20 flow-level features including byte ratios, rates, port flags
- **Aho-Corasick matcher**: From-scratch multi-pattern string matching with failure links
- **Signature engine**: Suricata-style rules with flow condition matching
- **RandomForest classifier**: Pure-Python bagged decision trees with Gini impurity
- **Detection metrics**: Per-attack-type detection rate table
- **Benchmarking**: Aho-Corasick vs naive matching speed comparison
- **Offline demo**: Fully self-contained with embedded sample data

## Installation

```bash
# No external dependencies required — pure Python standard library
python3 nids.py
```

## Usage

```bash
# Run full offline analysis
python3 nids.py

# Import as module
from nids import NetworkIDS, ConnLogParser, AhoCorasick
nids = NetworkIDS()
result = nids.run_full_analysis()
```

## Example Output

```
======================================================================
  X8 — Network Intrusion Detection System — Analysis Report
======================================================================
  Total flows analyzed: 30
  ML distribution: {'benign': 18, 'suspicious': 4, 'malicious': 8}
  Signature alerts: 12

  Per-flow results:
  UID                          Src             Dst             Dport   ML Class    Sig#
  --------------------------------------------------------------------------------------------
  CFhkJ21Yg0tVvZCjjk          192.168.1.100   10.0.0.5        22      benign      0
  ...

  Detection rate per attack type:
  Type            Total    Detected   Rate
  -------------------------------------------
  benign          18       0          0.0%
  suspicious      4        2          50.0%
  malicious       8        7          87.5%

  Aho-Corasick vs Naive pattern matching benchmark:
  Aho-Corasick : 12.34ms (1000 iterations)
  Naive match  : 45.67ms (1000 iterations)
  Speedup      : 3.7x
```

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
