"""
Detection engine: rule-based checks for well-known attack signatures,
plus an Isolation Forest model for catching anomalies that don't match
a fixed rule (the "unknown unknowns" a pure signature system misses).
"""

import time
import numpy as np
from sklearn.ensemble import IsolationForest

from .features import FEATURE_ORDER, to_vector

# Thresholds tuned for a small LAN demo, not production traffic volumes.
RULES = {
    "port_scan": lambda f: f["unique_dst_ports"] >= 15,
    "syn_flood": lambda f: f["syn_ratio"] >= 0.8 and f["pkt_rate"] >= 20,
    "exfil_volume": lambda f: f["byte_rate"] >= 500_000,
    "host_sweep": lambda f: f["unique_dst_ips"] >= 10,
}

MITRE_TAGS = {
    "port_scan": "T1046 - Network Service Discovery",
    "syn_flood": "T1499 - Endpoint Denial of Service",
    "exfil_volume": "T1041 - Exfiltration Over C2 Channel",
    "host_sweep": "T1018 - Remote System Discovery",
}


class AnomalyDetector:
    def __init__(self, tracker, contamination=0.05, history_size=500):
        self.tracker = tracker
        self.model = IsolationForest(
            n_estimators=150, contamination=contamination, random_state=42
        )
        self.history = []  # list of feature vectors, used to (re)fit the model
        self.history_size = history_size
        self.fitted = False
        self.alerts = []  # most recent first
        self.max_alerts = 200

    def _maybe_fit(self):
        if len(self.history) >= 30 and len(self.history) % 10 == 0:
            X = np.array(self.history[-self.history_size:])
            self.model.fit(X)
            self.fitted = True

    def _rule_checks(self, src_ip, f):
        hits = []
        for name, check in RULES.items():
            if check(f):
                hits.append(name)
        return hits

    def tick(self):
        """
        Run one detection pass over the current flow window. Call this
        on a timer (e.g. every 2 seconds) from the app.
        """
        snapshot = self.tracker.snapshot_features()
        results = []

        for src_ip, f in snapshot.items():
            vec = to_vector(f)
            self.history.append(vec)
            rule_hits = self._rule_checks(src_ip, f)

            ml_score = None
            ml_flag = False
            if self.fitted:
                arr = np.array([vec])
                ml_score = float(self.model.decision_function(arr)[0])
                ml_flag = self.model.predict(arr)[0] == -1

            is_anomaly = bool(rule_hits) or ml_flag
            entry = {
                "ts": time.time(),
                "src_ip": src_ip,
                "features": f,
                "rule_hits": rule_hits,
                "ml_score": ml_score,
                "ml_flag": ml_flag,
                "is_anomaly": is_anomaly,
                "mitre": [MITRE_TAGS[r] for r in rule_hits],
            }
            results.append(entry)

            if is_anomaly:
                self.alerts.insert(0, entry)
                self.alerts = self.alerts[: self.max_alerts]

        self._maybe_fit()
        return results
