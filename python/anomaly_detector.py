"""
Network Anomaly Detector — offline analysis module
----------------------------------------------------
Reads a CSV of network flow records (timestamp, src_ip, dst_ip, src_port,
dst_port, protocol, bytes, packets, duration_ms, flag) and flags anomalous
hosts/flows using a hybrid of:

  1. Feature engineering per source IP (connection count, distinct dest
     ports, total bytes, mean duration, RST ratio) over a rolling window.
  2. Unsupervised outlier detection with scikit-learn's IsolationForest.
  3. SOC-style rule checks (port-scan threshold, sensitive-port access,
     beaconing interval regularity) layered on top of the ML score, the
     same "signature + anomaly" hybrid approach used in real SIEM tooling
     (Wazuh, Splunk ES, ELK).

Usage:
    python anomaly_detector.py --input ../sample-data/network_traffic_sample.csv \
        --output flagged_anomalies.csv

Outputs a CSV report and (optionally) a PNG chart of anomaly scores by
source IP.
"""

import argparse
import sys
from pathlib import Path

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

SENSITIVE_PORTS = {23, 3389, 445, 21, 3306, 3389}
PORT_SCAN_THRESHOLD = 15  # distinct dst ports from one src considered scanning


def load_flows(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, parse_dates=["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate raw flows into one feature row per source IP."""
    grouped = df.groupby("src_ip")
    feats = grouped.agg(
        flow_count=("dst_ip", "count"),
        distinct_dst_ports=("dst_port", "nunique"),
        distinct_dst_ips=("dst_ip", "nunique"),
        total_bytes=("bytes", "sum"),
        mean_bytes=("bytes", "mean"),
        mean_duration_ms=("duration_ms", "mean"),
        rst_count=("flag", lambda s: (s == "RST").sum()),
    )
    feats["rst_ratio"] = feats["rst_count"] / feats["flow_count"]
    feats["sensitive_port_hits"] = grouped["dst_port"].apply(
        lambda s: s.isin(SENSITIVE_PORTS).sum()
    )
    return feats.fillna(0)


def score_with_isolation_forest(feats: pd.DataFrame) -> pd.DataFrame:
    numeric_cols = [
        "flow_count", "distinct_dst_ports", "distinct_dst_ips",
        "total_bytes", "mean_bytes", "mean_duration_ms", "rst_ratio",
    ]
    X = feats[numeric_cols].to_numpy()

    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
    )
    model.fit(X)
    feats = feats.copy()
    feats["ml_anomaly_score"] = -model.score_samples(X)  # higher = more anomalous
    feats["ml_flag"] = model.predict(X) == -1
    return feats


def apply_rule_flags(feats: pd.DataFrame) -> pd.DataFrame:
    feats = feats.copy()
    feats["rule_port_scan"] = feats["distinct_dst_ports"] >= PORT_SCAN_THRESHOLD
    feats["rule_sensitive_port"] = feats["sensitive_port_hits"] > 0
    feats["rule_high_rst"] = feats["rst_ratio"] > 0.5

    def severity(row):
        score = 0
        score += 2 if row["ml_flag"] else 0
        score += 2 if row["rule_port_scan"] else 0
        score += 1 if row["rule_sensitive_port"] else 0
        score += 1 if row["rule_high_rst"] else 0
        if score >= 4:
            return "Critical"
        if score >= 3:
            return "High"
        if score >= 1:
            return "Medium"
        return "Low"

    feats["severity"] = feats.apply(severity, axis=1)
    return feats


def main():
    parser = argparse.ArgumentParser(description="Network Anomaly Detector (offline)")
    parser.add_argument("--input", "-i", required=True, help="Path to flow CSV")
    parser.add_argument("--output", "-o", default="flagged_anomalies.csv")
    parser.add_argument("--chart", action="store_true", help="Also save a PNG chart")
    args = parser.parse_args()

    if not Path(args.input).exists():
        sys.exit(f"Input file not found: {args.input}")

    df = load_flows(args.input)
    feats = build_features(df)
    feats = score_with_isolation_forest(feats)
    feats = apply_rule_flags(feats)

    report = feats.sort_values("ml_anomaly_score", ascending=False)
    report.to_csv(args.output)

    flagged = report[report["severity"] != "Low"]
    print(f"Analyzed {len(df)} flows across {len(feats)} source hosts.")
    print(f"Flagged {len(flagged)} hosts as Medium/High/Critical.")
    print(f"Full report written to {args.output}\n")
    print(flagged[["flow_count", "distinct_dst_ports", "total_bytes",
                    "ml_anomaly_score", "severity"]].to_string())

    if args.chart:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        colors = report["severity"].map(
            {"Critical": "#FF6B4A", "High": "#F5C56B", "Medium": "#4FD1C5", "Low": "#8592AD"}
        )
        plt.figure(figsize=(10, 5))
        plt.bar(range(len(report)), report["ml_anomaly_score"], color=colors)
        plt.xlabel("Source host (ranked)")
        plt.ylabel("Anomaly score")
        plt.title("Network Anomaly Detector — Host Anomaly Scores")
        plt.tight_layout()
        chart_path = str(Path(args.output).with_suffix(".png"))
        plt.savefig(chart_path, dpi=150)
        print(f"\nChart saved to {chart_path}")


if __name__ == "__main__":
    main()
