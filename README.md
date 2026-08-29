Network Anomaly Detector

A lightweight SOC-style tool that watches network traffic flows and flags
anomalies in real time, combining rule-based detection (port scans, SYN
floods, host sweeps) with an Isolation Forest model for outliers that don't
match a known signature. Live-updating web dashboard built with Flask.

## Why this project

Built to demonstrate practical SOC/network-monitoring skills: flow-based
feature extraction, MITRE ATT&CK-mapped detection rules, and anomaly
scoring with a real ML model — not just a log viewer.

## How it works

```
packets (live capture or replay) 
      -> FlowTracker: 10s rolling window per source IP
      -> feature vector: pkt/s, bytes/s, unique dst IPs/ports, SYN ratio, avg pkt size
      -> AnomalyDetector:
            - rule engine (port scan / SYN flood / host sweep / volume exfil)
            - Isolation Forest, retrained periodically on recent traffic
      -> Flask API (/api/status, /api/flows, /api/alerts)
      -> dashboard polls every 2s and renders live
```

Two run modes:

- **`replay` (default)** — generates realistic synthetic background traffic
  with randomly injected attack bursts. No special permissions needed, so
  this is what runs on the hosted demo.
- **`live`** — captures real packets on a network interface via `scapy`.
  Requires root/administrator privileges and a local machine (raw sockets
  aren't available on most hosting platforms).

## Run locally

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Safe demo mode (synthetic traffic, no root required)
python app.py --mode replay

# Real packet capture (requires root, Linux/macOS shown)
sudo venv/bin/python app.py --mode live --iface eth0
```

Then open `http://localhost:5000`.

## Deploy the live demo

This ships in `replay` mode by default, which is exactly what you want for
a public demo — no raw sockets, no risk, works anywhere.


## Project structure

```
├── app.py                  # Flask app, API routes, run loops
├── capture/
│   ├── features.py         # FlowTracker: rolling window -> feature vectors
│   ├── sniffer.py          # scapy live capture (local, root required)
│   ├── replay.py           # synthetic traffic generator (hosted demo)
│   └── detector.py         # rule engine + Isolation Forest scoring
├── templates/index.html    # dashboard markup
├── static/style.css        # NOC-style dashboard theme
├── static/dashboard.js     # polling + rendering
└── requirements.txt
```

## Detection logic

| Rule | Trigger | MITRE ATT&CK |
|---|---|---|
| Port scan | ≥15 unique destination ports from one source in 10s | T1046 |
| SYN flood | SYN ratio ≥0.8 and packet rate ≥20/s | T1499 |
| Host sweep | ≥10 unique destination IPs from one source in 10s | T1018 |
| Volume exfil | Byte rate ≥500KB/s sustained | T1041 |
| ML outlier | Isolation Forest flags the feature vector regardless of rule match | — |

The Isolation Forest is retrained every 10 new observations on the most
recent 500 samples, so it adapts to what "normal" looks like on the network
it's watching rather than using fixed global thresholds.

## Possible extensions

- Persist alerts to SQLite/Postgres instead of in-memory
- Replace synthetic replay with a real pcap/CSV dataset (e.g. CICIDS2017)
- Add Slack/email webhook notifications on critical alerts
- Swap Isolation Forest for an autoencoder for richer feature spaces

## Tech stack

Python, Flask, scapy, scikit-learn (Isolation Forest), vanilla JS/CSS
dashboard.

