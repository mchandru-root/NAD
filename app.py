"""
Network Anomaly Detector - Flask app

Modes:
    python app.py --mode replay   (default, no root needed, safe for hosting)
    sudo python app.py --mode live --iface eth0   (real packet capture, local only)
"""

import argparse
import threading
import time

from flask import Flask, jsonify, render_template

from capture.features import FlowTracker
from capture.detector import AnomalyDetector
from capture.replay import ReplayGenerator

app = Flask(__name__)

tracker = FlowTracker(window_seconds=10)
detector = AnomalyDetector(tracker)

STATE = {"mode": "replay", "running": True, "started_at": time.time()}


def replay_loop():
    gen = ReplayGenerator(tracker)
    while STATE["running"]:
        gen.step()
        time.sleep(0.15)


def live_loop(iface):
    from capture.sniffer import LiveSniffer

    sniffer = LiveSniffer(tracker, iface=iface)
    sniffer.start()
    while STATE["running"]:
        time.sleep(1)


def detection_loop():
    while STATE["running"]:
        detector.tick()
        time.sleep(2)


@app.route("/")
def index():
    return render_template("index.html", mode=STATE["mode"])


@app.route("/api/status")
def status():
    return jsonify(
        {
            "mode": STATE["mode"],
            "uptime_seconds": round(time.time() - STATE["started_at"]),
            "tracked_hosts": len(tracker.windows),
            "total_alerts": len(detector.alerts),
            "model_fitted": detector.fitted,
        }
    )


@app.route("/api/alerts")
def alerts():
    return jsonify(detector.alerts[:50])


@app.route("/api/flows")
def flows():
    snap = tracker.snapshot_features()
    return jsonify(
        [{"src_ip": ip, "features": f} for ip, f in sorted(snap.items())]
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["replay", "live"], default="replay")
    parser.add_argument("--iface", default=None, help="Interface for live mode")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    STATE["mode"] = args.mode

    if args.mode == "live":
        threading.Thread(target=live_loop, args=(args.iface,), daemon=True).start()
    else:
        threading.Thread(target=replay_loop, daemon=True).start()

    threading.Thread(target=detection_loop, daemon=True).start()

    app.run(host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()
