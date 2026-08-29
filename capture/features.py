"""
Flow feature extraction.

A 'flow' here is a rolling window of traffic grouped by source IP.
We keep it deliberately simple (no full 5-tuple state machine) so the
project is easy to read, extend, and explain in an interview.
"""

import time
from collections import defaultdict, deque


class FlowTracker:
    """
    Maintains a sliding window of packet metadata per source IP and
    turns it into a numeric feature vector the detector can score.
    """

    def __init__(self, window_seconds=10):
        self.window_seconds = window_seconds
        # src_ip -> deque of packet records (each a dict)
        self.windows = defaultdict(deque)

    def add_packet(self, record):
        """
        record: dict with keys
            ts, src_ip, dst_ip, dst_port, proto, length, flags
        """
        src = record["src_ip"]
        dq = self.windows[src]
        dq.append(record)
        self._trim(dq, record["ts"])

    def _trim(self, dq, now_ts):
        while dq and now_ts - dq[0]["ts"] > self.window_seconds:
            dq.popleft()

    def snapshot_features(self):
        """
        Returns {src_ip: feature_dict} for every IP with recent activity.
        Called on a timer by the detector loop.
        """
        now = time.time()
        out = {}
        for src, dq in list(self.windows.items()):
            self._trim(dq, now)
            if not dq:
                del self.windows[src]
                continue
            out[src] = self._features_for(dq)
        return out

    @staticmethod
    def _features_for(dq):
        pkt_count = len(dq)
        total_bytes = sum(p["length"] for p in dq)
        unique_dst_ips = len({p["dst_ip"] for p in dq})
        unique_dst_ports = len({p["dst_port"] for p in dq if p["dst_port"] is not None})
        syn_count = sum(1 for p in dq if p.get("flags") == "S")
        span = max(p["ts"] for p in dq) - min(p["ts"] for p in dq)
        # Floor the span so a couple of packets arriving almost together
        # doesn't get divided by a near-zero window and produce an
        # artificially huge (false-positive) rate.
        span = max(span, 1.0)

        return {
            "pkt_rate": pkt_count / span,
            "byte_rate": total_bytes / span,
            "unique_dst_ips": unique_dst_ips,
            "unique_dst_ports": unique_dst_ports,
            "syn_ratio": syn_count / pkt_count if pkt_count else 0,
            "avg_pkt_size": total_bytes / pkt_count if pkt_count else 0,
        }


FEATURE_ORDER = [
    "pkt_rate",
    "byte_rate",
    "unique_dst_ips",
    "unique_dst_ports",
    "syn_ratio",
    "avg_pkt_size",
]


def to_vector(feature_dict):
    return [feature_dict[k] for k in FEATURE_ORDER]
