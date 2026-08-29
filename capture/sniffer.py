"""
Live packet capture using scapy.

Requires root/administrator privileges to open a raw socket:
    sudo python app.py --mode live

Not used when the app runs in --mode replay (e.g. on a hosted demo
server where raw sockets aren't available).
"""

import time
import threading

from scapy.all import sniff, IP, TCP, UDP


class LiveSniffer:
    def __init__(self, tracker, iface=None):
        self.tracker = tracker
        self.iface = iface
        self._thread = None
        self._stop = threading.Event()

    def _handle_packet(self, pkt):
        if IP not in pkt:
            return

        proto = "OTHER"
        dst_port = None
        flags = None

        if TCP in pkt:
            proto = "TCP"
            dst_port = pkt[TCP].dport
            flag_bits = pkt[TCP].flags
            flags = "S" if flag_bits & 0x02 and not flag_bits & 0x10 else str(flag_bits)
        elif UDP in pkt:
            proto = "UDP"
            dst_port = pkt[UDP].dport

        record = {
            "ts": time.time(),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "dst_port": dst_port,
            "proto": proto,
            "length": len(pkt),
            "flags": flags,
        }
        self.tracker.add_packet(record)

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        sniff(
            iface=self.iface,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda p: self._stop.is_set(),
        )

    def stop(self):
        self._stop.set()
