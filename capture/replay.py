"""
Replay mode: generates realistic-looking traffic (normal background
noise plus injected attack patterns) so the hosted demo works without
root privileges or real network access.

Swap `generate_packet()` for a pcap/CSV reader if you want to replay
a real captured dataset (e.g. CICIDS2017) instead.
"""

import random
import time

NORMAL_HOSTS = [f"10.0.0.{i}" for i in range(2, 20)]
EXTERNAL_HOSTS = [f"172.16.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(30)]
COMMON_PORTS = [80, 443, 53, 22, 25, 3306]


class ReplayGenerator:
    """
    Call step() roughly every 100-200ms from a background thread; each
    call feeds 1-5 synthetic packets into the tracker, occasionally
    bursting an attack pattern from one random "attacker" host.
    """

    def __init__(self, tracker, attack_interval=(15, 30)):
        self.tracker = tracker
        self.attack_interval = attack_interval
        self._next_attack_at = time.time() + random.uniform(*attack_interval)
        self._attack_until = 0
        self._attack_type = None
        self._attacker_ip = None

    def _start_attack(self):
        self._attack_type = random.choice(["port_scan", "syn_flood", "host_sweep"])
        self._attacker_ip = random.choice(EXTERNAL_HOSTS)
        self._attack_until = time.time() + random.uniform(3, 6)

    def _normal_packet(self):
        return {
            "ts": time.time(),
            "src_ip": random.choice(NORMAL_HOSTS),
            "dst_ip": random.choice(EXTERNAL_HOSTS),
            "dst_port": random.choice(COMMON_PORTS),
            "proto": "TCP",
            "length": random.randint(60, 1500),
            "flags": None,
        }

    def _attack_packet(self):
        if self._attack_type == "port_scan":
            return {
                "ts": time.time(),
                "src_ip": self._attacker_ip,
                "dst_ip": random.choice(NORMAL_HOSTS),
                "dst_port": random.randint(1, 65535),
                "proto": "TCP",
                "length": 60,
                "flags": "S",
            }
        if self._attack_type == "syn_flood":
            return {
                "ts": time.time(),
                "src_ip": self._attacker_ip,
                "dst_ip": random.choice(NORMAL_HOSTS),
                "dst_port": 80,
                "proto": "TCP",
                "length": 60,
                "flags": "S",
            }
        if self._attack_type == "host_sweep":
            return {
                "ts": time.time(),
                "src_ip": self._attacker_ip,
                "dst_ip": f"10.0.0.{random.randint(2,254)}",
                "dst_port": 445,
                "proto": "TCP",
                "length": 60,
                "flags": "S",
            }

    def step(self):
        now = time.time()

        if now >= self._next_attack_at and now > self._attack_until:
            self._start_attack()

        in_attack = now < self._attack_until

        n_packets = random.randint(3, 8) if in_attack else random.randint(1, 3)
        for _ in range(n_packets):
            record = self._attack_packet() if in_attack else self._normal_packet()
            self.tracker.add_packet(record)

        if not in_attack and now >= self._next_attack_at:
            self._next_attack_at = now + random.uniform(*self.attack_interval)
