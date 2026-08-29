import csv, random, datetime

random.seed(42)
start = datetime.datetime(2026, 8, 24, 9, 0, 0)
rows = []

internal_hosts = [f"10.0.0.{i}" for i in range(10, 40)]
external_hosts = [f"203.0.113.{i}" for i in range(1, 60)] + [f"198.51.100.{i}" for i in range(1, 40)]
common_ports = [80, 443, 53, 22, 25]
sensitive_ports = [23, 3389, 445, 21, 3306]
protocols = ["TCP", "UDP"]
flags = ["SYN", "SYN-ACK", "ACK", "FIN", "RST"]

t = start
def add_flow(src, dst, sport, dport, proto, nbytes, npackets, dur, flag):
    global t
    t += datetime.timedelta(seconds=random.uniform(0.2, 3))
    rows.append([t.isoformat(sep=" "), src, dst, sport, dport, proto, nbytes, npackets, dur, flag])

# 1. Normal baseline traffic
for _ in range(420):
    src = random.choice(internal_hosts)
    dst = random.choice(external_hosts)
    dport = random.choice(common_ports)
    sport = random.randint(1024, 65000)
    proto = "TCP" if dport != 53 else "UDP"
    nbytes = random.randint(200, 15000)
    npackets = max(1, nbytes // 500)
    dur = random.randint(10, 2000)
    flag = random.choice(["SYN-ACK", "ACK", "FIN"])
    add_flow(src, dst, sport, dport, proto, nbytes, npackets, dur, flag)

# 2. Port scan: single internal host hits 40 distinct ports on one external host rapidly
scanner = "10.0.0.17"
target = "198.51.100.9"
for p in range(1, 45):
    add_flow(scanner, target, random.randint(40000, 60000), p*111 % 60000 + 20, "TCP", random.randint(40, 90), 1, random.randint(1, 15), "SYN")

# 3. Volume anomaly: huge exfil-style transfer from one host
exfil_src = "10.0.0.25"
exfil_dst = "203.0.113.44"
for _ in range(6):
    add_flow(exfil_src, exfil_dst, random.randint(1024, 65000), 443, "TCP", random.randint(4_000_000, 9_000_000), random.randint(3000, 6000), random.randint(2000, 5000), "ACK")

# 4. Beaconing: regular small callbacks to same external IP every ~30s
beacon_src = "10.0.0.31"
beacon_dst = "203.0.113.201"
bt = start + datetime.timedelta(minutes=2)
for _ in range(20):
    bt += datetime.timedelta(seconds=30)
    rows.append([bt.isoformat(sep=" "), beacon_src, beacon_dst, random.randint(50000, 51000), 443, "TCP", random.randint(180, 260), 2, random.randint(50, 90), "ACK"])

# 5. Sensitive port access from external-looking source
susp_src = "198.51.100.77"
susp_dst = "10.0.0.12"
for port in [3389, 445, 23]:
    add_flow(susp_src, susp_dst, random.randint(1024, 60000), port, "TCP", random.randint(60, 400), random.randint(1, 4), random.randint(5, 60), "SYN")

# 6. Brute-force-like RST pattern
bf_src = "10.0.0.19"
bf_dst = "203.0.113.5"
for _ in range(25):
    add_flow(bf_src, bf_dst, random.randint(30000, 40000), 22, "TCP", random.randint(50, 120), 1, random.randint(1, 8), "RST")

rows.sort(key=lambda r: r[0])

with open("sample-data/network_traffic_sample.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["timestamp","src_ip","dst_ip","src_port","dst_port","protocol","bytes","packets","duration_ms","flag"])
    w.writerows(rows)

print(f"wrote {len(rows)} flows")
