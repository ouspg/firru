#!/usr/bin/env python3
"""Synthetic flows for the zoned fleet, in the flow record
(docs/flow-record.md). Not a capture: a day of made-up traffic with a few
patterns for tighten to decide. Fixed seed, so every run writes the same file.

  internet -> web1 80,443, mail1 25, ns1 53   stays ANY (no asset behind it)
  CLIENTS  -> dc1 88,389,445,135, files1 445   narrows to the clients
  web1     -> db1 5432, and ws2 a few times    tighten keeps both; the review
                                               keeps web1 (run.sh, step 6)
  jump1    -> every server's SSH/RDP           already jump1 by the profile

    python3 make-flows.py > flows.jsonl
"""
import json
import random

random.seed(1)
T0 = 1792800000.0                      # 2026-10-23T08:00:00Z
IP = {"web1": "10.20.1.10", "mail1": "10.20.1.11", "ns1": "10.20.1.12",
      "dc1": "10.20.2.10", "files1": "10.20.2.11", "db1": "10.20.2.13",
      "smb1": "10.20.2.14", "ws1": "10.20.3.21", "ws2": "10.20.3.22",
      "ws3": "10.20.3.23", "jump1": "10.20.9.10"}
CLIENTS = ["ws1", "ws2", "ws3"]


def flows(src, dst, dport, n, proto="tcp"):
    for _ in range(n):
        ts = T0 + random.uniform(0, 86400)
        yield {"protocol": proto, "src_ip": src, "dst_ip": dst,
               "src_port": random.randint(32768, 60999), "dst_port": dport,
               "originator": src, "timestamp": ts, "end_time": ts + 0.4,
               "orig_pkts": 6, "resp_pkts": 5, "responded": True,
               "source": "zeek", "direction_known": True}


def internet():
    net = random.choice(["198.51.100", "203.0.113", "192.0.2"])  # documentation ranges
    return f"{net}.{random.randint(1, 254)}"


out = []
for _ in range(40):
    out += flows(internet(), IP["web1"], random.choice([80, 443]), random.randint(1, 20))
for _ in range(15):
    out += flows(internet(), IP["mail1"], 25, random.randint(1, 5))
for _ in range(30):
    out += flows(internet(), IP["ns1"], 53, random.randint(1, 10), proto="udp")
for c in CLIENTS:
    for port, n in ((88, 40), (389, 60), (445, 20), (135, 10)):
        out += flows(IP[c], IP["dc1"], port, n)
    out += flows(IP[c], IP["files1"], 445, 30)
out += flows(IP["web1"], IP["db1"], 5432, 500)
out += flows(IP["ws2"], IP["db1"], 5432, 3)
for h in ("web1", "mail1", "ns1", "db1", "smb1"):
    out += flows(IP["jump1"], IP[h], 22, 4)
for h in ("dc1", "files1"):
    out += flows(IP["jump1"], IP[h], 3389, 2)
for r in sorted(out, key=lambda r: r["timestamp"]):
    print(json.dumps(r))
