#!/usr/bin/env python3
"""Synthetic flows for the fleet walk-through, in the flow record
(docs/flow-record.md). Not a capture: made up so that tighten has something
to decide, and then something to stop. Fixed seeds, so every run writes the
same files.

Day 1, the learning window: three patterns.

  mon1 tcp/4949  polled by one monitoring host     -> narrows to MONITORING
  win1 tcp/22    from two admin workstations        -> narrows to ADMIN
  web1 tcp/80    from 40 scattered internet clients -> stays ANY

Day 2: the same, and an attacker. 203.0.113.99 probes web1, tries passwords
on win1's SSH and sends requests at web1's web server; then, from web1, it
reaches for mon1's munin port and the domain controller. A refused
connection is recorded unanswered, as the firewall in force (day 1's
narrowed policy) would leave it.

    python3 make-flows.py 1 > flows.jsonl
    python3 make-flows.py 2 > flows-day2.jsonl
"""
import json
import random
import sys

DAY = int(sys.argv[1]) if len(sys.argv) > 1 else 1
random.seed(DAY)
T0 = 1792800000.0 + (DAY - 1) * 86400  # 2026-10-23T08:00:00Z, then the next day
MON1, WIN1, WEB1, DC1 = "192.168.150.169", "192.168.150.184", "192.168.150.126", "192.168.150.194"
ATTACKER = "203.0.113.99"


def flows(src, dst, dport, n, responded=True):
    for _ in range(n):
        ts = T0 + random.uniform(0, 86400)
        yield {"protocol": "tcp", "src_ip": src, "dst_ip": dst,
               "src_port": random.randint(32768, 60999), "dst_port": dport,
               "originator": src, "timestamp": ts, "end_time": ts + 0.4,
               "orig_pkts": 6 if responded else 2, "resp_pkts": 5 if responded else 0,
               "responded": responded, "source": "zeek", "direction_known": True}


out = []
out += flows("192.168.150.250", MON1, 4949, 288)     # every 5 minutes for a day
out += flows("192.168.150.3", WIN1, 22, 12)
out += flows("192.168.150.9", WIN1, 22, 4)
for _ in range(40):                                  # documentation ranges only
    net = random.choice(["198.51.100", "203.0.113", "192.0.2"])
    out += flows(f"{net}.{random.randint(1, 254)}", WEB1, 80, random.randint(1, 20))
if DAY == 2:
    for port in (21, 22, 23, 25, 443, 3306, 4949, 8080):  # a port scan: nothing answers
        out += flows(ATTACKER, WEB1, port, 1, responded=False)
    out += flows(ATTACKER, WEB1, 80, 30)              # the web server answers anyone
    out += flows(ATTACKER, WIN1, 22, 200, responded=False)  # passwords, against ADMIN only
    out += flows(WEB1, MON1, 4949, 3, responded=False)      # from web1, now the attacker's
    out += flows(WEB1, DC1, 389, 6)                   # nobody used LDAP on day 1
    out += flows(WEB1, DC1, 445, 4)
for r in sorted(out, key=lambda r: r["timestamp"]):
    print(json.dumps(r))
