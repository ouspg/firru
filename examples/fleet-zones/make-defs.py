#!/usr/bin/env python3
"""The site's half of the definitions for the zoned fleet: one network per
zone, a token per host, the zone groups, and host_metadata.json naming each
host's zone. Private addresses and the IPv6 documentation prefix; none of it
is real.

    python3 make-defs.py def/
"""
import json
import sys
from pathlib import Path

ZONES = {  # zone: (v4 /24, v6 /64, {host: last octet})
    "DMZ":     ("10.20.1", "2001:db8:20:1", {"web1": 10, "mail1": 11, "ns1": 12}),
    "SERVERS": ("10.20.2", "2001:db8:20:2", {"dc1": 10, "files1": 11, "print1": 12,
                                             "db1": 13, "smb1": 14}),
    "CLIENTS": ("10.20.3", "2001:db8:20:3", {"ws1": 21, "ws2": 22, "ws3": 23}),
    "MGMT":    ("10.20.9", "2001:db8:20:9", {"jump1": 10}),
}


def main(out):
    out = Path(out)
    lines = ["networks:"]
    meta = {}
    for zone, (v4, v6, hosts) in ZONES.items():
        lines += [f"  {zone}:", "    values:",
                  f"      - address: {v4}.0/24", f"      - address: {v6}::/64"]
        lines += [f"  {zone}_HOSTS:", "    values:"] + [f"      - name: {h}" for h in hosts]
        for h, n in hosts.items():
            lines += [f"  {h}:", "    values:",
                      f"      - address: {v4}.{n}/32", f"      - address: {v6}::{n:x}/128"]
            meta[h] = {"zone": zone}
    (out / "networks.yml").write_text("\n".join(lines) + "\n")
    (out / "host_metadata.json").write_text(json.dumps(meta, indent=2) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
