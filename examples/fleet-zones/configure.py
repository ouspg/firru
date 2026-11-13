#!/usr/bin/env python3
"""What the site changed from stock, applied to normalized loot. A stock
install is not yet a server: PostgreSQL and BIND answer only on loopback,
Apache has no TLS, Samba is installed but not started, and Ubuntu's task
installs come without sshd. Here those are configured the way a site would,
so the fleet has something to firewall. Edits the loot, not a host: it is a
stand-in for collecting from configured machines.

    python3 configure.py STOCK_DIR OUT_DIR
"""
import copy
import json
import sys
from pathlib import Path

ANY = ("0.0.0.0/0", "::/0")


def listener(proto, port, name, exe, bind):
    return {"protocol": proto, "port": port, "bind_address": bind,
            "process": {"name": name, "exe": exe, "cmdline": exe, "services": [],
                        "user": None, "pid": None},
            "flags": ["world-listen", "well-known"]}


def serve(proto, port, name, exe):
    return [listener(proto, port, name, exe, b) for b in ANY]


SSHD = serve("tcp", 22, "sshd", "/usr/sbin/sshd")
CHANGES = {
    "web1":  serve("tcp", 443, "apache2", "/usr/sbin/apache2") + SSHD,
    "mail1": SSHD,
    "ns1":   serve("udp", 53, "named", "/usr/sbin/named") + serve("tcp", 53, "named", "/usr/sbin/named"),
    "db1":   serve("tcp", 5432, "postgres", "/usr/lib/postgresql/16/bin/postgres") + SSHD,
    "smb1":  serve("tcp", 445, "smbd", "/usr/sbin/smbd"),
}


def main(stock, out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for p in sorted(Path(stock).glob("*.json")):
        doc = json.loads(p.read_text())
        host = doc["metadata"]["hostname"]
        added = copy.deepcopy(CHANGES.get(host, []))
        have = {(l["protocol"], l["port"], l["bind_address"]) for l in doc["listen_ports"]}
        doc["listen_ports"] += [l for l in added
                                if (l["protocol"], l["port"], l["bind_address"]) not in have]
        (out / p.name).write_text(json.dumps(doc, indent=2) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:3])
