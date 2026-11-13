#!/usr/bin/env python3
"""
services_from_loot — name the ports the loot shows that services.yml does not.

    python3 services_from_loot.py --loot loot-ossec/ --defs def/

`firru synth` reports every (protocol, port) it cannot name and leaves the term
carrying a bare number. This turns that report into `def/services-observed.yml`,
which Aerleon loads alongside the curated file.

TWO FILES, ON PURPOSE. `services.yml` is a curated set whose port definitions
follow vendor references -- HTTPS is 443 because the registry says so, and that
is true of every deployment. This file is the opposite kind of claim: these
ports are what *these* hosts were observed listening on, and the process name
beside each one is the only evidence for what it is. Merging them would make
the second kind of statement look like the first.

WHAT IS LEFT OUT, and both cases follow synthesis rather than collection. The
loot is the observed record and keeps everything; this file names what could
become a term, so it has to make the same two calls `listeners-to-aerleon`
makes.

A service bound only to 127.0.0.1 is not reachable off-host, so synthesis emits
no term for it and a token naming it is dead weight. Across the LSPR24 fleet 42
ports never appear on any other address -- kubelet's 10248, xrdp-sesman's 3350,
chronyd's 323 -- and a port bound both ways still counts, because the other
address is what the term is for.

A port in the kernel's ephemeral range that some process happened to be holding
is not a service either: it is a different number after the next restart, so a
term naming it is a rule that will never match again. The range is the one
`loot-diff` already assumes for detecting exactly this (32768-60999 on Linux),
reused rather than restated. Ports registered inside that range are kept by
name -- MySQL's X Protocol really does live on 33060 -- and each exception says
why.

Everything dropped is listed in the file's trailing comment with its process
and host, because "not a service" is a judgment the reader may want to
overturn, and a silent omission gives them nothing to overturn.
"""

import argparse
import collections
import ipaddress
import json
import pathlib
import re
import sys

import yaml

from firru.cli.loot_diff import DEFAULT_EPHEMERAL, ephemeral_for

# Registered services that fall inside the ephemeral range. The range test is a
# heuristic about who *assigned* the port; these were assigned by the registry.
REGISTERED_IN_RANGE = {
    ("tcp", 33060): "MySQL X Protocol",
    ("tcp", 47001): "Windows Remote Management (WinRM) over HTTP",
    ("udp", 33434): "traceroute",
}


def covered(defs_dir):
    """Every (proto, port) the curated service files already name."""
    out = set()
    for path in sorted(pathlib.Path(defs_dir).glob("*.yml")):
        if path.name == "services-observed.yml":
            continue
        for entries in (yaml.safe_load(path.read_text()) or {}).get("services", {}).values():
            for e in entries or []:
                if not isinstance(e, dict) or "port" not in e:
                    continue          # a group reference; its members expand
                proto = e.get("protocol", "tcp")
                lo, _, hi = str(e["port"]).partition("-")
                for p in range(int(lo), int(hi or lo) + 1):
                    out.add((proto, p))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--loot", default="loot-ossec", metavar="DIR")
    ap.add_argument("--defs", default="def", metavar="DIR")
    ap.add_argument("--ephemeral", default=None, metavar="LO-HI",
                    help=f"override the ephemeral range "
                         f"(default {DEFAULT_EPHEMERAL[0]}-{DEFAULT_EPHEMERAL[1]})")
    args = ap.parse_args()

    lo, hi = DEFAULT_EPHEMERAL
    if args.ephemeral:
        lo, hi = (int(x) for x in args.ephemeral.split("-"))

    known = covered(args.defs)
    seen = collections.defaultdict(lambda: {"procs": collections.Counter(),
                                            "hosts": set(), "offhost": False,
                                            "eph": True})
    for path in sorted(pathlib.Path(args.loot).glob("*.json")):
        doc = json.loads(path.read_text())
        host = doc["metadata"]["hostname"]
        for e in doc["listen_ports"]:
            key = (e["protocol"], e["port"])
            if key in known:
                continue
            rec = seen[key]
            rec["hosts"].add(host)
            # The range is per host: Windows keeps 32768-49151 across restarts
            # where Linux churns it at 0.85, so one fleet-wide range mislabels
            # whichever OS it was not written for. A port is ephemeral only if
            # it falls in the range of every host that listens on it.
            lo_h, hi_h = ephemeral_for(doc, args.ephemeral and (lo, hi))
            rec["eph"] = rec["eph"] and (lo_h <= e["port"] <= hi_h)
            addr = ipaddress.ip_address(e["bind_address"].split("/")[0])
            rec["offhost"] = rec["offhost"] or not addr.is_loopback
            name = (e.get("process") or {}).get("name")
            if name and name.strip():
                rec["procs"][name.strip()] += 1

    named, dropped, loopback = {}, {}, {}
    for key in sorted(seen, key=lambda k: (k[0], k[1])):
        proto, port = key
        if not seen[key]["offhost"]:
            loopback[key] = seen[key]
        elif seen[key]["eph"] and key not in REGISTERED_IN_RANGE:
            dropped[key] = seen[key]
        else:
            named[key] = seen[key]

    def note(rec):
        procs = ", ".join(f"{p}" for p, _ in rec["procs"].most_common(3)) or "no process name"
        hosts = sorted(rec["hosts"])
        shown = ", ".join(hosts[:4]) + (f", +{len(hosts) - 4} more" if len(hosts) > 4 else "")
        return f"{procs} on {shown}"

    lines = [
        "# services-observed.yml -- generated by services_from_loot.py.",
        "#",
        "# Ports these hosts were seen listening on that the curated",
        "# services.yml does not name. The evidence for what each one is is the",
        "# process name beside it and nothing else, which is a weaker claim than",
        "# the curated file makes; that is why the two are separate files.",
        "#",
        "# Two kinds of port are excluded, both because synthesis would emit no",
        "# term for them: those bound only to loopback, which are unreachable",
        f"# off-host, and those in the ephemeral range ({lo}-{hi}), which are a",
        "# different number after the next restart. Both are listed at the end",
        "# of this file rather than dropped silently.",
        "services:",
    ]
    for (proto, port), rec in named.items():
        token = f"{proto.upper()}_{port}"
        why = REGISTERED_IN_RANGE.get((proto, port))
        lines.append(f"  {token}:   # {note(rec)}"
                     + (f" -- {why}, registered despite the range" if why else ""))
        lines.append(f"    - port: {port}")
        lines.append(f"      protocol: {proto}")
    lines.append("")
    lines.append(f"# Excluded, loopback-bound only ({len(loopback)} ports). Never reachable")
    lines.append("# off-host, so no term would name them:")
    for (proto, port), rec in loopback.items():
        lines.append(f"#   {proto}/{port:<6} {note(rec)}")
    lines.append("")
    lines.append(f"# Excluded as ephemeral ({len(dropped)} ports). Move one up into the")
    lines.append("# block above if it is in fact a fixed listener on these hosts:")
    for (proto, port), rec in dropped.items():
        lines.append(f"#   {proto}/{port:<6} {note(rec)}")

    out = pathlib.Path(args.defs) / "services-observed.yml"
    out.write_text("\n".join(lines) + "\n")
    print(f"{len(named)} tokens -> {out}")
    print(f"  {len(loopback)} excluded as loopback-only, "
          f"{len(dropped)} as ephemeral (per-host range from the OS)")
    if REGISTERED_IN_RANGE:
        kept = [f"{p}/{n}" for (p, n) in named if (p, n) in REGISTERED_IN_RANGE]
        if kept:
            print(f"  kept despite the range: {', '.join(kept)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
