#!/usr/bin/env python3
"""
ossec-to-loot — loot inventories from a Wazuh/OSSEC archive.

    ossec-to-loot archive.json --output loot/
    ossec-to-loot archive.json --output loot/ --scan fullest
    ossec-to-loot archive.json --outdir-per-scan loot-series/   # time series

Reads the rootcheck `netstat listening ports` check, which dumps a host's whole
listening table on every scan. That completeness is the point: Wazuh's other
port source, syscollector's `dbsync_ports`, is a *delta* stream (INSERTED /
DELETED per socket), so a service that stays up all week emits nothing and the
feed is biased against exactly the durable listeners policy is about. On the
LSPR24 archive dbsync yields 84 distinct sockets on 13 agents; the netstat
check yields 883 on 50.

Each record's `full_log` holds netstat output in one of two shapes:

    tcp  0.0.0.0:22   0.0.0.0:*  /usr                 # 4 fields
    udp  0  0  0.0.0.0:4789  0.0.0.0:*  -             # 6, with Recv-Q/Send-Q

PROCESS ATTRIBUTION IS PARTIAL. The last field is `pid/name` where OSSEC could
read it, a bare truncated path (`/usr`) where it could not, and `-` where there
was nothing. Roughly half of LSPR24's entries are the truncated form, so a
name is recorded when available and left null otherwise rather than guessed.
That still beats flow-derived loot, which has no process field at all.

TWO SOURCES, SPLIT BY PLATFORM. The netstat check is a Unix rootcheck, so
Windows agents contribute nothing to it -- on LSPR24 all 50 netstat hosts are
Linux. Windows listening sockets appear only in syscollector's `dbsync_ports`,
which is used as a fallback for hosts the netstat check never covered. That
fallback is a *union over the capture window*, not a snapshot: dbsync reports
deltas, so a Windows service that never changed during the window is absent
and always will be. Good enough to exercise the Windows policy path with real
process attribution; not a basis for any claim about coverage.
`metadata.listenfile` records which source a host came from, because the two
do not mean the same thing.

LOOPBACK IS KEPT. Raw data is raw data: a service bound to 127.0.0.1 is
evidence the host was configured correctly, which is worth storing whether or
not anything downstream reads it. Synthesis, not collection, decides that such
a socket is not a policy subject (`listeners-to-aerleon` skips loopback binds).
`--skip-loopback` drops them here instead, matching what the older
`loot-listeners` collector does at capture time.
"""

import argparse
import collections
import ipaddress
import json
import pathlib
import sys

from firru.ephemeral import parse_range
from firru.tokens import is_loopback

MARKER = "netstat listening ports"
OSINFO = '"type":"dbsync_osinfo"'
DBPORTS = '"type":"dbsync_ports"'


def parse_line(line):
    """One netstat row -> (proto, bind_ip, port, pid, procname) or None."""
    f = line.split()
    if len(f) == 6:                      # proto recvq sendq local foreign proc
        proto, local, proc = f[0], f[3], f[5]
    elif len(f) == 4:                    # proto local foreign proc
        proto, local, proc = f[0], f[1], f[3]
    else:
        return None
    if ":" not in local:
        return None
    host, _, port = local.rpartition(":")
    if not port.isdigit():
        return None
    # netstat renders a v6 wildcard as ":::22", leaving "::" after rpartition.
    host = host or "::"

    pid = name = None
    if proc and proc != "-":
        if "/" in proc and proc.split("/", 1)[0].isdigit():
            pid, name = proc.split("/", 1)
        # else: a truncated path such as "/usr"; no reliable name to record
    return proto, host, int(port), pid, name


def to_cidr(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_unspecified:
        return "0.0.0.0/0" if addr.version == 4 else "::/0"
    return f"{ip}/{addr.max_prefixlen}"


def flags_for(cidr, port):
    f = ["world-listen"] if cidr in ("0.0.0.0/0", "::/0") else ["specific-ip"]
    f.append("well-known" if port < 1024 else "high-port")
    return sorted(f)


def entries_from(body, keep_loopback):
    """The listening table in one record, deduplicated and sorted."""
    seen = {}
    for line in body.split("\n")[1:]:
        parsed = parse_line(line.strip())
        if not parsed:
            continue
        proto, ip, port, pid, name = parsed
        try:
            if not keep_loopback and is_loopback(ip):
                continue
        except ValueError:
            continue
        cidr = to_cidr(ip)
        if cidr is None:
            continue
        # tcp6/udp6 are the same protocol; the family lives in the bind address.
        base = proto.rstrip("6")
        seen[(base, port, cidr)] = {
            "protocol": base, "port": port, "bind_address": cidr,
            "process": {"name": name, "cmdline": None, "exe": None,
                        "services": [], "user": None,
                        "pid": int(pid) if pid else None},
            "flags": flags_for(cidr, port),
        }
    return [seen[k] for k in sorted(seen)]


def load_ranges(path):
    """Assumed dynamic port ranges, from a hand-written file.

    The archive records no host's range, so without this every consumer falls
    back to the OS default silently. Written into the loot instead, each range
    carries where it came from, and the assumption is in the data a reviewer
    reads rather than in a constant they do not see:

        ranges:                       # per OS family, the default
          linux:   {tcp: 32768-60999, udp: 32768-60999, source: ..., why: ...}
        hosts:                        # per collector host name, overriding it
          mail:    {tcp: 6005-64325, udp: 49152-64325, source: ..., why: ...}

    Returns (by_os, by_host), each name -> {'tcp': [lo, hi], 'udp': [lo, hi],
    'source': str}.
    """
    import yaml
    doc = yaml.safe_load(pathlib.Path(path).read_text()) or {}

    def entry(name, e):
        if not e.get("source") or not e.get("why"):
            raise SystemExit(f"ossec-to-loot: {path}: {name} needs a source and a why")
        out = {p: list(parse_range(e[p])) for p in ("tcp", "udp") if e.get(p)}
        if not out:
            raise SystemExit(f"ossec-to-loot: {path}: {name} names no range")
        out["source"] = e["source"]
        return out
    return ({k.lower(): entry(k, v) for k, v in (doc.get("ranges") or {}).items()},
            {k.lower(): entry(k, v) for k, v in (doc.get("hosts") or {}).items()})


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("archive", help="Wazuh archive JSONL")
    ap.add_argument("--output", metavar="DIR", help="one loot file per host")
    ap.add_argument("--outdir-per-scan", metavar="DIR",
                    help="every scan, as DIR/<timestamp>/<host>.json")
    ap.add_argument("--scan", choices=["latest", "fullest"], default="fullest",
                    help="which scan to keep per host (default: fullest, the "
                         "one listing most sockets)")
    ap.add_argument("--skip-loopback", action="store_true",
                    help="drop loopback binds at conversion, as the older "
                         "loot-listeners collector does (default: keep them)")
    ap.add_argument("--ranges", metavar="FILE",
                    help="assumed dynamic port ranges per OS and per host, each "
                         "with its source and reasoning (the archive records "
                         "none); written to metadata.ephemeral and "
                         "metadata.ephemeral_source")
    args = ap.parse_args()
    if not args.output and not args.outdir_per_scan:
        ap.error("one of --output or --outdir-per-scan is required")

    best, series = {}, collections.defaultdict(dict)
    ident = {}
    sources = {}
    scanned = collections.Counter()
    osmap = {}
    dbports = collections.defaultdict(dict)
    dbts = {}
    with open(args.archive) as fh:
        for line in fh:
            # syscollector's osinfo is the only place the archive names a
            # host's OS; the netstat records carry no such field, and without
            # it every host would default to the Linux policy shape.
            if OSINFO in line:
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                host = ((d.get("agent") or {}).get("name") or "").strip()
                name = (((d.get("data") or {}).get("os") or {})
                        .get("name") or "")
                if host and name:
                    osmap[host] = ("windows" if "windows" in name.lower()
                                   else "linux")
                continue
            if DBPORTS in line:
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                agent = d.get("agent") or {}
                host = (agent.get("name") or "").strip()
                ident.setdefault(host, {"agent_id": agent.get("id"),
                                        "ip": agent.get("ip")})
                port = ((d.get("data") or {}).get("port") or {})
                if not host or port.get("state") != "listening":
                    continue
                cidr = to_cidr(port.get("local_ip") or "")
                try:
                    pnum = int(port.get("local_port"))
                except (TypeError, ValueError):
                    continue
                if cidr is None:
                    continue
                proto = (port.get("protocol") or "tcp").rstrip("6")
                pid = port.get("pid")
                dbports[host][(proto, pnum, cidr)] = {
                    "protocol": proto, "port": pnum, "bind_address": cidr,
                    "process": {"name": port.get("process"), "cmdline": None,
                                "exe": None, "services": [], "user": None,
                                "pid": int(pid) if str(pid).isdigit() else None},
                    "flags": flags_for(cidr, pnum),
                }
                dbts[host] = max(dbts.get(host, ""), d["timestamp"][:19])
                continue
            if MARKER not in line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            agent = d.get("agent") or {}
            # NOT lowercased here. Wazuh reports Windows agents in caps and
            # Unix ones in lower, so it is tempting to fold the case -- but on
            # this archive `DC1` (agent 116, 10.5.12.2) and `dc1` (agent 001,
            # 10.5.11.2) are two different domain controllers in two different
            # zones. Folding merged them and silently gave the beg DC the baf
            # DC's address. The case is part of the name until the filename is
            # written, where a collision is detected rather than resolved.
            host = (agent.get("name") or "").strip()
            body = d.get("full_log") or ""
            if not host or MARKER not in body:
                continue
            # The agent record carries the host's address and its Wazuh id.
            # Both are identity evidence the name alone does not give: an
            # address resolves against an inventory unambiguously where a
            # short name may name three different hosts, and id 000 is the
            # manager itself rather than any agent.
            ident.setdefault(host, {"agent_id": agent.get("id"),
                                    "ip": agent.get("ip")})
            ts = d["timestamp"][:19]
            entries = entries_from(body, keep_loopback=not args.skip_loopback)
            if not entries:
                continue
            scanned[host] += 1
            series[ts][host] = entries
            prev = best.get(host)
            better = (prev is None
                      or (args.scan == "latest" and ts >= prev[0])
                      or (args.scan == "fullest" and len(entries) > len(prev[1])))
            if better:
                best[host] = (ts, entries)

    # Hosts the netstat check never covered (Windows) fall back to dbsync.
    fallback = 0
    for host, entries in dbports.items():
        if host in best or not entries:
            continue
        kept = [e for e in (entries[k] for k in sorted(entries))
                if args.skip_loopback is False
                or not is_loopback(e["bind_address"])]
        if kept:
            best[host] = (dbts.get(host, ""), kept)
            sources[host] = "wazuh syscollector dbsync_ports (union, partial)"
            fallback += 1

    # Filenames and the recorded hostname are lowercase, so a policy, its loot
    # and its inventory token are all spelled alike. Two agents whose names
    # differ only in case would collide here; that is reported, never merged.
    lower = collections.defaultdict(list)
    for host in best:
        lower[host.lower()].append(host)
    collisions = {k: v for k, v in lower.items() if len(v) > 1}

    def filename(host):
        if len(lower[host.lower()]) == 1:
            return host.lower()
        return f"{host.lower()}-{(ident.get(host) or {}).get('agent_id') or 'x'}"

    by_os, by_host = load_ranges(args.ranges) if args.ranges else ({}, {})

    def doc(host, ts, entries):
        i = ident.get(host, {})
        meta = {"hostname": filename(host),
                "os": osmap.get(host), "collected_at": ts,
                "agent_id": i.get("agent_id"), "ip": i.get("ip"),
                "listenfile": sources.get(host, "ossec rootcheck netstat"),
                "annotationfile": None}
        rng = by_host.get(host.lower()) or by_os.get((osmap.get(host) or "").lower())
        if rng:
            meta["ephemeral"] = {p: rng[p] for p in ("tcp", "udp") if p in rng}
            meta["ephemeral_source"] = "assumed: " + rng["source"]
        return {"metadata": meta, "listen_ports": entries}

    if args.output:
        out = pathlib.Path(args.output)
        out.mkdir(parents=True, exist_ok=True)
        for host, (ts, entries) in sorted(best.items()):
            (out / f"{filename(host)}.json").write_text(
                json.dumps(doc(host, ts, entries), indent=2, sort_keys=True) + "\n")
        total = sum(len(e) for _, e in best.values())
        print(f"{len(best)} hosts, {total} listening sockets -> {out}")
        known = sum(1 for h in best if osmap.get(h))
        print(f"  scans read: {sum(scanned.values())}, "
              f"kept the {args.scan} per host")
        print(f"  OS resolved for {known}/{len(best)} hosts from osinfo records")
        if fallback:
            print(f"  {fallback} host(s) from dbsync_ports fallback "
                  f"(partial: a delta stream, not a snapshot)")
        for low, hosts in sorted(collisions.items()):
            print(f"  name collision on {low!r}: {', '.join(sorted(hosts))} "
                  f"are different agents; kept apart by agent id")

    if args.outdir_per_scan:
        out = pathlib.Path(args.outdir_per_scan)
        for ts, hosts in sorted(series.items()):
            d = out / ts.replace(":", "").replace("-", "")
            d.mkdir(parents=True, exist_ok=True)
            for host, entries in sorted(hosts.items()):
                (d / f"{filename(host)}.json").write_text(
                    json.dumps(doc(host, ts, entries), indent=2,
                               sort_keys=True) + "\n")
        print(f"{len(series)} scans -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
