#!/usr/bin/env python3
"""
address-summarizer — Collapse a list of addresses into a one-line comment.

The sources (or destinations) of one firewall term, in; at most N entries out,
as a string fit to sit behind a `#`. Where a term's addresses carry an
inventory token the pipeline already names them; this is for the ones that do
not, which today land in a single `EXTERNAL` bucket with a four-address sample
and one summed hit count.

    $ cut -f1 sources.txt | address-summarizer -n 5
    9 addresses in 3 blocks: 10.85.7.176/28 (2 src, 456 hits), ...

    $ cut -f1 rt-sources.txt | address-summarizer -n 5
    11 addresses in 11 blocks, widest /1: 128.0.0.0/1 (6 src, 6 hits), ...

A summary always comes out. A prefix that has widened to /1 is a result -- it
says these addresses have no common neighborhood -- and it is more useful than
a refusal, because it is uniform: every term gets N entries and the prefix
length is the quality score. Narrow prefixes are a client population worth
naming; /1 and /2 are a fan-in.

    $ cut -f1 dsts.txt | address-summarizer -n 5 --asn
    212 addresses in 4 ASes: AS8075 Microsoft (196 dst, 41k hits), ...

`--asn` groups by autonomous system instead of by prefix, which is the grouping
that survives a CDN. For egress it is the useful one: "windows update went to
Microsoft space" is a statement a reviewer can accept or reject, where a list of
forty /24s is not. Needs a MaxMind ASN database (--asn-db, or $GEOIP_ASN_DB,
or a GeoLite2-ASN.mmdb beside the definitions or where geoipupdate installs it).

Input is one address per line, optionally followed by whitespace and a count
(flows, hits, whatever the caller is weighting by), so a summary can report
volume per group rather than membership alone. `-` or no argument reads stdin.

Aggregation is greedy least-waste over adjacent prefixes, address families kept
apart: a supernet spanning v4 and v6 means nothing.
"""

import argparse
import ipaddress
import os
import sys
from collections import Counter, defaultdict

BLOCK = {4: 24, 6: 48}


def _supernet_of(a, b):
    lo, hi = (a, b) if a.network_address <= b.network_address else (b, a)
    sup = lo
    while sup.prefixlen > 0 and not sup.supernet_of(hi):
        sup = sup.supernet()
    return sup


def aggregate(nets, budget):
    """Merge adjacent prefixes, cheapest first, until at most `budget` remain."""
    nets = sorted(ipaddress.collapse_addresses(nets), key=lambda n: n.network_address)
    while len(nets) > budget:
        best_i, best_cost = None, None
        for i in range(len(nets) - 1):
            cost = _supernet_of(nets[i], nets[i + 1]).num_addresses
            if best_cost is None or cost < best_cost:
                best_i, best_cost = i, cost
        sup = _supernet_of(nets[best_i], nets[best_i + 1])
        nets = sorted(ipaddress.collapse_addresses(
            nets[:best_i] + [sup] + nets[best_i + 2:]),
            key=lambda n: n.network_address)
    return nets


def _entry(label, members, weight, noun):
    hits = f"{weight} hit" + ("s" if weight != 1 else "")
    if len(members) > 1:
        return f"{label} ({len(members)} {noun}, {hits})"
    return f"{label} ({hits})"


def summarize(counts, budget, noun="src"):
    """counts: {address: weight}. Returns the comment string."""
    if not counts:
        return "no addresses"
    fams = defaultdict(list)
    for ip in counts:
        fams[ipaddress.ip_address(ip).version].append(ip)

    blocks = {str(ipaddress.ip_network(
        f"{ip}/{BLOCK[ipaddress.ip_address(ip).version]}", strict=False)) for ip in counts}
    total = len(counts)
    lead = (f"{total} address{'es' if total != 1 else ''} in "
            f"{len(blocks)} block{'s' if len(blocks) != 1 else ''}")

    share = {}
    if len(fams) == 1:
        share[next(iter(fams))] = budget
    else:
        s4 = max(1, min(budget - 1, round(budget * len(fams[4]) / total)))
        share[4], share[6] = s4, max(1, budget - s4)

    rows, widest = [], None
    for ver, ips in sorted(fams.items()):
        for n in aggregate([ipaddress.ip_network(i) for i in ips], share.get(ver, budget)):
            members = [ip for ip in ips if ipaddress.ip_address(ip) in n]
            rows.append((sum(counts[ip] for ip in members), n, members))
            if widest is None or n.prefixlen < widest:
                widest = n.prefixlen
    rows.sort(key=lambda r: -r[0])
    parts = [_entry(str(n), m, w, noun) for w, n, m in rows]
    return f"{lead}, widest /{widest}: " + ", ".join(parts)


def asn_groups(counts, db_path):
    """{(asn, org): {"w": weight, "n": addresses}} plus an `unknown` bucket."""
    import geoip2.database
    reader = geoip2.database.Reader(db_path)
    groups = defaultdict(lambda: {"w": 0, "n": 0})
    unknown = {"w": 0, "n": 0}
    for ip, w in counts.items():
        try:
            rec = reader.asn(ip)
            key = (rec.autonomous_system_number, rec.autonomous_system_organization)
        except Exception:
            unknown["w"] += w
            unknown["n"] += 1
            continue
        groups[key]["w"] += w
        groups[key]["n"] += 1
    reader.close()
    return groups, unknown


def prefix_group_sizes(counts):
    """Addresses per neighborhood (/24, /48), largest first.

    Deliberately not budgeted. Aggregating to a display budget manufactures
    structure: nine addresses in nine unrelated /8s, squeezed into four
    entries, produce a group of five that exists only because the budget said
    four. Whether addresses share a neighborhood is a fact about the addresses.
    """
    blocks = Counter()
    for ip in counts:
        a = ipaddress.ip_address(ip)
        blocks[str(ipaddress.ip_network(f"{ip}/{BLOCK[a.version]}", strict=False))] += 1
    return sorted(blocks.values(), reverse=True)


def summarize_asn(counts, budget, db_path, noun="src"):
    import geoip2.database
    reader = geoip2.database.Reader(db_path)
    groups = defaultdict(lambda: {"w": 0, "n": 0})
    unknown = {"w": 0, "n": 0}
    for ip, w in counts.items():
        try:
            rec = reader.asn(ip)
            key = (rec.autonomous_system_number, rec.autonomous_system_organization)
        except Exception:
            unknown["w"] += w
            unknown["n"] += 1
            continue
        groups[key]["w"] += w
        groups[key]["n"] += 1
    reader.close()

    total = len(counts)
    named = len(groups)
    plural = f"{total} address{'es' if total != 1 else ''}"
    if not named:
        return f"{plural}, none of them routable"
    lead = f"{plural} in {named} AS{'es' if named != 1 else ''}"
    if unknown["n"]:
        lead += f" ({unknown['n']} unrouted or unknown)"
    ordered = sorted(groups.items(), key=lambda kv: -kv[1]["w"])
    parts = []
    for (num, org), d in ordered[:budget]:
        org = (org or "?")[:28]
        parts.append(_entry(f"AS{num} {org}", range(d["n"]), d["w"], noun))
    if len(ordered) > budget:
        rest = sum(d["w"] for _, d in ordered[budget:])
        parts.append(f"+{len(ordered) - budget} more AS ({rest} hits)")
    if not parts:
        return lead
    return f"{lead}: " + ", ".join(parts)


def _default_asn_db():
    # $GEOIP_ASN_DB, then beside the definitions, then where geoipupdate puts it
    for c in (os.environ.get("GEOIP_ASN_DB"),
              "GeoLite2-ASN.mmdb", "def/GeoLite2-ASN.mmdb",
              "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
              "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
              "/usr/local/share/GeoIP/GeoLite2-ASN.mmdb"):
        if c and os.path.exists(c):
            return c
    return None


def main():
    ap = argparse.ArgumentParser(
        description="Collapse a term's addresses into a one-line comment.")
    ap.add_argument("files", nargs="*", help="address list(s); '-' or empty for stdin")
    ap.add_argument("-n", type=int, default=5, metavar="N",
                    help="most entries to emit (default 5)")
    ap.add_argument("--asn", action="store_true",
                    help="group by autonomous system instead of by prefix")
    ap.add_argument("--asn-db", default=None,
                    help="MaxMind ASN mmdb (default $GEOIP_ASN_DB or a local GeoLite2-ASN.mmdb)")
    ap.add_argument("--noun", default="src",
                    help="what one address is, for the counts (default 'src'; try 'dst')")
    args = ap.parse_args()

    streams = [sys.stdin] if not args.files or args.files == ["-"] \
        else [open(f) for f in args.files]
    counts = Counter()
    for st in streams:
        for line in st:
            bits = line.split()
            if not bits:
                continue
            try:
                ipaddress.ip_address(bits[0])
            except ValueError:
                continue
            counts[bits[0]] += int(bits[1]) if len(bits) > 1 and bits[1].isdigit() else 1

    if args.asn:
        db = args.asn_db or _default_asn_db()
        if not db:
            sys.exit("no ASN database found; pass --asn-db or set GEOIP_ASN_DB")
        print(summarize_asn(counts, args.n, db, args.noun))
    else:
        print(summarize(counts, args.n, args.noun))


if __name__ == "__main__":
    main()
