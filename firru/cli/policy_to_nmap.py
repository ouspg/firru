#!/usr/bin/env python3
"""
policy-to-nmap — Generate nmap acceptance test commands from aerleon policies.

Given a source IP (where you are running nmap from), reads one or more aerleon
policy YAML files and emits nmap commands for ports that should be closed from
that source (default) or open (--open).

Works with host policies (policies/pol/*.yml), zone/merge policies
(zones/*.yml), or any mix — pass whatever is relevant to the segment under test.

Usage:
    policy-to-nmap --source 10.1.1.1 --policies 'policies/pol/*.yml' --defs def/
    policy-to-nmap --source 10.1.1.1 --policies zones/NET_DMZ.yml --defs def/
    policy-to-nmap --source 10.1.1.1 --segment DMZ --defs def/
"""

import argparse
import collections
import glob as _glob
import ipaddress
import sys

import yaml
from aerleon.lib import naming


SKIP_TOKENS = {"ANY", "ANY_V4", "ANY_V6", "LOOPBACK"}


def _net(addr_str):
    return ipaddress.ip_network(str(addr_str), strict=False)


def resolve_token_addrs(token, defs):
    try:
        return [_net(a) for a in defs.GetNetAddr(token)]
    except Exception:
        return []


def resolve_service_ports(token, proto, defs):
    try:
        return defs.GetServiceByProto(token, proto) or []
    except Exception:
        return []


def source_zone(src_ip, defs, zone_names):
    """Return the zone name whose subnet contains src_ip, or None."""
    ip = ipaddress.ip_address(src_ip)
    for zone in zone_names:
        for net in resolve_token_addrs(zone, defs):
            if ip in net:
                return zone
    return None


def token_matches_source(token, src_ip, defs):
    """True if src_ip is covered by the token's addresses."""
    ip = ipaddress.ip_address(src_ip)
    for net in resolve_token_addrs(token, defs):
        if net.version == ip.version and ip in net:
            return True
    return False


def src_matches(term_src, src_ip, defs):
    """True if src_ip is covered by the term's source-address."""
    if not term_src or (isinstance(term_src, str) and term_src in SKIP_TOKENS):
        return True  # ANY
    if isinstance(term_src, list):
        return any(token_matches_source(t, src_ip, defs)
                   for t in term_src if t not in SKIP_TOKENS)
    tokens = [t for t in term_src.split() if t not in SKIP_TOKENS]
    return any(token_matches_source(t, src_ip, defs) for t in tokens)


def dst_ips(token, defs, af=None):
    """Return host IPs for a destination token, optionally filtered by AF."""
    addrs = resolve_token_addrs(token, defs)
    result = []
    for net in addrs:
        if net.prefixlen == (32 if net.version == 4 else 128):
            if af is None or net.version == af:
                result.append(str(net.network_address))
    return result


def collect_testcases(docs, src_ip, defs, all_zone_names):
    """
    Returns list of dicts:
        {dst_ip, proto, ports, expected: 'open'|'closed'}

    SHOULD BE OPEN:   policy allows traffic from src_ip to that port/host.
    SHOULD BE CLOSED: policy allows that port/host for *some* source, but not src_ip.
                      The firewall's default deny should block it — good test case.
    """
    # (dst_ip, proto) -> set of port strings
    all_allow = collections.defaultdict(set)   # any allow rule, any source
    our_allow = collections.defaultdict(set)   # allow rules matching our source IP
    # dst_ip -> token name (last one wins, just for display)
    ip_label = {}

    for _, doc in docs:
        for filt in doc.get("filters", []):
            for term in filt.get("terms", []):
                action = term.get("action", "accept").lower()
                if action in ("drop", "deny", "reject"):
                    continue  # default deny covers these; no need to track explicitly

                proto = term.get("proto") or term.get("protocol")
                port_token = term.get("destination-port")
                src = term.get("source-address")
                dst = term.get("destination-address")

                if not dst:
                    dst = doc.get("metadata", {}).get("host")
                if not dst or not port_token:
                    continue

                matches = src_matches(src, src_ip, defs)

                dst_tokens = dst if isinstance(dst, list) else dst.split()
                for dt in dst_tokens:
                    if dt in SKIP_TOKENS:
                        continue
                    for ip in dst_ips(dt, defs):
                        ip_label[ip] = dt
                        all_ports = resolve_service_ports(port_token, proto or "tcp", defs)
                        fixed = [p for p in all_ports if "-" not in str(p)]
                        ports = fixed if fixed else []
                        if not ports:
                            continue
                        key = (ip, proto or "tcp")
                        all_allow[key].update(ports)
                        if matches:
                            our_allow[key].update(ports)

    cases = []
    seen = set()

    for (dst_ip, proto), ports in sorted(our_allow.items()):
        if not ports:
            continue
        k = (dst_ip, proto, tuple(sorted(ports)), "open")
        if k not in seen:
            seen.add(k)
            cases.append({"dst_ip": dst_ip, "label": ip_label.get(dst_ip, dst_ip),
                          "proto": proto, "ports": sorted(ports), "expected": "open"})

    for (dst_ip, proto), ports in sorted(all_allow.items()):
        closed = ports - our_allow.get((dst_ip, proto), set())
        if not closed:
            continue
        k = (dst_ip, proto, tuple(sorted(closed)), "closed")
        if k not in seen:
            seen.add(k)
            cases.append({"dst_ip": dst_ip, "label": ip_label.get(dst_ip, dst_ip),
                          "proto": proto, "ports": sorted(closed), "expected": "closed"})

    return cases


def emit_nmap(cases, src_ip, show_open=False):
    lines = [f"# nmap test cases for source {src_ip}", ""]

    # Group by (expected, proto, frozenset(ports)) -> list of (dst_ip, label)
    by_portset = collections.defaultdict(list)
    for c in cases:
        key = (c["expected"], c["proto"], tuple(c["ports"]))
        by_portset[key].append((c["dst_ip"], c["label"]))

    expected_order = []
    if show_open:
        expected_order.append("open")
    expected_order.append("closed")

    for expected in expected_order:
        label = "SHOULD BE OPEN" if expected == "open" else "SHOULD BE CLOSED"
        entries = {k: v for k, v in by_portset.items() if k[0] == expected}
        if not entries:
            continue
        lines.append(f"# {label}")
        for (exp, proto, ports), targets in sorted(entries.items(),
                key=lambda x: (x[0][1], int(x[0][2][0].split("-")[0]) if x[0][2] else 0)):
            port_str = ",".join(ports)
            flag = "-sU" if proto == "udp" else "-sT"
            host_str = " ".join(ip for ip, _ in sorted(targets))
            comments = " ".join(
                f"{lbl}={ip}" if lbl != ip else ip
                for ip, lbl in sorted(targets)
            )
            lines.append(f"# {proto}: {comments}")
            lines.append(f"nmap {flag} -p {port_str} {host_str}")
        lines.append("")

    return lines


def main():
    parser = argparse.ArgumentParser(
        description="Generate nmap acceptance test commands from aerleon policies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--source", required=True, metavar="IP",
                        help="Source IP address (where you are running nmap from)")
    parser.add_argument("--segment", default=None, metavar="NAME",
                        help="Segment name — globs zones/*NAME* for policy files")
    parser.add_argument("--policies", nargs="+", default=None, metavar="FILE",
                        help="Policy YAML files or glob patterns (overrides --segment)")
    parser.add_argument("--defs", default="def",
                        help="Aerleon definitions directory (default: def)")
    parser.add_argument("--open", action="store_true",
                        help="Also emit SHOULD BE OPEN commands (default: closed only)")
    args = parser.parse_args()

    if not args.segment and not args.policies:
        parser.error("specify --segment NAME or --policies files")

    zone_pats = args.policies if args.policies else [f"zones/*{args.segment}*"]
    zone_yamls = []
    for pat in zone_pats:
        zone_yamls.extend(_glob.glob(pat))
    zone_yamls = sorted(set(zone_yamls))
    if not zone_yamls:
        print(f"No policy files found for: {zone_pats}", file=sys.stderr)
        sys.exit(1)

    defs = naming.Naming(args.defs)

    docs = []
    zone_names = set()
    for path in zone_yamls:
        with open(path) as f:
            doc = yaml.safe_load(f)
        docs.append((path, doc))
        zone = doc.get("metadata", {}).get("zone")
        if zone:
            zone_names.add(zone)

    src_zone = source_zone(args.source, defs, zone_names)
    if src_zone:
        print(f"# Source {args.source} is in zone {src_zone}", file=sys.stderr)
    else:
        print(f"# Warning: source {args.source} not found in any zone subnet", file=sys.stderr)

    cases = collect_testcases(docs, args.source, defs, zone_names)
    print(f"# {len(cases)} test cases", file=sys.stderr)

    lines = emit_nmap(cases, args.source, show_open=args.open)
    print("\n".join(lines))


if __name__ == "__main__":
    main()
