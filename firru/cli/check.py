#!/usr/bin/env python3
"""
firru check — what a policy refuses of the traffic, and what of that the host
answered.

    firru check policies/pol/dc1.yml --window d2
    firru check policies/pol/ --since "d2 08:00" --until "d2 09:00"

For each host, every inbound flow the policy's accept terms would not admit:
a port no term covers, or a source the covering term does not name. A refused
flow the host answered is what would break if the policy were deployed (or,
if it is deployed, a rule that is not enforced); one it did not answer agrees
with the policy (a scan, an attempt). Flows that record no answer either way
count as answered, the side that never hides a break.

Exits 1 when any refused flow was answered, so `make validate` can run it.
"""

import argparse
import sys
from collections import defaultdict

from firru.cli.propose import (add_flow_arguments, find_blocked, host_flows, open_flows,
                               prescan)
from firru.policy import DIR_IN, filter_directions


def _accept_terms(policy):
    terms = []
    for filt in policy.get("filters", []):
        # Membership, not "not egress": an unstated direction is neither
        # half, and must not be checked as if it were ingress.
        if DIR_IN in filter_directions(filt):
            terms.extend(t for t in filt.get("terms", [])
                         if t.get("action", "accept").lower() not in ("deny", "drop", "reject"))
    return terms


def aggregate(blocked, annotator):
    """By (proto, service, peer token): flows, unanswered, addresses, why."""
    agg = defaultdict(lambda: {"hits": 0, "unanswered": 0, "ips": set(), "why": ""})
    for b in blocked:
        ann = annotator.annotate_ip(b["src_ip"])
        tok = ann.get("host") or (ann["parents"][0] if ann.get("parents") else b["src_ip"])
        a = agg[(b["proto"], b["svc"], tok)]
        a["hits"] += b["hits"]
        a["unanswered"] += b.get("unanswered", 0)
        a["ips"].add(b["src_ip"])
        a["why"] = "no term" if b.get("proposed_src") is None else "source"
    return agg


def report(host, agg, limit):
    total = sum(a["hits"] for a in agg.values())
    unans = sum(a["unanswered"] for a in agg.values())
    answered = total - unans
    if not total:
        print(f"{host}: nothing refused")
        return 0
    sources = len({ip for a in agg.values() for ip in a["ips"]})
    print(f"{host}: {total} refused flows from {sources} sources")
    print(f"  answered {answered} · unanswered {unans}")

    def rows(key):
        out = []
        for (proto, svc, tok), a in agg.items():
            n = key(a)
            if n:
                ips = sorted(a["ips"])
                peer = tok if ips == [tok] else f"{tok} ({', '.join(ips[:3])}{', …' if len(ips) > 3 else ''})"
                out.append((n, f"{proto}/{svc}", peer, a["why"]))
        return sorted(out, key=lambda r: (-r[0], r[1], r[2]))

    for title, key in (("would break (answered)", lambda a: a["hits"] - a["unanswered"]),
                       ("agrees (unanswered)", lambda a: a["unanswered"])):
        rs = rows(key)
        if not rs:
            continue
        print(f"  {title}:")
        for n, svc, peer, why in rs[:limit]:
            print(f"    {n:6d} {svc:28s} {peer:40s} {why}")
        if len(rs) > limit:
            print(f"    … {len(rs) - limit} more")
    return 1 if answered else 0


def main():
    parser = argparse.ArgumentParser(
        prog="firru check",
        description="What each policy refuses of the inbound traffic, split by "
                    "whether the host answered: answered is what would break. "
                    "Read-only; exits 1 when an answered flow is refused.")
    add_flow_arguments(parser)
    parser.add_argument("--limit", type=int, default=20,
                        help="rows per section and host (default 20)")
    args = parser.parse_args()
    ctx = open_flows(args, parser)
    prescan(ctx, args)
    rc = 0
    for policy_path, policy, host_token, host_ips in ctx.hosts:
        if policy is None:
            print(f"{host_token}: no policy file", file=sys.stderr)
            continue
        got = host_flows(ctx, args, host_token, host_ips)
        if got is None:
            continue
        _, _, ingress, _, ingress_ports, _ = got
        blocked = find_blocked(ingress, _accept_terms(policy), ctx.annotator, ctx.defs,
                               ingress_ports)
        host = (policy.get("metadata") or {}).get("host") or host_token
        rc |= report(host, aggregate(blocked, ctx.annotator), args.limit)
    return rc


if __name__ == "__main__":
    sys.exit(main())
