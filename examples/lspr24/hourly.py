#!/usr/bin/env python3
"""
hourly — the check before a deploy, an hour at a time: what a host's
tightened policy would have cut from each hour of another window.

    python3 hourly.py --old policies/r1-synthesized --new policies/r2-tightened \\
        --window d2 --defs def/ HOST...

For each host this is `firru diff OLD NEW --flows ... --since H --until H+1`
once an hour, using diff's own evidence, so the verdicts are the ones its
-o sh script would carry: a narrowing the hour's traffic contradicts would
cut those flows, and the script comments it out. Peers are named by the
inventory, as diff names them.

The last block is the reason to look at hours at all: who is cut in most of
them. A peer the learn window never showed and the next day shows every hour
is not noise; the window missed it, and either it joins the source set or the
policy learns from a window that has it.

A peer marked [red] is a red-team address (the store's rt_src/rt_dst, from
the dataset's Label): cutting it is the point, where cutting the rest is a
cost. firru diff cannot say this; the label is the dataset's, and is used here
to read the result, never to make the policy.
"""

import argparse
import collections
import pathlib
import sys

from firru.cli.edit import (_diff_evidence, _host_flow_index, _load_side,
                            _name_peers)
from firru.cli.naming_cache import cached_naming
from firru.policy import diff_surface
from lspr24_to_flows import PROJECT, TIMES, WINDOWS


TOP = 12


def red_team(span):
    """The addresses the store marks red team in a window."""
    import duckdb
    from firru.flows import window_where
    where = " AND ".join(window_where(span, {"timestamp", "hour"}))
    rel = f"read_parquet({str(PROJECT.store) + '/**/*.parquet'!r})"
    return {ip for (ip,) in duckdb.sql(
        f"SELECT src_ip FROM {rel} WHERE rt_src AND {where} "
        f"UNION SELECT dst_ip FROM {rel} WHERE rt_dst AND {where}").fetchall()}


def _mark(peer, red):
    return f"{peer} [red]" if peer.split(" (")[0] in red else peer


def host_report(host, args, defs, out, red):
    old_path = pathlib.Path(args.old) / f"{host}.yml"
    new_path = pathlib.Path(args.new) / f"{host}.yml"
    old_doc, _ = _load_side(str(old_path), args.defs)
    new_doc, _ = _load_side(str(new_path), args.defs)
    result = diff_surface(old_doc, new_doc, defs, "in")
    narrowed = [t for t, _ in result["narrowed"]]

    start, end = (t.timestamp() for t in TIMES.window(args.window))
    out(f"{host}: {args.window} against {pathlib.Path(args.new).name}, "
        f"{len(narrowed)} narrowed terms\n")
    every = collections.defaultdict(lambda: [set(), set(), 0])   # peer -> terms, hours, flows
    hours = 0
    t = start
    while t < end:
        hours += 1
        span = (t, min(t + 3600, end))
        label = f"{_local(t):%m-%d %H:%M}-{_local(span[1]):%H:%M}"
        ev, _ = _host_flow_index(str(PROJECT.store), (new_doc, old_doc), defs, span,
                                 (str(new_path), str(old_path)))
        evidence = _diff_evidence(ev, old_doc, new_doc, defs, result) if ev else {}
        if evidence:
            _name_peers(evidence, args.defs)
        cut = [(term, evidence[id(term)]["cut"]) for term in narrowed
               if evidence.get(id(term), {}).get("cut")]
        out(f"  {label}  {len(cut)} of {len(narrowed)} contradicted\n")
        for term, c in cut:
            name = term.get("name", "").removeprefix("allow-")
            top = sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))
            peers = ", ".join(f"{_mark(p, red)} {n}" for p, n in top[:3])
            more = f", +{len(top) - 3} more" if len(top) > 3 else ""
            out(f"      {name:24} cuts {sum(c.values()):>6,}   {peers}{more}\n")
            for p, n in c.items():
                every[p][0].add(name)
                every[p][1].add(span[0])
                every[p][2] += n
        t = span[1]

    total = sum(n for _, _, n in every.values())
    red_n = sum(n for p, (_, _, n) in every.items() if p.split(" (")[0] in red)
    out(f"  cut across {args.window}: {total:,} flows from {len(every)} "
        f"peer{'' if len(every) == 1 else 's'}"
        + (f", {red_n:,} from red team" if red_n else "") + "\n")
    ranked = sorted(every.items(), key=lambda kv: (-len(kv[1][1]), -kv[1][2], kv[0]))
    for p, (terms, hrs, n) in ranked[:TOP]:
        out(f"      {_mark(p, red):40} {len(hrs):>2}/{hours} hours {n:>7,} flows   "
            f"{' '.join(sorted(terms))}\n")
    rest = ranked[TOP:]
    if rest:
        rest_red = sum(1 for p, _ in rest if p.split(" (")[0] in red)
        out(f"      ... {len(rest)} more peers, {sum(v[2] for _, v in rest):,} flows"
            + (f", {rest_red} of them red team" if rest_red else "") + "\n")


def _local(t):
    """An epoch time in the project's zone, as the window names are written."""
    from datetime import datetime
    return datetime.fromtimestamp(t, TIMES.tz)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("hosts", nargs="+", metavar="HOST", help="inventory tokens (policy file names)")
    ap.add_argument("--old", required=True, metavar="DIR", help="the policies before tightening")
    ap.add_argument("--new", required=True, metavar="DIR", help="the tightened policies")
    ap.add_argument("--window", default="d2", choices=sorted(WINDOWS),
                    help="the window to go through an hour at a time (default d2)")
    ap.add_argument("--defs", default="def", metavar="DIR")
    ap.add_argument("--out", metavar="DIR", help="one <host>.txt per host here, else stdout")
    args = ap.parse_args()

    defs = cached_naming(args.defs)
    red = red_team(tuple(t.timestamp() for t in TIMES.window(args.window)))
    for host in args.hosts:
        if args.out:
            pathlib.Path(args.out).mkdir(parents=True, exist_ok=True)
            with open(pathlib.Path(args.out) / f"{host}.txt", "w") as f:
                host_report(host, args, defs, f.write, red)
            print(f"{host} -> {args.out}/{host}.txt", file=sys.stderr)
        else:
            host_report(host, args, defs, sys.stdout.write, red)
            print()


if __name__ == "__main__":
    main()
