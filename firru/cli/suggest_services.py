#!/usr/bin/env python3
"""
suggest-services — propose names for the ports the inventory does not name.

Synthesis emits no term for a port it cannot name, and a generic term for one
it names badly. `annotate-services` refreshes the evidence on tokens that
already exist and `audit-services` reads raw `ss` dumps; neither proposes a
new token from normalized loot, which is what this does.

    suggest-services --input loot/ --defs def/               # report
    suggest-services --input loot/ --defs def/ --yaml def/services-observed.yml

Output is a proposal, never a policy. The naming decision is the one place the
pipeline deliberately stops and asks, because a wrong name is a wrong rule that
looks right: called `UDP_5050` a port is unknown and gets ANY, called
`WINDOWS-CDP` it is peer discovery and gets the zone by definition. Same
evidence, same port, different rule.

Each proposal carries its basis, and they are not equally strong:

  curated    a (protocol, port, process) triple someone has decided before.
             Take it.
  baseline   a stock install of the same OS family runs this process on this
             port (the records `firru baseline-synth` ships, or a checkout in
             $FIRRU_BASELINES). The port is the product's, not the site's.
  derived    the process names itself and is the only one on the port. Usually
             right, worth a glance.
  ambiguous  different processes on different hosts. Reported without a name,
             because the right answer is per host.

--yaml writes a services file Aerleon can load beside the curated ones. Only
the first two bases give a token its name there; every other port is
`TCP_<port>` or `UDP_<port>`, with the derived name, the process and the hosts
in its comment, so a name the site's own processes claimed stays visibly
weaker than one that holds everywhere. Rerunning reads the definitions without
that file, so it never counts its own earlier output as a name.

Two kinds of port are left out, because synthesis emits no term for them, and
both are listed at the end of the file rather than dropped silently:

  loopback   bound only to a loopback address, so not reachable off-host. A
             port also bound to another address counts, because that address
             is what the term is for.
  ephemeral  in the host's own ephemeral range, from its recorded OS rather
             than one constant for the fleet. The two ranges barely overlap --
             Linux hands out 32768-60999, Windows 49152-65535 -- so a single
             cutoff is wrong in both directions at once, keeping a Linux client
             socket on 40000 and discarding a Linux service on 61000. What sits
             in the high range also differs in kind: on Windows it is RPC
             endpoint-mapper allocations, on Linux client sockets and the random
             port avahi opens beside its fixed one. Ports the registry assigned
             inside the range are kept, each saying why. `--keep-ephemeral`
             shows them all, `--ephemeral LO-HI` overrides the range.
"""

import argparse
import collections
import glob
import ipaddress
import json
import os
import pathlib
import sys
import tempfile

from firru.ephemeral import ephemeral_for, is_ephemeral, parse_range
from firru.service_naming import CURATED, best_token, contradicted, derive_token, name_port

# Registered services that fall inside the ephemeral range. The range test is a
# heuristic about who *assigned* the port; these were assigned by the registry.
REGISTERED_IN_RANGE = {
    ("tcp", 33060): "MySQL X Protocol",
    ("tcp", 47001): "Windows Remote Management (WinRM) over HTTP",
    ("udp", 33434): "traceroute",
}


def _family(doc):
    os_name = str(((doc or {}).get("metadata") or {}).get("os") or "").lower()
    return "windows" if os_name.startswith("win") else "linux"


def _process_key(name):
    """A process name as both loot and baselines are matched on: Windows
    collectors record `svchost.exe` or `svchost` for the same process."""
    return name.strip().lower().removesuffix(".exe")


def _loopback_only(bind):
    try:
        return ipaddress.ip_address(str(bind or "").split("/")[0].strip("[]")).is_loopback
    except ValueError:
        return False


def collect(paths, drop_ephemeral=True, override=None):
    """What the loot listens on, by (protocol, port):

        seen      {key: {process: {hosts}}}, the listeners proposals are for
        families  {key: {os family}} of the hosts in seen
        loopback  {key: {process: {hosts}}}, ports bound only to loopback
        dropped   {key: {process: {hosts}}}, ports in the ephemeral range of
                  every host listening on them
        n_dropped how many listeners the ephemeral range dropped

    The ephemeral range is the host's own, from its recorded OS, not one
    constant for the fleet. Linux hands out 32768-60999 and Windows
    49152-65535, so a single cutoff is wrong twice over: it keeps a Linux
    client socket on 40000 and discards a Linux service on 61000.
    """
    nest = lambda: collections.defaultdict(lambda: collections.defaultdict(set))
    seen, dropped, all_binds = nest(), nest(), nest()
    offhost, families = set(), collections.defaultdict(set)
    n_dropped = 0
    for path in paths:
        files = (sorted(glob.glob(os.path.join(path, "*.json")))
                 if os.path.isdir(path) else [path])
        for f in files:
            if f.endswith("manifest.json"):
                continue
            try:
                doc = json.load(open(f))
            except Exception:
                continue
            host = ((doc.get("metadata") or {}).get("hostname")
                    or os.path.basename(f)[:-5]).lower()
            rng = ephemeral_for(doc, override)
            for lp in doc.get("listen_ports") or []:
                proto = (lp.get("protocol") or "").lower()
                if proto not in ("tcp", "udp"):
                    continue
                key = (proto, int(lp["port"]))
                proc = lp.get("process")
                name = (proc.get("name") if isinstance(proc, dict) else proc) or "?"
                all_binds[key][name].add(host)
                if not _loopback_only(lp.get("bind_address")):
                    offhost.add(key)
                if (drop_ephemeral and key not in REGISTERED_IN_RANGE
                        and is_ephemeral(key[1], rng)):
                    dropped[key][name].add(host)
                    n_dropped += 1
                    continue
                seen[key][name].add(host)
                families[key].add(_family(doc))
    loopback = {k: v for k, v in all_binds.items() if k not in offhost}
    seen = {k: v for k, v in seen.items() if k in offhost}
    dropped = {k: v for k, v in dropped.items() if k in offhost and k not in seen}
    return seen, families, loopback, dropped, n_dropped


def load_loot(paths, drop_ephemeral=True, override=None):
    """{(protocol, port): {process: {hosts}}} for the ports a term could be
    for, so without loopback-only ones, and the number of listeners the
    ephemeral range dropped."""
    seen, _, _, _, n_dropped = collect(paths, drop_ephemeral, override)
    return seen, n_dropped


def baseline_index():
    """{(os family, protocol, port, process): ({run}, {Windows service})} over
    every available baseline run."""
    from firru.cli.loot_diff import available_baselines, load_run
    index = collections.defaultdict(lambda: (set(), set()))
    for run, path in sorted(available_baselines().items()):
        try:
            docs = load_run(path)
        except Exception:
            continue
        docs = docs.values() if isinstance(docs, dict) and "listen_ports" not in docs else [docs]
        for doc in docs:
            family = _family(doc)
            for lp in doc.get("listen_ports") or []:
                proc = lp.get("process")
                name = _process_key((proc.get("name") if isinstance(proc, dict) else proc) or "")
                if not name or _loopback_only(lp.get("bind_address")):
                    continue
                key = (family, (lp.get("protocol") or "").lower(), int(lp["port"]), name)
                index[key][0].add(run)
                services = proc.get("services") if isinstance(proc, dict) else None
                index[key][1].update(services or [])
    return index


def from_baseline(index, proto, port, procs, families, taken):
    """(token or None, comment) when a stock install of the same OS family
    runs one of these processes on this port, else None."""
    hits = {}
    for p in procs:
        for family in families:
            runs, services = index.get((family, proto, port, _process_key(p)), (set(), set()))
            if runs:
                hits[p] = (runs, services)
    if not hits:
        return None
    runs = sorted(set().union(*(r for r, _ in hits.values())))
    services = sorted(set().union(*(s for _, s in hits.values())))
    shown = ", ".join(runs[:2]) + (f" +{len(runs) - 2} more" if len(runs) > 2 else "")
    token = None
    if len(services) == 1:
        token = derive_token(services[0])
    elif len(hits) == 1:
        token = derive_token(next(iter(hits)))
    if token and token in taken:
        token = None
    return token, f"Stock: {', '.join(sorted(hits))} on {shown}."


def registered(defs, protocol, port):
    """The token the definitions already grant this port under, or None: a
    real name before a TCP_/UDP_ placeholder. A placeholder counts, because
    writing the same token again would define it twice."""
    try:
        toks = defs.GetPortParents(port, protocol)
    except Exception:
        return None
    return best_token(defs, toks)


def load_definitions(defs_dir, without=None):
    """aerleon Naming over defs_dir, leaving out `without` (this tool's own
    earlier output), so a rerun does not count it as a name."""
    from aerleon.lib import naming
    skip = pathlib.Path(without).resolve() if without else None
    if skip is None or skip.parent != pathlib.Path(defs_dir).resolve():
        return naming.Naming(defs_dir)
    # Naming reads every file when it is built, so the links can go after.
    with tempfile.TemporaryDirectory(prefix="suggest-services-") as tmp:
        for f in pathlib.Path(defs_dir).iterdir():
            if f.is_file() and f.resolve() != skip:
                os.symlink(f.resolve(), os.path.join(tmp, f.name))
        return naming.Naming(tmp)


def _evidence(procs, limit=4):
    hosts = sorted(set().union(*procs.values()))
    who = ", ".join(sorted(procs, key=lambda p: (-len(procs[p]), p))[:3])
    shown = ", ".join(hosts[:limit]) + (f", +{len(hosts) - limit} more" if len(hosts) > limit else "")
    return f"{who} on {shown}"


def write_services(path, rows, loopback, dropped):
    """The services file: curated and baseline names, TCP_/UDP_ for the rest."""
    named, placeholder = collections.defaultdict(list), []
    for proto, port, token, basis, comment, procs, _ in rows:
        if basis in ("already named", "contradicted"):
            continue
        if token and basis in ("curated", "baseline"):
            named[token].append((proto, port, basis, comment, procs))
        else:
            hint = f"{token} ({basis})" if token else basis
            # The comment goes along where it says something the hint does
            # not: what a baseline found, or why a name was refused.
            keep = comment.startswith("Stock:") or basis == "collides"
            placeholder.append((proto, port, hint, comment if keep else "", procs))

    lines = [
        "# Generated by suggest-services. Every entry is a naming decision for a",
        "# human: accept, rename, or delete.",
        "#",
        "# A name is given only on evidence that holds beyond these hosts: a",
        "# curated entry, or a stock install running the same process on the",
        "# port. Every other port is TCP_<port> or UDP_<port>, with what the",
        "# hosts' own processes suggest in its comment, because that is a weaker",
        "# claim than a registry name makes.",
        "services:",
    ]
    for token in sorted(named):
        entries = sorted(named[token])
        proto, port, basis, comment, procs = entries[0]
        lines.append(f"  {token}:   # [{basis}] {comment} | {_evidence(procs)}")
        for proto, port, *_ in entries:
            lines.append(f"    - port: {port}")
            lines.append(f"      protocol: {proto}")
    for proto, port, hint, comment, procs in sorted(placeholder):
        why = REGISTERED_IN_RANGE.get((proto, port))
        note = f"[{hint}] {comment + ' ' if comment else ''}{_evidence(procs)}" + (
            f" -- {why}, registered despite the range" if why else "")
        lines.append(f"  {proto.upper()}_{port}:   # {note}")
        lines.append(f"    - port: {port}")
        lines.append(f"      protocol: {proto}")
    lines.append("")
    lines.append(f"# Left out, loopback-bound only ({len(loopback)} ports). Never reachable")
    lines.append("# off-host, so no term would name them:")
    for (proto, port), procs in sorted(loopback.items()):
        lines.append(f"#   {proto}/{port:<6} {_evidence(procs)}")
    lines.append("")
    lines.append(f"# Left out as ephemeral ({len(dropped)} ports, the host's own range from")
    lines.append("# its OS). Move one up if it is in fact a fixed listener on these hosts:")
    for (proto, port), procs in sorted(dropped.items()):
        lines.append(f"#   {proto}/{port:<6} {_evidence(procs)}")
    pathlib.Path(path).write_text("\n".join(lines) + "\n")
    return len(named), len(placeholder)


BASES = ("contradicted", "curated", "baseline", "derived", "suite", "minority",
         "collides", "ambiguous", "opaque")


def main():
    ap = argparse.ArgumentParser(
        description="Propose service names for unnamed ports, from the process "
                    "the socket inventory recorded.")
    ap.add_argument("--input", "-i", nargs="+", required=True,
                    help="loot directory or file(s)")
    ap.add_argument("--defs", "-d", default="def",
                    help="aerleon definitions dir (default: def)")
    ap.add_argument("--yaml", default=None, metavar="PATH",
                    help="write a services file: curated and baseline names, "
                         "TCP_/UDP_<port> for the rest")
    ap.add_argument("--no-baselines", action="store_true",
                    help="do not look the ports up in the stock-install baselines")
    ap.add_argument("--keep-ephemeral", action="store_true",
                    help="include ports in the host's ephemeral range; they are "
                         "client sockets caught in a snapshot, not services")
    ap.add_argument("--ephemeral", metavar="LO-HI", default=None,
                    help="override the per-OS ephemeral range for every host")
    ap.add_argument("--min-hosts", type=int, default=1, metavar="N",
                    help="only propose for ports seen on at least N hosts")
    args = ap.parse_args()

    defs = load_definitions(args.defs, without=args.yaml)

    # Every token the definitions already use, so a proposal cannot collide
    # with one. `httpd` on tcp/444 wants to be called HTTP, and must not be.
    known_tokens = {str(t).upper() for t in defs.GetServiceNames()}

    override = parse_range(args.ephemeral) if args.ephemeral else None
    seen, families, loopback, dropped, _ = collect(args.input, not args.keep_ephemeral, override)
    # A port the definitions name is not left out, whatever its binds.
    loopback = {k: v for k, v in loopback.items() if not registered(defs, *k)}
    dropped = {k: v for k, v in dropped.items() if not registered(defs, *k)}
    index = {} if args.no_baselines else baseline_index()
    rows, counts = [], collections.Counter()
    for (proto, port), procs in sorted(seen.items()):
        hosts = set().union(*procs.values())
        if len(hosts) < args.min_hosts:
            continue
        existing = registered(defs, proto, port)
        if existing:
            found = contradicted(proto, port, procs.keys())
            if found:
                proc, note = found
                counts["contradicted"] += 1
                # Only the hosts running the contradicting process are the
                # finding; the rest of the port's hosts are unremarkable.
                scoped = {proc: procs[proc]}
                rows.append((proto, port, existing, "contradicted", note,
                             scoped, procs[proc]))
            else:
                counts["already named"] += 1
            continue
        token, basis, comment = name_port(proto, port, procs, taken=known_tokens)
        if basis != "curated":
            stock = from_baseline(index, proto, port, procs, families[(proto, port)],
                                  known_tokens)
            if stock and stock[0]:
                token, basis, comment = stock[0], "baseline", stock[1]
            elif stock:
                comment = f"{stock[1]} {comment}"   # stock, but no name it gives
        if token and basis == "curated" and token in known_tokens:
            # The site defines this token already, for other ports: writing it
            # again would define it twice, and widening the site's token is
            # the site's call.
            basis, comment = "collides", (
                f"{comment} The definitions already use {token} for other "
                f"ports; add this one to it, or name it apart.")
        counts[basis] += 1
        rows.append((proto, port, token, basis, comment, procs, hosts))

    print(f"{sum(counts.values())} (protocol, port) pairs in the inventory"
          + (f", {len(dropped)} ephemeral and {len(loopback)} loopback-only left out"
             if dropped or loopback else ""))
    for k in ("already named",) + BASES:
        if counts[k]:
            print(f"  {k:14s} {counts[k]:5d}")
    print()

    for basis in BASES:
        group = [r for r in rows if r[3] == basis]
        if not group:
            continue
        print(f"== {basis} ({len(group)}) ==")
        for proto, port, token, _, comment, procs, hosts in sorted(
                group, key=lambda r: -len(r[6]))[:40]:
            who = ", ".join(f"{p} x{len(h)}" for p, h in
                            sorted(procs.items(), key=lambda kv: -len(kv[1]))[:3])
            print(f"  {proto}/{port:<6} {(token or '-'):32s} {len(hosts):3d} hosts  [{who}]")
        if len(group) > 40:
            print(f"  ... and {len(group) - 40} more")
        print()

    if args.yaml:
        n_named, n_placeholder = write_services(args.yaml, rows, loopback, dropped)
        print(f"Wrote {args.yaml}: {n_named} named tokens, "
              f"{n_placeholder} by port number")
    return 0


if __name__ == "__main__":
    sys.exit(main())
