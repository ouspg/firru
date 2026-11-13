#!/usr/bin/env python3
"""
suggest-services — propose names for the ports the inventory does not name.

Synthesis emits no term for a port it cannot name, and a generic term for one
it names badly. `annotate-services` refreshes the evidence on tokens that
already exist and `unknown-services` reads raw `ss` dumps; neither proposes a
new token from normalized loot, which is what this does.

    suggest-services --input loot/ --defs def/               # report
    suggest-services --input loot/ --defs def/ --yaml stub.yml

Output is a proposal, never a policy. The naming decision is the one place the
pipeline deliberately stops and asks, because a wrong name is a wrong rule that
looks right: called `UDP_5050` a port is unknown and gets ANY, called
`WINDOWS-CDP` it is peer discovery and gets the zone by definition. Same
evidence, same port, different rule.

Each proposal carries its basis, and the three are not equally strong:

  curated    a (protocol, port, process) triple someone has decided before.
             Take it.
  derived    the process names itself and is the only one on the port. Usually
             right, worth a glance.
  ambiguous  different processes on different hosts. Reported without a name,
             because the honest answer is per host.

Ephemeral binds are dropped by default, using each host's own range from its
recorded OS rather than one constant for the fleet. The two ranges barely
overlap -- Linux hands out 32768-60999, Windows 49152-65535 -- so a single
cutoff is wrong in both directions at once, keeping a Linux client socket on
40000 and discarding a Linux service on 61000. What sits in the high range also
differs in kind: on Windows it is RPC endpoint-mapper allocations, on Linux
there is no such mechanism and the occupants are client sockets and the random
port avahi opens beside its fixed one. `--keep-ephemeral` shows them,
`--ephemeral LO-HI` overrides.
"""

import argparse
import collections
import glob
import json
import os
import sys

from firru.ephemeral import ephemeral_for, is_ephemeral, parse_range
from firru.service_naming import CURATED, contradicted, name_port


def load_loot(paths, drop_ephemeral=True, override=None):
    """{(protocol, port): {process: {hosts}}} from normalized loot JSON.

    The ephemeral range is the host's own, from its recorded OS, not one
    constant for the fleet. Linux hands out 32768-60999 and Windows
    49152-65535, so a single cutoff is wrong twice over: it keeps a Linux
    client socket on 40000 and discards a Linux service on 61000.
    """
    seen = collections.defaultdict(lambda: collections.defaultdict(set))
    dropped = 0
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
                port = int(lp["port"])
                if drop_ephemeral and is_ephemeral(port, rng):
                    dropped += 1
                    continue
                proc = lp.get("process")
                name = proc.get("name") if isinstance(proc, dict) else proc
                seen[(proto, port)][name or "?"].add(host)
    return seen, dropped


def registered(defs, protocol, port):
    """Whether the definitions already give this port a real name."""
    try:
        toks = defs.GetPortParents(port, protocol)
    except Exception:
        return None
    real = [t for t in toks if not t.upper().startswith(("TCP_", "UDP_"))]
    return real[0] if real else None


def main():
    ap = argparse.ArgumentParser(
        description="Propose service names for unnamed ports, from the process "
                    "the socket inventory recorded.")
    ap.add_argument("--input", "-i", nargs="+", required=True,
                    help="loot directory or file(s)")
    ap.add_argument("--defs", "-d", default="def",
                    help="aerleon definitions dir (default: def)")
    ap.add_argument("--yaml", default=None, metavar="PATH",
                    help="write the confident proposals as an aerleon services stub")
    ap.add_argument("--keep-ephemeral", action="store_true",
                    help="include ports in the host's ephemeral range; they are "
                         "client sockets caught in a snapshot, not services")
    ap.add_argument("--ephemeral", metavar="LO-HI", default=None,
                    help="override the per-OS ephemeral range for every host")
    ap.add_argument("--min-hosts", type=int, default=1, metavar="N",
                    help="only propose for ports seen on at least N hosts")
    args = ap.parse_args()

    from aerleon.lib import naming
    defs = naming.Naming(args.defs)

    # Every token the definitions already use, so a proposal cannot collide
    # with one. `httpd` on tcp/444 wants to be called HTTP, and must not be.
    known_tokens = set()
    for attr in ("services", "_services", "GetServiceNames"):
        obj = getattr(defs, attr, None)
        if callable(obj):
            try:
                known_tokens |= {str(t).upper() for t in obj()}
            except Exception:
                pass
        elif isinstance(obj, dict):
            known_tokens |= {str(t).upper() for t in obj}

    override = parse_range(args.ephemeral) if args.ephemeral else None
    seen, dropped = load_loot(args.input, not args.keep_ephemeral, override)
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
        counts[basis] += 1
        rows.append((proto, port, token, basis, comment, procs, hosts))

    print(f"{sum(counts.values())} (protocol, port) pairs in the inventory"
          + (f", {dropped} ephemeral listeners dropped by the host's own range"
             if dropped else ""))
    for k in ("already named", "contradicted", "curated", "derived", "suite",
              "minority", "collides", "ambiguous", "opaque"):
        if counts[k]:
            print(f"  {k:14s} {counts[k]:5d}")
    print()

    for basis in ("contradicted", "curated", "derived", "suite", "minority",
                  "collides", "ambiguous", "opaque"):
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
        # Only the two strong bases go into a stub. A minority naming and a
        # collision are findings for a person, not entries for a file.
        confident = [r for r in rows if r[2] and r[3] in ("curated", "derived", "suite")]
        by_token = collections.defaultdict(list)
        for proto, port, token, basis, comment, procs, hosts in confident:
            by_token[token].append((proto, port, basis, comment, len(hosts)))
        with open(args.yaml, "w") as fh:
            fh.write("# suggest-services proposals. Every entry is a naming\n"
                     "# decision for a human: accept, rename, or delete. The\n"
                     "# basis and the evidence are on each token.\n"
                     "services:\n")
            for token in sorted(by_token):
                entries = by_token[token]
                basis = entries[0][2]
                fh.write(f"\n  {token}:  # [{basis}] {entries[0][3]}\n")
                for proto, port, _, _, nhosts in sorted(entries):
                    fh.write(f"    - port: {port}\n      protocol: {proto}"
                             f"   # {nhosts} hosts\n")
        print(f"Wrote {len(by_token)} proposed tokens to {args.yaml}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
