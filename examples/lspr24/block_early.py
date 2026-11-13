#!/usr/bin/env python3
"""
block_early — the R4 variant: drop every service the evidence never touched.

    python3 block_early.py --flows night.jsonl --loot loot-ossec/ \
        --defs def/ --policy policies/r2-tightened --out policies/r4-block-early

R2 narrows a service's sources to what the window showed. R4 goes one step
further and removes the service outright where the window showed *no client at
all*. The ladder prices that as a rate; this renders it as policy, so the bet
can be read per host and merged per zone like any other variant.

WHY THIS IS A CHOICE AND R3 IS NOT. `flows_to_enforced` deliberately emits no
deny for a service nobody tried: silence is not evidence that anything was
enforced. Here the same silence is acted on deliberately -- nobody used it, so
close it -- which is a policy decision an operator makes and can be argued
with, not an inference about what was already running. Same input, opposite
epistemic status, which is why they are separate tools.

ONE PASS. The obvious route is `firru diff --zero-evidence` per host, but each
invocation re-reads the whole flow file; on LSPR24 that is 2.6 GB times 59
hosts and does not finish. Evidence is a property of (service, window), not of
the host being processed, so it is gathered once and applied to every policy.
That also puts the flow source behind one function, which is where a Zeek
parquet store plugs in when it replaces the single-file input.
"""

import argparse
import collections
import pathlib
import sys

import yaml
from ruyaml import YAML

from lspr24_to_flows import canonical_ip
from firru.policy import DIR_IN, filter_directions
from flows_to_enforced import inventory, listeners, service_tokens

# Round-trip, not safe_load: `firru tighten` records its evidence as comments
# above each term ("900 flows total | 900 hits: BEG_GT_OTHER ... via SSH/tcp/22")
# and a plain load/dump cycle silently deletes all of it. R4 is the variant a
# reviewer is most entitled to question, so it is the last place to throw the
# reasons away.
_rt = YAML()
_rt.preserve_quotes = True


def ports_of_token(defs):
    """token -> {(proto, port)}, so a group is judged on all of its members."""
    raw, groups = {}, {}
    for path in sorted(defs.glob("*.yml")):
        for token, entries in ((yaml.safe_load(path.read_text()) or {})
                               .get("services", {})).items():
            for e in entries or []:
                if not isinstance(e, dict):
                    continue
                if "name" in e:
                    groups.setdefault(token, set()).add(e["name"])
                elif "port" in e:
                    proto = e.get("protocol", "tcp")
                    lo, _, hi = str(e["port"]).partition("-")
                    raw.setdefault(token, set()).update(
                        (proto, p) for p in range(int(lo), int(hi or lo) + 1))

    def expand(token, seen=()):
        if token in seen:                      # a group cycle names nothing new
            return set()
        out = set(raw.get(token, ()))
        for member in groups.get(token, ()):
            out |= expand(member, seen + (token,))
        return out

    return {t: expand(t) for t in set(raw) | set(groups)}


def evidence(flows, listen, owner):
    """
    (token, proto, port) that saw at least one inbound flow in the learn file.

    The learn file is the one `firru tighten` read for R2 (night.jsonl), so R4
    is R2's own evidence with the zero-evidence services removed: a service
    tighten marked "no flows observed" is exactly a service this drops. An
    earlier version re-read the parquet with its own window bounds, which did
    not match lspr24_to_flows.py', and kept services alive on flows R2 never saw.

    The single pass the module docstring is about. The flow source is this
    function and nothing else, so a Zeek parquet store replaces it without
    touching the policy rewriting below.
    """
    import duckdb
    con = duckdb.connect()
    con.execute("create table addrs(ip varchar, tok varchar)")
    # The flow file carries canonical addresses (docs/flow-record.md); the
    # inventory keeps the dataset's spelling, which for IPv6 is not that.
    con.executemany("insert into addrs values (?,?)",
                    [(canonical_ip(ip), tok) for ip, tok in owner.items()])
    con.execute("create table svc(tok varchar, proto varchar, port int)")
    con.executemany("insert into svc values (?,?,?)",
                    [(t, p, n) for t, s in listen.items() for p, n in sorted(s)])
    rows = con.execute(f"""
        select distinct a.tok, s.proto, s.port
          from read_json({flows!r}, format='newline_delimited',
                         columns={{'protocol': 'VARCHAR', 'dst_ip': 'VARCHAR',
                                   'dst_port': 'INTEGER'}}) f
          join addrs a on a.ip = f.dst_ip
          join svc s on s.tok = a.tok and s.port = f.dst_port
                    and s.proto = f.protocol""").fetchall()
    return {(t, p, n) for t, p, n in rows}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--flows", required=True, metavar="JSONL",
                    help="the learn file R2 was tightened against (night.jsonl); "
                         "a service with no inbound flow in it is dropped")
    ap.add_argument("--loot", default="loot-ossec", metavar="DIR")
    ap.add_argument("--defs", default="def", metavar="DIR")
    ap.add_argument("--policy", required=True, metavar="DIR",
                    help="the variant to close down, normally r2-tightened")
    ap.add_argument("--out", required=True, metavar="DIR")
    args = ap.parse_args()

    defs = pathlib.Path(args.defs)
    owner, meta = inventory(defs)
    listen, names = listeners(args.loot, meta)
    used = evidence(args.flows, listen, owner)
    token_ports = ports_of_token(defs)

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    kept = dropped = 0
    dropped_by_host = collections.Counter()

    for path in sorted(pathlib.Path(args.policy).glob("*.yml")):
        # tighten writes its reports beside the policies; they are R2's.
        if path.name.endswith((".blocked.yml", ".dead.yml", ".groups.yml")):
            continue
        with open(path) as fh:
            doc = _rt.load(fh)
        tok = path.stem
        for f in doc.get("filters", []):
            # Inbound flows are evidence for ingress terms only. An egress
            # term's service is the peer's, and judging it by connections
            # *to* this host deleted every one of them.
            if filter_directions(f) != {DIR_IN}:
                continue
            terms = []
            for t in f.get("terms", []):
                svc = t.get("destination-port")
                if t.get("action") != "accept" or not svc:
                    terms.append(t)               # structural, or the terminal
                    continue
                members = token_ports.get(svc) or set()
                if any((tok, p, n) in used for p, n in members):
                    terms.append(t)
                    kept += 1
                else:
                    dropped += 1
                    dropped_by_host[tok] += 1
            f["terms"] = terms
        doc.setdefault("metadata", {})["variant"] = (
            f"r4-block-early (learn file: {pathlib.Path(args.flows).name}) — services with no "
            f"observed client are removed, not merely narrowed")
        with open(out / path.name, "w") as fh:
            _rt.dump(doc, fh)

    print(f"{len(list(out.glob('*.yml')))} policies -> {out}  "
          f"(learn file: {args.flows})")
    print(f"  accept terms kept    {kept}")
    print(f"  accept terms dropped {dropped}  "
          f"across {len(dropped_by_host)} hosts")
    if dropped_by_host:
        top = ", ".join(f"{h.split('_')[0]} {n}"
                        for h, n in dropped_by_host.most_common(5))
        print(f"  most closed down: {top}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
