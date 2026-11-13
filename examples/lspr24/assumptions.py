#!/usr/bin/env python3
"""
assumptions — apply assumptions.yml: everything the case study assumes.

    python3 assumptions.py --loot loot-ossec/ --defs def/ \
        --assumptions assumptions.yml --out loot-assumed/ [--flows night.jsonl]

The dataset records listening sockets and traffic. It does not record a host's
dynamic port range, the Windows services that never changed while syscollector
watched, or who the blue team's administrators were, and the policies need all
three. Each is written down in assumptions.yml with its source and reasoning,
and this is the only code that turns them into data:

  loot-assumed/   a copy of the measured loot (loot-ossec/ is left as it is)
                  with metadata.ephemeral and metadata.ephemeral_source set,
                  and Windows hosts filled in from their baseline. A filled-in
                  listener carries the `inferred` flag and `inferred_from`, the
                  run it came from; an observed listener always wins.
  def/            MGMT_HOSTS defined, and every host's management source set to
                  it in host_metadata.json.

With --flows, the Windows fill is checked against the traffic: a filled-in
port that never answered and an answering port nothing explains are listed,
so the assumption is tested by the data rather than only asserted.
"""

import argparse
import collections
import gzip
import ipaddress
import json
import pathlib
import re
import sys

import yaml

from firru.defs_dir import STOCK_BASELINE
from firru.ephemeral import parse_range


def baseline(run):
    """A baseline run's listeners, from firru's stock-install records."""
    path = pathlib.Path(STOCK_BASELINE) / f"{run}.json.gz"
    if not path.is_file():
        sys.exit(f"assumptions: no baseline record {run} in {STOCK_BASELINE}")
    docs = json.loads(gzip.open(path).read())["documents"]
    return next(iter(docs.values()))["listen_ports"]


def reachable(entry):
    bind = str(entry.get("bind_address") or "")
    return not bind.startswith(("127.", "::1"))


def key(entry):
    return entry["protocol"], int(entry["port"])


def windows_fill(spec, dyn):
    """The listeners `spec` assumes, outside the host's dynamic range."""
    def in_dyn(e):
        lo, hi = dyn.get(e["protocol"], (65536, 65536))
        return lo <= int(e["port"]) <= hi

    chosen = {}                                   # (proto, port, bind) -> (entry, run)
    for e in baseline(spec["base"]):
        if reachable(e) and not in_dyn(e):
            chosen.setdefault((*key(e), e.get("bind_address")), (e, spec["base"]))
    for layer in spec.get("layers", []):
        stock = {key(e) for e in baseline(layer["minus"])} if layer.get("minus") else set()
        only = {(s.split("/")[0], int(s.split("/")[1])) for s in layer.get("only", [])}
        for e in baseline(layer["run"]):
            k = key(e)
            if not reachable(e) or in_dyn(e) or k in stock or (only and k not in only):
                continue
            chosen.setdefault((*k, e.get("bind_address")), (e, layer["run"]))
    return chosen


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--loot", required=True, metavar="DIR")
    ap.add_argument("--defs", required=True, metavar="DIR")
    ap.add_argument("--assumptions", required=True, metavar="FILE")
    ap.add_argument("--out", required=True, metavar="DIR")
    ap.add_argument("--flows", metavar="JSONL",
                    help="check the Windows fill against these flows")
    args = ap.parse_args()

    a = yaml.safe_load(pathlib.Path(args.assumptions).read_text())
    for section in ("dynamic_ranges", "windows", "mgmt_hosts"):
        if section not in a:
            sys.exit(f"assumptions: {args.assumptions} has no {section}")

    ranges = a["dynamic_ranges"]

    def range_for(host, os_name):
        e = (ranges.get("hosts") or {}).get(host) or ranges.get((os_name or "").lower())
        if not e:
            return None, None
        return ({p: list(parse_range(e[p])) for p in ("tcp", "udp") if e.get(p)},
                e["source"])

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("*.json"):
        old.unlink()
    filled = {}
    stats = collections.Counter()
    for path in sorted(pathlib.Path(args.loot).glob("*.json")):
        doc = json.loads(path.read_text())
        meta = doc["metadata"]
        host = path.stem
        assumed = []
        dyn, source = range_for(host, meta.get("os"))
        if dyn:
            meta["ephemeral"] = dyn
            meta["ephemeral_source"] = "assumed: " + source
            assumed.append("dynamic_ranges")
        spec = (a["windows"] or {}).get(host)
        if spec:
            seen = {key(e) for e in doc["listen_ports"]}
            add = []
            for (proto, port, _), (e, run) in sorted(windows_fill(spec, dyn or {}).items(),
                                                     key=lambda kv: (kv[0][0], kv[0][1], str(kv[0][2]))):
                if (proto, port) in seen:
                    continue
                add.append(dict(e, flags=sorted(set(e.get("flags") or []) | {"inferred"}),
                                inferred_from=run))
            doc["listen_ports"].extend(add)
            filled[host] = {(e["protocol"], int(e["port"])) for e in add}
            stats["listeners filled in"] += len(add)
            assumed.append("windows")
        if assumed:
            meta["assumed"] = assumed
        (out / path.name).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        stats["hosts"] += 1

    # MGMT_HOSTS: the blue team's own sources.
    m = a["mgmt_hosts"]
    nets = pathlib.Path(args.defs) / "networks.yml"
    text = nets.read_text()
    # Empty as defs_from_expoid writes it, or filled by an earlier run.
    block = re.compile(r"^  MGMT_HOSTS:[^\n]*\n    values:(?: \[\]\n|\n(?:      - [^\n]*\n)+)", re.M)
    if not block.search(text):
        sys.exit(f"assumptions: {nets} defines no MGMT_HOSTS")
    values = "".join(f"      - address: {ipaddress.ip_address(x)}\n" for x in m["addresses"])
    text = block.sub(f"  MGMT_HOSTS:   # assumed: {m['source']} (assumptions.yml)\n"
                     f"    values:\n{values}", text, count=1)
    nets.write_text(text)
    hm_path = pathlib.Path(args.defs) / "host_metadata.json"
    hm = json.loads(hm_path.read_text())
    for token, entry in hm.items():
        if isinstance(entry, dict) and "alias_of" not in entry:
            entry["mgmt"] = "MGMT_HOSTS"
    hm_path.write_text(json.dumps(hm, indent=2, sort_keys=True) + "\n")

    print(f"{stats['hosts']} hosts -> {out}: {stats['listeners filled in']} Windows "
          f"listeners filled in on {len(filled)} hosts; MGMT_HOSTS = "
          f"{len(m['addresses'])} addresses")

    if args.flows and filled:
        check(args.flows, filled, out, pathlib.Path(args.defs), hm)
    return 0


def check(flows, filled, out, defs, hm):
    """Filled-in ports against what answered, per Windows host."""
    import duckdb
    nets = yaml.safe_load((defs / "networks.yml").read_text())["networks"]
    con = duckdb.connect()
    print("\nWindows fill against the flows (TCP ports that answered):")
    for host, inferred in sorted(filled.items()):
        token = (hm.get(host) or {}).get("alias_of") or host
        addrs = [ipaddress.ip_address(v["address"].split("/")[0]).compressed
                 for v in (nets.get(token) or {}).get("values", []) if "address" in v]
        doc = json.loads((out / f"{host}.json").read_text())
        dyn = doc["metadata"].get("ephemeral", {}).get("tcp", [65536, 65536])
        listening = {key(e) for e in doc["listen_ports"]}
        if not addrs:
            print(f"  {host}: no addresses in the inventory, not checked")
            continue
        ph = ",".join("?" * len(addrs))
        answered = {p for (p,) in con.execute(
            f"select distinct dst_port from read_json(?, format='newline_delimited', "
            f"columns={{'dst_ip':'VARCHAR','dst_port':'INTEGER','protocol':'VARCHAR','responded':'BOOLEAN'}}) "
            f"where protocol='tcp' and responded and dst_ip in ({ph})", [flows, *addrs]).fetchall()
            if not dyn[0] <= p <= dyn[1]}
        quiet = sorted(p for proto, p in inferred if proto == "tcp" and p not in answered)
        unexplained = sorted(p for p in answered if ("tcp", p) not in listening)
        print(f"  {host:10} answered {len(answered):2}  inferred, never answered {quiet or '-'}"
              f"  answered, nothing listening {unexplained or '-'}")


if __name__ == "__main__":
    sys.exit(main())
