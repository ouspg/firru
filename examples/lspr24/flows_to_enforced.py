#!/usr/bin/env python3
"""
flows_to_enforced — reconstruct the policy that appears to have been running.

    python3 flows_to_enforced.py --parquet lspr24_v2.parquet --loot loot-ossec/ \
        --defs def/ --out policies/r3-apparent/
    firru diff policies/r1-synthesized policies/r3-apparent --defs def/

LSPR24 ships no firewall configuration. Its hosts were almost certainly running
one and nothing in the dataset says what, so the deployed arm of the
committed/deployed/practice comparison is simply missing -- which is the gap
the pipeline exists to close, and the reason this example could only ever show
the counterfactual half of the argument.

The listening table closes part of it. `Conn_state` names no blocked connection
anywhere in LSPR24 (`S0` and `REJ` occur zero times in 20.2M rows), but a flow
that got no packet back is visible, and the socket inventory says whether
anything was listening to answer it. That splits the unanswered flows in two,
and the half that reached a live listener is the only place an enforcement
decision could have been made.

WHAT THIS IS AND IS NOT. It is a hypothesis rendered as a policy so it can be
diffed, not a recovered configuration. Three things produce the same evidence
as a drop -- the host being down, the application refusing above the transport,
and one-sided capture -- and nothing here separates them. So:

  * A deny term is emitted only for TCP, only where a service that answered
    *nobody* was *tried by somebody*, and only where the host answered on some
    other port in the same window. A host that answered nothing was
    unreachable rather than filtered, and the first version of this tool
    called three such hosts a firewall rule.

    TCP only because silence means something there and nothing in UDP: a UDP
    service that never replies is behaving normally, so "no packets back" is
    not evidence of refusal. Dropping the restriction surfaces exactly one
    inferred deny on this dataset and it is a UDP listener.

    `--min-tries` defaults to 1: scored against Zeek `conn_state` on the
    capture it was calibrated on, refusals were as genuine (S0 or REJ) at one
    refused source as at more, so raising the threshold discards services
    without improving the evidence. The host-answered-something-else guard is
    what carries the weight. LSPR24 cannot check this itself: S0 and REJ occur
    zero times in its 20.2M rows.
  * A narrowed source is emitted only where some sources were answered on a
    service and others were not, which is the one pattern host-down cannot
    produce: a dead host answers no one.
  * A service is left at ANY whenever every source that tried was answered.

Read the diff against `policies/r1-synthesized`, not this file alone. A term this
tool narrows that synthesis left open is a candidate enforcement point; a term
synthesis emitted that never saw a client is the block-early bet the ladder
already prices. The value is the disagreement, which is what `firru diff`
shows.
"""

import argparse
import collections
import ipaddress
import json
import pathlib
import sys

import yaml

WINDOWS = {                                   # exercise windows, UTC hours
    "d1":    ("2024-03-06 10", "2024-03-06 18"),
    "d2":    ("2024-03-07 08", "2024-03-07 17"),
    "night": ("2024-03-06 18", "2024-03-07 08"),
    "all":   (None, None),
}


def inventory(defs):
    """(address -> token, token -> zone/segment metadata)."""
    nets = (yaml.safe_load((defs / "networks.yml").read_text()) or {}).get("networks", {})
    meta = json.loads((defs / "host_metadata.json").read_text())
    owner = {}
    for token, spec in nets.items():
        if token not in meta or "alias_of" in meta[token]:
            continue
        for v in (spec or {}).get("values", []):
            if isinstance(v, dict) and "address" in v:
                owner[v["address"]] = token
    return owner, meta


def service_tokens(defs):
    """
    (proto, port) -> the token synthesis would name, so the diff compares
    terms rather than spellings. Without this every term reads as changed
    because one side says SSH and the other TCP_22.
    """
    out = {}
    for path in sorted(defs.glob("services*.yml")):
        doc = (yaml.safe_load(path.read_text()) or {}).get("services", {})
        for token, entries in doc.items():
            for e in entries or []:
                if not isinstance(e, dict) or "port" not in e:
                    continue
                proto = e.get("protocol", "tcp")
                lo, _, hi = str(e["port"]).partition("-")
                if hi:                      # a range names no single service
                    continue
                out.setdefault((proto, int(lo)), token)
    return out


def listeners(loot, meta):
    """token -> {(proto, port)}, loopback-only binds excluded as unreachable."""
    out = collections.defaultdict(set)
    names = {}
    for path in sorted(pathlib.Path(loot).glob("*.json")):
        doc = json.loads(path.read_text())
        host = doc["metadata"]["hostname"]
        token = host.lower()
        if token in meta and "alias_of" in meta[token]:
            token = meta[token]["alias_of"]
        if token not in meta:
            continue
        names[token] = host
        for e in doc["listen_ports"]:
            addr = ipaddress.ip_address(e["bind_address"].split("/")[0])
            if not addr.is_loopback:
                out[token].add((e["protocol"], e["port"]))
    return out, names


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--parquet", required=True)
    ap.add_argument("--loot", default="loot-ossec", metavar="DIR")
    ap.add_argument("--defs", default="def", metavar="DIR")
    ap.add_argument("--out", required=True, metavar="DIR")
    ap.add_argument("--window", choices=sorted(WINDOWS), default="all")
    ap.add_argument("--min-tries", type=int, default=1, metavar="N",
                    help="distinct sources that must have been refused before "
                         "a deny is emitted (default 1: a second source "
                         "adds no evidence)")
    args = ap.parse_args()

    import duckdb
    con = duckdb.connect()
    P = repr(args.parquet)
    defs = pathlib.Path(args.defs)
    owner, meta = inventory(defs)
    listen, names = listeners(args.loot, meta)

    con.execute("create table addrs(ip varchar, tok varchar)")
    con.executemany("insert into addrs values (?,?)", list(owner.items()))
    con.execute("create table svc(tok varchar, proto varchar, port int)")
    con.executemany("insert into svc values (?,?,?)",
                    [(t, p, n) for t, s in listen.items() for p, n in sorted(s)])

    start, end = WINDOWS[args.window]
    clause = ""
    if start:
        clause = (f"""and f."mTimestampStart"/1000000
                      between epoch(timestamp '{start}:00:00')
                          and epoch(timestamp '{end}:00:00')""")

    # One row per (service, source): was that source ever answered?
    rows = con.execute(f"""
        select a.tok, s.proto, s.port, f."SrcIP" src,
               max(case when f."Tot Bwd Pkts" > 0 then 1 else 0 end) answered
          from read_parquet({P}) f
          join addrs a on a.ip = f."DstIP"
          join svc s on s.tok = a.tok and s.port = f."DstPort"
                    and s.proto = (case when f."Protocol" = 6 then 'tcp' else 'udp' end)
         where 1=1 {clause}
         group by 1,2,3,4""").fetchall()

    seen = collections.defaultdict(lambda: {"yes": set(), "no": set()})
    for tok, proto, port, src, answered in rows:
        seen[(tok, proto, port)]["yes" if answered else "no"].add(src)

    # A host that answered nothing anywhere was unreachable in this window --
    # powered off, not yet built, or behind a link that was down. Calling that
    # a firewall rule is the easiest mistake this tool can make, and it made
    # it: the first run reported the three fiveg-ue simulators as dropping
    # SSH when in truth they answered nothing at all.
    alive = {tok for (tok, _, _), ev in seen.items() if ev["yes"]}
    svc_token = service_tokens(defs)

    # Listening services no flow ever touched. These never reach `seen` -- the
    # join has nothing to join them to -- so counting them in the loop below
    # misses them entirely, which is how this reported "no evidence 1" for
    # what is actually 149 services. They get no term and the terminal drop
    # covers them, which is the correct shape: the absence of an accept is a
    # default, while an explicit deny would assert an enforcement decision
    # that nobody ever gave the network a chance to make.
    untouched = sum(1 for tok, svcs in listen.items() for ps in [svcs]
                    for pp in ps if (tok, pp[0], pp[1]) not in seen)

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stats = collections.Counter()
    per_host = collections.defaultdict(list)

    for (tok, proto, port), ev in sorted(seen.items()):
        yes, no = ev["yes"], ev["no"]
        # A port with no name gets no term, as in synthesis: these are the
        # ports def/services-observed.yml leaves unnamed on purpose (an sshd
        # on an ephemeral port, say), and a term would name an undefined
        # service and not compile.
        port_token = svc_token.get((proto, port))
        if port_token is None:
            stats["unnamed port, no term"] += 1
            continue
        # UDP silence is not refusal: a UDP service that never answers is
        # working as designed, so the whole inference only holds for TCP.
        deniable = proto == "tcp" and not yes and len(no) >= args.min_tries
        if deniable and tok not in alive:
            stats["host unreachable in window"] += 1
            continue
        if deniable:
            # Tried by several, answered nobody. The only shape that reads as
            # a drop without also reading as "no client existed".
            per_host[tok].append({
                "name": f"deny-{proto}-{port_token}", "protocol": proto,
                "destination-port": port_token,
                "action": "deny",
                "comment": f"listening; {len(no)} sources tried, none answered",
            })
            stats["denied"] += 1
        elif yes and no:
            # Some answered, some not, on a live service: the one pattern a
            # dead host cannot produce. Named sources only -- an unnamed
            # source resolves to nothing, so the term keeps ANY, which is the
            # pipeline's rule and not a special case here.
            toks = sorted({owner[a] for a in yes if a in owner})
            src = toks if toks and len(toks) == len({a for a in yes}) else "ANY"
            per_host[tok].append({
                "name": f"allow-{proto}-{port_token}", "protocol": proto,
                "destination-port": port_token,
                "action": "accept", "source-address": src,
                "comment": (f"{len(yes)} sources answered, {len(no)} not"),
            })
            stats["narrowed" if src != "ANY" else "mixed-but-external"] += 1
        elif yes:
            per_host[tok].append({
                "name": f"allow-{proto}-{port_token}", "protocol": proto,
                "destination-port": port_token,
                "action": "accept", "source-address": "ANY",
                "comment": f"every one of {len(yes)} sources was answered",
            })
            stats["open"] += 1
        else:
            stats["no evidence"] += 1

    for tok, terms in sorted(per_host.items()):
        m = meta.get(tok, {})
        doc = {
            "metadata": {"host": names.get(tok, tok), "zone": m.get("zone"),
                         "provenance": "flows_to_enforced.py — INFERRED, "
                                       "not a recovered configuration"},
            "filters": [{"header": {"targets": {"nftables": "mixed input DROP"}},
                         "terms": terms + [{"name": "drop-ANY", "action": "deny"}]}],
        }
        # Named by the inventory token, as synthesis is, so `firru diff` can
        # pair the two sides by filename. A short label cannot: this archive
        # has a DC1 and a dc1 in different zones.
        (out / f"{tok}.yml").write_text(
            yaml.safe_dump(doc, sort_keys=False, default_flow_style=False))

    print(f"{len(per_host)} hosts -> {out}  (window={args.window})")
    stats["never tried by anyone"] = untouched
    for k in ("open", "narrowed", "mixed-but-external", "denied",
              "host unreachable in window", "never tried by anyone"):
        if stats[k]:
            print(f"  {k:<26} {stats[k]}")
    print("\nServices nobody tried get no term; the policy's terminal drop\n"
          "covers them. That is deliberate -- an explicit deny would assert an\n"
          "enforcement decision the network was never asked to make. Dropping\n"
          "them on purpose is the block-early variant, which is a choice\n"
          "rather than an inference.")
    print("\nINFERRED. A drop, a host that was down, an application refusing "
          "above\nthe transport and one-sided capture all look the same here. "
          "Diff it\nagainst policies/r1-synthesized; the disagreement is the "
          "finding, not\nthis file on its own.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
