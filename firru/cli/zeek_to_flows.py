#!/usr/bin/env python3
"""
zeek-to-flows — Turn Zeek conn.log into the flow schema the rest of the
pipeline consumes, with no Arkime/Elastic in the loop.

For post-exercise analysis the input is raw pcap: run Zeek over it and feed
the conn.log here.

    zstd -dc capture.pcap.zst | zeek -r - LogAscii::use_json=T
    zeek-to-flows conn.log > flows.jsonl     # conn.log may be JSON or TSV
    flow-verdict --pol policies/pol --defs def [...] flows.jsonl > annotated.jsonl

Multiple conn.log files (batched extraction) may be passed at once; each is
streamed, so a large log does not have to fit in memory.

Output is one JSON object per connection, the same shape as
firru.arkime.process_flow so flow-verdict and flow_analysis.sql are
unchanged:

    protocol src_ip dst_ip src_port dst_port originator
    timestamp end_time orig_pkts resp_pkts responded conn_state

PRACTICE AXIS (responded). For TCP the admitted/blocked signal is taken from
Zeek's `history` field: a lowercase 'h' is a responder SYN-ACK, i.e. the
listener answered = admitted. No 'h' = blocked. This is finer than Arkime's
`responded = syn-ack OR any responder packet`: it keeps a RST refusal (REJ,
responder sent only 'r') and a silent drop (S0, no responder letters) on the
*blocked* side, where Arkime's resp-packet test would call the REJ admitted.
The raw `conn_state` is passed through so either definition can be recovered
downstream. For UDP/ICMP (no handshake) responded falls back to "any
responder packet seen", matching Arkime.

Caveat (same as Arkime): under partial capture an uncaptured return path
reads as not-responded.

With --out-parquet the conversion is done in SQL and lands in an
hour-partitioned parquet store rather than JSONL:

    zeek-to-flows --out-parquet flows/store zeek/conn

That reads parquet input only, and is the route to prefer at exercise scale:
no line of JSON is ever built, and the store is the input tighten and the
diff's --flows already read. The JSONL route stays the default and is the only
one that reads TSV or JSON conn.log.

`fqdn` is null here. Naming destinations (--dns) is the name-labeling layer in
firru.namemap, and the option exists only where that module is installed.
"""

import argparse
import gzip
import pathlib
import json
import os
import sys

from firru.flows import naming, zeek_direction_known


def _open(path):
    if path == "-":
        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt")
    return open(path)


def parse_parquet(path):
    """
    Stream a Zeek conn export held as parquet, yielding one dict per row.

    A conn.log that has been folded to parquet -- which is how a multi-day
    capture is kept once the JSONL no longer fits anywhere -- carries the same
    flat dotted column names as the JSON and TSV forms, so nothing downstream
    changes. Read in batches rather than whole: a multi-day export runs to
    100M rows and materialising it as Python dicts at once is not possible.

    A directory or a glob is expanded, so an hourly-partitioned export is one
    argument. duckdb is imported here because the JSON and TSV paths must keep
    working without it.
    """
    import duckdb
    con = duckdb.connect()
    src = f"{path}/*.parquet" if pathlib.Path(path).is_dir() else path
    res = con.execute(f"select * from read_parquet({src!r})")
    names = [d[0] for d in res.description]
    while True:
        rows = res.fetchmany(50_000)
        if not rows:
            return
        for row in rows:
            yield dict(zip(names, row))


def parse_zeek(path):
    """Stream a Zeek log (JSON, TSV or parquet), yielding one dict per row.

    Auto-detected per line: a line starting with '{' is a JSON record
    (LogAscii::use_json=T); otherwise the default TSV, where the #fields header
    names the columns and other #comment lines are skipped. Zeek's JSON uses
    flat dotted keys (``id.orig_h`` etc.) identical to the TSV column names, so
    downstream field access is the same either way. A parquet file, or a
    directory of them, is read through duckdb by the same rule.
    """
    if str(path).endswith(".parquet") or pathlib.Path(path).is_dir():
        yield from parse_parquet(path)
        return
    fields = None
    f = _open(path)
    try:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            if line[0] == "{":
                yield json.loads(line)
            elif line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            elif fields:
                yield dict(zip(fields, line.split("\t")))
    finally:
        if f is not sys.stdin:
            f.close()


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _responded(proto, history, resp_pkts):
    if proto == "tcp":
        return "h" in (history or "")        # responder SYN-ACK
    return (resp_pkts or 0) > 0              # udp/icmp: any return traffic


def _float(v):
    """
    A Zeek numeric field, or None.

    The text forms write an absent value as "-" and float() rejects that with
    ValueError; parquet writes a real NULL and float() rejects that with
    TypeError. Catching only the first meant a single null `duration` killed
    the generator mid-stream -- 26 of 427,420 rows converted, with the
    traceback going to stderr where a `2>/dev/null` in a pipeline hides it.
    """
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def conn_to_flow(row, label=None):
    """Convert a conn.log row to a flow dict matching arkime.process_flow.

    `timestamp` and `end_time` keep zeek's fractional seconds. They used to be
    truncated to whole seconds, which is lossless for the policy-in-force
    lookup (git commit times) and destroys everything else: a busy hour of ~4M
    flows has nearly as many distinct sub-second times, and int() collapses
    those into 3,600 one-second buckets. A consumer ordering flows against each
    other saw ~1,000 simultaneous events per bucket.

    `label(ip, ts)` names the destination, or returns None; firru.namemap
    supplies one for --dns.
    """
    ts = _float(row.get("ts"))
    if ts is None:
        return None

    proto = (row.get("proto") or "-").lower()
    src_ip, dst_ip = row.get("id.orig_h", "-"), row.get("id.resp_h", "-")
    if proto == "-" or src_ip == "-" or dst_ip == "-":
        return None

    duration = _float(row.get("duration"))
    if duration is None:
        duration = 0.0

    history = row.get("history", "")
    resp_pkts = _int(row.get("resp_pkts"))

    flow = {
        "protocol":   proto,
        "src_ip":     src_ip,
        "dst_ip":     dst_ip,
        "src_port":   _int(row.get("id.orig_p")),
        "dst_port":   _int(row.get("id.resp_p")),
        "originator": src_ip,
        "timestamp":  ts,
        "end_time":   ts + duration,
        "orig_pkts":  _int(row.get("orig_pkts")),
        "resp_pkts":  resp_pkts,
        "responded":  _responded(proto, history, resp_pkts),
        "conn_state": row.get("conn_state"),
        "source":     "zeek",
        "direction_known": zeek_direction_known(row.get("conn_state")),
    }

    if label is not None:
        fqdn = label(dst_ip, ts)
        if fqdn:
            flow["fqdn"] = fqdn

    return flow


# The flow columns the SQL path writes, in order. Same fields conn_to_flow
# builds, so a parquet run and a JSONL run of the same input differ only in
# their container. `fqdn` is always written, null without --dns, so a store
# appended one run at a time reads back as one glob.
# conn -> flow, in SQL. The projection lives in firru.flows, because a zeek
# conn store is now read as a flow source directly and both paths have to agree
# column for column.
from firru.flows import (ZEEK_COLUMNS as _SQL_COLUMNS,
                         ZEEK_KEEP_ROW as _SQL_KEEP_ROW)


def _parquet_src(paths):
    """The read_parquet argument for these inputs, or None if any is not
    parquet -- the SQL path reads parquet only."""
    out = []
    for p in paths:
        if str(p).endswith(".parquet"):
            out.append(str(p))
        elif pathlib.Path(p).is_dir():
            out.append(f"{p}/*.parquet")
        else:
            return None
    return out


def write_parquet_store(conn_paths, out_dir, dns_paths=None, dns_window=300,
                        name_map=None, kinds=None):
    """Convert zeek parquet straight to a partitioned flow store, in SQL.

    Every field of a flow is an expression over the conn columns, and the name
    label is an ASOF join against the claim map. Written that way no row is
    ever a Python object: a ~150M-flow export against ~10M name claims
    converts in minutes to a ~2.4GB store, where the JSONL route spends
    ~23 minutes and 30GB of disk on an intermediate that is read once and
    deleted.

    The layout is Hive hour partitions, which the readers glob.

    ``fqdn`` is the latest name claimed for the address at or before the flow,
    from any of the three places zeek records one: a dns answer, a TLS SNI, an
    HTTP Host header. ``kinds`` restricts that to a subset ({'dns'} for answers
    only); ``name_map`` overrides where the cache lives, which only tests need.
    """
    import duckdb
    from firru.flows import ZEEK_FLOW_COLUMNS, check_appendable
    # what the COPY below writes: the projection, plus fqdn (always written,
    # null without --dns) and the hive partition column
    refuse = check_appendable(str(out_dir),
                              ZEEK_FLOW_COLUMNS + ("fqdn", "hour"))
    if refuse:
        raise ValueError(refuse)
    con = duckdb.connect()

    src = _parquet_src(conn_paths)
    if src is None:
        raise ValueError("--out-parquet reads parquet input only; for text logs "
                         "use the JSONL output")

    fqdn, join = "CAST(NULL AS VARCHAR) AS fqdn", ""
    if dns_paths:
        names = naming()
        if names is None:
            raise ValueError("--dns needs the name-labeling layer (firru.namemap), "
                             "which this install does not have")
        if _parquet_src(dns_paths) is None:
            raise ValueError("--out-parquet needs parquet --dns input too")
        fqdn, join = names.store_name_join(con, _parquet_src(conn_paths),
                                           dns_paths, dns_window, name_map, kinds)

    os.makedirs(out_dir, exist_ok=True)
    con.execute(f"""
        COPY (
          SELECT {_SQL_COLUMNS} {fqdn},
                 strftime(to_timestamp(c.ts), '%Y-%m-%dT%H') AS hour
          FROM (SELECT * FROM read_parquet({src!r}) WHERE {_SQL_KEEP_ROW}) c
          {join}
        ) TO {str(out_dir)!r}
        (FORMAT parquet, PARTITION_BY (hour), OVERWRITE_OR_IGNORE,
         FILENAME_PATTERN 'part-{{i}}')
    """)

    written = con.sql("SELECT count(*), count(fqdn) FROM read_parquet(?)",
                      params=[os.path.join(str(out_dir), "**", "*.parquet")]).fetchall()[0]
    msg = f"# {written[0]} flows -> {out_dir}"
    if dns_paths:
        msg += f", {written[1]} name-labeled"
    print(msg, file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[1],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("conn", nargs="*", default=["conn.log"],
                    help="Zeek conn.log file(s), a parquet export, or a directory "
                         "of parquet; '-' for stdin (default: conn.log)")
    names = naming()
    if names is not None:
        ap.add_argument("--dns", action="append", metavar="FILE",
                        help="Zeek dns.log to label flows with fqdn (repeatable; off by default)")
        ap.add_argument("--dns-window", type=int, default=300,
                        help="max seconds between a DNS answer and the flow (default 300)")
    ap.set_defaults(dns=None, dns_window=300)
    ap.add_argument("--out-parquet", metavar="DIR",
                    help="write an hour-partitioned parquet flow store instead of "
                         "JSONL, converting in SQL (parquet input only, much faster)")
    args = ap.parse_args()

    if args.out_parquet:
        try:
            return write_parquet_store(args.conn, args.out_parquet,
                                       args.dns, args.dns_window)
        except ValueError as e:
            print(f"zeek-to-flows: {e}", file=sys.stderr)
            return 2

    label = None
    if args.dns:
        dns_map = names.build_dns_map(args.dns)
        print(f"# {len(dns_map)} DNS answer IPs mapped from {len(args.dns)} log(s)",
              file=sys.stderr)
        label = lambda ip, ts: names.lookup_fqdn(dns_map, ip, ts, args.dns_window)

    out = sys.stdout.write
    count = labeled = skipped = 0
    for path in args.conn:
        for row in parse_zeek(path):
            flow = conn_to_flow(row, label)
            if flow is None:
                skipped += 1
                continue
            out(json.dumps(flow) + "\n")
            count += 1
            if "fqdn" in flow:
                labeled += 1

    msg = f"# {count} flows emitted"
    if label is not None:
        msg += f", {labeled} DNS-labeled"
    if skipped:
        msg += f", {skipped} rows skipped"
    print(msg, file=sys.stderr)


if __name__ == "__main__":
    main()
