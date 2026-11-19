#!/usr/bin/env python3
"""
lspr24_to_flows.py — Turn the public LSPR24 parquet into the flow schema the rest
of the pipeline consumes, with no Arkime/Elastic in the loop.

LSPR24 is the Locked Shields Partner Run 2024 flow dataset: ~20.2M flows over
2024-03-01..03-07, CICFlowMeter features plus a Zeek `conn_state` and per-host
FQDNs. It is the one public dataset firru can be driven end-to-end on.

    python lspr24_to_flows.py data/lspr24_v2.parquet --store data/flows/   # all of it
    python lspr24_to_flows.py data/lspr24_v2.parquet --window night > night.jsonl

--store writes the flows as the hour-partitioned parquet store zeek-to-flows
writes, which firru tighten and firru diff read for a window
(`--window night`); without it, one JSON object per flow goes to stdout. Both
have the shape of firru.arkime.process_flow and zeek-to-flows:

    protocol src_ip dst_ip src_port dst_port originator
    timestamp end_time orig_pkts resp_pkts responded conn_state

PRACTICE AXIS (responded). LSPR24 has no Zeek `history` field, so the
admitted/blocked signal is taken from `Conn_state`: the states below mean the
responder sent a SYN-ACK (= the listener answered = admitted). A RST refusal
(REJ) and a silent drop (S0) stay on the *blocked* side, matching
zeek-to-flows rather than Arkime's looser "any responder packet" test. `OTH`
(midstream capture, no handshake observed) carries no handshake evidence
either way, so it falls back to the packet-count test -- with one correction.
A bare `resp_pkts > 0` test counts a RST refusal as an answer, because the
RST *is* a returned packet. On d1 that mislabels 85,313 flows, and they are
not spread evenly: they concentrate in port scans, since a scan is what hits
closed ports. One 15-minute window of a sweep across gas-hmi and
gas-historian was 100% of this error. So an OTH flow that returned a single
packet carrying a RST is treated as refused. The cut is unambiguous in the
data: those flows average 20 bytes back against one forward SYN, while
flows with 4+ returned packets average hundreds to thousands of bytes and
are real sessions that happened to end in a reset. --refusal-max-pkts
widens or disables it. The raw conn_state is passed through so either
definition can be recovered downstream.

IPv6 TCP is different. Every one of LSPR24's 2.41M IPv6 TCP rows has all TCP
flags at zero, a window of 0 and often no payload: the CICFlowMeter that
produced the dataset does not read the TCP header on its IPv6 path. With no
flags there is no handshake evidence and no RST test, and the backward count
comes from the same parser. So an IPv6 TCP row is `responded: true` only when
more packets came back than a lone refusal sends, and otherwise `null`
(unknown), never `false`: nothing in the row can show a refusal.

WINDOWS. The exercise is two execution days with an attack-free night between
them; the 03-01..03-05 run-up is idle (~58 flows/hour) and excluded by every
window. The windows are firru.toml's, beside this script (UTC+02, the
timestamps' local zone):

    d1        2024-03-06 10:00-18:00    5,027,792 flows, 4.173% red
    night     2024-03-06 19:00-08:00    9,385,895 flows, 0.009% red
    d1+night  2024-03-06 10:00-08:00   15,121,074 flows (18:00-19:00 too)
    d2        2024-03-07 08:00-18:00    5,099,940 flows, 5.954% red
    all       everything in the file (the default), 20,227,356 flows

"Red" is a flow with a red-team host at either end (rt_src or rt_dst).

`night` is the natural learning window: it is attack-free by the exercise
schedule, so a policy derived from it does not depend on the dataset's Label
column (which is circular — Label is defined as "the peer is a red-team host",
not as a behavioural detection).

TIMES. --window names one; --since and --until take what journalctl takes
(firru.times): `night`, `"d2 09:00"`, `"2024-03-07 12:00"`, `"-2h"`, with a
window name standing for a day. Times are in UTC+02 unless they say ` UTC`.
The window used is printed, in UTC, before any flow.

THE STORE is written in SQL, not row by row: every field above is an
expression over the dataset's columns, so all 20M rows convert in seconds.
The two paths are pinned to agree by test_lspr24_to_flows.py, which writes
both from the same rows.

CAVEAT. Under partial capture an uncaptured return path reads as
not-responded, the same caveat Arkime and Zeek carry.
"""

import argparse
import functools
import ipaddress
import json
import pathlib
import sys
from datetime import timezone

from firru import project
from firru.flows import DIRECTED_STATES, zeek_direction_known

# LSPR24 stores the IANA protocol number; the pipeline wants a name.
PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6", 132: "sctp"}

# Zeek conn_state values where the responder sent a SYN-ACK, i.e. admitted.
# S0/REJ/RSTOS0/SH have no responder SYN-ACK and stay blocked. OTH is
# midstream with no handshake evidence and falls back to the packet test.
RESPONDED_STATES = frozenset({"SF", "S1", "S2", "S3", "RSTO", "RSTR", "RSTRH", "SHR"})
BLOCKED_STATES = frozenset({"S0", "REJ", "RSTOS0", "SH"})

# An OTH flow returning at most this many packets, one of them a RST, is a
# refusal rather than an answer. 1 is the near-unambiguous case (SYN -> RST);
# see the note on the practice axis above.
REFUSAL_MAX_PKTS = 1

# The windows and their zone, from the firru.toml beside this script, so every
# script in the example and every firru command run here agree on them.
PROJECT = project.load(pathlib.Path(__file__).resolve().parent)
WINDOWS = PROJECT.windows
TIMES = PROJECT.times()

# The 13 of 101 columns actually needed; projecting them keeps the 2.8 GB file
# streamable in a few hundred MB.
COLUMNS = [
    "SrcIP", "DstIP", "SrcPort", "DstPort", "Protocol",
    "mTimestampStart", "mTimestampLast",
    "Tot Fwd Pkts", "Tot Bwd Pkts", "Conn_state", "RST Flag Cnt",
    "Label_src", "Label_dst",
]

# Label_src/Label_dst == 1 marks a red-team host, emitted as the record's
# `rt_src`/`rt_dst` (docs/flow-record.md, "Conditional fields"). This is
# exercise ground truth about *who the peer is*, not a detection result — see
# the note on Label's circularity in the LSPR24 example README. Emitted only so
# an inventory step can name red-team addresses; never use it to score a policy.
# Note the column is a STRING in the parquet ('0'/'1'/'2'), not an integer.
RED_TEAM_LABEL = "1"


def _responded(conn_state, resp_pkts, rst_cnt=0, max_refusal_pkts=REFUSAL_MAX_PKTS):
    """Practice-outcome signal: did the listener answer? See module docstring."""
    if conn_state in RESPONDED_STATES:
        return True
    if conn_state in BLOCKED_STATES:
        return False
    # OTH / missing: no handshake evidence, so fall back to the packets that
    # came back -- but a lone RST is a refusal, not an answer.
    n = resp_pkts or 0
    if max_refusal_pkts >= 0 and 0 < n <= max_refusal_pkts and (rst_cnt or 0) > 0:
        return False
    return n > 0


def _responded_v6_tcp(resp_pkts, max_refusal_pkts=REFUSAL_MAX_PKTS):
    """IPv6 TCP rows carry no flags (see module docstring): an answer shows as
    more returned packets than a refusal sends; anything less is unknown."""
    n = resp_pkts or 0
    return True if n > max(max_refusal_pkts, 0) else None


@functools.lru_cache(maxsize=1 << 16)
def canonical_ip(ip):
    """RFC 5952 text form, as the flow record requires: LSPR24 writes IPv6
    fully expanded (2a07:1182:0005:0012:0000:...), which no definition or
    other producer spells that way, so every v6 flow went unmatched."""
    try:
        return ipaddress.ip_address(ip).compressed
    except ValueError:
        return ip


def row_to_flow(row, max_refusal_pkts=REFUSAL_MAX_PKTS):
    """Convert one LSPR24 record dict to a flow dict matching process_flow."""
    src_ip, dst_ip = row.get("SrcIP"), row.get("DstIP")
    src_ip = canonical_ip(src_ip) if src_ip else src_ip
    dst_ip = canonical_ip(dst_ip) if dst_ip else dst_ip
    proto_num = row.get("Protocol")
    if not src_ip or not dst_ip or proto_num is None:
        return None

    proto = PROTO_NAMES.get(proto_num, str(proto_num))
    start, last = row.get("mTimestampStart"), row.get("mTimestampLast")
    resp_pkts = row.get("Tot Bwd Pkts")
    conn_state = row.get("Conn_state")

    flow = {
        "protocol":   proto,
        "src_ip":     src_ip,
        "dst_ip":     dst_ip,
        "src_port":   row.get("SrcPort"),
        "dst_port":   row.get("DstPort"),
        # LSPR24 records the originator as SrcIP, as Zeek's id.orig_h does.
        "originator": src_ip,
        # Timestamps are MICROseconds, not the milliseconds Arkime uses.
        "timestamp":  int(start // 1_000_000) if start is not None else None,
        "end_time":   int(last // 1_000_000) if last is not None else None,
        "orig_pkts":  row.get("Tot Fwd Pkts"),
        "resp_pkts":  resp_pkts,
        "responded":  (_responded_v6_tcp(resp_pkts, max_refusal_pkts)
                       if proto == "tcp" and ":" in src_ip else
                       _responded(conn_state, resp_pkts,
                                  row.get("RST Flag Cnt"), max_refusal_pkts)),
        "conn_state": conn_state,
        "source":     "lspr24",
        "direction_known": zeek_direction_known(conn_state),
    }

    # Written whenever the label column was there to read, `false` included:
    # absent means "not evaluated", not "not red team". A consumer counting the
    # clean arm filters on NOT rt_src, and a missing field is null, so the row
    # would fall out of both arms rather than into the clean one.
    for column, field in (("Label_src", "rt_src"), ("Label_dst", "rt_dst")):
        if row.get(column) is not None:
            flow[field] = str(row[column]) == RED_TEAM_LABEL

    return flow


def flow_rows(flows, window=None):
    """SQL for the flow records in `flows`, a store or a JSONL file, cut to a
    window firru.toml names (or all of them)."""
    from firru.flows import flow_relation, is_parquet, window_where
    if is_parquet(flows):
        rel, columns = flow_relation(flows), {"timestamp", "hour"}
    else:
        rel, columns = f"read_json({flows!r}, format='newline_delimited')", {"timestamp"}
    if not window:
        return rel
    span = tuple(t.timestamp() for t in TIMES.window(window))
    return f"(SELECT * FROM {rel} WHERE {' AND '.join(window_where(span, columns))})"


def micros(text, end=False):
    """A --since/--until value (firru.times, UTC+02 unless it says UTC) as the
    epoch microseconds LSPR24 timestamps are written in."""
    return int(TIMES.parse(text, end=end).timestamp() * 1_000_000)


def iter_rows(path, lo, hi, batch_size=131072):
    """Stream the parquet in batches, yielding row dicts inside the window."""
    try:
        import pyarrow.parquet as pq
    except ImportError:
        sys.exit("lspr24_to_flows.py needs pyarrow: pip install 'firru[lspr24]'")

    # The window arrives as integer bounds (or None for all of it): comparing
    # per row would otherwise be a datetime construction across 20M rows.
    pf = pq.ParquetFile(path)
    for batch in pf.iter_batches(batch_size=batch_size, columns=COLUMNS):
        if lo is not None:
            # Filter in Arrow before materializing Python objects.
            col = batch.column("mTimestampStart")
            import pyarrow.compute as pc
            batch = batch.filter(pc.and_(pc.greater_equal(col, lo), pc.less(col, hi)))
            if batch.num_rows == 0:
                continue
        yield from batch.to_pylist()


def _sql_list(values):
    return ", ".join(f"'{v}'" for v in sorted(values))


def write_store(path, out, lo=None, hi=None, max_refusal_pkts=REFUSAL_MAX_PKTS):
    """Write the flows of `path` (epoch microseconds [lo, hi), or all of it) to
    `out` as an hour-partitioned flow store. Each field is row_to_flow's rule
    as an SQL expression; test_lspr24_to_flows.py pins the two together."""
    import duckdb
    con = duckdb.connect()
    src = f"read_parquet({str(path)!r})"
    window = (f' AND "mTimestampStart" >= {int(lo)} AND "mTimestampStart" < {int(hi)}'
              if lo is not None else "")

    # canonical_ip in SQL is a join: the distinct addresses are few.
    ips = [r[0] for r in con.sql(
        f'SELECT DISTINCT "SrcIP" FROM {src} UNION SELECT DISTINCT "DstIP" FROM {src}').fetchall()
        if r[0]]
    con.execute("CREATE TABLE canon (raw VARCHAR, ip VARCHAR)")
    con.executemany("INSERT INTO canon VALUES (?, ?)", [(ip, canonical_ip(ip)) for ip in ips])

    proto = " ".join(f"WHEN {n} THEN '{name}'" for n, name in PROTO_NAMES.items())
    n_back, rst = 'coalesce(r."Tot Bwd Pkts", 0)', 'coalesce(r."RST Flag Cnt", 0)'
    refused = (f"{max_refusal_pkts} >= 0 AND {n_back} > 0 AND {n_back} <= {max_refusal_pkts}"
               f" AND {rst} > 0")
    label = lambda col: (f'CASE WHEN r."{col}" IS NULL THEN NULL '
                         f'ELSE CAST(r."{col}" AS VARCHAR) = \'{RED_TEAM_LABEL}\' END')
    import os
    os.makedirs(out, exist_ok=True)
    con.execute(f"""
        COPY (
          SELECT
            CASE r."Protocol" {proto} ELSE CAST(r."Protocol" AS VARCHAR) END AS protocol,
            s.ip AS src_ip,
            d.ip AS dst_ip,
            CAST(r."SrcPort" AS BIGINT) AS src_port,
            CAST(r."DstPort" AS BIGINT) AS dst_port,
            s.ip AS originator,
            r."mTimestampStart" / 1e6 AS timestamp,
            r."mTimestampLast" / 1e6 AS end_time,
            CAST(r."Tot Fwd Pkts" AS BIGINT) AS orig_pkts,
            CAST(r."Tot Bwd Pkts" AS BIGINT) AS resp_pkts,
            CASE
              WHEN r."Protocol" = 6 AND contains(s.ip, ':')
                THEN CASE WHEN {n_back} > greatest({max_refusal_pkts}, 0) THEN true END
              WHEN r."Conn_state" IN ({_sql_list(RESPONDED_STATES)}) THEN true
              WHEN r."Conn_state" IN ({_sql_list(BLOCKED_STATES)}) THEN false
              WHEN {refused} THEN false
              ELSE {n_back} > 0
            END AS responded,
            r."Conn_state" AS conn_state,
            'lspr24' AS source,
            coalesce(r."Conn_state" IN ({_sql_list(DIRECTED_STATES)}), false) AS direction_known,
            {label("Label_src")} AS rt_src,
            {label("Label_dst")} AS rt_dst,
            strftime(make_timestamp(CAST(r."mTimestampStart" AS BIGINT)), '%Y-%m-%dT%H') AS hour
          FROM {src} r
          JOIN canon s ON s.raw = r."SrcIP"
          JOIN canon d ON d.raw = r."DstIP"
          WHERE r."Protocol" IS NOT NULL{window}
        ) TO {str(out)!r}
        (FORMAT parquet, PARTITION_BY (hour), OVERWRITE)
    """)
    return con.sql(f"SELECT count(*) FROM read_parquet({str(out) + '/**/*.parquet'!r})").fetchall()[0][0]


def main():
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[1],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("parquet", help="LSPR24 parquet file (lspr24_v2.parquet)")
    ap.add_argument("--window", choices=sorted(WINDOWS) + ["all"], default="all",
                    help="named exercise window (default: all); see firru.toml")
    ap.add_argument("--store", metavar="DIR",
                    help="write a parquet flow store here instead of JSONL to stdout")
    ap.add_argument("--since", metavar="TIME",
                    help="window start, as journalctl takes it: a window name, "
                         "'d2 09:00', '2024-03-07 12:00', '-2h'; overrides --window")
    ap.add_argument("--until", metavar="TIME",
                    help="window end (exclusive), same forms; overrides --window")
    ap.add_argument("--refusal-max-pkts", type=int, default=REFUSAL_MAX_PKTS,
                    metavar="N",
                    help="an OTH flow returning at most N packets, one a RST, "
                         f"counts as refused rather than answered "
                         f"(default {REFUSAL_MAX_PKTS}; -1 restores the plain "
                         "resp_pkts > 0 test)")
    args = ap.parse_args()

    since = args.since or (args.window if args.window != "all" else None)
    until = args.until or (args.window if args.window != "all" else None)
    if bool(since) != bool(until):
        ap.error("--since and --until go together (or name a --window)")
    try:
        lo, hi = (micros(since), micros(until, end=True)) if since else (None, None)
    except (ValueError, KeyError) as e:
        ap.error(str(e))
    if lo is not None and lo >= hi:
        ap.error(f"the window ends before it starts ({since} .. {until})")
    print("window: " + ("all of the file" if lo is None else
          f"{TIMES.parse(since).astimezone(timezone.utc):%Y-%m-%d %H:%M}Z to "
          f"{TIMES.parse(until, end=True).astimezone(timezone.utc):%Y-%m-%d %H:%M}Z"),
          file=sys.stderr)

    if args.store:
        n = write_store(args.parquet, args.store, lo, hi, args.refusal_max_pkts)
        print(f"# {n} flows -> {args.store} (window={args.window})", file=sys.stderr)
        return

    out = sys.stdout.write
    count = skipped = 0

    for row in iter_rows(args.parquet, lo, hi):
        flow = row_to_flow(row, args.refusal_max_pkts)
        if flow is None:
            skipped += 1
            continue
        out(json.dumps(flow) + "\n")
        count += 1

    msg = f"# {count} flows emitted (window={args.window})"
    if skipped:
        msg += f", {skipped} rows skipped"
    print(msg, file=sys.stderr)


if __name__ == "__main__":
    main()
