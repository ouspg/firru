#!/usr/bin/env python3
"""
lspr24_to_flows.py — Turn the public LSPR24 parquet into the flow schema the rest
of the pipeline consumes, with no Arkime/Elastic in the loop.

LSPR24 is the Locked Shields Partner Run 2024 flow dataset: ~20.2M flows over
2024-03-01..03-07, CICFlowMeter features plus a Zeek `conn_state` and per-host
FQDNs. It is the one public dataset firru can be driven end-to-end on.

    python lspr24_to_flows.py lspr24_v2.parquet --window night > night.jsonl
    flows-to-listeners --input night.jsonl --hostnames hosts.json --output loot/

Output is one JSON object per flow, the same shape as firru.arkime.process_flow
and zeek-to-flows, so flow-verdict and flow_analysis.sql are unchanged:

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

WINDOWS. The exercise is two execution days with an attack-free night between
them; the 03-01..03-05 run-up is idle (~58 flows/hour) and excluded by every
preset except `all`. Named presets (UTC+02, the timestamps' local zone):

    d1        2024-03-06 10:00-18:00   2,234,628 flows, 0.466% red
    night     2024-03-06 19:00-08:00   3,570,813 flows, 0 red
    d1+night  2024-03-06 10:00-08:00   both of the above
    d2        2024-03-07 08:00-18:00   2,259,098 flows, 0.278% red
    all       everything in the file

`night` is the natural learning window: it is attack-free by the exercise
schedule, so a policy derived from it does not depend on the dataset's Label
column (which is circular — Label is defined as "the peer is a red-team host",
not as a behavioural detection).

CAVEAT. Under partial capture an uncaptured return path reads as
not-responded, the same caveat Arkime and Zeek carry.
"""

import argparse
import functools
import ipaddress
import json
import sys

from firru.flows import zeek_direction_known

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

# Local-time window presets; see the module docstring.
WINDOWS = {
    "d1":       ("2024-03-06 10", "2024-03-06 18"),
    "night":    ("2024-03-06 19", "2024-03-07 08"),
    "d1+night": ("2024-03-06 10", "2024-03-07 08"),
    "d2":       ("2024-03-07 08", "2024-03-07 18"),
    "all":      (None, None),
}

# The 12 of 101 columns actually needed; projecting them keeps the 2.8 GB file
# streamable in a few hundred MB.
COLUMNS = [
    "SrcIP", "DstIP", "SrcPort", "DstPort", "Protocol",
    "mTimestampStart", "mTimestampLast",
    "Tot Fwd Pkts", "Tot Bwd Pkts", "Conn_state", "RST Flag Cnt",
    "Segment_src", "Segment_dst", "Label_src", "Label_dst",
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
        "responded":  _responded(conn_state, resp_pkts,
                                 row.get("RST Flag Cnt"), max_refusal_pkts),
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


def _hour_to_micros(hour_str):
    """'YYYY-MM-DD HH' in the timestamps' local zone -> epoch microseconds."""
    import datetime
    dt = datetime.datetime.strptime(hour_str, "%Y-%m-%d %H")
    return int(dt.timestamp() * 1_000_000)


def iter_rows(path, start_hr, end_hr, batch_size=131072):
    """Stream the parquet in batches, yielding row dicts inside the window."""
    try:
        import pyarrow.parquet as pq
    except ImportError:
        sys.exit("lspr24_to_flows.py needs pyarrow: pip install 'firru[lspr24]'")

    # Resolve the window to integer bounds once; comparing per row is otherwise
    # a datetime construction and strftime across 20M rows.
    lo = _hour_to_micros(start_hr) if start_hr else None
    hi = _hour_to_micros(end_hr) if end_hr else None

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


def main():
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[1],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("parquet", help="LSPR24 parquet file (lspr24_v2.parquet)")
    ap.add_argument("--window", choices=sorted(WINDOWS), default="all",
                    help="named exercise window (default: all); see the module docstring")
    ap.add_argument("--start", metavar="'YYYY-MM-DD HH'",
                    help="explicit window start, overrides --window")
    ap.add_argument("--end", metavar="'YYYY-MM-DD HH'",
                    help="explicit window end (exclusive), overrides --window")
    ap.add_argument("--refusal-max-pkts", type=int, default=REFUSAL_MAX_PKTS,
                    metavar="N",
                    help="an OTH flow returning at most N packets, one a RST, "
                         f"counts as refused rather than answered "
                         f"(default {REFUSAL_MAX_PKTS}; -1 restores the plain "
                         "resp_pkts > 0 test)")
    ap.add_argument("--hostmap", metavar="FILE",
                    help="also write an IP -> FQDN map here, for flows-to-listeners --hostnames")
    ap.add_argument("--zonemap", metavar="FILE",
                    help="also write an FQDN -> {zone} host_metadata.json stub, "
                         "zone taken from the org unit in the FQDN (baf/beg/bgp)")
    args = ap.parse_args()

    start_hr, end_hr = WINDOWS[args.window]
    if args.start or args.end:
        start_hr, end_hr = args.start, args.end
        if not (start_hr and end_hr):
            ap.error("--start and --end must be given together")

    hostmap, zonemap = {}, {}
    out = sys.stdout.write
    count = skipped = 0

    for row in iter_rows(args.parquet, start_hr, end_hr):
        flow = row_to_flow(row, args.refusal_max_pkts)
        if flow is None:
            skipped += 1
            continue
        out(json.dumps(flow) + "\n")
        count += 1

        # LSPR24 carries the FQDN inline on both ends, and the IP -> host
        # mapping is 1:1 across the whole file, so the inventory falls out
        # of the same pass.
        for ip_key, name_key in (("SrcIP", "Segment_src"), ("DstIP", "Segment_dst")):
            ip, name = row.get(ip_key), row.get(name_key)
            if ip and name:
                hostmap.setdefault(canonical_ip(ip), name)
                if name not in zonemap:
                    parts = name.split(".")
                    # dc1.int.baf.05.berylia.org -> baf ; fw1-baf.5.berylia.org -> fw1-baf
                    if len(parts) >= 4:
                        zonemap[name] = {"zone": parts[-4]}

    if args.hostmap:
        with open(args.hostmap, "w") as f:
            json.dump(hostmap, f, indent=2, sort_keys=True)
        print(f"# {len(hostmap)} IP -> FQDN mappings -> {args.hostmap}", file=sys.stderr)

    if args.zonemap:
        with open(args.zonemap, "w") as f:
            json.dump(zonemap, f, indent=2, sort_keys=True)
        print(f"# {len(zonemap)} hosts with zones -> {args.zonemap}", file=sys.stderr)

    msg = f"# {count} flows emitted (window={args.window})"
    if skipped:
        msg += f", {skipped} rows skipped"
    print(msg, file=sys.stderr)


if __name__ == "__main__":
    main()
