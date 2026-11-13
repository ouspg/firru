#!/usr/bin/env python3
"""
make_zeek_tree — emit a miniature Zeek log tree carrying every shape that has
actually broken something, plus the loot inventory that conditions it.

    python3 tests/fixtures/make_zeek_tree.py /tmp/zeek-tree

Nothing here is random: the tree is small enough to read and every count in
`expected.json` is a hand-checked consequence of the records below. The point
is not coverage of Zeek's schema, it is that a naive implementation gets a
*different answer* than a correct one on each of these:

  P1  hostname join       loot says `db1.example.org`, analysis carries the
                          Aerleon token `db1_example_org`. Join on either
                          alone and you silently drop the host.
  P2  ragged schema       `orig_pkts` is absent in the 03Z hour and present
                          later; `TTLs` is absent from some dns records. Read
                          the hours as one relation without union_by_name and
                          it errors instead of filling nulls.
  P3  dotted field names  `id.orig_h` is a *name* containing a dot, not a path.
  P4  missing hours       06Z and 07Z do not exist (the exercise's offline
                          window). Anything assuming contiguity is wrong.
  P5  compression         the 05Z hour is gzipped, the rest plain.
  P6  straddling tuple    one (src, host, port) has flows in both the warm-up
                          hour and a live hour. Label per *flow* and it lands
                          in two cohorts; per *tuple* it is one, and it is not
                          warm-up-only. This is the shape that mislabelled 54
                          tuples as IPv6 drift.
  P7  flows != tuples     one tuple carries 50 retries; 40 scan tuples carry
                          one flow each. Flow-weighting and tuple-weighting
                          rank these two populations in opposite orders.
  P8  no listener         most scan traffic hits ports nothing listens on,
                          where a "block" is indistinguishable from an absent
                          service. Conditioning on loot must remove them.
  P9  gone by SYN time    db1:9999 is in the loot inventory and refuses every
                          later connection: listening at collection, gone when
                          the packet arrives. Bounds any over-enforcement read.
  P10 both families       the same (host, port) is blocked over IPv4 and
                          admitted over IPv6, the split the whole address
                          family finding turns on.
  P11 dns outweighs conn  more dns records than conn records, as on the real
                          capture. Anything assuming conn dominates is wrong.
  P12 absent log type     the 08Z hour has no ssl.log at all.
"""

import argparse
import gzip
import json
import os

# Hour directories, Zeek-style. 06Z and 07Z are deliberately absent (P4), and
# 05Z is gzipped (P5). The warm-up/live boundary sits at 04:00Z.
WARMUP_HOUR = "20260421T030000Z"
HOURS = [WARMUP_HOUR, "20260421T040000Z", "20260421T050000Z", "20260421T080000Z"]
GZIP_HOURS = {"20260421T050000Z"}
MISSING_HOURS = ["20260421T060000Z", "20260421T070000Z"]
BOUNDARY = 1776747600  # 2026-04-21T04:00:00Z, the warm-up/live boundary

HOUR_TS = {  # first second of each hour
    "20260421T030000Z": 1776744000,
    "20260421T040000Z": 1776747600,
    "20260421T050000Z": 1776751200,
    "20260421T080000Z": 1776762000,
}

WEB4, WEB6 = "192.0.2.10", "2001:db8::10"
DB4, DB6 = "192.0.2.20", "2001:db8::20"
ATT4, ATT6 = "198.51.100.5", "2001:db8:bad::5"
WARMONLY = "198.51.100.6"   # only ever seen in the warm-up hour
SCANNER = "198.51.100.99"
CLIENT = "192.0.2.11"

# loot uses the FQDN, the policy/analysis side uses the Aerleon token (P1).
HOSTS = {
    "web1.example.org": {"token": "web1_example_org", "os": "linux",
                         "v4": WEB4, "v6": WEB6, "ports": [22, 443]},
    "db1.example.org": {"token": "db1_example_org", "os": "linux",
                        "v4": DB4, "v6": DB6, "ports": [22, 5432, 9999]},
}


def conn(ts, src, dst, dport, state, sport=40000, proto="tcp", pkts=None):
    """One conn.log record. `orig_pkts` is omitted where pkts is None (P2)."""
    rec = {"ts": ts, "uid": f"C{int(ts)}{src[-3:]}{dport}", "id.orig_h": src,
           "id.orig_p": sport, "id.resp_h": dst, "id.resp_p": dport,
           "proto": proto, "conn_state": state}
    if pkts is not None:
        rec["orig_pkts"] = pkts
    return rec


def build_hour(hour):
    """Every log type for one hour, as {logname: [records]}."""
    t = HOUR_TS[hour]
    warm = hour == WARMUP_HOUR
    # orig_pkts appears only from the second hour on (P2).
    pkts = None if warm else 3
    c = []

    # P6: this tuple appears in the warm-up hour AND in a live hour, so it is
    # not warm-up-only even though some of its flows are.
    if warm or hour == "20260421T040000Z":
        c.append(conn(t + 10, ATT4, DB4, 5432, "SF", pkts=pkts))

    # P6 control: only ever in the warm-up hour, so genuinely warm-up-only.
    if warm:
        c.append(conn(t + 11, WARMONLY, DB4, 5432, "SF", pkts=pkts))

    # P10: same (host, port) blocked over v4, admitted over v6, every hour.
    c.append(conn(t + 20, ATT4, DB4, 22, "S0", pkts=pkts))
    c.append(conn(t + 21, ATT6, DB6, 22, "SF", pkts=pkts))

    # P7: one tuple, fifty retries. Flow-weighted this dwarfs the scan; tuple-
    # weighted it is a single relationship.
    for i in range(50):
        c.append(conn(t + 100 + i, CLIENT, WEB4, 443, "SF", sport=41000 + i,
                      pkts=pkts))

    # P7/P8: forty scan tuples, one flow each, on ports with no listener.
    # REJ is the answered-but-closed case that belongs in the no-listener bucket.
    for i, port in enumerate(range(3000, 3040)):
        c.append(conn(t + 200 + i, SCANNER, DB4, port,
                      "REJ" if port % 2 else "S0", sport=42000 + i, pkts=pkts))

    # P9: listening at collection time, refusing by the time the SYN lands.
    c.append(conn(t + 300, CLIENT, DB4, 9999, "REJ", pkts=pkts))

    # P11: more dns than conn. Some records omit TTLs (P2).
    d = []
    for i in range(len(c) + 20):
        rec = {"ts": t + i, "uid": f"D{int(t)}{i}", "id.orig_h": CLIENT,
               "id.resp_h": WEB4, "id.resp_p": 53, "proto": "udp",
               "query": f"h{i % 7}.example.org", "qtype_name": "A",
               "answers": [WEB4]}
        if i % 3:
            rec["TTLs"] = [300.0]
        d.append(rec)

    s = []  # ssl.log — absent entirely in the 08Z hour (P12)
    if hour != "20260421T080000Z":
        s = [{"ts": t + 30, "uid": f"S{int(t)}1", "id.orig_h": CLIENT,
              "id.resp_h": WEB4, "id.resp_p": 443,
              "server_name": "web1.example.org", "version": "TLSv13"},
             # no server_name: an SSL session that names nothing (P2)
             {"ts": t + 31, "uid": f"S{int(t)}2", "id.orig_h": CLIENT,
              "id.resp_h": DB4, "id.resp_p": 5432, "version": "TLSv12"}]

    h = [{"ts": t + 40, "uid": f"H{int(t)}1", "id.orig_h": CLIENT,
          "id.resp_h": WEB4, "id.resp_p": 80, "host": "web1.example.org",
          "method": "GET", "uri": "/"}]

    ks = [{"ts": t, "host": WEB4, "port_num": 443, "port_proto": "tcp",
           "service": ["SSL"]},
          {"ts": t, "host": DB4, "port_num": 5432, "port_proto": "tcp",
           "service": []}]

    return {"conn": c, "dns": d, "ssl": s, "http": h, "known_services": ks}


def write_log(path, records, gz):
    data = "".join(json.dumps(r) + "\n" for r in records).encode()
    if gz:
        with gzip.open(path + ".gz", "wb") as fh:
            fh.write(data)
    else:
        with open(path, "wb") as fh:
            fh.write(data)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("out", help="directory to create the tree in")
    args = ap.parse_args()

    counts = {}
    for hour in HOURS:
        d = os.path.join(args.out, hour)
        os.makedirs(d, exist_ok=True)
        for name, recs in build_hour(hour).items():
            if not recs:
                continue                      # P12: no file at all
            write_log(os.path.join(d, f"{name}.{hour}.json"), recs,
                      hour in GZIP_HOURS)
            counts[name] = counts.get(name, 0) + len(recs)

    # The loot inventory the flow analysis conditions on. Hostnames are FQDNs
    # here and tokens elsewhere, which is P1.
    loot = os.path.join(args.out, "loot")
    os.makedirs(loot, exist_ok=True)
    for fqdn, h in HOSTS.items():
        with open(os.path.join(loot, f"{fqdn}.json"), "w") as fh:
            json.dump({"metadata": {"hostname": fqdn, "os": h["os"]},
                       "listen_ports": [{"protocol": "tcp", "port": p}
                                        for p in h["ports"]],
                       "addresses": [h["v4"], h["v6"]]}, fh, indent=2)

    expected = {
        "hours_present": HOURS,
        "hours_missing": MISSING_HOURS,
        "warmup_hour": WARMUP_HOUR,
        "boundary_ts": BOUNDARY,
        "rows": counts,
        "dns_outweighs_conn": counts["dns"] > counts["conn"],
        # P6: every tuple present in the warm-up hour touches it (46 of them,
        # dominated by the 40 scan tuples); exactly one is warm-up-*only*. The
        # discriminating pair is named, because the totals move whenever a
        # record is added and the pair is what the pathology is about.
        "warmup_touching_tuples": 46,
        "warmup_only_tuples": 1,
        "straddling_tuple": f"{ATT4}|{DB4}|5432",
        "warmup_only_tuple": f"{WARMONLY}|{DB4}|5432",
        # P7: the retry tuple is 1 tuple / 50 flows per hour; the scan is 40
        # tuples / 40 flows per hour.
        "retry_tuples": 1, "retry_flows_per_hour": 50,
        "scan_tuples": 40, "scan_flows_per_hour": 40,
        # P8: scan ports 3000-3039 have no listener; db1 listens on 22/5432/9999.
        "listener_ports": {h["token"]: h["ports"] for h in HOSTS.values()},
        "no_listener_scan_tuples": 40,
        # P10
        "both_family_host_port": {"host": "db1.example.org", "port": 22,
                                  "v4_state": "S0", "v6_state": "SF"},
        "log_types_missing_in_08Z": ["ssl"],
    }
    with open(os.path.join(args.out, "expected.json"), "w") as fh:
        json.dump(expected, fh, indent=2, sort_keys=True)

    print(f"wrote {len(HOURS)} hours to {args.out}")
    for name in sorted(counts):
        print(f"  {name:<16}{counts[name]:>7} records")
    print(f"  loot            {len(HOSTS):>7} hosts")


if __name__ == "__main__":
    main()
