#!/usr/bin/env python3
"""
listening_split — the README's table: unanswered inbound TCP, split by whether
the measured loot says something was listening.

    python3 listening_split.py --parquet lspr24_v2.parquet --loot loot-ossec/ --defs def/

Inbound TCP is every TCP row whose destination is an inventory address.
Listening is what flows_to_enforced.py means by it: the host, protocol and port
appear in the loot, loopback binds excluded. No reply is `Tot Bwd Pkts` = 0.

Split by family, because the IPv6 rows cannot show a reply reliably: the
CICFlowMeter that built the dataset does not parse the TCP header on its IPv6
path (see lspr24_to_flows.py). The IPv4 rows are the ones that carry the
argument; the IPv6 rows are reported, not relied on. Windows are
firru.toml's, in the timestamps' local zone, UTC+02.
"""

import argparse
import pathlib

import flows_to_enforced as fe
from lspr24_to_flows import micros


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--parquet", required=True)
    ap.add_argument("--loot", default="loot-ossec", metavar="DIR")
    ap.add_argument("--defs", default="def", metavar="DIR")
    args = ap.parse_args()

    import duckdb
    owner, meta = fe.inventory(pathlib.Path(args.defs))
    listen, _ = fe.listeners(args.loot, meta)
    con = duckdb.connect()
    con.execute("create table addrs(ip varchar, tok varchar)")
    con.executemany("insert into addrs values (?,?)", list(owner.items()))
    con.execute("create table svc(tok varchar, port int)")
    con.executemany("insert into svc values (?,?)",
                    sorted({(t, p) for t, s in listen.items() for proto, p in s if proto == "tcp"}))
    con.execute(f"""create table t as select
          (f."DstIP" like '%:%') v6, (s.tok is not null) listening,
          f."mTimestampStart" ts,
          f."Tot Bwd Pkts" = 0 silent
        from read_parquet({args.parquet!r}) f
        join addrs a on a.ip = f."DstIP"
        left join svc s on s.tok = a.tok and s.port = f."DstPort"
        where f."Protocol" = 6""")

    print("inbound TCP           family   flows        no reply")
    for v6, listening, n, z in con.execute(
            "select v6, listening, count(*), sum(silent::int) from t group by all order by 2, 1").fetchall():
        where = "listening  " if listening else "no listener"
        print(f"  {where}          {'IPv6' if v6 else 'IPv4'}   {n:>10,}   {z:>8,} ({100 * z / n:.1f}%)")
    print("listening, by exercise window (firru.toml's):")
    for name in ("d1", "night", "d2"):
        lo, hi = micros(name), micros(name, end=True)
        for v6, n, z in con.execute(f"""select v6, count(*), sum(silent::int) from t
                where listening and ts >= {lo} and ts < {hi}
                group by v6 order by v6""").fetchall():
            print(f"  {name:6} {'IPv6' if v6 else 'IPv4'}  {n:>10,}   {z:>8,} ({100 * z / n:.1f}%)")


if __name__ == "__main__":
    main()
