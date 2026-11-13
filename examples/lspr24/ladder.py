#!/usr/bin/env python3
"""
ladder — the block-early counterfactual, on LSPR24 instead of exercise data.

    python3 ladder.py --parquet lspr24_v2.parquet --loot loot-ossec/
    python3 ladder.py ... --learn night --eval d2 --protected scored.txt

Answers the question the exercise evaluation asks: of the attacker traffic a
policy admitted, how much would a *stricter* variant have denied, and what
would that have cost in legitimate traffic? Three variants over one socket
inventory, matched against traffic the inventory never saw:

    deployed   sources left at ANY, as synthesis emits them
    R2         tighten each service to the sources observed in the learn
               window; a service with no observations stays at ANY, because
               absence of traffic is missing data rather than evidence of
               disuse
    R4         R2, plus close every service the learn window never saw at all
    Rh         an auditable heuristic, independent of per-service evidence:
               management ports are reachable only from the administrative
               sources. The exercise pipeline takes that source set from
               documented environment knowledge; LSPR24 ships none, so it is
               derived here by fan-out -- a source that reached >= N distinct
               hosts on a management port during the quiet window is an admin.
               That derivation is the auditable part: it is a short list a
               reviewer can read and sign off. On LSPR24 it recovers the
               documented set exactly -- all 16 sources it finds are
               `Label_src='2'`, the organiser/green-team infrastructure, and
               using that label directly instead costs 66 clean tuples against
               the derivation's 68. So the heuristic does not need the dataset's
               metadata; observation over a quiet window reconstructs it.

               The remaining cost is the half of the rule not modelled here. The
               exercise heuristic restricts management to the green team *and a
               management segment*; this models only the first. The 66 clean
               tuples Rh still denies are all `Label_src='0'` -- 14 blue-team
               sources reaching 47 hosts, which is what a management segment
               looks like. Both halves are load-bearing.

WHAT THIS CANNOT SHOW. No policy from this pipeline was ever deployed on
LSPR24, so the practice outcome reflects that blue team's controls, not ours.
This is the counterfactual arm only: what a variant *would* have denied. An
enforcement rate is a property of a deployment and no public dataset supplies
one.

NO SCORED-SERVICE FLOOR. The exercise evaluation could subtract services the
scoring system requires to stay reachable, which is one of the two backstops
evidence-only synthesis depends on (the other being human review). LSPR24 ships
no such list, so the clean-traffic cost printed here is **unfiltered** and
overstates what a deployment that knew its scored services would pay. It also
means block-early
is genuinely riskier here than it was in the exercise: nothing tells you which
of the never-sampled services had to stay open. Supply your own list with
--protected (one `host:port` per line) to see the effect.

THREE ENCODING TRAPS, each of which produces a confident wrong answer:

  1. Tightening to exact source addresses makes the result a tautology. The
     learn window is attack-free by construction, so no attacker address can
     ever be in the allowed set and R2 "denies" 100% of attacker traffic. It
     also denies most legitimate traffic. Generalise to the asset, as here.
  2. R2 must leave never-sampled services at ANY. Deny them and R4 collapses
     into R2, hiding the only thing the comparison exists to measure.
  3. "Management is never reachable from outside" is NOT a portable rule.
     On LSPR24 90% of external SSH is legitimate (172 clean tuples against 18
     attacker), because legitimate administration originates outside the
     External_src boundary. Blanket-denying external management costs 204 clean
     tuples to deny 18 attacker ones. The admin *source set* is what makes the
     heuristic work, and it is environment knowledge, not a constant.
  4. `Conn_state` cannot supply the practice axis: `S0` and `REJ` do not occur
     anywhere in LSPR24's 20.2M flows. Admission is read from packet counts
     instead (a reply came back), which is what --admitted-by encodes.
"""

import argparse
import glob
import json
import pathlib
import sys

WINDOWS = {                                    # local time, matching lspr24_to_flows.py
    "d1":       ("2024-03-06 10:00", "2024-03-06 18:00"),
    "night":    ("2024-03-06 19:00", "2024-03-07 08:00"),
    "d1+night": ("2024-03-06 10:00", "2024-03-07 08:00"),
    "d2":       ("2024-03-07 08:00", "2024-03-07 18:00"),
}


def load_services(lootdir):
    """Listening TCP services from loot: the policy subjects. Loopback excluded."""
    out = set()
    for f in glob.glob(str(pathlib.Path(lootdir) / "*.json")):
        if f.endswith("manifest.json"):
            continue
        d = json.loads(pathlib.Path(f).read_text())
        host = (d.get("metadata") or {}).get("hostname", "").lower()
        for e in d.get("listen_ports") or []:
            if e.get("protocol") != "tcp":
                continue
            if str(e.get("bind_address", "")).startswith(("127.", "::1")):
                continue
            out.add((host, int(e["port"])))
    return sorted(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--parquet", required=True)
    ap.add_argument("--loot", required=True, help="loot directory (ossec-to-loot output)")
    ap.add_argument("--learn", default="night", choices=sorted(WINDOWS),
                    help="attack-free window the tightening learns from")
    ap.add_argument("--eval", default="d2", choices=sorted(WINDOWS),
                    help="window the variants are matched against")
    ap.add_argument("--admin-fanout", type=int, default=2, metavar="N",
                    help="a learn-window source reaching >= N distinct hosts on "
                         "a management port is treated as administrative (Rh)")
    ap.add_argument("--admins", metavar="FILE",
                    help="administrative sources, one per line: literal "
                         "addresses or CIDRs. Overrides the fan-out derivation")
    ap.add_argument("--mgmt-top", type=int, default=0, metavar="N",
                    help="also treat the top N addresses of every IPv4 /24 as "
                         "administrative -- the per-segment management hosts. "
                         "The exercise used the last 3; on LSPR24 any N from 2 "
                         "to 10 gives the same answer, and no attacker source "
                         "falls in the band at any width")
    ap.add_argument("--protected", metavar="FILE",
                    help="services that must stay reachable, one host:port per "
                         "line; the scored-service floor LSPR24 does not ship")
    args = ap.parse_args()

    import duckdb
    con = duckdb.connect()
    P = repr(args.parquet)
    services = load_services(args.loot)
    if not services:
        sys.exit(f"no TCP listeners found under {args.loot}")

    protected = set()
    if args.protected:
        for line in pathlib.Path(args.protected).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                h, _, p = line.rpartition(":")
                protected.add((h.lower(), int(p)))

    # asset -> addresses, from both ends of the flow table
    con.execute(f"""create view amap as
      select lower(split_part("Expoid_src",'.',1)) a, "SrcIP" ip
        from read_parquet({P}) where "Expoid_src" is not null
      union
      select lower(split_part("Expoid_dst",'.',1)) a, "DstIP" ip
        from read_parquet({P}) where "Expoid_dst" is not null""")

    con.execute("create table L(a varchar, port bigint)")
    con.executemany("insert into L values (?, ?)", services)
    con.execute("create table PROT(a varchar, port bigint)")
    if protected:
        con.executemany("insert into PROT values (?, ?)", sorted(protected))
    con.execute("create view svc as select distinct L.a, L.port, amap.ip "
                "from L join amap using (a)")

    for name, key in (("learn", args.learn), ("evalw", args.eval)):
        s, e = WINDOWS[key]
        con.execute(f"""create view {name} as
          select "SrcIP" src, "DstIP" dip, "DstPort" dport, "Label_src" lsrc,
                 "Tot Bwd Pkts" bwd
          from read_parquet({P}) where "Protocol" = 6
            and to_timestamp("mTimestampStart"/1e6) >= TIMESTAMPTZ '{s}'
            and to_timestamp("mTimestampStart"/1e6) <  TIMESTAMPTZ '{e}'""")

    con.execute("""create view obs as select distinct s.a, s.port, l.src,
      (select min(m.a) from amap m where m.ip = l.src) src_asset
      from svc s join learn l on l.dip = s.ip and l.dport = s.port""")
    con.execute("create view sampled as select distinct a, port from obs")
    # An unresolvable (external) client leaves the term at ANY -- firru's rule.
    con.execute("create view any_term as select distinct a, port from obs "
                "where src_asset is null")
    con.execute("""create view allowed as select distinct o.a, o.port, m.ip
      from obs o join amap m on m.a = o.src_asset""")
    # "Admitted" = a reply came back. See trap 3.
    con.execute("""create view adm as select distinct s.a, s.port, d.src, d.lsrc
      from svc s join evalw d on d.dip = s.ip and d.dport = s.port and d.bwd > 0""")

    MGMT = "(22, 3389, 5985, 5986, 9389)"
    if args.admins:
        entries = [l.strip() for l in pathlib.Path(args.admins).read_text().splitlines()
                   if l.strip() and not l.startswith("#")]
        con.execute("create table admins(src varchar)")
        # A CIDR entry expands against the addresses the capture actually shows,
        # so the allowed set stays a list of real hosts rather than a range.
        cidrs = [e for e in entries if "/" in e]
        con.executemany("insert into admins values (?)",
                        [(e,) for e in entries if "/" not in e])
        for c in cidrs:
            con.execute(f"""insert into admins
              select distinct src from (select "SrcIP" src from read_parquet({P}))
              where try_cast(src as inet) is not null
                and host(try_cast(src as inet)) is not null
                and src::inet <<= '{c}'::inet""")
    else:
        con.execute(f"""create table admins as select l.src src from svc s
          join learn l on l.dip = s.ip and l.dport = s.port
          where s.port in {MGMT}
          group by l.src having count(distinct s.a) >= {args.admin_fanout}""")

    SAMPLED = "exists (select 1 from sampled s where s.a=x.a and s.port=x.port)"
    R2 = f"""{SAMPLED}
      and not exists (select 1 from any_term t where t.a=x.a and t.port=x.port)
      and not exists (select 1 from allowed w
                      where w.a=x.a and w.port=x.port and w.ip=x.src)"""
    R4 = f"""({R2}) or (not {SAMPLED}
      and not exists (select 1 from PROT p where p.a=x.a and p.port=x.port))"""

    top = ""
    if args.mgmt_top:
        top = (f" and not (x.src not like '%:%' and "
               f"try_cast(split_part(x.src,'.',4) as int) >= {256 - args.mgmt_top})")
    RH = (f"x.port in {MGMT} and x.src not in (select src from admins){top}")

    q = lambda s: con.execute(s).fetchone()[0]
    nsvc = q("select count(*) from (select distinct a, port from svc)")
    nadm = q("select count(*) from admins")
    print(f"learn={args.learn}  eval={args.eval}  loot={args.loot}")
    print(f"{nsvc} services under policy | sampled {q('select count(*) from sampled')}"
          f" | kept ANY {q('select count(*) from any_term')}"
          f" | never sampled {q(f'select count(*) from (select distinct a,port from svc) x where not {SAMPLED}')}"
          + (f" | protected {len(protected)}" if protected else " | no scored floor"))
    print(f"admin sources for Rh: {nadm}"
          + (f" + top {args.mgmt_top} of each /24" if args.mgmt_top else "")
          + (" (from --admins)" if args.admins else f" (fan-out >= {args.admin_fanout})"))
    print()
    # Label_src is 0 / 1 / 2, not a binary: 2 covers a quarter of the dataset
    # (organiser and user-simulation traffic). It is legitimate traffic a policy
    # must admit, so "clean" is everything that is not red team, not just '0'.
    for label, cond in (("attacker", "lsrc = '1'"), ("clean   ", "lsrc <> '1'")):
        tot = q(f"select count(*) from adm x where {cond}")
        if not tot:
            print(f"{label}: no admitted tuples in {args.eval}")
            continue
        r2 = q(f"select count(*) from adm x where {cond} and ({R2})")
        r4 = q(f"select count(*) from adm x where {cond} and ({R4})")
        rh = q(f"select count(*) from adm x where {cond} and ({RH})")
        both = q(f"select count(*) from adm x where {cond} and (({R4}) or ({RH}))")
        print(f"{label}: {tot} admitted tuples")
        print(f"    deployed  would deny {0:>6}")
        print(f"    R2        would deny {r2:>6}  ({r2/tot*100:4.1f}%)")
        print(f"    R4        would deny {r4:>6}  ({r4/tot*100:4.1f}%)   "
              f"block-early edge {r4-r2}")
        print(f"    Rh        would deny {rh:>6}  ({rh/tot*100:4.1f}%)   "
              f"adds {both-r4} beyond R4")
        print(f"    R4+Rh     would deny {both:>6}  ({both/tot*100:4.1f}%)")
    if not protected:
        print("\nThe clean cost above is unfiltered: LSPR24 ships no scored-service\n"
              "list, so services that had to stay reachable cannot be subtracted.\n"
              "--protected FILE takes one (host:port per line).")


if __name__ == "__main__":
    main()
