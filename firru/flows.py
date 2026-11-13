"""Flow sources: read observed flows from JSONL or partitioned parquet.

Tightening and the diff's evidence both scan the flow record, filtered to a
handful of host addresses. On JSONL that means decoding every record whether or
not a fleet host touches it — fine for a FAM-sized slice, the bottleneck once
the record is a full exercise of hourly zeek output.

Parquet inverts it: the host-address filter pushes down as a predicate on
src_ip/dst_ip, and only the four columns the bucketing needs are read, so cost
scales with matched flows, not file size. The store is *many* files, not one —
one parquet per hour (`flows/hour=YYYY-MM-DDTHH/part.parquet`), read as a glob.
That matches the production feed (arkime pcap -> zeek -> one parquet an hour, no
rewrite), lets a tighten window prune to the hours it needs, and appends
without touching what is already written.

`fqdn` is a best-effort name column: present, null where nothing named the
destination. Tightening ignores it; a null name is an auditable destination,
never an error.

The reader yields plain dicts with the JSONL field names, so a caller that
buckets flow dicts (tighten._bucket_flow) works unchanged whichever source
backs it.
"""

import glob
import re
import json
import os
import pathlib

# The columns any flow consumer needs; fqdn is optional (passive DNS).
_CORE = ("protocol", "src_ip", "dst_ip", "dst_port")


def is_parquet(path):
    """True if `path` names parquet: a .parquet file, a glob, or a directory
    (a partitioned store) that contains one."""
    if any(ch in path for ch in "*?[]"):
        return True
    if path.endswith(".parquet"):
        return True
    if os.path.isdir(path):
        return bool(glob.glob(os.path.join(path, "**", "*.parquet"), recursive=True))
    return False


def _parquet_glob(path):
    if any(ch in path for ch in "*?[]") or path.endswith(".parquet"):
        return path
    return os.path.join(path, "**", "*.parquet")


def store_timestamp_type(path):
    """The stored type of a flow store's `timestamp` column, or None if the
    store does not exist yet or has no such column."""
    pat = os.path.join(path, "**", "*.parquet")
    if not glob.glob(pat, recursive=True):
        return None
    import duckdb
    for name, typ, *_ in duckdb.sql(
            f"DESCRIBE SELECT * FROM read_parquet({pat!r})").fetchall():
        if name == "timestamp":
            return typ
    return None


def store_columns(path):
    """The column names of a flow store, or None if it does not exist yet."""
    pat = os.path.join(path, "**", "*.parquet")
    if not glob.glob(pat, recursive=True):
        return None
    import duckdb
    return [name for name, *_ in duckdb.sql(
        f"DESCRIBE SELECT * FROM read_parquet({pat!r})").fetchall()]


def check_appendable(path, columns=None):
    """Refuse an append that would make a store unreadable.

    Two ways that happens, both silent or worse without this.

    A store written before timestamps were DOUBLE holds `timestamp` as BIGINT.
    Reading such a store together with a DOUBLE partition does not fail --
    duckdb unifies the glob on the first file's type and quietly *rounds* every
    new time back to a whole second. The precision is gone and nothing says so,
    which is worse than an error, so this is the error.

    Returns a message to print and refuse on, or None when the store is empty
    or already DOUBLE.
    """
    typ = store_timestamp_type(path)
    if typ is not None and typ.upper() not in ("DOUBLE", "FLOAT"):
        return (f"{path} is an older store with a {typ} `timestamp`; appending "
                f"fractional times to it would silently round them to whole "
                f"seconds. Write to a new directory, or rebuild this one.")

    # The column set, when the caller knows what it is about to write. duckdb
    # reads a glob of parquet only when every file agrees on its schema, so a
    # partition with different columns does not spoil itself -- it makes the
    # whole store unreadable, including everything already in it. Stores
    # written before `source` and `direction_known` existed are the current
    # case; each store keeps its own projection, so this compares against the
    # caller's list rather than against one blessed set.
    if columns is not None:
        have = store_columns(path)
        if have is not None and set(have) != set(columns):
            missing = [c for c in columns if c not in have]
            extra = [c for c in have if c not in columns]
            detail = []
            if missing:
                detail.append(f"would add {', '.join(missing)}")
            if extra:
                detail.append(f"would drop {', '.join(extra)}")
            return (f"{path} has a different column set from what this run "
                    f"writes ({'; '.join(detail)}). duckdb reads a glob of "
                    f"parquet only when every file has the same columns, so "
                    f"the append would make the whole store unreadable rather "
                    f"than just the new partition. Write to a new directory, "
                    f"or rebuild this one.")

    return None


# ---------------------------------------------------------------------------
# Zeek conn as a flow source
#
# The flow record is a projection of zeek's conn log: renamed columns, two
# derived fields, and rows with no time, protocol or address dropped. Nothing
# else. Materializing it was worth doing while the alternative was 30GB of
# JSONL; against the conn parquet the projection costs about 0.04s an hour,
# which is a rounding error next to reading the rows at all.
#
# So a zeek conn store reads as a flow store, and the derived copy becomes
# optional. Verified on a ~150M-row export: every row of the derived flow
# store and the projection of the conn store agree on every
# one of the twelve flow columns, same count, same order-independent hash.
# ---------------------------------------------------------------------------

#: Zeek `conn_state` values that prove which end opened the connection.
#: Anything else -- OTH, or no state at all -- is midstream capture, where the
#: originator is a guess. This lives here rather than in a consumer because
#: two producers speak this vocabulary (zeek and LSPR24's CICFlowMeter export)
#: and the consumer should no longer have to.
DIRECTED_STATES = frozenset({"SF", "S0", "S1", "S2", "S3", "REJ",
                             "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR"})


def zeek_direction_known(conn_state):
    """Whether a Zeek-vocabulary conn_state settles which end opened the flow."""
    return conn_state in DIRECTED_STATES


#: The column zeek's conn log has and a flow record does not. Its presence is
#: how a source announces which of the two it is.
_ZEEK_MARK = "id.orig_h"

#: conn -> flow. `responded` is the one field that is not a rename: for TCP it
#: is the history flag for a server-side handshake, for everything else it is
#: whether the responder sent a packet. `direction_known` spells DIRECTED_STATES
#: out in SQL because duckdb has no access to the frozenset above; the two are
#: pinned to agree by tests/test_zeek_to_flows_parquet.py, which compares this
#: projection against conn_to_flow row by row.
ZEEK_COLUMNS = """
    lower(c.proto)                              AS protocol,
    c."id.orig_h"                               AS src_ip,
    c."id.resp_h"                               AS dst_ip,
    CAST(c."id.orig_p" AS BIGINT)               AS src_port,
    CAST(c."id.resp_p" AS BIGINT)               AS dst_port,
    c."id.orig_h"                               AS originator,
    CAST(c.ts AS DOUBLE)                        AS timestamp,
    CAST(c.ts + coalesce(c.duration, 0) AS DOUBLE) AS end_time,
    CAST(c.orig_pkts AS BIGINT)                 AS orig_pkts,
    CAST(c.resp_pkts AS BIGINT)                 AS resp_pkts,
    CASE WHEN lower(c.proto) = 'tcp'
         THEN contains(coalesce(c.history, ''), 'h')
         ELSE coalesce(c.resp_pkts, 0) > 0 END  AS responded,
    CAST(c.conn_state AS VARCHAR)               AS conn_state,
    'zeek'                                      AS source,
    CAST(c.conn_state IN ('SF','S0','S1','S2','S3','REJ','RSTO','RSTR',
                          'RSTOS0','RSTRH','SH','SHR') AS BOOLEAN)
                                                AS direction_known,
"""

#: The rows conn_to_flow drops: no time, or no protocol, or no address. Zeek's
#: text forms spell an absent value "-" and parquet spells it NULL.
#: The names ZEEK_COLUMNS projects, read off the SQL so the two cannot drift.
#: An alias always ends its line; the `AS BOOLEAN` and `AS BIGINT` casts inside
#: an expression never do.
ZEEK_FLOW_COLUMNS = tuple(re.findall(r"AS\s+(\w+),\s*$", ZEEK_COLUMNS,
                                     re.MULTILINE))

ZEEK_KEEP_ROW = """
    ts IS NOT NULL
    AND proto IS NOT NULL AND proto <> '-'
    AND "id.orig_h" IS NOT NULL AND "id.orig_h" <> '-'
    AND "id.resp_h" IS NOT NULL AND "id.resp_h" <> '-'
"""

def _columns(src):
    import duckdb
    return [r[0] for r in duckdb.sql(
        f"DESCRIBE SELECT * FROM read_parquet({src!r})").fetchall()]


def is_zeek_conn(path):
    """True if `path` holds zeek conn parquet rather than flow records."""
    if not is_parquet(path):
        return False
    try:
        return _ZEEK_MARK in _columns(_parquet_glob(path))
    except Exception:
        return False


def naming():
    """firru.namemap, the name-labeling layer, or None where it is not
    installed. Looked up rather than imported: a tree may ship without it, and
    then flows simply carry no names."""
    import importlib
    import importlib.util
    try:
        if importlib.util.find_spec("firru.namemap") is None:
            return None
    except ModuleNotFoundError:
        return None
    return importlib.import_module("firru.namemap")


def flow_relation(path, with_fqdn=False, name_map=None):
    """A SQL relation yielding flow records from `path`, whichever kind it is.

    A flow store reads as itself. A zeek conn store is projected on the way
    past. Its fqdn is null unless the name-labeling layer (firru.namemap) is
    installed and asked for, which joins the claim map in at read time.
    """
    src = _parquet_glob(path)
    if not is_zeek_conn(path):
        return f"read_parquet({src!r})"
    fqdn, join = "CAST(NULL AS VARCHAR) AS fqdn", ""
    names = naming() if with_fqdn else None
    if names is not None:
        fqdn, join = names.fqdn_join(path, name_map) or (fqdn, join)
    return (f"(SELECT {ZEEK_COLUMNS} {fqdn} FROM "
            f"(SELECT * FROM read_parquet({src!r}) WHERE {ZEEK_KEEP_ROW}) c {join})")


def iter_flow_groups(path, host_ips=None):
    """Yield distinct (protocol, src_ip, dst_ip, dst_port) with a count `n`.

    Everything that buckets flows for tightening does the same thing to each
    row: look at those four fields and add one to a counter. Handing back rows
    makes the caller pay per flow; handing back groups makes it pay per distinct
    conversation, which on real traffic is orders of magnitude fewer. Over one
    overnight window the predicate already reduced 26M rows to 3M in
    a quarter of a second, and it was the 3.1M Python dicts that cost minutes.

    On parquet the grouping is a GROUP BY the engine does. On JSONL it is done
    here, which saves the caller's work but not the decode, so JSONL is no
    faster than it was -- just uniform.

    Rows carry `n`; a consumer that ignores it counts conversations rather than
    flows, which is why `_bucket_flow` takes a weight. They also carry
    `unanswered`: how many of the `n` say `responded` false. A flow without
    `responded` is not counted, so `unanswered == n` means every flow said so.
    """
    if is_parquet(path):
        yield from _group_parquet(path, host_ips)
    else:
        groups = {}
        for flow in _iter_jsonl(path, host_ips, False):
            key = tuple(flow.get(c) for c in _CORE)
            g = groups.setdefault(key, [0, 0])
            g[0] += 1
            g[1] += flow.get("responded") is False
        for key, (n, unanswered) in groups.items():
            d = dict(zip(_CORE, key))
            d["n"] = n
            d["unanswered"] = unanswered
            yield d


def _group_parquet(path, host_ips):
    import duckdb

    rel = flow_relation(path)
    where, params = "", []
    if host_ips:
        ips = list(host_ips)
        ph = ", ".join(["?"] * len(ips))
        where = f" WHERE src_ip IN ({ph}) OR dst_ip IN ({ph})"
        params = ips + ips
    cols = ", ".join(_CORE)
    have = {r[0] for r in duckdb.sql(f"DESCRIBE SELECT * FROM {rel}").fetchall()}
    unanswered = ("count(*) FILTER (WHERE responded = false)"
                  if "responded" in have else "0")
    q = (f"SELECT {cols}, count(*) AS n, {unanswered} AS unanswered FROM {rel}"
         f"{where} GROUP BY {cols}")
    res = duckdb.execute(q, params) if params else duckdb.execute(q)
    names = _CORE + ("n", "unanswered")
    while True:
        batch = res.fetchmany(10000)
        if not batch:
            break
        for row in batch:
            d = dict(zip(names, row))
            if d.get("dst_port") is not None:
                try:
                    d["dst_port"] = int(d["dst_port"])
                except (TypeError, ValueError):
                    d["dst_port"] = None
            yield d


def iter_flows(path, host_ips=None, with_fqdn=False):
    """Yield flow dicts from `path`, optionally filtered to flows that touch
    `host_ips` (as src or dst). Parquet pushes the filter down; JSONL scans."""
    if is_parquet(path):
        yield from _iter_parquet(path, host_ips, with_fqdn)
    else:
        yield from _iter_jsonl(path, host_ips, with_fqdn)


def _iter_jsonl(path, host_ips, with_fqdn):
    ipset = set(host_ips) if host_ips is not None else None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                flow = json.loads(line)
            except ValueError:
                continue
            if ipset is not None and flow.get("src_ip") not in ipset \
                    and flow.get("dst_ip") not in ipset:
                continue
            yield flow


def _iter_parquet(path, host_ips, with_fqdn):
    import duckdb

    rel = flow_relation(path, with_fqdn=with_fqdn)
    cols = list(_CORE)
    # fqdn only if the source can produce it: a store written without passive
    # DNS has no such column, and a zeek store with no claim map beside it
    # yields nulls rather than names.
    if with_fqdn:
        names = [r[0] for r in duckdb.sql(
            f"DESCRIBE SELECT * FROM {rel}").fetchall()]
        if "fqdn" in names:
            cols.append("fqdn")

    select = ", ".join(cols)
    where = ""
    params = []
    if host_ips:
        ips = list(host_ips)
        placeholders = ", ".join(["?"] * len(ips))
        where = f" WHERE src_ip IN ({placeholders}) OR dst_ip IN ({placeholders})"
        params = ips + ips

    q = f"SELECT {select} FROM {rel}{where}"
    res = duckdb.execute(q, params) if params else duckdb.execute(q)
    while True:
        batch = res.fetchmany(10000)
        if not batch:
            break
        for row in batch:
            d = dict(zip(cols, row))
            # dst_port may come back as a non-int; normalize like the JSONL path
            if d.get("dst_port") is not None:
                try:
                    d["dst_port"] = int(d["dst_port"])
                except (TypeError, ValueError):
                    d["dst_port"] = None
            yield d
