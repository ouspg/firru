"""
--out-parquet converts in SQL what the default route converts in Python, and
the two have to agree flow for flow.

They very nearly did not: DuckDB's CAST(DOUBLE AS BIGINT) rounds to nearest
where Python's int() truncates, so a first cut of the SQL disagreed with the
Python path on half of every hour by one second. The timestamps are DOUBLE now
and the trap is gone, but the equivalence is worth pinning: the SQL is a second
implementation of conn_to_flow, and nothing but a test keeps the two in step.
"""

import json

import pytest

duckdb = pytest.importorskip("duckdb")

from firru.cli.zeek_to_flows import conn_to_flow, parse_zeek, write_parquet_store

# Sub-second times on purpose: whole seconds would hide a truncation bug.
CONN = [
    # ts, orig_h, orig_p, resp_h, resp_p, proto, duration, history, conn_state, o_pkts, r_pkts
    (1776862800.75, "10.0.0.1", 5000, "10.0.0.5", 22, "tcp", 1.5, "ShAdDaf", "SF", 6, 5),
    (1776862800.25, "10.0.0.1", 5001, "10.0.0.6", 22, "tcp", 0.0, "S", "S0", 1, 0),
    (1776862801.50, "10.0.0.2", 40000, "8.8.8.8", 53, "udp", 0.1, "Dd", "SF", 1, 1),
    (1776862802.00, "10.0.0.2", 40001, "8.8.8.8", 53, "udp", 0.0, "D", "S0", 1, 0),
    (1776862803.99, "10.0.0.3", 6000, "10.0.0.7", 443, "tcp", 2.0, "ShR", "RSTO", 4, 3),
]

DNS = [
    (1776862700.0, "dns.google", ["8.8.8.8"]),
    (1776862750.0, "also.google", ["8.8.8.8"]),      # later, wins inside window
    (1776860000.0, "stale.example", ["10.0.0.5"]),   # outside a 300s window
    (1776862799.0, "cname.example", ["not-an-ip"]),  # dropped, not an address
]


@pytest.fixture
def zeek(tmp_path):
    """A zeek-shaped parquet pair: dotted column names, list-typed answers."""
    con = duckdb.connect()
    con.execute("""CREATE TABLE conn (ts DOUBLE, "id.orig_h" VARCHAR,
        "id.orig_p" BIGINT, "id.resp_h" VARCHAR, "id.resp_p" BIGINT,
        proto VARCHAR, duration DOUBLE, history VARCHAR, conn_state VARCHAR,
        orig_pkts BIGINT, resp_pkts BIGINT)""")
    con.executemany("INSERT INTO conn VALUES (?,?,?,?,?,?,?,?,?,?,?)", CONN)
    con.execute("CREATE TABLE dns (ts DOUBLE, query VARCHAR, answers VARCHAR[])")
    con.executemany("INSERT INTO dns VALUES (?,?,?)", DNS)
    cdir, ddir = tmp_path / "conn", tmp_path / "dns"
    cdir.mkdir(), ddir.mkdir()
    con.execute(f"COPY conn TO '{cdir}/part.parquet' (FORMAT parquet)")
    con.execute(f"COPY dns TO '{ddir}/part.parquet' (FORMAT parquet)")
    return str(cdir), str(ddir)


def python_path(conn_dir, label=None):
    out = []
    for row in parse_zeek(conn_dir):
        flow = conn_to_flow(row, label)
        if flow is not None:
            flow.setdefault("fqdn", None)
            out.append(flow)
    return sorted(out, key=lambda f: (f["timestamp"], f["src_port"]))


def sql_path(conn_dir, out, dns_dir=None):
    write_parquet_store([conn_dir], str(out), [dns_dir] if dns_dir else None, 300)
    rows = duckdb.sql(f"SELECT * EXCLUDE (hour) FROM read_parquet('{out}/**/*.parquet')")
    names = [d[0] for d in rows.description]
    got = [dict(zip(names, r)) for r in rows.fetchall()]
    return sorted(got, key=lambda f: (f["timestamp"], f["src_port"]))


class TestTheTwoRoutesAgree:
    def test_without_dns(self, zeek, tmp_path):
        conn_dir, _ = zeek
        assert sql_path(conn_dir, tmp_path / "s1") == python_path(conn_dir)


class TestTheFlowsThemselves:
    def test_fractional_seconds_survive(self, zeek, tmp_path):
        conn_dir, _ = zeek
        got = sql_path(conn_dir, tmp_path / "s3")
        assert [f["timestamp"] for f in got] == sorted(c[0] for c in CONN)
        assert got[0]["timestamp"] != int(got[0]["timestamp"])

    def test_two_flows_in_one_second_stay_ordered(self, zeek, tmp_path):
        """The reason for the DOUBLE: both of these truncate to 1776862800."""
        conn_dir, _ = zeek
        got = [f for f in sql_path(conn_dir, tmp_path / "s4")
               if int(f["timestamp"]) == 1776862800]
        assert len(got) == 2
        assert got[0]["timestamp"] < got[1]["timestamp"]

    def test_responded_follows_the_history_field(self, zeek, tmp_path):
        conn_dir, _ = zeek
        by_port = {f["src_port"]: f for f in sql_path(conn_dir, tmp_path / "s5")}
        assert by_port[5000]["responded"] is True     # 'h' = responder SYN-ACK
        assert by_port[5001]["responded"] is False    # S0, silent drop
        assert by_port[6000]["responded"] is True     # ShR, RST after SYN-ACK
        assert by_port[40000]["responded"] is True    # udp, return packet
        assert by_port[40001]["responded"] is False   # udp, none

    def test_the_store_is_hour_partitioned(self, zeek, tmp_path):
        import glob, os
        conn_dir, _ = zeek
        out = tmp_path / "s7"
        write_parquet_store([conn_dir], str(out))
        parts = glob.glob(os.path.join(out, "**", "*.parquet"), recursive=True)
        assert parts and all("hour=" in p for p in parts)

    def test_fqdn_column_exists_even_without_dns(self, zeek, tmp_path):
        """A store appended by both a --dns and a non---dns run reads as one glob."""
        conn_dir, _ = zeek
        assert "fqdn" in sql_path(conn_dir, tmp_path / "s8")[0]


def test_text_input_is_refused_with_a_pointer(tmp_path):
    log = tmp_path / "conn.log"
    log.write_text(json.dumps({"ts": 1.0, "proto": "tcp", "id.orig_h": "10.0.0.1",
                               "id.resp_h": "10.0.0.2"}) + "\n")
    with pytest.raises(ValueError, match="JSONL output"):
        write_parquet_store([str(log)], str(tmp_path / "out"))


class TestOldStoresAreRefused:
    """Appending fractional times to a whole-second store loses them silently:
    duckdb unifies the glob on the first file's type and rounds. Refuse instead."""

    def _bigint_store(self, tmp_path):
        store = tmp_path / "old"
        (store / "hour=2026-04-22T13").mkdir(parents=True)
        duckdb.execute(f"""COPY (SELECT 'tcp' AS protocol, '10.0.0.1' AS src_ip,
            '10.0.0.2' AS dst_ip, 1::BIGINT AS src_port, 22::BIGINT AS dst_port,
            1776862800::BIGINT AS "timestamp", NULL::VARCHAR AS fqdn)
            TO '{store}/hour=2026-04-22T13/part.parquet' (FORMAT parquet)""")
        return store

    def test_the_silent_rounding_is_real(self, tmp_path):
        """What the guard exists to prevent, shown directly."""
        store = self._bigint_store(tmp_path)
        (store / "hour=2026-04-22T14").mkdir()
        duckdb.execute(f"""COPY (SELECT 'tcp' AS protocol, '10.0.0.1' AS src_ip,
            '10.0.0.3' AS dst_ip, 2::BIGINT AS src_port, 22::BIGINT AS dst_port,
            1776862801.5::DOUBLE AS "timestamp", NULL::VARCHAR AS fqdn)
            TO '{store}/hour=2026-04-22T14/part.parquet' (FORMAT parquet)""")
        got = duckdb.sql(
            f"""SELECT "timestamp" FROM read_parquet('{store}/**/*.parquet')
                ORDER BY 1""").fetchall()
        assert got == [(1776862800,), (1776862802,)]   # .5 rounded away, no error

    def test_appending_to_one_is_refused(self, zeek, tmp_path):
        conn_dir, _ = zeek
        store = self._bigint_store(tmp_path)
        with pytest.raises(ValueError, match="silently round"):
            write_parquet_store([conn_dir], str(store))

    def test_a_fresh_directory_is_fine(self, zeek, tmp_path):
        conn_dir, _ = zeek
        assert write_parquet_store([conn_dir], str(tmp_path / "new")) == 0

    def test_appending_to_a_double_store_is_fine(self, zeek, tmp_path):
        conn_dir, _ = zeek
        store = tmp_path / "growing"
        write_parquet_store([conn_dir], str(store))
        assert write_parquet_store([conn_dir], str(store)) == 0
