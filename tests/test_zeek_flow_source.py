"""
A zeek conn store is a flow store. The flow record is a projection of conn --
renamed columns, two derived fields, rows with no time/protocol/address dropped
-- so materializing it buys nothing but disk and a second thing to keep
current. These tests pin the equivalence that made it safe to stop.

It was checked at scale before it was checked here: over a ~150M-row export,
every row of the derived store and the projection of the conn store
agree on every one of the twelve flow columns, and an hour scored through the
full verdict recipe from each side agrees on 24 of 25 output columns. The
twenty-fifth is fqdn, where reading conn is strictly better, because the claim
map carries TLS SNI and HTTP Host as well as dns answers.
"""

import json

import pytest

duckdb = pytest.importorskip("duckdb")

from firru import flows

T0 = 1776862800.0

CONN = [
    # ts, orig_h, orig_p, resp_h, resp_p, proto, duration, history, conn_state, o_pkts, r_pkts
    (T0 + 1.5, "10.0.0.1", 5000, "10.0.0.5", 22, "tcp", 1.0, "ShAdDaf", "SF", 6, 5),
    (T0 + 2.5, "10.0.0.1", 5001, "10.0.0.6", 443, "tcp", 0.0, "S", "S0", 1, 0),
    (T0 + 3.5, "10.0.0.2", 40000, "8.8.8.8", 53, "udp", 0.1, "Dd", "SF", 1, 1),
    # dropped by the keep-row filter: no protocol, then no address
    (T0 + 4.5, "10.0.0.3", 6000, "10.0.0.7", 80, None, 0.0, "S", "S0", 1, 0),
    (T0 + 5.5, "-", 6001, "10.0.0.7", 80, "tcp", 0.0, "S", "S0", 1, 0),
]

DNS = [(T0 + 1.0, "ssh.example", ["10.0.0.5"])]
SSL = [(T0 + 2.0, "10.0.0.6", "sni.example")]


@pytest.fixture
def zeek(tmp_path):
    """A zeek store: conn/ and dns/ and ssl/ side by side, as zeek writes them."""
    con = duckdb.connect()
    root = tmp_path / "parquet"
    (root / "conn").mkdir(parents=True)
    (root / "dns").mkdir()
    (root / "ssl").mkdir()
    con.execute("""CREATE TABLE conn (ts DOUBLE, "id.orig_h" VARCHAR,
        "id.orig_p" BIGINT, "id.resp_h" VARCHAR, "id.resp_p" BIGINT,
        proto VARCHAR, duration DOUBLE, history VARCHAR, conn_state VARCHAR,
        orig_pkts BIGINT, resp_pkts BIGINT)""")
    con.executemany("INSERT INTO conn VALUES (?,?,?,?,?,?,?,?,?,?,?)", CONN)
    con.execute(f"COPY conn TO '{root}/conn/h0.parquet' (FORMAT parquet)")
    con.execute("CREATE TABLE dns (ts DOUBLE, query VARCHAR, answers VARCHAR[])")
    con.executemany("INSERT INTO dns VALUES (?,?,?)", DNS)
    con.execute(f"COPY dns TO '{root}/dns/h0.parquet' (FORMAT parquet)")
    con.execute('CREATE TABLE ssl (ts DOUBLE, "id.resp_h" VARCHAR, server_name VARCHAR)')
    con.executemany("INSERT INTO ssl VALUES (?,?,?)", SSL)
    con.execute(f"COPY ssl TO '{root}/ssl/h0.parquet' (FORMAT parquet)")
    return root


@pytest.fixture
def derived(zeek, tmp_path):
    """The same flows through the materialized store, for comparison."""
    from firru.cli.zeek_to_flows import write_parquet_store
    out = tmp_path / "flowstore"
    write_parquet_store([str(zeek / "conn")], str(out))
    return out


class TestRecognisingIt:
    def test_a_conn_store_is_zeek(self, zeek):
        assert flows.is_zeek_conn(str(zeek / "conn"))

    def test_a_flow_store_is_not(self, derived):
        assert not flows.is_zeek_conn(str(derived))

    def test_jsonl_is_not(self, tmp_path):
        p = tmp_path / "f.jsonl"
        p.write_text('{"protocol":"tcp"}\n')
        assert not flows.is_zeek_conn(str(p))


class TestItReadsAsAFlowStore:
    def test_the_rows_match_the_derived_store(self, zeek, derived):
        """The equivalence itself, on every column but the name."""
        con = duckdb.connect()
        cols = ("protocol, src_ip, dst_ip, src_port, dst_port, originator, "
                "timestamp, end_time, orig_pkts, resp_pkts, responded, conn_state")
        q = lambda rel: con.execute(
            f"SELECT {cols} FROM {rel} ORDER BY timestamp").fetchall()
        assert q(flows.flow_relation(str(zeek / "conn"))) == \
               q(f"read_parquet('{derived}/**/*.parquet')")

    def test_unusable_rows_are_dropped(self, zeek):
        got = list(flows.iter_flows(str(zeek / "conn")))
        assert len(got) == 3          # the null proto and the "-" address go
        assert {f["dst_port"] for f in got} == {22, 443, 53}

    def test_responded_is_derived_not_renamed(self, zeek):
        """The one field that is not a rename: for TCP it is the history flag
        for a server-side handshake, not a packet count. tcp/443 sent one packet
        and got no handshake, so it did not respond."""
        rows = duckdb.connect().execute(
            f"SELECT dst_port, responded FROM "
            f"{flows.flow_relation(str(zeek / 'conn'))} ORDER BY dst_port").fetchall()
        assert rows == [(22, True), (53, True), (443, False)]

    def test_the_host_filter_pushes_down(self, zeek):
        got = list(flows.iter_flows(str(zeek / "conn"), host_ips={"8.8.8.8"}))
        assert [f["dst_port"] for f in got] == [53]

    def test_grouping_counts_the_unanswered(self, zeek):
        """tcp/443 got no handshake, so its one flow went unanswered."""
        got = {g["dst_port"]: g["unanswered"] for g in flows.iter_flow_groups(str(zeek / "conn"))}
        assert got == {22: 0, 53: 0, 443: 1}

    def test_grouping_agrees_with_the_derived_store(self, zeek, derived):
        key = lambda gs: sorted((g["protocol"], g["src_ip"], g["dst_ip"],
                                 g["dst_port"], g["n"]) for g in gs)
        assert key(flows.iter_flow_groups(str(zeek / "conn"))) == \
               key(flows.iter_flow_groups(str(derived)))
