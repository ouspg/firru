"""
Regression tests for the shapes that have actually broken analyses.

Each test names the pathology it pins (P1..P12 in make_zeek_tree.py) and, where
one exists, the bug it would have caught. Several of these are not hypothetical:
they are defects that shipped and were found months later by reconstructing
from the capture, which is the slow way to learn them.
"""

import json
import pathlib
import subprocess
import sys

import duckdb
import pytest

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "make_zeek_tree.py"


@pytest.fixture(scope="module")
def tree(tmp_path_factory):
    out = tmp_path_factory.mktemp("zeek")
    subprocess.run([sys.executable, str(FIXTURE), str(out)], check=True,
                   capture_output=True)
    return out


@pytest.fixture(scope="module")
def expected(tree):
    return json.loads((tree / "expected.json").read_text())


def read(tree, log):
    """Every hour of one log type, as one relation. union_by_name is the point."""
    return duckdb.sql(
        f"SELECT * FROM read_json_auto('{tree}/*/{log}.*', "
        "union_by_name=true, ignore_errors=true)")


def test_ragged_schema_reads_as_one_relation(tree, expected):
    """P2/P5: hours disagree on columns and one is gzipped; it still reads."""
    rel = read(tree, "conn")
    assert rel.aggregate("count(*)").fetchall()[0][0] == expected["rows"]["conn"]
    # orig_pkts is absent in the warm-up hour and present later: nulls, not error.
    nulls = duckdb.sql(
        f"SELECT count(*) FROM read_json_auto('{tree}/*/conn.*', "
        "union_by_name=true) WHERE orig_pkts IS NULL").fetchall()[0][0]
    assert nulls > 0, "warm-up hour should contribute null orig_pkts"


def test_dotted_field_names_survive(tree):
    """P3: id.orig_h is a name containing a dot, not a nested path."""
    n = duckdb.sql(
        f"SELECT count(DISTINCT \"id.orig_h\") FROM "
        f"read_json_auto('{tree}/*/conn.*', union_by_name=true)").fetchall()[0][0]
    assert n >= 4


def test_hours_are_not_contiguous(tree, expected):
    """P4: the offline window is a real hole; nothing may assume contiguity."""
    present = sorted(p.name for p in tree.iterdir() if p.is_dir()
                     and p.name != "loot")
    assert present == expected["hours_present"]
    for missing in expected["hours_missing"]:
        assert not (tree / missing).exists()


def test_absent_log_type_is_not_an_error(tree, expected):
    """P12: the 08Z hour has no ssl.log; the glob must simply not match it."""
    assert not list((tree / "20260421T080000Z").glob("ssl.*"))
    assert read(tree, "ssl").aggregate("count(*)").fetchall()[0][0] \
        == expected["rows"]["ssl"]


def test_tuple_attribution_is_per_tuple_not_per_flow(tree, expected):
    """P6. The bug this pins: labelling a straddling tuple per *flow* puts it in
    two cohorts and double-counts it. One tuple has flows in the warm-up hour
    and a live hour; one is warm-up-only. Per-tuple, exactly one is warm-up-only.
    """
    b = expected["boundary_ts"]
    q = duckdb.sql(f"""
        SELECT "id.orig_h" || '|' || "id.resp_h" || '|' || "id.resp_p" AS t,
               bool_and(ts < {b}) AS warmup_only,
               bool_or(ts < {b})  AS touches_warmup
        FROM read_json_auto('{tree}/*/conn.*', union_by_name=true)
        GROUP BY 1""")
    rows = {r[0]: (r[1], r[2]) for r in q.fetchall()}
    only = sum(1 for w, _ in rows.values() if w)
    touching = sum(1 for _, t in rows.values() if t)
    assert only == expected["warmup_only_tuples"]
    assert touching == expected["warmup_touching_tuples"]
    assert only < touching, "the straddling tuple must not count as warm-up-only"

    # The discriminating pair, named: same source port and service, one
    # straddles the boundary and one does not. Per-flow labelling cannot tell
    # them apart; per-tuple must.
    straddle = rows[expected["straddling_tuple"]]
    warmonly = rows[expected["warmup_only_tuple"]]
    assert straddle == (False, True), "straddling tuple: touches, not only"
    assert warmonly == (True, True), "control tuple: warm-up only"


def test_flow_weighting_and_tuple_weighting_disagree(tree, expected):
    """P7. The bug this pins: a flow-weighted cell lets one retried connection
    outweigh forty distinct relationships, reversing which population dominates.
    """
    rows = duckdb.sql(f"""
        SELECT "id.orig_h" AS src, count(*) AS flows,
               count(DISTINCT "id.resp_p") AS tuples
        FROM read_json_auto('{tree}/*/conn.*', union_by_name=true)
        WHERE "id.orig_h" IN ('192.0.2.11', '198.51.100.99')
        GROUP BY 1""").fetchall()
    by_src = {r[0]: (r[1], r[2]) for r in rows}
    retry_flows, retry_tuples = by_src["192.0.2.11"]
    scan_flows, scan_tuples = by_src["198.51.100.99"]
    # Opposite orderings under the two weightings: that is the whole point.
    assert retry_flows > scan_flows
    assert retry_tuples < scan_tuples


def test_conditioning_on_loot_removes_the_no_listener_bulk(tree, expected):
    """P1/P8. Two bugs at once: the hostname join (loot FQDN vs Aerleon token,
    dots vs underscores) and the no-listener bulk that makes a "block"
    indistinguishable from an absent service.
    """
    loot = []
    for f in (tree / "loot").glob("*.json"):
        doc = json.loads(f.read_text())
        host = doc["metadata"]["hostname"]
        for addr in doc["addresses"]:
            for lp in doc["listen_ports"]:
                loot.append((host, addr, lp["port"]))
    con = duckdb.connect()
    con.execute("CREATE TABLE L(host VARCHAR, addr VARCHAR, port BIGINT)")
    con.executemany("INSERT INTO L VALUES (?, ?, ?)", loot)

    tot, cond = con.execute(f"""
        WITH c AS (SELECT * FROM read_json_auto('{tree}/*/conn.*',
                                                union_by_name=true))
        SELECT (SELECT count(DISTINCT "id.orig_h" || "id.resp_h" || "id.resp_p")
                FROM c),
               (SELECT count(DISTINCT "id.orig_h" || c."id.resp_h"
                             || c."id.resp_p")
                FROM c JOIN L ON L.addr = c."id.resp_h"
                             AND L.port = c."id.resp_p")
    """).fetchall()[0]
    assert tot - cond == expected["no_listener_scan_tuples"], \
        "conditioning must drop exactly the scan ports nothing listens on"

    # P1: joining the token form against the FQDN form finds nothing. This is
    # the shape that needs replace(lower(host), '_', '.') on the analysis side.
    tokens = {h.replace(".", "_") for h in
              (json.loads(f.read_text())["metadata"]["hostname"]
               for f in (tree / "loot").glob("*.json"))}
    fqdns = {h for h in (json.loads(f.read_text())["metadata"]["hostname"]
                         for f in (tree / "loot").glob("*.json"))}
    assert tokens.isdisjoint(fqdns)
    assert {t.replace("_", ".") for t in tokens} == fqdns


def test_address_families_split_on_the_same_host_and_port(tree, expected):
    """P10. The bug this pins: collapsing families hides that the same rule was
    enforced over one and not the other.
    """
    both = expected["both_family_host_port"]
    rows = duckdb.sql(f"""
        SELECT contains("id.resp_h", ':') AS is_v6, conn_state, count(*)
        FROM read_json_auto('{tree}/*/conn.*', union_by_name=true)
        WHERE "id.resp_p" = {both['port']}
          AND "id.orig_h" IN ('198.51.100.5', '2001:db8:bad::5')
        GROUP BY 1, 2""").fetchall()
    states = {(r[0], r[1]) for r in rows}
    assert (False, both["v4_state"]) in states
    assert (True, both["v6_state"]) in states


def test_dns_outweighs_conn(tree, expected):
    """P11: on the real capture dns records outnumber connections. Nothing may
    size its work off conn alone."""
    assert expected["dns_outweighs_conn"]
    assert expected["rows"]["dns"] > expected["rows"]["conn"]


def test_service_gone_by_the_time_the_syn_lands(tree):
    """P9: db1:9999 is in the inventory and refuses every connection. A cell
    read as over-enforcement must be reported as an upper bound because of it.
    """
    n = duckdb.sql(f"""
        SELECT count(*) FROM read_json_auto('{tree}/*/conn.*',
                                            union_by_name=true)
        WHERE "id.resp_p" = 9999 AND conn_state = 'REJ'""").fetchall()[0][0]
    assert n == 4, "one refusal per hour, on a port the loot says was listening"


# --- the LSPR24 example's synthetic arm regenerates what is committed -------

def test_synthetic_loot_manifest_has_not_drifted(tmp_path):
    """
    The synthetic loot tree is not committed (1.4 MB, 77% tail filler that
    churns on every seed change); its manifest is. That only works if the
    manifest provably matches a fresh run, so this is the guard: change the
    generator without refreshing the manifest and this fails.
    """
    import json
    import pathlib
    import subprocess
    import sys

    ex = pathlib.Path(__file__).parent.parent / "examples" / "lspr24"
    committed = ex / "loot-synth-manifest.json"
    if not committed.exists():
        import pytest
        pytest.skip("LSPR24 example not present")

    out = tmp_path / "loot"
    subprocess.run([sys.executable, str(ex / "make_loot.py"),
                    "--hosts", str(ex / "def" / "host_metadata.json"),
                    "--out", str(out), "--seed", "1"],
                   check=True, capture_output=True)
    fresh = json.loads((out / "manifest.json").read_text())
    assert fresh == json.loads(committed.read_text()), \
        "generator output drifted from the committed manifest; run `make manifest`"
