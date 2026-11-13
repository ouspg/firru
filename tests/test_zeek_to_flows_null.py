"""
A Zeek numeric field is absent in two different spellings.

The text forms write "-" and float() rejects it with ValueError; a parquet
export writes a real NULL and float() rejects it with TypeError. Catching only
the first killed the generator mid-stream on the first null `duration`: 26 of
427,420 rows converted, and the traceback went to stderr where the `2>/dev/null`
in a shell pipeline hides it. Silent truncation, not a crash the caller sees.
"""

from firru.cli.zeek_to_flows import conn_to_flow, _float


def row(**over):
    base = {"ts": "1776740402.4", "proto": "tcp", "id.orig_h": "10.0.0.1",
            "id.resp_h": "10.0.0.2", "id.orig_p": 1234, "id.resp_p": 443,
            "duration": "0.5", "history": "ShAd", "orig_pkts": "3",
            "resp_pkts": "2", "conn_state": "SF"}
    base.update(over)
    return base


def test_float_accepts_both_spellings_of_absent():
    assert _float("-") is None
    assert _float(None) is None
    assert _float("") is None
    assert _float(1.5) == 1.5


def test_a_null_duration_still_yields_a_flow():
    """The parquet spelling. This is the one that truncated the stream."""
    assert conn_to_flow(row(duration=None)) is not None


def test_a_dash_duration_still_yields_a_flow():
    """The TSV spelling, which already worked and must keep working."""
    assert conn_to_flow(row(duration="-")) is not None


def test_a_null_timestamp_drops_only_that_row():
    assert conn_to_flow(row(ts=None)) is None
    assert conn_to_flow(row()) is not None


def test_numeric_types_survive_the_parquet_path():
    """Parquet hands back floats and ints, not the strings the text forms do."""
    flow = conn_to_flow(row(ts=1776740402.4, duration=0.5, orig_pkts=3,
                            resp_pkts=2))
    assert flow is not None
    assert flow["orig_pkts"] == 3 and flow["resp_pkts"] == 2
