"""The LSPR24 practice axis: did the listener answer, or refuse?

Zeek's named conn_state values decide it outright. The interesting case is
OTH (and null), where LSPR24 gives no handshake evidence and the fallback is
the returned-packet count -- which on its own counts a RST refusal as an
answer, because the RST is a returned packet.
"""
from lspr24_to_flows import REFUSAL_MAX_PKTS, _responded, row_to_flow


def test_named_states_decide_outright():
    for state in ("SF", "S1", "S2", "S3", "RSTO", "RSTR", "RSTRH", "SHR"):
        assert _responded(state, 0, 0) is True
    for state in ("S0", "REJ", "RSTOS0", "SH"):
        assert _responded(state, 99, 0) is False


def test_a_named_state_outranks_the_refusal_test():
    """SF with a trailing RST is a completed session, not a refusal."""
    assert _responded("SF", 1, 1) is True


def test_lone_rst_is_a_refusal():
    # SYN -> RST: one packet back, carrying the reset.
    assert _responded("OTH", 1, 1) is False
    assert _responded(None, 1, 1) is False


def test_a_returned_packet_without_a_rst_still_answers():
    assert _responded("OTH", 1, 0) is True


def test_a_session_that_ends_in_a_reset_still_answered():
    """Past the threshold there is real data in the response."""
    assert _responded("OTH", 12, 1) is True
    assert _responded("OTH", 2, 1) is True


def test_nothing_back_is_never_answered():
    assert _responded("OTH", 0, 0) is False
    assert _responded("OTH", 0, 1) is False


def test_threshold_is_tunable_and_disablable():
    assert _responded("OTH", 3, 1, 3) is False
    assert _responded("OTH", 4, 1, 3) is True
    # -1 restores the plain resp_pkts > 0 test, for reproducing older runs.
    assert _responded("OTH", 1, 1, -1) is True


def test_absent_counts_do_not_raise():
    assert _responded("OTH", None, None) is False
    assert _responded(None, None, None) is False


def _row(**kw):
    row = {"SrcIP": "10.0.0.1", "DstIP": "10.0.0.2", "Protocol": 6,
           "SrcPort": 40000, "DstPort": 22,
           "mTimestampStart": 1_700_000_000_000_000,
           "mTimestampLast": 1_700_000_001_000_000,
           "Tot Fwd Pkts": 1, "Tot Bwd Pkts": 1, "Conn_state": "OTH",
           "RST Flag Cnt": 1}
    row.update(kw)
    return row


def test_row_to_flow_carries_the_refusal_through():
    assert row_to_flow(_row())["responded"] is False
    assert row_to_flow(_row(**{"RST Flag Cnt": 0}))["responded"] is True


def test_row_to_flow_honours_the_override():
    assert row_to_flow(_row(), -1)["responded"] is True


def test_default_threshold_is_the_unambiguous_one():
    assert REFUSAL_MAX_PKTS == 1


def test_addresses_come_out_canonical():
    from lspr24_to_flows import row_to_flow
    f = row_to_flow({"SrcIP": "2A07:1182:0005:0012:0000:0000:0000:0002",
                     "DstIP": "10.5.12.3", "Protocol": 6, "SrcPort": 1, "DstPort": 22,
                     "mTimestampStart": 0, "mTimestampLast": 0, "Tot Bwd Pkts": 1})
    assert f["src_ip"] == f["originator"] == "2a07:1182:5:12::2"
    assert f["dst_ip"] == "10.5.12.3"


class TestRespondedSignal:
    def test_syn_ack_states_are_admitted(self):
        for st in ("SF", "S1", "S2", "S3", "RSTO", "RSTR", "RSTRH", "SHR"):
            assert _responded(st, 0) is True, st

    def test_refused_and_dropped_stay_blocked(self):
        # A RST refusal and a silent drop are both 'not admitted', even
        # though a REJ does put packets on the wire.
        for st in ("S0", "REJ", "RSTOS0", "SH"):
            assert _responded(st, 5) is False, st

    def test_midstream_falls_back_to_packet_count(self):
        assert _responded("OTH", 4) is True
        assert _responded("OTH", 0) is False
        assert _responded(None, 1) is True


class TestRowToFlow:
    def test_microsecond_timestamps_become_epoch_seconds(self):
        f = row_to_flow({"SrcIP": "10.0.0.2", "DstIP": "10.0.0.1",
                         "SrcPort": 4000, "DstPort": 443, "Protocol": 6,
                         "mTimestampStart": 1_709_715_604_289_731,
                         "mTimestampLast": 1_709_715_610_000_000,
                         "Tot Fwd Pkts": 5, "Tot Bwd Pkts": 4,
                         "Conn_state": "SF"})
        assert f["timestamp"] == 1_709_715_604
        assert f["end_time"] == 1_709_715_610
        assert f["protocol"] == "tcp"
        assert f["responded"] is True

    def test_protocol_number_mapped_to_name(self):
        for num, name in ((6, "tcp"), (17, "udp"), (1, "icmp"), (58, "icmpv6")):
            row = {"SrcIP": "a", "DstIP": "b", "Protocol": num,
                   "mTimestampStart": 0, "mTimestampLast": 0,
                   "Tot Bwd Pkts": 1, "Conn_state": "SF"}
            assert row_to_flow(row)["protocol"] == name

    def test_missing_endpoints_skipped(self):
        assert row_to_flow({"SrcIP": None, "DstIP": "b", "Protocol": 6}) is None

    def test_red_team_label_is_a_string_column(self):
        # Label_src/Label_dst are '0'/'1'/'2' strings in the parquet, not ints;
        # comparing against int 1 silently never matches.
        base = {"SrcIP": "a", "DstIP": "b", "Protocol": 6,
                "mTimestampStart": 0, "mTimestampLast": 0,
                "Tot Bwd Pkts": 1, "Conn_state": "SF"}
        assert row_to_flow({**base, "Label_src": "1"})["rt_src"] is True
        assert row_to_flow({**base, "Label_dst": "1"})["rt_dst"] is True

    def test_a_label_that_is_not_red_is_false_not_missing(self):
        # The clean arm of the 2x2 is `NOT rt_src`. A missing field reads as
        # null, and NOT null is null, so a row omitted here would fall out of
        # both arms instead of landing in the clean one.
        base = {"SrcIP": "a", "DstIP": "b", "Protocol": 6,
                "mTimestampStart": 0, "mTimestampLast": 0,
                "Tot Bwd Pkts": 1, "Conn_state": "SF"}
        assert row_to_flow({**base, "Label_src": "0"})["rt_src"] is False
        assert row_to_flow({**base, "Label_dst": "2"})["rt_dst"] is False

    def test_no_rt_keys_when_labels_absent(self):
        # No label column is the one case that means "not evaluated".
        f = row_to_flow({"SrcIP": "a", "DstIP": "b", "Protocol": 6,
                         "mTimestampStart": 0, "mTimestampLast": 0,
                         "Tot Bwd Pkts": 1, "Conn_state": "SF"})
        assert "rt_src" not in f and "rt_dst" not in f


def test_the_record_carries_the_contract_fields():
    """The flow record's required fields, from docs/flow-record.schema.json;
    tests/test_flow_record.py checks the in-tree producers against the schema."""
    import json
    import pathlib
    schema = json.loads((pathlib.Path(__file__).parents[2]
                         / "docs" / "flow-record.schema.json").read_text())
    f = row_to_flow({"Protocol": 6, "SrcIP": "10.0.0.1", "DstIP": "10.0.0.2",
                     "SrcPort": 5000, "DstPort": 443, "Timestamp": 1758369296000000,
                     "Last_seen": 1758369298000000, "Tot Fwd Pkts": 10,
                     "Tot Bwd Pkts": 8, "Conn_state": "SF"})
    assert f["source"] == "lspr24"
    assert isinstance(f["direction_known"], bool)
    for field in schema["required"]:
        assert field in f, field
