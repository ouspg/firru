"""address-summarizer: the lead line is the finding, so pin its shapes."""
import pytest

from firru.cli.address_summarizer import summarize

# Scattered on purpose: public resolvers in five unrelated /8s.
FAN_IN = {"1.1.1.1": 1, "9.9.9.9": 1, "64.6.64.6": 1,
          "149.112.112.112": 1, "208.67.222.222": 1}
CLUSTER = {"10.85.7.176": 400, "10.85.7.177": 56, "10.85.7.180": 12}


def test_budget_only_binds_when_there_are_more_addresses_than_entries():
    # Three addresses at a budget of five need no widening. .176 and .177 still
    # collapse to a /31, which is lossless -- adjacent addresses genuinely are
    # that prefix -- so the summary stays exact.
    out = summarize(CLUSTER, 5)
    assert out.startswith("3 addresses in 1 block, widest /31:")
    assert "10.85.7.180/32" in out


def test_a_binding_budget_aggregates_and_sums_the_weights():
    out = summarize(CLUSTER, 1)
    assert "10.85.7.176/29" in out and "3 src, 468 hits" in out


def test_a_fan_in_still_gets_a_summary_and_the_width_is_the_signal():
    # A prefix that has widened to /1 or /4 is a result: these addresses have no
    # common neighbourhood. Refusing would break the "always N entries" contract
    # that makes the output automatable.
    out = summarize(FAN_IN, 2)
    assert out.startswith("5 addresses in 5 blocks, widest /")
    assert int(out.split("widest /")[1].split(":")[0]) <= 8


def test_clustered_and_scattered_are_told_apart_by_the_widest_prefix():
    narrow = int(summarize(CLUSTER, 1).split("widest /")[1].split(":")[0])
    wide = int(summarize(FAN_IN, 1).split("widest /")[1].split(":")[0])
    assert narrow > wide


def test_families_never_share_a_supernet():
    out = summarize({"10.0.0.1": 1, "2001:db8::1": 1}, 2)
    assert "::/0" not in out and "0.0.0.0/0" not in out


def test_singular_hit_and_custom_noun():
    assert "(1 hit)" in summarize({"10.0.0.1": 1}, 5)
    assert "2 dst" in summarize({"10.0.0.1": 1, "10.0.0.2": 1}, 1, noun="dst")


def test_empty_input():
    assert summarize({}, 5) == "no addresses"


def test_asn_grouping_reports_organisations():
    geoip2 = pytest.importorskip("geoip2.database")
    import os
    from firru.cli.address_summarizer import summarize_asn, _default_asn_db
    db = _default_asn_db()
    if not db or not os.path.exists(db):
        pytest.skip("no ASN database available")
    out = summarize_asn({"8.8.8.8": 5}, 3, db, "dst")
    assert "1 address in 1 AS" in out and "AS15169" in out


# --- the tighten wiring: what ANY means, as a comment -----------------------

class _Ann:
    """annotate_ip stub: anything not in `known` is EXTERNAL."""
    def __init__(self, known=()):
        self.known = set(known)
        self.group_members = {}

    def annotate_ip(self, ip):
        if ip in self.known:
            return {"type": "HOST", "host": "known_host", "parents": []}
        return {"type": "EXTERNAL"}


def test_note_is_none_when_every_source_resolves():
    from collections import Counter
    from firru.cli.tighten import unresolved_note
    assert unresolved_note(Counter({"10.0.0.1": 3}), _Ann(["10.0.0.1"])) is None


def test_private_space_outranks_the_other_verdicts():
    from collections import Counter
    from firru.cli.tighten import unresolved_note
    out = unresolved_note(Counter({"10.85.7.176": 400, "10.85.7.177": 5}), _Ann())
    assert "private address space" in out and "inventory" in out


def test_a_single_unresolved_source_says_so():
    from collections import Counter
    from firru.cli.tighten import unresolved_note
    out = unresolved_note(Counter({"9.9.9.9": 1}), _Ann())
    assert "a single source" in out


def test_a_fan_in_is_called_honest_any():
    from collections import Counter
    from firru.cli.tighten import unresolved_note
    out = unresolved_note(Counter(dict.fromkeys(FAN_IN, 1)), _Ann())
    assert "ANY is honest" in out


def test_dns_names_win_when_every_address_has_one():
    from collections import Counter
    from firru.cli.tighten import unresolved_note
    store = {"93.184.216.34": "update.example.com", "93.184.216.35": "cdn.example.com"}
    out = unresolved_note(Counter({"93.184.216.34": 9, "93.184.216.35": 2}),
                          _Ann(), dns_store=store, noun="dst")
    assert "all named" in out and "update.example.com" in out
    assert "inventory" in out


def test_structure_needs_a_majority_in_one_group_not_merely_a_collapse():
    # 27 addresses in 22 unrelated networks is a fan-in, not a group. An earlier
    # rule called any collapse structure and got this exactly backwards.
    from collections import Counter
    from firru.cli.tighten import _verdict
    # Genuinely unrelated networks, one address each: no prefix holds a
    # majority however the budget is spent.
    scattered = {f"{a}.12.34.{i}": 1
                 for i, a in enumerate((11, 37, 62, 88, 102, 141, 176, 199, 221))}
    assert "ANY is honest" in _verdict(Counter(scattered), "")

    # Twenty in one /24 and one stray: that is a group worth naming.
    clustered = {f"11.12.34.{i}": 1 for i in range(20)}
    clustered["77.88.99.1"] = 1
    assert "would cover most of this" in _verdict(Counter(clustered), "")


def test_nothing_routable_does_not_report_zero_ases():
    import os
    import pytest as _pytest
    _pytest.importorskip("geoip2.database")
    from firru.cli.address_summarizer import summarize_asn, _default_asn_db
    db = _default_asn_db()
    if not db or not os.path.exists(db):
        _pytest.skip("no ASN database available")
    out = summarize_asn({"10.85.7.176": 4}, 5, db)
    assert "0 AS" not in out and "none of them routable" in out


# --- grouped flow reads must not change a single count ----------------------

def test_group_iteration_matches_row_iteration(tmp_path):
    """The GROUP BY is an optimization, so every counter must come out the same."""
    import json
    from collections import Counter
    from firru.flows import iter_flows, iter_flow_groups

    rows = [
        {"protocol": "tcp", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.9", "dst_port": 443},
        {"protocol": "tcp", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.9", "dst_port": 443},
        {"protocol": "tcp", "src_ip": "10.0.0.2", "dst_ip": "10.0.0.9", "dst_port": 22},
        {"protocol": "udp", "src_ip": "10.0.0.3", "dst_ip": "10.0.0.9", "dst_port": 53},
    ]
    p = tmp_path / "flows.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    key = lambda f: (f["protocol"], f["src_ip"], f["dst_ip"], f["dst_port"])
    by_row = Counter(key(f) for f in iter_flows(str(p)))
    by_group = Counter()
    for f in iter_flow_groups(str(p)):
        by_group[key(f)] += f["n"]

    assert by_row == by_group
    assert sum(by_group.values()) == 4
    assert len(by_group) == 3


def test_bucket_flow_honors_the_group_weight():
    from collections import Counter, defaultdict
    from aerleon.lib import naming
    from firru.cli.tighten import _bucket_flow

    defs = naming.Naming.__new__(naming.Naming)   # GetPortParents is not needed
    defs.GetPortParents = lambda port, proto: []
    ing, eg = defaultdict(Counter), defaultdict(Counter)
    ip, ep = defaultdict(Counter), defaultdict(Counter)
    flow = {"protocol": "tcp", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.9",
            "dst_port": 443, "n": 17}
    _bucket_flow(flow, {"10.0.0.9"}, defs, ing, eg, ip, ep)
    assert sum(c["10.0.0.1"] for c in ing.values()) == 17
