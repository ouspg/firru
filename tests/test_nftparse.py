"""
Importing a running nftables ruleset as policy.

The parse is partial on purpose, so most of what is pinned here is about the
partiality: what it resolves, what it refuses to guess, and above all which
direction an error runs. A term that comes out wider than the rule it came from
is the one failure that matters, because it turns a firewall audit into a
false clean bill.
"""

import shutil
import subprocess

import pytest

from firru.cli.aerleon_to_nftables import add_counters, drop_family_mismatch
from firru.cli.nft_to_aerleon import convert
from firru.nftparse import chains_with_rules, merge_rules, named_sets, parse_rule


def rule(chain="c", expr=None, handle=1):
    return {"rule": {"family": "inet", "table": "t", "chain": chain,
                     "handle": handle, "expr": expr or []}}


def chain(name, base=False, policy=None):
    c = {"family": "inet", "table": "t", "name": name, "handle": 1}
    if base:
        c.update({"type": "filter", "hook": "input", "prio": 0, "policy": policy})
    return {"chain": c}


MATCH_SADDR = {"match": {"op": "==", "left": {"payload": {"protocol": "ip",
                                                          "field": "saddr"}},
                         "right": {"prefix": {"addr": "10.0.0.0", "len": 8}}}}
MATCH_DPORT = {"match": {"op": "==", "left": {"payload": {"protocol": "tcp",
                                                          "field": "dport"}},
                         "right": 22}}
COUNTER = {"counter": {"packets": 7, "bytes": 400}}
ACCEPT = {"accept": None}


def test_a_rule_becomes_addresses_ports_protocol_and_an_action():
    m, ignored = parse_rule({"expr": [MATCH_SADDR, MATCH_DPORT, COUNTER, ACCEPT]})
    assert str(m["source-address"][0]) == "10.0.0.0/8"
    assert m["destination-port"] == [(22, 22)]
    assert m["protocol"] == "tcp" and m["action"] == "accept"
    assert m["packets"] == 7 and ignored == []


def test_a_match_the_parser_cannot_represent_is_named_not_swallowed():
    rate = {"limit": {"rate": 5, "per": "minute"}}
    m, ignored = parse_rule({"expr": [rate, ACCEPT]})
    assert ignored == ["limit"]
    assert m["action"] == "accept"  # still converted


def test_an_interface_match_is_policy_on_a_container_host_not_decoration():
    iif = {"match": {"op": "==", "left": {"meta": {"key": "iifname"}},
                     "right": "virbr0"}}
    m, ignored = parse_rule({"expr": [iif, ACCEPT]})
    assert m["source-interface"] == "virbr0" and ignored == []


def test_a_negated_interface_is_ignored_rather_than_inverted():
    """`iifname != docker0` has no equivalent here, and a near-equivalent lies."""
    iif = {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}},
                     "right": "docker0"}}
    m, ignored = parse_rule({"expr": [iif, ACCEPT]})
    assert m["source-interface"] is None
    assert ignored == ["meta.iifname (negated)"]


def test_a_conditional_jump_is_routing_and_does_not_count_against_coverage():
    doc = {"nftables": [chain("c"), rule("c", [MATCH_SADDR,
                                               {"jump": {"target": "other"}}])]}
    _, skipped, _ = chains_with_rules(doc)
    assert skipped == {}


def test_a_translation_rule_is_neither_policy_nor_a_parse_failure():
    doc = {"nftables": [chain("post"), rule("post", [MATCH_SADDR,
                                                     {"masquerade": None}])]}
    _, skipped, nat = chains_with_rules(doc)
    assert skipped == {} and sum(nat.values()) == 1


def test_a_masked_match_is_named_by_what_it_matches_not_by_the_operator():
    mark = {"match": {"op": "==",
                      "left": {"&": [{"meta": {"key": "mark"}}, 65536]},
                      "right": 65536}}
    _, ignored = parse_rule({"expr": [mark, ACCEPT]})
    assert ignored == ["meta.mark (masked)"]


def test_a_named_set_resolves_from_the_ruleset_that_declared_it():
    doc = {"nftables": [
        {"set": {"name": "hosts", "elem": ["10.1.1.1",
                                           {"prefix": {"addr": "10.2.0.0", "len": 16}}]}},
        chain("c"),
        rule("c", [{"match": {"op": "==",
                              "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                              "right": "@hosts"}}, ACCEPT]),
    ]}
    assert set(named_sets(doc)) == {"hosts"}
    chains, skipped, _ = chains_with_rules(doc)
    addrs = {str(a) for a in chains["c"][1][0]["source-address"]}
    assert addrs == {"10.1.1.1/32", "10.2.0.0/16"}


def test_a_set_the_document_does_not_declare_is_reported_not_invented():
    m, ignored = parse_rule({"expr": [
        {"match": {"op": "==",
                   "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                   "right": "@elsewhere"}}, ACCEPT]})
    assert ignored == ["saddr=@elsewhere"]
    assert m["source-address"] == []


def test_rules_that_only_jump_are_structure_and_do_not_count_against_coverage():
    doc = {"nftables": [chain("root", base=True, policy="drop"),
                        rule("root", [{"jump": {"target": "c"}}]),
                        chain("c"), rule("c", [MATCH_DPORT, ACCEPT])]}
    _, skipped, _ = chains_with_rules(doc)
    assert skipped == {}


def test_a_hooked_chain_holding_its_own_rules_is_read_not_skipped():
    """Aerleon gives each term a chain; Calico and hand-written firewalls do not."""
    doc = {"nftables": [chain("cali-INPUT", base=True, policy="drop"),
                        rule("cali-INPUT", [MATCH_SADDR, MATCH_DPORT, ACCEPT])]}
    policy, stats = convert(doc, defs=None, host="n1")
    names = [t["name"] for t in policy["filters"][0]["terms"]]
    assert "cali-INPUT-accept-tcp-22" in names
    assert stats["default"] == "drop"


def test_the_base_chains_policy_becomes_the_terminal():
    doc = {"nftables": [chain("root", base=True, policy="drop")]}
    policy, _ = convert(doc, defs=None)
    assert policy["filters"][0]["terms"][-1]["name"] == "drop-ANY"
    assert policy["filters"][0]["terms"][-1]["action"] == "deny"


def test_an_address_no_token_names_is_carried_as_a_literal_not_dropped():
    """Dropping the match would not narrow the term, it would widen it to all."""
    doc = {"nftables": [chain("c"), rule("c", [MATCH_SADDR, MATCH_DPORT, ACCEPT])]}
    policy, stats = convert(doc, defs=None)
    term = policy["filters"][0]["terms"][0]
    assert term["source-address"] == "10.0.0.0/8"
    assert stats["unnamed_terms"] == 1


def test_metadata_is_written_so_merge_zones_accepts_the_result():
    doc = {"nftables": [chain("c"), rule("c", [MATCH_DPORT, ACCEPT])]}
    policy, _ = convert(doc, defs=None, host="web1", zone="DMZ")
    assert policy["metadata"] == {"host": "web1", "zone": "DMZ"}


def test_counters_go_before_the_verdict_and_not_on_chain_headers():
    src = ("chain c {\n"
           "    type filter hook input priority 0; policy drop;\n"
           "    ip saddr 0.0.0.0/0 tcp dport 22 ct state new accept\n"
           "    jump other\n"
           "}\n")
    out = add_counters(src)
    assert "ct state new counter accept" in out
    assert "policy drop;" in out and "counter policy" not in out
    assert "    jump other" in out


def test_an_icmp_match_on_a_v6_rule_is_dropped_because_it_will_not_load():
    src = ("    ip daddr 10.0.0.1/32 ip protocol icmp ct state new accept\n"
           "    ip6 daddr 2001:db8::1/128 ip protocol icmp ct state new accept\n")
    out, dropped = drop_family_mismatch(src)
    assert dropped == 1 and "ip6 daddr" not in out and "# dropped:" in out


def test_an_icmpv6_match_on_a_v4_rule_is_dropped_because_it_can_never_match():
    out, dropped = drop_family_mismatch(
        "    ip daddr 10.0.0.1/32 meta l4proto icmpv6 accept\n")
    assert dropped == 1 and "# dropped:" in out


@pytest.mark.skipif(not shutil.which("nft") or not shutil.which("unshare"),
                    reason="needs nft and unshare")
def test_a_generated_ruleset_loads_into_a_real_kernel(tmp_path):
    """The check the pipeline never ran. No root: unshare -rn is enough."""
    src = ("chain allow-icmp {\n"
           "    ip daddr 10.0.0.1/32 ip protocol icmp ct state new accept\n"
           "    ip6 daddr 2001:db8::1/128 ip protocol icmp ct state new accept\n"
           "}\n"
           "chain root0 {\n"
           "    type filter hook input priority 0; policy drop;\n"
           "    jump allow-icmp\n"
           "}\n")
    fixed, _ = drop_family_mismatch(src)
    path = tmp_path / "r.nft"
    path.write_text("table inet filter {\n" + add_counters(fixed) + "}\n")
    r = subprocess.run(["unshare", "-rn", "nft", "-f", str(path)],
                       capture_output=True, text=True)
    if "Operation not permitted" in r.stderr or "unshare failed" in r.stderr:
        pytest.skip("user namespaces unavailable here")
    assert r.returncode == 0, r.stderr
