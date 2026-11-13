"""
Identity resolution: by name, by address, by assertion, or not at all.

The ordering is the whole point. A collector's short label is ambiguous on a
real network -- `ns1` names a different host in each of three zones -- so a
name match must not be allowed to pick one, while the host's own address picks
exactly one or nothing. What neither settles is a human decision, and it has to
stay visibly a human decision: `via` is what keeps "we decided this" from
reading as "the data said this" a year later.
"""

import json

from firru.cli.resolve_identity import address_index, resolve


NETWORKS = {
    "ns1_edge": {"values": [{"address": "198.51.100.2"}]},
    "ns1_dmz": {"values": [{"address": "198.51.100.3"}]},
    "web_dmz": {"values": [{"address": "10.0.0.7"}]},
    "shared":     {"values": [{"address": "10.0.0.7"}]},   # two owners
    "a_group":    {"values": [{"name": "web_dmz"}]},    # not an address
}


def test_address_index_maps_only_unshared_addresses():
    idx = address_index(NETWORKS)
    assert idx["198.51.100.2"] == "ns1_edge"
    # 10.0.0.7 belongs to two tokens, so it identifies neither.
    assert "10.0.0.7" not in idx


def loot(tmp_path, name, **meta):
    d = tmp_path / f"{name}.json"
    d.write_text(json.dumps({"metadata": {"hostname": name, **meta},
                             "listen_ports": []}))
    return tmp_path


def test_a_name_already_in_the_inventory_wins(tmp_path):
    loot(tmp_path, "web_dmz", ip="203.0.113.9")
    got = resolve(tmp_path, {"web_dmz": {}}, address_index(NETWORKS), {})
    assert got["web_dmz"] == ("web_dmz", "name", "web_dmz")


def test_an_ambiguous_label_resolves_by_address(tmp_path):
    """`ns1` names three hosts; 198.51.100.2 names one."""
    loot(tmp_path, "ns1", ip="198.51.100.2")
    got = resolve(tmp_path, {}, address_index(NETWORKS), {})
    assert got["ns1"] == ("ns1_edge", "address", "198.51.100.2")


def test_an_address_the_inventory_does_not_know_resolves_nothing(tmp_path):
    loot(tmp_path, "stranger", ip="198.51.100.4", agent_id="42")
    got = resolve(tmp_path, {}, address_index(NETWORKS), {})
    token, via, _ = got["stranger"]
    assert token is None and via == "unresolved"


def test_an_assertion_covers_what_no_evidence_decides(tmp_path):
    loot(tmp_path, "siem-server", agent_id="000", ip=None)
    asserted = {"siem-server": {"zone": "core", "why": "Wazuh manager, id 000"}}
    token, via, evidence = resolve(tmp_path, {}, address_index(NETWORKS),
                                   asserted)["siem-server"]
    assert (token, via) == ("siem-server", "asserted")
    assert "Wazuh manager" in evidence


def test_an_assertion_does_not_override_real_evidence(tmp_path):
    """A human note must not quietly rewrite what the address proves."""
    loot(tmp_path, "ns1", ip="198.51.100.2")
    asserted = {"ns1": {"token": "ns1_dmz", "why": "I think it is dmz"}}
    token, via, _ = resolve(tmp_path, {}, address_index(NETWORKS),
                            asserted)["ns1"]
    assert (token, via) == ("ns1_edge", "address")


def test_a_host_with_no_address_at_all_is_unresolved_not_guessed(tmp_path):
    loot(tmp_path, "ns1")
    token, via, _ = resolve(tmp_path, {}, address_index(NETWORKS), {})["ns1"]
    assert token is None and via == "unresolved"
