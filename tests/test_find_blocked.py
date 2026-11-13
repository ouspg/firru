"""find_blocked is the would-be-blocked preview and the future promotion gate:
it answers "what did the network do that this policy would have denied". It had
no coverage; these tests pin the surface-based behavior, including the group-
token case string matching got wrong."""

import textwrap

import pytest
from aerleon.lib import naming

from firru.annotator import PolicyAnnotator
from firru.cli.tighten import find_blocked


@pytest.fixture
def defs_dir(tmp_path):
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH:
            - {port: 22, protocol: tcp}
          TCP_5000:
            - {port: 5000, protocol: tcp}
          APPGROUP:
            - {port: 5000, protocol: tcp}
            - {port: 8080, protocol: tcp}
    """))
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          NET_MGMT:
            values:
              - address: 10.9.0.0/16
    """))
    return str(d)


@pytest.fixture
def defs(defs_dir):
    return naming.Naming(defs_dir)


@pytest.fixture
def annotator(defs_dir):
    return PolicyAnnotator(defs_dir)


def _term(name, svc, src=None, proto="tcp", action="accept"):
    t = {"name": name, "protocol": proto, "destination-port": svc, "action": action}
    if src:
        t["source-address"] = src
    return t


def _flows(*items):
    """items: (proto, svc, ip, hits, port)"""
    flows, ports = {}, {}
    for proto, svc, ip, hits, port in items:
        flows.setdefault((proto, svc), {}).setdefault(ip, 0)
        flows[(proto, svc)][ip] += hits
        ports.setdefault((proto, svc), {}).setdefault(port, 0)
        ports[(proto, svc)][port] += hits
    # find_blocked uses .most_common(); give it Counters
    from collections import Counter
    return ({k: Counter(v) for k, v in flows.items()},
            {k: Counter(v) for k, v in ports.items()})


class TestCoverage:
    def test_an_uncovered_port_reports_every_source(self, defs, annotator):
        flows, ports = _flows(("tcp", "TCP_5000", "10.1.1.1", 3, 5000))
        blocked = find_blocked(flows, [_term("allow-tcp-SSH", "SSH")],
                               annotator, defs, ports)
        assert len(blocked) == 1
        assert blocked[0]["reason"].startswith("port not in policy")
        assert blocked[0]["hits"] == 3

    def test_a_group_token_covers_its_ports_under_any_bucket_name(self, defs, annotator):
        # The regression: flow bucketed as TCP_5000, term written as APPGROUP.
        # String matching said "port not in policy"; the surface says covered.
        flows, ports = _flows(("tcp", "TCP_5000", "10.1.1.1", 3, 5000))
        blocked = find_blocked(flows, [_term("allow-tcp-appgroup", "APPGROUP")],
                               annotator, defs, ports)
        assert blocked == []

    def test_a_source_outside_the_restriction_is_blocked(self, defs, annotator):
        flows, ports = _flows(("tcp", "SSH", "1.2.3.4", 5, 22),
                              ("tcp", "SSH", "10.9.1.1", 2, 22))
        blocked = find_blocked(flows, [_term("allow-tcp-SSH", "SSH", src="NET_MGMT")],
                               annotator, defs, ports)
        assert [b["src_ip"] for b in blocked] == ["1.2.3.4"]
        assert "NET_MGMT" in blocked[0]["reason"]

    def test_a_catch_all_accepts_everything(self, defs, annotator):
        flows, ports = _flows(("tcp", "TCP_5000", "1.2.3.4", 9, 5000))
        assert find_blocked(flows, [{"name": "allow-ANY", "action": "accept"}],
                            annotator, defs, ports) == []

    def test_a_blanket_protocol_term_covers_portless_flows(self, defs, annotator):
        from collections import Counter
        flows = {("icmp", "ICMP"): Counter({"10.1.1.1": 4})}
        assert find_blocked(flows, [{"name": "allow-icmp", "protocol": "icmp",
                                     "action": "accept"}],
                            annotator, defs, {}) == []

    def test_a_deny_term_grants_nothing(self, defs, annotator):
        flows, ports = _flows(("tcp", "SSH", "10.1.1.1", 1, 22))
        blocked = find_blocked(flows, [_term("deny-ssh", "SSH", action="deny")],
                               annotator, defs, ports)
        assert len(blocked) == 1

    def test_results_sort_by_hits(self, defs, annotator):
        flows, ports = _flows(("tcp", "TCP_5000", "10.1.1.1", 2, 5000),
                              ("tcp", "SSH", "1.2.3.4", 7, 22))
        blocked = find_blocked(flows, [], annotator, defs, ports)
        assert [b["hits"] for b in blocked] == [7, 2]
