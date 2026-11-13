"""
Flow ingestion and source selection for `firru tighten`.

These are the functions that decide what a term's sources become. A wrong
bucket or a wrong token does not crash: it produces a plausible-looking policy
that is quietly too tight or too loose, which is the failure mode worth tests.
"""

import json
from collections import Counter, defaultdict

import pytest

from firru.cli.tighten import (
    _bucket_flow,
    _is_any_source,
    _is_broadcast_or_multicast,
    best_tokens,
    collect_flows_from_file,
    get_host_ips,
    ip_matches_source,
)


class StubDefs:
    """Ports 22->SSH, 443->HTTPS; everything else unknown."""

    PORTS = {(22, "tcp"): ["SSH"], (443, "tcp"): ["HTTPS"], (53, "udp"): ["DNS"]}

    def GetPortParents(self, port, proto):
        return self.PORTS.get((port, proto), [])

    def GetNetAddr(self, token):
        raise Exception(f"undefined: {token}")


class BoomDefs(StubDefs):
    def GetPortParents(self, port, proto):
        raise RuntimeError("definitions unavailable")


def buckets():
    return (defaultdict(Counter), defaultdict(Counter),
            defaultdict(Counter), defaultdict(Counter))


def flow(src="10.0.0.9", dst="10.0.0.1", proto="tcp", dst_port=22):
    return {"protocol": proto, "src_ip": src, "dst_ip": dst, "dst_port": dst_port}


HOST = {"10.0.0.1"}


class TestDirection:
    def test_traffic_to_the_host_is_ingress(self):
        ing, egr, ip_, ep_ = buckets()
        _bucket_flow(flow(), HOST, StubDefs(), ing, egr, ip_, ep_)
        assert ing[("tcp", "SSH")]["10.0.0.9"] == 1
        assert egr == {}

    def test_traffic_from_the_host_is_egress(self):
        ing, egr, ip_, ep_ = buckets()
        _bucket_flow(flow(src="10.0.0.1", dst="10.0.0.9"), HOST, StubDefs(), ing, egr, ip_, ep_)
        assert egr[("tcp", "SSH")]["10.0.0.9"] == 1
        assert ing == {}

    def test_ingress_wins_when_the_host_is_both_ends(self):
        # Host talking to itself must not be counted twice, and the ingress
        # reading is the one that can widen a rule.
        ing, egr, ip_, ep_ = buckets()
        _bucket_flow(flow(src="10.0.0.1", dst="10.0.0.1"), HOST, StubDefs(), ing, egr, ip_, ep_)
        assert sum(sum(c.values()) for c in ing.values()) == 1
        assert egr == {}

    def test_a_flow_touching_neither_end_is_dropped(self):
        ing, egr, ip_, ep_ = buckets()
        _bucket_flow(flow(src="10.9.9.9", dst="10.9.9.8"), HOST, StubDefs(), ing, egr, ip_, ep_)
        assert ing == {} and egr == {}


class TestServiceBucketing:
    def test_a_known_port_buckets_under_its_token(self):
        ing, egr, ip_, ep_ = buckets()
        _bucket_flow(flow(dst_port=443), HOST, StubDefs(), ing, egr, ip_, ep_)
        assert ("tcp", "HTTPS") in ing

    def test_an_unknown_port_gets_its_own_bucket(self):
        ing, egr, ip_, ep_ = buckets()
        _bucket_flow(flow(dst_port=9191), HOST, StubDefs(), ing, egr, ip_, ep_)
        assert ("tcp", "unknown-tcp-9191") in ing

    def test_definitions_blowing_up_does_not_lose_the_flow(self):
        ing, egr, ip_, ep_ = buckets()
        _bucket_flow(flow(dst_port=9191), HOST, BoomDefs(), ing, egr, ip_, ep_)
        assert ing[("tcp", "unknown-tcp-9191")]["10.0.0.9"] == 1

    def test_icmp_buckets_by_protocol(self):
        ing, egr, ip_, ep_ = buckets()
        _bucket_flow(flow(proto="icmp", dst_port=None), HOST, StubDefs(), ing, egr, ip_, ep_)
        assert ("icmp", "ICMP") in ing

    def test_ports_are_tracked_per_service(self):
        ing, egr, ip_, ep_ = buckets()
        _bucket_flow(flow(dst_port=22), HOST, StubDefs(), ing, egr, ip_, ep_)
        assert ip_[("tcp", "SSH")][22] == 1

    def test_a_portless_flow_records_no_port(self):
        ing, egr, ip_, ep_ = buckets()
        _bucket_flow(flow(proto="icmp", dst_port=None), HOST, StubDefs(), ing, egr, ip_, ep_)
        assert ip_ == {}


class TestNoiseFiltering:
    @pytest.mark.parametrize("ip", ["224.0.0.251", "239.1.1.1", "255.255.255.255", "ff02::1"])
    def test_multicast_and_broadcast_are_recognised(self, ip):
        assert _is_broadcast_or_multicast(ip)

    @pytest.mark.parametrize("ip", ["10.0.0.1", "2001:db8::1", "not-an-ip"])
    def test_ordinary_addresses_are_not(self, ip):
        assert not _is_broadcast_or_multicast(ip)

    def test_multicast_flows_never_become_sources(self):
        # An mDNS burst must not end up as a permitted source in a policy.
        ing, egr, ip_, ep_ = buckets()
        _bucket_flow(flow(src="224.0.0.251", dst_port=53, proto="udp"),
                     HOST, StubDefs(), ing, egr, ip_, ep_)
        assert ing == {} and egr == {}


class TestCollectFromFile:
    def _write(self, tmp_path, flows):
        p = tmp_path / "flows.jsonl"
        p.write_text("".join(json.dumps(f) + "\n" for f in flows))
        return str(p)

    def test_only_flows_touching_the_host_are_kept(self, tmp_path):
        f = self._write(tmp_path, [flow(), flow(src="10.9.9.9", dst="10.9.9.8")])
        ing, egr, _, _ = collect_flows_from_file(f, ["10.0.0.1"], StubDefs())
        assert ing[("tcp", "SSH")] == Counter({"10.0.0.9": 1})
        assert egr == {}

    def test_counts_accumulate_across_lines(self, tmp_path):
        f = self._write(tmp_path, [flow(), flow(), flow(src="10.0.0.8")])
        ing, _, _, _ = collect_flows_from_file(f, ["10.0.0.1"], StubDefs())
        assert ing[("tcp", "SSH")] == Counter({"10.0.0.9": 2, "10.0.0.8": 1})

    def test_blank_and_corrupt_lines_are_skipped(self, tmp_path):
        p = tmp_path / "flows.jsonl"
        p.write_text(json.dumps(flow()) + "\n\nnot json\n" + json.dumps(flow()) + "\n")
        ing, _, _, _ = collect_flows_from_file(str(p), ["10.0.0.1"], StubDefs())
        assert ing[("tcp", "SSH")]["10.0.0.9"] == 2

    def test_ipv6_host_addresses_work(self, tmp_path):
        f = self._write(tmp_path, [flow(src="2001:db8::9", dst="2001:db8::1")])
        ing, _, _, _ = collect_flows_from_file(f, ["2001:db8::1"], StubDefs())
        assert ing[("tcp", "SSH")]["2001:db8::9"] == 1

    def test_an_empty_file_yields_empty_buckets(self, tmp_path):
        f = self._write(tmp_path, [])
        ing, egr, ip_, ep_ = collect_flows_from_file(f, ["10.0.0.1"], StubDefs())
        assert (ing, egr, ip_, ep_) == ({}, {}, {}, {})


class TestGetHostIps:
    def test_an_unresolvable_token_yields_nothing_rather_than_raising(self):
        assert get_host_ips("NO_SUCH_HOST", StubDefs()) == []


class TestAnySource:
    @pytest.mark.parametrize("src", [None, "", "ANY", "ANY_V4", "ANY_V6",
                                     ["NET_APP", "ANY_V6"]])
    def test_unrestricted_forms(self, src):
        assert _is_any_source(src)

    @pytest.mark.parametrize("src", ["NET_APP", ["NET_APP", "NET_MGMT"]])
    def test_restricted_forms(self, src):
        assert not _is_any_source(src)


class StubAnnotator:
    """annotate_ip returns whatever the test set up for that address."""

    def __init__(self, mapping):
        self.mapping = mapping

    def annotate_ip(self, ip):
        return self.mapping.get(ip, {"type": "EXTERNAL", "host": "EXTERNAL"})


class TestIpMatchesSource:
    def test_no_restriction_matches_everything(self):
        assert ip_matches_source("10.0.0.9", None, StubAnnotator({}))

    def test_any_matches_everything(self):
        assert ip_matches_source("10.0.0.9", "ANY", StubAnnotator({}))

    def test_exact_host_token(self):
        ann = StubAnnotator({"10.0.0.9": {"type": "HOST", "host": "h1", "parents": []}})
        assert ip_matches_source("10.0.0.9", "h1", ann)

    def test_match_through_a_parent_group(self):
        ann = StubAnnotator({"10.0.0.9": {"type": "HOST", "host": "h1",
                                          "parents": ["NET_APP"]}})
        assert ip_matches_source("10.0.0.9", "NET_APP", ann)

    def test_an_unrelated_token_does_not_match(self):
        ann = StubAnnotator({"10.0.0.9": {"type": "HOST", "host": "h1",
                                          "parents": ["NET_APP"]}})
        assert not ip_matches_source("10.0.0.9", "NET_MGMT", ann)


def host(name, parents=()):
    return {"type": "HOST", "host": name, "parents": list(parents)}


class TestBestTokens:
    def test_no_relevant_annotations_means_no_tightening(self):
        assert best_tokens([]) == (None, None, None)

    def test_a_single_host_becomes_its_own_token(self):
        toks, suggest, note = best_tokens([host("h1")])
        assert toks == ["h1"] and suggest is None

    def test_an_external_source_blocks_tightening_entirely(self):
        # One address off the estate and the rule has to stay ANY, however many
        # internal sources sit beside it. This is the rule that produced the
        # most widenings on real estates, so it gets a test of its own.
        toks, suggest, note = best_tokens([host("h1"), {"type": "EXTERNAL"}])
        assert toks is None and suggest is None and note is None

    def test_duplicate_hosts_collapse(self):
        toks, _, _ = best_tokens([host("h1"), host("h1")])
        assert toks == ["h1"]

    def test_a_few_hosts_are_listed_individually_without_groups(self):
        toks, suggest, _ = best_tokens([host("h1"), host("h2")])
        assert sorted(toks) == ["h1", "h2"] and suggest is None

    def test_a_group_covering_exactly_the_observed_hosts_is_used(self):
        anns = [host("h1", ["NET_APP"]), host("h2", ["NET_APP"])]
        members = {"NET_APP": frozenset({"h1", "h2"})}
        toks, suggest, note = best_tokens(anns, members)
        assert toks == ["NET_APP"]
        assert note is None  # nothing extra permitted

    def test_a_group_permitting_more_than_it_covers_is_vetoed(self):
        # NET_APP would admit three unobserved hosts to cover two observed
        # ones. Listing the two is tighter, so the group must lose.
        anns = [host("h1", ["NET_APP"]), host("h2", ["NET_APP"])]
        members = {"NET_APP": frozenset({"h1", "h2", "x1", "x2", "x3"})}
        toks, suggest, note = best_tokens(anns, members)
        assert sorted(toks) == ["h1", "h2"]

    def test_using_a_looser_group_is_recorded_as_excess(self):
        anns = [host("h1", ["NET_APP"]), host("h2", ["NET_APP"])]
        members = {"NET_APP": frozenset({"h1", "h2", "x1"})}
        toks, suggest, note = best_tokens(anns, members)
        assert toks == ["NET_APP"]
        assert note and "x1" in note
        assert suggest == ["h1", "h2"]   # the tighter set, for groups.yml

    def test_too_many_individual_hosts_suggests_a_group_instead(self):
        anns = [host(f"h{i}") for i in range(20)]
        toks, suggest, _ = best_tokens(anns)
        assert toks is None
        assert suggest and len(suggest) == 20


def test_a_windows_egress_filter_is_egress(tmp_path):
    """`out` is Windows' word for what nftables calls `output`. Read as ingress,
    the egress allow-ANY became an ingress catch-all and hid every
    would-be-blocked flow, and the egress side was never tightened."""
    import json, textwrap, subprocess, sys
    d = tmp_path / "def"; d.mkdir()
    (d / "services.yml").write_text("services:\n  SSH:\n    - {port: 22, protocol: tcp}\n")
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          h1:
            values:
              - address: 10.0.0.5/32
    """))
    pol = tmp_path / "h1.yml"
    pol.write_text(textwrap.dedent("""\
        filters:
          - header:
              targets:
                windows_advfirewall: in mixed block
            terms:
              - name: allow-tcp-SSH
                protocol: tcp
                destination-port: SSH
                action: accept
              - name: drop-ANY
                action: deny
          - header:
              targets:
                windows_advfirewall: out mixed
            terms:
              - name: allow-ANY
                action: accept
        metadata:
          host: h1
    """))
    flows = tmp_path / "f.jsonl"
    flows.write_text("\n".join(json.dumps(f) for f in [
        {"protocol": "tcp", "src_ip": "10.0.0.9", "dst_ip": "10.0.0.5", "src_port": 40000,
         "dst_port": 22, "responded": True},
        {"protocol": "tcp", "src_ip": "10.0.0.9", "dst_ip": "10.0.0.5", "src_port": 40001,
         "dst_port": 134, "responded": True}]) + "\n")
    out = tmp_path / "out"
    r = subprocess.run([sys.executable, "-m", "firru.cli.tighten", "--policy", str(pol),
                        "--defs", str(d), "--flows-file", str(flows), "--outdir", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (out / "h1.blocked.yml").exists(), r.stderr
    assert "134" in (out / "h1.blocked.yml").read_text()
