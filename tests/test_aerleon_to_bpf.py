"""aerleon-to-bpf against current policy shapes. The tool emits violation
detectors from the ingress side; these pin what it produces for a merged
ingress+egress policy, including the fact that egress terms emit nothing (a
documented gap, not an accident — see test names)."""

import textwrap

import pytest
from aerleon.lib import naming

from firru.cli.aerleon_to_bpf import generate_filters, get_host_ips


@pytest.fixture
def defs(tmp_path):
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH:
            - {port: 22, protocol: tcp}
          HTTPS:
            - {port: 443, protocol: tcp}
    """))
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          H1:
            values:
              - address: 10.1.0.5/32
          NET_MGMT:
            values:
              - address: 10.9.0.0/16
          DNS_CDN:
            values:
              - address: 142.250.0.1/32
          HD:
            values:
              - address: 10.1.0.7/32
              - address: 2001:db8::7/128
          H6:
            values:
              - address: 2001:db8::9/128
          MGMT_DUAL:
            values:
              - address: 10.9.0.0/16
              - address: 2001:db8:9::/48
    """))
    return naming.Naming(str(d))


def _policy(in_terms, out_terms=()):
    filters = [{"header": {"targets": {"nftables": "mixed input DROP"}},
                "terms": list(in_terms)}]
    if out_terms:
        filters.append({"header": {"targets": {"nftables": "mixed output"}},
                        "terms": list(out_terms)})
    return {"metadata": {"host": "H1"}, "filters": filters}


SSH_RESTRICTED = {"name": "allow-tcp-SSH", "protocol": "tcp",
                  "destination-port": "SSH", "source-address": "NET_MGMT",
                  "action": "accept"}
EG_GROUP = {"name": "allow-egress-https-dns", "protocol": "tcp",
            "destination-port": "HTTPS", "destination-address": "DNS_CDN",
            "action": "accept"}


class TestIngressDetectors:
    def _run(self, defs, pol):
        return generate_filters(pol, defs, get_host_ips("H1", defs))

    def test_a_restricted_term_yields_syn_and_synack_detectors(self, defs):
        results = self._run(defs, _policy([SSH_RESTRICTED]))
        ssh = [r for r in results if "allow-tcp-SSH" in r["name"]]
        bpf = " ".join(r["bpf"] for r in ssh)
        assert "tcp dst port 22" in bpf and "0x12 == 0x02" in bpf   # SYN inbound
        assert "tcp src port 22" in bpf and "0x12 == 0x12" in bpf   # SYN-ACK out
        assert "not (src net 10.9.0.0/16)" in bpf

    def test_the_uncovered_catch_all_names_the_covered_ports(self, defs):
        results = self._run(defs, _policy([SSH_RESTRICTED]))
        assert "tcp=22" in results[-1]["comment"]
        assert "tcp dst port 22" in results[-1]["bpf"]

    def test_an_unrestricted_term_yields_no_source_detector(self, defs):
        results = self._run(defs, _policy(
            [{"name": "allow-tcp-HTTPS", "protocol": "tcp",
              "destination-port": "HTTPS", "action": "accept"}]))
        assert not any("allow-tcp-HTTPS" in r["name"] for r in results)
        # but the port counts as covered for the catch-all
        assert "443" in results[-1]["comment"]

    def test_egress_terms_emit_nothing_today(self, defs):
        # Pinned as a fact, not blessed as correct: the output filter is
        # skipped wholesale, so the egress group rules get no violation
        # detector (an outbound-443-to-not-DNS_CDN catch). When egress
        # detectors land, this test should flip.
        with_eg = self._run(defs, _policy([SSH_RESTRICTED], [EG_GROUP]))
        without = self._run(defs, _policy([SSH_RESTRICTED]))
        assert [r["name"] for r in with_eg] == [r["name"] for r in without]

    def test_a_merged_policy_still_yields_ingress_detectors(self, defs):
        results = self._run(defs, _policy([SSH_RESTRICTED], [EG_GROUP]))
        assert any("allow-tcp-SSH" in r["name"] for r in results)


def _pol_for(host, src):
    return {"metadata": {"host": host},
            "filters": [{"header": {"targets": {"nftables": "mixed input DROP"}},
                         "terms": [{"name": "allow-tcp-SSH", "protocol": "tcp",
                                    "destination-port": "SSH",
                                    "source-address": src, "action": "accept"}]}]}


class TestAddressFamilies:
    """libpcap's tcp[13] indexes the TCP header for IPv4 only: with IPv6 hosts
    alongside it, the expression parses and then never matches them. Every
    flags-based detector is built per family — tcp[13] for v4, ip6[53] for v6."""

    def _bpf(self, defs, host, src):
        results = generate_filters(_pol_for(host, src), defs, get_host_ips(host, defs))
        return "\n".join(r["bpf"] for r in results)

    def test_a_v4_only_host_emits_no_ip6_arm(self, defs):
        bpf = self._bpf(defs, "H1", "NET_MGMT")
        assert "tcp[13]" in bpf and "ip6[53]" not in bpf

    def test_a_v6_only_host_uses_ip6_flags(self, defs):
        bpf = self._bpf(defs, "H6", "MGMT_DUAL")
        assert "ip6[53]" in bpf and "tcp[13]" not in bpf

    def test_a_dual_stack_host_gets_one_arm_per_family(self, defs):
        bpf = self._bpf(defs, "HD", "MGMT_DUAL")
        assert "tcp[13]" in bpf and "ip6[53]" in bpf

    def test_each_arm_keeps_to_its_own_family(self, defs):
        from firru.cli.aerleon_to_bpf import bpf_tcp_synack
        expr = bpf_tcp_synack(["10.1.0.7", "2001:db8::7"], 22,
                              ["10.9.0.0/16", "2001:db8:9::/48"])
        v4_arm, v6_arm = expr[1:-1].split(" or ", 1)
        assert "2001" not in v4_arm and "tcp[13]" in v4_arm
        assert "10.9" not in v6_arm and "ip6[53]" in v6_arm

    def test_v4_only_sources_make_any_v6_hit_a_violation(self, defs):
        # The paper's IPv6 gap as a detector: a rule admitting only v4 sources
        # admits nobody on v6, so the v6 arm carries no exclusion at all.
        from firru.cli.aerleon_to_bpf import bpf_tcp_synack
        expr = bpf_tcp_synack(["10.1.0.7", "2001:db8::7"], 22, ["10.9.0.0/16"])
        v4_arm, v6_arm = expr[1:-1].split(" or ", 1)
        assert "not (" in v4_arm
        assert "not (" not in v6_arm

    def test_the_uncovered_catch_all_splits_tcp_but_not_udp(self, defs):
        from firru.cli.aerleon_to_bpf import bpf_uncovered
        expr = bpf_uncovered(["10.1.0.7", "2001:db8::7"], [22], [])
        assert "ip6[53]" in expr and "tcp[13]" in expr
        # the UDP arm has no flags byte, so it stays one family-neutral arm
        udp_arms = [a for a in expr.split(" or\n    ") if " udp" in a]
        assert len(udp_arms) == 1
        assert "10.1.0.7" in udp_arms[0] and "2001:db8::7" in udp_arms[0]


import shutil
import subprocess


@pytest.mark.skipif(shutil.which("tcpdump") is None, reason="tcpdump not available")
class TestBpfCompiles:
    """The strongest check: libpcap itself accepts every emitted expression.
    tcpdump -d -y EN10MB compiles offline, no interface, no privileges."""

    def _compiles(self, expr):
        return subprocess.run(["tcpdump", "-d", "-y", "EN10MB", expr],
                              capture_output=True).returncode == 0

    def test_every_generated_expression_compiles(self, defs):
        for host, src in (("H1", "NET_MGMT"), ("H6", "MGMT_DUAL"),
                          ("HD", "MGMT_DUAL"), ("HD", "NET_MGMT")):
            results = generate_filters(_pol_for(host, src), defs,
                                       get_host_ips(host, defs))
            for r in results:
                flat = " ".join(r["bpf"].split())
                assert self._compiles(flat), f"{host}/{src}: {r['name']}: {flat[:120]}"

    def test_the_v6_flags_offset_is_what_libpcap_loads(self):
        # ip6[53] must become a load of packet byte 67 (14 ether + 53) guarded
        # by ethertype 0x86dd — pinning the offset arithmetic itself.
        out = subprocess.run(
            ["tcpdump", "-d", "-y", "EN10MB", "ip6[53] & 0x12 == 0x12"],
            capture_output=True, text=True).stdout
        assert "#0x86dd" in out and "[67]" in out


class TestPortRuns:
    """Per-term detectors are emitted per port *run*, not per port: a DC term
    spanning 49152-65535 is one portrange expression each way, not 32,768
    filters."""

    def _dc_defs(self, tmp_path):
        import textwrap
        from aerleon.lib import naming
        d = tmp_path / "def"
        d.mkdir()
        (d / "services.yml").write_text(textwrap.dedent("""\
            services:
              WINDOWS-DC-BASE:
                - {port: 88, protocol: tcp}
                - {port: 135, protocol: tcp}
                - {port: 49152-65535, protocol: tcp}
        """))
        (d / "networks.yml").write_text(textwrap.dedent("""\
            networks:
              DC1:
                values:
                  - address: 10.1.0.10/32
              NET_MGMT:
                values:
                  - address: 10.9.0.0/16
        """))
        return naming.Naming(str(d))

    def _dc_pol(self):
        return {"metadata": {"host": "DC1"},
                "filters": [{"header": {"targets": {"nftables": "mixed input DROP"}},
                             "terms": [{"name": "allow-tcp-dc", "protocol": "tcp",
                                        "destination-port": "WINDOWS-DC-BASE",
                                        "source-address": "NET_MGMT",
                                        "action": "accept"}]}]}

    def test_a_dc_range_is_a_handful_of_detectors(self, tmp_path):
        defs = self._dc_defs(tmp_path)
        results = generate_filters(self._dc_pol(), defs, get_host_ips("DC1", defs))
        # 3 runs (88, 135, 49152-65535) × 2 layers + catch-all
        assert len(results) == 7

    def test_the_range_renders_as_portrange(self, tmp_path):
        defs = self._dc_defs(tmp_path)
        results = generate_filters(self._dc_pol(), defs, get_host_ips("DC1", defs))
        bpf = "\n".join(r["bpf"] for r in results)
        ark = "\n".join(r["arkime"] for r in results)
        assert "tcp dst portrange 49152-65535" in bpf
        assert "(destination.port >= 49152 && destination.port <= 65535)" in ark

    def test_a_single_port_still_renders_as_port(self, defs):
        results = generate_filters(_pol_for("H1", "NET_MGMT"),
                                   defs, get_host_ips("H1", defs))
        assert any("tcp dst port 22" in r["bpf"] for r in results)
        assert "portrange" not in " ".join(r["bpf"] for r in results
                                           if r["name"] == "allow-tcp-SSH")

    @pytest.mark.skipif(shutil.which("tcpdump") is None, reason="tcpdump not available")
    def test_the_portrange_expression_compiles(self, tmp_path):
        defs = self._dc_defs(tmp_path)
        for r in generate_filters(self._dc_pol(), defs, get_host_ips("DC1", defs)):
            flat = " ".join(r["bpf"].split())
            assert subprocess.run(["tcpdump", "-d", "-y", "EN10MB", flat],
                                  capture_output=True).returncode == 0, flat[:120]
