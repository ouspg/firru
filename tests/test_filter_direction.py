"""
Which half of a policy a filter enforces, across the two spellings aerleon uses.

This is not cosmetic. `is_ingress` in flow_verdict tested `"input" in value`,
and aerleon's windows_advfirewall target says "in", not "input". No filter
matched, so every Windows host loaded ZERO policy terms, and every ingress
flow to them scored deny with a null matched_term -- identical in the output
to a host that really denies all. On a mixed estate that was most of the
deny/admitted cell.

The mirror bug lived in policy.is_output_filter (`"output" in value`), which
read every windows *outbound* filter as inbound, and made `firru apply
--direction out` skip windows egress terms while reporting them as added.
"""

import pytest

from firru.policy import (DIR_IN, DIR_OUT, filter_direction, filter_directions,
                          is_input_filter, is_output_filter, is_transit_filter,
                          iter_accept_terms, target_names)


def filt(**targets):
    return {"header": {"targets": targets}, "terms": []}


NFT_IN = filt(nftables="mixed input DROP")
NFT_OUT = filt(nftables="mixed output")
WIN_IN = filt(windows_advfirewall="in")
WIN_OUT = filt(windows_advfirewall="out")


class TestBothSpellings:
    @pytest.mark.parametrize("f", [NFT_IN, WIN_IN])
    def test_inbound_filters_are_inbound(self, f):
        assert is_input_filter(f) and not is_output_filter(f)
        assert filter_direction(f) == DIR_IN

    @pytest.mark.parametrize("f", [NFT_OUT, WIN_OUT])
    def test_outbound_filters_are_outbound(self, f):
        assert is_output_filter(f) and not is_input_filter(f)
        assert filter_direction(f) == DIR_OUT

    def test_the_windows_pair_is_not_both_the_same_side(self):
        """The regression itself: `in` and `out` must not read alike."""
        assert filter_direction(WIN_IN) != filter_direction(WIN_OUT)


class TestWholeWordsOnly:
    """`out` is a substring of too much to match loosely."""

    def test_an_unrelated_option_containing_out_is_not_egress(self):
        assert not is_output_filter(filt(nftables="mixed input timeout"))
        assert not is_output_filter(filt(nftables="routed input"))

    def test_an_unrelated_option_containing_in_is_not_ingress(self):
        assert not is_input_filter(filt(nftables="mixed output inet"))

    def test_a_comma_separated_option_list_still_splits(self):
        assert is_output_filter(filt(some_target="mixed,output"))


class TestNeitherDirection:
    def test_a_filter_naming_no_direction_is_neither(self):
        f = filt(cisco="extended")
        assert not is_input_filter(f) and not is_output_filter(f)

    def test_missing_header_does_not_raise(self):
        assert not is_input_filter({}) and not is_output_filter({})
        assert not is_input_filter({"header": {}})


class TestFlowVerdictAgrees:
    """flow_verdict's own gate is the one that dropped the windows policies."""

    def test_it_delegates_to_the_shared_test(self):
        from firru.cli.flow_verdict import is_ingress
        assert is_ingress(WIN_IN) and is_ingress(NFT_IN)
        assert not is_ingress(WIN_OUT) and not is_ingress(NFT_OUT)

    def test_a_windows_policy_now_contributes_its_terms(self):
        from firru.cli.flow_verdict import build_matcher
        doc = {"metadata": {"host": "h", "zone": "Z"},
               "filters": [{"header": {"targets": {"windows_advfirewall": "in"}},
                            "terms": [{"name": "allow-tcp-RDP", "protocol": "tcp",
                                       "destination-port": "RDP", "action": "accept"}]},
                           {"header": {"targets": {"windows_advfirewall": "out"}},
                            "terms": [{"name": "allow-ANY", "action": "accept"}]}]}
        _, _, host_terms = build_matcher([doc], {})
        assert [t["name"] for t in host_terms["h"]] == ["allow-tcp-RDP"]


class TestOtherGenerators:
    """Every aerleon generator that states a direction in the header, so a
    ruleset other than nftables/advfirewall is read rather than guessed at."""

    @pytest.mark.parametrize("target,opts", [
        ("iptables", "INPUT ACCEPT"),
        ("speedway", "INPUT ACCEPT"),
        ("ipset", "INPUT ACCEPT"),
        ("packetfilter", "pf-in inet in"),
        ("juniper", "edge-filter inet ingress"),
        ("gce", "INGRESS global/networks/default"),
        ("k8s", "INGRESS"),
        ("proxmox", "host IN"),
    ])
    def test_inbound_spellings(self, target, opts):
        assert filter_directions(filt(**{target: opts})) == {DIR_IN}

    @pytest.mark.parametrize("target,opts", [
        ("iptables", "OUTPUT DROP"),
        ("packetfilter", "pf-out inet out"),
        ("juniper", "edge-filter inet egress"),
        ("gce", "EGRESS global/networks/default"),
        ("proxmox", "host OUT"),
    ])
    def test_outbound_spellings(self, target, opts):
        assert filter_directions(filt(**{target: opts})) == {DIR_OUT}


class TestBidirectional:
    """pf without `in`/`out` emits `pass quick ...`, which matches both ways."""

    PF_BOTH = filt(packetfilter="pf-both inet")

    def test_it_is_both_halves_not_neither(self):
        assert filter_directions(self.PF_BOTH) == {DIR_IN, DIR_OUT}
        assert is_input_filter(self.PF_BOTH) and is_output_filter(self.PF_BOTH)

    def test_it_has_no_single_direction(self):
        assert filter_direction(self.PF_BOTH) is None

    def test_its_terms_land_on_both_sides(self):
        doc = {"filters": [{"header": {"targets": {"packetfilter": "pf-both inet"}},
                            "terms": [{"name": "t", "action": "accept"}]}]}
        assert [d for d, _ in iter_accept_terms(doc)] == [DIR_IN, DIR_OUT]
        assert [d for d, _ in iter_accept_terms(doc, DIR_OUT)] == [DIR_OUT]

    def test_an_explicit_direction_still_wins(self):
        """Only the *absence* of in/out makes a pf filter bidirectional."""
        assert filter_directions(filt(packetfilter="pf-in inet in")) == {DIR_IN}


class TestUnstatedDirection:
    """Generators that bind direction outside the policy file. The document
    cannot say which half, so firru must not pick one."""

    @pytest.mark.parametrize("target,opts", [
        ("paloaltofw", "from-zone trust to-zone untrust"),
        ("junipersrx", "from-zone all to-zone all"),
        ("fortigate", "from-id 1 to-id 2"),
        ("cisco", "acl-name extended"),
        ("ciscoasa", "outside"),
        ("arista_tp", "edge-filter inet"),
        ("aruba", "acl-name"),
        ("openconfig", "acl-name inet"),
        ("sonic", "acl-name inet"),
        ("nokiasrl", "acl-name inet"),
        ("windows_ipsec", "my-policy"),
    ])
    def test_neither_half(self, target, opts):
        f = filt(**{target: opts})
        assert filter_directions(f) == frozenset()
        assert not is_input_filter(f) and not is_output_filter(f)

    def test_no_side_is_invented_for_them(self):
        """The regression this file exists for, in its general form: an
        unreadable filter must not default to ingress."""
        assert filter_direction(filt(cisco="acl-name extended")) is None

    def test_their_terms_enter_no_surface(self):
        doc = {"filters": [{"header": {"targets": {"cisco": "acl-name extended"}},
                            "terms": [{"name": "t", "action": "accept"}]}]}
        assert list(iter_accept_terms(doc)) == []

    def test_flow_verdict_does_not_read_them_as_ingress(self):
        from firru.cli.flow_verdict import build_matcher
        doc = {"metadata": {"host": "h"},
               "filters": [{"header": {"targets": {"paloaltofw": "from-zone a to-zone b"}},
                            "terms": [{"name": "allow-tcp-SSH", "action": "accept"}]}]}
        _, _, host_terms = build_matcher([doc], {})
        assert host_terms["h"] == []

    def test_the_generator_is_named_for_the_report(self):
        assert target_names(filt(paloaltofw="from-zone a to-zone b")) == ["paloaltofw"]


class TestTransit:
    """FORWARD is a direction, but not one of this host's own halves."""

    @pytest.mark.parametrize("f", [filt(iptables="FORWARD DROP"),
                                   filt(proxmox="host FORWARD")])
    def test_forward_is_neither_half(self, f):
        assert filter_directions(f) == frozenset()

    @pytest.mark.parametrize("f", [filt(iptables="FORWARD DROP"),
                                   filt(proxmox="host FORWARD")])
    def test_forward_is_distinguishable_from_unreadable(self, f):
        """A forward filter is understood, not unread: it should not appear in
        the "could not read this generator" report."""
        assert is_transit_filter(f)
        assert not is_transit_filter(filt(cisco="acl-name extended"))

    def test_a_forward_filter_is_not_reported_as_unread(self, capsys):
        from firru.cli.flow_verdict import build_matcher
        doc = {"metadata": {"host": "h"},
               "filters": [{"header": {"targets": {"iptables": "FORWARD DROP"}},
                            "terms": []}]}
        build_matcher([doc], {})
        assert "state no direction" not in capsys.readouterr().err


class TestUnreadableFiltersAnnounceThemselves:
    """Silence is what let the windows bug reach print: a host with no readable
    ingress filter scores every inbound flow as deny/no-term, which is exactly
    what a deny-all host looks like."""

    def test_build_matcher_warns_and_names_the_host(self, capsys):
        from firru.cli.flow_verdict import build_matcher
        doc = {"metadata": {"host": "mac1"},
               "filters": [{"header": {"targets": {"ciscoasa": "outside"}},
                            "terms": [{"name": "t", "action": "accept"}]}]}
        build_matcher([doc], {})
        err = capsys.readouterr().err
        assert "state no direction" in err and "mac1" in err and "ciscoasa" in err

    def test_a_readable_policy_is_quiet(self, capsys):
        from firru.cli.flow_verdict import build_matcher
        doc = {"metadata": {"host": "h"},
               "filters": [{"header": {"targets": {"windows_advfirewall": "in"}},
                            "terms": []}]}
        build_matcher([doc], {})
        assert capsys.readouterr().err == ""
