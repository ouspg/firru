"""The interface mask, which loot-host.sh collects and firru used to discard.

An address without its prefix length is true about the address and silent about
the subnet it sits in, so it cannot answer the zone question downstream. These
pin that both `ip -j addr show` and the text form yield the same CIDRs, and that
loopback and link-local stay out.
"""

import json
import textwrap

from firru.cli.loot_listeners import _parse_ipaddr_file, parse_ipaddr_cidrs

TEXT = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    inet 192.0.2.18/24 brd 192.0.2.255 scope global eth0
    inet6 2001:db8:0:a2::18/64 scope global
    inet6 fe80::5054:ff:fe12:3456/64 scope link
"""

JSON_DOC = [
    {"ifname": "lo", "addr_info": [
        {"family": "inet", "local": "127.0.0.1", "prefixlen": 8},
        {"family": "inet6", "local": "::1", "prefixlen": 128}]},
    {"ifname": "eth0", "addr_info": [
        {"family": "inet", "local": "192.0.2.18", "prefixlen": 24},
        {"family": "inet6", "local": "2001:db8:0:a2::18", "prefixlen": 64},
        {"family": "inet6", "local": "fe80::5054:ff:fe12:3456", "prefixlen": 64}]},
]

EXPECTED = ["192.0.2.18/24", "2001:db8:0:a2::18/64"]


def test_text_form_keeps_the_prefix_length(tmp_path):
    p = tmp_path / "ipaddr"
    p.write_text(TEXT)
    assert parse_ipaddr_cidrs(str(p)) == EXPECTED


def test_json_form_keeps_the_prefix_length(tmp_path):
    p = tmp_path / "ipaddr.json"
    p.write_text(json.dumps(JSON_DOC))
    assert parse_ipaddr_cidrs(str(p)) == EXPECTED


def test_both_forms_agree(tmp_path):
    t = tmp_path / "ipaddr"
    t.write_text(TEXT)
    j = tmp_path / "ipaddr.json"
    j.write_text(json.dumps(JSON_DOC))
    assert parse_ipaddr_cidrs(str(t)) == parse_ipaddr_cidrs(str(j))


def test_loopback_and_link_local_stay_out(tmp_path):
    p = tmp_path / "ipaddr.json"
    p.write_text(json.dumps(JSON_DOC))
    got = parse_ipaddr_cidrs(str(p))
    assert not any(a.startswith(("127.", "fe80", "::1")) for a in got)


def test_the_old_parser_dropped_the_mask(tmp_path):
    """Pins what changed: the bare-IP helper is still there for netns naming."""
    p = tmp_path / "ipaddr"
    p.write_text(TEXT)
    assert _parse_ipaddr_file(str(p)) == ["192.0.2.18", "2001:db8:0:a2::18"]


def test_missing_file_is_empty_not_an_error(tmp_path):
    assert parse_ipaddr_cidrs(str(tmp_path / "nope")) == []


def test_malformed_json_falls_back_to_text(tmp_path):
    """A truncated ipaddr.json must not lose the addresses silently."""
    p = tmp_path / "ipaddr.json"
    p.write_text('[{"ifname": "eth0", "addr_info": [')
    assert parse_ipaddr_cidrs(str(p)) == []


def test_absurd_prefix_length_is_rejected(tmp_path):
    p = tmp_path / "ipaddr.json"
    p.write_text(json.dumps([{"ifname": "eth0", "addr_info": [
        {"family": "inet", "local": "10.0.0.1", "prefixlen": 99}]}]))
    assert parse_ipaddr_cidrs(str(p)) == []
