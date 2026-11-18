"""net-tools netstat writes `:::5500` for a dual-stack socket and an IPv6-only
one alike, so a lone IPv6 wildcard is read as both families, as on Windows.

The wrong guess the other way was seen on LSPR24: a java X-Road server,
recorded as IPv6-only, answered 2,143 IPv4 flows from its federation peers,
and the synthesized ANY_V6 term would have refused every one.
"""
import pathlib

from firru.cli.loot_listeners import process_host
from firru.cli.ossec_to_loot import dual_stack, flags_for
from firru.discovery import get_discovery_list

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "netstat_linux_tulnp.txt"
LONE_V6 = ("tcp6       0      0 :::5500                 :::*                    LISTEN"
           "      2001/java           \n")


def _binds(tmp_path, text):
    host = tmp_path / "hosts" / "xroad"
    host.mkdir(parents=True)
    (host / "netstat").write_text(text)
    (entry,) = get_discovery_list(str(tmp_path / "hosts"))
    _, listen_ports = process_host(entry)
    binds = {}
    for p in listen_ports:
        binds.setdefault((p["protocol"], p["port"]), set()).add(p["bind_address"])
    return binds


class TestNetTools:
    def test_a_lone_ipv6_wildcard_serves_both_families(self, tmp_path):
        binds = _binds(tmp_path, FIXTURE.read_text() + LONE_V6)
        assert binds[("tcp", 5500)] == {"0.0.0.0/0", "::/0"}

    def test_a_port_with_its_own_ipv4_entry_is_left_alone(self, tmp_path):
        """sshd bound 0.0.0.0:22 and :::22 itself: two sockets, read as two."""
        binds = _binds(tmp_path, FIXTURE.read_text() + LONE_V6)
        assert binds[("tcp", 22)] == {"0.0.0.0/0", "::/0"}
        assert binds[("udp", 5353)] == {"0.0.0.0/0", "::/0"}


def _e(bind, port=5500, proto="tcp"):
    return {"protocol": proto, "port": port, "bind_address": bind,
            "process": {"name": "java"}, "flags": flags_for(bind, port)}


class TestOssec:
    def test_a_lone_ipv6_wildcard_gains_its_ipv4_half(self):
        out = dual_stack([_e("::/0")])
        assert [e["bind_address"] for e in out] == ["0.0.0.0/0", "::/0"]
        assert out[0]["process"] == {"name": "java"}

    def test_an_ipv4_entry_on_the_same_port_keeps_it_ipv6_only(self):
        out = dual_stack([_e("::/0"), _e("100.98.5.6/32")])
        assert sorted(e["bind_address"] for e in out) == ["100.98.5.6/32", "::/0"]

    def test_a_specific_ipv6_address_is_not_a_wildcard(self):
        assert [e["bind_address"] for e in dual_stack([_e("2a07:1182:5:30::6/128")])] == \
            ["2a07:1182:5:30::6/128"]
