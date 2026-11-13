"""
Loopback binds: recorded at collection, dropped at synthesis.

The split matters in both directions. A service bound to 127.0.0.1 is not
reachable off-host, so a term for it would declare surface that does not exist;
but the bind is also evidence the host was configured correctly, which is the
resolved form of the operator taxonomy's configuration-issue case, so the loot
must keep it whether or not anything downstream reads it.

The regression these pin: `listeners_to_aerleon` used to read `bind_address`
only to choose the address family, so a loopback-only listener produced an
ordinary accept term. Nothing caught it because the `ss` collector filters
loopback at capture, so no loot from that path ever exercised it -- but loot
from `ossec-to-loot`, `nmap-to-listeners`, a hand inventory or a new collector
does. On the LSPR24 OSSEC archive it is 27% of listeners.
"""


import pytest

import firru.cli.listeners_to_aerleon as l2a


def entry(cidr, name="svc", port=443):
    return {"protocol": "tcp", "port": port, "bind_address": cidr,
            "process": {"name": name, "exe": f"/usr/sbin/{name}",
                        "services": [], "user": "root", "pid": 1},
            "flags": []}


def synth(entries, port=443):
    """The terms for one (host, port), or None when nothing is emitted."""
    return l2a.listen_to_term("h1", "tcp", port, ["HTTPS"], entries, {})


def test_loopback_only_listener_gets_no_term():
    assert synth([entry("127.0.0.1/32")]) is None


def test_ipv6_loopback_only_listener_gets_no_term():
    assert synth([entry("::1/128")]) is None


def test_world_bound_listener_still_gets_a_term():
    assert synth([entry("0.0.0.0/0")]) is not None


def test_port_bound_both_ways_keeps_its_term():
    """Only the loopback *entry* is dropped, never the port itself."""
    rule = synth([entry("127.0.0.1/32"), entry("0.0.0.0/0")])
    assert rule is not None


def test_specific_non_loopback_address_is_unaffected():
    assert synth([entry("192.0.2.10/32")]) is not None


def test_ossec_converter_keeps_loopback_in_the_loot():
    """Raw data is raw data: the converter records what was observed."""
    from firru.cli.ossec_to_loot import entries_from
    body = ("ossec: output: 'netstat listening ports':\n"
            "tcp 127.0.0.53:53 0.0.0.0:* 628/systemd-resolve\n"
            "tcp 0.0.0.0:443 0.0.0.0:* 755/nginx\n")
    kept = entries_from(body, keep_loopback=True)
    binds = {e["bind_address"] for e in kept}
    assert "127.0.0.53/32" in binds and "0.0.0.0/0" in binds

    dropped = entries_from(body, keep_loopback=False)
    assert {e["bind_address"] for e in dropped} == {"0.0.0.0/0"}


def test_ossec_converter_parses_both_netstat_shapes():
    from firru.cli.ossec_to_loot import parse_line
    # 4-field, pid/name
    assert parse_line("tcp 0.0.0.0:443 0.0.0.0:* 755/nginx") == \
        ("tcp", "0.0.0.0", 443, "755", "nginx")
    # 4-field, truncated path: no name rather than a guessed one
    assert parse_line("tcp 0.0.0.0:22 0.0.0.0:* /usr") == \
        ("tcp", "0.0.0.0", 22, None, None)
    # 6-field raw netstat with Recv-Q/Send-Q and no process
    assert parse_line("udp 0 0 0.0.0.0:4789 0.0.0.0:* -") == \
        ("udp", "0.0.0.0", 4789, None, None)
    # v6 wildcard renders as ":::22"
    assert parse_line("tcp6 :::80 :::* 755/nginx") == \
        ("tcp6", "::", 80, "755", "nginx")


# --- the term itself: emitted for Linux, not for Windows, never merged -------

def build(os_type):
    return l2a.build_policy("h1", [], os_type, {})


def term_names(policy, idx):
    return [t["name"] for t in policy["filters"][idx]["terms"]]


def test_linux_gets_an_explicit_loopback_term_in_both_filters():
    """nftables input policy is DROP, so the accept is load-bearing."""
    p = build("linux")
    assert "allow-loopback" in term_names(p, 0)
    assert "allow-loopback" in term_names(p, 1)


def test_windows_gets_no_loopback_term():
    """WFP permits loopback implicitly; the term would be inert noise."""
    p = build("windows")
    assert "allow-loopback" not in term_names(p, 0)
    assert "allow-loopback" not in term_names(p, 1)


def test_windows_still_gets_icmp_and_the_terminal_drop():
    p = build("windows")
    ingress = term_names(p, 0)
    assert "allow-icmp" in ingress and "allow-icmpv6" in ingress
    assert ingress[-1] == "drop-ANY"


def test_unknown_os_defaults_to_the_linux_shape():
    assert "allow-loopback" in term_names(build(None), 0)


def test_merge_drops_loopback_by_address_not_by_token_name():
    """A differently-named token resolving to loopback must still be dropped."""
    from firru.cli.merge_zones import is_loopback_term

    class Defs:                      # the shape resolve_nets expects
        _n = {"LOCALHOST": ["127.0.0.0/8", "::1/128"],
              "WORKSTATIONS": ["192.0.2.0/24"]}

        def GetNetAddr(self, name):
            return self._n.get(name, [])

    defs = Defs()
    assert is_loopback_term({"source-address": "LOOPBACK"}, defs)
    assert is_loopback_term({"source-address": "LOCALHOST"}, defs)
    assert not is_loopback_term({"source-address": "WORKSTATIONS"}, defs)
    assert not is_loopback_term({"source-address": None}, defs)


def test_ranges_need_a_source_and_a_reason(tmp_path):
    from firru.cli.ossec_to_loot import load_ranges
    p = tmp_path / "r.yml"
    p.write_text("ranges:\n  linux: {tcp: 32768-60999, udp: 32768-60999, "
                 "source: baselines, why: measured}\n"
                 "hosts:\n  Mail: {tcp: 6005-64325, source: exchange run, why: Exchange}\n")
    by_os, by_host = load_ranges(p)
    assert by_os["linux"]["udp"] == [32768, 60999]
    assert by_host["mail"] == {"tcp": [6005, 64325], "source": "exchange run"}
    p.write_text("ranges:\n  linux: {tcp: 32768-60999}\n")
    with pytest.raises(SystemExit):
        load_ranges(p)
