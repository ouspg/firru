"""A deny-listed service (SSDP) is only denied explicitly when the host listens
on it — that override is meaningful. With no listener the filter's default DROP
already denies it, so no dead deny term is emitted."""

import pathlib
import textwrap

import pytest
from aerleon.lib import naming

from firru.cli.listeners_to_aerleon import synth_host


@pytest.fixture
def defs(tmp_path):
    (tmp_path / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSDP: [{port: 1900, protocol: udp}]
          SSH:  [{port: 22, protocol: tcp}]
    """))
    (tmp_path / "networks.yml").write_text(
        "networks:\n  H:\n    values: [{address: 10.0.0.1/32}]\n")
    return naming.Naming(str(tmp_path))


def _listen(proto, port, proc="p"):
    return {"protocol": proto, "port": port, "bind_address": "0.0.0.0/0",
            "process": {"name": proc}, "flags": []}


def _names(defs, listen):
    _, pol, _ = synth_host({"metadata": {"hostname": "h", "os": "linux"},
                            "listen_ports": listen}, defs)
    return [(t.get("name"), t.get("action")) for t in pol["filters"][0]["terms"]]


def test_no_ssdp_listener_emits_no_deny(defs):
    names = _names(defs, [_listen("tcp", 22)])
    assert not any("ssdp" in n.lower() for n, _ in names)
    # default DROP still terminates the filter
    assert names[-1] == ("drop-ANY", "deny")


def test_an_ssdp_listener_is_denied_in_place(defs):
    names = _names(defs, [_listen("udp", 1900)])
    denies = [(n, a) for n, a in names if "ssdp" in n.lower()]
    assert len(denies) == 1 and denies[0][1] == "deny"


def test_the_deny_is_not_duplicated(defs):
    # both a listener and the (former) blanket loop would have produced two
    names = _names(defs, [_listen("udp", 1900), _listen("tcp", 22)])
    assert sum(1 for n, _ in names if "ssdp" in n.lower()) == 1


def _targets(defs, os_type):
    _, pol, _ = synth_host({"metadata": {"hostname": "h", "os": os_type},
                            "listen_ports": [_listen("tcp", 22)]}, defs)
    return [f["header"]["targets"] for f in pol["filters"]]


def test_windows_default_deny_is_in_the_header(defs):
    # A deny-all term would render as a block rule, and on Windows block beats
    # allow; the inbound default lives in the header. Outbound keeps the
    # host's own default.
    tgts = _targets(defs, "windows")
    waf = [t["windows_advfirewall"] for t in tgts if "windows_advfirewall" in t]
    assert waf == ["in mixed block", "out mixed"]


def test_linux_target_keeps_mixed(defs):
    # nftables does support mixed (dual family); leave it.
    tgts = _targets(defs, "linux")
    nft = [t["nftables"] for t in tgts if "nftables" in t]
    assert nft and all("mixed" in v for v in nft)
