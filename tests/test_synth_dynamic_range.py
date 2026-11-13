"""Which ports synthesis treats as a client's: the host's own dynamic range,
per protocol, and no range-wide token passing for a service name."""
import pathlib

import pytest
from aerleon.lib import naming

from firru.cli.listeners_to_aerleon import synth_entries

DEF = pathlib.Path(__file__).parent.parent / "def"


@pytest.fixture(scope="module")
def defs():
    return naming.Naming(str(DEF))


def ports(defs, os_name, listeners, ephemeral=None):
    meta = {"hostname": "h", "os": os_name}
    if ephemeral:
        meta["ephemeral"] = ephemeral
    doc = {"metadata": meta, "listen_ports": [
        {"protocol": p, "port": n, "bind_address": "0.0.0.0/0"} for p, n in listeners]}
    return set(synth_entries(doc, defs)[3])


def test_a_linux_client_socket_in_the_windows_range_is_not_a_service(defs):
    # avahi's udp/58065: inside Linux's 32768-60999, and WINDOWS-RPC-DYNAMIC
    # (narrower than the Linux range) must not rescue it.
    assert ports(defs, "linux", [("udp", 58065), ("udp", 5353)]) == {("udp", 5353)}


def test_registered_ports_inside_a_range_are_kept(defs):
    assert ("tcp", 33060) in ports(defs, "linux", [("tcp", 33060)])
    assert ("tcp", 47001) in ports(defs, "windows", [("tcp", 47001)])


def test_the_hosts_own_range_wins_per_protocol(defs):
    # Exchange setup moves TCP to 6005-64325 and leaves UDP at 49152-64325.
    exch = {"tcp": [6005, 64325], "udp": [49152, 64325]}
    got = ports(defs, "windows", [("tcp", 23456), ("udp", 23456), ("tcp", 65000)], exch)
    assert got == {("udp", 23456), ("tcp", 65000)}
