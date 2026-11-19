"""arkime-filter: the expression shapes, and what they select.

What they select is checked by evaluating the expression over sessions, with
Arkime's reading of it: ip.src and ip.dst hold one address each, a list or a
CIDR matches by membership, `!=` is not-a-member. Whether Arkime itself reads
it so is for a test against a running Arkime.
"""

import ipaddress
import re
import subprocess
import sys

import pytest

from firru.cli.arkime_filter import build_filter

NET = [ipaddress.ip_network("10.0.0.0/24")]
HOSTS = [ipaddress.ip_network(a) for a in ("10.0.0.5/32", "10.0.0.6/32")]
DMZ = [ipaddress.ip_network("192.0.2.0/24")]


def matches(expr, src, dst):
    """Evaluate expr for one session, src -> dst."""
    def member(side, op, values):
        addr = ipaddress.ip_address(src if side == "src" else dst)
        nets = [ipaddress.ip_network(v) for v in values.strip("[]").split(",")]
        hit = any(addr in n for n in nets)
        return str(hit if op == "==" else not hit)
    py = re.sub(r"ip\.(src|dst) (==|!=) (\[[^\]]*\]|[0-9a-f.:/]+)",
                lambda m: member(*m.groups()), expr)
    py = py.replace("&&", " and ").replace("||", " or ")
    # Nothing of the expression may survive but booleans and connectives.
    assert not re.sub(r"True|False|and|or|[() ]", "", py), py
    return eval(py)


def test_a_rogue_device_is_caught_talking_to_a_known_host():
    # The reason exclusion is per endpoint: `ip != host` would drop this session.
    f = build_filter([], [], NET, HOSTS)
    assert matches(f, "10.0.0.99", "10.0.0.5")
    assert matches(f, "10.0.0.5", "10.0.0.99")
    assert not matches(f, "10.0.0.5", "10.0.0.6")
    assert not matches(f, "198.51.100.1", "10.0.0.5")


def test_a_zone_pair_matches_both_directions_and_nothing_else():
    f = build_filter(NET, DMZ, [], [])
    assert matches(f, "10.0.0.1", "192.0.2.1")
    assert matches(f, "192.0.2.1", "10.0.0.1")
    assert not matches(f, "10.0.0.1", "10.0.0.2")
    assert not matches(f, "192.0.2.1", "198.51.100.1")


def test_a_zone_pair_from_unknown_hosts():
    f = build_filter(NET, DMZ, [], HOSTS)
    assert matches(f, "10.0.0.99", "192.0.2.1")
    assert not matches(f, "10.0.0.5", "192.0.2.1")
    assert not matches(f, "192.0.2.1", "10.0.0.6")


def test_exclude_alone_leaves_out_sessions_either_endpoint_takes_part_in():
    f = build_filter([], [], [], HOSTS)
    assert not matches(f, "10.0.0.5", "198.51.100.1")
    assert not matches(f, "198.51.100.1", "10.0.0.6")
    assert matches(f, "10.0.0.7", "198.51.100.1")


def test_addresses_are_collapsed_into_one_list_per_side():
    four = [ipaddress.ip_network(f"10.0.0.{i}/32") for i in range(4)]
    f = build_filter([], [], four + [ipaddress.ip_network("2001:db8::1/128")], [])
    assert f == "((ip.src == [10.0.0.0/30,2001:db8::1]) || (ip.dst == [10.0.0.0/30,2001:db8::1]))"


def test_one_host_is_a_bare_address():
    f = build_filter([], [], [ipaddress.ip_network("10.0.0.5/32")], [])
    assert f == "((ip.src == 10.0.0.5) || (ip.dst == 10.0.0.5))"


@pytest.fixture
def defs(tmp_path):
    (tmp_path / "networks.yml").write_text(
        "networks:\n"
        "  INT_NET:\n    values:\n    - address: 10.0.0.0/24\n"
        "  INT_HOSTS:\n    values:\n    - address: 10.0.0.5/32\n    - address: 10.0.0.6/32\n")
    (tmp_path / "services.yml").write_text("services:\n  SSH: [{port: 22, protocol: tcp}]\n")
    return tmp_path


def run(defs, *argv):
    return subprocess.run([sys.executable, "-m", "firru.cli.arkime_filter",
                           "--defs", str(defs), *argv], capture_output=True, text=True)


def test_the_command_prints_the_expression(defs):
    r = run(defs, "--include", "INT_NET", "--exclude", "INT_HOSTS")
    assert r.returncode == 0
    assert r.stdout.strip() == build_filter([], [], NET, HOSTS)


def test_a_token_that_names_nothing_is_refused_not_dropped(defs):
    # Dropped, a mistyped --exclude would make the filter match more.
    r = run(defs, "--include", "INT_NET", "--exclude", "INT_HOTS")
    assert r.returncode == 2
    assert r.stdout == ""
    assert "INT_HOTS" in r.stderr
