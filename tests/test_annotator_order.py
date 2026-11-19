"""An address several tokens define is named by the most specific one, not
by whichever definition file the directory happened to list first."""

import textwrap

import pytest

from firru.annotator import PolicyAnnotator

HOST = "  WEB1:\n    values:\n    - address: 10.0.0.5/32\n"
WIDE = ("  EVERY_NAMED_HOST:\n    values:\n    - address: 10.0.0.5/32\n"
        "    - address: 10.0.0.6/32\n    - address: 10.0.0.7/32\n")


@pytest.mark.parametrize("first,second", [(HOST, WIDE), (WIDE, HOST)])
def test_the_host_token_wins_in_either_order(tmp_path, first, second):
    (tmp_path / "networks.yml").write_text("networks:\n" + first + second)
    (tmp_path / "services.yml").write_text("services:\n  SSH: [{port: 22, protocol: tcp}]\n")
    assert PolicyAnnotator(str(tmp_path)).annotate_ip("10.0.0.5")["host"] == "WEB1"


@pytest.mark.parametrize("first,second", [(HOST, WIDE), (WIDE, HOST)])
def test_the_host_keeps_its_groups_in_either_order(tmp_path, first, second):
    grp = "  WEB_SERVERS:\n    values:\n    - name: WEB1\n    - address: 10.0.0.9/32\n"
    (tmp_path / "networks.yml").write_text("networks:\n" + first + second + grp)
    (tmp_path / "services.yml").write_text("services:\n  SSH: [{port: 22, protocol: tcp}]\n")
    a = PolicyAnnotator(str(tmp_path))
    assert "WEB_SERVERS" in a.annotate_ip("10.0.0.5")["parents"]
    assert "WEB1" in a.group_members["WEB_SERVERS"]


REPLICA = "  HYPERV_REPLICA:\n  - {port: 80, protocol: tcp}\n  - {port: 443, protocol: tcp}\n"
HTTPS = "  HTTPS:\n  - {port: 443, protocol: tcp}\n"


@pytest.mark.parametrize("first,second", [(REPLICA, HTTPS), (HTTPS, REPLICA)])
def test_a_port_is_named_by_the_narrowest_service_in_either_order(tmp_path, first, second):
    (tmp_path / "networks.yml").write_text("networks:\n" + HOST)
    (tmp_path / "a.yml").write_text("services:\n" + first)
    (tmp_path / "b.yml").write_text("services:\n" + second)
    a = PolicyAnnotator(str(tmp_path))
    assert a.annotate_port(443, "tcp") == "HTTPS"
    assert a.annotate_port(80, "TCP") == "HYPERV_REPLICA"
    assert a.annotate_port(8443, "tcp") is None


def test_a_real_name_beats_a_narrower_placeholder(tmp_path):
    # As synthesis's best_token: TCP_443 grants one port and says nothing.
    (tmp_path / "networks.yml").write_text("networks:\n" + HOST)
    (tmp_path / "a.yml").write_text("services:\n  HTTPS:\n  - {port: 443, protocol: tcp}\n"
                                    "  - {port: 8443, protocol: tcp}\n")
    (tmp_path / "b.yml").write_text("services:\n  TCP_443:\n  - {port: 443, protocol: tcp}\n")
    assert PolicyAnnotator(str(tmp_path)).annotate_port(443, "tcp") == "HTTPS"
