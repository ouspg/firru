"""Double-booked ports: the listener's owner picks the name, or the guess is said."""
from pathlib import Path

import pytest
from aerleon.lib import naming

from firru.listeners import unit_from_cgroup
from firru.owners import load_owners, owner_evidence, parse_owner_comments
from firru.service_naming import best_token, choose_token

DEFS = Path(__file__).resolve().parent.parent / "def"


@pytest.fixture(scope="module")
def defs():
    return naming.Naming(str(DEFS))


@pytest.fixture(scope="module")
def owners():
    return load_owners(DEFS)


def pick(defs, owners, port, proto, *evidence):
    return choose_token(defs, defs.GetPortParents(port, proto), owners, set(evidence))


# --- reading the hints -------------------------------------------------------

def test_an_owner_line_belongs_to_the_key_below_it():
    text = """services:
  # Source: somewhere
  # Owner: units=a.socket processes=A,b
  NAME:
    - port: 1
      protocol: tcp
  OTHER:
    - port: 2
      protocol: tcp
"""
    assert parse_owner_comments(text) == {"NAME": {"units": ["a.socket"], "processes": ["a", "b"]}}


def test_a_blank_line_ends_an_owner_block():
    text = "services:\n  # Owner: processes=x\n\n  NAME:\n    - port: 1\n"
    assert parse_owner_comments(text) == {}


def test_a_misspelled_owner_field_is_an_error_not_a_silent_skip():
    with pytest.raises(ValueError):
        parse_owner_comments("services:\n  # Owner: proceses=x\n  NAME:\n")


def test_every_shipped_owner_hint_names_a_shipped_service(defs, owners):
    assert owners
    for token in owners:
        assert defs.GetService(token), token


# --- the evidence ------------------------------------------------------------

@pytest.mark.parametrize("cgroup,unit", [
    ("0::/system.slice/cockpit.socket", "cockpit.socket"),
    ("/system.slice/sshd.service", "sshd.service"),
    ("/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope", "x.scope"),
    ("/", ""),
    ("", ""),
])
def test_the_unit_is_the_last_unit_in_the_cgroup_path(cgroup, unit):
    assert unit_from_cgroup(cgroup) == unit


def test_evidence_is_process_exe_unit_and_windows_services():
    ev = owner_evidence([
        {"process": {"name": "systemd", "unit": "cockpit.socket"}},
        {"process": {"name": "svchost", "exe": r"C:\Windows\System32\svchost.exe",
                     "services": ["VMMS"]}},
        {"process": {"name": "UNKNOWN"}},
    ])
    assert ev == {"systemd", "cockpit.socket", "svchost", "svchost.exe", "vmms"}


# --- choosing ----------------------------------------------------------------

def test_a_socket_activated_cockpit_is_cockpit(defs, owners):
    assert pick(defs, owners, 9090, "tcp", "systemd", "cockpit.socket") == ("COCKPIT", None)


def test_prometheus_on_9090_is_prometheus_not_the_alphabetically_first(defs, owners):
    assert pick(defs, owners, 9090, "tcp", "prometheus") == ("PROMETHEUS", None)


def test_an_unattributable_9090_is_a_guess_that_says_so(defs, owners):
    token, note = pick(defs, owners, 9090, "tcp", "java")
    assert token in ("COCKPIT", "PROMETHEUS")
    assert note and "ambiguous" in note and "java" in note


def test_the_generic_name_wins_when_the_specific_one_does_not_match(defs, owners):
    """System on 443 is a web server; only vmms makes it Hyper-V Replica."""
    assert pick(defs, owners, 443, "tcp", "system") == ("HTTPS", None)
    assert pick(defs, owners, 443, "tcp", "system", "vmms") == ("WINDOWS-HYPERV-REPLICA-HTTPS", None)


def test_an_owner_match_beats_a_narrower_name(defs, owners):
    """dockerd on 7946 is swarm gossip although METALLB-MEMBERLIST is narrower."""
    assert pick(defs, owners, 7946, "tcp", "dockerd") == ("DOCKER-SWARM", None)
    assert pick(defs, owners, 7946, "tcp", "speaker") == ("METALLB-MEMBERLIST", None)
    assert pick(defs, owners, 7946, "tcp")[0] == "METALLB-MEMBERLIST"


def test_two_unhinted_names_are_ambiguous(defs, owners):
    token, note = pick(defs, owners, 8472, "udp")
    assert note and "CILIUM-VXLAN/FLANNEL-VXLAN" in note


def test_without_any_hints_the_choice_is_what_best_token_always_made(defs):
    for port, proto in ((9090, "tcp"), (443, "tcp"), (7946, "udp"), (8472, "udp")):
        tokens = defs.GetPortParents(port, proto)
        assert choose_token(defs, tokens, {}, set())[0] == best_token(defs, tokens)


# --- end to end --------------------------------------------------------------

def test_synthesis_names_the_port_after_its_owner(defs, owners):
    from firru.cli.listeners_to_aerleon import synth_host

    def port_name(process):
        data = {"metadata": {"hostname": "h1.example.org", "os": "linux"},
                "listen_ports": [{"protocol": "tcp", "port": 9090,
                                  "bind_address": "0.0.0.0/0", "process": process}]}
        _, policy, _ = synth_host(data, defs, owners=owners)
        return [t["destination-port"] for t in policy["filters"][0]["terms"]
                if t.get("destination-port") in ("COCKPIT", "PROMETHEUS")]

    assert port_name({"name": "prometheus"}) == ["PROMETHEUS"]
    assert port_name({"name": "systemd", "unit": "cockpit.socket"}) == ["COCKPIT"]


def test_an_el9_padded_line_keeps_its_unit(tmp_path):
    """EL9 ss pads after users:(...), jc then keeps opts as a bare string and
    drops the cgroup; it is recovered from the raw row."""
    from firru.listeners import normalize_linux_entry
    from firru.ss import parse_ss_safe
    f = tmp_path / "ss"
    f.write_text(
        "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\n"
        'tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    '
        'users:(("sshd",pid=820,fd=7))    ino:23047 sk:3 cgroup:/system.slice/sshd.service <->\n'
        'tcp   LISTEN 0      4096         0.0.0.0:9090      0.0.0.0:*    '
        'users:(("systemd",pid=1,fd=59)) ino:6939 sk:5 cgroup:/system.slice/cockpit.socket <->\n')
    units = {n["local_port"]: n["process_info"].get("unit")
             for n in (normalize_linux_entry(e, {}) for e in parse_ss_safe(str(f))) if n}
    assert units == {22: "sshd.service", 9090: "cockpit.socket"}


# --- unexpected owners -------------------------------------------------------

from firru.owners import load_expected  # noqa: E402
from firru.service_naming import owner_surprise  # noqa: E402


@pytest.fixture(scope="module")
def expected():
    return load_expected(DEFS)


def served(*names, **kw):
    return [{"process": {"name": n, **kw}} for n in names]


def test_expect_lines_are_read_separately_from_owner_lines():
    text = "services:\n  # Owner: processes=a\n  # Expect: processes=b,c\n  NAME:\n"
    assert parse_owner_comments(text) == {"NAME": {"processes": ["a"]}}
    assert parse_owner_comments(text, "Expect") == {"NAME": {"processes": ["b", "c"]}}


def test_an_expected_web_server_is_silent(expected):
    for p in ("nginx", "apache2", "caddy", "System"):
        assert owner_surprise("HTTP", served(p), expected) is None, p


def test_python_on_a_web_port_is_said_and_called_a_runtime(expected):
    note = owner_surprise("HTTP-ALT", served("python3"), expected)
    assert "python3" in note and "runtime" in note and "nginx" in note


def test_a_forwarder_points_behind_itself(expected):
    assert "behind it" in owner_surprise("HTTPS", served("docker-proxy"), expected)


def test_no_attribution_is_its_own_grade(expected):
    assert "no process attribution" in owner_surprise("HTTPS", served("UNKNOWN"), expected)


def test_an_owner_line_is_an_expectation_too(expected):
    assert owner_surprise("COCKPIT", served("systemd", unit="cockpit.socket"), expected) is None
    assert "nginx" in owner_surprise("COCKPIT", served("nginx"), expected)


def test_a_name_without_expectations_has_no_opinion(expected):
    assert owner_surprise("REDIS", served("python3"), expected) is None


def test_expect_does_not_change_which_name_wins(defs, owners):
    """python3 on 443 is still HTTPS -- an unexpected HTTPS, not an ambiguous one."""
    assert pick(defs, owners, 443, "tcp", "python3") == ("HTTPS", None)


def test_synthesis_puts_the_surprise_on_its_own_comment_line(defs, owners, expected):
    import io
    from ruyaml import YAML
    from firru.cli.listeners_to_aerleon import synth_host
    data = {"metadata": {"hostname": "h1.example.org", "os": "linux"},
            "listen_ports": [{"protocol": "tcp", "port": 8080, "bind_address": "0.0.0.0/0",
                              "process": {"name": "python3"}}]}
    _, policy, _ = synth_host(data, defs, owners=owners, expected=expected)
    buf = io.StringIO()
    YAML().dump(policy, buf)
    lines = [l.strip() for l in buf.getvalue().splitlines()]
    assert any(l.startswith("# [auto] unexpected owner: HTTP-ALT served by python3") for l in lines)
